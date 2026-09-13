//! Deterministic regressions for M7-C33: a device that answers with a
//! challenge whose frozen identity does not match the in-flight authorization
//! must fail that stream now, with a typed code from the existing closed
//! authorization-failure vocabulary, instead of leaving the operation waiting
//! for its whole authorization deadline.
//!
//! Every assertion below is synchronous: the refusal is observed on the exact
//! `begin_device_challenge` call, with no timer, no wall-clock sleep and no
//! background actor loop, so "promptly" is proven by construction rather than
//! by measuring an elapsed duration.

use std::collections::BTreeSet;

use chrono::{Duration, Utc};
use tokio::sync::{mpsc, oneshot};
use tunnel_catalog::{AuthenticatedConsumer, DeviceIdentity, GrantSnapshot, PermissionSet};
use tunnel_protocol::{AuthorizationChallenge, ControlMessage};
use uuid::Uuid;

use super::{
    ControlOutbound, DataCarrier, DataOutbound, DispatchRequest, EchoOutcome, RelayActor,
    SessionKey, runtime::CarrierContext, stream_identity_tests::admitted_control_actor, wire,
};

const SESSION_ID: &str = "challenge-mismatch";
const EXPECTED_REASON: &str = "challenge mismatch";
const EXPECTED_CODE: &str = "AUTHORIZATION_INVALIDATED";

/// The three ways a device answer can fail to match the in-flight record.  All
/// of them are equally unconfirmable, so all of them must refuse now.
#[derive(Clone, Copy, Debug)]
enum Mismatch {
    PermissionDigest,
    GrantRevision,
    ServiceId,
}

impl Mismatch {
    const ALL: [Self; 3] = [Self::PermissionDigest, Self::GrantRevision, Self::ServiceId];
}

fn drain_control(rx: &mut mpsc::Receiver<ControlOutbound>) -> Vec<ControlMessage> {
    let mut messages = Vec::new();
    while let Ok(item) = rx.try_recv() {
        if let ControlOutbound::Text(mut text) = item {
            let message =
                wire::parse_control(text.as_bytes()).expect("queued control message decodes");
            text.release();
            messages.push(message);
        }
    }
    messages
}

struct Fixture {
    device_id: Uuid,
    service_id: Uuid,
    identity: DeviceIdentity,
    consumer: AuthenticatedConsumer,
    grant: GrantSnapshot,
    key: SessionKey,
}

fn fixture() -> Fixture {
    let now = Utc::now();
    let tenant_id = Uuid::from_u128(0x33_0001);
    let device_id = Uuid::from_u128(0x33_0002);
    let principal_id = Uuid::from_u128(0x33_0003);
    let service_id = Uuid::from_u128(0x33_0004);
    Fixture {
        device_id,
        service_id,
        identity: DeviceIdentity {
            tenant_id,
            device_id,
            owner_user_id: principal_id,
            credential_id: Uuid::from_u128(0x33_0005),
            spki_fingerprint: "challenge-mismatch-spki".to_owned(),
            credential_not_before: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(5),
            credential_revoked_at: None,
            device_active: true,
            credential_active: true,
            device_version: 1,
            owner_epoch: 1,
            last_seen_at: Some(now),
        },
        consumer: AuthenticatedConsumer {
            tenant_id,
            principal_id,
        },
        grant: GrantSnapshot {
            tenant_id,
            principal_id,
            device_id,
            service_id,
            revision: 7,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            valid_until: now + Duration::minutes(5),
            read_started_at: now,
        },
        key: SessionKey {
            tenant_id,
            device_id,
            session_id: SESSION_ID.to_owned(),
            epoch: 1,
        },
    }
}

/// A challenge that matches the in-flight record in every field, so each
/// mismatch case below differs from a confirmable answer in exactly one way.
fn matching_challenge(
    fixture: &Fixture,
    stream_id: u64,
    challenge_id: &str,
) -> AuthorizationChallenge {
    AuthorizationChallenge::new(
        "challenge-mismatch-auth",
        SESSION_ID,
        fixture.key.epoch,
        stream_id,
        challenge_id,
        "challenge-mismatch-nonce",
        fixture.service_id.to_string(),
        wire::permission_digest(&fixture.grant, &fixture.service_id.to_string()),
        fixture.grant.revision,
    )
}

fn apply(mut challenge: AuthorizationChallenge, mismatch: Mismatch) -> AuthorizationChallenge {
    match mismatch {
        // A digest over the same grant with a different service name: well
        // formed, bounded, and not the frozen digest this record expects.
        Mismatch::PermissionDigest => {
            challenge.permission_digest = wire::permission_digest(
                &GrantSnapshot {
                    permissions: PermissionSet {
                        operations: BTreeSet::from(["echo:other".to_owned()]),
                    },
                    ..fixture().grant
                },
                &challenge.service_id,
            );
        }
        Mismatch::GrantRevision => challenge.grant_revision += 1,
        Mismatch::ServiceId => challenge.service_id = Uuid::from_u128(0x33_00FF).to_string(),
    }
    challenge
}

/// An M2 session with one data carrier: the stream path needs an active
/// carrier before a consumer stream can be admitted.
type M2Fixture = (
    RelayActor,
    mpsc::Receiver<ControlOutbound>,
    mpsc::Receiver<DataOutbound>,
);

fn m2_actor(fixture: &Fixture) -> M2Fixture {
    let (mut actor, registration) =
        admitted_control_actor(fixture.identity.clone(), fixture.key.clone());
    let (data_tx, data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
    let session = actor
        .sessions
        .get_mut(&fixture.key.scope())
        .expect("test session");
    session.profile = super::RuntimeProfile::M2;
    session.data_tx = Some(data_tx.clone());
    session.active_carrier = Some(DataCarrier {
        context: CarrierContext::new(
            fixture.key.session_id.clone(),
            fixture.key.epoch,
            1,
            "challenge-mismatch-data".to_owned(),
        ),
        tx: data_tx,
    });
    // The carrier receiver is returned so it stays open for the whole test: a
    // queued frame must not fail for a closed channel instead of the reason
    // under test.
    (actor, registration.rx, data_rx)
}

#[tokio::test]
async fn mismatched_stream_challenge_fails_that_stream_promptly_with_its_typed_code() {
    for mismatch in Mismatch::ALL {
        let fixture = fixture();
        let (mut actor, mut control_rx, _data_rx) = m2_actor(&fixture);
        let (open_tx, open_rx) = oneshot::channel();
        actor.open_echo_stream(
            fixture.consumer.clone(),
            fixture.device_id,
            fixture.service_id,
            fixture.grant.clone(),
            Utc::now() + Duration::minutes(5),
            open_tx,
        );
        let admitted = open_rx
            .await
            .expect("open response")
            .expect("stream admitted");
        assert!(
            matches!(
                drain_control(&mut control_rx).as_slice(),
                [ControlMessage::Open(_)]
            ),
            "{mismatch:?}: exactly one OPEN precedes the challenge"
        );
        {
            let stream = &actor.sessions[&fixture.key.scope()].streams[&admitted.stream_id];
            assert!(
                !stream.terminal && !stream.authorization_in_flight,
                "{mismatch:?}: the admitted stream must start live and unchallenged"
            );
            assert_eq!(
                stream.authorization_failure_code, None,
                "{mismatch:?}: no authorization failure may precede the challenge"
            );
        }

        let challenge_id = "challenge-mismatch-stream";
        actor.begin_device_challenge(
            fixture.key.clone(),
            apply(
                matching_challenge(&fixture, admitted.stream_id, challenge_id),
                mismatch,
            ),
        );

        // Observed on the same call: no deadline was armed and none elapsed.
        let stream = &actor.sessions[&fixture.key.scope()].streams[&admitted.stream_id];
        assert_eq!(
            stream.authorization_failure_code,
            Some(EXPECTED_CODE),
            "{mismatch:?}: a mismatched challenge must carry the typed failure code"
        );
        assert!(
            stream.terminal && stream.terminal_fin_failure,
            "{mismatch:?}: the mismatched stream must be terminal"
        );
        assert!(
            !stream.authorization_in_flight,
            "{mismatch:?}: no authorization may remain in flight"
        );
        assert_eq!(
            stream.authorization_deadline_ms, None,
            "{mismatch:?}: the refusal must not arm an authorization deadline to wait out"
        );
        assert_eq!(
            stream.authorization_admission_deadline_ms, None,
            "{mismatch:?}: a mismatched challenge must not admit dispatch"
        );
        assert_eq!(
            stream.authorized_until, None,
            "{mismatch:?}: a mismatched challenge must not open a dispatch gate"
        );
        assert!(
            stream.closed.is_cancelled(),
            "{mismatch:?}: the mismatched stream must be closed, not left pending"
        );

        match drain_control(&mut control_rx).as_slice() {
            [ControlMessage::AuthorizationInvalidated(invalidated)] => {
                assert_eq!(invalidated.session_id, fixture.key.session_id);
                assert_eq!(invalidated.epoch, fixture.key.epoch);
                assert_eq!(invalidated.stream_id, admitted.stream_id);
                assert_eq!(invalidated.challenge_id, challenge_id);
                assert_eq!(
                    invalidated.reason, EXPECTED_REASON,
                    "{mismatch:?}: the diagnostic reason is a fixed payload-free literal"
                );
            }
            other => panic!(
                "{mismatch:?}: exactly one AUTHORIZATION_INVALIDATED must be queued: {other:?}"
            ),
        }

        let snapshot = actor.snapshot();
        assert!(
            snapshot
                .stream_terminal_events
                .iter()
                .any(|event| event.stream_id == admitted.stream_id
                    && event.reason == "AUTHORIZATION_REVOKED"),
            "{mismatch:?}: the terminal must be retained with its existing typed reason"
        );
        assert_eq!(
            snapshot.lifetime_application_dispatches, 0,
            "{mismatch:?}: a mismatched challenge must never dispatch"
        );
    }
}

#[tokio::test]
async fn mismatched_pending_challenge_fails_the_operation_promptly_with_its_typed_outcome() {
    for mismatch in Mismatch::ALL {
        let fixture = fixture();
        let (mut actor, mut control_rx, _data_rx) = m2_actor(&fixture);
        let (response, mut response_rx) = oneshot::channel();
        actor
            .dispatch_echo(DispatchRequest {
                consumer: fixture.consumer.clone(),
                device_id: fixture.device_id,
                service_id: fixture.service_id,
                grant: fixture.grant.clone(),
                body: b"challenge-mismatch-body".to_vec(),
                consumer_expires_at: Utc::now() + Duration::minutes(5),
                response,
            })
            .await;
        let stream_id = 1;
        assert!(
            actor.sessions[&fixture.key.scope()]
                .pending
                .contains_key(&stream_id),
            "{mismatch:?}: the finite echo must be pending admission"
        );
        assert!(
            matches!(
                drain_control(&mut control_rx).as_slice(),
                [ControlMessage::Open(_)]
            ),
            "{mismatch:?}: exactly one OPEN precedes the challenge"
        );
        assert!(
            matches!(
                response_rx.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ),
            "{mismatch:?}: the operation must still be waiting before the challenge"
        );

        let challenge_id = "challenge-mismatch-pending";
        actor.begin_device_challenge(
            fixture.key.clone(),
            apply(
                matching_challenge(&fixture, stream_id, challenge_id),
                mismatch,
            ),
        );

        // Resolved on the same call: the waiter no longer depends on the
        // authorization deadline expiring.
        match response_rx.try_recv() {
            Ok(EchoOutcome::Failure { code, execution }) => {
                assert_eq!(
                    code, "AUTHORIZATION_REVOKED",
                    "{mismatch:?}: the refusal must reuse the existing typed failure code"
                );
                assert_eq!(
                    execution, "not_dispatched",
                    "{mismatch:?}: a mismatched challenge precedes any side effect"
                );
            }
            other => panic!("{mismatch:?}: the operation must fail promptly: {other:?}"),
        }
        assert!(
            !actor.sessions[&fixture.key.scope()]
                .pending
                .contains_key(&stream_id),
            "{mismatch:?}: the refused pending operation must be reclaimed"
        );
        match drain_control(&mut control_rx).as_slice() {
            [ControlMessage::AuthorizationInvalidated(invalidated)] => {
                assert_eq!(invalidated.stream_id, stream_id);
                assert_eq!(invalidated.challenge_id, challenge_id);
                assert_eq!(invalidated.reason, EXPECTED_REASON);
            }
            other => panic!(
                "{mismatch:?}: exactly one AUTHORIZATION_INVALIDATED must be queued: {other:?}"
            ),
        }
        assert_eq!(
            actor.snapshot().lifetime_application_dispatches,
            0,
            "{mismatch:?}: a mismatched challenge must never dispatch"
        );
    }
}

/// A challenge that matches the in-flight record must still be accepted, so
/// the refusal above cannot be an unconditional rejection of device answers.
#[tokio::test]
async fn matching_stream_challenge_is_still_accepted_for_authorization() {
    let fixture = fixture();
    let (mut actor, mut control_rx, _data_rx) = m2_actor(&fixture);
    let (open_tx, open_rx) = oneshot::channel();
    actor.open_echo_stream(
        fixture.consumer.clone(),
        fixture.device_id,
        fixture.service_id,
        fixture.grant.clone(),
        Utc::now() + Duration::minutes(5),
        open_tx,
    );
    let admitted = open_rx
        .await
        .expect("open response")
        .expect("stream admitted");
    let _ = drain_control(&mut control_rx);
    actor.begin_device_challenge(
        fixture.key.clone(),
        matching_challenge(&fixture, admitted.stream_id, "challenge-match-stream"),
    );
    let stream = &actor.sessions[&fixture.key.scope()].streams[&admitted.stream_id];
    assert!(
        stream.authorization_in_flight && !stream.terminal,
        "a matching challenge must start the authorization read"
    );
    assert_eq!(stream.authorization_failure_code, None);
    assert!(
        stream.authorization_deadline_ms.is_some(),
        "a matching challenge arms its bounded authorization deadline"
    );
    assert!(
        drain_control(&mut control_rx).is_empty(),
        "no refusal may be queued for a matching challenge"
    );
}
