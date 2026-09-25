//! M7-C62 / EC-038: a cancellation that cannot be delivered fences the
//! session.
//!
//! docs/protocol.md reserves control capacity for cancellation and requires
//! that "failure to deliver a cancellation fences the session".  The actor's
//! `cancel` path must therefore never discard a refused CANCEL enqueue: the
//! consumer keeps its unknown outcome, the session closes with a typed
//! closed-vocabulary reason, and a healthy enqueue leaves the session live
//! with exactly one CANCEL on the control queue.

use std::{collections::BTreeSet, time::Instant};

use chrono::{Duration, Utc};
use tokio::sync::{mpsc, oneshot};
use tunnel_catalog::{AuthenticatedConsumer, DeviceIdentity, GrantSnapshot, PermissionSet};
use tunnel_protocol::ControlMessage;
use uuid::Uuid;

use super::stream_identity_tests::admitted_control_actor;
use super::{
    CANCEL_UNDELIVERABLE, ControlOutbound, EchoOutcome, PendingEcho, RelayActor, SessionKey,
    queue_control,
};

fn cancel_fixture(
    session_id: &str,
) -> (
    RelayActor,
    mpsc::Receiver<ControlOutbound>,
    SessionKey,
    oneshot::Receiver<EchoOutcome>,
) {
    let now = Utc::now();
    let tenant_id = Uuid::from_u128(1);
    let device_id = Uuid::from_u128(2);
    let service_id = Uuid::from_u128(3);
    let principal_id = Uuid::from_u128(4);
    let key = SessionKey {
        tenant_id,
        device_id,
        session_id: session_id.to_owned(),
        epoch: 1,
    };
    let identity = DeviceIdentity {
        tenant_id,
        device_id,
        owner_user_id: principal_id,
        credential_id: Uuid::from_u128(5),
        spki_fingerprint: "cancel-spki".to_owned(),
        credential_not_before: now - Duration::minutes(1),
        expires_at: now + Duration::minutes(1),
        credential_revoked_at: None,
        device_active: true,
        credential_active: true,
        device_version: 1,
        owner_epoch: 1,
        last_seen_at: Some(now),
    };
    let (mut actor, registration) = admitted_control_actor(identity, key.clone());
    let (response_tx, response_rx) = oneshot::channel();
    let pending = PendingEcho {
        operation_id: "cancel-op".to_owned(),
        forget: super::UnaryForgetIdentity::default(),
        send_sequence: 1,
        response: response_tx,
        response_sequence: 0,
        response_body: Vec::new(),
        challenge_id: None,
        consumer: AuthenticatedConsumer {
            tenant_id,
            principal_id,
        },
        service_id,
        grant: GrantSnapshot {
            tenant_id,
            principal_id,
            device_id,
            service_id,
            revision: 1,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            valid_until: now + Duration::minutes(1),
            read_started_at: now,
        },
        consumer_expires_at: now + Duration::minutes(1),
        body: Vec::new(),
        created_at: Instant::now(),
        dispatched: true,
        authorization_in_flight: false,
        deferred_authorization: None,
        abandon: super::UnaryAbandon::default(),
    };
    actor
        .sessions
        .get_mut(&key.scope())
        .expect("admitted session")
        .pending
        .insert(7, pending);
    (actor, registration.rx, key, response_rx)
}

fn drain_cancels(rx: &mut mpsc::Receiver<ControlOutbound>, stream_id: u64) -> usize {
    let mut cancels = 0;
    while let Ok(outbound) = rx.try_recv() {
        let ControlOutbound::Text(mut text) = outbound else {
            continue;
        };
        let message = super::wire::parse_control(text.as_bytes()).expect("control message decodes");
        text.release();
        if let ControlMessage::Cancel(cancel) = message
            && cancel.stream_id == stream_id
            && cancel.operation_id == "cancel-op"
        {
            cancels += 1;
        }
    }
    cancels
}

#[tokio::test]
async fn undeliverable_cancel_fences_the_session_with_a_typed_reason() {
    let (mut actor, mut control_rx, key, response_rx) = cancel_fixture("cancel-fenced");
    // Fill the bounded control queue through the real enqueue path so the
    // CANCEL is refused at the slot bound rather than by a synthetic error.
    let (control_tx, queue_budget, capacity) = {
        let session = actor.sessions.get(&key.scope()).expect("session");
        (
            session.control_tx.clone(),
            session.queue_budget.clone(),
            session.control_tx.max_capacity(),
        )
    };
    // Filler messages target an unrelated stream so the CANCEL count below
    // only sees the cancelled operation.
    let filler = super::wire::encode_control_message(&super::wire::cancel(
        &key.session_id,
        key.epoch,
        99,
        "filler-op",
    ))
    .expect("encode filler control message");
    for _ in 0..capacity {
        queue_control(&control_tx, &queue_budget, filler.clone())
            .expect("filler control message enqueues below the bound");
    }
    assert!(
        queue_control(&control_tx, &queue_budget, filler.clone()).is_err(),
        "the control queue must be at its bound before the cancellation"
    );

    actor
        .inbound_control(
            key.clone(),
            super::wire::cancel(&key.session_id, key.epoch, 7, "cancel-op"),
        )
        .await;

    assert!(
        !actor.sessions.contains_key(&key.scope()),
        "a CANCEL that cannot enter the control queue must fence the session"
    );
    assert_eq!(
        actor
            .session_terminal_events
            .back()
            .map(|event| event.reason),
        Some(CANCEL_UNDELIVERABLE),
        "the fence must carry the typed closed-vocabulary reason"
    );
    assert_eq!(
        super::runtime::terminal_close_reason(CANCEL_UNDELIVERABLE),
        CANCEL_UNDELIVERABLE,
        "the reason must be on the terminal-close allowlist, not redacted to OTHER"
    );
    assert!(
        matches!(
            response_rx.await,
            Ok(EchoOutcome::Failure {
                code: "CANCELLED",
                execution: "unknown",
            })
        ),
        "the consumer keeps its unknown outcome; fencing never claims a definite result"
    );
    assert_eq!(
        drain_cancels(&mut control_rx, 7),
        0,
        "no CANCEL was delivered, which is exactly why the session fenced"
    );
}

#[tokio::test]
async fn deliverable_cancel_leaves_the_session_live_and_sends_cancel_once() {
    let (mut actor, mut control_rx, key, response_rx) = cancel_fixture("cancel-live");

    actor
        .inbound_control(
            key.clone(),
            super::wire::cancel(&key.session_id, key.epoch, 7, "cancel-op"),
        )
        .await;

    let session = actor
        .sessions
        .get(&key.scope())
        .expect("a delivered CANCEL must leave the session live");
    assert!(!session.closed);
    assert!(
        !session.pending.contains_key(&7),
        "the cancelled operation leaves the pending set"
    );
    assert!(
        actor.session_terminal_events.is_empty(),
        "a delivered CANCEL records no terminal event"
    );
    assert!(matches!(
        response_rx.await,
        Ok(EchoOutcome::Failure {
            code: "CANCELLED",
            execution: "unknown",
        })
    ));
    assert_eq!(
        drain_cancels(&mut control_rx, 7),
        1,
        "exactly one CANCEL reaches the device"
    );
    // A repeated CANCEL for an operation that is no longer pending is a
    // no-op: no second CANCEL and no fence.
    actor
        .inbound_control(
            key.clone(),
            super::wire::cancel(&key.session_id, key.epoch, 7, "cancel-op"),
        )
        .await;
    assert!(actor.sessions.contains_key(&key.scope()));
    assert_eq!(drain_cancels(&mut control_rx, 7), 0);
}
