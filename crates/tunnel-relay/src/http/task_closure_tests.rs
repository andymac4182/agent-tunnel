//! EC-061 closure half: the control, data and consumer adapter task bodies
//! must each report a bounded lifecycle stage and cause, recorded before the
//! owner state that tuple refers to is unregistered.
//!
//! The ordering half (803520b) put an `OwnerUnregisterEvent` tombstone on the
//! same diagnostic clock the fault tuples use.  These regressions close the
//! other half by driving the real exit of each task body and asserting the
//! *same* predicate that half established:
//!
//! ```text
//! closure.sequence < unregister.sequence
//! ```
//!
//! which holds only if the closure's `record_closure` released the shared
//! diagnostics mutex before the unregister's `stamp` acquired it, and hence
//! before the removal that follows that stamp in the actor's program order.
//!
//! What these tests do and do not prove is stated exactly.
//!
//! * They drive `finish_control_task`, `finish_data_task` and
//!   `finish_consumer_task` — the single exit each task body funnels through.
//!   The record and the unregister hand-off live in one function there, so
//!   the ordering these assertions check is the production ordering, not a
//!   re-implementation of it.
//! * They do NOT prove the cause selection inside each socket loop.  Each
//!   break sets `closure_cause` before breaking; that is placement, and a
//!   mutation that mislabels one break is not detectable here.  Driving every
//!   break of the control and data loops needs a real mTLS device socket,
//!   because `TlsIdentity` has no constructor outside the transport crate's
//!   completed handshake.  That is a harness concern, recorded as a limit
//!   rather than implied away.
//! * They do NOT prove stamp placement relative to the removal.  As the
//!   ordering half already recorded, a mutation that relocates a stamp to
//!   after the removal it marks is not detectable by a single-threaded test:
//!   nothing can interleave a record into the window such a relocation opens.
//!   Stamp-before-removal stays an analytical property argued at the call
//!   sites.
//!
//! `predicate_can_fail` is the permanent negative control: a closure recorded
//! after the unregister lands on the far side of the same tombstone, so the
//! predicate above is shown to be capable of failing rather than vacuous.

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use chrono::{Duration as ChronoDuration, Utc};
use rcgen::KeyPair;
use tokio::time::timeout;
use tunnel_catalog::{
    ApprovedJwk, AuthenticatedConsumer, Catalog, CatalogFixture, CredentialRecord, FixtureDevice,
    GrantSpec, MembershipRecord, MembershipRole, MemoryCatalog, OidcConfig, OidcVerifier,
    PermissionSet, PrincipalIdentity, ServiceSpec, TenantRecord, UserRecord,
};
use tunnel_protocol::{ControlMessage, Hello};
use uuid::Uuid;

use super::{finish_consumer_task, finish_control_task, finish_data_task, wire};
use crate::{
    actor::{CarrierKey, RelayHandle, SessionKey},
    config::RelayOptions,
    peer_fault_diagnostics::{
        TaskClosureCause, TaskClosureEventSnapshot, TaskClosureScope, TaskClosureStage,
    },
    runtime::{OwnerUnregisterEvent, OwnerUnregisterKind, RelaySnapshot},
};

const ISSUER: &str = "https://task-closure-issuer.example";
const AUDIENCE: &str = "task-closure-audience";
const SUBJECT: &str = "task-closure-consumer";
const DEVICE_SPKI: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const BUDGET: Duration = Duration::from_secs(5);

fn tenant_id() -> Uuid {
    Uuid::from_u128(0x6100_0000_0000_0000_0000_0000_0000_0001)
}

fn user_id() -> Uuid {
    Uuid::from_u128(0x6100_0000_0000_0000_0000_0000_0000_0002)
}

fn device_id() -> Uuid {
    Uuid::from_u128(0x6100_0000_0000_0000_0000_0000_0000_0003)
}

fn service_id() -> Uuid {
    Uuid::from_u128(0x6100_0000_0000_0000_0000_0000_0000_0004)
}

fn oidc_verifier() -> Arc<OidcVerifier> {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("OIDC signing key");
    let approved = ApprovedJwk::from_ed25519_der("task-closure", key.public_key_raw())
        .expect("OIDC verification key");
    let config =
        OidcConfig::new(ISSUER, [AUDIENCE.to_owned()], vec![approved]).expect("OIDC config");
    Arc::new(OidcVerifier::new(config).expect("OIDC verifier"))
}

fn catalog_fixture() -> CatalogFixture {
    let now = Utc::now();
    CatalogFixture {
        tenants: vec![TenantRecord {
            tenant_id: tenant_id(),
            display_name: "task-closure tenant".to_owned(),
            active: true,
        }],
        users: vec![UserRecord {
            user_id: user_id(),
            display_name: "task-closure consumer".to_owned(),
        }],
        identities: vec![PrincipalIdentity {
            issuer: ISSUER.to_owned(),
            subject: SUBJECT.to_owned(),
            user_id: user_id(),
        }],
        memberships: vec![MembershipRecord {
            tenant_id: tenant_id(),
            user_id: user_id(),
            role: MembershipRole::Member,
            active: true,
        }],
        devices: vec![FixtureDevice {
            tenant_id: tenant_id(),
            device_id: device_id(),
            owner_user_id: user_id(),
            display_name: "task-closure device".to_owned(),
            active: true,
            last_seen_at: Some(now),
        }],
        credentials: vec![CredentialRecord {
            tenant_id: tenant_id(),
            device_id: device_id(),
            credential_id: Uuid::from_u128(0x6100_0000_0000_0000_0000_0000_0000_0005),
            spki_fingerprint: DEVICE_SPKI.to_owned(),
            serial: Some("task-closure-device".to_owned()),
            not_before: now - ChronoDuration::seconds(1),
            expires_at: now + ChronoDuration::minutes(5),
            revoked_at: None,
            active: true,
        }],
        services: vec![ServiceSpec {
            tenant_id: tenant_id(),
            device_id: device_id(),
            service_id: service_id(),
            service_type: "echo".to_owned(),
            display_name: "Echo".to_owned(),
            capabilities: serde_json::json!({"operations": ["echo:invoke"]}),
            version: 1,
            active: true,
        }],
        grants: vec![GrantSpec {
            tenant_id: tenant_id(),
            principal_id: user_id(),
            device_id: device_id(),
            service_id: service_id(),
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            expires_at: Some(now + ChronoDuration::minutes(5)),
            active: true,
        }],
    }
}

/// A relay with one admitted device session and one attached data carrier:
/// exactly the owner state the three task bodies unregister at their exits.
struct Stage {
    handle: RelayHandle,
    catalog: Arc<MemoryCatalog>,
    key: SessionKey,
    carrier: CarrierKey,
    _control_rx: tokio::sync::mpsc::Receiver<crate::actor::ControlOutbound>,
    _data_rx: tokio::sync::mpsc::Receiver<crate::actor::DataOutbound>,
}

impl Stage {
    async fn start(label: &str) -> Self {
        let catalog = Arc::new(MemoryCatalog::new());
        catalog
            .seed_fixture(&catalog_fixture())
            .await
            .expect("seed task-closure catalog");
        let mut options = RelayOptions::new(oidc_verifier());
        options.node_id = format!("{label}-node");
        options.boot_id = format!("{label}-boot");
        let handle = RelayHandle::spawn(options, catalog.clone());

        let device = catalog
            .resolve_device(DEVICE_SPKI, Utc::now())
            .await
            .expect("resolve device")
            .expect("device identity");
        let mut hello = Hello::new(format!("{label}-hello"), device_id().to_string(), 1, 0);
        hello.features = vec![
            wire::M1_PROFILE_FEATURE.to_owned(),
            wire::ORDERED_ROTATION_FEATURE.to_owned(),
            "echo".to_owned(),
        ];
        let registration = handle
            .register_forwarded_control(device, DEVICE_SPKI.to_owned(), hello)
            .await
            .expect("admit control session");
        let key = registration.key.clone();
        let ticket = match wire::parse_control(registration.welcome.as_bytes()).expect("WELCOME") {
            ControlMessage::Welcome(welcome) => welcome.attachment_ticket,
            other => panic!("unexpected registration response: {other:?}"),
        };
        // Owner admission advances the catalog owner epoch; resolve again so
        // the carrier attaches behind the same generation fence a real data
        // socket proves.
        let data_device = catalog
            .resolve_device(DEVICE_SPKI, Utc::now())
            .await
            .expect("resolve data device")
            .expect("data device identity");
        let data_registration = handle
            .attach_forwarded_data(data_device, DEVICE_SPKI.to_owned(), ticket)
            .await
            .expect("attach data carrier");
        let carrier = data_registration.carrier.clone();

        Self {
            handle,
            catalog,
            key,
            carrier,
            _control_rx: registration.rx,
            _data_rx: data_registration.rx,
        }
    }

    async fn snapshot(&self) -> RelaySnapshot {
        timeout(BUDGET, self.handle.snapshot())
            .await
            .expect("snapshot within its bound")
            .expect("relay snapshot")
    }

    async fn shutdown(self) {
        let _ = self.handle.shutdown().await;
    }
}

/// The closure tuple this stage's session recorded at the named stage.
fn closure_for<'a>(
    snapshot: &'a RelaySnapshot,
    key: &SessionKey,
    stage: TaskClosureStage,
) -> &'a TaskClosureEventSnapshot {
    snapshot
        .peer_fault_diagnostics
        .closures
        .iter()
        .find(|closure| {
            closure.stage == stage
                && closure.session_id == key.session_id
                && closure.epoch == key.epoch
                && closure.device_id == key.device_id
        })
        .unwrap_or_else(|| {
            panic!(
                "no {} closure tuple was recorded for session {}; recorded: {:?}",
                stage.as_str(),
                key.session_id,
                snapshot.peer_fault_diagnostics.closures,
            )
        })
}

/// The unregister tombstone this stage's session produced for `kind`.
fn unregister_for<'a>(
    snapshot: &'a RelaySnapshot,
    key: &SessionKey,
    kind: OwnerUnregisterKind,
) -> &'a OwnerUnregisterEvent {
    snapshot
        .owner_unregister_events
        .iter()
        .find(|event| {
            event.kind == kind
                && event.session_id == key.session_id
                && event.epoch == key.epoch
                && event.device_id == key.device_id.to_string()
        })
        .unwrap_or_else(|| {
            panic!(
                "no {} unregister tombstone was stamped for session {}; recorded: {:?}",
                kind.as_str(),
                key.session_id,
                snapshot.owner_unregister_events,
            )
        })
}

/// The whole point of the row, in one predicate.
fn assert_sequenced_before(
    closure: &TaskClosureEventSnapshot,
    unregister: &OwnerUnregisterEvent,
    leg: &str,
) {
    assert!(
        closure.sequence < unregister.sequence,
        "{leg}: closure tuple ({}, {}) at sequence {} must be recorded before the {} unregister it \
         refers to, which is stamped at sequence {}",
        closure.stage.as_str(),
        closure.cause.as_str(),
        closure.sequence,
        unregister.kind.as_str(),
        unregister.sequence,
    );
    assert!(
        closure.observed_at_ms <= unregister.unregistered_at_ms,
        "{leg}: closure timestamp {} must not follow the unregister timestamp {}",
        closure.observed_at_ms,
        unregister.unregistered_at_ms,
    );
}

#[tokio::test]
async fn control_task_closure_is_recorded_before_the_session_unregister() {
    let stage = Stage::start("control-closure").await;
    let key = stage.key.clone();
    let mut cleanup = stage.handle.control_cleanup_guard(key.clone());

    // The production exit of `handle_control`: record, then hand the close to
    // the actor.  `disconnect_control` closes the session, which the ordering
    // half stamps as `OwnerUnregisterKind::Session`.
    finish_control_task(
        &stage.handle,
        key.clone(),
        TaskClosureCause::PeerClosed,
        &mut cleanup,
    )
    .await;

    // Commands are one ordered mailbox, so the snapshot that follows is taken
    // after the disconnect was applied.  Nothing here polls or races.
    let snapshot = stage.snapshot().await;
    let closure = closure_for(&snapshot, &key, TaskClosureStage::Control);
    assert_eq!(closure.cause, TaskClosureCause::PeerClosed);
    assert_eq!(closure.tenant_id, tenant_id());
    assert_eq!(
        closure.stream_id, None,
        "the control task unregisters a session, not one stream"
    );
    let unregister = unregister_for(&snapshot, &key, OwnerUnregisterKind::Session);
    assert_sequenced_before(closure, unregister, "control");

    // A closure is a lifecycle end, never a peer fault: it must not have
    // moved any fault counter or the fault ring.
    assert_eq!(snapshot.peer_fault_diagnostics.fault_count, 0);
    assert!(snapshot.peer_fault_diagnostics.recent.is_empty());
    assert_eq!(
        snapshot
            .peer_fault_diagnostics
            .closure_stage_counts
            .get("control"),
        Some(&1),
    );
    stage.shutdown().await;
}

#[tokio::test]
async fn data_task_closure_is_recorded_before_the_data_carrier_unregister() {
    let stage = Stage::start("data-closure").await;
    let key = stage.key.clone();
    let carrier = stage.carrier.clone();
    let mut cleanup = stage.handle.data_cleanup_guard(carrier.clone());

    // The production exit of `handle_data`.  `disconnect_data` drops the
    // active carrier, stamped as `OwnerUnregisterKind::DataCarrier`.
    finish_data_task(
        &stage.handle,
        carrier,
        TaskClosureCause::ServerClose,
        &mut cleanup,
    )
    .await;

    let snapshot = stage.snapshot().await;
    let closure = closure_for(&snapshot, &key, TaskClosureStage::Data);
    assert_eq!(closure.cause, TaskClosureCause::ServerClose);
    let unregister = unregister_for(&snapshot, &key, OwnerUnregisterKind::DataCarrier);
    assert_sequenced_before(closure, unregister, "data");

    assert_eq!(snapshot.peer_fault_diagnostics.fault_count, 0);
    assert_eq!(
        snapshot
            .peer_fault_diagnostics
            .closure_stage_counts
            .get("data"),
        Some(&1),
    );
    stage.shutdown().await;
}

#[tokio::test]
async fn consumer_task_closure_is_recorded_before_the_consumer_stream_unregister() {
    let stage = Stage::start("consumer-closure").await;
    let key = stage.key.clone();
    let consumer = AuthenticatedConsumer {
        tenant_id: tenant_id(),
        principal_id: user_id(),
    };
    let now = Utc::now();
    let grant = stage
        .catalog
        .authorize(&consumer, device_id(), service_id(), now, now)
        .await
        .expect("authorize consumer")
        .expect("grant snapshot");
    let registration = stage
        .handle
        .open_echo_stream(
            consumer,
            device_id(),
            service_id(),
            grant,
            now + ChronoDuration::minutes(1),
        )
        .await
        .expect("open consumer stream");
    let stream_id = registration.stream_id;
    let operation_id = registration.operation_id.clone();
    let mut cleanup =
        stage
            .handle
            .echo_cleanup_guard(key.clone(), stream_id, operation_id.clone(), None);

    // The production exit of `handle_consumer_stream`.  The close releases
    // this stream's owner-side registration, stamped as
    // `OwnerUnregisterKind::ConsumerStream`.
    finish_consumer_task(
        &stage.handle,
        key.clone(),
        stream_id,
        operation_id,
        None,
        TaskClosureCause::StreamClosed,
        &mut cleanup,
    )
    .await;

    let snapshot = stage.snapshot().await;
    let closure = closure_for(&snapshot, &key, TaskClosureStage::ConsumerStream);
    assert_eq!(closure.cause, TaskClosureCause::StreamClosed);
    assert_eq!(
        closure.stream_id,
        Some(stream_id),
        "the consumer adapter unregisters one stream inside the session",
    );
    let unregister = unregister_for(&snapshot, &key, OwnerUnregisterKind::ConsumerStream);
    assert_sequenced_before(closure, unregister, "consumer");

    assert_eq!(snapshot.peer_fault_diagnostics.fault_count, 0);
    assert_eq!(
        snapshot
            .peer_fault_diagnostics
            .closure_stage_counts
            .get("consumer_stream"),
        Some(&1),
    );
    stage.shutdown().await;
}

#[tokio::test]
async fn the_ordering_predicate_can_fail() {
    // Permanent negative control.  If this ever passes with the record taken
    // after the unregister, the three assertions above prove nothing.
    let stage = Stage::start("closure-negative").await;
    let key = stage.key.clone();
    let mut cleanup = stage.handle.control_cleanup_guard(key.clone());

    finish_control_task(
        &stage.handle,
        key.clone(),
        TaskClosureCause::PeerClosed,
        &mut cleanup,
    )
    .await;
    let ordered = stage.snapshot().await;
    let unregister = unregister_for(&ordered, &key, OwnerUnregisterKind::Session).clone();

    // Now record a second tuple deliberately *after* that unregister.
    stage.handle.record_task_closure(
        &TaskClosureScope {
            tenant_id: key.tenant_id,
            device_id: key.device_id,
            session_id: key.session_id.clone(),
            epoch: key.epoch,
            stream_id: None,
        },
        TaskClosureStage::Control,
        TaskClosureCause::ServerClose,
    );
    let after = stage.snapshot().await;
    let late = after
        .peer_fault_diagnostics
        .closures
        .iter()
        .find(|closure| closure.cause == TaskClosureCause::ServerClose)
        .expect("the late closure tuple was recorded");
    assert!(
        late.sequence > unregister.sequence,
        "a tuple recorded after the unregister must land on the far side of the same tombstone: \
         tuple {} vs unregister {}",
        late.sequence,
        unregister.sequence,
    );
    stage.shutdown().await;
}
