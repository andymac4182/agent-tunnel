//! Real-socket stage for EC-036: a public consumer WebSocket client abandons
//! its upgrade while the owner-side OPEN is still pending admission.
//!
//! The consumer route runs on a plain loopback TCP listener through Axum and
//! Hyper, so the abandonment crosses the real handler/upgrade boundary: the
//! fixture-only upgrade barrier holds the handler after admission and before
//! the 101 is constructed, the raw TCP client disconnects, and the relay's
//! terminal cleanup guard reclaims the exact registration.  A fake connector
//! (the forwarded control/data registrations) then proves the late owner
//! outcome: an exact REJECTED reclaims the reservation with no-stream
//! evidence, and an exact OPENED produces exactly one real FIN and one
//! terminal result.  Consumer TLS is not part of this stage; the transport
//! crate covers it separately.

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use axum::{Router, routing::get};
use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rcgen::KeyPair;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::{Semaphore, mpsc},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{
    ApprovedJwk, Catalog, CatalogFixture, CredentialRecord, FixtureDevice, GrantSpec,
    MembershipRecord, MembershipRole, MemoryCatalog, OidcConfig, OidcVerifier, PermissionSet,
    PrincipalIdentity, ServiceSpec, TenantRecord, UserRecord,
};
use tunnel_protocol::{
    ControlMessage, Frame, FrameKind, Hello, rotation_control::ResumeDirectionState,
    rotation_control::TerminalState,
};
use uuid::Uuid;

use super::{
    ConsumerUpgradeBarrier, ECHO_STREAM_SUBPROTOCOL, HttpState, ScopedAdmission, echo_stream, wire,
};
use crate::{
    actor::{CarrierKey, ControlOutbound, DataOutbound, RelayHandle, SessionKey},
    config::RelayOptions,
    runtime::RelaySnapshot,
};

const ISSUER: &str = "https://pending-open-issuer.example";
const AUDIENCE: &str = "pending-open-audience";
const SUBJECT: &str = "pending-open-consumer";
const DEVICE_SPKI: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const POLL_BUDGET: Duration = Duration::from_secs(5);

fn tenant_id() -> Uuid {
    Uuid::from_u128(0x3600_0000_0000_0000_0000_0000_0000_0001)
}

fn user_id() -> Uuid {
    Uuid::from_u128(0x3600_0000_0000_0000_0000_0000_0000_0002)
}

fn device_id() -> Uuid {
    Uuid::from_u128(0x3600_0000_0000_0000_0000_0000_0000_0003)
}

fn service_id() -> Uuid {
    Uuid::from_u128(0x3600_0000_0000_0000_0000_0000_0000_0004)
}

#[derive(serde::Serialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    exp: usize,
    scope: String,
}

fn oidc_fixture() -> (Arc<OidcVerifier>, String) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("OIDC signing key");
    let approved = ApprovedJwk::from_ed25519_der("pending-open", key.public_key_raw())
        .expect("OIDC verification key");
    let config =
        OidcConfig::new(ISSUER, [AUDIENCE.to_owned()], vec![approved]).expect("OIDC config");
    let verifier = Arc::new(OidcVerifier::new(config).expect("OIDC verifier"));
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("pending-open".to_owned());
    let claims = Claims {
        iss: ISSUER.to_owned(),
        sub: SUBJECT.to_owned(),
        aud: AUDIENCE.to_owned(),
        exp: (Utc::now().timestamp() + 60) as usize,
        scope: crate::ECHO_OPERATION.to_owned(),
    };
    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_ed_der(key.serialized_der()),
    )
    .expect("OIDC token");
    (verifier, token)
}

fn catalog_fixture() -> CatalogFixture {
    let now = Utc::now();
    CatalogFixture {
        tenants: vec![TenantRecord {
            tenant_id: tenant_id(),
            display_name: "pending-open tenant".to_owned(),
            active: true,
        }],
        users: vec![UserRecord {
            user_id: user_id(),
            display_name: "pending-open consumer".to_owned(),
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
            display_name: "pending-open device".to_owned(),
            active: true,
            last_seen_at: Some(now),
        }],
        credentials: vec![CredentialRecord {
            tenant_id: tenant_id(),
            device_id: device_id(),
            credential_id: Uuid::from_u128(0x3600_0000_0000_0000_0000_0000_0000_0005),
            spki_fingerprint: DEVICE_SPKI.to_owned(),
            serial: Some("pending-open-device".to_owned()),
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

fn drain_control(rx: &mut mpsc::Receiver<ControlOutbound>) -> Vec<ControlMessage> {
    let mut messages = Vec::new();
    while let Ok(item) = rx.try_recv() {
        if let ControlOutbound::Text(text) = item {
            let (text, mut charge) = text.into_parts();
            charge.release();
            messages.push(wire::parse_control(text.as_bytes()).expect("control message decodes"));
        }
    }
    messages
}

fn drain_data(rx: &mut mpsc::Receiver<DataOutbound>) -> Vec<Frame> {
    let mut frames = Vec::new();
    while let Ok(item) = rx.try_recv() {
        match item {
            DataOutbound::Binary(bytes) => {
                let (bytes, mut charge) = bytes.into_parts();
                charge.release();
                frames.push(Frame::decode(&bytes).expect("data frame decodes"));
            }
            DataOutbound::Barrier(done) => {
                let _ = done.send(());
            }
            DataOutbound::Close => {}
        }
    }
    frames
}

async fn wait_snapshot<F>(handle: &RelayHandle, what: &str, mut ready: F) -> RelaySnapshot
where
    F: FnMut(&RelaySnapshot) -> bool,
{
    timeout(POLL_BUDGET, async {
        loop {
            let snapshot = handle.snapshot().await.expect("relay snapshot");
            if ready(&snapshot) {
                break snapshot;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}: snapshot deadline exceeded"))
}

fn only_stream(snapshot: &RelaySnapshot) -> Option<&crate::runtime::RelayStreamSnapshot> {
    let session = snapshot.sessions.first()?;
    (session.streams.len() == 1).then(|| &session.streams[0])
}

/// Everything the abandonment leaves behind: the live owner handle, the
/// fake connector's queues, the exact OPEN identity, and the HTTP admission
/// semaphore whose permit the abandoned handler must have released.
struct AbandonedUpgradeStage {
    handle: RelayHandle,
    key: SessionKey,
    carrier: CarrierKey,
    control_rx: mpsc::Receiver<ControlOutbound>,
    data_rx: mpsc::Receiver<DataOutbound>,
    open: tunnel_protocol::Open,
    admission: Arc<Semaphore>,
    max_permits: usize,
    barrier: Arc<ConsumerUpgradeBarrier>,
    server_cancel: CancellationToken,
    server_task: JoinHandle<()>,
}

impl AbandonedUpgradeStage {
    /// Bring up the owner, one M2 device session, the public consumer route
    /// on a loopback listener, then run the abandonment through real sockets
    /// and prove the pre-admission invariants before returning.
    async fn run(label: &str) -> Self {
        let catalog = Arc::new(MemoryCatalog::new());
        catalog
            .seed_fixture(&catalog_fixture())
            .await
            .expect("seed pending-open catalog");
        let (oidc, token) = oidc_fixture();
        let mut options = RelayOptions::new(oidc.clone());
        options.node_id = format!("{label}-node");
        options.boot_id = format!("{label}-boot");
        let limits = options.limits.clone();
        let handle = RelayHandle::spawn(options, catalog.clone());

        // The fake connector: forwarded control and data registrations keep
        // the exact queues a real device socket would drain.
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
            .expect("admit M2 control session");
        let key = registration.key.clone();
        let mut control_rx = registration.rx;
        let ticket = match wire::parse_control(registration.welcome.as_bytes()).expect("WELCOME") {
            ControlMessage::Welcome(welcome) => welcome.attachment_ticket,
            other => panic!("unexpected registration response: {other:?}"),
        };
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
        let mut data_rx = data_registration.rx;
        assert!(
            drain_control(&mut control_rx)
                .iter()
                .all(|message| matches!(message, ControlMessage::DataReady(_))),
            "only DATA_READY precedes the consumer OPEN"
        );

        // The public consumer route with the fixture-only upgrade barrier.
        let barrier = Arc::new(ConsumerUpgradeBarrier::default());
        assert!(barrier.arm());
        let max_permits = limits.max_pending_operations;
        let admission = Arc::new(Semaphore::new(max_permits));
        let state = HttpState {
            handle: handle.clone(),
            catalog: Some(catalog.clone()),
            oidc: Some(oidc),
            limits: limits.clone(),
            admission: admission.clone(),
            scoped_admission: ScopedAdmission::new(
                limits.max_pending_operations_per_owner,
                limits.max_pending_operations,
            ),
            peer: None,
            consumer_upgrade_barrier: Some(barrier.clone()),
            peer_admission_barrier: None,
            control_attach_barrier: None,
            http_forward: None,
        };
        let router = Router::new()
            .route(
                "/v1/devices/{device}/services/{service}/stream",
                get(echo_stream),
            )
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let address = listener.local_addr().expect("listener address");
        let server_cancel = CancellationToken::new();
        let shutdown = server_cancel.clone();
        let server_task = tokio::spawn(async move {
            axum::serve(listener, router.into_make_service())
                .with_graceful_shutdown(async move { shutdown.cancelled().await })
                .await
                .expect("consumer route server");
        });

        let baseline = handle.snapshot().await.expect("baseline snapshot");
        assert_eq!(baseline.lifetime_application_dispatches, 0);
        assert!(baseline.stream_terminal_events.is_empty());
        assert!(baseline.sessions[0].streams.is_empty());

        // A real WebSocket upgrade request; the client never completes it.
        let mut client = TcpStream::connect(address)
            .await
            .expect("connect consumer client");
        let request = format!(
            "GET /v1/devices/{}/services/{}/stream HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Protocol: {ECHO_STREAM_SUBPROTOCOL}\r\n\
             Authorization: Bearer {token}\r\n\
             \r\n",
            device_id(),
            service_id(),
        );
        client
            .write_all(request.as_bytes())
            .await
            .expect("write upgrade request");
        timeout(POLL_BUDGET, barrier.wait_reached())
            .await
            .expect("upgrade barrier reached");
        assert_eq!(barrier.hit_count(), 1);
        assert!(barrier.is_held());

        // Held after admission and before the 101: exactly one pending
        // registration, unclaimed by Axum, with no sequence state, and the
        // relay-global admission permit still owned by the handler.
        let held = wait_snapshot(&handle, "held registration", |snapshot| {
            only_stream(snapshot).is_some()
        })
        .await;
        let held_stream = only_stream(&held).expect("held stream").clone();
        assert!(!held_stream.admission_claimed);
        assert!(!held_stream.terminal);
        assert_eq!(held_stream.last_emitted_relay_to_connector, 0);
        assert_eq!(held_stream.peer_acked_relay_to_connector, 0);
        assert_eq!(held_stream.recv_contiguous_connector_to_relay, 0);
        assert_eq!(held_stream.queue_bytes, 0);
        assert_eq!(held.lifetime_application_dispatches, 0);
        assert!(held.stream_terminal_events.is_empty());
        assert_eq!(admission.available_permits(), max_permits - 1);
        let open = match drain_control(&mut control_rx).as_slice() {
            [ControlMessage::Open(open)] => open.clone(),
            other => panic!("exactly one OPEN must be queued while held: {other:?}"),
        };
        assert_eq!(open.stream_id, held_stream.stream_id);
        assert_eq!(open.operation_id, held_stream.operation_id);
        assert_eq!(open.session_id, key.session_id);
        assert_eq!(open.epoch, key.epoch);
        assert!(drain_data(&mut data_rx).is_empty());

        // The consumer abandons the upgrade while the OPEN is pending; then
        // the handler is released.
        drop(client);
        barrier.release();
        let abandoned = wait_snapshot(&handle, "abandoned registration", |snapshot| {
            only_stream(snapshot).is_some_and(|stream| stream.admission_claimed)
                && snapshot.sessions[0].queue_bytes == 0
        })
        .await;
        let abandoned_stream = only_stream(&abandoned).expect("abandoned stream");
        assert_eq!(abandoned_stream.stream_id, open.stream_id);
        assert_eq!(abandoned_stream.operation_id, open.operation_id);
        assert!(
            !abandoned_stream.terminal,
            "abandonment before admission must not create terminal state"
        );
        assert_eq!(abandoned_stream.last_emitted_relay_to_connector, 0);
        assert_eq!(abandoned_stream.queue_bytes, 0);
        assert_eq!(abandoned.lifetime_application_dispatches, 0);
        assert!(abandoned.stream_terminal_events.is_empty());
        assert!(
            drain_data(&mut data_rx).is_empty(),
            "no FIN/RESET may reach the connector before admission"
        );
        assert!(
            drain_control(&mut control_rx).is_empty(),
            "no FORGET before the owner outcome"
        );
        timeout(POLL_BUDGET, async {
            while admission.available_permits() != max_permits {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the abandoned handler releases the admission permit");
        assert_eq!(abandoned.lifetime_consumer_chunk_reads, 0);

        Self {
            handle,
            key,
            carrier,
            control_rx,
            data_rx,
            open,
            admission,
            max_permits,
            barrier,
            server_cancel,
            server_task,
        }
    }

    async fn shutdown(self) {
        self.server_cancel.cancel();
        timeout(POLL_BUDGET, self.server_task)
            .await
            .expect("server shutdown deadline")
            .expect("server task joins");
        self.handle.shutdown().await.expect("relay shutdown");
        assert_eq!(self.admission.available_permits(), self.max_permits);
        assert_eq!(self.barrier.hit_count(), 1);
    }
}

#[tokio::test]
async fn abandoned_public_upgrade_before_admission_is_reclaimed_by_late_rejected() {
    let mut stage = AbandonedUpgradeStage::run("ec036-real-rejected").await;
    let open = stage.open.clone();

    // A mismatched late REJECTED cannot reclaim the exact reservation.
    stage
        .handle
        .inbound_control(
            stage.key.clone(),
            ControlMessage::Rejected(tunnel_protocol::Rejected::new(
                "late-rejected-wrong-reply",
                "different-open",
                stage.key.session_id.clone(),
                stage.key.epoch,
                open.stream_id,
                open.operation_id.clone(),
                "RESOURCE_EXHAUSTED",
                "wrong reply",
            )),
        )
        .await
        .expect("deliver mismatched REJECTED");
    let retained = stage.handle.snapshot().await.expect("retained snapshot");
    assert!(only_stream(&retained).is_some_and(|stream| stream.stream_id == open.stream_id));
    assert!(drain_control(&mut stage.control_rx).is_empty());

    // The exact late REJECTED reclaims it once with no-stream evidence.
    stage
        .handle
        .inbound_control(
            stage.key.clone(),
            ControlMessage::Rejected(tunnel_protocol::Rejected::new(
                "late-rejected",
                open.message_id.clone(),
                stage.key.session_id.clone(),
                stage.key.epoch,
                open.stream_id,
                open.operation_id.clone(),
                "RESOURCE_EXHAUSTED",
                "late rejection",
            )),
        )
        .await
        .expect("deliver exact REJECTED");
    let reclaimed = wait_snapshot(&stage.handle, "reclaimed registration", |snapshot| {
        snapshot.sessions[0].streams.is_empty()
    })
    .await;
    assert_eq!(reclaimed.lifetime_application_dispatches, 0);
    assert!(reclaimed.stream_terminal_events.is_empty());
    let messages = drain_control(&mut stage.control_rx);
    assert_eq!(messages.len(), 1);
    match &messages[0] {
        ControlMessage::StreamForget(forget) => {
            assert_eq!(forget.stream_id, open.stream_id);
            assert_eq!(forget.operation_id, open.operation_id);
            assert_eq!(
                forget.final_state,
                ResumeDirectionState {
                    stream_id: open.stream_id,
                    ..ResumeDirectionState::default()
                }
            );
        }
        other => panic!("expected the owner FORGET, got {other:?}"),
    }
    assert!(drain_data(&mut stage.data_rx).is_empty());
    // The queued FORGET charge is released exactly once the connector's
    // writer takes it; nothing else remains charged to the session budget.
    let drained = stage.handle.snapshot().await.expect("drained snapshot");
    assert_eq!(drained.sessions[0].queue_bytes, 0);

    // A late duplicate and a late OPENED for the reclaimed identity are
    // bounded no-ops: nothing is re-created and nothing is dispatched.
    stage
        .handle
        .inbound_control(
            stage.key.clone(),
            ControlMessage::Opened(tunnel_protocol::Opened::new(
                "late-opened-after-forget",
                open.message_id.clone(),
                stage.key.session_id.clone(),
                stage.key.epoch,
                open.stream_id,
                open.operation_id.clone(),
                open.initial_send_window,
                open.initial_receive_window,
            )),
        )
        .await
        .expect("deliver late OPENED");
    let settled = stage.handle.snapshot().await.expect("settled snapshot");
    assert_eq!(settled.sessions.len(), 1);
    assert!(settled.sessions[0].streams.is_empty());
    assert_eq!(settled.lifetime_application_dispatches, 0);
    assert!(settled.stream_terminal_events.is_empty());
    assert!(drain_control(&mut stage.control_rx).is_empty());
    assert!(drain_data(&mut stage.data_rx).is_empty());
    stage.shutdown().await;
}

#[tokio::test]
async fn abandoned_public_upgrade_before_admission_closes_once_after_late_opened() {
    let mut stage = AbandonedUpgradeStage::run("ec036-real-opened").await;
    let open = stage.open.clone();
    let key = stage.key.clone();

    // The exact late OPENED admits the abandoned stream: exactly one real
    // FIN at sequence 1 and exactly one terminal result.
    stage
        .handle
        .inbound_control(
            key.clone(),
            ControlMessage::Opened(tunnel_protocol::Opened::new(
                "late-opened",
                open.message_id.clone(),
                key.session_id.clone(),
                key.epoch,
                open.stream_id,
                open.operation_id.clone(),
                open.initial_send_window,
                open.initial_receive_window,
            )),
        )
        .await
        .expect("deliver exact OPENED");
    let closed = wait_snapshot(&stage.handle, "late-admitted close", |snapshot| {
        only_stream(snapshot).is_some_and(|stream| stream.terminal)
    })
    .await;
    let closed_stream = only_stream(&closed).expect("closed stream");
    assert_eq!(closed_stream.stream_id, open.stream_id);
    assert_eq!(closed_stream.last_emitted_relay_to_connector, 1);
    assert_eq!(closed.lifetime_application_dispatches, 0);
    assert_eq!(closed.stream_terminal_events.len(), 1);
    let event = &closed.stream_terminal_events[0];
    assert_eq!(event.stream_id, open.stream_id);
    assert_eq!(event.operation_id, open.operation_id);
    assert_eq!(event.reason, "STREAM_CLOSED");
    assert_eq!(event.last_emitted_relay_to_connector, 1);
    let frames = drain_data(&mut stage.data_rx);
    assert_eq!(frames.len(), 1, "exactly one terminal frame");
    assert_eq!(frames[0].kind, FrameKind::Fin);
    assert_eq!(frames[0].stream_id, open.stream_id);
    assert_eq!(frames[0].sequence, 1);
    assert_eq!(frames[0].generation, stage.carrier.generation);
    assert!(drain_control(&mut stage.control_rx).is_empty());

    // A duplicate OPENED cannot produce a second FIN or terminal result.
    stage
        .handle
        .inbound_control(
            key.clone(),
            ControlMessage::Opened(tunnel_protocol::Opened::new(
                "late-opened-duplicate",
                open.message_id.clone(),
                key.session_id.clone(),
                key.epoch,
                open.stream_id,
                open.operation_id.clone(),
                open.initial_send_window,
                open.initial_receive_window,
            )),
        )
        .await
        .expect("deliver duplicate OPENED");
    let duplicate = stage.handle.snapshot().await.expect("duplicate snapshot");
    assert_eq!(duplicate.stream_terminal_events.len(), 1);
    assert!(
        only_stream(&duplicate).is_some_and(|stream| {
            stream.terminal && stream.last_emitted_relay_to_connector == 1
        })
    );
    assert!(drain_data(&mut stage.data_rx).is_empty());

    // The connector acknowledges the FIN and closes its direction; the owner
    // reclaims the tombstone exactly once with the real final cursors.
    stage
        .handle
        .inbound_data(
            stage.carrier.clone(),
            Frame::fin(key.epoch, stage.carrier.generation, open.stream_id, 1, 1)
                .encode()
                .expect("connector FIN encodes"),
        )
        .await
        .expect("deliver connector FIN");
    let reclaimed = wait_snapshot(&stage.handle, "reclaimed tombstone", |snapshot| {
        snapshot.sessions[0].streams.is_empty()
    })
    .await;
    assert_eq!(reclaimed.stream_terminal_events.len(), 1);
    assert_eq!(reclaimed.lifetime_application_dispatches, 0);
    let messages = drain_control(&mut stage.control_rx);
    assert_eq!(messages.len(), 1);
    match &messages[0] {
        ControlMessage::StreamForget(forget) => {
            assert_eq!(forget.stream_id, open.stream_id);
            assert_eq!(forget.operation_id, open.operation_id);
            assert_eq!(forget.final_state.last_emitted, 1);
            assert_eq!(forget.final_state.peer_acked, 1);
            assert_eq!(forget.final_state.send_terminal, Some(TerminalState::Fin));
        }
        other => panic!("expected the owner FORGET, got {other:?}"),
    }
    let frames = drain_data(&mut stage.data_rx);
    assert_eq!(frames.len(), 1, "the connector FIN is acknowledged once");
    assert_eq!(frames[0].kind, FrameKind::Ack);
    assert_eq!(frames[0].ack, 1);
    // Every FIN/ACK/FORGET charge was released exactly once when the fake
    // connector took ownership of it; the session budget is back to zero.
    let drained = stage.handle.snapshot().await.expect("drained snapshot");
    assert_eq!(drained.sessions[0].queue_bytes, 0);
    assert!(drained.sessions[0].streams.is_empty());
    stage.shutdown().await;
}
