//! Deterministic component regressions for the reopened M7 matrix rows
//! EC-036 (a consumer abandons its OPEN before the connector admits it) and
//! EC-041 (a device data attachment presenting a one-use ticket races a
//! control-plane generation change).
//!
//! Every scenario drives the real actor entry points with an explicit
//! interleaving: no wall-clock sleeps, no timers and no background actor loop.
//! Background attachment results are pulled from the actor mailbox and applied
//! at the exact point the race requires, so each sub-invariant is proven
//! against exact identities and counters rather than against timing.

use std::{collections::BTreeSet, sync::Arc, time::Instant};

use chrono::{DateTime, Duration, Utc};
use tokio::sync::{mpsc, oneshot};
use tunnel_catalog::{
    AttachmentTicketConsumeRequest, AttachmentTicketIssueRequest, AuthenticatedConsumer, Catalog,
    CatalogError, DeviceIdentity, GrantSnapshot, MemoryCatalog, OwnerClaimRequest, OwnerToken,
    PermissionSet, SharedCatalog,
};
use tunnel_protocol::{
    ControlMessage, Direction, Frame, FrameKind,
    rotation::{RecoveryReason, RotationPhase},
    rotation_control::{
        DataAttachmentPurpose, ResumeDirectionState, RotationAttemptIdentity, TerminalState,
    },
    sequence::{StreamSnapshot, Terminal},
};
use uuid::Uuid;

use super::{
    CarrierKey, Command, ConsumerStreamRegistration, ControlOutbound, ControlRegistration,
    DataCarrier, DataOutbound, DataRegistration, DeviceSession, M2Stream, PendingCatalogTicket,
    RelayActor, RelayError, RotationRuntime, RuntimeProfile, SessionKey, TerminalCleanup, Ticket,
    monotonic_millis,
    runtime::{self, CarrierContext},
    stream_identity_tests::{
        admitted_control_actor, session_attempt, shared_device_fixture, test_rotation_runtime,
    },
    wire,
};

const CANDIDATE_PURPOSE: &str = "rotation-candidate";

/// Decode and release every queued outbound control text.  `Close` markers are
/// dropped; tests that need them inspect the session terminal events instead.
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

/// Decode and release every queued outbound data frame.  Writer barriers are
/// acknowledged immediately so a rotation quiesce never waits on the test.
fn drain_data(rx: &mut mpsc::Receiver<DataOutbound>) -> Vec<Frame> {
    let mut frames = Vec::new();
    while let Ok(item) = rx.try_recv() {
        match item {
            DataOutbound::Binary(mut bytes) => {
                frames.push(Frame::decode(bytes.as_slice()).expect("queued data frame decodes"));
                bytes.release();
            }
            DataOutbound::Barrier(done) => {
                let _ = done.send(());
            }
            DataOutbound::Close => {}
        }
    }
    frames
}

fn count_data_ready(messages: &[ControlMessage]) -> usize {
    messages
        .iter()
        .filter(|message| matches!(message, ControlMessage::DataReady(_)))
        .count()
}

fn forgets(messages: &[ControlMessage]) -> Vec<tunnel_protocol::rotation_control::StreamForget> {
    messages
        .iter()
        .filter_map(|message| match message {
            ControlMessage::StreamForget(forget) => Some(forget.clone()),
            _ => None,
        })
        .collect()
}

fn zero_sequence_state(snapshot: &StreamSnapshot) -> bool {
    let relay = snapshot.direction(Direction::RelayToConnector);
    let connector = snapshot.direction(Direction::ConnectorToRelay);
    relay.last_emitted == 0
        && relay.peer_acked == 0
        && relay.sent_bytes == 0
        && relay.send_terminal.is_none()
        && relay.replay_floor.is_none()
        && connector.recv_contiguous == 0
        && connector.delivered_contiguous == 0
        && connector.received_bytes == 0
        && connector.receive_terminal.is_none()
        && connector.reorder_frames == 0
}

// ---------------------------------------------------------------------------
// EC-036: consumer abandons a pending OPEN before admission completes.
// ---------------------------------------------------------------------------

struct PendingOpenFixture {
    actor: RelayActor,
    control: ControlRegistration,
    data_rx: mpsc::Receiver<DataOutbound>,
    key: SessionKey,
    carrier: CarrierKey,
    consumer: AuthenticatedConsumer,
    grant: GrantSnapshot,
    device_id: Uuid,
    service_id: Uuid,
    consumer_expires_at: DateTime<Utc>,
}

impl PendingOpenFixture {
    fn new(label: &str) -> Self {
        let now = Utc::now();
        let tenant_id = Uuid::from_u128(0x3601);
        let device_id = Uuid::from_u128(0x3602);
        let principal_id = Uuid::from_u128(0x3603);
        let service_id = Uuid::from_u128(0x3604);
        let identity = DeviceIdentity {
            tenant_id,
            device_id,
            owner_user_id: principal_id,
            credential_id: Uuid::from_u128(0x3605),
            spki_fingerprint: format!("{label}-spki"),
            credential_not_before: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(5),
            credential_revoked_at: None,
            device_active: true,
            credential_active: true,
            device_version: 1,
            owner_epoch: 1,
            last_seen_at: Some(now),
        };
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: format!("{label}-session"),
            epoch: 1,
        };
        let (mut actor, control) = admitted_control_actor(identity, key.clone());
        let (data_tx, data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        let carrier = CarrierKey {
            session: key.clone(),
            generation: 1,
            connection_id: format!("{label}-data"),
        };
        let session = actor
            .sessions
            .get_mut(&key.scope())
            .expect("fixture session present");
        session.profile = RuntimeProfile::M2;
        session.connection_id = carrier.connection_id.clone();
        session.data_tx = Some(data_tx.clone());
        session.active_carrier = Some(DataCarrier {
            context: carrier.context(),
            tx: data_tx,
        });
        Self {
            actor,
            control,
            data_rx,
            key,
            carrier,
            consumer: AuthenticatedConsumer {
                tenant_id,
                principal_id,
            },
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
                valid_until: now + Duration::minutes(5),
                read_started_at: now,
            },
            device_id,
            service_id,
            consumer_expires_at: now + Duration::minutes(5),
        }
    }

    async fn open(&mut self) -> Result<ConsumerStreamRegistration, RelayError> {
        let (response, receiver) = oneshot::channel();
        self.actor.open_echo_stream(
            self.consumer.clone(),
            self.device_id,
            self.service_id,
            self.grant.clone(),
            self.consumer_expires_at,
            response,
        );
        receiver.await.expect("open registration response")
    }

    fn session(&self) -> &DeviceSession {
        self.actor
            .sessions
            .get(&self.key.scope())
            .expect("fixture session is live")
    }

    fn stream(&self, stream_id: u64) -> &M2Stream {
        self.session()
            .streams
            .get(&stream_id)
            .expect("stream is retained")
    }

    fn open_message_id(&self, stream_id: u64) -> String {
        self.stream(stream_id).open_message_id.clone()
    }

    fn budget_used(&self) -> usize {
        self.session().queue_budget.used()
    }

    /// A sibling that never saw the abandonment keeps its complete pending
    /// identity: still admitting, still claimable, no sequence state.
    fn assert_untouched_pending(&self, stream_id: u64, operation_id: &str) {
        let stream = self.stream(stream_id);
        assert_eq!(stream.operation_id, operation_id);
        assert!(stream.open_pending, "sibling OPEN must remain pending");
        assert!(!stream.registration_dropped);
        assert!(!stream.terminal);
        assert!(!stream.terminal_fin_failure);
        assert!(!stream.closed.is_cancelled());
        assert!(!stream.admission_lease.is_cancelled());
        assert_eq!(stream.budget_bytes, 0);
        assert!(zero_sequence_state(&stream.sequence.snapshot()));
    }

    async fn opened(&mut self, message_id: &str, stream_id: u64, operation_id: &str) {
        let reply_to = self.open_message_id(stream_id);
        self.actor
            .inbound_control(
                self.key.clone(),
                ControlMessage::Opened(tunnel_protocol::Opened::new(
                    message_id,
                    reply_to,
                    self.key.session_id.clone(),
                    self.key.epoch,
                    stream_id,
                    operation_id,
                    wire::M2_INITIAL_WINDOW_BYTES as u64,
                    wire::M2_INITIAL_WINDOW_BYTES as u64,
                )),
            )
            .await;
    }

    async fn rejected(
        &mut self,
        message_id: &str,
        reply_to: &str,
        stream_id: u64,
        operation_id: &str,
    ) {
        self.actor
            .inbound_control(
                self.key.clone(),
                ControlMessage::Rejected(tunnel_protocol::Rejected::new(
                    message_id,
                    reply_to,
                    self.key.session_id.clone(),
                    self.key.epoch,
                    stream_id,
                    operation_id,
                    "RESOURCE_EXHAUSTED",
                    "late owner rejection",
                )),
            )
            .await;
    }

    async fn connector_frame(&mut self, frame: Frame) {
        self.actor
            .inbound_data(self.carrier.clone(), frame.encode().expect("frame encodes"))
            .await;
    }

    /// The public handler disappeared while its OPEN was pending: the
    /// transport cleanup guard enqueues this exact identity and the actor
    /// applies it.  This is the production path for a consumer that drops
    /// before (or right after) the 101 without ever reaching the socket loop.
    async fn abandon(&mut self, stream_id: u64, operation_id: &str) {
        self.actor
            .handle_terminal_cleanup(TerminalCleanup::EchoStream {
                key: self.key.clone(),
                stream_id,
                operation_id: operation_id.to_owned(),
            })
            .await;
    }

    fn assert_no_pre_admission_state(&self, stream_id: u64, operation_id: &str) {
        let stream = self.stream(stream_id);
        assert_eq!(stream.operation_id, operation_id);
        assert!(
            stream.open_pending,
            "the OPEN stays pending until the owner proves OPENED or REJECTED"
        );
        assert!(stream.registration_dropped);
        assert!(
            !stream.terminal,
            "pre-admission abandonment must not create terminal state"
        );
        assert!(!stream.terminal_fin_failure);
        assert!(stream.closed.is_cancelled());
        assert!(
            stream.admission_lease.is_cancelled(),
            "the unclaimed-lease expiry must not fire a second reclamation"
        );
        assert_eq!(stream.budget_bytes, 0);
        assert!(
            zero_sequence_state(&stream.sequence.snapshot()),
            "no sequence state may exist before admission"
        );
    }
}

#[tokio::test]
async fn abandoned_pending_open_creates_no_sequence_state_and_reclaims_exactly_once() {
    let mut fixture = PendingOpenFixture::new("ec036-abandon");
    fixture.actor.options.limits.max_streams_per_device = 2;
    let key = fixture.key.clone();

    let sibling = fixture.open().await.expect("sibling OPEN admitted");
    let abandoned = fixture.open().await.expect("abandoned OPEN admitted");
    let abandoned_id = abandoned.stream_id;
    let abandoned_operation = abandoned.operation_id.clone();
    let abandoned_open_message_id = fixture.open_message_id(abandoned_id);
    assert_ne!(sibling.stream_id, abandoned_id);
    let opens = drain_control(&mut fixture.control.rx);
    assert_eq!(opens.len(), 2, "both OPENs were queued on control");
    assert!(
        opens
            .iter()
            .all(|message| matches!(message, ControlMessage::Open(_)))
    );
    assert_eq!(fixture.budget_used(), 0);
    // The active admission ceiling is now full.
    assert!(matches!(fixture.open().await, Err(RelayError::StreamLimit)));
    let dispatches_before = fixture.actor.lifetime_application_dispatches;
    let next_stream_id_before = fixture.session().next_stream_id;
    assert_eq!(next_stream_id_before, abandoned_id + 1);

    // The consumer disappears while OPEN is pending.
    fixture.abandon(abandoned_id, &abandoned_operation).await;
    // The post-101 socket loop's explicit close reports the same deferred
    // outcome and is idempotent: nothing below may happen twice.
    assert!(
        fixture
            .actor
            .close_echo_stream(&key, abandoned_id, &abandoned_operation)
    );
    drop(abandoned);

    fixture.assert_no_pre_admission_state(abandoned_id, &abandoned_operation);
    assert!(
        drain_data(&mut fixture.data_rx).is_empty(),
        "no FIN/RESET may be emitted for an unadmitted stream"
    );
    assert!(
        fixture.actor.stream_terminal_events.is_empty(),
        "no terminal result exists before admission"
    );
    assert_eq!(
        fixture.actor.lifetime_application_dispatches,
        dispatches_before
    );
    assert_eq!(fixture.budget_used(), 0);
    assert!(
        !fixture.actor.owner_forgets.contains_key(&key),
        "no FORGET may be staged before the owner outcome"
    );
    assert!(drain_control(&mut fixture.control.rx).is_empty());
    fixture.assert_untouched_pending(sibling.stream_id, &sibling.operation_id);
    // The reservation is still held until the owner proves the outcome.
    assert!(matches!(fixture.open().await, Err(RelayError::StreamLimit)));
    assert_eq!(fixture.session().next_stream_id, next_stream_id_before);

    // A mismatched late REJECTED cannot reclaim the exact reservation.
    fixture
        .rejected(
            "owner-rejected-wrong-reply",
            "different-open",
            abandoned_id,
            &abandoned_operation,
        )
        .await;
    assert!(fixture.session().streams.contains_key(&abandoned_id));
    assert!(drain_control(&mut fixture.control.rx).is_empty());

    // The exact late REJECTED reclaims the reservation once, with no-stream
    // evidence that matches the zero sequence state.
    fixture
        .rejected(
            "owner-rejected-late",
            &abandoned_open_message_id,
            abandoned_id,
            &abandoned_operation,
        )
        .await;
    let messages = drain_control(&mut fixture.control.rx);
    let forgets = forgets(&messages);
    assert_eq!(messages.len(), 1);
    assert_eq!(forgets.len(), 1, "exactly one owner FORGET");
    let forget = &forgets[0];
    assert_eq!(forget.session_id, key.session_id);
    assert_eq!(forget.epoch, key.epoch);
    assert_eq!(forget.stream_id, abandoned_id);
    assert_eq!(forget.operation_id, abandoned_operation);
    assert_eq!(forget.direction, Direction::RelayToConnector);
    assert_eq!(
        forget.final_state,
        ResumeDirectionState {
            stream_id: abandoned_id,
            ..ResumeDirectionState::default()
        }
    );
    assert!(!fixture.session().streams.contains_key(&abandoned_id));
    assert_eq!(fixture.session().forgotten_stream_through, abandoned_id);
    assert!(!fixture.actor.owner_forgets.contains_key(&key));
    assert_eq!(fixture.budget_used(), 0);
    assert!(fixture.actor.stream_terminal_events.is_empty());
    assert!(drain_data(&mut fixture.data_rx).is_empty());
    assert_eq!(
        fixture.actor.lifetime_application_dispatches,
        dispatches_before
    );
    fixture.assert_untouched_pending(sibling.stream_id, &sibling.operation_id);

    // Exactly one admission slot was released and the reserved identifier is
    // never reused: the successor takes the next monotonic ID.
    let successor = fixture
        .open()
        .await
        .expect("reclaimed slot admits one successor");
    assert_eq!(successor.stream_id, abandoned_id + 1);
    assert!(
        matches!(fixture.open().await, Err(RelayError::StreamLimit)),
        "reclamation released exactly one active slot"
    );
    assert_eq!(drain_control(&mut fixture.control.rx).len(), 1);

    // Late duplicates for the abandoned identity are bounded tombstones: no
    // second terminal result, no FORGET, no state, no dispatch.
    fixture
        .rejected(
            "owner-rejected-late",
            &abandoned_open_message_id,
            abandoned_id,
            &abandoned_operation,
        )
        .await;
    fixture
        .actor
        .inbound_control(
            key.clone(),
            ControlMessage::Opened(tunnel_protocol::Opened::new(
                "owner-opened-too-late",
                abandoned_open_message_id.clone(),
                key.session_id.clone(),
                key.epoch,
                abandoned_id,
                abandoned_operation.clone(),
                wire::M2_INITIAL_WINDOW_BYTES as u64,
                wire::M2_INITIAL_WINDOW_BYTES as u64,
            )),
        )
        .await;
    fixture
        .connector_frame(Frame::fin(key.epoch, 1, abandoned_id, 1, 0))
        .await;
    assert!(
        fixture.actor.sessions.contains_key(&key.scope()),
        "late traffic for a forgotten identity is stale data, not a session fault"
    );
    assert!(fixture.actor.session_terminal_events.is_empty());
    assert!(!fixture.session().streams.contains_key(&abandoned_id));
    assert_eq!(fixture.session().forgotten_stream_through, abandoned_id);
    assert!(drain_control(&mut fixture.control.rx).is_empty());
    assert!(drain_data(&mut fixture.data_rx).is_empty());
    assert!(fixture.actor.stream_terminal_events.is_empty());
    assert_eq!(
        fixture.actor.lifetime_application_dispatches,
        dispatches_before
    );
    assert_eq!(fixture.budget_used(), 0);
    fixture.assert_untouched_pending(sibling.stream_id, &sibling.operation_id);
    fixture.assert_untouched_pending(successor.stream_id, &successor.operation_id);
}

#[tokio::test]
async fn abandoned_pending_open_admitted_late_closes_once_with_exact_fin_then_forget() {
    let mut fixture = PendingOpenFixture::new("ec036-late-opened");
    let key = fixture.key.clone();

    let sibling = fixture.open().await.expect("sibling OPEN admitted");
    let abandoned = fixture.open().await.expect("abandoned OPEN admitted");
    let abandoned_id = abandoned.stream_id;
    let abandoned_operation = abandoned.operation_id.clone();
    let abandoned_open_message_id = fixture.open_message_id(abandoned_id);
    assert_eq!(drain_control(&mut fixture.control.rx).len(), 2);
    let dispatches_before = fixture.actor.lifetime_application_dispatches;

    fixture.abandon(abandoned_id, &abandoned_operation).await;
    drop(abandoned);
    fixture.assert_no_pre_admission_state(abandoned_id, &abandoned_operation);
    assert!(drain_data(&mut fixture.data_rx).is_empty());
    assert!(fixture.actor.stream_terminal_events.is_empty());

    // The exact late OPENED admits the abandoned stream.  Only now does the
    // relay own a real terminal transition: one FIN at sequence 1.
    fixture
        .opened("owner-opened-late", abandoned_id, &abandoned_operation)
        .await;
    let frames = drain_data(&mut fixture.data_rx);
    assert_eq!(frames.len(), 1, "exactly one terminal frame");
    let fin = &frames[0];
    assert_eq!(fin.kind, FrameKind::Fin);
    assert_eq!(fin.epoch, key.epoch);
    assert_eq!(fin.generation, 1);
    assert_eq!(fin.stream_id, abandoned_id);
    assert_eq!(fin.sequence, 1);
    assert_eq!(fin.ack, 0);
    {
        let stream = fixture.stream(abandoned_id);
        assert!(!stream.open_pending);
        assert!(stream.registration_dropped);
        assert!(stream.terminal);
        assert!(!stream.terminal_fin_failure);
        let snapshot = stream.sequence.snapshot();
        let relay = snapshot.direction(Direction::RelayToConnector);
        assert_eq!(relay.last_emitted, 1);
        assert_eq!(relay.peer_acked, 0);
        assert_eq!(relay.send_terminal, Some(Terminal::Fin));
        assert_eq!(relay.send_terminal_sequence, Some(1));
        let connector = snapshot.direction(Direction::ConnectorToRelay);
        assert_eq!(connector.recv_contiguous, 0);
        assert!(connector.receive_terminal.is_none());
    }
    assert_eq!(fixture.actor.stream_terminal_events.len(), 1);
    {
        let event = &fixture.actor.stream_terminal_events[0];
        assert_eq!(event.session_id, key.session_id);
        assert_eq!(event.epoch, key.epoch);
        assert_eq!(event.stream_id, abandoned_id);
        assert_eq!(event.operation_id, abandoned_operation);
        assert_eq!(event.reason, "STREAM_CLOSED");
        assert_eq!(event.cause, None);
        assert_eq!(event.active_generation, 1);
        assert_eq!(event.last_emitted_relay_to_connector, 1);
        assert_eq!(event.peer_acked_relay_to_connector, 0);
        assert_eq!(event.recv_contiguous_connector_to_relay, 0);
    }
    assert_eq!(
        fixture.actor.lifetime_application_dispatches,
        dispatches_before
    );
    assert!(
        drain_control(&mut fixture.control.rx).is_empty(),
        "FORGET waits for the connector's cursor evidence"
    );
    assert!(!fixture.actor.owner_forgets.contains_key(&key));
    fixture.assert_untouched_pending(sibling.stream_id, &sibling.operation_id);

    // A duplicate OPENED and a stale REJECTED for the now-admitted stream
    // cannot create a second terminal result or a no-stream reclamation.
    fixture
        .opened("owner-opened-duplicate", abandoned_id, &abandoned_operation)
        .await;
    fixture
        .rejected(
            "owner-rejected-after-admission",
            &abandoned_open_message_id,
            abandoned_id,
            &abandoned_operation,
        )
        .await;
    assert!(fixture.session().streams.contains_key(&abandoned_id));
    assert!(drain_data(&mut fixture.data_rx).is_empty());
    assert!(drain_control(&mut fixture.control.rx).is_empty());
    assert_eq!(fixture.actor.stream_terminal_events.len(), 1);
    assert_eq!(
        fixture
            .stream(abandoned_id)
            .sequence
            .snapshot()
            .direction(Direction::RelayToConnector)
            .last_emitted,
        1
    );

    // The connector acknowledges the relay FIN and closes its own direction;
    // the owner then reclaims the retained tombstone exactly once with the
    // real final cursors.
    fixture
        .connector_frame(Frame::ack(key.epoch, 1, abandoned_id, 1))
        .await;
    assert_eq!(
        fixture
            .stream(abandoned_id)
            .sequence
            .snapshot()
            .direction(Direction::RelayToConnector)
            .peer_acked,
        1
    );
    assert!(
        drain_control(&mut fixture.control.rx).is_empty(),
        "an ACK alone is not the connector's terminal proof"
    );
    fixture
        .connector_frame(Frame::fin(key.epoch, 1, abandoned_id, 1, 1))
        .await;
    let frames = drain_data(&mut fixture.data_rx);
    assert_eq!(frames.len(), 1, "the connector FIN is acknowledged once");
    assert_eq!(frames[0].kind, FrameKind::Ack);
    assert_eq!(frames[0].stream_id, abandoned_id);
    assert_eq!(frames[0].ack, 1);
    let messages = drain_control(&mut fixture.control.rx);
    let forgets = forgets(&messages);
    assert_eq!(messages.len(), 1);
    assert_eq!(forgets.len(), 1, "exactly one owner FORGET");
    let forget = &forgets[0];
    assert_eq!(forget.stream_id, abandoned_id);
    assert_eq!(forget.operation_id, abandoned_operation);
    assert_eq!(forget.direction, Direction::RelayToConnector);
    assert_eq!(forget.final_state.stream_id, abandoned_id);
    assert_eq!(forget.final_state.last_emitted, 1);
    assert_eq!(forget.final_state.peer_acked, 1);
    assert_eq!(forget.final_state.send_terminal, Some(TerminalState::Fin));
    assert!(forget.final_state.replay_floor.is_none());
    assert!(!fixture.session().streams.contains_key(&abandoned_id));
    assert_eq!(fixture.session().forgotten_stream_through, abandoned_id);
    assert_eq!(fixture.budget_used(), 0);
    assert_eq!(
        fixture.actor.stream_terminal_events.len(),
        1,
        "reclamation never produces a second terminal result"
    );
    assert_eq!(
        fixture.actor.lifetime_application_dispatches,
        dispatches_before
    );
    fixture.assert_untouched_pending(sibling.stream_id, &sibling.operation_id);

    // Late duplicates of the connector's terminal frame are stale data.
    fixture
        .connector_frame(Frame::fin(key.epoch, 1, abandoned_id, 1, 1))
        .await;
    assert!(fixture.actor.sessions.contains_key(&key.scope()));
    assert!(drain_data(&mut fixture.data_rx).is_empty());
    assert!(drain_control(&mut fixture.control.rx).is_empty());
    assert_eq!(fixture.actor.stream_terminal_events.len(), 1);
    fixture.assert_untouched_pending(sibling.stream_id, &sibling.operation_id);
}

#[tokio::test]
async fn unclaimed_pending_open_expiry_defers_to_owner_outcome_then_fails_closed() {
    let mut fixture = PendingOpenFixture::new("ec036-unclaimed");
    let key = fixture.key.clone();
    let sibling = fixture.open().await.expect("sibling OPEN admitted");
    let unclaimed = fixture.open().await.expect("unclaimed OPEN admitted");
    let unclaimed_id = unclaimed.stream_id;
    let unclaimed_operation = unclaimed.operation_id.clone();
    assert_eq!(drain_control(&mut fixture.control.rx).len(), 2);
    // The public upgrade callback never claims the lease before the deadline.
    drop(unclaimed);
    fixture
        .actor
        .sessions
        .get_mut(&key.scope())
        .expect("session")
        .streams
        .get_mut(&unclaimed_id)
        .expect("unclaimed stream")
        .admission_deadline = Instant::now() - std::time::Duration::from_secs(1);

    fixture
        .actor
        .expire_unclaimed_echo_streams(&key, Instant::now());
    fixture.assert_no_pre_admission_state(unclaimed_id, &unclaimed_operation);
    assert!(drain_data(&mut fixture.data_rx).is_empty());
    assert!(fixture.actor.stream_terminal_events.is_empty());
    assert!(
        fixture.session().terminal_fin_failure_deadline.is_none(),
        "no FIN was attempted, so no failed-FIN debt exists"
    );
    assert_eq!(fixture.budget_used(), 0);
    fixture.assert_untouched_pending(sibling.stream_id, &sibling.operation_id);
    // A second expiry pass cannot reclaim the same lease twice.
    fixture
        .actor
        .expire_unclaimed_echo_streams(&key, Instant::now());
    fixture.assert_no_pre_admission_state(unclaimed_id, &unclaimed_operation);
    assert!(drain_data(&mut fixture.data_rx).is_empty());

    // With neither OPENED nor REJECTED by the admission deadline the owner
    // fails the fenced session closed instead of inventing terminal proof.
    fixture.actor.tick().await;
    assert!(fixture.actor.sessions.is_empty());
    assert_eq!(fixture.actor.session_terminal_events.len(), 1);
    assert_eq!(
        fixture.actor.session_terminal_events[0].reason,
        "OPEN_ADMISSION_TIMEOUT"
    );
    assert_eq!(
        fixture.actor.session_terminal_events[0].session_id,
        key.session_id
    );
    assert!(
        fixture.actor.stream_terminal_events.is_empty(),
        "no stream ever reached a terminal transition"
    );
    let messages = drain_control(&mut fixture.control.rx);
    assert!(messages.iter().any(|message| matches!(
        message,
        ControlMessage::Rejected(rejected) if rejected.code == "OPEN_ADMISSION_TIMEOUT"
    )));
    assert!(forgets(&messages).is_empty());
    assert!(drain_data(&mut fixture.data_rx).is_empty());
}

// ---------------------------------------------------------------------------
// EC-041: one-use data attachment tickets racing control-plane changes.
// ---------------------------------------------------------------------------

struct CandidateFixture {
    actor: RelayActor,
    control: ControlRegistration,
    data_rx: mpsc::Receiver<DataOutbound>,
    key: SessionKey,
    catalog: Arc<MemoryCatalog>,
    device: DeviceIdentity,
    spki: String,
    other_spki: String,
    owner: OwnerToken,
    attempt: RotationAttemptIdentity,
    ticket: String,
    prepare_message_id: String,
    tenant_id: Uuid,
    device_id: Uuid,
}

impl CandidateFixture {
    /// An owner session with a prepared rotation attempt whose catalog-backed
    /// candidate ticket was issued through the production callback.
    async fn new(label: &str) -> Self {
        let (fixture, device_id, tenant_id, _tenant_b, spki, other_spki) = shared_device_fixture();
        let catalog = Arc::new(MemoryCatalog::new());
        catalog
            .seed_fixture(&fixture)
            .await
            .expect("seed shared-device fixture");
        let session_id = format!("{label}-session");
        let claim = catalog
            .claim_owner(&OwnerClaimRequest {
                deployment_incarnation: "test-incarnation".to_owned(),
                tenant_id,
                device_id,
                node_id: "test-node".to_owned(),
                boot_id: "test-boot".to_owned(),
                session_id: session_id.clone(),
                lease_expires_at: Utc::now() + Duration::seconds(30),
            })
            .await
            .expect("claim owner");
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id,
            epoch: claim.token.epoch,
        };
        let device = catalog
            .resolve_device(&spki, Utc::now())
            .await
            .expect("resolve device")
            .expect("device identity");
        let (mut actor, control) = admitted_control_actor(device.clone(), key.clone());
        let shared: SharedCatalog = catalog.clone();
        actor.catalog = shared;
        let owner = actor
            .sessions
            .get(&key.scope())
            .expect("session")
            .owner
            .clone();
        assert_eq!(
            owner, claim.token,
            "fixture owner token must equal the authoritative claim"
        );
        let attempt = session_attempt(&key, &runtime::owner_id(&owner), label, 1);
        let now_ms = monotonic_millis();
        let mut rotation = test_rotation_runtime(now_ms, attempt.clone(), now_ms + 60_000);
        rotation
            .state
            .prepare(attempt.clone(), now_ms)
            .expect("prepare candidate attempt");
        rotation.attempt_deadline_ms = rotation.state.status().deadline_ms;
        rotation.old_connection_id = attempt.old_connection_id.clone();
        let binding_digest = runtime::attachment_binding_digest(
            &owner,
            attempt.new_generation,
            &attempt.new_connection_id,
            CANDIDATE_PURPOSE,
        );
        rotation.pending_ticket = Some(PendingCatalogTicket {
            attempt: attempt.clone(),
            purpose: DataAttachmentPurpose::RotationCandidate,
            catalog_purpose: CANDIDATE_PURPOSE.to_owned(),
            binding_digest: binding_digest.clone(),
            reply_to: String::new(),
            request: None,
        });
        let (data_tx, data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        {
            let session = actor.sessions.get_mut(&key.scope()).expect("session");
            session.profile = RuntimeProfile::M2;
            session.cluster_profile = true;
            session.connection_id = attempt.old_connection_id.clone();
            session.data_tx = Some(data_tx.clone());
            session.active_carrier = Some(DataCarrier {
                context: CarrierContext::new(
                    key.session_id.clone(),
                    key.epoch,
                    1,
                    attempt.old_connection_id.clone(),
                ),
                tx: data_tx,
            });
            session.rotation = Some(rotation);
        }
        let issued = catalog
            .issue_attachment_ticket(&AttachmentTicketIssueRequest {
                tenant_id,
                device_id,
                spki_fingerprint: spki.clone(),
                owner: owner.clone(),
                generation: attempt.new_generation,
                connection_id: attempt.new_connection_id.clone(),
                purpose: CANDIDATE_PURPOSE.to_owned(),
                binding_digest,
                expires_at: Utc::now() + Duration::seconds(10),
            })
            .await
            .expect("issue candidate ticket");
        actor
            .finish_catalog_ticket(&key, &attempt, Ok(issued.clone()))
            .await;
        assert!(
            actor.sessions.contains_key(&key.scope()),
            "catalog ticket completion keeps the session live"
        );
        let prepare_message_id = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.rotation.as_ref())
            .map(|rotation| rotation.prepare_message_id.clone())
            .expect("PREPARE was published");
        assert!(!prepare_message_id.is_empty());
        let mut fixture = Self {
            actor,
            control,
            data_rx,
            key,
            catalog,
            device,
            spki,
            other_spki,
            owner,
            attempt,
            ticket: issued.ticket,
            prepare_message_id,
            tenant_id,
            device_id,
        };
        let messages = drain_control(&mut fixture.control.rx);
        assert_eq!(messages.len(), 1);
        assert!(matches!(
            &messages[0],
            ControlMessage::RotatePrepare(prepare)
                if prepare.attempt == fixture.attempt
                    && prepare.attachment_ticket == fixture.ticket
                    && prepare.attachment_purpose == DataAttachmentPurpose::RotationCandidate
        ));
        {
            let ticket = fixture.ticket_entry();
            assert!(ticket.catalog_backed && ticket.candidate && !ticket.consuming);
            assert_eq!(ticket.generation, fixture.attempt.new_generation);
            assert_eq!(ticket.connection_id, fixture.attempt.new_connection_id);
        }
        fixture
    }

    fn session(&self) -> &DeviceSession {
        self.actor
            .sessions
            .get(&self.key.scope())
            .expect("fixture session is live")
    }

    fn rotation(&self) -> &RotationRuntime {
        self.session()
            .rotation
            .as_ref()
            .expect("rotation runtime present")
    }

    fn ticket_entry(&self) -> &Ticket {
        self.actor
            .tickets
            .get(&self.ticket)
            .expect("candidate ticket is retained")
    }

    fn candidate_context(&self) -> CarrierContext {
        CarrierContext::new(
            self.key.session_id.clone(),
            self.key.epoch,
            self.attempt.new_generation,
            self.attempt.new_connection_id.clone(),
        )
    }

    /// Present a ticket on the forwarded device data path.  The owner consumes
    /// the authoritative record in a background task whose result is applied
    /// only by `apply_next_attach_result`, so the race point is explicit.
    fn present(
        &mut self,
        device: DeviceIdentity,
        spki: &str,
        ticket: &str,
    ) -> oneshot::Receiver<Result<DataRegistration, RelayError>> {
        let (response, receiver) = oneshot::channel();
        self.actor.begin_attach_forwarded_data(
            device,
            spki.to_owned(),
            ticket.to_owned(),
            response,
        );
        receiver
    }

    async fn apply_next_attach_result(&mut self) {
        let command = self
            .actor
            .rx
            .recv()
            .await
            .expect("background attachment result");
        assert!(matches!(command, Command::AttachResolved { .. }));
        self.actor.handle(command).await;
    }

    fn assert_no_pending_mailbox_work(&mut self) {
        assert!(
            self.actor.rx.try_recv().is_err(),
            "a refused presentation must not start background work"
        );
    }

    fn consume_request(&self, connection_id: &str, ticket: &str) -> AttachmentTicketConsumeRequest {
        AttachmentTicketConsumeRequest {
            ticket: ticket.to_owned(),
            tenant_id: self.tenant_id,
            device_id: self.device_id,
            spki_fingerprint: self.spki.clone(),
            owner: self.owner.clone(),
            generation: self.attempt.new_generation,
            connection_id: connection_id.to_owned(),
            purpose: CANDIDATE_PURPOSE.to_owned(),
            binding_digest: runtime::attachment_binding_digest(
                &self.owner,
                self.attempt.new_generation,
                connection_id,
                CANDIDATE_PURPOSE,
            ),
        }
    }

    async fn assert_catalog_record_spent(&self, connection_id: &str, ticket: &str) {
        assert!(
            matches!(
                self.catalog
                    .consume_attachment_ticket(&self.consume_request(connection_id, ticket))
                    .await,
                Err(CatalogError::Unauthorized)
            ),
            "the one-use catalog record must not accept a second transition"
        );
    }

    /// Counters that a losing or stale presentation must never move.
    fn logical_state(&self) -> (u64, String, u64, Vec<(u64, StreamSnapshot)>) {
        let session = self.session();
        let mut streams: Vec<_> = session
            .streams
            .iter()
            .map(|(stream_id, stream)| (*stream_id, stream.sequence.snapshot()))
            .collect();
        streams.sort_by_key(|(stream_id, _)| *stream_id);
        (
            session.generation,
            session.connection_id.clone(),
            self.rotation().state.generation_high_watermark(),
            streams,
        )
    }

    /// Admit one consumer stream and emit one application record on it so the
    /// session carries non-trivial logical sequence state.
    async fn admitted_stream_with_emitted_record(&mut self) -> u64 {
        let principal_id = Uuid::from_u128(11);
        let service_id = Uuid::from_u128(31);
        let now = Utc::now();
        let (response, receiver) = oneshot::channel();
        self.actor.open_echo_stream(
            AuthenticatedConsumer {
                tenant_id: self.tenant_id,
                principal_id,
            },
            self.device_id,
            service_id,
            GrantSnapshot {
                tenant_id: self.tenant_id,
                principal_id,
                device_id: self.device_id,
                service_id,
                revision: 1,
                permissions: PermissionSet {
                    operations: BTreeSet::from(["echo:invoke".to_owned()]),
                },
                constraints: serde_json::json!({}),
                valid_until: now + Duration::minutes(5),
                read_started_at: now,
            },
            now + Duration::minutes(5),
            response,
        );
        let registration = receiver
            .await
            .expect("stream registration response")
            .expect("stream admitted");
        registration.claim_admission();
        let stream_id = registration.stream_id;
        let operation_id = registration.operation_id.clone();
        let open_message_id = self
            .session()
            .streams
            .get(&stream_id)
            .map(|stream| stream.open_message_id.clone())
            .expect("OPEN correlation");
        self.actor
            .inbound_control(
                self.key.clone(),
                ControlMessage::Opened(tunnel_protocol::Opened::new(
                    "ec041-opened",
                    open_message_id,
                    self.key.session_id.clone(),
                    self.key.epoch,
                    stream_id,
                    operation_id.clone(),
                    wire::M2_INITIAL_WINDOW_BYTES as u64,
                    wire::M2_INITIAL_WINDOW_BYTES as u64,
                )),
            )
            .await;
        self.actor
            .sessions
            .get_mut(&self.key.scope())
            .expect("session")
            .streams
            .get_mut(&stream_id)
            .expect("admitted stream")
            .authorized_until = Some(Instant::now() + std::time::Duration::from_secs(60));
        let (write_response, _write_receiver) = oneshot::channel();
        self.actor.write_echo_stream(
            self.key.clone(),
            stream_id,
            operation_id,
            b"ec041".to_vec(),
            write_response,
        );
        // Keep the consumer waiter alive for the session lifetime so the
        // emitted record stays a live logical obligation.
        std::mem::forget(_write_receiver);
        assert_eq!(drain_control(&mut self.control.rx).len(), 1, "one OPEN");
        let frames = drain_data(&mut self.data_rx);
        assert_eq!(frames.len(), 1, "one emitted DATA frame");
        assert_eq!(frames[0].kind, FrameKind::Data);
        assert_eq!(
            self.session()
                .streams
                .get(&stream_id)
                .map(|stream| {
                    stream
                        .sequence
                        .snapshot()
                        .direction(Direction::RelayToConnector)
                        .last_emitted
                })
                .expect("stream"),
            1
        );
        stream_id
    }
}

#[tokio::test]
async fn concurrent_candidate_ticket_presentations_attach_exactly_once() {
    let mut fixture = CandidateFixture::new("ec041-once").await;
    let ticket = fixture.ticket.clone();
    let device = fixture.device.clone();
    let spki = fixture.spki.clone();
    let stream_id = fixture.admitted_stream_with_emitted_record().await;
    let dispatches_before = fixture.actor.lifetime_application_dispatches;
    let state_before = fixture.logical_state();

    // The first presentation reserves the ticket while the authoritative
    // consume is in flight.
    let winner = fixture.present(device.clone(), &spki, &ticket);
    assert!(fixture.ticket_entry().consuming);

    // A concurrent presentation of the same ticket loses immediately with a
    // typed rejection and starts no background work.
    let loser = fixture.present(device.clone(), &spki, &ticket);
    assert!(matches!(
        loser.await.expect("loser response"),
        Err(RelayError::Unauthorized)
    ));
    assert!(
        fixture.ticket_entry().consuming,
        "the loser must not release the winner's reservation"
    );
    assert!(drain_control(&mut fixture.control.rx).is_empty());
    assert!(drain_data(&mut fixture.data_rx).is_empty());
    assert_eq!(fixture.logical_state(), state_before);

    // The winner's authoritative result attaches exactly once.
    fixture.apply_next_attach_result().await;
    let registration = winner
        .await
        .expect("winner response")
        .expect("winner attaches the candidate");
    assert_eq!(
        registration.carrier,
        CarrierKey {
            session: fixture.key.clone(),
            generation: fixture.attempt.new_generation,
            connection_id: fixture.attempt.new_connection_id.clone(),
        }
    );
    let messages = drain_control(&mut fixture.control.rx);
    assert_eq!(count_data_ready(&messages), 1, "exactly one DATA_READY");
    assert!(matches!(
        &messages[0],
        ControlMessage::DataReady(ready)
            if ready.reply_to == fixture.prepare_message_id
                && ready.session_id == fixture.key.session_id
                && ready.epoch == fixture.key.epoch
                && ready.generation == fixture.attempt.new_generation
                && ready.connection_id == fixture.attempt.new_connection_id
    ));
    assert!(
        messages
            .iter()
            .any(|message| matches!(message, ControlMessage::RotateQuiesce(_))),
        "the admitted candidate lets the coordinator quiesce"
    );
    // The quiesce barrier is the only data-side effect; no sequenced frame.
    assert!(drain_data(&mut fixture.data_rx).is_empty());
    assert_eq!(
        fixture
            .rotation()
            .candidate
            .as_ref()
            .map(|carrier| carrier.context.clone()),
        Some(fixture.candidate_context())
    );
    assert!(
        !fixture.actor.tickets.contains_key(&ticket),
        "the consumed ticket is forgotten by the owner"
    );
    fixture
        .assert_catalog_record_spent(&fixture.attempt.new_connection_id.clone(), &ticket)
        .await;
    // Logical counters are untouched by either presentation: the active
    // generation/connection, the generation watermark and the live stream's
    // sequence state are exactly what they were.
    assert_eq!(fixture.logical_state(), state_before);
    assert_eq!(
        fixture.actor.lifetime_application_dispatches,
        dispatches_before
    );
    assert!(
        fixture
            .session()
            .streams
            .get(&stream_id)
            .is_some_and(|stream| !stream.terminal && !stream.open_pending)
    );

    // Late presentations of the spent ticket are refused before any
    // background work and never produce a second DATA_READY.
    for _ in 0..2 {
        let late = fixture.present(device.clone(), &spki, &ticket);
        assert!(matches!(
            late.await.expect("late response"),
            Err(RelayError::Unauthorized)
        ));
    }
    fixture.assert_no_pending_mailbox_work();
    assert!(drain_control(&mut fixture.control.rx).is_empty());
    assert_eq!(
        fixture
            .rotation()
            .candidate
            .as_ref()
            .map(|carrier| carrier.context.clone()),
        Some(fixture.candidate_context())
    );
    assert_eq!(fixture.logical_state(), state_before);
}

#[tokio::test]
async fn candidate_ticket_in_flight_during_active_carrier_loss_cannot_attach_to_recovery() {
    let mut fixture = CandidateFixture::new("ec041-recovery").await;
    let ticket = fixture.ticket.clone();
    let device = fixture.device.clone();
    let spki = fixture.spki.clone();
    let old_connection_id = fixture.attempt.old_connection_id.clone();

    let pending = fixture.present(device.clone(), &spki, &ticket);
    assert!(fixture.ticket_entry().consuming);

    // The active carrier is lost while the candidate consume is outstanding.
    // The coordinator reserves a fresh generation for recovery and fences the
    // queued PREPARE's candidate identity, even though its ticket is mid-use.
    fixture
        .actor
        .disconnect_data(CarrierKey {
            session: fixture.key.clone(),
            generation: 1,
            connection_id: old_connection_id.clone(),
        })
        .await;
    assert!(fixture.actor.sessions.contains_key(&fixture.key.scope()));
    let recovery_attempt = {
        let rotation = fixture.rotation();
        assert_eq!(rotation.state.phase(), RotationPhase::Recovering);
        assert!(rotation.candidate.is_none());
        assert!(rotation.pending_ticket.is_none());
        let attempt = rotation.attempt.clone().expect("recovery attempt");
        assert_eq!(attempt.old_generation, 1);
        assert_eq!(
            attempt.new_generation, 3,
            "the aborted candidate generation is not reused"
        );
        assert_ne!(attempt.new_connection_id, fixture.attempt.new_connection_id);
        attempt
    };
    assert!(
        fixture.actor.tickets.is_empty(),
        "the fenced candidate ticket is discarded while its consume is in flight"
    );
    let messages = drain_control(&mut fixture.control.rx);
    assert!(matches!(
        &messages[0],
        ControlMessage::RecoveryBegin(begin) if begin.attempt == recovery_attempt
    ));
    assert!(
        messages
            .iter()
            .any(|message| matches!(message, ControlMessage::RecoveryClosed(_)))
    );
    assert_eq!(count_data_ready(&messages), 0);

    // The late authoritative result belongs to the fenced generation: typed
    // rejection, nothing installed, recovery untouched.
    fixture.apply_next_attach_result().await;
    assert!(matches!(
        pending.await.expect("stale attach response"),
        Err(RelayError::Unauthorized)
    ));
    assert!(drain_control(&mut fixture.control.rx).is_empty());
    assert!(drain_data(&mut fixture.data_rx).is_empty());
    {
        let session = fixture.session();
        assert!(session.data_tx.is_none());
        assert!(session.active_carrier.is_none());
        assert_eq!(session.generation, 1);
        let rotation = session.rotation.as_ref().expect("rotation");
        assert_eq!(rotation.state.phase(), RotationPhase::Recovering);
        assert_eq!(rotation.attempt.as_ref(), Some(&recovery_attempt));
        assert!(rotation.candidate.is_none());
        assert!(
            !rotation
                .recovery
                .as_ref()
                .expect("recovery runtime")
                .candidate_ready
        );
        assert_eq!(rotation.state.generation_high_watermark(), 3);
    }

    // Re-presenting the fenced ticket is refused before any background work,
    // and the catalog record it consumed cannot be consumed again.
    let stale = fixture.present(device, &spki, &ticket);
    assert!(matches!(
        stale.await.expect("stale response"),
        Err(RelayError::Unauthorized)
    ));
    fixture.assert_no_pending_mailbox_work();
    fixture
        .assert_catalog_record_spent(&fixture.attempt.new_connection_id.clone(), &ticket)
        .await;
    assert!(fixture.actor.sessions.contains_key(&fixture.key.scope()));
}

#[tokio::test]
async fn candidate_ticket_in_flight_during_owner_abort_cannot_attach() {
    let mut fixture = CandidateFixture::new("ec041-abort").await;
    let ticket = fixture.ticket.clone();
    let device = fixture.device.clone();
    let spki = fixture.spki.clone();
    let attempt = fixture.attempt.clone();
    let state_before = fixture.logical_state();

    let pending = fixture.present(device.clone(), &spki, &ticket);
    assert!(fixture.ticket_entry().consuming);

    // The coordinator decides to abort the attempt before the attachment
    // result is applied.  This is the same owner decision the handshake
    // deadline and physical candidate loss take; the unsolicited ABORT fences
    // the candidate ticket immediately.
    fixture
        .actor
        .sessions
        .get_mut(&fixture.key.scope())
        .expect("session")
        .rotation
        .as_mut()
        .expect("rotation")
        .state
        .abort(
            &attempt,
            monotonic_millis(),
            RecoveryReason::CandidateTransportLost,
        )
        .expect("owner abort decision");
    fixture
        .actor
        .emit_rotation_abort(&fixture.key, "test abort");
    {
        let rotation = fixture.rotation();
        assert_eq!(rotation.state.phase(), RotationPhase::Aborting);
        assert!(rotation.abort_message_id.is_some());
        assert!(rotation.candidate.is_none());
    }
    assert!(
        fixture.actor.tickets.is_empty(),
        "ABORT fences the still-consuming candidate ticket"
    );
    let messages = drain_control(&mut fixture.control.rx);
    assert_eq!(messages.len(), 1);
    assert!(matches!(
        &messages[0],
        ControlMessage::RotateAbort(abort) if abort.attempt == attempt && abort.reply_to.is_empty()
    ));

    fixture.apply_next_attach_result().await;
    assert!(matches!(
        pending.await.expect("stale attach response"),
        Err(RelayError::Unauthorized)
    ));
    assert!(drain_control(&mut fixture.control.rx).is_empty());
    assert!(drain_data(&mut fixture.data_rx).is_empty());
    assert!(fixture.rotation().candidate.is_none());
    assert_eq!(fixture.rotation().state.phase(), RotationPhase::Aborting);
    assert_eq!(fixture.logical_state(), state_before);

    let stale = fixture.present(device, &spki, &ticket);
    assert!(matches!(
        stale.await.expect("stale response"),
        Err(RelayError::Unauthorized)
    ));
    fixture.assert_no_pending_mailbox_work();
    fixture
        .assert_catalog_record_spent(&attempt.new_connection_id, &ticket)
        .await;
}

#[tokio::test]
async fn candidate_ticket_result_after_session_epoch_change_installs_nothing_on_successor() {
    let mut fixture = CandidateFixture::new("ec041-epoch").await;
    let ticket = fixture.ticket.clone();
    let device = fixture.device.clone();
    let spki = fixture.spki.clone();
    let old_key = fixture.key.clone();

    let pending = fixture.present(device.clone(), &spki, &ticket);
    assert!(fixture.ticket_entry().consuming);

    // Control is lost while the consume is in flight: the owner session ends
    // and every ticket bound to its session/epoch is fenced.
    fixture.actor.disconnect_control(old_key.clone()).await;
    assert!(!fixture.actor.sessions.contains_key(&old_key.scope()));
    assert!(fixture.actor.tickets.is_empty());
    assert_eq!(fixture.actor.session_terminal_events.len(), 1);
    assert_eq!(
        fixture.actor.session_terminal_events[0].reason,
        "CONTROL_CLOSED"
    );

    // A successor claims the same device at a higher epoch.
    let successor_session_id = format!("{}-successor", old_key.session_id);
    let successor_claim = fixture
        .catalog
        .claim_owner(&OwnerClaimRequest {
            deployment_incarnation: "test-incarnation".to_owned(),
            tenant_id: fixture.tenant_id,
            device_id: fixture.device_id,
            node_id: "test-node".to_owned(),
            boot_id: "test-boot".to_owned(),
            session_id: successor_session_id.clone(),
            lease_expires_at: Utc::now() + Duration::seconds(30),
        })
        .await
        .expect("successor claim");
    assert_eq!(successor_claim.token.epoch, old_key.epoch + 1);
    let successor_key = SessionKey {
        session_id: successor_session_id,
        epoch: successor_claim.token.epoch,
        ..old_key.clone()
    };
    let successor_device = fixture
        .catalog
        .resolve_device(&spki, Utc::now())
        .await
        .expect("resolve successor device")
        .expect("successor identity");
    assert_eq!(successor_device.owner_epoch, successor_key.epoch);
    let (mut successor_actor, mut successor_control) =
        admitted_control_actor(successor_device.clone(), successor_key.clone());
    let mut successor = successor_actor
        .sessions
        .remove(&successor_key.scope())
        .expect("successor session");
    successor.profile = RuntimeProfile::M2;
    successor.cluster_profile = true;
    assert_eq!(successor.owner, successor_claim.token);
    fixture
        .actor
        .sessions
        .insert(successor_key.scope(), successor);

    // The stale result belongs to the closed epoch: typed rejection and no
    // effect on the successor's control/data bindings.
    fixture.apply_next_attach_result().await;
    assert!(matches!(
        pending.await.expect("stale attach response"),
        Err(RelayError::Unauthorized)
    ));
    {
        let successor = fixture
            .actor
            .sessions
            .get(&successor_key.scope())
            .expect("successor remains live");
        assert_eq!(successor.key, successor_key);
        assert!(successor.data_tx.is_none());
        assert!(successor.active_carrier.is_none());
        assert_eq!(successor.generation, 1);
        assert!(successor.rotation.is_none());
    }
    assert!(
        drain_control(&mut successor_control.rx).is_empty(),
        "the successor must not observe a DATA_READY for a fenced epoch"
    );
    let old_messages = drain_control(&mut fixture.control.rx);
    assert_eq!(count_data_ready(&old_messages), 0);
    assert!(old_messages.iter().any(|message| matches!(
        message,
        ControlMessage::Rejected(rejected) if rejected.code == "CONTROL_CLOSED"
    )));
    assert!(fixture.actor.tickets.is_empty());

    // A fresh presentation of the fenced ticket against the successor is
    // refused before any background work; the catalog record is spent.
    let stale = fixture.present(successor_device, &spki, &ticket);
    assert!(matches!(
        stale.await.expect("stale response"),
        Err(RelayError::Unauthorized)
    ));
    fixture.assert_no_pending_mailbox_work();
    assert!(drain_control(&mut successor_control.rx).is_empty());
    fixture
        .assert_catalog_record_spent(&fixture.attempt.new_connection_id.clone(), &ticket)
        .await;
    assert_eq!(fixture.actor.session_terminal_events.len(), 1);
}

#[tokio::test]
async fn ticket_bound_to_other_identity_or_connection_is_rejected_without_burning_the_bound_ticket()
{
    let mut fixture = CandidateFixture::new("ec041-binding").await;
    let ticket = fixture.ticket.clone();
    let device = fixture.device.clone();
    let spki = fixture.spki.clone();
    let other_spki = fixture.other_spki.clone();
    let state_before = fixture.logical_state();

    // (a) A different valid device certificate cannot consume the ticket and
    // does not burn it.
    let mut other_device = device.clone();
    other_device.spki_fingerprint = other_spki.clone();
    let wrong_spki = fixture.present(other_device, &other_spki, &ticket);
    assert!(matches!(
        wrong_spki.await.expect("wrong SPKI response"),
        Err(RelayError::Unauthorized)
    ));
    fixture.assert_no_pending_mailbox_work();
    assert!(!fixture.ticket_entry().consuming);

    // (b) The same certificate enrolled in another tenant cannot consume it.
    let other_tenant_device = fixture
        .catalog
        .resolve_device(&other_spki, Utc::now())
        .await
        .expect("resolve tenant-b identity")
        .expect("tenant-b identity");
    assert_ne!(other_tenant_device.tenant_id, fixture.tenant_id);
    let wrong_tenant = fixture.present(other_tenant_device, &other_spki, &ticket);
    assert!(matches!(
        wrong_tenant.await.expect("wrong tenant response"),
        Err(RelayError::Unauthorized)
    ));
    fixture.assert_no_pending_mailbox_work();
    assert!(!fixture.ticket_entry().consuming);
    assert!(drain_control(&mut fixture.control.rx).is_empty());

    // (c) A ticket for the same session and generation but a different
    // connection identity (a stale attempt) has a valid catalog record and
    // still cannot attach: the owner rejects it after the authoritative
    // consume, without DATA_READY and without installing a candidate.
    let stale_connection_id = "stale-attempt-connection".to_owned();
    let stale_binding = runtime::attachment_binding_digest(
        &fixture.owner,
        fixture.attempt.new_generation,
        &stale_connection_id,
        CANDIDATE_PURPOSE,
    );
    let stale_issued = fixture
        .catalog
        .issue_attachment_ticket(&AttachmentTicketIssueRequest {
            tenant_id: fixture.tenant_id,
            device_id: fixture.device_id,
            spki_fingerprint: spki.clone(),
            owner: fixture.owner.clone(),
            generation: fixture.attempt.new_generation,
            connection_id: stale_connection_id.clone(),
            purpose: CANDIDATE_PURPOSE.to_owned(),
            binding_digest: stale_binding.clone(),
            expires_at: Utc::now() + Duration::seconds(10),
        })
        .await
        .expect("issue stale-connection ticket");
    let now = Utc::now();
    fixture.actor.tickets.insert(
        stale_issued.ticket.clone(),
        Ticket {
            value: stale_issued.ticket.clone(),
            tenant_id: fixture.tenant_id,
            device_id: fixture.device_id,
            spki: spki.clone(),
            session_id: fixture.key.session_id.clone(),
            epoch: fixture.key.epoch,
            generation: fixture.attempt.new_generation,
            welcome_message_id: "stale-prepare".to_owned(),
            connection_id: stale_connection_id.clone(),
            issued_at_wall: now,
            expires_at_wall: stale_issued.expires_at,
            expires_at: Instant::now() + wire::TICKET_TTL,
            consuming: false,
            owner: fixture.owner.clone(),
            candidate: true,
            attachment_purpose: DataAttachmentPurpose::RotationCandidate,
            catalog_purpose: CANDIDATE_PURPOSE.to_owned(),
            binding_digest: stale_binding,
            locator_digest: stale_issued.locator.digest.clone(),
            catalog_backed: true,
        },
    );
    let stale = fixture.present(device.clone(), &spki, &stale_issued.ticket);
    fixture.apply_next_attach_result().await;
    assert!(matches!(
        stale.await.expect("stale connection response"),
        Err(RelayError::Unauthorized)
    ));
    assert!(drain_control(&mut fixture.control.rx).is_empty());
    assert!(drain_data(&mut fixture.data_rx).is_empty());
    assert!(fixture.rotation().candidate.is_none());
    assert_eq!(fixture.logical_state(), state_before);
    fixture
        .assert_catalog_record_spent(&stale_connection_id, &stale_issued.ticket)
        .await;
    // Its relay entry cannot be reused either: the spent record fails the
    // authoritative consume and the owner forgets the ticket.
    let reused = fixture.present(device.clone(), &spki, &stale_issued.ticket);
    fixture.apply_next_attach_result().await;
    assert!(matches!(
        reused.await.expect("reused stale response"),
        Err(RelayError::Unauthorized)
    ));
    assert!(!fixture.actor.tickets.contains_key(&stale_issued.ticket));
    assert!(drain_control(&mut fixture.control.rx).is_empty());

    // (d) The correctly bound ticket still attaches exactly once afterwards.
    assert!(!fixture.ticket_entry().consuming);
    let bound = fixture.present(device, &spki, &ticket);
    fixture.apply_next_attach_result().await;
    let registration = bound
        .await
        .expect("bound response")
        .expect("bound ticket attaches");
    assert_eq!(
        registration.carrier.generation,
        fixture.attempt.new_generation
    );
    assert_eq!(
        registration.carrier.connection_id,
        fixture.attempt.new_connection_id
    );
    let messages = drain_control(&mut fixture.control.rx);
    assert_eq!(count_data_ready(&messages), 1);
    assert_eq!(
        fixture
            .rotation()
            .candidate
            .as_ref()
            .map(|carrier| carrier.context.clone()),
        Some(fixture.candidate_context())
    );
    assert!(!fixture.actor.tickets.contains_key(&ticket));
}

#[tokio::test]
async fn stale_generation_initial_ticket_is_rejected_before_data_ready() {
    let (fixture, device_id, tenant_id, _tenant_b, spki, _other_spki) = shared_device_fixture();
    let catalog = Arc::new(MemoryCatalog::new());
    catalog
        .seed_fixture(&fixture)
        .await
        .expect("seed shared-device fixture");
    let session_id = "ec041-stale-initial-session".to_owned();
    let claim = catalog
        .claim_owner(&OwnerClaimRequest {
            deployment_incarnation: "test-incarnation".to_owned(),
            tenant_id,
            device_id,
            node_id: "test-node".to_owned(),
            boot_id: "test-boot".to_owned(),
            session_id: session_id.clone(),
            lease_expires_at: Utc::now() + Duration::seconds(30),
        })
        .await
        .expect("claim owner");
    let key = SessionKey {
        tenant_id,
        device_id,
        session_id,
        epoch: claim.token.epoch,
    };
    let device = catalog
        .resolve_device(&spki, Utc::now())
        .await
        .expect("resolve device")
        .expect("device identity");
    let (mut actor, mut control) = admitted_control_actor(device.clone(), key.clone());
    let shared: SharedCatalog = catalog.clone();
    actor.catalog = shared;
    let owner = actor.sessions[&key.scope()].owner.clone();
    assert_eq!(owner, claim.token);
    // A committed rotation moved the session to generation 2 while a stale
    // initial-generation ticket is still retained; no carrier is active.
    {
        let session = actor.sessions.get_mut(&key.scope()).expect("session");
        session.profile = RuntimeProfile::M2;
        session.generation = 2;
        session.connection_id = "committed-connection".to_owned();
        assert!(session.data_tx.is_none());
    }
    let now = Utc::now();
    let stale_ticket = "stale-initial-ticket".to_owned();
    actor.tickets.insert(
        stale_ticket.clone(),
        Ticket {
            value: stale_ticket.clone(),
            tenant_id,
            device_id,
            spki: spki.clone(),
            session_id: key.session_id.clone(),
            epoch: key.epoch,
            generation: 1,
            welcome_message_id: "stale-welcome".to_owned(),
            connection_id: "initial-connection".to_owned(),
            issued_at_wall: now,
            expires_at_wall: now + Duration::seconds(10),
            expires_at: Instant::now() + wire::TICKET_TTL,
            consuming: false,
            owner: owner.clone(),
            candidate: false,
            attachment_purpose: DataAttachmentPurpose::RotationCandidate,
            catalog_purpose: String::new(),
            binding_digest: String::new(),
            locator_digest: String::new(),
            catalog_backed: false,
        },
    );

    let (response, receiver) = oneshot::channel();
    actor.begin_attach_forwarded_data(device, spki, stale_ticket.clone(), response);
    let command = actor.rx.recv().await.expect("attachment result");
    assert!(matches!(command, Command::AttachResolved { .. }));
    actor.handle(command).await;
    assert!(matches!(
        receiver.await.expect("stale generation response"),
        Err(RelayError::Unauthorized)
    ));
    let messages = drain_control(&mut control.rx);
    assert_eq!(
        count_data_ready(&messages),
        0,
        "a rejected stale-generation ticket must never queue DATA_READY"
    );
    assert!(messages.is_empty());
    let session = actor
        .sessions
        .get(&key.scope())
        .expect("session remains live");
    assert!(session.data_tx.is_none());
    assert!(session.active_carrier.is_none());
    assert_eq!(session.generation, 2);
    assert_eq!(session.connection_id, "committed-connection");
}
