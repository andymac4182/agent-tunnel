//! Deterministic regressions for the shared inbound frame validator on the
//! owner's device carrier: ordering, late events and terminal sequences.
//!
//! Every frame the owner receives from a device, whether the device socket is
//! terminated locally or forwarded by an ingress relay as an HTTP/3
//! `CompleteDeviceData` record (`http.rs` peer ingress), enters the actor
//! through `RelayActor::inbound_data` with an installed `CarrierKey`.  These
//! scenarios install that carrier directly, so the assertions hold for the
//! peer path and the local path alike, and drive the real handlers with an
//! explicit connector stand-in: no socket I/O, no wall-clock waiting.
//!
//! Coverage (docs/m7-edge-cases.md): EC-030 serialized sequence reservation,
//! EC-037/IN-06 narrowly bound late events, EC-044 validator dimensions on
//! the peer path, EC-047 terminal frames at the current accepted sequence.

use std::{
    collections::{BTreeSet, VecDeque},
    time::{Duration as StdDuration, Instant},
};

use chrono::{Duration, Utc};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{AuthenticatedConsumer, DeviceIdentity, GrantSnapshot, PermissionSet};
use tunnel_protocol::{ControlMessage, Direction, Frame, FrameKind, StreamState, Terminal};
use uuid::Uuid;

use super::stream_identity_tests::admitted_control_actor;
use super::{
    CarrierKey, Command, ControlOutbound, DataCarrier, DataOutbound, DeviceSession, EchoOutcome,
    M2Stream, RelayActor, SessionKey, runtime, wire,
};
use crate::consumer_write_diagnostics::{ConsumerWriteOutcome, send_until};
use crate::runtime::StreamTerminalCause;

const STREAM_A: u64 = 7;
const STREAM_B: u64 = 8;
const GENERATION: u64 = 3;
const EPOCH: u64 = 5;

fn operation_id(stream_id: u64) -> String {
    format!("late-operation-{stream_id}")
}

/// One M2 session whose device carrier was installed exactly as
/// `attach_data_verified` installs a forwarded carrier, with two admitted
/// logical streams so every scenario can prove a sibling is unaffected.
struct LateFixture {
    actor: RelayActor,
    key: SessionKey,
    carrier: CarrierKey,
    control_rx: mpsc::Receiver<ControlOutbound>,
    data_rx: mpsc::Receiver<DataOutbound>,
}

impl LateFixture {
    fn new(label: &str) -> Self {
        let now = Utc::now();
        let tenant_id = Uuid::from_u128(9_001);
        let device_id = Uuid::from_u128(9_002);
        let principal_id = Uuid::from_u128(9_003);
        let service_id = Uuid::from_u128(9_004);
        let identity = DeviceIdentity {
            tenant_id,
            device_id,
            owner_user_id: principal_id,
            credential_id: Uuid::from_u128(9_005),
            spki_fingerprint: format!("late-{label}-spki"),
            credential_not_before: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(10),
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
            session_id: format!("late-{label}"),
            epoch: EPOCH,
        };
        let (mut actor, registration) = admitted_control_actor(identity, key.clone());
        let capacity = actor.options.limits.max_queue_messages;
        let (data_tx, data_rx) = mpsc::channel(capacity);
        let carrier = CarrierKey {
            session: key.clone(),
            generation: GENERATION,
            connection_id: format!("forwarded-{label}"),
        };
        let consumer = AuthenticatedConsumer {
            tenant_id,
            principal_id,
        };
        let grant = GrantSnapshot {
            tenant_id,
            principal_id,
            device_id,
            service_id,
            revision: 1,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            valid_until: now + Duration::minutes(10),
            read_started_at: now,
        };
        let session = actor
            .sessions
            .get_mut(&key.scope())
            .expect("fixture session");
        session.profile = runtime::RuntimeProfile::M2;
        session.generation = GENERATION;
        session.connection_id = carrier.connection_id.clone();
        session.data_tx = Some(data_tx.clone());
        session.active_carrier = Some(DataCarrier {
            context: carrier.context(),
            tx: data_tx,
        });
        session.next_stream_id = STREAM_B + 1;
        for stream_id in [STREAM_A, STREAM_B] {
            session.streams.insert(
                stream_id,
                M2Stream {
                    deferred_terminal_cause: None,
                    credit_held: false,
                    open_message_id: format!("late-open-{stream_id}"),
                    operation_id: operation_id(stream_id),
                    request_id: None,
                    service_id,
                    consumer: consumer.clone(),
                    grant: grant.clone(),
                    sequence: StreamState::new(stream_id, wire::M2_INITIAL_WINDOW_BYTES as u64)
                        .expect("fixture stream sequence"),
                    response_bytes: Vec::new(),
                    response_records: VecDeque::new(),
                    orphaned_response_records: 0,
                    late_response_records: 0,
                    send_bytes: 0,
                    receive_bytes: 0,
                    authorized_until: Some(Instant::now() + StdDuration::from_secs(60)),
                    consumer_expires_at: now + Duration::minutes(10),
                    challenge_id: None,
                    authorization_in_flight: false,
                    authorization_started_at_ms: None,
                    authorization_deadline_ms: None,
                    authorization_admission_deadline_ms: None,
                    pending_records: VecDeque::new(),
                    pending_record_bytes: 0,
                    budget_bytes: 0,
                    terminal: false,
                    pending_terminal: None,
                    terminal_fin_failure: false,
                    open_pending: false,
                    registration_dropped: false,
                    closed: CancellationToken::new(),
                    admission_lease: CancellationToken::new(),
                    admission_deadline: Instant::now() + StdDuration::from_secs(60),
                    authorization_failure_code: None,
                    http: None,
                },
            );
        }
        Self {
            actor,
            key,
            carrier,
            control_rx: registration.rx,
            data_rx,
        }
    }

    fn session_alive(&self) -> bool {
        self.actor.sessions.contains_key(&self.key.scope())
    }

    /// The typed reason of the most recent session closure, from the
    /// bounded diagnostic ring the fence publishes before removal.
    fn close_reason(&self) -> Option<&'static str> {
        self.actor
            .session_terminal_events
            .back()
            .filter(|event| event.session_id == self.key.session_id)
            .map(|event| event.reason)
    }

    fn stream(&self, stream_id: u64) -> &M2Stream {
        self.actor
            .sessions
            .get(&self.key.scope())
            .expect("fixture session")
            .streams
            .get(&stream_id)
            .expect("fixture stream")
    }

    fn has_stream(&self, stream_id: u64) -> bool {
        self.actor
            .sessions
            .get(&self.key.scope())
            .is_some_and(|session| session.streams.contains_key(&stream_id))
    }

    /// `[last_emitted, peer_acked, sent_bytes, send_credit]` of the relay
    /// direction and `[recv_contiguous, delivered_contiguous, received_bytes,
    /// receive_credit]` of the connector direction.
    fn cursors(&self, stream_id: u64) -> [u64; 8] {
        let sequence = &self.stream(stream_id).sequence;
        let send = sequence.direction(Direction::RelayToConnector);
        let receive = sequence.direction(Direction::ConnectorToRelay);
        [
            send.last_emitted(),
            send.peer_acked(),
            send.sent_bytes(),
            send.send_credit(),
            receive.recv_contiguous(),
            receive.delivered_contiguous(),
            receive.received_bytes(),
            receive.receive_credit(),
        ]
    }

    fn relay_last_emitted(&self, stream_id: u64) -> u64 {
        self.stream(stream_id)
            .sequence
            .direction(Direction::RelayToConnector)
            .last_emitted()
    }

    fn recv_contiguous(&self, stream_id: u64) -> u64 {
        self.stream(stream_id)
            .sequence
            .direction(Direction::ConnectorToRelay)
            .recv_contiguous()
    }

    fn write(
        &mut self,
        stream_id: u64,
        body: &[u8],
    ) -> oneshot::Receiver<Result<Vec<u8>, EchoOutcome>> {
        let (response, receiver) = oneshot::channel();
        self.actor.write_echo_stream(
            self.key.clone(),
            stream_id,
            operation_id(stream_id),
            body.to_vec(),
            response,
        );
        receiver
    }

    fn close(&mut self, stream_id: u64) -> bool {
        self.actor
            .close_echo_stream(&self.key, stream_id, &operation_id(stream_id))
    }

    fn close_with_cause(
        &mut self,
        stream_id: u64,
        cause: Option<runtime::StreamTerminalCause>,
    ) -> bool {
        self.actor.close_echo_stream_with_cause(
            &self.key,
            stream_id,
            &operation_id(stream_id),
            cause,
        )
    }

    fn session_mut(&mut self) -> &mut DeviceSession {
        self.actor
            .sessions
            .get_mut(&self.key.scope())
            .expect("fixture session")
    }

    fn stream_mut(&mut self, stream_id: u64) -> &mut M2Stream {
        self.session_mut()
            .streams
            .get_mut(&stream_id)
            .expect("fixture stream")
    }

    /// Every retained first-terminal latch for one stream, in capture order.
    fn terminal_events(&self, stream_id: u64) -> Vec<&runtime::StreamTerminalEvent> {
        self.actor
            .stream_terminal_events
            .iter()
            .filter(|event| event.stream_id == stream_id && event.session_id == self.key.session_id)
            .collect()
    }

    /// The single retained latch for one stream: its reason and typed cause.
    fn terminal_latch(
        &self,
        stream_id: u64,
    ) -> (&'static str, Option<runtime::StreamTerminalCause>) {
        let events = self.terminal_events(stream_id);
        assert_eq!(
            events.len(),
            1,
            "stream {stream_id} must retain exactly one first-terminal latch"
        );
        (events[0].reason, events[0].cause)
    }

    /// Deliver one decoded connector frame through the full validator entry
    /// point, exactly as the forwarded peer record or the local socket does.
    async fn inbound(&mut self, frame: Frame) {
        let bytes = frame.encode().expect("connector frame encodes");
        self.actor.inbound_data(self.carrier.clone(), bytes).await;
    }

    async fn inbound_bytes(&mut self, bytes: Vec<u8>) {
        self.actor.inbound_data(self.carrier.clone(), bytes).await;
    }

    /// Every frame queued to the device carrier since the previous drain, in
    /// queue order.  Panics on a carrier close because every scenario that
    /// expects one asserts the session removal directly.
    fn drain_frames(&mut self) -> Vec<Frame> {
        let mut frames = Vec::new();
        while let Ok(item) = self.data_rx.try_recv() {
            match item {
                DataOutbound::Binary(mut bytes) => {
                    frames.push(Frame::decode(bytes.as_slice()).expect("relay frame decodes"));
                    bytes.release();
                }
                DataOutbound::Barrier(_) => {}
                DataOutbound::Close => {}
            }
        }
        frames
    }

    fn drain_control(&mut self) -> Vec<ControlMessage> {
        let mut messages = Vec::new();
        while let Ok(item) = self.control_rx.try_recv() {
            if let ControlOutbound::Text(mut queued) = item {
                messages
                    .push(wire::parse_control(queued.as_bytes()).expect("relay control decodes"));
                queued.release();
            }
        }
        messages
    }
}

/// A complete length-prefixed application record as carried in DATA payloads.
fn record(body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(body.len() + 4);
    payload.extend_from_slice(&(body.len() as u32).to_be_bytes());
    payload.extend_from_slice(body);
    payload
}

fn sequenced(frames: &[Frame]) -> Vec<(u64, FrameKind, u64)> {
    frames
        .iter()
        .filter(|frame| {
            matches!(
                frame.kind,
                FrameKind::Data | FrameKind::Fin | FrameKind::Reset
            )
        })
        .map(|frame| (frame.stream_id, frame.kind, frame.sequence))
        .collect()
}

fn acks(frames: &[Frame]) -> Vec<(u64, u64)> {
    frames
        .iter()
        .filter(|frame| frame.kind == FrameKind::Ack)
        .map(|frame| (frame.stream_id, frame.ack))
        .collect()
}

fn resolved(
    receiver: &mut oneshot::Receiver<Result<Vec<u8>, EchoOutcome>>,
) -> Option<Result<Vec<u8>, EchoOutcome>> {
    receiver.try_recv().ok()
}

/// The delivered response body, panicking on a typed failure so the failure
/// code is visible in the assertion output.
fn resolved_ok(receiver: &mut oneshot::Receiver<Result<Vec<u8>, EchoOutcome>>) -> Option<Vec<u8>> {
    match resolved(receiver) {
        Some(Ok(body)) => Some(body),
        Some(Err(failure)) => panic!("record failed instead of resolving: {failure:?}"),
        None => None,
    }
}

// ---------------------------------------------------------------------------
// EC-030: per-session/stream/direction sequence reservation and enqueue are
// serialized; counters advance only after accepted frames.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn interleaved_producers_keep_each_stream_contiguous_without_reordering() {
    let mut fixture = LateFixture::new("interleave");
    let max_body = wire::MAX_BODY_BYTES;
    // Explicit interleaving of two producers on sibling streams, with one
    // maximum record that must span two DATA frames on stream A.
    let mut a1 = fixture.write(STREAM_A, b"a1");
    let mut b1 = fixture.write(STREAM_B, b"b1");
    let mut a2 = fixture.write(STREAM_A, b"a2");
    let mut a3 = fixture.write(STREAM_A, &vec![0x33; max_body]);
    let mut b2 = fixture.write(STREAM_B, b"b2");
    let frames = fixture.drain_frames();
    assert_eq!(
        sequenced(&frames),
        vec![
            (STREAM_A, FrameKind::Data, 1),
            (STREAM_B, FrameKind::Data, 1),
            (STREAM_A, FrameKind::Data, 2),
            (STREAM_A, FrameKind::Data, 3),
            (STREAM_A, FrameKind::Data, 4),
            (STREAM_B, FrameKind::Data, 2),
        ],
        "enqueue order must equal reservation order, per stream contiguous from 1"
    );
    let a3_chunks: Vec<usize> = frames
        .iter()
        .filter(|frame| frame.stream_id == STREAM_A && frame.sequence >= 3)
        .map(|frame| frame.payload.len())
        .collect();
    assert_eq!(
        a3_chunks,
        vec![
            tunnel_protocol::MAX_PAYLOAD_LEN,
            max_body + 4 - tunnel_protocol::MAX_PAYLOAD_LEN
        ],
        "a multi-frame record keeps its chunks adjacent in its own sequence space"
    );
    assert_eq!(fixture.relay_last_emitted(STREAM_A), 4);
    assert_eq!(fixture.relay_last_emitted(STREAM_B), 2);
    for (label, receiver) in [
        ("a1", &mut a1),
        ("b1", &mut b1),
        ("a2", &mut a2),
        ("a3", &mut a3),
        ("b2", &mut b2),
    ] {
        assert!(
            resolved(receiver).is_none(),
            "{label}: an accepted record waits for the connector response"
        );
    }

    // Connector producers on both streams: a gapped frame on A is held
    // without advancing the contiguous cursor, and the ACK it triggers still
    // reports the accepted cursor only.  The missing frame releases both in
    // order, and the sibling's cursor is never touched.
    let before_b = fixture.cursors(STREAM_B);
    fixture
        .inbound(Frame::data(
            EPOCH,
            GENERATION,
            STREAM_A,
            2,
            4,
            record(b"resp-a2"),
        ))
        .await;
    assert_eq!(
        fixture.recv_contiguous(STREAM_A),
        0,
        "a gap must not advance the cursor"
    );
    assert_eq!(acks(&fixture.drain_frames()), vec![(STREAM_A, 0)]);
    assert!(
        resolved(&mut a1).is_none(),
        "no record is delivered across a gap"
    );
    fixture
        .inbound(Frame::data(
            EPOCH,
            GENERATION,
            STREAM_A,
            1,
            4,
            record(b"resp-a1"),
        ))
        .await;
    assert_eq!(fixture.recv_contiguous(STREAM_A), 2);
    assert_eq!(acks(&fixture.drain_frames()), vec![(STREAM_A, 2)]);
    assert_eq!(resolved_ok(&mut a1), Some(record(b"resp-a1")));
    assert_eq!(resolved_ok(&mut a2), Some(record(b"resp-a2")));
    assert_eq!(
        fixture.cursors(STREAM_B),
        before_b,
        "sibling cursors are untouched"
    );
    fixture
        .inbound(Frame::data(
            EPOCH,
            GENERATION,
            STREAM_B,
            1,
            2,
            record(b"resp-b1"),
        ))
        .await;
    assert_eq!(resolved_ok(&mut b1), Some(record(b"resp-b1")));
    assert_eq!(fixture.recv_contiguous(STREAM_B), 1);
    assert!(fixture.session_alive());
}

#[tokio::test]
async fn refused_records_never_advance_the_relay_sequence_or_leak_budget() {
    let mut fixture = LateFixture::new("refusal");
    let mut accepted = fixture.write(STREAM_A, b"accepted");
    assert_eq!(
        sequenced(&fixture.drain_frames()),
        vec![(STREAM_A, FrameKind::Data, 1)]
    );
    let before = fixture.cursors(STREAM_A);
    let budget_before = fixture.stream(STREAM_A).budget_bytes;

    // A body over the limit is refused before any reservation.
    let mut oversized = fixture.write(STREAM_A, &vec![0x44; wire::MAX_BODY_BYTES + 1]);
    assert!(matches!(
        resolved(&mut oversized),
        Some(Err(EchoOutcome::Failure {
            code: "BODY_LIMIT",
            execution: "not_dispatched"
        }))
    ));
    assert_eq!(fixture.cursors(STREAM_A), before);
    assert!(fixture.drain_frames().is_empty());

    // A writer whose bounded queue refuses the frame must not consume the
    // reserved sequence number: the frame was never accepted by the carrier.
    let (full_tx, mut full_rx) = mpsc::channel(1);
    full_tx
        .try_send(DataOutbound::Close)
        .expect("filler occupies the only slot");
    let original_tx = {
        let session = fixture
            .actor
            .sessions
            .get_mut(&fixture.key.scope())
            .expect("fixture session");
        let original = session.data_tx.clone().expect("active writer");
        session.data_tx = Some(full_tx.clone());
        session.active_carrier = Some(DataCarrier {
            context: fixture.carrier.context(),
            tx: full_tx,
        });
        original
    };
    let mut refused = fixture.write(STREAM_A, b"refused");
    assert!(
        matches!(
            resolved(&mut refused),
            Some(Err(EchoOutcome::Failure {
                code: "REVERSE_CHANNEL_UNAVAILABLE",
                execution: "not_dispatched"
            }))
        ),
        "a queue refusal is a typed, not-dispatched outcome"
    );
    assert_eq!(
        fixture.cursors(STREAM_A),
        before,
        "a refused frame must not advance last_emitted or sent_bytes"
    );
    assert_eq!(
        fixture.stream(STREAM_A).budget_bytes,
        budget_before,
        "a refused frame must release its stream budget reservation"
    );
    assert!(matches!(full_rx.try_recv(), Ok(DataOutbound::Close)));
    assert!(
        full_rx.try_recv().is_err(),
        "nothing was queued behind the filler"
    );
    drop(full_rx);

    // With the writer restored the next record takes the very next sequence.
    {
        let session = fixture
            .actor
            .sessions
            .get_mut(&fixture.key.scope())
            .expect("fixture session");
        session.data_tx = Some(original_tx.clone());
        session.active_carrier = Some(DataCarrier {
            context: fixture.carrier.context(),
            tx: original_tx,
        });
    }
    let mut next = fixture.write(STREAM_A, b"next");
    assert_eq!(
        sequenced(&fixture.drain_frames()),
        vec![(STREAM_A, FrameKind::Data, 2)]
    );
    assert_eq!(fixture.relay_last_emitted(STREAM_A), 2);
    assert!(resolved(&mut accepted).is_none());
    assert!(resolved(&mut next).is_none());
    assert!(fixture.session_alive());
}

#[tokio::test]
async fn credit_bound_record_waits_for_window_update_and_then_takes_the_next_sequence() {
    let mut fixture = LateFixture::new("credit");
    let window = wire::M2_INITIAL_WINDOW_BYTES;
    // Two maximum records exhaust the initial absolute window exactly.
    let max_body = wire::MAX_BODY_BYTES;
    let _first = fixture.write(STREAM_A, &vec![0x11; max_body]);
    let _second = fixture.write(STREAM_A, &vec![0x22; max_body - 8]);
    let emitted = sequenced(&fixture.drain_frames());
    assert_eq!(
        emitted.len(),
        3,
        "two records span three frames: {emitted:?}"
    );
    assert_eq!(fixture.relay_last_emitted(STREAM_A), 3);
    let sent = fixture
        .stream(STREAM_A)
        .sequence
        .direction(Direction::RelayToConnector)
        .sent_bytes();
    assert_eq!(sent as usize, window, "the window is exactly consumed");
    let before = fixture.cursors(STREAM_A);
    let mut held = fixture.write(STREAM_A, b"held");
    assert!(resolved(&mut held).is_none());
    assert!(
        fixture.drain_frames().is_empty(),
        "no frame beyond credit is emitted"
    );
    assert_eq!(
        fixture.cursors(STREAM_A),
        before,
        "a held record reserves no sequence"
    );
    assert_eq!(fixture.stream(STREAM_A).pending_records.len(), 1);
    // The sibling is not blocked by A's exhausted credit.
    let _sibling = fixture.write(STREAM_B, b"b");
    assert_eq!(
        sequenced(&fixture.drain_frames()),
        vec![(STREAM_B, FrameKind::Data, 1)]
    );
    // Absolute credit from the connector releases the held record with the
    // continuing sequence.
    fixture
        .inbound(Frame::window_update(
            EPOCH,
            GENERATION,
            STREAM_A,
            (window * 2) as u64,
        ))
        .await;
    assert_eq!(
        sequenced(&fixture.drain_frames()),
        vec![(STREAM_A, FrameKind::Data, 4)]
    );
    assert_eq!(fixture.relay_last_emitted(STREAM_A), 4);
    assert!(fixture.stream(STREAM_A).pending_records.is_empty());
    assert!(fixture.session_alive());
}

// ---------------------------------------------------------------------------
// EC-037 / IN-06: late events are narrowly bound to a live stream and
// generation; they cannot recreate state, grant credit or touch a sibling.
// Malformed and conflicting frames still fence the whole session.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn late_frames_on_a_forgotten_stream_are_dropped_while_the_sibling_keeps_serving() {
    let mut fixture = LateFixture::new("forgotten");
    // Sibling B is live with one outstanding record.
    let mut b1 = fixture.write(STREAM_B, b"b1");
    assert_eq!(
        sequenced(&fixture.drain_frames()),
        vec![(STREAM_B, FrameKind::Data, 1)]
    );

    // Close A: relay FIN 1, connector FIN 1 acknowledging it, relay ACK, and
    // the owner's STREAM_FORGET reclaims the stream.
    assert!(fixture.close(STREAM_A));
    assert_eq!(
        sequenced(&fixture.drain_frames()),
        vec![(STREAM_A, FrameKind::Fin, 1)]
    );
    fixture
        .inbound(Frame::fin(EPOCH, GENERATION, STREAM_A, 1, 1))
        .await;
    assert_eq!(acks(&fixture.drain_frames()), vec![(STREAM_A, 1)]);
    let forgets: Vec<u64> = fixture
        .drain_control()
        .into_iter()
        .filter_map(|message| match message {
            ControlMessage::StreamForget(forget) => Some(forget.stream_id),
            _ => None,
        })
        .collect();
    assert_eq!(
        forgets,
        vec![STREAM_A],
        "the owner reclaims exactly stream A"
    );
    assert!(!fixture.has_stream(STREAM_A));
    assert_eq!(
        fixture
            .actor
            .sessions
            .get(&fixture.key.scope())
            .map(|session| session.forgotten_stream_through),
        Some(STREAM_A)
    );
    let receipts_before = fixture.actor.stream_terminal_receipt_events.len();
    let terminals_before = fixture.actor.stream_terminal_events.len();
    let sibling_before = fixture.cursors(STREAM_B);

    // Late DATA, FIN, RESET, ACK, credit and a replay of the accepted FIN on
    // the forgotten stream, interleaved with nothing else.
    for late in [
        Frame::window_update(EPOCH, GENERATION, STREAM_A, u64::MAX / 2),
        Frame::data(EPOCH, GENERATION, STREAM_A, 2, 1, record(b"late")),
        Frame::fin(EPOCH, GENERATION, STREAM_A, 2, 1),
        Frame::reset(EPOCH, GENERATION, STREAM_A, 2, 1, 4_002),
        Frame::ack(EPOCH, GENERATION, STREAM_A, 1),
        Frame::fin(EPOCH, GENERATION, STREAM_A, 1, 1),
    ] {
        fixture.inbound(late).await;
        assert!(
            fixture.session_alive(),
            "a late frame on a forgotten stream never fences"
        );
        assert!(
            !fixture.has_stream(STREAM_A),
            "a late frame cannot recreate state"
        );
    }
    assert!(
        fixture.drain_frames().is_empty(),
        "no ACK, credit or terminal is emitted for it"
    );
    assert!(
        fixture.drain_control().is_empty(),
        "no second FORGET or control reply"
    );
    assert_eq!(
        fixture.actor.stream_terminal_receipt_events.len(),
        receipts_before
    );
    assert_eq!(fixture.actor.stream_terminal_events.len(), terminals_before);
    assert!(!fixture.actor.owner_forgets.contains_key(&fixture.key));
    assert_eq!(
        fixture.cursors(STREAM_B),
        sibling_before,
        "late credit on A grants B nothing"
    );

    // The sibling continues in both directions with the continuing sequence.
    fixture
        .inbound(Frame::data(
            EPOCH,
            GENERATION,
            STREAM_B,
            1,
            1,
            record(b"resp-b1"),
        ))
        .await;
    assert_eq!(resolved_ok(&mut b1), Some(record(b"resp-b1")));
    assert_eq!(acks(&fixture.drain_frames()), vec![(STREAM_B, 1)]);
    let mut b2 = fixture.write(STREAM_B, b"b2");
    assert_eq!(
        sequenced(&fixture.drain_frames()),
        vec![(STREAM_B, FrameKind::Data, 2)]
    );
    assert!(resolved(&mut b2).is_none());

    // A frame for a stream that never existed above the FORGET watermark is
    // not a late event: it still fences the session, interrupting B.
    fixture
        .inbound(Frame::data(
            EPOCH,
            GENERATION,
            STREAM_B + 1,
            1,
            0,
            record(b"ghost"),
        ))
        .await;
    assert!(
        !fixture.session_alive(),
        "an unknown live stream ID fails closed"
    );
    assert_eq!(fixture.close_reason(), Some("UNKNOWN_STREAM"));
    assert!(matches!(
        resolved(&mut b2),
        Some(Err(EchoOutcome::Failure {
            code: "REVERSE_CHANNEL_INTERRUPTED",
            ..
        }))
    ));
}

#[tokio::test]
async fn identical_replay_is_idempotent_and_conflicting_replay_fences_the_session() {
    let mut fixture = LateFixture::new("replay");
    let mut a1 = fixture.write(STREAM_A, b"a1");
    let mut b1 = fixture.write(STREAM_B, b"b1");
    fixture.drain_frames();
    let response = Frame::data(EPOCH, GENERATION, STREAM_A, 1, 1, record(b"resp-a1"));
    fixture.inbound(response.clone()).await;
    assert_eq!(resolved_ok(&mut a1), Some(record(b"resp-a1")));
    assert_eq!(acks(&fixture.drain_frames()), vec![(STREAM_A, 1)]);
    let after_first = fixture.cursors(STREAM_A);
    let credit_before = fixture
        .stream(STREAM_A)
        .sequence
        .direction(Direction::ConnectorToRelay)
        .receive_credit();

    // The identical frame again: acknowledged again, delivered never again,
    // no counter movement and no fresh credit.
    fixture.inbound(response.clone()).await;
    assert!(fixture.session_alive());
    let frames = fixture.drain_frames();
    assert_eq!(
        acks(&frames),
        vec![(STREAM_A, 1)],
        "a duplicate is re-acknowledged"
    );
    assert!(
        frames
            .iter()
            .all(|frame| frame.kind != FrameKind::WindowUpdate),
        "a duplicate grants no receive credit"
    );
    assert_eq!(fixture.cursors(STREAM_A), after_first);
    assert_eq!(
        fixture
            .stream(STREAM_A)
            .sequence
            .direction(Direction::ConnectorToRelay)
            .receive_credit(),
        credit_before
    );
    assert!(
        fixture.stream(STREAM_A).response_bytes.is_empty(),
        "no partial second delivery"
    );
    assert!(fixture.stream(STREAM_A).response_records.is_empty());

    // The same sequence with different content is a protocol error while its
    // fingerprint is retained: the session fences and the sibling is
    // interrupted with a typed outcome.
    fixture
        .inbound(Frame::data(
            EPOCH,
            GENERATION,
            STREAM_A,
            1,
            1,
            record(b"resp-a1-forged"),
        ))
        .await;
    assert!(
        !fixture.session_alive(),
        "a conflicting replay fails closed"
    );
    assert_eq!(fixture.close_reason(), Some("INVALID_SEQUENCE"));
    assert!(matches!(
        resolved(&mut b1),
        Some(Err(EchoOutcome::Failure {
            code: "REVERSE_CHANNEL_INTERRUPTED",
            ..
        }))
    ));
}

#[tokio::test]
async fn malformed_bytes_beside_a_healthy_sibling_fence_before_reaching_stream_state() {
    for (label, reason, malformed) in [
        ("truncated-header", "INVALID_FRAME", vec![0x01_u8; 7]),
        (
            "oversized",
            "FRAME_LIMIT",
            vec![0x00_u8; tunnel_protocol::frame::MAX_FRAME_LEN + 1],
        ),
        ("invalid-kind", "INVALID_FRAME", {
            let mut bytes = Frame::data(EPOCH, GENERATION, STREAM_A, 1, 0, record(b"x"))
                .encode()
                .expect("frame encodes");
            bytes[0] = 0xff;
            bytes
        }),
    ] {
        let mut fixture = LateFixture::new(&format!("malformed-{label}"));
        let mut b1 = fixture.write(STREAM_B, b"b1");
        fixture.drain_frames();
        let a_before = fixture.cursors(STREAM_A);
        fixture.inbound_bytes(malformed).await;
        assert!(
            !fixture.session_alive(),
            "{label}: malformed bytes fail closed"
        );
        assert_eq!(fixture.close_reason(), Some(reason), "{label}");
        assert!(
            matches!(
                resolved(&mut b1),
                Some(Err(EchoOutcome::Failure {
                    code: "REVERSE_CHANNEL_INTERRUPTED",
                    ..
                }))
            ),
            "{label}: the healthy sibling is interrupted with a typed outcome"
        );
        assert_eq!(
            a_before[4], 0,
            "{label}: no stream cursor moved before the fence"
        );
    }
}

#[tokio::test]
async fn stale_epoch_or_generation_on_the_active_carrier_fails_closed() {
    for (label, frame) in [
        (
            "stale-generation",
            Frame::data(EPOCH, GENERATION - 1, STREAM_A, 1, 0, record(b"x")),
        ),
        (
            "future-generation",
            Frame::data(EPOCH, GENERATION + 1, STREAM_A, 1, 0, record(b"x")),
        ),
        (
            "stale-epoch",
            Frame::data(EPOCH - 1, GENERATION, STREAM_A, 1, 0, record(b"x")),
        ),
    ] {
        let mut fixture = LateFixture::new(&format!("stale-{label}"));
        let mut b1 = fixture.write(STREAM_B, b"b1");
        fixture.drain_frames();
        fixture.inbound(frame).await;
        assert!(
            !fixture.session_alive(),
            "{label}: STALE_DATA fences the session"
        );
        assert_eq!(fixture.close_reason(), Some("STALE_DATA"), "{label}");
        assert!(matches!(
            resolved(&mut b1),
            Some(Err(EchoOutcome::Failure {
                code: "REVERSE_CHANNEL_INTERRUPTED",
                ..
            }))
        ));
    }
}

// ---------------------------------------------------------------------------
// EC-044: direction and terminal-precedence dimensions of the shared
// validator on the device carrier (generation, fragmentation and post-drain
// rejection are covered above and in the rotation freeze regressions).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn acknowledgement_beyond_the_relay_direction_fails_closed() {
    let mut fixture = LateFixture::new("ack-direction");
    let _a1 = fixture.write(STREAM_A, b"a1");
    fixture.drain_frames();
    assert_eq!(fixture.relay_last_emitted(STREAM_A), 1);
    // A cumulative ACK is bounded by the opposite direction's emitted cursor.
    fixture
        .inbound(Frame::data(
            EPOCH,
            GENERATION,
            STREAM_A,
            1,
            2,
            record(b"resp"),
        ))
        .await;
    assert!(
        !fixture.session_alive(),
        "an ACK beyond last_emitted is a protocol error"
    );
    assert_eq!(fixture.close_reason(), Some("INVALID_SEQUENCE"));
}

#[tokio::test]
async fn connector_terminal_precedence_allows_one_reset_after_fin_and_nothing_after() {
    let mut fixture = LateFixture::new("terminal-precedence");
    let _a1 = fixture.write(STREAM_A, b"a1");
    let mut b1 = fixture.write(STREAM_B, b"b1");
    fixture.drain_frames();
    fixture
        .inbound(Frame::fin(EPOCH, GENERATION, STREAM_A, 1, 1))
        .await;
    let frames = fixture.drain_frames();
    assert_eq!(acks(&frames), vec![(STREAM_A, 1)]);
    assert_eq!(
        sequenced(&frames),
        vec![(STREAM_A, FrameKind::Fin, 2)],
        "the relay half-closes with the next sequence after its one DATA frame"
    );
    assert!(fixture.stream(STREAM_A).terminal);
    assert_eq!(
        fixture
            .stream(STREAM_A)
            .sequence
            .direction(Direction::ConnectorToRelay)
            .receive_terminal(),
        Some(Terminal::Fin)
    );

    // One RESET after FIN is accepted and acknowledged, but the relay emits
    // no second terminal in its own direction.
    fixture
        .inbound(Frame::reset(EPOCH, GENERATION, STREAM_A, 2, 2, 4_010))
        .await;
    assert!(fixture.session_alive());
    let frames = fixture.drain_frames();
    assert_eq!(acks(&frames), vec![(STREAM_A, 2)]);
    assert!(
        sequenced(&frames).is_empty(),
        "no duplicate terminal after FIN: {frames:?}"
    );
    assert_eq!(
        fixture
            .stream(STREAM_A)
            .sequence
            .direction(Direction::RelayToConnector)
            .send_terminal_sequence(),
        Some(2)
    );
    assert_eq!(
        fixture
            .stream(STREAM_A)
            .sequence
            .direction(Direction::ConnectorToRelay)
            .receive_terminal(),
        Some(Terminal::Reset(4_010))
    );

    // DATA after the connector's terminal is a protocol error: the session
    // fences and the sibling's outstanding record is interrupted.
    fixture
        .inbound(Frame::data(
            EPOCH,
            GENERATION,
            STREAM_A,
            3,
            2,
            record(b"after"),
        ))
        .await;
    assert!(!fixture.session_alive());
    assert_eq!(fixture.close_reason(), Some("INVALID_SEQUENCE"));
    assert!(matches!(
        resolved(&mut b1),
        Some(Err(EchoOutcome::Failure {
            code: "REVERSE_CHANNEL_INTERRUPTED",
            ..
        }))
    ));
}

// ---------------------------------------------------------------------------
// EC-047: error/close frames use the current accepted per-direction
// sequence, with no hard-coded gap and no duplicate terminal result.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn consumer_close_uses_the_next_sequence_after_zero_one_and_many_records() {
    for prior in [0_u64, 1, 3] {
        let mut fixture = LateFixture::new(&format!("close-after-{prior}"));
        let mut waiters = Vec::new();
        for index in 0..prior {
            waiters.push(fixture.write(STREAM_A, format!("a{index}").as_bytes()));
        }
        fixture.drain_frames();
        // The connector answers every record so both directions hold
        // `prior` accepted frames.
        for index in 0..prior {
            fixture
                .inbound(Frame::data(
                    EPOCH,
                    GENERATION,
                    STREAM_A,
                    index + 1,
                    prior,
                    record(format!("r{index}").as_bytes()),
                ))
                .await;
        }
        fixture.drain_frames();
        for (index, waiter) in waiters.iter_mut().enumerate() {
            assert_eq!(
                resolved_ok(waiter),
                Some(record(format!("r{index}").as_bytes()))
            );
        }
        assert_eq!(fixture.relay_last_emitted(STREAM_A), prior);
        assert_eq!(fixture.recv_contiguous(STREAM_A), prior);

        assert!(fixture.close(STREAM_A));
        let frames = fixture.drain_frames();
        assert_eq!(
            sequenced(&frames),
            vec![(STREAM_A, FrameKind::Fin, prior + 1)],
            "prior={prior}: FIN takes exactly the next accepted sequence"
        );
        let fin = frames
            .iter()
            .find(|frame| frame.kind == FrameKind::Fin)
            .expect("FIN");
        assert_eq!(
            fin.ack, prior,
            "prior={prior}: FIN carries the accepted receive cursor"
        );
        assert_eq!(fin.generation, GENERATION);
        assert_eq!(
            fixture
                .stream(STREAM_A)
                .sequence
                .direction(Direction::RelayToConnector)
                .send_terminal_sequence(),
            Some(prior + 1)
        );

        // Closing again is idempotent: no second terminal, no cursor change.
        assert!(fixture.close(STREAM_A));
        assert!(
            fixture.drain_frames().is_empty(),
            "prior={prior}: no duplicate FIN"
        );
        assert_eq!(fixture.relay_last_emitted(STREAM_A), prior + 1);

        // The connector's own FIN completes the stream with one ACK and one
        // FORGET; the relay never emits a second terminal.
        fixture
            .inbound(Frame::fin(
                EPOCH,
                GENERATION,
                STREAM_A,
                prior + 1,
                prior + 1,
            ))
            .await;
        let frames = fixture.drain_frames();
        assert_eq!(acks(&frames), vec![(STREAM_A, prior + 1)]);
        assert!(
            sequenced(&frames).is_empty(),
            "prior={prior}: no terminal after FIN"
        );
        let forgets = fixture
            .drain_control()
            .into_iter()
            .filter(|message| matches!(message, ControlMessage::StreamForget(_)))
            .count();
        assert_eq!(forgets, 1, "prior={prior}: exactly one owner FORGET");
        assert!(!fixture.has_stream(STREAM_A));
        assert!(
            fixture.has_stream(STREAM_B),
            "prior={prior}: the sibling is retained"
        );
        assert!(fixture.session_alive());
    }
}

#[tokio::test]
async fn reciprocal_reset_uses_the_next_sequence_after_zero_one_and_many_records() {
    for prior in [0_u64, 1, 3] {
        let mut fixture = LateFixture::new(&format!("reset-after-{prior}"));
        for index in 0..prior {
            drop(fixture.write(STREAM_A, format!("a{index}").as_bytes()));
        }
        fixture.drain_frames();
        for index in 0..prior {
            fixture
                .inbound(Frame::data(
                    EPOCH,
                    GENERATION,
                    STREAM_A,
                    index + 1,
                    prior,
                    record(format!("r{index}").as_bytes()),
                ))
                .await;
        }
        fixture.drain_frames();
        let reset = Frame::reset(EPOCH, GENERATION, STREAM_A, prior + 1, prior, 4_002);
        fixture.inbound(reset.clone()).await;
        let frames = fixture.drain_frames();
        assert_eq!(acks(&frames), vec![(STREAM_A, prior + 1)]);
        assert_eq!(
            sequenced(&frames),
            vec![(STREAM_A, FrameKind::Reset, prior + 1)],
            "prior={prior}: the reciprocal RESET takes exactly the next accepted sequence"
        );
        let reciprocal = frames
            .iter()
            .find(|frame| frame.kind == FrameKind::Reset)
            .expect("RESET");
        assert_eq!(
            reciprocal.ack,
            prior + 1,
            "prior={prior}: RESET acknowledges the peer RESET"
        );
        assert_eq!(reciprocal.reset_reason().expect("reason"), Some(4_002));
        assert_eq!(fixture.relay_last_emitted(STREAM_A), prior + 1);

        // A duplicate peer RESET is re-acknowledged but never answered twice,
        // and a consumer close after the RESET adds no terminal either.
        fixture.inbound(reset).await;
        let frames = fixture.drain_frames();
        assert_eq!(acks(&frames), vec![(STREAM_A, prior + 1)]);
        assert!(
            sequenced(&frames).is_empty(),
            "prior={prior}: no duplicate RESET"
        );
        assert!(fixture.close(STREAM_A));
        assert!(
            fixture.drain_frames().is_empty(),
            "prior={prior}: no FIN after RESET"
        );
        assert_eq!(fixture.relay_last_emitted(STREAM_A), prior + 1);
        assert!(fixture.session_alive());
        assert!(fixture.has_stream(STREAM_B));
    }
}

#[tokio::test]
async fn late_response_for_an_owner_closed_stream_is_discarded_without_fencing_the_session() {
    // Regression from the queue-saturation gate after EC-045: the owner side
    // closes a stream (the ingress reset the peer request half) while a
    // dispatched record's waiter is still outstanding.  The connector already
    // holds that record and answers it after the close.  That answer is late,
    // not unsolicited: it must be discarded on the tombstone with the cursors
    // and ACK advancing normally, the session must stay alive and the sibling
    // must keep serving.  A second, genuinely unsolicited record on the same
    // closed stream is still a protocol failure.
    let mut fixture = LateFixture::new("orphaned-response");
    let mut a1 = fixture.write(STREAM_A, b"a1");
    let mut b1 = fixture.write(STREAM_B, b"b1");
    assert_eq!(
        sequenced(&fixture.drain_frames()),
        vec![
            (STREAM_A, FrameKind::Data, 1),
            (STREAM_B, FrameKind::Data, 1)
        ]
    );
    assert!(fixture.close(STREAM_A));
    assert!(
        matches!(
            resolved(&mut a1),
            Some(Err(EchoOutcome::Failure {
                code: "REVERSE_CHANNEL_INTERRUPTED",
                execution: "unknown",
            }))
        ),
        "the outstanding waiter is failed with the typed unknown outcome"
    );
    assert_eq!(fixture.stream(STREAM_A).orphaned_response_records, 1);
    assert_eq!(
        sequenced(&fixture.drain_frames()),
        vec![(STREAM_A, FrameKind::Fin, 2)],
        "the owner close takes the next relay sequence"
    );

    // The connector answers the record it received before the close.
    fixture
        .inbound(Frame::data(
            EPOCH,
            GENERATION,
            STREAM_A,
            1,
            2,
            record(b"resp-a1"),
        ))
        .await;
    assert!(
        fixture.session_alive(),
        "a late answer to an owner-closed stream must not fence the session"
    );
    assert_eq!(fixture.close_reason(), None);
    assert_eq!(fixture.recv_contiguous(STREAM_A), 1);
    assert_eq!(acks(&fixture.drain_frames()), vec![(STREAM_A, 1)]);
    let closed = fixture.stream(STREAM_A);
    assert_eq!(closed.orphaned_response_records, 0);
    assert_eq!(closed.late_response_records, 1);
    assert!(closed.response_bytes.is_empty());
    assert!(closed.terminal);

    // The sibling is untouched and still resolves its own record.
    fixture
        .inbound(Frame::data(
            EPOCH,
            GENERATION,
            STREAM_B,
            1,
            1,
            record(b"resp-b1"),
        ))
        .await;
    assert_eq!(resolved_ok(&mut b1), Some(record(b"resp-b1")));
    assert!(fixture.session_alive());

    // Beyond the orphan allowance a record on the closed stream is
    // unsolicited and fences the session exactly as before.
    fixture
        .inbound(Frame::data(
            EPOCH,
            GENERATION,
            STREAM_A,
            2,
            2,
            record(b"unsolicited"),
        ))
        .await;
    assert!(!fixture.session_alive());
    assert_eq!(fixture.close_reason(), Some("INVALID_SEQUENCE"));
}

#[tokio::test]
async fn partial_late_response_keeps_its_framing_across_the_owner_close() {
    // The close must not clear a half-received response record: the
    // remainder arrives after the close and completes the same record, so
    // the length prefix of any later record stays aligned.
    let mut fixture = LateFixture::new("orphaned-partial");
    let mut a1 = fixture.write(STREAM_A, b"a1");
    let _ = fixture.drain_frames();
    let full = record(b"resp-a1-partial");
    let (head, tail) = full.split_at(6);
    fixture
        .inbound(Frame::data(
            EPOCH,
            GENERATION,
            STREAM_A,
            1,
            1,
            head.to_vec(),
        ))
        .await;
    let _ = fixture.drain_frames();
    assert!(resolved(&mut a1).is_none());
    assert_eq!(fixture.stream(STREAM_A).response_bytes, head);

    assert!(fixture.close(STREAM_A));
    assert!(matches!(resolved(&mut a1), Some(Err(_))));
    assert_eq!(
        fixture.stream(STREAM_A).response_bytes,
        head,
        "partial response bytes survive the close"
    );
    let _ = fixture.drain_frames();

    fixture
        .inbound(Frame::data(
            EPOCH,
            GENERATION,
            STREAM_A,
            2,
            2,
            tail.to_vec(),
        ))
        .await;
    assert!(fixture.session_alive());
    assert_eq!(fixture.close_reason(), None);
    let closed = fixture.stream(STREAM_A);
    assert!(closed.response_bytes.is_empty());
    assert_eq!(closed.late_response_records, 1);
    assert_eq!(closed.orphaned_response_records, 0);
    assert_eq!(fixture.recv_contiguous(STREAM_A), 2);
}

#[tokio::test]
async fn connector_terminal_releases_a_partial_response_and_keeps_the_tombstone_reclaimable() {
    // Audit finding on the orphan allowance: a connector that answers the
    // owner's close with its own FIN while a response record is half
    // received must not leave a tombstone that STREAM_FORGET can never
    // reclaim.  The partial bytes and their charge are released on the
    // connector terminal, the late-reply allowance closes, and the stream
    // becomes a FORGET candidate once the relay's FIN is acknowledged.
    let mut fixture = LateFixture::new("orphaned-terminal");
    let mut a1 = fixture.write(STREAM_A, b"a1");
    let _ = fixture.drain_frames();
    let full = record(b"resp-a1-partial");
    let (head, _tail) = full.split_at(6);
    fixture
        .inbound(Frame::data(
            EPOCH,
            GENERATION,
            STREAM_A,
            1,
            1,
            head.to_vec(),
        ))
        .await;
    let _ = fixture.drain_frames();
    assert!(fixture.close(STREAM_A));
    assert!(matches!(resolved(&mut a1), Some(Err(_))));
    let _ = fixture.drain_frames();
    let budget_before = fixture.stream(STREAM_A).budget_bytes;
    assert!(budget_before >= head.len());
    assert_eq!(fixture.stream(STREAM_A).orphaned_response_records, 1);

    // The connector acknowledges the relay's FIN (sequence 2) and ends its
    // own direction without completing the record.
    fixture
        .inbound(Frame::fin(EPOCH, GENERATION, STREAM_A, 2, 2))
        .await;
    assert!(fixture.session_alive());
    assert_eq!(fixture.close_reason(), None);
    // Both terminals are now authenticated and nothing is retained, so the
    // tombstone is reclaimed on this very ACK path: the stream is gone, the
    // sibling is untouched and the session keeps serving.
    assert!(
        !fixture.has_stream(STREAM_A),
        "the tombstone must be reclaimed once both terminals are in and no partial record is retained"
    );
    assert!(fixture.has_stream(STREAM_B));
    let mut b1 = fixture.write(STREAM_B, b"b1");
    let _ = fixture.drain_frames();
    fixture
        .inbound(Frame::data(
            EPOCH,
            GENERATION,
            STREAM_B,
            1,
            1,
            record(b"resp-b1"),
        ))
        .await;
    assert_eq!(resolved_ok(&mut b1), Some(record(b"resp-b1")));
    let _ = budget_before;
}

// ---------------------------------------------------------------------------
// M7-I27: typed first causes for the stream terminal latch.
//
// `StreamTerminalCause` distinguishes the conditions a close can prove for
// itself.  Each regression below produces exactly one condition and asserts
// exactly the cause it proves, with the existing latch semantics unchanged:
// one immutable, payload-free record per stream, captured at the first
// terminal transition and therefore before STREAM_FORGET can reclaim it.
// Nothing here changes when a stream closes, what is emitted, or the
// `STREAM_CLOSED` reason string.
// ---------------------------------------------------------------------------

/// Fill the device carrier's bounded writer queue with barriers so the next
/// terminal frame cannot be handed to a carrier that is still live.
///
/// Barriers carry no queue-budget charge, so this saturates the writer slots
/// exactly, without also draining the byte budget and blurring the two facts.
fn saturate_carrier_slots(fixture: &mut LateFixture) -> Vec<oneshot::Receiver<()>> {
    let data_tx = fixture
        .session_mut()
        .data_tx
        .clone()
        .expect("fixture carrier sender");
    let mut held = Vec::new();
    loop {
        let (done, waiter) = oneshot::channel();
        if data_tx.try_send(DataOutbound::Barrier(done)).is_err() {
            break;
        }
        held.push(waiter);
    }
    assert_eq!(
        data_tx.capacity(),
        0,
        "the writer queue must have no free slot"
    );
    assert!(!data_tx.is_closed(), "the carrier itself stays live");
    held
}

/// Smaller than the four-byte length prefix alone, so no complete record
/// can ever fit this absolute window.
const NARROW_SEND_WINDOW: u64 = 4;

/// Give stream A a send window too small for any complete record, so the
/// next write is parked on cumulative send credit and on nothing else.
///
/// Deliberately not "write until the initial window is exhausted": that
/// route also charges the session queue budget, which is the *other* fact
/// the close site reads.  Starting from a narrow window keeps the queue and
/// budget far from full, so the cause under test is the only one available.
fn park_first_write_on_credit(
    fixture: &mut LateFixture,
) -> oneshot::Receiver<Result<Vec<u8>, EchoOutcome>> {
    fixture.stream_mut(STREAM_A).sequence =
        StreamState::new(STREAM_A, NARROW_SEND_WINDOW).expect("narrow credit window");
    let mut parked = fixture.write(STREAM_A, b"needs-credit");
    assert!(
        resolved(&mut parked).is_none(),
        "the record is parked, not refused"
    );
    assert!(
        fixture.stream(STREAM_A).credit_held,
        "the credit decision is what parked it"
    );
    assert_eq!(fixture.stream(STREAM_A).pending_records.len(), 1);
    assert!(
        fixture.drain_frames().is_empty(),
        "no DATA frame is emitted for a record that does not fit the credit"
    );
    assert_eq!(
        fixture.relay_last_emitted(STREAM_A),
        0,
        "a parked record reserves no sequence"
    );
    parked
}

/// The same refused terminal on a carrier that is *gone* is carrier loss,
/// not queue exhaustion, and stays unclassified.
///
/// This is the discriminating case for the liveness half of the close site's
/// classification. It is built on the byte-budget arm deliberately: a sender
/// whose receiver has been dropped reports its buffer as entirely free, so
/// the writer-slot arm can never fire for a lost carrier, while an exhausted
/// data budget looks identical whether the carrier is alive or gone. Without
/// the liveness guard this close would be mislabelled a capacity problem.
#[tokio::test]
async fn terminal_refused_by_a_lost_carrier_is_not_queue_exhaustion() {
    let mut fixture = LateFixture::new("cause-carrier-lost");
    // Drop the connector's receiving end: the carrier is gone.
    let (_unused_tx, unused_rx) = mpsc::channel(1);
    drop(std::mem::replace(&mut fixture.data_rx, unused_rx));
    // And leave the data lane with no byte headroom at all.
    let session = fixture.session_mut();
    while session.queue_budget.reserve_data(1) {}
    let queue_budget = session.queue_budget.clone();
    let data_tx = session
        .data_tx
        .clone()
        .expect("carrier sender outlives the receiver");
    assert!(data_tx.is_closed(), "the carrier is gone");
    assert!(
        queue_budget.data_exhausted(),
        "and the data lane has no headroom, which alone would read as exhaustion"
    );

    assert!(fixture.close(STREAM_A));

    assert_eq!(
        fixture.terminal_latch(STREAM_A),
        ("STREAM_CLOSED", None),
        "a terminal refused by a lost carrier is carrier loss, not exhaustion"
    );
    assert!(
        fixture.stream(STREAM_A).terminal_fin_failure,
        "the terminal-FIN failure marker is unchanged by the classification"
    );
    assert!(fixture.session_alive());
}

/// A close whose own terminal frame is refused by a live but full carrier
/// queue is queue exhaustion, and is latched as exactly that.
#[tokio::test]
async fn terminal_refused_by_a_full_live_carrier_latches_queue_exhaustion() {
    let mut fixture = LateFixture::new("cause-queue-exhausted");
    let _held = saturate_carrier_slots(&mut fixture);

    assert!(fixture.close(STREAM_A));

    assert_eq!(
        fixture.terminal_latch(STREAM_A),
        ("STREAM_CLOSED", Some(StreamTerminalCause::QueueExhausted)),
        "a terminal the live carrier queue refused is queue exhaustion"
    );
    assert!(
        fixture.stream(STREAM_A).terminal,
        "the stream still reaches its terminal tombstone"
    );
    assert!(
        fixture.stream(STREAM_A).terminal_fin_failure,
        "and still carries the terminal-FIN failure marker"
    );
    assert_eq!(
        fixture.relay_last_emitted(STREAM_A),
        0,
        "no phantom FIN consumed a sequence number"
    );
    assert!(
        fixture.terminal_events(STREAM_B).is_empty(),
        "the sibling stream is untouched"
    );
    assert!(fixture.session_alive());
}

/// A stream whose head record is still parked for cumulative send credit when
/// it closes is latched as delayed credit, not as a generic close and not as
/// queue exhaustion: its own FIN is queued normally.
#[tokio::test]
async fn terminal_while_the_head_record_waits_for_credit_latches_delayed_credit() {
    let mut fixture = LateFixture::new("cause-delayed-credit");
    let _parked = park_first_write_on_credit(&mut fixture);

    assert!(fixture.close(STREAM_A));

    assert_eq!(
        fixture.terminal_latch(STREAM_A),
        ("STREAM_CLOSED", Some(StreamTerminalCause::DelayedCredit)),
        "a terminal reached while the head record waits on credit is delayed credit"
    );
    let frames = fixture.drain_frames();
    assert_eq!(
        sequenced(&frames),
        vec![(STREAM_A, FrameKind::Fin, 1)],
        "the FIN itself is queued normally: this is not queue exhaustion"
    );
    assert!(
        !fixture.stream(STREAM_A).terminal_fin_failure,
        "and carries no terminal-FIN failure marker"
    );
    assert!(fixture.session_alive());
}

/// Credit that arrives before the close clears the marker, so the same stream
/// then closes unclassified. This is the negative half of the regression
/// above: the marker tracks the credit decision, not queue depth.
#[tokio::test]
async fn credit_that_arrives_before_the_close_leaves_the_terminal_unclassified() {
    let mut fixture = LateFixture::new("cause-credit-released");
    let _parked = park_first_write_on_credit(&mut fixture);

    fixture
        .inbound(Frame::window_update(
            EPOCH,
            GENERATION,
            STREAM_A,
            wire::M2_INITIAL_WINDOW_BYTES as u64,
        ))
        .await;
    assert!(
        !fixture.stream(STREAM_A).credit_held,
        "the admitted record clears the marker"
    );
    assert!(fixture.stream(STREAM_A).pending_records.is_empty());
    fixture.drain_frames();

    assert!(fixture.close(STREAM_A));

    assert_eq!(
        fixture.terminal_latch(STREAM_A),
        ("STREAM_CLOSED", None),
        "a close with nothing to prove stays unclassified"
    );
}

/// A physical public response write that stalls past the relay's own bounded
/// write deadline is a typed physical write timeout, and that cause is latched
/// at the first terminal transition, before STREAM_FORGET removes the stream.
///
/// The stall is real: `send_until` is the relay's own deadline wrapper and it
/// is driven here against a write that never completes, exactly as
/// `physical_write_deadline_remains_a_timeout_before_expiry` does in
/// `consumer_write_diagnostics`.  The deadline is shortened to milliseconds
/// so the regression does not sleep; the production callsite passes the same
/// wrapper its own five-second bound.
#[tokio::test]
async fn a_stalled_physical_write_latches_its_timeout_before_stream_forget() {
    // 1. The physical write stalls past the relay's own deadline.
    let outcome = send_until(
        std::future::pending::<Result<(), ()>>(),
        tokio::time::Instant::now() + StdDuration::from_millis(5),
    )
    .await;
    assert_eq!(
        outcome,
        ConsumerWriteOutcome::TimedOut,
        "the relay's own write deadline, not the consumer's authorization, ended the write"
    );
    assert!(outcome.is_timed_out());
    assert!(!outcome.is_sent());

    // 2. That outcome, and only that outcome, proves the typed cause the
    //    public handler carries into its close.
    let cause = outcome.terminal_cause();
    assert_eq!(cause, Some(StreamTerminalCause::PhysicalWriteTimeout));

    // 3. The close latches it at the first terminal transition.
    let mut fixture = LateFixture::new("cause-physical-write-timeout");
    assert!(fixture.close_with_cause(STREAM_A, cause));
    assert_eq!(
        fixture.terminal_latch(STREAM_A),
        (
            "STREAM_CLOSED",
            Some(StreamTerminalCause::PhysicalWriteTimeout)
        )
    );
    let frames = fixture.drain_frames();
    assert_eq!(sequenced(&frames), vec![(STREAM_A, FrameKind::Fin, 1)]);

    // A second close cannot overwrite or duplicate the latch.
    assert!(fixture.close_with_cause(STREAM_A, Some(StreamTerminalCause::QueueExhausted)));
    assert_eq!(
        fixture.terminal_latch(STREAM_A),
        (
            "STREAM_CLOSED",
            Some(StreamTerminalCause::PhysicalWriteTimeout)
        ),
        "the first terminal latch is immutable"
    );

    // 4. The connector's FIN completes the stream; the owner reclaims it with
    //    exactly one STREAM_FORGET and joins every piece of its state.
    fixture
        .inbound(Frame::fin(EPOCH, GENERATION, STREAM_A, 1, 1))
        .await;
    let forgets = fixture
        .drain_control()
        .into_iter()
        .filter(|message| matches!(message, ControlMessage::StreamForget(_)))
        .count();
    assert_eq!(forgets, 1, "exactly one owner FORGET reclaims the stream");
    assert!(
        !fixture.has_stream(STREAM_A),
        "cleanup joined: no stream state survives the FORGET"
    );
    assert!(
        fixture
            .actor
            .sessions
            .get(&fixture.key.scope())
            .is_some_and(|session| session.terminal_fin_failure_deadline.is_none()),
        "cleanup joined: no terminal-FIN debt is left armed"
    );

    // 5. The latch outlives the state it describes, with the same cause.
    assert_eq!(
        fixture.terminal_latch(STREAM_A),
        (
            "STREAM_CLOSED",
            Some(StreamTerminalCause::PhysicalWriteTimeout)
        ),
        "the typed cause was latched before STREAM_FORGET and survives it"
    );
    assert!(fixture.session_alive());
}

/// Only the relay's own write deadline proves a physical write timeout. An
/// authorization expiry, a transport failure and a completed write prove
/// nothing and must stay unclassified.
#[test]
fn only_the_write_deadline_proves_a_physical_write_timeout() {
    assert_eq!(
        ConsumerWriteOutcome::TimedOut.terminal_cause(),
        Some(StreamTerminalCause::PhysicalWriteTimeout)
    );
    for outcome in [
        ConsumerWriteOutcome::Sent,
        ConsumerWriteOutcome::Expired,
        ConsumerWriteOutcome::Failed,
    ] {
        assert_eq!(
            outcome.terminal_cause(),
            None,
            "{outcome:?} is not the relay's own physical write deadline"
        );
    }
}

/// An unclaimed admission lease that reaches its absolute deadline is latched
/// as lease expiry by the actor tick that expires it.
#[tokio::test]
async fn an_expired_unclaimed_admission_lease_latches_lease_expiry() {
    let mut fixture = LateFixture::new("cause-admission-lease");
    let now = Instant::now();
    // Stream A's lease is unclaimed and already past its deadline; stream B
    // claimed its lease, so the same tick must leave it alone.
    fixture.stream_mut(STREAM_A).admission_deadline = now - StdDuration::from_secs(1);
    fixture.stream_mut(STREAM_B).admission_lease.cancel();
    fixture.stream_mut(STREAM_B).admission_deadline = now - StdDuration::from_secs(1);

    let key = fixture.key.clone();
    fixture.actor.expire_unclaimed_echo_streams(&key, now);

    assert_eq!(
        fixture.terminal_latch(STREAM_A),
        (
            "STREAM_CLOSED",
            Some(StreamTerminalCause::AdmissionLeaseExpired)
        ),
        "the expired unclaimed lease is the cause of this terminal"
    );
    assert!(
        fixture.terminal_events(STREAM_B).is_empty(),
        "a claimed lease is not expired by the same tick"
    );
    assert!(!fixture.stream(STREAM_B).terminal);

    // A repeated tick is idempotent: the latch stays single and immutable.
    fixture.actor.expire_unclaimed_echo_streams(&key, now);
    assert_eq!(
        fixture.terminal_latch(STREAM_A),
        (
            "STREAM_CLOSED",
            Some(StreamTerminalCause::AdmissionLeaseExpired)
        )
    );
    assert!(fixture.session_alive());
}

/// The same expiry on a stream whose OPEN is still pending has no terminal
/// transition yet, so the cause is held on the stream and applied to the
/// deferred terminal once the connector admits it. The latch stays a
/// first-transition record; nothing is published early.
#[tokio::test]
async fn an_expired_lease_on_a_pending_open_defers_its_cause_to_the_real_terminal() {
    let mut fixture = LateFixture::new("cause-admission-lease-pending");
    let now = Instant::now();
    fixture.stream_mut(STREAM_A).open_pending = true;
    fixture.stream_mut(STREAM_A).admission_deadline = now - StdDuration::from_secs(1);

    let key = fixture.key.clone();
    fixture.actor.expire_unclaimed_echo_streams(&key, now);

    assert!(
        fixture.terminal_events(STREAM_A).is_empty(),
        "a pending OPEN has no terminal transition to latch yet"
    );
    assert!(
        !fixture.stream(STREAM_A).terminal,
        "and no terminal tombstone is invented for it"
    );
    assert_eq!(
        fixture.stream(STREAM_A).deferred_terminal_cause,
        Some(StreamTerminalCause::AdmissionLeaseExpired),
        "the cause is held for the terminal the admitted OPEN will produce"
    );
    assert!(
        fixture.stream(STREAM_A).registration_dropped,
        "the registration is recorded as dropped, exactly as before"
    );
    assert!(fixture.session_alive());
}

/// A close completed by the shutdown drain is latched as a planned drain, and
/// a cause the closing handler already proved is preserved through it.
#[tokio::test]
async fn a_close_completed_by_the_shutdown_drain_latches_planned_drain() {
    let mut fixture = LateFixture::new("cause-planned-drain");
    let key = fixture.key.clone();
    let (response, mut receiver) = oneshot::channel();
    fixture
        .actor
        .apply_terminal_command_during_drain(Command::CloseEchoStream {
            key: key.clone(),
            stream_id: STREAM_A,
            operation_id: operation_id(STREAM_A),
            cause: None,
            response,
        });
    assert_eq!(
        receiver.try_recv().ok(),
        Some(true),
        "the drain completes the close"
    );
    assert_eq!(
        fixture.terminal_latch(STREAM_A),
        ("STREAM_CLOSED", Some(StreamTerminalCause::PlannedDrain)),
        "an otherwise unclassified close on the drain path is a planned drain"
    );
    let frames = fixture.drain_frames();
    assert_eq!(
        sequenced(&frames),
        vec![(STREAM_A, FrameKind::Fin, 1)],
        "the drain still queues the device-facing FIN"
    );

    // A handler that proved its own cause keeps it: the drain never overwrites
    // a cause established at a real close site.
    let (response, mut receiver) = oneshot::channel();
    fixture
        .actor
        .apply_terminal_command_during_drain(Command::CloseEchoStream {
            key,
            stream_id: STREAM_B,
            operation_id: operation_id(STREAM_B),
            cause: Some(StreamTerminalCause::PeerMembershipExpired),
            response,
        });
    assert_eq!(receiver.try_recv().ok(), Some(true));
    assert_eq!(
        fixture.terminal_latch(STREAM_B),
        (
            "STREAM_CLOSED",
            Some(StreamTerminalCause::PeerMembershipExpired)
        ),
        "the drain preserves a cause the closing handler proved"
    );
}
