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
    CarrierKey, ControlOutbound, DataCarrier, DataOutbound, EchoOutcome, M2Stream, RelayActor,
    SessionKey, runtime, wire,
};

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
