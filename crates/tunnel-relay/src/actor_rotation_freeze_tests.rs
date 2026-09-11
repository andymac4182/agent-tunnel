//! Deterministic regressions for the relay-side rotation freeze.
//!
//! From `ROTATE_QUIESCE` until the connector's `ROTATE_COMMITTED` (or the
//! final owner `ROTATE_ABORTED`) the relay must not emit sequenced
//! DATA/FIN/RESET on the old carrier, must hold new consumer output bounded
//! against the session queue budget, and must pause new OPEN admission so the
//! immutable roster fixed at QUIESCE cannot drift.  Every scenario drives the
//! real actor handlers with an explicit connector stand-in; there is no socket
//! I/O and no wall-clock waiting.

use std::{
    collections::{BTreeSet, VecDeque},
    time::{Duration as StdDuration, Instant},
};

use chrono::{DateTime, Duration, Utc};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{AuthenticatedConsumer, DeviceIdentity, GrantSnapshot, PermissionSet};
use tunnel_protocol::rotation::RotationPhase;
use tunnel_protocol::rotation_control::{
    DrainProof, FenceSnapshot, RotateAborted, RotateCommitted, RotateDrained, RotateFrozen,
    RotateRetired, RotationAttemptIdentity, StreamAck, StreamFence,
};
use tunnel_protocol::{
    ControlMessage, Direction, Frame, FrameKind, Rejected, StreamState, Terminal,
};
use uuid::Uuid;

use super::stream_identity_tests::{
    admitted_control_actor, session_attempt, test_rotation_runtime,
};
use super::{
    CarrierKey, ControlOutbound, DataCarrier, DataOutbound, DeviceSession, DispatchRequest,
    EchoOutcome, M2Stream, RelayActor, RelayError, SessionKey, runtime, wire,
};

const STREAM_ID: u64 = 7;
const OPERATION_ID: &str = "freeze-operation";
const OPEN_MESSAGE_ID: &str = "freeze-open";
const CONNECTOR_FROZEN_ID: &str = "connector-frozen";
const CONNECTOR_DRAINED_ID: &str = "connector-drained";
const CONNECTOR_COMMITTED_ID: &str = "connector-committed";
const CONNECTOR_RETIRED_ID: &str = "connector-retired";
const CONNECTOR_ABORTED_ID: &str = "connector-aborted";

/// One decoded item taken from a data writer queue.
enum Observed {
    Frame(Frame),
    Barrier(oneshot::Sender<()>),
    Close,
}

fn drain_data(rx: &mut mpsc::Receiver<DataOutbound>) -> Vec<Observed> {
    let mut items = Vec::new();
    while let Ok(item) = rx.try_recv() {
        items.push(match item {
            DataOutbound::Binary(mut bytes) => {
                let frame = Frame::decode(bytes.as_slice()).expect("relay data frame decodes");
                bytes.release();
                Observed::Frame(frame)
            }
            DataOutbound::Barrier(tx) => Observed::Barrier(tx),
            DataOutbound::Close => Observed::Close,
        });
    }
    items
}

fn is_sequenced(frame: &Frame) -> bool {
    matches!(
        frame.kind,
        FrameKind::Data | FrameKind::Fin | FrameKind::Reset
    )
}

/// `(kind, sequence, generation)` for every sequenced frame, in queue order.
fn sequenced(items: &[Observed]) -> Vec<(FrameKind, u64, u64)> {
    items
        .iter()
        .filter_map(|item| match item {
            Observed::Frame(frame) if is_sequenced(frame) => {
                Some((frame.kind, frame.sequence, frame.generation))
            }
            _ => None,
        })
        .collect()
}

fn record_bodies(items: &[Observed]) -> Vec<Vec<u8>> {
    items
        .iter()
        .filter_map(|item| match item {
            Observed::Frame(frame) if frame.kind == FrameKind::Data && frame.payload.len() >= 4 => {
                Some(frame.payload[4..].to_vec())
            }
            _ => None,
        })
        .collect()
}

fn has_close(items: &[Observed]) -> bool {
    items.iter().any(|item| matches!(item, Observed::Close))
}

fn assert_held(receiver: &mut oneshot::Receiver<Result<Vec<u8>, EchoOutcome>>, label: &str) {
    assert!(
        matches!(
            receiver.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ),
        "{label}: a record written while the relay writer is frozen must stay pending"
    );
}

struct FreezeFixture {
    actor: RelayActor,
    key: SessionKey,
    attempt: RotationAttemptIdentity,
    control_rx: mpsc::Receiver<ControlOutbound>,
    old_rx: mpsc::Receiver<DataOutbound>,
    candidate_rx: mpsc::Receiver<DataOutbound>,
    old_carrier: CarrierKey,
    candidate_carrier: CarrierKey,
    device_id: Uuid,
    service_id: Uuid,
    consumer: AuthenticatedConsumer,
    grant: GrantSnapshot,
    consumer_expires_at: DateTime<Utc>,
    snapshot_id: String,
    quiesce_message_id: String,
    relay_frozen_message_id: String,
    relay_fence: Option<FenceSnapshot>,
    commit_message_id: String,
    retire_message_id: String,
}

impl FreezeFixture {
    /// An M2 session with one authorized stream, an active old carrier and a
    /// ready rotation candidate.  The pure rotation state is `Preparing` with
    /// candidate readiness recorded, so `begin_rotation_quiesce` is the next
    /// real transition.
    fn new(label: &str, open_pending: bool) -> Self {
        let now = Utc::now();
        let tenant_id = Uuid::from_u128(7_001);
        let device_id = Uuid::from_u128(7_002);
        let principal_id = Uuid::from_u128(7_003);
        let service_id = Uuid::from_u128(7_004);
        let identity = DeviceIdentity {
            tenant_id,
            device_id,
            owner_user_id: principal_id,
            credential_id: Uuid::from_u128(7_005),
            spki_fingerprint: format!("freeze-{label}-spki"),
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
            session_id: format!("freeze-{label}"),
            epoch: 1,
        };
        let (mut actor, registration) = admitted_control_actor(identity, key.clone());
        let owner_id = runtime::owner_id(
            &actor
                .sessions
                .get(&key.scope())
                .expect("fixture session")
                .owner,
        );
        let attempt = session_attempt(&key, &owner_id, label, 1);
        let capacity = actor.options.limits.max_queue_messages;
        let (old_tx, old_rx) = mpsc::channel(capacity);
        let (candidate_tx, candidate_rx) = mpsc::channel(capacity);
        let old_carrier = CarrierKey {
            session: key.clone(),
            generation: attempt.old_generation,
            connection_id: attempt.old_connection_id.clone(),
        };
        let candidate_carrier = CarrierKey {
            session: key.clone(),
            generation: attempt.new_generation,
            connection_id: attempt.new_connection_id.clone(),
        };
        let now_ms = super::monotonic_millis();
        let mut rotation = test_rotation_runtime(now_ms, attempt.clone(), now_ms + 60_000);
        rotation
            .state
            .prepare(attempt.clone(), now_ms)
            .expect("fixture rotation prepares");
        rotation
            .state
            .candidate_ready(&attempt, now_ms)
            .expect("fixture candidate is ready");
        rotation.candidate = Some(DataCarrier {
            context: candidate_carrier.context(),
            tx: candidate_tx,
        });
        rotation.old_connection_id = attempt.old_connection_id.clone();
        rotation.prepare_message_id = "relay-prepare".to_owned();
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
        let consumer_expires_at = now + Duration::minutes(10);
        let sequence = StreamState::new(STREAM_ID, wire::M2_INITIAL_WINDOW_BYTES as u64)
            .expect("fixture stream sequence");
        let session = actor
            .sessions
            .get_mut(&key.scope())
            .expect("fixture session");
        session.profile = runtime::RuntimeProfile::M2;
        session.generation = attempt.old_generation;
        session.connection_id = attempt.old_connection_id.clone();
        session.data_tx = Some(old_tx.clone());
        session.active_carrier = Some(DataCarrier {
            context: old_carrier.context(),
            tx: old_tx,
        });
        session.rotation = Some(rotation);
        session.next_stream_id = STREAM_ID + 1;
        session.streams.insert(
            STREAM_ID,
            M2Stream {
                // These fixtures build admitted streams; a deferred
                // pre-admission terminal cause never applies to them.
                deferred_terminal_cause: None,
                open_message_id: OPEN_MESSAGE_ID.to_owned(),
                operation_id: OPERATION_ID.to_owned(),
                request_id: None,
                service_id,
                consumer: consumer.clone(),
                grant: grant.clone(),
                sequence,
                response_bytes: Vec::new(),
                response_records: VecDeque::new(),
                send_bytes: 0,
                receive_bytes: 0,
                authorized_until: Some(Instant::now() + StdDuration::from_secs(60)),
                consumer_expires_at,
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
                open_pending,
                registration_dropped: false,
                closed: CancellationToken::new(),
                admission_lease: CancellationToken::new(),
                admission_deadline: Instant::now() + StdDuration::from_secs(60),
                authorization_failure_code: None,
            },
        );
        Self {
            actor,
            key,
            attempt,
            control_rx: registration.rx,
            old_rx,
            candidate_rx,
            old_carrier,
            candidate_carrier,
            device_id,
            service_id,
            consumer,
            grant,
            consumer_expires_at,
            snapshot_id: String::new(),
            quiesce_message_id: String::new(),
            relay_frozen_message_id: String::new(),
            relay_fence: None,
            commit_message_id: String::new(),
            retire_message_id: String::new(),
        }
    }

    fn session(&self) -> &DeviceSession {
        self.actor
            .sessions
            .get(&self.key.scope())
            .expect("fixture session")
    }

    fn stream(&self) -> &M2Stream {
        self.session()
            .streams
            .get(&STREAM_ID)
            .expect("fixture stream")
    }

    fn phase(&self) -> RotationPhase {
        self.session()
            .rotation
            .as_ref()
            .expect("fixture rotation")
            .state
            .phase()
    }

    fn rotation_status(&self) -> tunnel_protocol::rotation::RotationStatus {
        self.session()
            .rotation
            .as_ref()
            .expect("fixture rotation")
            .state
            .status()
    }

    /// The attempt's absolute overlap deadline.  Deterministic regressions pass
    /// it straight to the relay deadline poll instead of waiting for it.
    fn overlap_deadline_ms(&self) -> u64 {
        self.rotation_status()
            .deadline_ms
            .expect("live attempt has an absolute overlap deadline")
    }

    /// Every retained cursor and credit of the fixture stream, in both
    /// directions.  Recovery must preserve these exactly.
    fn retained_cursors(&self) -> Vec<[u64; 8]> {
        [Direction::RelayToConnector, Direction::ConnectorToRelay]
            .into_iter()
            .map(|direction| {
                let stream = self.stream();
                let state = stream.sequence.direction(direction);
                [
                    state.last_emitted(),
                    state.peer_acked(),
                    state.recv_contiguous(),
                    state.delivered_contiguous(),
                    state.sent_bytes(),
                    state.received_bytes(),
                    state.send_credit(),
                    state.receive_credit(),
                ]
            })
            .collect()
    }

    fn relay_last_emitted(&self) -> u64 {
        self.stream()
            .sequence
            .direction(Direction::RelayToConnector)
            .last_emitted()
    }

    fn budget_used(&self) -> usize {
        self.session().queue_budget.used()
    }

    fn write(&mut self, body: &[u8]) -> oneshot::Receiver<Result<Vec<u8>, EchoOutcome>> {
        let (response, receiver) = oneshot::channel();
        self.actor.write_echo_stream(
            self.key.clone(),
            STREAM_ID,
            OPERATION_ID.to_owned(),
            body.to_vec(),
            response,
        );
        receiver
    }

    fn drain_control(&mut self) -> Vec<ControlMessage> {
        let mut messages = Vec::new();
        while let Ok(item) = self.control_rx.try_recv() {
            match item {
                ControlOutbound::Text(mut queued) => {
                    let message = wire::parse_control(queued.as_bytes())
                        .expect("relay control message decodes");
                    queued.release();
                    messages.push(message);
                }
                ControlOutbound::Close => panic!("relay closed the control socket"),
            }
        }
        messages
    }

    /// Enter `Quiescing` through the real coordinator path and capture the
    /// QUIESCE identity the connector stand-in must reply to.
    fn quiesce(&mut self) {
        self.actor.begin_rotation_quiesce(&self.key);
        assert_eq!(self.phase(), RotationPhase::Quiescing);
        let quiesce = self
            .drain_control()
            .into_iter()
            .find_map(|message| match message {
                ControlMessage::RotateQuiesce(quiesce) => Some(quiesce),
                _ => None,
            })
            .expect("relay queues ROTATE_QUIESCE");
        assert_eq!(quiesce.roster.stream_ids, vec![STREAM_ID]);
        self.snapshot_id = quiesce.roster.snapshot_id.clone();
        self.quiesce_message_id = quiesce.message_id.clone();
    }

    /// Complete the old writer barrier and let the coordinator measure its
    /// immutable fence.  Returns the sequenced frames queued before the
    /// barrier and asserts nothing sequenced was queued behind it.
    fn complete_barrier(&mut self) -> Vec<(FrameKind, u64, u64)> {
        let items = drain_data(&mut self.old_rx);
        let mut before = Vec::new();
        let mut barrier = None;
        let mut behind = Vec::new();
        for item in items {
            match item {
                Observed::Barrier(tx) => barrier = Some(tx),
                Observed::Frame(frame) if barrier.is_none() => before.push(Observed::Frame(frame)),
                Observed::Frame(frame) => behind.push(Observed::Frame(frame)),
                Observed::Close => panic!("old carrier closed before the writer barrier"),
            }
        }
        assert!(
            sequenced(&behind).is_empty(),
            "sequenced frames were queued behind the fence barrier: {:?}",
            sequenced(&behind)
        );
        barrier
            .expect("relay queues the writer barrier")
            .send(())
            .expect("barrier receiver is retained by the rotation runtime");
        self.actor.poll_rotation_barrier(&self.key);
        self.relay_fence = self
            .session()
            .rotation
            .as_ref()
            .and_then(|rotation| rotation.own_fence.clone());
        sequenced(&before)
    }

    fn relay_fence(&self) -> &FenceSnapshot {
        self.relay_fence
            .as_ref()
            .expect("relay records its own fence after the writer barrier")
    }

    /// The connector reports its fence; the coordinator enters `Draining`
    /// and queues its own FROZEN.
    async fn connector_frozen(&mut self, connector_last_emitted: u64) {
        let snapshot = FenceSnapshot::new(
            self.snapshot_id.clone(),
            vec![StreamFence::new(
                STREAM_ID,
                Direction::ConnectorToRelay,
                connector_last_emitted,
            )],
        );
        self.actor
            .handle_rotate_frozen(
                &self.key,
                RotateFrozen {
                    message_id: CONNECTOR_FROZEN_ID.to_owned(),
                    reply_to: self.quiesce_message_id.clone(),
                    attempt: self.attempt.clone(),
                    snapshot,
                },
            )
            .await;
        assert_eq!(self.phase(), RotationPhase::Draining);
        let frozen = self
            .drain_control()
            .into_iter()
            .find_map(|message| match message {
                ControlMessage::RotateFrozen(frozen) => Some(frozen),
                _ => None,
            })
            .expect("relay queues its own ROTATE_FROZEN after the connector fence");
        assert_eq!(frozen.reply_to, CONNECTOR_FROZEN_ID);
        assert_eq!(&frozen.snapshot, self.relay_fence());
        self.relay_frozen_message_id = frozen.message_id;
    }

    /// The connector proves receipt through the relay fence; the coordinator
    /// enters `Committing` and queues COMMIT.
    async fn connector_drained(&mut self) {
        let fence = self.relay_fence().clone();
        let acks = fence
            .entries
            .iter()
            .map(|entry| StreamAck::new(entry.stream_id, entry.last_emitted))
            .collect();
        let proof = DrainProof::new(
            self.snapshot_id.clone(),
            fence.digest().expect("relay fence digest"),
            Direction::RelayToConnector,
            acks,
        );
        self.actor
            .handle_rotate_drained(
                &self.key,
                RotateDrained {
                    message_id: CONNECTOR_DRAINED_ID.to_owned(),
                    reply_to: self.relay_frozen_message_id.clone(),
                    attempt: self.attempt.clone(),
                    proof,
                },
            )
            .await;
        assert_eq!(self.phase(), RotationPhase::Committing);
        let commit = self
            .drain_control()
            .into_iter()
            .find_map(|message| match message {
                ControlMessage::RotateCommit(commit) => Some(commit),
                _ => None,
            })
            .expect("relay queues ROTATE_COMMIT after both drain proofs");
        self.commit_message_id = commit.message_id;
    }

    /// The connector activates the candidate; the coordinator switches its
    /// writer and queues RETIRE.
    async fn connector_committed(&mut self) {
        self.actor
            .handle_rotate_committed(
                &self.key,
                RotateCommitted {
                    message_id: CONNECTOR_COMMITTED_ID.to_owned(),
                    reply_to: self.commit_message_id.clone(),
                    attempt: self.attempt.clone(),
                    snapshot_id: self.snapshot_id.clone(),
                },
            )
            .await;
        assert_eq!(self.phase(), RotationPhase::Retiring);
        let retire = self
            .drain_control()
            .into_iter()
            .find_map(|message| match message {
                ControlMessage::RotateRetire(retire) => Some(retire),
                _ => None,
            })
            .expect("relay queues ROTATE_RETIRE after COMMITTED");
        self.retire_message_id = retire.message_id;
    }

    /// The connector attests its own old-transport closure.  The attempt stays
    /// `Retiring` until the relay's physical close event arrives as well.
    async fn connector_retired(&mut self) {
        self.actor
            .handle_rotate_retired(
                &self.key,
                RotateRetired {
                    message_id: CONNECTOR_RETIRED_ID.to_owned(),
                    reply_to: self.retire_message_id.clone(),
                    attempt: self.attempt.clone(),
                    snapshot_id: self.snapshot_id.clone(),
                    closed_connection_id: self.attempt.old_connection_id.clone(),
                },
            )
            .await;
    }

    /// Both endpoints close the old transport and the attempt completes.
    async fn retire_old_carrier(&mut self) {
        self.connector_retired().await;
        self.actor.disconnect_data(self.old_carrier.clone()).await;
        assert_eq!(self.phase(), RotationPhase::Active);
        assert!(
            self.drain_control()
                .iter()
                .any(|message| matches!(message, ControlMessage::RotateComplete(_))),
            "relay queues ROTATE_COMPLETE after both old closures"
        );
    }

    /// Physical candidate loss before commit: the coordinator decides ABORT.
    async fn abort_by_candidate_loss(&mut self) -> String {
        self.actor
            .disconnect_data(self.candidate_carrier.clone())
            .await;
        assert_eq!(self.phase(), RotationPhase::Aborting);
        self.drain_control()
            .into_iter()
            .find_map(|message| match message {
                ControlMessage::RotateAbort(abort) => Some(abort.message_id),
                _ => None,
            })
            .expect("relay queues ROTATE_ABORT after candidate loss")
    }

    /// The connector acknowledges the abort; the coordinator journals its
    /// final ABORTED and may resume the old writer.
    async fn connector_aborted(&mut self, abort_message_id: &str) {
        self.actor
            .handle_rotate_aborted(
                &self.key,
                RotateAborted {
                    message_id: CONNECTOR_ABORTED_ID.to_owned(),
                    reply_to: abort_message_id.to_owned(),
                    attempt: self.attempt.clone(),
                    reason: "candidate transport lost".to_owned(),
                    closed_connection_id: self.attempt.new_connection_id.clone(),
                },
            )
            .await;
        assert_eq!(self.phase(), RotationPhase::Active);
        let aborted = self
            .drain_control()
            .into_iter()
            .find_map(|message| match message {
                ControlMessage::RotateAborted(aborted) => Some(aborted),
                _ => None,
            })
            .expect("relay queues its final ROTATE_ABORTED");
        assert_eq!(aborted.reply_to, CONNECTOR_ABORTED_ID);
    }
}

#[tokio::test]
async fn frozen_relay_writer_holds_consumer_records_until_committed() {
    let mut fixture = FreezeFixture::new("hold-records", false);
    let _active = fixture.write(b"active-record");
    assert_eq!(
        sequenced(&drain_data(&mut fixture.old_rx)),
        vec![(FrameKind::Data, 1, fixture.attempt.old_generation)]
    );

    fixture.quiesce();
    // A write that lands between QUIESCE and the flushed barrier must not
    // enter the old writer either: the fence is measured after the barrier.
    let used_before = fixture.budget_used();
    let mut held_pre_barrier = fixture.write(b"pre-barrier-record");
    assert_held(&mut held_pre_barrier, "pre-barrier");
    assert_eq!(fixture.relay_last_emitted(), 1);
    assert!(fixture.complete_barrier().is_empty());
    assert_eq!(fixture.relay_fence().entries.len(), 1);
    assert_eq!(fixture.relay_fence().entries[0].last_emitted, 1);

    let mut held_quiescing = fixture.write(b"quiescing-record");
    assert_held(&mut held_quiescing, "quiescing");
    assert_eq!(
        fixture.relay_last_emitted(),
        1,
        "a frozen writer must not assign a sequence past its immutable fence"
    );
    assert!(
        sequenced(&drain_data(&mut fixture.old_rx)).is_empty(),
        "no sequenced frame may follow the fence on the old carrier"
    );
    assert_eq!(fixture.stream().pending_records.len(), 2);
    assert_eq!(
        fixture.budget_used() - used_before,
        b"pre-barrier-record".len() + b"quiescing-record".len(),
        "held bytes are charged to the session queue budget"
    );

    fixture.connector_frozen(0).await;
    let mut held_draining = fixture.write(b"draining-record");
    assert_held(&mut held_draining, "draining");
    assert_eq!(fixture.relay_last_emitted(), 1);
    assert!(sequenced(&drain_data(&mut fixture.old_rx)).is_empty());

    fixture.connector_drained().await;
    // COMMIT is in flight; the connector may already have retired the old
    // carrier, so this write must not be lost on it.
    let mut held_committing = fixture.write(b"committing-record");
    assert_held(&mut held_committing, "committing");
    assert_eq!(fixture.relay_last_emitted(), 1);
    assert!(sequenced(&drain_data(&mut fixture.old_rx)).is_empty());
    assert_eq!(fixture.stream().pending_records.len(), 4);

    fixture.connector_committed().await;
    let candidate = drain_data(&mut fixture.candidate_rx);
    let new_generation = fixture.attempt.new_generation;
    assert_eq!(
        sequenced(&candidate),
        vec![
            (FrameKind::Data, 2, new_generation),
            (FrameKind::Data, 3, new_generation),
            (FrameKind::Data, 4, new_generation),
            (FrameKind::Data, 5, new_generation),
        ],
        "held records continue the sequence space on the activated carrier"
    );
    assert_eq!(
        record_bodies(&candidate),
        vec![
            b"pre-barrier-record".to_vec(),
            b"quiescing-record".to_vec(),
            b"draining-record".to_vec(),
            b"committing-record".to_vec(),
        ],
        "held records keep their FIFO order"
    );
    let old = drain_data(&mut fixture.old_rx);
    assert!(
        sequenced(&old).is_empty(),
        "the retired carrier never receives a post-fence frame"
    );
    assert!(has_close(&old));
    assert_eq!(fixture.relay_last_emitted(), 5);
    assert!(fixture.stream().pending_records.is_empty());
    assert_eq!(fixture.stream().pending_record_bytes, 0);
    for held in [
        &mut held_pre_barrier,
        &mut held_quiescing,
        &mut held_draining,
        &mut held_committing,
    ] {
        assert_held(
            held,
            "dispatched record still awaits its connector response",
        );
    }
}

#[tokio::test]
async fn frozen_relay_writer_bounds_held_records_with_typed_refusal() {
    let mut fixture = FreezeFixture::new("bounded-hold", false);
    fixture.actor.options.limits.max_pending_operations = 1;
    fixture.quiesce();
    assert!(fixture.complete_barrier().is_empty());

    let used_before = fixture.budget_used();
    let mut held = fixture.write(b"held");
    assert_held(&mut held, "held");
    let mut refused = fixture.write(b"refused");
    match refused.try_recv() {
        Ok(Err(EchoOutcome::Failure { code, execution })) => {
            assert_eq!(code, "RESOURCE_EXHAUSTED");
            assert_eq!(execution, "not_dispatched");
        }
        Ok(Ok(_)) => panic!("a refused record must not complete"),
        Ok(Err(EchoOutcome::Success(_))) => panic!("a refused record must not succeed"),
        Err(_) => panic!("the bounded hold must refuse the record synchronously"),
    }
    assert_eq!(fixture.stream().pending_records.len(), 1);
    assert_eq!(fixture.budget_used() - used_before, b"held".len());

    fixture.actor.options.limits.max_pending_operations = 64;
    fixture.actor.options.limits.max_queue_bytes = b"held".len();
    let mut refused_bytes = fixture.write(b"x");
    match refused_bytes.try_recv() {
        Ok(Err(EchoOutcome::Failure { code, execution })) => {
            assert_eq!(code, "RESOURCE_EXHAUSTED");
            assert_eq!(execution, "not_dispatched");
        }
        _ => panic!("the byte bound must refuse the record synchronously"),
    }
    assert_eq!(fixture.stream().pending_records.len(), 1);
    assert_eq!(fixture.budget_used() - used_before, b"held".len());
    assert_eq!(fixture.relay_last_emitted(), 0);
    assert!(
        sequenced(&drain_data(&mut fixture.old_rx)).is_empty(),
        "neither the held nor the refused record may reach the old carrier"
    );
}

#[tokio::test]
async fn frozen_relay_writer_defers_consumer_fin_until_committed() {
    let mut fixture = FreezeFixture::new("consumer-fin", false);
    let _active = fixture.write(b"active-record");
    assert_eq!(sequenced(&drain_data(&mut fixture.old_rx)).len(), 1);
    fixture.quiesce();
    assert!(fixture.complete_barrier().is_empty());
    fixture.connector_frozen(0).await;

    assert!(
        fixture
            .actor
            .close_echo_stream(&fixture.key, STREAM_ID, OPERATION_ID)
    );
    assert!(
        sequenced(&drain_data(&mut fixture.old_rx)).is_empty(),
        "FIN must not be emitted on the frozen old carrier"
    );
    assert_eq!(fixture.relay_last_emitted(), 1);
    assert!(fixture.stream().terminal);
    assert!(
        !fixture.stream().terminal_fin_failure,
        "a deferred FIN is bounded backpressure, not a publication failure"
    );
    assert!(fixture.session().terminal_fin_failure_deadline.is_none());

    fixture.connector_drained().await;
    fixture.connector_committed().await;
    assert_eq!(
        sequenced(&drain_data(&mut fixture.candidate_rx)),
        vec![(FrameKind::Fin, 2, fixture.attempt.new_generation)],
        "the deferred FIN follows the fence on the activated carrier"
    );
    assert_eq!(
        fixture
            .stream()
            .sequence
            .direction(Direction::RelayToConnector)
            .send_terminal(),
        Some(Terminal::Fin)
    );
    assert!(!fixture.stream().terminal_fin_failure);
    assert!(fixture.session().terminal_fin_failure_deadline.is_none());
}

#[tokio::test]
async fn frozen_relay_writer_defers_peer_terminal_reply_until_committed() {
    let mut fixture = FreezeFixture::new("peer-fin", false);
    let _active = fixture.write(b"active-record");
    assert_eq!(sequenced(&drain_data(&mut fixture.old_rx)).len(), 1);
    fixture.quiesce();
    assert!(fixture.complete_barrier().is_empty());
    // The connector's fence covers its FIN at sequence 1, which is still in
    // flight on the old carrier when FROZEN arrives.
    fixture.connector_frozen(1).await;

    let epoch = fixture.key.epoch;
    let old_generation = fixture.attempt.old_generation;
    fixture
        .actor
        .inbound_m2_stream_data(
            fixture.old_carrier.clone(),
            Frame::fin(epoch, old_generation, STREAM_ID, 1, 1),
            false,
        )
        .await;
    let old = drain_data(&mut fixture.old_rx);
    assert!(
        sequenced(&old).is_empty(),
        "the relay's terminal reply must be held while its writer is frozen"
    );
    assert!(
        old.iter().any(|item| matches!(
            item,
            Observed::Frame(frame) if frame.kind == FrameKind::Ack && frame.ack == 1
        )),
        "ACK housekeeping stays responsive during drain"
    );
    assert_eq!(fixture.relay_last_emitted(), 1);
    assert!(fixture.stream().terminal);
    assert!(!fixture.stream().terminal_fin_failure);
    assert!(fixture.session().terminal_fin_failure_deadline.is_none());
    assert!(
        fixture
            .drain_control()
            .iter()
            .any(|message| matches!(message, ControlMessage::RotateDrained(_))),
        "the relay proves its own drain once the connector fence is covered"
    );

    fixture.connector_drained().await;
    fixture.connector_committed().await;
    assert_eq!(
        sequenced(&drain_data(&mut fixture.candidate_rx)),
        vec![(FrameKind::Fin, 2, fixture.attempt.new_generation)],
        "the deferred terminal reply follows the fence on the activated carrier"
    );
    assert!(!fixture.stream().terminal_fin_failure);
}

#[tokio::test]
async fn open_admission_pauses_during_quiesce_and_roster_stays_matched() {
    let mut fixture = FreezeFixture::new("open-pause", false);
    fixture.quiesce();

    let (response, mut receiver) = oneshot::channel();
    fixture.actor.open_echo_stream(
        fixture.consumer.clone(),
        fixture.device_id,
        fixture.service_id,
        fixture.grant.clone(),
        fixture.consumer_expires_at,
        response,
    );
    match receiver.try_recv() {
        Ok(Err(RelayError::OwnerNotReady)) => {}
        Ok(Err(other)) => {
            panic!("OPEN during quiesce must be refused as retryable owner-not-ready, got {other}")
        }
        Ok(Ok(_)) => panic!("OPEN must not be admitted while the roster is frozen"),
        Err(_) => panic!("OPEN admission must answer synchronously"),
    }
    assert!(
        fixture
            .drain_control()
            .iter()
            .all(|message| !matches!(message, ControlMessage::Open(_))),
        "no OPEN may reach the connector while admission is paused"
    );
    assert_eq!(fixture.session().streams.len(), 1);

    assert!(fixture.complete_barrier().is_empty());
    assert_eq!(
        fixture
            .relay_fence()
            .entries
            .iter()
            .map(|entry| entry.stream_id)
            .collect::<Vec<_>>(),
        vec![STREAM_ID],
        "the relay fence matches the roster fixed at QUIESCE"
    );
    assert!(
        fixture
            .session()
            .rotation
            .as_ref()
            .expect("fixture rotation")
            .state
            .status()
            .writers_frozen[0]
    );
    fixture.connector_frozen(0).await;
    fixture.connector_drained().await;
    fixture.connector_committed().await;

    // Admission resumes once the candidate is active.
    let (response, mut receiver) = oneshot::channel();
    fixture.actor.open_echo_stream(
        fixture.consumer.clone(),
        fixture.device_id,
        fixture.service_id,
        fixture.grant.clone(),
        fixture.consumer_expires_at,
        response,
    );
    match receiver.try_recv() {
        Ok(Ok(registration)) => assert_eq!(registration.stream_id, STREAM_ID + 1),
        Ok(Err(error)) => panic!("OPEN after activation must be admitted, got {error}"),
        Err(_) => panic!("OPEN admission must answer synchronously"),
    }
    assert!(
        fixture
            .drain_control()
            .iter()
            .any(|message| matches!(message, ControlMessage::Open(_)))
    );
    assert_eq!(fixture.session().streams.len(), 2);
}

#[tokio::test]
async fn finite_echo_dispatch_pauses_during_quiesce() {
    let mut fixture = FreezeFixture::new("dispatch-pause", false);
    fixture.quiesce();

    let (response, mut receiver) = oneshot::channel();
    fixture
        .actor
        .dispatch_echo(DispatchRequest {
            consumer: fixture.consumer.clone(),
            device_id: fixture.device_id,
            service_id: fixture.service_id,
            grant: fixture.grant.clone(),
            body: b"finite-echo".to_vec(),
            consumer_expires_at: fixture.consumer_expires_at,
            response,
        })
        .await;
    match receiver.try_recv() {
        Ok(EchoOutcome::Failure { code, execution }) => {
            assert_eq!(code, "RESOURCE_EXHAUSTED");
            assert_eq!(execution, "not_dispatched");
        }
        Ok(EchoOutcome::Success(_)) => panic!("finite echo must not complete during quiesce"),
        Err(_) => panic!("finite echo admission must answer synchronously"),
    }
    assert!(
        fixture.session().pending.is_empty(),
        "a refused finite echo must not join the frozen roster"
    );
    assert!(
        fixture
            .drain_control()
            .iter()
            .all(|message| !matches!(message, ControlMessage::Open(_)))
    );
}

#[tokio::test]
async fn coordinated_abort_resumes_old_writer_without_gap() {
    let mut fixture = FreezeFixture::new("abort-resume", false);
    let _active = fixture.write(b"active-record");
    assert_eq!(sequenced(&drain_data(&mut fixture.old_rx)).len(), 1);
    fixture.quiesce();
    assert!(fixture.complete_barrier().is_empty());

    let mut held_quiescing = fixture.write(b"held-quiescing");
    assert_held(&mut held_quiescing, "quiescing");
    let abort_message_id = fixture.abort_by_candidate_loss().await;
    let mut held_aborting = fixture.write(b"held-aborting");
    assert_held(&mut held_aborting, "aborting");
    assert_eq!(fixture.relay_last_emitted(), 1);
    assert!(
        sequenced(&drain_data(&mut fixture.old_rx)).is_empty(),
        "old writes stay frozen until the final owner ABORTED is journaled"
    );

    fixture.connector_aborted(&abort_message_id).await;
    let old = drain_data(&mut fixture.old_rx);
    let old_generation = fixture.attempt.old_generation;
    assert_eq!(
        sequenced(&old),
        vec![
            (FrameKind::Data, 2, old_generation),
            (FrameKind::Data, 3, old_generation),
        ],
        "the old writer resumes in the same sequence space with no gap"
    );
    assert_eq!(
        record_bodies(&old),
        vec![b"held-quiescing".to_vec(), b"held-aborting".to_vec()]
    );
    assert!(!has_close(&old));
    assert_eq!(fixture.relay_last_emitted(), 3);
    assert!(fixture.stream().pending_records.is_empty());
    assert!(
        sequenced(&drain_data(&mut fixture.candidate_rx)).is_empty(),
        "an abandoned candidate never carries sequenced frames"
    );
}

#[tokio::test]
async fn rejected_open_during_quiesce_keeps_roster_until_attempt_completes() {
    let mut fixture = FreezeFixture::new("rejected-roster", true);
    fixture.quiesce();

    fixture
        .actor
        .inbound_control(
            fixture.key.clone(),
            ControlMessage::Rejected(Rejected::new(
                "connector-rejected",
                OPEN_MESSAGE_ID,
                fixture.key.session_id.clone(),
                fixture.key.epoch,
                STREAM_ID,
                OPERATION_ID,
                "GOAWAY",
                "connector is draining",
            )),
        )
        .await;
    assert!(
        fixture.session().streams.contains_key(&STREAM_ID),
        "a REJECTED landing after QUIESCE must not shrink the immutable roster"
    );
    assert!(
        fixture
            .drain_control()
            .iter()
            .all(|message| !matches!(message, ControlMessage::StreamForget(_))),
        "STREAM_FORGET is serialized after the attempt, never inside it"
    );

    assert!(fixture.complete_barrier().is_empty());
    assert_eq!(
        fixture
            .relay_fence()
            .entries
            .iter()
            .map(|entry| entry.stream_id)
            .collect::<Vec<_>>(),
        vec![STREAM_ID]
    );
    fixture.connector_frozen(0).await;
    fixture.connector_drained().await;
    fixture.connector_committed().await;
    fixture.retire_old_carrier().await;

    // The attempt is complete; the deferred reclamation publishes now.
    assert!(fixture.actor.flush_owner_stream_forgets(&fixture.key));
    assert!(
        fixture.drain_control().iter().any(|message| matches!(
            message,
            ControlMessage::StreamForget(forget) if forget.stream_id == STREAM_ID
        )),
        "the rejected OPEN is reclaimed once the roster is released"
    );
    assert!(!fixture.session().streams.contains_key(&STREAM_ID));
}

#[tokio::test]
async fn recovering_session_defers_consumer_fin_without_failure_deadline() {
    let mut fixture = FreezeFixture::new("recovery-fin", false);
    {
        let now_ms = super::monotonic_millis();
        let mut rotation = test_rotation_runtime(now_ms, fixture.attempt.clone(), now_ms + 60_000);
        rotation.attempt = None;
        fixture
            .actor
            .sessions
            .get_mut(&fixture.key.scope())
            .expect("fixture session")
            .rotation = Some(rotation);
    }
    let _active = fixture.write(b"active-record");
    assert_eq!(sequenced(&drain_data(&mut fixture.old_rx)).len(), 1);

    // Losing the active carrier enters retained-state recovery.
    fixture
        .actor
        .disconnect_data(fixture.old_carrier.clone())
        .await;
    assert_eq!(fixture.phase(), RotationPhase::Recovering);
    assert!(fixture.session().data_tx.is_none());
    assert!(
        fixture
            .drain_control()
            .iter()
            .any(|message| matches!(message, ControlMessage::RecoveryBegin(_)))
    );

    let mut held = fixture.write(b"recovering-record");
    assert_held(&mut held, "recovering");
    assert!(
        fixture
            .actor
            .close_echo_stream(&fixture.key, STREAM_ID, OPERATION_ID)
    );
    assert!(fixture.stream().terminal);
    assert!(
        !fixture.stream().terminal_fin_failure,
        "a FIN deferred by recovery is not a publication failure"
    );
    assert!(fixture.session().terminal_fin_failure_deadline.is_none());
    assert_eq!(fixture.relay_last_emitted(), 1);
}

/// protocol.md, "Abort, deadline and loss during handover": "Old transport
/// fails before drain completes: do not declare a successful drain or discard
/// an unacknowledged prefix. Close failed/candidate transports as needed to
/// preserve the socket bound and enter retained-state recovery with a fresh
/// greater generation. The original overlap deadline still retires the
/// abandoned attempt."  The state diagram's `Draining --> Recovering: old
/// transport lost` edge is the same contract.  Here the old carrier disappears
/// while the attempt is `Draining` with an unacknowledged relay prefix and an
/// unreachable connector fence, so no drain proof is possible.
#[tokio::test]
async fn old_carrier_loss_while_draining_enters_retained_recovery() {
    let mut fixture = FreezeFixture::new("draining-old-loss", false);
    let _active = fixture.write(b"active-record");
    assert_eq!(
        sequenced(&drain_data(&mut fixture.old_rx)),
        vec![(FrameKind::Data, 1, fixture.attempt.old_generation)],
        "one unacknowledged relay record is outstanding on the old carrier"
    );
    fixture.quiesce();
    assert!(fixture.complete_barrier().is_empty());
    // The connector's fence advertises a sequence the relay has not received,
    // so the relay owes a receive cursor it can never reach on this carrier.
    fixture.connector_frozen(2).await;
    assert_eq!(fixture.phase(), RotationPhase::Draining);
    let retained_before = fixture.retained_cursors();
    let abandoned_candidate_generation = fixture.attempt.new_generation;
    let overlap_deadline_ms = fixture.overlap_deadline_ms();
    let _ = fixture.drain_control();

    fixture
        .actor
        .disconnect_data(fixture.old_carrier.clone())
        .await;

    assert!(
        fixture.actor.sessions.contains_key(&fixture.key.scope()),
        "losing the old carrier while draining must not close the session"
    );
    assert_eq!(fixture.phase(), RotationPhase::Recovering);
    assert!(fixture.session().data_tx.is_none());
    assert!(fixture.session().active_carrier.is_none());
    let rotation = fixture
        .session()
        .rotation
        .as_ref()
        .expect("rotation state retained");
    assert!(rotation.recovery.is_some(), "a recovery episode is owned");
    assert!(
        rotation.candidate.is_none(),
        "the abandoned candidate transport is released"
    );
    let status = fixture.rotation_status();
    assert_eq!(
        status.recovery_reason,
        Some(tunnel_protocol::rotation::RecoveryReason::OldTransportLost)
    );
    // Neither abandoned carrier can be promoted: the episode anchors on the
    // retained old generation and allocates a fresh greater one.
    assert_eq!(status.active_generation, fixture.attempt.old_generation);
    assert_eq!(
        status.active_connection_id,
        fixture.attempt.old_connection_id
    );
    let recovery_attempt = status.attempt.clone().expect("recovery attempt identity");
    assert_eq!(
        recovery_attempt.old_generation,
        fixture.attempt.old_generation
    );
    assert!(
        recovery_attempt.new_generation > abandoned_candidate_generation,
        "recovery must use a fresh greater generation, got {} after candidate {}",
        recovery_attempt.new_generation,
        abandoned_candidate_generation
    );
    assert!(
        status.socket_count <= 3,
        "recovery exceeded the one-control/two-data bound: {}",
        status.socket_count
    );
    assert_eq!(
        fixture.retained_cursors(),
        retained_before,
        "recovery preserves every retained cursor and credit"
    );

    // Both abandoned data transports are released immediately, which retires
    // the abandoned attempt well inside its original overlap deadline.
    assert!(
        has_close(&drain_data(&mut fixture.candidate_rx)),
        "the candidate transport is closed to preserve the socket bound"
    );
    assert!(
        super::monotonic_millis() < overlap_deadline_ms,
        "the abandoned attempt is retired before its original overlap deadline"
    );
    let control = fixture.drain_control();
    assert!(
        control
            .iter()
            .any(|message| matches!(message, ControlMessage::RecoveryBegin(_))),
        "the coordinator begins the retained-state episode"
    );
    let closed = control
        .iter()
        .find_map(|message| match message {
            ControlMessage::RecoveryClosed(closed) => Some(closed),
            _ => None,
        })
        .expect("the coordinator attests its closure delta");
    let mut expected_closed = vec![
        fixture.attempt.old_connection_id.clone(),
        fixture.attempt.new_connection_id.clone(),
    ];
    expected_closed.sort();
    assert_eq!(
        closed.closed_connection_ids, expected_closed,
        "both abandoned carriers are named in the closure delta"
    );

    // The writer stays frozen and nothing is resumed on either abandoned
    // carrier while the episode runs.
    let mut held = fixture.write(b"recovering-record");
    assert_held(&mut held, "recovering after old-carrier loss");
    assert_eq!(fixture.relay_last_emitted(), 1);
    assert!(sequenced(&drain_data(&mut fixture.old_rx)).is_empty());
    assert!(sequenced(&drain_data(&mut fixture.candidate_rx)).is_empty());
}

/// The same contract at the commit-uncertain boundary.  protocol.md: "Commit
/// uncertain: a connector timeout is not permission to resume old writes. If
/// COMMIT may be in flight or the control connection is unavailable, remain
/// quiesced and enter recovery", with the state diagram's
/// `Committing --> Recovering: failure or uncertain commit`.  COMMIT has been
/// queued but no COMMITTED has been accepted, so the episode may promote
/// neither the candidate generation nor the old one.
#[tokio::test]
async fn old_carrier_loss_while_committing_enters_recovery_without_promoting_either_carrier() {
    let mut fixture = FreezeFixture::new("committing-old-loss", false);
    let _active = fixture.write(b"active-record");
    assert_eq!(sequenced(&drain_data(&mut fixture.old_rx)).len(), 1);
    fixture.quiesce();
    assert!(fixture.complete_barrier().is_empty());
    fixture.connector_frozen(0).await;
    fixture.connector_drained().await;
    assert_eq!(fixture.phase(), RotationPhase::Committing);
    let retained_before = fixture.retained_cursors();
    let candidate_generation = fixture.attempt.new_generation;
    let _ = fixture.drain_control();

    fixture
        .actor
        .disconnect_data(fixture.old_carrier.clone())
        .await;

    assert!(
        fixture.actor.sessions.contains_key(&fixture.key.scope()),
        "an uncertain commit must enter recovery rather than close the session"
    );
    let status = fixture.rotation_status();
    assert_eq!(status.phase, RotationPhase::Recovering);
    assert_eq!(
        status.recovery_reason,
        Some(tunnel_protocol::rotation::RecoveryReason::OldTransportLost)
    );
    // No commit was accepted, so the episode anchors on the retained old
    // generation; the candidate generation is never promoted in its place.
    assert_eq!(status.active_generation, fixture.attempt.old_generation);
    assert_eq!(
        status.active_connection_id,
        fixture.attempt.old_connection_id
    );
    assert_eq!(fixture.session().generation, fixture.attempt.old_generation);
    assert!(
        fixture.session().data_tx.is_none(),
        "neither abandoned carrier remains writable"
    );
    let recovery_attempt = status.attempt.clone().expect("recovery attempt identity");
    assert!(
        recovery_attempt.new_generation > candidate_generation,
        "recovery allocates a fresh greater generation, got {} after candidate {}",
        recovery_attempt.new_generation,
        candidate_generation
    );
    assert!(status.socket_count <= 3);
    assert_eq!(fixture.retained_cursors(), retained_before);
    assert!(
        fixture
            .session()
            .rotation
            .as_ref()
            .is_some_and(|rotation| rotation.candidate.is_none()),
        "the uncommitted candidate transport is released"
    );
    assert!(has_close(&drain_data(&mut fixture.candidate_rx)));

    // The writer stays frozen until the episode reaches READY; neither
    // abandoned carrier receives a sequenced frame.
    let mut held = fixture.write(b"committing-loss-record");
    assert_held(&mut held, "recovering after an uncertain commit");
    assert_eq!(fixture.relay_last_emitted(), 1);
    assert!(sequenced(&drain_data(&mut fixture.old_rx)).is_empty());
    assert!(sequenced(&drain_data(&mut fixture.candidate_rx)).is_empty());
}

/// protocol.md, "Abort, deadline and loss during handover": "Absolute overlap
/// deadline: after commit, forcibly close any old transport still lingering",
/// and the retire step: "`ROTATE_COMPLETE` ends the attempt after retirement
/// evidence; deadline-forced closure is recorded distinctly."  The committed
/// candidate is already serving the retained streams, and the state diagram has
/// no `Retiring --> Recovering` edge, so the deadline must not tear the session
/// down.
#[tokio::test]
async fn overlap_deadline_while_retiring_forces_retirement_and_keeps_serving() {
    let mut fixture = FreezeFixture::new("retiring-deadline", false);
    let _active = fixture.write(b"active-record");
    assert_eq!(sequenced(&drain_data(&mut fixture.old_rx)).len(), 1);
    fixture.quiesce();
    assert!(fixture.complete_barrier().is_empty());
    fixture.connector_frozen(0).await;
    fixture.connector_drained().await;
    fixture.connector_committed().await;
    assert_eq!(fixture.phase(), RotationPhase::Retiring);
    // The connector attests its own old-transport closure; the relay's own
    // physical close event never arrives, so the old transport lingers.
    fixture.connector_retired().await;
    assert_eq!(fixture.phase(), RotationPhase::Retiring);
    let new_generation = fixture.attempt.new_generation;
    let overlap_deadline_ms = fixture.overlap_deadline_ms();
    let retained_before = fixture.retained_cursors();
    let _ = fixture.drain_control();

    assert!(
        !fixture
            .actor
            .poll_rotation_deadline_at(&fixture.key, overlap_deadline_ms),
        "the overlap deadline must not tear down a committed handover"
    );

    assert!(
        fixture.actor.sessions.contains_key(&fixture.key.scope()),
        "the session keeps serving its retained streams on the new generation"
    );
    let status = fixture.rotation_status();
    assert_eq!(status.phase, RotationPhase::Active);
    assert_eq!(
        status.active_generation, new_generation,
        "the attempt completes on the committed candidate"
    );
    assert_eq!(
        status.active_connection_id,
        fixture.attempt.new_connection_id
    );
    assert!(
        status.deadline_forced_retirement,
        "the forced closure is recorded distinctly"
    );
    assert_eq!(
        status.socket_count, 2,
        "one control plus the committed data socket remain"
    );
    assert_eq!(fixture.retained_cursors(), retained_before);
    let forced = fixture
        .drain_control()
        .into_iter()
        .find_map(|message| match message {
            ControlMessage::RotateComplete(complete) => Some(complete),
            _ => None,
        })
        .expect("the forced retirement still ends the attempt with ROTATE_COMPLETE");
    assert!(forced.forced, "ROTATE_COMPLETE records the forced closure");
    assert_eq!(
        forced.reason.as_deref(),
        Some("overlap deadline forced retirement")
    );
    assert_eq!(forced.attempt.new_generation, new_generation);
    let event = fixture
        .actor
        .rotation_deadline_events
        .iter()
        .find(|event| event.session_id == fixture.key.session_id)
        .expect("a payload-free forced-retirement record is latched");
    assert_eq!(event.reason, "forced_retirement");
    assert_eq!(event.deadline_ms, overlap_deadline_ms);
    assert!(event.fired_at_ms >= overlap_deadline_ms);

    // The retained stream keeps serving on the committed candidate, and the
    // old carrier never receives another sequenced frame.
    let mut served = fixture.write(b"post-retirement-record");
    assert_held(&mut served, "served after forced retirement");
    assert_eq!(
        sequenced(&drain_data(&mut fixture.candidate_rx)),
        vec![(FrameKind::Data, 2, new_generation)],
        "retained streams continue their sequence space on the new generation"
    );
    let old = drain_data(&mut fixture.old_rx);
    assert!(
        sequenced(&old).is_empty(),
        "no path resumes writes on the old carrier after a commit"
    );
}
