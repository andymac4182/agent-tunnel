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
                credit_held: false,
                open_message_id: OPEN_MESSAGE_ID.to_owned(),
                operation_id: OPERATION_ID.to_owned(),
                request_id: None,
                service_id,
                consumer: consumer.clone(),
                grant: grant.clone(),
                sequence,
                response_bytes: Vec::new(),
                response_records: VecDeque::new(),
                orphaned_response_records: 0,
                late_response_records: 0,
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
                http: None,
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

/// M7-C44.  protocol.md, "Abort, deadline and loss during handover": only a
/// "Known uncommitted attempt, old healthy" may coordinate `ROTATE_ABORT`, and
/// the state diagram's `Aborting --> Recovering: deadline or decision
/// uncertain` edge covers the moment the old carrier disappears while that
/// abort is still in flight.  The abort can no longer complete (its final
/// owner ABORTED would resume old writes on a carrier that is gone), so the
/// decision is uncertain: the candidate is closed, both abandoned identifiers
/// are recorded, cursors and credits are retained and no write ever resumes
/// on the old carrier.  A late connector ROTATE_ABORTED for the abandoned
/// attempt is rejected deterministically once the episode has begun.
#[tokio::test]
async fn old_carrier_loss_while_aborting_enters_retained_recovery_and_fences_the_abort() {
    let mut fixture = FreezeFixture::new("aborting-old-loss", false);
    let _active = fixture.write(b"active-record");
    assert_eq!(sequenced(&drain_data(&mut fixture.old_rx)).len(), 1);
    fixture.quiesce();
    assert!(fixture.complete_barrier().is_empty());
    fixture.connector_frozen(0).await;
    assert_eq!(fixture.phase(), RotationPhase::Draining);
    let abort_message_id = fixture.abort_by_candidate_loss().await;
    assert_eq!(fixture.phase(), RotationPhase::Aborting);
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
        "losing the old carrier while an abort is in flight must not close the session"
    );
    let status = fixture.rotation_status();
    assert_eq!(status.phase, RotationPhase::Recovering);
    assert_eq!(
        status.recovery_reason,
        Some(tunnel_protocol::rotation::RecoveryReason::OldTransportLost)
    );
    assert_eq!(status.active_generation, fixture.attempt.old_generation);
    assert_eq!(
        status.active_connection_id,
        fixture.attempt.old_connection_id
    );
    let recovery_attempt = status.attempt.clone().expect("recovery attempt identity");
    assert!(
        recovery_attempt.new_generation > abandoned_candidate_generation,
        "recovery must use a fresh greater generation, got {} after candidate {}",
        recovery_attempt.new_generation,
        abandoned_candidate_generation
    );
    assert!(status.socket_count <= 3);
    assert_eq!(fixture.retained_cursors(), retained_before);
    assert!(fixture.session().data_tx.is_none());
    assert!(fixture.session().active_carrier.is_none());
    {
        let rotation = fixture
            .session()
            .rotation
            .as_ref()
            .expect("rotation state retained");
        assert!(rotation.recovery.is_some(), "a recovery episode is owned");
        assert!(rotation.candidate.is_none());
        assert!(
            rotation.abort_message_id.is_none(),
            "the in-flight abort is fenced by the episode"
        );
        assert!(rotation.pending_abort_ack.is_none());
    }
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
    assert!(
        !control
            .iter()
            .any(|message| matches!(message, ControlMessage::RotateAborted(_))),
        "no final ABORTED is emitted once the decision became uncertain"
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
    assert_eq!(closed.closed_connection_ids, expected_closed);

    // The connector's ROTATE_ABORTED for the abandoned attempt may still be
    // in flight.  Delivered through the authenticated inbound path and
    // directly to the handler, it is rejected without closing the session,
    // without a final owner ABORTED and without touching the episode.
    let late_aborted = RotateAborted {
        message_id: CONNECTOR_ABORTED_ID.to_owned(),
        reply_to: abort_message_id,
        attempt: fixture.attempt.clone(),
        reason: "candidate transport lost".to_owned(),
        closed_connection_id: fixture.attempt.new_connection_id.clone(),
    };
    fixture
        .actor
        .inbound_control(
            fixture.key.clone(),
            ControlMessage::RotateAborted(late_aborted.clone()),
        )
        .await;
    fixture
        .actor
        .handle_rotate_aborted(&fixture.key, late_aborted)
        .await;
    assert!(fixture.actor.sessions.contains_key(&fixture.key.scope()));
    let status = fixture.rotation_status();
    assert_eq!(status.phase, RotationPhase::Recovering);
    assert_eq!(status.attempt.as_ref(), Some(&recovery_attempt));
    assert!(
        !fixture
            .drain_control()
            .iter()
            .any(|message| matches!(message, ControlMessage::RotateAborted(_))),
        "a late connector ABORTED cannot revive the abandoned abort"
    );

    // The writer stays frozen and nothing is resumed on either abandoned
    // carrier while the episode runs.
    let mut held = fixture.write(b"recovering-record");
    assert_held(&mut held, "recovering after old-carrier loss during abort");
    assert_eq!(fixture.relay_last_emitted(), 1);
    assert!(sequenced(&drain_data(&mut fixture.old_rx)).is_empty());
    assert!(sequenced(&drain_data(&mut fixture.candidate_rx)).is_empty());
}

/// The same contract when the abort is half resolved: the connector has
/// already acknowledged with ROTATE_ABORTED and only the owner's own candidate
/// closure is outstanding.  The old carrier is lost before that closure, so
/// the final owner ABORTED (which would resume old writes) is never sent; the
/// pending acknowledgement is discarded and recovery begins instead.
#[tokio::test]
async fn old_carrier_loss_after_connector_aborted_but_before_owner_closure_enters_recovery() {
    let mut fixture = FreezeFixture::new("aborting-acked-old-loss", false);
    let _active = fixture.write(b"active-record");
    assert_eq!(sequenced(&drain_data(&mut fixture.old_rx)).len(), 1);
    // The coordinator decides ABORT (as it does at the candidate handshake
    // deadline) while the candidate transport is still attached, so the
    // owner-side closure proof stays outstanding until its physical close.
    fixture
        .actor
        .with_rotation_mut(&fixture.key, |_session, rotation| {
            let attempt = rotation.attempt.clone().expect("fixture attempt");
            rotation.state.abort(
                &attempt,
                super::monotonic_millis(),
                tunnel_protocol::rotation::RecoveryReason::CandidateTransportLost,
            )
        })
        .expect("known uncommitted attempt aborts");
    fixture
        .actor
        .emit_rotation_abort(&fixture.key, "candidate handshake timeout");
    assert_eq!(fixture.phase(), RotationPhase::Aborting);
    let abort_message_id = fixture
        .drain_control()
        .into_iter()
        .find_map(|message| match message {
            ControlMessage::RotateAbort(abort) => Some(abort.message_id),
            _ => None,
        })
        .expect("relay queues ROTATE_ABORT for the attached candidate");
    assert!(
        has_close(&drain_data(&mut fixture.candidate_rx)),
        "the coordinator asks the attached candidate to close"
    );
    assert!(
        fixture
            .session()
            .rotation
            .as_ref()
            .is_some_and(|rotation| rotation.candidate.is_some()),
        "the candidate transport is still attached until its physical close"
    );
    fixture
        .actor
        .handle_rotate_aborted(
            &fixture.key,
            RotateAborted {
                message_id: CONNECTOR_ABORTED_ID.to_owned(),
                reply_to: abort_message_id,
                attempt: fixture.attempt.clone(),
                reason: "candidate handshake timeout".to_owned(),
                closed_connection_id: fixture.attempt.new_connection_id.clone(),
            },
        )
        .await;
    assert_eq!(
        fixture.phase(),
        RotationPhase::Aborting,
        "the owner's own candidate closure is still outstanding"
    );
    assert!(
        fixture
            .session()
            .rotation
            .as_ref()
            .is_some_and(|rotation| rotation.pending_abort_ack.is_some()),
        "the connector acknowledgement is pending the owner closure"
    );
    let retained_before = fixture.retained_cursors();
    let candidate_generation = fixture.attempt.new_generation;
    let _ = fixture.drain_control();

    fixture
        .actor
        .disconnect_data(fixture.old_carrier.clone())
        .await;

    assert!(fixture.actor.sessions.contains_key(&fixture.key.scope()));
    let status = fixture.rotation_status();
    assert_eq!(status.phase, RotationPhase::Recovering);
    assert_eq!(status.active_generation, fixture.attempt.old_generation);
    let recovery_attempt = status.attempt.clone().expect("recovery attempt identity");
    assert!(recovery_attempt.new_generation > candidate_generation);
    assert!(status.socket_count <= 3);
    assert_eq!(fixture.retained_cursors(), retained_before);
    {
        let rotation = fixture
            .session()
            .rotation
            .as_ref()
            .expect("rotation state retained");
        assert!(rotation.recovery.is_some());
        assert!(rotation.candidate.is_none());
        assert!(rotation.pending_abort_ack.is_none());
        assert!(rotation.abort_message_id.is_none());
    }
    let control = fixture.drain_control();
    assert!(
        !control
            .iter()
            .any(|message| matches!(message, ControlMessage::RotateAborted(_))),
        "the final owner ABORTED is never sent after the old carrier is gone"
    );
    let closed = control
        .iter()
        .find_map(|message| match message {
            ControlMessage::RecoveryClosed(closed) => Some(closed),
            _ => None,
        })
        .expect("closure delta");
    let mut expected_closed = vec![
        fixture.attempt.old_connection_id.clone(),
        fixture.attempt.new_connection_id.clone(),
    ];
    expected_closed.sort();
    assert_eq!(closed.closed_connection_ids, expected_closed);

    // A late physical close of the already-abandoned candidate is absorbed.
    fixture
        .actor
        .disconnect_data(fixture.candidate_carrier.clone())
        .await;
    assert!(fixture.actor.sessions.contains_key(&fixture.key.scope()));
    assert_eq!(fixture.phase(), RotationPhase::Recovering);

    let mut held = fixture.write(b"recovering-record");
    assert_held(
        &mut held,
        "recovering after old-carrier loss during acked abort",
    );
    assert_eq!(fixture.relay_last_emitted(), 1);
    assert!(sequenced(&drain_data(&mut fixture.old_rx)).is_empty());
    assert!(sequenced(&drain_data(&mut fixture.candidate_rx)).is_empty());
}

/// The overlap budget can elapse before the maintenance tick observes it, and
/// a candidate carrier's physical close can be processed inside that window.
/// protocol.md scopes the recover-or-fail rule at the absolute deadline to "an
/// unfinished abort or drain", and the tick's own path is to latch the typed
/// deadline event and end the attempt with `ROTATION_DEADLINE_EXPIRED`.  A
/// close that lands first must take exactly that path; it must not be
/// misclassified as a fresh candidate failure with the deadline event lost.
/// The drain is stalled the way the M7 timing sweep stalled it: the
/// connector's fence advertises a sequence the relay never received, so the
/// relay owes a receive cursor it cannot reach before the budget runs out.
#[tokio::test]
async fn candidate_loss_after_overlap_deadline_takes_the_deadline_path() {
    let mut fixture = FreezeFixture::new("post-deadline-candidate-loss", false);
    let _active = fixture.write(b"active-record");
    assert_eq!(sequenced(&drain_data(&mut fixture.old_rx)).len(), 1);
    fixture.quiesce();
    assert!(fixture.complete_barrier().is_empty());
    fixture.connector_frozen(2).await;
    assert_eq!(fixture.phase(), RotationPhase::Draining);
    let candidate_generation = fixture.attempt.new_generation;
    let overlap_deadline_ms = fixture.overlap_deadline_ms();
    let _ = fixture.drain_control();

    fixture
        .actor
        .disconnect_data_at(fixture.candidate_carrier.clone(), overlap_deadline_ms)
        .await;

    assert!(
        !fixture.actor.sessions.contains_key(&fixture.key.scope()),
        "an expired overlap budget ends the unfinished drain"
    );
    let terminal = fixture
        .actor
        .session_terminal_events
        .iter()
        .rev()
        .find(|event| {
            event.session_id == fixture.key.session_id && event.epoch == fixture.key.epoch
        })
        .expect("the session records its typed terminal cause");
    assert_eq!(
        terminal.reason, "ROTATION_DEADLINE_EXPIRED",
        "a post-deadline candidate close is the deadline outcome, not a candidate failure"
    );
    assert_eq!(terminal.candidate_generation, Some(candidate_generation));
    let event = fixture
        .actor
        .rotation_deadline_events
        .iter()
        .find(|event| event.session_id == fixture.key.session_id)
        .expect("the typed deadline event is latched exactly as the tick would latch it");
    assert_eq!(event.reason, "deadline");
    assert_eq!(event.deadline_ms, overlap_deadline_ms);
    assert_eq!(event.fired_at_ms, overlap_deadline_ms);
    assert_eq!(event.candidate_generation, candidate_generation);
}

/// The same close one millisecond inside the budget is still an ordinary
/// candidate transport loss: the owner queues a bounded `ROTATE_ABORT` with
/// the remaining budget, the session stays up in `Aborting`, and neither a
/// terminal cause nor a deadline event is recorded.  This pins that the
/// post-deadline path above does not widen into the in-budget case.
#[tokio::test]
async fn candidate_loss_with_budget_remaining_keeps_the_bounded_abort() {
    let mut fixture = FreezeFixture::new("in-budget-candidate-loss", false);
    let _active = fixture.write(b"active-record");
    assert_eq!(sequenced(&drain_data(&mut fixture.old_rx)).len(), 1);
    fixture.quiesce();
    assert!(fixture.complete_barrier().is_empty());
    fixture.connector_frozen(2).await;
    assert_eq!(fixture.phase(), RotationPhase::Draining);
    let overlap_deadline_ms = fixture.overlap_deadline_ms();
    let _ = fixture.drain_control();

    fixture
        .actor
        .disconnect_data_at(fixture.candidate_carrier.clone(), overlap_deadline_ms - 1)
        .await;

    assert!(
        fixture.actor.sessions.contains_key(&fixture.key.scope()),
        "a candidate loss inside the budget never ends the session by itself"
    );
    assert_eq!(fixture.phase(), RotationPhase::Aborting);
    let abort = fixture
        .drain_control()
        .into_iter()
        .find_map(|message| match message {
            ControlMessage::RotateAbort(abort) => Some(abort),
            _ => None,
        })
        .expect("the owner queues a bounded ROTATE_ABORT after in-budget candidate loss");
    assert_eq!(
        abort.remaining_ms, 1,
        "the abort carries exactly the budget that was left"
    );
    assert!(
        !fixture
            .actor
            .session_terminal_events
            .iter()
            .any(|event| event.session_id == fixture.key.session_id),
        "no terminal cause is recorded while the budget remains"
    );
    assert!(
        !fixture
            .actor
            .rotation_deadline_events
            .iter()
            .any(|event| event.session_id == fixture.key.session_id),
        "no deadline event is latched while the budget remains"
    );
}

/// M7-C45.  A connector that never sends `ROTATE_RETIRED` after a committed
/// handover.  protocol.md: "Absolute overlap deadline: after commit, forcibly
/// close any old transport still lingering" and "`ROTATE_COMPLETE` ends the
/// attempt after retirement evidence; deadline-forced closure is recorded
/// distinctly."  The forced closure is the owner's evidence: after one
/// bounded post-deadline grace (the handshake budget) the attempt completes
/// on the committed candidate with the missing attestation recorded
/// distinctly, a later RETIRED is stale, and the session can rotate again.
/// The stall is driven with an explicit clock; nothing waits and nothing
/// hangs.
#[tokio::test]
async fn missing_connector_retirement_completes_after_bounded_grace_and_rotates_again() {
    let mut fixture = FreezeFixture::new("retiring-missing-retired", false);
    let _active = fixture.write(b"active-record");
    assert_eq!(sequenced(&drain_data(&mut fixture.old_rx)).len(), 1);
    fixture.quiesce();
    assert!(fixture.complete_barrier().is_empty());
    fixture.connector_frozen(0).await;
    fixture.connector_drained().await;
    fixture.connector_committed().await;
    assert_eq!(fixture.phase(), RotationPhase::Retiring);
    // The relay's own old transport closes; the connector never attests.
    fixture
        .actor
        .disconnect_data(fixture.old_carrier.clone())
        .await;
    assert_eq!(fixture.phase(), RotationPhase::Retiring);
    let new_generation = fixture.attempt.new_generation;
    let overlap_deadline_ms = fixture.overlap_deadline_ms();
    let grace_ms = fixture
        .session()
        .rotation
        .as_ref()
        .expect("rotation")
        .state
        .config()
        .handshake_timeout_ms;
    let retained_before = fixture.retained_cursors();
    let _ = fixture.drain_control();

    // At the deadline the forced closure is latched but the attestation is
    // still awaited; the session keeps serving on the committed candidate.
    assert!(
        !fixture
            .actor
            .poll_rotation_deadline_at(&fixture.key, overlap_deadline_ms)
    );
    assert!(fixture.actor.sessions.contains_key(&fixture.key.scope()));
    assert_eq!(fixture.phase(), RotationPhase::Retiring);
    assert!(fixture.rotation_status().deadline_forced_retirement);
    assert!(
        !fixture
            .drain_control()
            .iter()
            .any(|message| matches!(message, ControlMessage::RotateComplete(_))),
        "no COMPLETE before the bounded grace elapses"
    );
    assert!(
        !fixture
            .actor
            .poll_rotation_deadline_at(&fixture.key, overlap_deadline_ms + grace_ms - 1)
    );
    assert_eq!(fixture.phase(), RotationPhase::Retiring);

    // The grace elapses with no RETIRED: the attempt completes on the forced
    // closure alone and the missing attestation is recorded distinctly.
    assert!(
        !fixture
            .actor
            .poll_rotation_deadline_at(&fixture.key, overlap_deadline_ms + grace_ms)
    );
    assert!(fixture.actor.sessions.contains_key(&fixture.key.scope()));
    let status = fixture.rotation_status();
    assert_eq!(status.phase, RotationPhase::Active);
    assert_eq!(status.active_generation, new_generation);
    assert_eq!(
        status.active_connection_id,
        fixture.attempt.new_connection_id
    );
    assert!(status.deadline_forced_retirement);
    assert!(
        status.connector_retirement_missing,
        "the missing connector attestation is recorded distinctly"
    );
    assert!(status.attempt.is_none(), "the attempt is complete");
    assert_eq!(status.socket_count, 2);
    assert_eq!(fixture.retained_cursors(), retained_before);
    let complete = fixture
        .drain_control()
        .into_iter()
        .find_map(|message| match message {
            ControlMessage::RotateComplete(complete) => Some(complete),
            _ => None,
        })
        .expect("the forced closure ends the attempt with ROTATE_COMPLETE");
    assert!(complete.forced);
    assert!(
        complete.reply_to.is_empty(),
        "there is no connector RETIRED to correlate to"
    );
    assert_eq!(
        complete.reason.as_deref(),
        Some("overlap deadline forced retirement without connector retirement evidence")
    );
    assert_eq!(complete.attempt, fixture.attempt);
    let event = fixture
        .actor
        .rotation_deadline_events
        .iter()
        .find(|event| {
            event.session_id == fixture.key.session_id
                && event.reason == "missing_connector_retirement"
        })
        .expect("a payload-free missing-retirement record is latched");
    assert_eq!(event.deadline_ms, overlap_deadline_ms);
    assert!(event.fired_at_ms >= overlap_deadline_ms + grace_ms);

    // A later RETIRED for the completed attempt is stale: absorbed through the
    // authenticated inbound path and by the handler, with no second COMPLETE.
    let stale = RotateRetired {
        message_id: CONNECTOR_RETIRED_ID.to_owned(),
        reply_to: fixture.retire_message_id.clone(),
        attempt: fixture.attempt.clone(),
        snapshot_id: fixture.snapshot_id.clone(),
        closed_connection_id: fixture.attempt.old_connection_id.clone(),
    };
    fixture
        .actor
        .inbound_control(
            fixture.key.clone(),
            ControlMessage::RotateRetired(stale.clone()),
        )
        .await;
    fixture
        .actor
        .handle_rotate_retired(&fixture.key, stale)
        .await;
    assert!(fixture.actor.sessions.contains_key(&fixture.key.scope()));
    assert_eq!(fixture.phase(), RotationPhase::Active);
    assert!(
        !fixture
            .drain_control()
            .iter()
            .any(|message| matches!(message, ControlMessage::RotateComplete(_))),
        "a stale RETIRED cannot produce a second COMPLETE"
    );

    // Retained streams keep serving on the committed candidate and the old
    // carrier never receives another sequenced frame.
    let mut served = fixture.write(b"post-grace-record");
    assert_held(
        &mut served,
        "served after the missing-retirement completion",
    );
    assert_eq!(
        sequenced(&drain_data(&mut fixture.candidate_rx)),
        vec![(FrameKind::Data, 2, new_generation)]
    );
    assert!(sequenced(&drain_data(&mut fixture.old_rx)).is_empty());

    // The session can rotate again: the next scheduled attempt allocates a
    // fresh greater generation on top of the committed carrier, and its
    // status no longer carries the previous attempt's forced markers.
    let started = fixture.actor.start_rotation_local_at(
        &fixture.key,
        None,
        "timer",
        overlap_deadline_ms + grace_ms + 1,
    );
    assert!(
        matches!(started, super::RotationStart::Started(_)),
        "a completed forced retirement must not leave the session unable to rotate"
    );
    let next = fixture.rotation_status();
    assert_eq!(next.phase, RotationPhase::Preparing);
    let next_attempt = next.attempt.expect("next scheduled attempt");
    assert_eq!(next_attempt.old_generation, new_generation);
    assert!(next_attempt.new_generation > new_generation);
    assert_ne!(
        next_attempt.new_connection_id, fixture.attempt.old_connection_id,
        "the force-retired carrier identifier is never reused"
    );
    assert!(!next.deadline_forced_retirement);
    assert!(!next.connector_retirement_missing);
    assert!(
        fixture
            .drain_control()
            .iter()
            .any(|message| matches!(message, ControlMessage::RotatePrepare(_))),
        "the next attempt's PREPARE is queued"
    );
}

/// EC-044 post-drain rejection on the retiring carrier.  Once the connector
/// has attested its immutable fence, a sequenced frame beyond that fence on
/// the old carrier is a protocol violation: accepting it would move the
/// relay's receive cursor above the fence and make its own DRAIN proof
/// unprovable (`AckAboveFence`).  The validator must fence the session
/// instead of admitting the frame into stream state.
#[tokio::test]
async fn beyond_fence_frame_on_the_old_carrier_after_frozen_fails_closed() {
    let mut fixture = FreezeFixture::new("beyond-fence", false);
    let _pending = fixture.write(b"before-fence");
    assert_eq!(sequenced(&drain_data(&mut fixture.old_rx)).len(), 1);
    fixture.quiesce();
    assert!(fixture.complete_barrier().is_empty());
    // The connector's fence covers exactly one in-flight frame.
    fixture.connector_frozen(1).await;
    let epoch = fixture.key.epoch;
    let old_generation = fixture.attempt.old_generation;
    let mut payload = 7_u32.to_be_bytes().to_vec();
    payload.extend_from_slice(b"in-fenc");
    fixture
        .actor
        .inbound_m2_stream_data(
            fixture.old_carrier.clone(),
            Frame::data(epoch, old_generation, STREAM_ID, 1, 1, payload.clone()),
            false,
        )
        .await;
    let old = drain_data(&mut fixture.old_rx);
    assert!(
        old.iter().any(|item| matches!(
            item,
            Observed::Frame(frame) if frame.kind == FrameKind::Ack && frame.ack == 1
        )),
        "the frame inside the fence is accepted and acknowledged"
    );
    assert!(
        fixture
            .drain_control()
            .iter()
            .any(|message| matches!(message, ControlMessage::RotateDrained(_))),
        "the relay proves its drain exactly at the connector fence"
    );
    assert_eq!(fixture.phase(), RotationPhase::Draining);

    // A second sequenced frame on the old carrier is beyond the attested
    // fence: it must never advance the receive cursor past the fence.  The
    // payload is a record prefix without its body, so nothing downstream of
    // the sequence validator (record parsing, waiter matching) can reject it
    // by accident: only the fence rule can.
    fixture
        .actor
        .inbound_data(
            fixture.old_carrier.clone(),
            Frame::data(
                epoch,
                old_generation,
                STREAM_ID,
                2,
                1,
                32_u32.to_be_bytes().to_vec(),
            )
            .encode()
            .expect("beyond-fence frame encodes"),
        )
        .await;
    assert!(
        !fixture.actor.sessions.contains_key(&fixture.key.scope()),
        "a frame beyond the connector's own fence on the retiring carrier fails closed"
    );
    assert_eq!(
        fixture
            .actor
            .session_terminal_events
            .back()
            .map(|event| event.reason),
        Some("FENCE_VIOLATION")
    );
    assert!(
        drain_data(&mut fixture.old_rx)
            .iter()
            .all(|item| !matches!(item, Observed::Frame(frame) if frame.kind == FrameKind::Ack)),
        "the beyond-fence frame is never acknowledged"
    );
}

/// EC-044 post-drain rejection after commit: delayed bytes on the retired
/// generation are dropped at the carrier boundary and cannot reach stream
/// state, acknowledge, or disturb the activated carrier.
#[tokio::test]
async fn retired_carrier_frames_after_commit_are_dropped_without_touching_stream_state() {
    let mut fixture = FreezeFixture::new("retired-late", false);
    fixture.quiesce();
    assert!(fixture.complete_barrier().is_empty());
    fixture.connector_frozen(0).await;
    fixture.connector_drained().await;
    fixture.connector_committed().await;
    assert_eq!(fixture.phase(), RotationPhase::Retiring);
    let cursors = fixture.retained_cursors();
    let epoch = fixture.key.epoch;
    let old_generation = fixture.attempt.old_generation;
    let mut payload = 4_u32.to_be_bytes().to_vec();
    payload.extend_from_slice(b"late");
    for late in [
        Frame::data(epoch, old_generation, STREAM_ID, 1, 0, payload),
        Frame::fin(epoch, old_generation, STREAM_ID, 1, 0),
        Frame::reset(epoch, old_generation, STREAM_ID, 1, 0, 4_002),
        Frame::window_update(epoch, old_generation, STREAM_ID, u64::MAX / 2),
    ] {
        fixture
            .actor
            .inbound_data(
                fixture.old_carrier.clone(),
                late.encode().expect("late frame encodes"),
            )
            .await;
        assert!(fixture.actor.sessions.contains_key(&fixture.key.scope()));
    }
    assert_eq!(
        fixture.retained_cursors(),
        cursors,
        "late frames on the retired generation never reach stream state"
    );
    assert!(!fixture.stream().terminal);
    assert!(
        sequenced(&drain_data(&mut fixture.old_rx)).is_empty()
            && drain_data(&mut fixture.candidate_rx).is_empty(),
        "nothing is acknowledged or emitted for a retired-generation frame"
    );
    assert_eq!(fixture.phase(), RotationPhase::Retiring);

    // The old generation on the activated connection is stale data, not a
    // late event: it fails closed.
    fixture
        .actor
        .inbound_data(
            fixture.candidate_carrier.clone(),
            Frame::fin(epoch, old_generation, STREAM_ID, 1, 0)
                .encode()
                .expect("stale frame encodes"),
        )
        .await;
    assert!(!fixture.actor.sessions.contains_key(&fixture.key.scope()));
    assert_eq!(
        fixture
            .actor
            .session_terminal_events
            .back()
            .map(|event| event.reason),
        Some("STALE_DATA")
    );
}

/// M7-C66: a beyond-fence frame that races ahead of FROZEN must fail closed.
///
/// The forward check added with M7-C65 is anchored on the processed FROZEN, so
/// it can only refuse a frame that arrives after the fence is known. A frame
/// beyond the fence that arrives first is admitted and advances the receive
/// cursor, and the relay then accepts an attestation that contradicts its own
/// state, leaving the drain proof unprovable. The check is retroactive: when
/// FROZEN arrives, a settled receive cursor above the attested fence fails the
/// session closed.
#[tokio::test]
async fn beyond_fence_frame_before_frozen_fails_closed_when_the_fence_arrives() {
    let mut fixture = FreezeFixture::new("beyond-fence-early", false);
    // Two outstanding records, so two inbound responses are both solicited and
    // the scenario turns on the fence rather than on an unsolicited reply.
    let _first = fixture.write(b"before-fence-1");
    let _second = fixture.write(b"before-fence-2");
    assert_eq!(sequenced(&drain_data(&mut fixture.old_rx)).len(), 2);
    fixture.quiesce();
    assert!(fixture.complete_barrier().is_empty());

    // The connector will attest a fence of 1, but this frame at sequence 2
    // arrives while the relay still has no fence to compare against.
    let epoch = fixture.key.epoch;
    let old_generation = fixture.attempt.old_generation;
    let mut payload = 7_u32.to_be_bytes().to_vec();
    payload.extend_from_slice(b"beyond!");
    fixture
        .actor
        .inbound_m2_stream_data(
            fixture.old_carrier.clone(),
            Frame::data(epoch, old_generation, STREAM_ID, 1, 1, payload.clone()),
            false,
        )
        .await;
    fixture
        .actor
        .inbound_m2_stream_data(
            fixture.old_carrier.clone(),
            Frame::data(epoch, old_generation, STREAM_ID, 2, 1, payload),
            false,
        )
        .await;
    let _ = drain_data(&mut fixture.old_rx);
    assert!(
        fixture.actor.sessions.contains_key(&fixture.key.scope()),
        "the frame is admitted before the fence exists; nothing can reject it yet (closed with {:?})",
        fixture
            .actor
            .session_terminal_events
            .back()
            .map(|event| event.reason)
    );

    // The attestation now contradicts the relay's own receive cursor. Drive the
    // handler directly: the `connector_frozen` helper asserts the rotation
    // reaches Draining, which is exactly what must not happen here.
    let snapshot = FenceSnapshot::new(
        fixture.snapshot_id.clone(),
        vec![StreamFence::new(STREAM_ID, Direction::ConnectorToRelay, 1)],
    );
    fixture
        .actor
        .handle_rotate_frozen(
            &fixture.key,
            RotateFrozen {
                message_id: CONNECTOR_FROZEN_ID.to_owned(),
                reply_to: fixture.quiesce_message_id.clone(),
                attempt: fixture.attempt.clone(),
                snapshot,
            },
        )
        .await;
    assert!(
        !fixture.actor.sessions.contains_key(&fixture.key.scope()),
        "an attested fence below the settled receive cursor must fail the session closed"
    );
    assert_eq!(
        fixture
            .actor
            .session_terminal_events
            .back()
            .map(|event| event.reason),
        Some("FENCE_VIOLATION")
    );
}

/// Companion negative: the in-flight frames the drain exists to receive must
/// still be admitted.
///
/// A connector flushes frames queued before its own freeze, and those are valid
/// right up to the fence it is about to attest. If anyone later tightens the
/// check above into a forward bound anchored on the relay's cursor at quiesce,
/// this test fails loudly rather than the rejection showing up as a stalled
/// rotation in production.
#[tokio::test]
async fn in_flight_frames_before_frozen_within_the_fence_are_admitted() {
    let mut fixture = FreezeFixture::new("within-fence-early", false);
    let _first = fixture.write(b"before-fence-1");
    let _second = fixture.write(b"before-fence-2");
    assert_eq!(sequenced(&drain_data(&mut fixture.old_rx)).len(), 2);
    fixture.quiesce();
    assert!(fixture.complete_barrier().is_empty());

    let epoch = fixture.key.epoch;
    let old_generation = fixture.attempt.old_generation;
    let mut payload = 7_u32.to_be_bytes().to_vec();
    payload.extend_from_slice(b"in-flig");
    fixture
        .actor
        .inbound_m2_stream_data(
            fixture.old_carrier.clone(),
            Frame::data(epoch, old_generation, STREAM_ID, 1, 1, payload.clone()),
            false,
        )
        .await;
    fixture
        .actor
        .inbound_m2_stream_data(
            fixture.old_carrier.clone(),
            Frame::data(epoch, old_generation, STREAM_ID, 2, 1, payload),
            false,
        )
        .await;
    let _ = drain_data(&mut fixture.old_rx);

    // The connector attests exactly what it sent, so both frames are inside
    // the fence and the rotation proceeds.
    fixture.connector_frozen(2).await;
    assert!(
        fixture.actor.sessions.contains_key(&fixture.key.scope()),
        "frames flushed before the connector's freeze are legitimate up to the attested fence"
    );
    assert_ne!(
        fixture
            .actor
            .session_terminal_events
            .back()
            .map(|event| event.reason),
        Some("FENCE_VIOLATION")
    );
    assert_eq!(fixture.phase(), RotationPhase::Draining);
}

/// Turn the fixture stream into an admitted `http-forward/1` stream.
fn attach_http(fixture: &mut FreezeFixture) -> super::http_stream::HttpStreamWatchers {
    let frozen = super::RelayActor::rotation_frozen(fixture.session());
    let (state, watchers) = super::HttpStreamState::new(frozen);
    fixture
        .actor
        .sessions
        .get_mut(&fixture.key.scope())
        .expect("fixture session")
        .streams
        .get_mut(&STREAM_ID)
        .expect("fixture stream")
        .http = Some(state);
    watchers
}

/// Gate-4 review item 1: the post-command HTTP maintenance must not visit
/// every device's streams for every command.  Per-frame commands name their
/// session, and a session's streams are visited only when its writer-freeze
/// state actually changes.
#[tokio::test]
async fn http_freeze_is_republished_only_on_its_own_sessions_transition() {
    use super::HttpMaintenanceScope;
    let mut fixture = FreezeFixture::new("http-maintenance", false);
    let watchers = attach_http(&mut fixture);
    let scope = fixture.key.scope();
    let unrelated = super::DeviceScope::new(Uuid::from_u128(9_001), Uuid::from_u128(9_002));

    let inbound = super::Command::InboundData {
        carrier: fixture.old_carrier.clone(),
        bytes: Vec::new(),
    };
    assert_eq!(
        inbound.http_maintenance_scope(),
        HttpMaintenanceScope::Session(scope.clone()),
        "a data frame names its own session"
    );

    for _ in 0..16 {
        fixture
            .actor
            .after_command_http_maintenance(HttpMaintenanceScope::Session(scope.clone()))
            .await;
        fixture
            .actor
            .after_command_http_maintenance(HttpMaintenanceScope::All)
            .await;
    }
    assert_eq!(
        fixture.actor.http_maintenance.freeze_stream_scans, 0,
        "no stream is visited while the freeze state is unchanged"
    );
    assert!(!watchers.freeze.is_paused());

    fixture.quiesce();
    fixture
        .actor
        .after_command_http_maintenance(HttpMaintenanceScope::Session(unrelated))
        .await;
    assert_eq!(fixture.actor.http_maintenance.freeze_stream_scans, 0);
    assert!(
        !watchers.freeze.is_paused(),
        "another session's command does not touch this session"
    );

    fixture
        .actor
        .after_command_http_maintenance(HttpMaintenanceScope::Session(scope.clone()))
        .await;
    assert!(
        watchers.freeze.is_paused(),
        "the freeze transition is published"
    );
    for _ in 0..16 {
        fixture
            .actor
            .after_command_http_maintenance(HttpMaintenanceScope::Session(scope.clone()))
            .await;
        fixture
            .actor
            .after_command_http_maintenance(HttpMaintenanceScope::All)
            .await;
    }
    assert_eq!(
        fixture.actor.http_maintenance.freeze_stream_scans, 1,
        "exactly one visit for exactly one transition"
    );
}

/// Gate-4 review item 4: a RESET the writer queue refuses outside a freeze
/// is kept for an ordered retry, and the device learns of the cancellation
/// out of band meanwhile.
#[tokio::test]
async fn refused_http_reset_is_retried_in_order_and_cancels_out_of_band() {
    let mut fixture = FreezeFixture::new("http-reset-refused", false);
    let _watchers = attach_http(&mut fixture);
    let data_tx = fixture
        .session()
        .data_tx
        .clone()
        .expect("fixture data writer");
    while data_tx.try_send(super::DataOutbound::Close).is_ok() {}
    let outcome = fixture.actor.reset_http_stream(
        &fixture.key,
        STREAM_ID,
        OPERATION_ID,
        tunnel_protocol::reset_reason::CANCELLED,
    );
    assert!(outcome.accepted);
    assert_eq!(
        fixture.stream().pending_terminal,
        Some(Terminal::Reset(tunnel_protocol::reset_reason::CANCELLED)),
        "the refused RESET stays pending"
    );
    assert!(fixture.stream().terminal_fin_failure);
    assert!(fixture.session().terminal_fin_failure_deadline.is_some());
    assert!(
        fixture
            .drain_control()
            .iter()
            .any(|message| matches!(message, ControlMessage::Cancel(cancel) if cancel.stream_id == STREAM_ID)),
        "the device is cancelled out of band"
    );

    // The writer drains; the next tick retries the RESET in order.
    let _ = drain_data(&mut fixture.old_rx);
    fixture.actor.retry_failed_terminals(&fixture.key);
    assert_eq!(
        sequenced(&drain_data(&mut fixture.old_rx)),
        vec![(FrameKind::Reset, 1, fixture.attempt.old_generation)]
    );
    assert!(fixture.stream().pending_terminal.is_none());
    assert!(!fixture.stream().terminal_fin_failure);
    assert!(fixture.session().terminal_fin_failure_deadline.is_none());
}

/// Review item 9: an HTTP stream whose RESET is still deferred behind a
/// freeze defers its owner-stream record to reclamation; a session that ends
/// first must still record it, exactly once.
#[tokio::test]
async fn session_teardown_records_an_http_stream_with_a_deferred_terminal() {
    let mut fixture = FreezeFixture::new("http-teardown-record", false);
    let _watchers = attach_http(&mut fixture);
    fixture.quiesce();
    assert!(
        fixture
            .actor
            .close_echo_stream(&fixture.key, STREAM_ID, OPERATION_ID)
    );
    assert!(fixture.stream().pending_terminal.is_some());
    let recorded = |fixture: &FreezeFixture| {
        fixture
            .actor
            .http_forward_diagnostics
            .snapshot()
            .owner_streams
            .iter()
            .filter(|record| record.stream_id == STREAM_ID)
            .cloned()
            .collect::<Vec<_>>()
    };
    assert!(recorded(&fixture).is_empty(), "deferred to reclamation");

    let key = fixture.key.clone();
    fixture.actor.close_session(&key, "TEST_TEARDOWN").await;
    let records = recorded(&fixture);
    assert_eq!(records.len(), 1, "recorded exactly once at teardown");
    assert!(records[0].reset_deferred_by_freeze);
    assert_eq!(records[0].release, "reset");
}

// ---------------------------------------------------------------------------
// M4-35: which teardowns may be reported to a filesystem consumer as "the
// backend went away".
//
// A connector that stops closes both of its sockets, and which loss the relay
// notices first is a race the relay does not control.  Control first is
// `CONTROL_CLOSED`; data first is a frame that fails to queue, which tears the
// session down as `REVERSE_CHANNEL_UNAVAILABLE`.  Both are the same event and
// must reach the consumer as the same close code — a codeless close roughly a
// quarter of the time was gate 9's intermittent failure.
//
// The dangerous half is the second, because `REVERSE_CHANNEL_UNAVAILABLE` is
// *also* how a queue budget refusal arrives: the relay declining to buffer
// more while the device is perfectly healthy.  Reporting that as 1012 is
// exactly the defect M4-28's narrowing removed.  So these cases pin the
// discrimination rather than the reason string — the last two are the ones
// that go red if a later change widens the gate back to the string, or
// loosens it to the bare fact of a dead carrier.
// ---------------------------------------------------------------------------

/// The event gate 9 measures, reached through the control socket.
#[tokio::test]
async fn a_closed_control_session_publishes_the_device_gone_cause() {
    let mut fixture = FreezeFixture::new("teardown-control-closed", false);
    let watchers = attach_http(&mut fixture);
    let key = fixture.key.clone();
    fixture.actor.close_session(&key, "CONTROL_CLOSED").await;
    assert_eq!(
        *watchers.terminal.borrow(),
        Some(super::StreamTeardownCause::DeviceGone),
        "the device's control session ended"
    );
}

/// The same event, reached through the data socket instead: the carrier's
/// receiver is gone, so the device's transport is provably not there.
#[tokio::test]
async fn a_dead_data_carrier_publishes_the_device_gone_cause() {
    let mut fixture = FreezeFixture::new("teardown-carrier-dead", false);
    let watchers = attach_http(&mut fixture);
    // The device's data socket task is finished: its receiver is gone, so the
    // session's sender reports itself closed.
    fixture.old_rx.close();
    let key = fixture.key.clone();
    fixture
        .actor
        .close_session(&key, "REVERSE_CHANNEL_UNAVAILABLE")
        .await;
    assert_eq!(
        *watchers.terminal.borrow(),
        Some(super::StreamTeardownCause::DeviceGone),
        "the device's data carrier ended"
    );
}

/// The refusal that wears the same reason string.  The carrier is alive and
/// the **relay's** queue budget declined the bytes, so no consumer may be told
/// the device is not connected.
#[tokio::test]
async fn a_live_carrier_refusing_a_frame_publishes_no_cause() {
    let mut fixture = FreezeFixture::new("teardown-carrier-live", false);
    let watchers = attach_http(&mut fixture);
    let key = fixture.key.clone();
    fixture
        .actor
        .close_session(&key, "REVERSE_CHANNEL_UNAVAILABLE")
        .await;
    assert_eq!(
        *watchers.terminal.borrow(),
        None,
        "a budget refusal is the relay, not the device"
    );
}

/// A dead carrier is not on its own a licence to report a backend that went
/// away: the relay stopping fences every session, and the device is fine.
#[tokio::test]
async fn a_dead_carrier_under_another_reason_publishes_no_cause() {
    let mut fixture = FreezeFixture::new("teardown-carrier-dead-shutdown", false);
    let watchers = attach_http(&mut fixture);
    fixture.old_rx.close();
    let key = fixture.key.clone();
    fixture.actor.close_session(&key, "SHUTDOWN").await;
    assert_eq!(
        *watchers.terminal.borrow(),
        None,
        "the relay stopped, and the device went nowhere"
    );
}
