use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use axum::Router;
use chrono::{Duration as ChronoDuration, Utc};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{
    AuthenticatedConsumer, DeviceIdentity, GrantSnapshot, OwnerClaimRequest, OwnerToken,
    SharedCatalog,
};
use tunnel_protocol::control_journal::{
    ControlJournal, JournalError, Observation as JournalObservation,
};
use tunnel_protocol::rotation::{
    ClosureEvidence, RecoveryReason, RotationPhase, RotationSide, RotationState, ValidatedRecovery,
};
use tunnel_protocol::rotation_control::{
    DataAttachmentPurpose, DrainProof, DrainProofRef, FenceSnapshot, RecoverySide,
    ResumeDirectionState, ResumeStage, RotationAttemptIdentity, StreamFence, StreamRoster,
};
use tunnel_protocol::{
    AuthorizationChallenge, ControlMessage, Direction, Frame, FrameKind, Hello, ReceiveDisposition,
    RecoveryClosed, RecoveryPlan, StreamSnapshot, StreamState,
};
use tunnel_transport::{CertificateRole, TlsIdentity};
use uuid::Uuid;

use crate::{
    config::{RelayLimits, RelayOptions},
    http,
    runtime::{
        self, CarrierContext, RelaySessionSnapshot, RelaySnapshot, RelayStreamSnapshot,
        RuntimeProfile,
    },
    wire::{self, WireError},
};

const AUTHORIZATION_LIFETIME: Duration = Duration::from_secs(5);
const OWNER_LEASE_SAFETY_MARGIN: Duration = Duration::from_secs(5);
const MAX_ECHO_RESPONSE_EXTRA_BYTES: usize = 256;

/// Errors returned by the relay API.  HTTP handlers map these to bounded,
/// sanitized responses; certificate details, tokens, and backend payloads are
/// never included in this type's public message.
#[derive(Debug)]
pub enum RelayError {
    Config(String),
    Catalog(String),
    Unauthorized,
    Forbidden,
    Conflict(&'static str),
    NotFound,
    Overloaded(&'static str),
    Protocol(String),
    Transport(String),
    Shutdown,
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(message)
            | Self::Catalog(message)
            | Self::Protocol(message)
            | Self::Transport(message) => formatter.write_str(message),
            Self::Unauthorized => formatter.write_str("authentication failed"),
            Self::Forbidden => formatter.write_str("operation is not authorized"),
            Self::Conflict(message) => formatter.write_str(message),
            Self::NotFound => formatter.write_str("device or service was not found"),
            Self::Overloaded(message) => formatter.write_str(message),
            Self::Shutdown => formatter.write_str("relay is shutting down"),
        }
    }
}

impl std::error::Error for RelayError {}

impl From<WireError> for RelayError {
    fn from(error: WireError) -> Self {
        Self::Protocol(error.to_string())
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct SessionKey {
    pub(crate) device_id: Uuid,
    pub(crate) session_id: String,
    pub(crate) epoch: u64,
}

/// A data-socket event must identify the complete physical carrier.  The
/// generation and connection ID are intentionally part of the event rather
/// than inferred from the current session so delayed old-socket events cannot
/// mutate the replacement.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct CarrierKey {
    pub(crate) session: SessionKey,
    pub(crate) generation: u64,
    pub(crate) connection_id: String,
}

impl CarrierKey {
    fn context(&self) -> CarrierContext {
        CarrierContext::new(
            self.session.session_id.clone(),
            self.session.epoch,
            self.generation,
            self.connection_id.clone(),
        )
    }
}

#[derive(Debug)]
pub(crate) enum ControlOutbound {
    Text(String),
    Close,
}

#[derive(Debug)]
pub(crate) enum DataOutbound {
    Binary(Vec<u8>),
    Barrier(oneshot::Sender<()>),
    Close,
}

pub(crate) struct ControlRegistration {
    pub(crate) key: SessionKey,
    pub(crate) welcome: String,
    pub(crate) rx: mpsc::Receiver<ControlOutbound>,
    pub(crate) queue_budget: QueueBudget,
}

pub(crate) struct DataRegistration {
    pub(crate) carrier: CarrierKey,
    pub(crate) rx: mpsc::Receiver<DataOutbound>,
    pub(crate) queue_budget: QueueBudget,
}

/// Shared per-device byte accounting for pending request bodies and encoded
/// outbound control/data queue items.  Socket tasks release an item when they
/// take ownership of it from a bounded channel.
#[derive(Clone, Debug)]
pub(crate) struct QueueBudget {
    used: Arc<AtomicUsize>,
    limit: usize,
}

impl QueueBudget {
    fn new(limit: usize) -> Self {
        Self {
            used: Arc::new(AtomicUsize::new(0)),
            limit,
        }
    }

    fn reserve(&self, bytes: usize) -> bool {
        if bytes > self.limit {
            return false;
        }
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.limit)
            })
            .is_ok()
    }

    pub(crate) fn release(&self, bytes: usize) {
        self.used.fetch_sub(bytes, Ordering::AcqRel);
    }

    fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
}

struct DispatchRequest {
    consumer: AuthenticatedConsumer,
    device_id: Uuid,
    service_id: Uuid,
    grant: GrantSnapshot,
    body: Vec<u8>,
    consumer_expires_at: chrono::DateTime<Utc>,
    response: oneshot::Sender<EchoOutcome>,
}

#[derive(Debug)]
pub(crate) enum EchoOutcome {
    Success(Vec<u8>),
    Failure {
        code: &'static str,
        execution: &'static str,
    },
}

struct PendingEcho {
    operation_id: String,
    send_sequence: u64,
    response: oneshot::Sender<EchoOutcome>,
    response_sequence: u64,
    response_body: Vec<u8>,
    challenge_id: Option<String>,
    consumer: AuthenticatedConsumer,
    service_id: Uuid,
    grant: GrantSnapshot,
    consumer_expires_at: chrono::DateTime<Utc>,
    body: Vec<u8>,
    created_at: Instant,
    dispatched: bool,
    authorization_in_flight: bool,
}

struct DeviceChallenge {
    message_id: String,
    stream_id: u64,
    service_id: String,
    challenge_id: String,
    nonce: String,
    permission_digest: String,
    grant_revision: u64,
    received_at: Instant,
    lifetime: Duration,
}

enum ResponseFrameUpdate {
    Accepted,
    Complete(Vec<u8>, oneshot::Sender<EchoOutcome>),
    Invalid,
}

type ChallengeAuthorizationResult = Result<
    (
        Option<GrantSnapshot>,
        Option<tunnel_catalog::OwnerClaim>,
        Option<DeviceIdentity>,
        Option<Instant>,
    ),
    String,
>;

#[derive(Clone)]
struct Ticket {
    value: String,
    device_id: Uuid,
    spki: String,
    session_id: String,
    epoch: u64,
    generation: u64,
    welcome_message_id: String,
    connection_id: String,
    issued_at_wall: chrono::DateTime<Utc>,
    expires_at_wall: chrono::DateTime<Utc>,
    expires_at: Instant,
    consuming: bool,
    owner: OwnerToken,
    candidate: bool,
    attachment_purpose: DataAttachmentPurpose,
}

struct DataCarrier {
    context: CarrierContext,
    tx: mpsc::Sender<DataOutbound>,
}

struct M2Stream {
    operation_id: String,
    service_id: Uuid,
    consumer: AuthenticatedConsumer,
    grant: GrantSnapshot,
    sequence: StreamState,
    response_bytes: Vec<u8>,
    response_records: VecDeque<oneshot::Sender<Result<Vec<u8>, EchoOutcome>>>,
    send_bytes: usize,
    receive_bytes: usize,
    authorized_until: Option<Instant>,
    consumer_expires_at: chrono::DateTime<Utc>,
    challenge_id: Option<String>,
    authorization_in_flight: bool,
    pending_records: VecDeque<PendingConsumerRecord>,
    pending_record_bytes: usize,
    /// Bytes charged to the session-wide retained/reorder/application budget.
    /// This covers deferred consumer records, response reassembly and the
    /// sequence replay/reorder state; socket queue charges are separate and
    /// released when a writer takes ownership.
    budget_bytes: usize,
    terminal: bool,
    closed: CancellationToken,
}

type PendingConsumerRecord = (Vec<u8>, oneshot::Sender<Result<Vec<u8>, EchoOutcome>>);

struct RotationRuntime {
    state: RotationState,
    attempt: Option<RotationAttemptIdentity>,
    attempt_deadline_ms: Option<u64>,
    snapshot_id: String,
    /// The writer-flush barrier is supervised by the actor's bounded
    /// maintenance tick.  Keeping the receiver here avoids a detached task
    /// that could outlive the session or wait past the attempt deadline.
    barrier_rx: Option<oneshot::Receiver<()>>,
    candidate: Option<DataCarrier>,
    old_connection_id: String,
    prepare_message_id: String,
    last_message_id: String,
    /// Message id of the coordinator's unsolicited ABORT, when one has been
    /// queued for this attempt.  A separate marker is required because an
    /// owner ABORT has an empty `reply_to` and therefore is not a journal
    /// completion of any peer phase message.
    abort_message_id: Option<String>,
    /// Most recent authenticated peer phase message.  It stays separate from
    /// owner-generated replies so COMMIT/COMPLETE never reference an outbound
    /// ID that cannot be completed in the inbound journal.
    peer_message_id: String,
    /// Outbound phase IDs are retained separately so a delayed peer message
    /// is correlated with the phase it acknowledges even after a later local
    /// response has been emitted on the other control ordering.
    quiesce_message_id: String,
    frozen_message_id: String,
    commit_message_id: String,
    retire_message_id: String,
    /// Pin the first authenticated peer message for each phase.  A fresh
    /// message ID with the same attempt and reply target is not an idempotent
    /// retry and must not overwrite the source used by the next transition.
    peer_frozen_message_id: Option<String>,
    peer_drained_message_id: Option<String>,
    peer_committed_message_id: Option<String>,
    peer_retired_message_id: Option<String>,
    peer_aborted_message_id: Option<String>,
    /// Connector ABORTED may arrive before the relay's physical candidate
    /// close event.  Keep that authenticated acknowledgement pending until
    /// the owner-side closure proof is present.
    pending_abort_ack: Option<tunnel_protocol::rotation_control::RotateAborted>,
    tombstones: VecDeque<RotationTombstone>,
    remote_fences: [Option<FenceSnapshot>; 2],
    own_fence: Option<FenceSnapshot>,
    replayed_frames: u64,
    journal: ControlJournal,
    recovery: Option<RecoveryRuntime>,
}

struct RotationTombstone {
    attempt: RotationAttemptIdentity,
    deadline_ms: u64,
    journal: ControlJournal,
}

const MAX_ROTATION_TOMBSTONES: usize = 8;

/// The result of observing one authenticated rotation-control message in the
/// bounded per-attempt journal.  A duplicate is deliberately distinct from a
/// new message: pending work must not be dispatched twice, while a completed
/// reply can be retransmitted byte-for-byte without running the pure state
/// transition again.
#[derive(Debug)]
enum RotationJournalDecision {
    New,
    PendingDuplicate,
    CompletedDuplicate(Vec<Vec<u8>>),
    Error(JournalError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryReadyProgress {
    Pending,
    Sent,
}

struct RecoveryRuntime {
    episode_id: String,
    attempt_no: u64,
    episode_deadline_ms: u64,
    roster: StreamRoster,
    expected_closed_connection_ids: Vec<String>,
    local_closed: Option<RecoveryClosed>,
    peer_closed: Option<RecoveryClosed>,
    closure_digest: Option<String>,
    candidate_ready: bool,
    resume_message_ids: [Option<String>; 2],
    snapshot_reply_ids: [Option<String>; 2],
    local_snapshots: [Vec<ResumeDirectionState>; 2],
    /// Fresh local cursors captured only after retained replay and peer-prefix
    /// obligations have been accounted for.  READY is validated against these
    /// entries rather than the initial SNAPSHOT fence.
    ready_snapshots: [Vec<ResumeDirectionState>; 2],
    ready_message_ids: [Option<String>; 2],
    remote_snapshots: [HashMap<u64, ResumeDirectionState>; 2],
    ready_remote_snapshots: [HashMap<u64, ResumeDirectionState>; 2],
    remote_ready: [bool; 2],
    local_plans: HashMap<u64, RecoveryPlan>,
    ready_sent: [bool; 2],
    deferred_frames: VecDeque<(CarrierKey, Frame, usize)>,
    deferred_bytes: usize,
    activated: bool,
}

struct DeviceSession {
    identity: DeviceIdentity,
    owner: OwnerToken,
    key: SessionKey,
    control_tx: mpsc::Sender<ControlOutbound>,
    data_tx: Option<mpsc::Sender<DataOutbound>>,
    active_carrier: Option<DataCarrier>,
    generation: u64,
    connection_id: String,
    profile: RuntimeProfile,
    next_stream_id: u64,
    pending: HashMap<u64, PendingEcho>,
    streams: HashMap<u64, M2Stream>,
    rotation: Option<RotationRuntime>,
    last_rotation: Instant,
    rotations_completed: u64,
    total_replayed_frames: u64,
    queued_bytes: usize,
    queue_budget: QueueBudget,
    last_lease_renewal: Instant,
    maintenance_in_flight: bool,
    closed: bool,
}

enum Command {
    RegisterControl {
        identity: TlsIdentity,
        hello: ControlMessage,
        response: oneshot::Sender<Result<ControlRegistration, RelayError>>,
    },
    AttachData {
        identity: TlsIdentity,
        ticket: String,
        response: oneshot::Sender<Result<DataRegistration, RelayError>>,
    },
    InboundControl {
        key: SessionKey,
        message: ControlMessage,
    },
    InboundData {
        carrier: CarrierKey,
        bytes: Vec<u8>,
    },
    DisconnectControl(SessionKey),
    DisconnectData(CarrierKey),
    DispatchEcho {
        consumer: AuthenticatedConsumer,
        device_id: Uuid,
        service_id: Uuid,
        grant: GrantSnapshot,
        body: Vec<u8>,
        consumer_expires_at: chrono::DateTime<Utc>,
        response: oneshot::Sender<EchoOutcome>,
    },
    Tick,
    Shutdown(oneshot::Sender<()>),
    RegisterResolved {
        device_id: Uuid,
        identity: TlsIdentity,
        hello: Hello,
        response: oneshot::Sender<Result<ControlRegistration, RelayError>>,
        result: Result<(DeviceIdentity, tunnel_catalog::OwnerClaim), RelayError>,
    },
    AttachResolved {
        identity: TlsIdentity,
        ticket: Ticket,
        response: oneshot::Sender<Result<DataRegistration, RelayError>>,
        result: Result<(Option<DeviceIdentity>, Option<tunnel_catalog::OwnerClaim>), String>,
    },
    ChallengeAuthorized {
        key: SessionKey,
        challenge: DeviceChallenge,
        result: ChallengeAuthorizationResult,
    },
    MaintenanceResult {
        key: SessionKey,
        renewed: Option<Result<bool, String>>,
        identity: Result<Option<DeviceIdentity>, String>,
    },
    OpenEchoStream {
        consumer: AuthenticatedConsumer,
        device_id: Uuid,
        service_id: Uuid,
        grant: GrantSnapshot,
        consumer_expires_at: chrono::DateTime<Utc>,
        response: oneshot::Sender<Result<ConsumerStreamRegistration, RelayError>>,
    },
    WriteEchoStream {
        key: SessionKey,
        stream_id: u64,
        operation_id: String,
        body: Vec<u8>,
        response: oneshot::Sender<Result<Vec<u8>, EchoOutcome>>,
    },
    CloseEchoStream {
        key: SessionKey,
        stream_id: u64,
        operation_id: String,
    },
    Snapshot {
        response: oneshot::Sender<RelaySnapshot>,
    },
}

/// Registration returned to an authenticated consumer WebSocket.  The
/// operation and stream identifiers remain stable for the lifetime of that
/// socket; application records are multiplexed within the one logical stream.
pub(crate) struct ConsumerStreamRegistration {
    pub(crate) key: SessionKey,
    pub(crate) stream_id: u64,
    pub(crate) operation_id: String,
    pub(crate) closed: CancellationToken,
}

/// A cloneable, bounded command handle used by HTTP and WebSocket tasks.
#[derive(Clone)]
pub struct RelayHandle {
    tx: mpsc::Sender<Command>,
}

impl RelayHandle {
    pub(crate) fn spawn(options: RelayOptions, catalog: SharedCatalog) -> Self {
        let capacity = options.limits.max_queue_messages.max(32);
        let (tx, rx) = mpsc::channel(capacity);
        let handle = Self { tx: tx.clone() };
        let actor = RelayActor {
            options,
            catalog,
            command_tx: tx.clone(),
            rx,
            sessions: HashMap::new(),
            registering: HashSet::new(),
            tickets: HashMap::new(),
            cleanup_tasks: Vec::new(),
            shutting_down: false,
        };
        tokio::spawn(actor.run());
        let ticker = handle.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            loop {
                interval.tick().await;
                if ticker.tx.send(Command::Tick).await.is_err() {
                    break;
                }
            }
        });
        handle
    }

    pub(crate) async fn register_control(
        &self,
        identity: TlsIdentity,
        hello: ControlMessage,
    ) -> Result<ControlRegistration, RelayError> {
        let (response, receiver) = oneshot::channel();
        self.tx
            .send(Command::RegisterControl {
                identity,
                hello,
                response,
            })
            .await
            .map_err(|_| RelayError::Shutdown)?;
        receiver.await.map_err(|_| RelayError::Shutdown)?
    }

    pub(crate) async fn attach_data(
        &self,
        identity: TlsIdentity,
        ticket: String,
    ) -> Result<DataRegistration, RelayError> {
        let (response, receiver) = oneshot::channel();
        self.tx
            .send(Command::AttachData {
                identity,
                ticket,
                response,
            })
            .await
            .map_err(|_| RelayError::Shutdown)?;
        receiver.await.map_err(|_| RelayError::Shutdown)?
    }

    pub(crate) async fn inbound_control(
        &self,
        key: SessionKey,
        message: ControlMessage,
    ) -> Result<(), RelayError> {
        self.tx
            .send(Command::InboundControl { key, message })
            .await
            .map_err(|_| RelayError::Shutdown)
    }

    pub(crate) async fn inbound_data(
        &self,
        carrier: CarrierKey,
        bytes: Vec<u8>,
    ) -> Result<(), RelayError> {
        self.tx
            .send(Command::InboundData { carrier, bytes })
            .await
            .map_err(|_| RelayError::Shutdown)
    }

    pub(crate) async fn disconnect_control(&self, key: SessionKey) {
        let _ = self.tx.send(Command::DisconnectControl(key)).await;
    }

    pub(crate) async fn disconnect_data(&self, carrier: CarrierKey) {
        let _ = self.tx.send(Command::DisconnectData(carrier)).await;
    }

    pub(crate) async fn open_echo_stream(
        &self,
        consumer: AuthenticatedConsumer,
        device_id: Uuid,
        service_id: Uuid,
        grant: GrantSnapshot,
        consumer_expires_at: chrono::DateTime<Utc>,
    ) -> Result<ConsumerStreamRegistration, RelayError> {
        let (response, receiver) = oneshot::channel();
        self.tx
            .send(Command::OpenEchoStream {
                consumer,
                device_id,
                service_id,
                grant,
                consumer_expires_at,
                response,
            })
            .await
            .map_err(|_| RelayError::Shutdown)?;
        receiver.await.map_err(|_| RelayError::Shutdown)?
    }

    pub(crate) async fn write_echo_stream(
        &self,
        key: SessionKey,
        stream_id: u64,
        operation_id: String,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, EchoOutcome> {
        let (response, receiver) = oneshot::channel();
        self.tx
            .send(Command::WriteEchoStream {
                key,
                stream_id,
                operation_id,
                body,
                response,
            })
            .await
            .map_err(|_| EchoOutcome::Failure {
                code: "REVERSE_CHANNEL_UNAVAILABLE",
                execution: "not_dispatched",
            })?;
        receiver.await.map_err(|_| EchoOutcome::Failure {
            code: "REVERSE_CHANNEL_INTERRUPTED",
            execution: "unknown",
        })?
    }

    pub(crate) async fn close_echo_stream(
        &self,
        key: SessionKey,
        stream_id: u64,
        operation_id: String,
    ) {
        let _ = self
            .tx
            .send(Command::CloseEchoStream {
                key,
                stream_id,
                operation_id,
            })
            .await;
    }

    /// Redacted diagnostics for an internal harness.  No route exposes this
    /// method; callers need a clone of the typed relay handle.
    pub async fn snapshot(&self) -> Result<RelaySnapshot, RelayError> {
        let (response, receiver) = oneshot::channel();
        self.tx
            .send(Command::Snapshot { response })
            .await
            .map_err(|_| RelayError::Shutdown)?;
        receiver.await.map_err(|_| RelayError::Shutdown)
    }

    pub(crate) async fn dispatch_echo(
        &self,
        consumer: AuthenticatedConsumer,
        device_id: Uuid,
        service_id: Uuid,
        grant: GrantSnapshot,
        body: Vec<u8>,
        consumer_expires_at: chrono::DateTime<Utc>,
    ) -> Result<EchoOutcome, RelayError> {
        let (response, receiver) = oneshot::channel();
        self.tx
            .send(Command::DispatchEcho {
                consumer,
                device_id,
                service_id,
                grant,
                body,
                consumer_expires_at,
                response,
            })
            .await
            .map_err(|_| RelayError::Shutdown)?;
        receiver.await.map_err(|_| RelayError::Shutdown)
    }

    pub async fn shutdown(&self) -> Result<(), RelayError> {
        let (response, receiver) = oneshot::channel();
        self.tx
            .send(Command::Shutdown(response))
            .await
            .map_err(|_| RelayError::Shutdown)?;
        receiver.await.map_err(|_| RelayError::Shutdown)
    }
}

struct RelayActor {
    options: RelayOptions,
    catalog: SharedCatalog,
    command_tx: mpsc::Sender<Command>,
    rx: mpsc::Receiver<Command>,
    sessions: HashMap<Uuid, DeviceSession>,
    registering: HashSet<Uuid>,
    tickets: HashMap<String, Ticket>,
    cleanup_tasks: Vec<JoinHandle<()>>,
    shutting_down: bool,
}

impl RelayActor {
    async fn run(mut self) {
        while let Some(command) = self.rx.recv().await {
            let shutdown = matches!(command, Command::Shutdown(_));
            self.handle(command).await;
            if shutdown || self.shutting_down {
                break;
            }
        }
        self.close_all().await;
    }

    async fn handle(&mut self, command: Command) {
        match command {
            Command::RegisterControl {
                identity,
                hello,
                response,
            } => {
                self.begin_register_control(identity, hello, response);
            }
            Command::RegisterResolved {
                device_id,
                identity,
                hello,
                response,
                result,
            } => {
                self.finish_register_control(device_id, identity, hello, response, result);
            }
            Command::AttachData {
                identity,
                ticket,
                response,
            } => {
                self.begin_attach_data(identity, ticket, response);
            }
            Command::AttachResolved {
                identity,
                ticket,
                response,
                result,
            } => {
                self.finish_attach_data(identity, ticket, response, result);
            }
            Command::InboundControl { key, message } => self.inbound_control(key, message).await,
            Command::InboundData { carrier, bytes } => self.inbound_data(carrier, bytes).await,
            Command::DisconnectControl(key) => self.disconnect_control(key).await,
            Command::DisconnectData(carrier) => self.disconnect_data(carrier).await,
            Command::DispatchEcho {
                consumer,
                device_id,
                service_id,
                grant,
                consumer_expires_at,
                body,
                response,
            } => {
                self.dispatch_echo(DispatchRequest {
                    consumer,
                    device_id,
                    service_id,
                    grant,
                    body,
                    consumer_expires_at,
                    response,
                })
                .await;
            }
            Command::Tick => self.tick().await,
            Command::ChallengeAuthorized {
                key,
                challenge,
                result,
            } => {
                self.finish_device_challenge(key, challenge, result);
            }
            Command::MaintenanceResult {
                key,
                renewed,
                identity,
            } => {
                self.finish_maintenance(key, renewed, identity).await;
            }
            Command::OpenEchoStream {
                consumer,
                device_id,
                service_id,
                grant,
                consumer_expires_at,
                response,
            } => {
                self.open_echo_stream(
                    consumer,
                    device_id,
                    service_id,
                    grant,
                    consumer_expires_at,
                    response,
                );
            }
            Command::WriteEchoStream {
                key,
                stream_id,
                operation_id,
                body,
                response,
            } => {
                self.write_echo_stream(key, stream_id, operation_id, body, response);
            }
            Command::CloseEchoStream {
                key,
                stream_id,
                operation_id,
            } => {
                self.close_echo_stream(&key, stream_id, &operation_id);
            }
            Command::Snapshot { response } => {
                let _ = response.send(self.snapshot());
            }
            Command::Shutdown(response) => {
                self.shutting_down = true;
                let _ = response.send(());
            }
        }
    }

    fn begin_register_control(
        &mut self,
        identity: TlsIdentity,
        hello: ControlMessage,
        response: oneshot::Sender<Result<ControlRegistration, RelayError>>,
    ) {
        if !matches!(identity.role(), CertificateRole::Device { .. }) {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        }
        let device_id = match identity.role_id().parse::<Uuid>() {
            Ok(device_id) => device_id,
            Err(_) => {
                let _ = response.send(Err(RelayError::Unauthorized));
                return;
            }
        };
        let hello = match hello {
            ControlMessage::Hello(hello) => hello,
            _ => {
                let _ = response.send(Err(RelayError::Protocol(
                    "first control message must be HELLO".into(),
                )));
                return;
            }
        };
        if let Err(error) = validate_hello(&hello, device_id) {
            let _ = response.send(Err(error));
            return;
        }
        if self.sessions.contains_key(&device_id) || !self.registering.insert(device_id) {
            let _ = response.send(Err(RelayError::Conflict(
                "device already has an active control connection",
            )));
            return;
        }
        if self.sessions.len().saturating_add(self.registering.len())
            > self.options.limits.max_devices
        {
            self.registering.remove(&device_id);
            let _ = response.send(Err(RelayError::Overloaded(
                "relay device capacity is exhausted",
            )));
            return;
        }

        let catalog = self.catalog.clone();
        let command_tx = self.command_tx.clone();
        let options = self.options.clone();
        let spki = identity.spki_sha256().to_hex();
        tokio::spawn(async move {
            let result = async {
                let at = Utc::now();
                let device_identity = catalog
                    .resolve_device(&spki, at)
                    .await
                    .map_err(|error| RelayError::Catalog(error.to_string()))?
                    .filter(|record| {
                        record.device_id == device_id
                            && record.spki_fingerprint == spki
                            && record.device_active
                            && record.credential_active
                            && record.credential_revoked_at.is_none()
                            && record.expires_at > at
                    })
                    .ok_or(RelayError::Unauthorized)?;
                let session_id = wire::random_token();
                let lease_expires_at = at
                    + ChronoDuration::from_std(options.owner_lease)
                        .map_err(|_| RelayError::Config("owner lease is invalid".into()))?;
                let claim = catalog
                    .claim_owner(&OwnerClaimRequest {
                        deployment_incarnation: options.deployment_incarnation.clone(),
                        tenant_id: device_identity.tenant_id,
                        device_id,
                        node_id: options.node_id.clone(),
                        boot_id: options.boot_id.clone(),
                        session_id,
                        lease_expires_at,
                    })
                    .await
                    .map_err(|error| RelayError::Catalog(error.to_string()))?;
                Ok((device_identity, claim))
            }
            .await;
            let _ = command_tx
                .send(Command::RegisterResolved {
                    device_id,
                    identity,
                    hello,
                    response,
                    result,
                })
                .await;
        });
    }

    fn finish_register_control(
        &mut self,
        device_id: Uuid,
        identity: TlsIdentity,
        hello: Hello,
        response: oneshot::Sender<Result<ControlRegistration, RelayError>>,
        result: Result<(DeviceIdentity, tunnel_catalog::OwnerClaim), RelayError>,
    ) {
        self.registering.remove(&device_id);
        let (device_identity, claim) = match result {
            Ok(value) => value,
            Err(error) => {
                let _ = response.send(Err(error));
                return;
            }
        };
        if response.is_closed() {
            let token = claim.token;
            let catalog = self.catalog.clone();
            self.cleanup_tasks.push(tokio::spawn(async move {
                let _ = catalog.release_owner(&token).await;
            }));
            return;
        }
        if self.sessions.contains_key(&device_id) {
            let token = claim.token;
            let catalog = self.catalog.clone();
            self.cleanup_tasks.push(tokio::spawn(async move {
                let _ = catalog.release_owner(&token).await;
            }));
            let _ = response.send(Err(RelayError::Conflict(
                "device already has an active control connection",
            )));
            return;
        }
        let user_sessions = self
            .sessions
            .values()
            .filter(|session| {
                session.identity.tenant_id == device_identity.tenant_id
                    && session.identity.owner_user_id == device_identity.owner_user_id
            })
            .count();
        if user_sessions >= self.options.limits.max_devices_per_user {
            let token = claim.token;
            let catalog = self.catalog.clone();
            self.cleanup_tasks.push(tokio::spawn(async move {
                let _ = catalog.release_owner(&token).await;
            }));
            let _ = response.send(Err(RelayError::Overloaded(
                "per-user device capacity is exhausted",
            )));
            return;
        }
        let session_id = claim.token.session_id.clone();
        let key = SessionKey {
            device_id,
            session_id: session_id.clone(),
            epoch: claim.token.epoch,
        };
        let (control_tx, rx) = mpsc::channel(self.options.limits.max_queue_messages);
        let queue_budget = QueueBudget::new(self.options.limits.max_queue_bytes);
        let ticket = wire::random_token();
        let welcome_message_id = wire::random_token();
        let data_connection_id = wire::random_token();
        let profile = if hello
            .features
            .iter()
            .any(|feature| feature == wire::ORDERED_ROTATION_FEATURE)
        {
            RuntimeProfile::M2
        } else {
            RuntimeProfile::M1
        };
        let relay_interval_ms = self.options.rotation.interval_seconds.saturating_mul(1_000);
        let relay_handshake_ms = self
            .options
            .rotation
            .handshake_timeout_seconds
            .saturating_mul(1_000);
        let relay_overlap_ms = self.options.rotation.overlap_seconds.saturating_mul(1_000);
        let (rotation_interval_ms, handshake_timeout_ms, overlap_timeout_ms) =
            if profile.supports_rotation() {
                let requested = hello.rotation_policy.as_ref();
                (
                    requested
                        .map_or(relay_interval_ms, |policy| policy.interval_ms)
                        .min(relay_interval_ms),
                    requested
                        .map_or(relay_handshake_ms, |policy| policy.handshake_timeout_ms)
                        .min(relay_handshake_ms),
                    requested
                        .map_or(relay_overlap_ms, |policy| policy.overlap_timeout_ms)
                        .min(relay_overlap_ms),
                )
            } else {
                (relay_interval_ms, relay_handshake_ms, relay_overlap_ms)
            };
        let ticket_issued_at_wall = Utc::now();
        let ticket_expires_at_wall = ticket_issued_at_wall
            + ChronoDuration::from_std(wire::TICKET_TTL)
                .unwrap_or_else(|_| ChronoDuration::seconds(10));
        self.tickets.insert(
            ticket.clone(),
            Ticket {
                value: ticket.clone(),
                device_id,
                spki: identity.spki_sha256().to_hex(),
                session_id: session_id.clone(),
                epoch: claim.token.epoch,
                generation: 1,
                welcome_message_id: welcome_message_id.clone(),
                connection_id: data_connection_id.clone(),
                issued_at_wall: ticket_issued_at_wall,
                expires_at_wall: ticket_expires_at_wall,
                expires_at: Instant::now() + wire::TICKET_TTL,
                consuming: false,
                owner: claim.token.clone(),
                candidate: false,
                attachment_purpose: DataAttachmentPurpose::RotationCandidate,
            },
        );
        let welcome = match profile {
            RuntimeProfile::M1 => wire::welcome(
                &welcome_message_id,
                &hello.message_id,
                &session_id,
                claim.token.epoch,
                1,
                &data_connection_id,
                &ticket,
            ),
            RuntimeProfile::M2 => wire::welcome_m2(wire::WelcomeM2Params {
                message_id: &welcome_message_id,
                reply_to: &hello.message_id,
                session_id: &session_id,
                epoch: claim.token.epoch,
                generation: 1,
                connection_id: &data_connection_id,
                ticket: &ticket,
                owner: &claim.token,
                rotation_interval_ms,
                handshake_timeout_ms,
                overlap_timeout_ms,
            }),
        };
        let welcome = match wire::encode_control_message(&welcome) {
            Ok(value) => value,
            Err(error) => {
                let token = claim.token;
                let catalog = self.catalog.clone();
                self.cleanup_tasks.push(tokio::spawn(async move {
                    let _ = catalog.release_owner(&token).await;
                }));
                let _ = response.send(Err(RelayError::Protocol(error.to_string())));
                return;
            }
        };
        let trace_tenant_id = device_identity.tenant_id;
        let trace_epoch = claim.token.epoch;
        let rotation = if profile.supports_rotation() {
            let protocol_config = match runtime::protocol_rotation_config_ms(
                rotation_interval_ms,
                handshake_timeout_ms,
                overlap_timeout_ms,
            ) {
                Ok(config) => config,
                Err(error) => {
                    let token = claim.token;
                    let catalog = self.catalog.clone();
                    self.cleanup_tasks.push(tokio::spawn(async move {
                        let _ = catalog.release_owner(&token).await;
                    }));
                    let _ = response.send(Err(RelayError::Config(error.into())));
                    return;
                }
            };
            match RotationState::new(
                session_id.clone(),
                runtime::owner_id(&claim.token),
                claim.token.epoch,
                1,
                data_connection_id.clone(),
                protocol_config,
            ) {
                Ok(state) => Some(RotationRuntime {
                    state,
                    attempt: None,
                    attempt_deadline_ms: None,
                    snapshot_id: String::new(),
                    barrier_rx: None,
                    candidate: None,
                    old_connection_id: data_connection_id.clone(),
                    prepare_message_id: String::new(),
                    last_message_id: String::new(),
                    abort_message_id: None,
                    peer_message_id: String::new(),
                    quiesce_message_id: String::new(),
                    frozen_message_id: String::new(),
                    commit_message_id: String::new(),
                    retire_message_id: String::new(),
                    peer_frozen_message_id: None,
                    peer_drained_message_id: None,
                    peer_committed_message_id: None,
                    peer_retired_message_id: None,
                    peer_aborted_message_id: None,
                    pending_abort_ack: None,
                    tombstones: VecDeque::new(),
                    remote_fences: [None, None],
                    own_fence: None,
                    replayed_frames: 0,
                    journal: ControlJournal::new(
                        128,
                        self.options.limits.max_queue_bytes.min(4 * 1024 * 1024),
                        monotonic_millis(),
                        monotonic_millis().saturating_add(overlap_timeout_ms),
                    )
                    .expect("validated rotation journal bounds"),
                    recovery: None,
                }),
                Err(error) => {
                    let token = claim.token;
                    let catalog = self.catalog.clone();
                    self.cleanup_tasks.push(tokio::spawn(async move {
                        let _ = catalog.release_owner(&token).await;
                    }));
                    let _ = response.send(Err(RelayError::Config(error.to_string())));
                    return;
                }
            }
        } else {
            None
        };
        self.sessions.insert(
            device_id,
            DeviceSession {
                identity: device_identity,
                owner: claim.token,
                key: key.clone(),
                control_tx,
                data_tx: None,
                active_carrier: None,
                generation: 1,
                connection_id: data_connection_id.clone(),
                profile,
                next_stream_id: 1,
                pending: HashMap::new(),
                streams: HashMap::new(),
                rotation,
                last_rotation: Instant::now(),
                rotations_completed: 0,
                total_replayed_frames: 0,
                queued_bytes: 0,
                queue_budget: queue_budget.clone(),
                last_lease_renewal: Instant::now(),
                maintenance_in_flight: false,
                closed: false,
            },
        );
        tracing::info!(
            tenant_id = %trace_tenant_id,
            device_id = %device_id,
            session_id = %session_id,
            epoch = trace_epoch,
            phase = "session_admitted",
        );
        let _ = response.send(Ok(ControlRegistration {
            key,
            welcome,
            rx,
            queue_budget,
        }));
    }

    fn begin_attach_data(
        &mut self,
        identity: TlsIdentity,
        ticket_value: String,
        response: oneshot::Sender<Result<DataRegistration, RelayError>>,
    ) {
        if !matches!(identity.role(), CertificateRole::Device { .. }) {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        }
        let spki = identity.spki_sha256().to_hex();
        let now_wall = Utc::now();
        let Some(ticket) = self.tickets.get_mut(&ticket_value) else {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        };
        if ticket.value != ticket_value
            || ticket.expires_at <= Instant::now()
            || now_wall < ticket.issued_at_wall
            || now_wall >= ticket.expires_at_wall
            || ticket.spki != spki
            || ticket.consuming
        {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        }
        ticket.consuming = true;
        let ticket = ticket.clone();
        let catalog = self.catalog.clone();
        let command_tx = self.command_tx.clone();
        tokio::spawn(async move {
            let result = async {
                let device = catalog
                    .resolve_device(&spki, Utc::now())
                    .await
                    .map_err(|error| error.to_string())?;
                let Some(device) = device else {
                    return Ok((None, None));
                };
                let owner = catalog
                    .current_owner(device.tenant_id, ticket.device_id, Utc::now())
                    .await
                    .map_err(|error| error.to_string())?;
                Ok((Some(device), owner))
            }
            .await;
            let _ = command_tx
                .send(Command::AttachResolved {
                    identity,
                    ticket,
                    response,
                    result,
                })
                .await;
        });
    }

    fn finish_attach_data(
        &mut self,
        identity: TlsIdentity,
        ticket: Ticket,
        response: oneshot::Sender<Result<DataRegistration, RelayError>>,
        result: Result<(Option<DeviceIdentity>, Option<tunnel_catalog::OwnerClaim>), String>,
    ) {
        let now_wall = Utc::now();
        if !self.ticket_matches(&ticket) {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        }
        if ticket.expires_at <= Instant::now()
            || now_wall < ticket.issued_at_wall
            || now_wall >= ticket.expires_at_wall
        {
            self.remove_ticket_if_matches(&ticket);
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        }
        if response.is_closed() {
            self.remove_ticket_if_matches(&ticket);
            return;
        }
        let (identity_result, owner_result) = match result {
            Ok(value) => value,
            Err(_) => {
                self.remove_ticket_if_matches(&ticket);
                let _ = response.send(Err(RelayError::Unauthorized));
                return;
            }
        };
        let valid_identity = identity_result.filter(|record| {
            record.device_id == ticket.device_id
                && record.spki_fingerprint == ticket.spki
                && record.device_active
                && record.credential_active
                && record.credential_revoked_at.is_none()
                && record.expires_at > Utc::now()
        });
        let Some(device_identity) = valid_identity else {
            self.remove_ticket_if_matches(&ticket);
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        };
        let result =
            self.attach_data_verified(identity, ticket.clone(), device_identity, owner_result);
        let should_start_recovery = result.is_ok()
            && ticket.candidate
            && matches!(
                &ticket.attachment_purpose,
                DataAttachmentPurpose::Recovery { .. }
            );
        let should_quiesce = result.is_ok()
            && ticket.candidate
            && matches!(
                &ticket.attachment_purpose,
                DataAttachmentPurpose::RotationCandidate
            );
        if result.is_ok() {
            self.remove_ticket_if_matches(&ticket);
        } else if let Some(pending) = self.tickets.get_mut(&ticket.value) {
            pending.consuming = false;
        }
        if should_quiesce {
            let key = SessionKey {
                device_id: ticket.device_id,
                session_id: ticket.session_id.clone(),
                epoch: ticket.epoch,
            };
            self.begin_rotation_quiesce(&key);
        }
        if should_start_recovery {
            let key = SessionKey {
                device_id: ticket.device_id,
                session_id: ticket.session_id.clone(),
                epoch: ticket.epoch,
            };
            self.start_recovery_snapshots(&key);
        }
        let _ = response.send(result);
    }

    fn attach_data_verified(
        &mut self,
        identity: TlsIdentity,
        ticket: Ticket,
        current_identity: DeviceIdentity,
        current_owner: Option<tunnel_catalog::OwnerClaim>,
    ) -> Result<DataRegistration, RelayError> {
        let spki = identity.spki_sha256().to_hex();
        if current_identity.spki_fingerprint != spki {
            return Err(RelayError::Unauthorized);
        }
        let session = self
            .sessions
            .get_mut(&ticket.device_id)
            .ok_or(RelayError::Conflict("control connection is not active"))?;
        if session.key.session_id != ticket.session_id
            || session.key.epoch != ticket.epoch
            || (ticket.candidate && !session.profile.supports_rotation())
        {
            return Err(RelayError::Unauthorized);
        }
        if !ticket.candidate && session.data_tx.is_some() {
            return Err(RelayError::Conflict("data connection is already active"));
        }
        if session.identity.spki_fingerprint != spki {
            return Err(RelayError::Unauthorized);
        }
        if session.identity.device_version != current_identity.device_version {
            return Err(RelayError::Unauthorized);
        }
        if session.owner.epoch != current_identity.owner_epoch {
            return Err(RelayError::Unauthorized);
        }
        let now_wall = Utc::now();
        let Some(current_owner) = current_owner else {
            return Err(RelayError::Unauthorized);
        };
        if ticket.owner != session.owner
            || current_owner.token != session.owner
            || current_owner.lease_expires_at
                <= now_wall
                    + ChronoDuration::from_std(OWNER_LEASE_SAFETY_MARGIN)
                        .unwrap_or_else(|_| ChronoDuration::seconds(5))
        {
            return Err(RelayError::Unauthorized);
        }
        let (data_tx, rx) = mpsc::channel(self.options.limits.max_queue_messages);
        let carrier = CarrierKey {
            session: session.key.clone(),
            generation: ticket.generation,
            connection_id: ticket.connection_id.clone(),
        };
        let context = carrier.context();
        if ticket.candidate {
            let Some(rotation) = session.rotation.as_mut() else {
                return Err(RelayError::Conflict("rotation candidate is not expected"));
            };
            let Some(attempt) = rotation.attempt.as_ref() else {
                return Err(RelayError::Conflict("rotation candidate is not expected"));
            };
            if rotation.candidate.is_some()
                || attempt.new_generation != ticket.generation
                || attempt.new_connection_id != ticket.connection_id
            {
                return Err(RelayError::Unauthorized);
            }
            match &ticket.attachment_purpose {
                DataAttachmentPurpose::RotationCandidate => {
                    if rotation
                        .state
                        .candidate_ready(attempt, monotonic_millis())
                        .is_err()
                    {
                        return Err(RelayError::Conflict("rotation candidate deadline elapsed"));
                    }
                }
                DataAttachmentPurpose::Recovery {
                    episode_id,
                    attempt_no,
                    closure_digest,
                } => {
                    let Some(recovery) = rotation.recovery.as_ref() else {
                        return Err(RelayError::Conflict("recovery candidate is not expected"));
                    };
                    if recovery.episode_id != *episode_id
                        || recovery.attempt_no != *attempt_no
                        || recovery.closure_digest.as_deref() != Some(closure_digest.as_str())
                    {
                        return Err(RelayError::Unauthorized);
                    }
                    rotation
                        .state
                        .reserve_recovery_socket(monotonic_millis())
                        .map_err(|_| RelayError::Conflict("recovery candidate deadline elapsed"))?;
                }
            }
        }
        let ready = wire::encode_control_message(&wire::data_ready(
            &ticket.welcome_message_id,
            &session.key.session_id,
            session.key.epoch,
            ticket.generation,
            &ticket.connection_id,
        ))
        .map_err(|error| RelayError::Protocol(error.to_string()))?;
        queue_control(&session.control_tx, &session.queue_budget, ready)
            .map_err(|_| RelayError::Overloaded("control queue is full"))?;
        if ticket.candidate {
            let rotation = session
                .rotation
                .as_mut()
                .ok_or(RelayError::Conflict("rotation candidate is not expected"))?;
            rotation.candidate = Some(DataCarrier {
                context,
                tx: data_tx.clone(),
            });
            if matches!(
                &ticket.attachment_purpose,
                DataAttachmentPurpose::Recovery { .. }
            ) && let Some(recovery) = rotation.recovery.as_mut()
            {
                recovery.candidate_ready = true;
            }
        } else {
            if ticket.generation != session.generation {
                return Err(RelayError::Unauthorized);
            }
            session.active_carrier = Some(DataCarrier {
                context,
                tx: data_tx.clone(),
            });
            session.data_tx = Some(data_tx.clone());
        }
        tracing::info!(
            tenant_id = %session.identity.tenant_id,
            device_id = %ticket.device_id,
            session_id = %session.key.session_id,
            epoch = session.key.epoch,
            phase = "data_attached",
        );
        Ok(DataRegistration {
            carrier,
            rx,
            queue_budget: session.queue_budget.clone(),
        })
    }

    async fn dispatch_echo(&mut self, request: DispatchRequest) {
        let DispatchRequest {
            consumer,
            device_id,
            service_id,
            grant,
            body,
            consumer_expires_at,
            response,
        } = request;
        if response.is_closed() {
            return;
        }
        if body.len() > self.options.limits.max_body_bytes {
            let _ = response.send(EchoOutcome::Failure {
                code: "BODY_LIMIT",
                execution: "not_dispatched",
            });
            return;
        }
        if grant.tenant_id != consumer.tenant_id
            || grant.principal_id != consumer.principal_id
            || grant.device_id != device_id
            || grant.service_id != service_id
            || !grant.permissions.allows(crate::ECHO_OPERATION)
        {
            let _ = response.send(EchoOutcome::Failure {
                code: "FORBIDDEN",
                execution: "not_dispatched",
            });
            return;
        }
        let Some(session) = self.sessions.get_mut(&device_id) else {
            let _ = response.send(EchoOutcome::Failure {
                code: "DEVICE_OFFLINE",
                execution: "not_dispatched",
            });
            return;
        };
        if session.identity.tenant_id != consumer.tenant_id || session.data_tx.is_none() {
            let _ = response.send(EchoOutcome::Failure {
                code: "DEVICE_OFFLINE",
                execution: "not_dispatched",
            });
            return;
        }
        if session.pending.len() >= self.options.limits.max_pending_operations
            || session.pending.len() >= self.options.limits.max_streams_per_device
        {
            let _ = response.send(EchoOutcome::Failure {
                code: "RESOURCE_EXHAUSTED",
                execution: "not_dispatched",
            });
            return;
        }
        if session.queued_bytes.saturating_add(body.len()) > self.options.limits.max_queue_bytes {
            let _ = response.send(EchoOutcome::Failure {
                code: "RESOURCE_EXHAUSTED",
                execution: "not_dispatched",
            });
            return;
        }
        let sequence = 1;
        let Some(stream_id) = allocate_stream_id(&mut session.next_stream_id) else {
            let _ = response.send(EchoOutcome::Failure {
                code: "STREAM_LIMIT",
                execution: "not_dispatched",
            });
            return;
        };
        let operation_id = Uuid::new_v4().to_string();
        let queued_len = body.len();
        let digest = wire::permission_digest(&grant, &service_id.to_string());
        let service_name = service_id.to_string();
        let open = match wire::encode_control_message(&wire::open(wire::OpenRequest {
            session_id: &session.key.session_id,
            epoch: session.key.epoch,
            stream_id,
            operation_id: &operation_id,
            service_id: &service_name,
            body_len: body.len(),
            grant_revision: grant.revision,
            digest: &digest,
            operation: "echo",
        })) {
            Ok(value) => value,
            Err(_) => {
                let _ = response.send(EchoOutcome::Failure {
                    code: "CONTROL_LIMIT",
                    execution: "not_dispatched",
                });
                return;
            }
        };
        let open_bytes = open.len();
        if !session.queue_budget.reserve(queued_len) {
            let _ = response.send(EchoOutcome::Failure {
                code: "RESOURCE_EXHAUSTED",
                execution: "not_dispatched",
            });
            return;
        }
        if !session.queue_budget.reserve(open_bytes) {
            session.queue_budget.release(queued_len);
            let _ = response.send(EchoOutcome::Failure {
                code: "RESOURCE_EXHAUSTED",
                execution: "not_dispatched",
            });
            return;
        }
        session.pending.insert(
            stream_id,
            PendingEcho {
                operation_id: operation_id.clone(),
                send_sequence: sequence,
                response,
                response_sequence: 0,
                response_body: Vec::new(),
                challenge_id: None,
                consumer,
                service_id,
                grant,
                consumer_expires_at,
                body,
                created_at: Instant::now(),
                dispatched: false,
                authorization_in_flight: false,
            },
        );
        session.queued_bytes = session.queued_bytes.saturating_add(queued_len);
        if session
            .control_tx
            .try_send(ControlOutbound::Text(open))
            .is_err()
        {
            if let Some(pending) = session.pending.remove(&stream_id) {
                session.queue_budget.release(open_bytes);
                release_pending_budget(session, &pending);
                let _ = pending.response.send(EchoOutcome::Failure {
                    code: "CONTROL_UNAVAILABLE",
                    execution: "not_dispatched",
                });
            }
            return;
        }
        tracing::debug!(
            tenant_id = %session.identity.tenant_id,
            device_id = %device_id,
            session_id = %session.key.session_id,
            epoch = session.key.epoch,
            stream_id,
            operation_id = %operation_id,
            service_id = %service_id,
            bytes = queued_len,
            phase = "stream_admitted",
        );
    }

    /// Admit one long-lived M2 echo stream.  The HTTP layer has already
    /// authenticated the consumer and resolved the catalog grant; the actor
    /// repeats the tenant/device/service checks while it owns the live
    /// session and allocates the logical stream ID without wrapping.
    fn open_echo_stream(
        &mut self,
        consumer: AuthenticatedConsumer,
        device_id: Uuid,
        service_id: Uuid,
        grant: GrantSnapshot,
        consumer_expires_at: chrono::DateTime<Utc>,
        response: oneshot::Sender<Result<ConsumerStreamRegistration, RelayError>>,
    ) {
        if grant.valid_until <= Utc::now()
            || consumer_expires_at <= Utc::now()
            || grant.tenant_id != consumer.tenant_id
            || grant.principal_id != consumer.principal_id
            || grant.device_id != device_id
            || grant.service_id != service_id
            || !grant.permissions.allows(crate::ECHO_OPERATION)
        {
            let _ = response.send(Err(RelayError::Forbidden));
            return;
        }
        let Some(session) = self.sessions.get_mut(&device_id) else {
            let _ = response.send(Err(RelayError::NotFound));
            return;
        };
        if !session.profile.supports_rotation()
            || session.active_carrier.is_none()
            || session.identity.tenant_id != consumer.tenant_id
        {
            let _ = response.send(Err(RelayError::Conflict(
                "M2 ordered stream is not available",
            )));
            return;
        }
        if session.streams.len() >= self.options.limits.max_streams_per_device {
            let _ = response.send(Err(RelayError::Overloaded("stream limit reached")));
            return;
        }
        let Some(stream_id) = allocate_stream_id(&mut session.next_stream_id) else {
            let _ = response.send(Err(RelayError::Conflict("stream ID space exhausted")));
            return;
        };
        let operation_id = Uuid::new_v4().to_string();
        let service_name = service_id.to_string();
        let digest = wire::permission_digest(&grant, &service_name);
        let open = match wire::encode_control_message(&wire::open(wire::OpenRequest {
            session_id: &session.key.session_id,
            epoch: session.key.epoch,
            stream_id,
            operation_id: &operation_id,
            service_id: &service_name,
            body_len: 0,
            grant_revision: grant.revision,
            digest: &digest,
            operation: "echo_stream",
        })) {
            Ok(value) => value,
            Err(_) => {
                let _ = response.send(Err(RelayError::Protocol(
                    "stream OPEN exceeds the control bound".into(),
                )));
                return;
            }
        };
        if queue_control(&session.control_tx, &session.queue_budget, open).is_err() {
            let _ = response.send(Err(RelayError::Overloaded("control queue is full")));
            return;
        }
        let stream_slots = self.options.limits.max_streams_per_device.max(1);
        // Keep enough retained capacity for one legal response record even
        // when the fair-share value is smaller.  The actual aggregate budget
        // remains the session queue budget; this floor prevents a maximum
        // 64 KiB request plus canary from being rejected merely because it
        // spans two tunnel frames.
        let minimum_record_bytes = wire::MAX_BODY_BYTES
            .saturating_add(MAX_ECHO_RESPONSE_EXTRA_BYTES)
            .saturating_add(4);
        let per_stream_queue =
            (self.options.limits.max_queue_bytes / stream_slots).max(minimum_record_bytes);
        let per_stream_frames = (self.options.limits.max_queue_messages / stream_slots).max(1);
        let limits = tunnel_protocol::sequence::SequenceLimits::new(
            tunnel_protocol::sequence::DEFAULT_MAX_REPLAY_FRAMES,
            tunnel_protocol::sequence::DEFAULT_MAX_REPLAY_BYTES.min(per_stream_queue),
            tunnel_protocol::sequence::DEFAULT_MAX_REORDER_FRAMES.min(per_stream_frames),
            tunnel_protocol::sequence::DEFAULT_MAX_REORDER_BYTES.min(per_stream_queue),
        );
        let sequence = match StreamState::with_credits_and_limits(
            stream_id,
            wire::M2_INITIAL_WINDOW_BYTES as u64,
            wire::M2_INITIAL_WINDOW_BYTES as u64,
            limits,
        ) {
            Ok(sequence) => sequence,
            Err(error) => {
                let _ = response.send(Err(RelayError::Protocol(error.to_string())));
                return;
            }
        };
        let closed = CancellationToken::new();
        session.streams.insert(
            stream_id,
            M2Stream {
                operation_id: operation_id.clone(),
                service_id,
                consumer,
                grant,
                sequence,
                response_bytes: Vec::new(),
                response_records: VecDeque::new(),
                send_bytes: 0,
                receive_bytes: 0,
                authorized_until: None,
                consumer_expires_at,
                challenge_id: None,
                authorization_in_flight: false,
                pending_records: VecDeque::new(),
                pending_record_bytes: 0,
                budget_bytes: 0,
                terminal: false,
                closed: closed.clone(),
            },
        );
        let _ = response.send(Ok(ConsumerStreamRegistration {
            key: session.key.clone(),
            stream_id,
            operation_id,
            closed,
        }));
    }

    /// Queue one length-prefixed application record without waiting for a
    /// socket writer.  The shared queue budget charges every encoded frame;
    /// a dropped/retired candidate therefore cannot create a second budget.
    fn write_echo_stream(
        &mut self,
        key: SessionKey,
        stream_id: u64,
        operation_id: String,
        body: Vec<u8>,
        response: oneshot::Sender<Result<Vec<u8>, EchoOutcome>>,
    ) {
        if body.len() > wire::MAX_BODY_BYTES {
            let _ = response.send(Err(EchoOutcome::Failure {
                code: "BODY_LIMIT",
                execution: "not_dispatched",
            }));
            return;
        }
        let max_pending_operations = self.options.limits.max_pending_operations;
        let max_queue_bytes = self.options.limits.max_queue_bytes;
        let now = Utc::now();
        let Some(session) = self.session_mut(&key) else {
            let _ = response.send(Err(EchoOutcome::Failure {
                code: "DEVICE_OFFLINE",
                execution: "not_dispatched",
            }));
            return;
        };
        let data_tx = session.data_tx.clone();
        let recovering = session
            .rotation
            .as_ref()
            .is_some_and(|rotation| rotation.state.phase() == RotationPhase::Recovering);
        if data_tx.is_none() && !recovering {
            let _ = response.send(Err(EchoOutcome::Failure {
                code: "DEVICE_OFFLINE",
                execution: "not_dispatched",
            }));
            return;
        }
        let queue_budget = session.queue_budget.clone();
        let generation = session.generation;
        let Some(stream) = session.streams.get_mut(&stream_id) else {
            let _ = response.send(Err(EchoOutcome::Failure {
                code: "STREAM_NOT_FOUND",
                execution: "not_dispatched",
            }));
            return;
        };
        if stream.operation_id != operation_id || stream.terminal {
            let _ = response.send(Err(EchoOutcome::Failure {
                code: "STREAM_NOT_FOUND",
                execution: "not_dispatched",
            }));
            return;
        }
        if stream.grant.valid_until <= now || stream.consumer_expires_at <= now {
            let _ = response.send(Err(EchoOutcome::Failure {
                code: "AUTHORIZATION_EXPIRED",
                execution: "not_dispatched",
            }));
            return;
        }
        if stream
            .authorized_until
            .is_none_or(|deadline| deadline <= Instant::now())
        {
            if stream.pending_records.len() >= max_pending_operations
                || stream.pending_record_bytes.saturating_add(body.len()) > max_queue_bytes
                || !reserve_m2_bytes(&queue_budget, stream, body.len())
            {
                let _ = response.send(Err(EchoOutcome::Failure {
                    code: "RESOURCE_EXHAUSTED",
                    execution: "not_dispatched",
                }));
            } else {
                stream.pending_record_bytes =
                    stream.pending_record_bytes.saturating_add(body.len());
                stream.pending_records.push_back((body, response));
            }
            return;
        }
        let Some(data_tx) = data_tx else {
            if stream.pending_records.len() >= max_pending_operations
                || stream.pending_record_bytes.saturating_add(body.len()) > max_queue_bytes
                || !reserve_m2_bytes(&queue_budget, stream, body.len())
            {
                let _ = response.send(Err(EchoOutcome::Failure {
                    code: "RESOURCE_EXHAUSTED",
                    execution: "not_dispatched",
                }));
            } else {
                stream.pending_record_bytes =
                    stream.pending_record_bytes.saturating_add(body.len());
                stream.pending_records.push_back((body, response));
            }
            return;
        };
        let Some(record_len) = body.len().checked_add(4) else {
            let _ = response.send(Err(EchoOutcome::Failure {
                code: "BODY_LIMIT",
                execution: "not_dispatched",
            }));
            return;
        };
        let Ok(record_len_u32) = u32::try_from(body.len()) else {
            let _ = response.send(Err(EchoOutcome::Failure {
                code: "BODY_LIMIT",
                execution: "not_dispatched",
            }));
            return;
        };
        let mut record = Vec::with_capacity(record_len);
        record.extend_from_slice(&record_len_u32.to_be_bytes());
        record.extend_from_slice(&body);
        let mut response = Some(response);
        for chunk in record.chunks(tunnel_protocol::MAX_PAYLOAD_LEN) {
            let sequence = match stream
                .sequence
                .direction(Direction::RelayToConnector)
                .last_emitted()
                .checked_add(1)
            {
                Some(sequence) => sequence,
                None => {
                    let _ = response.take().expect("response available").send(Err(
                        EchoOutcome::Failure {
                            code: "STREAM_LIMIT",
                            execution: "not_dispatched",
                        },
                    ));
                    return;
                }
            };
            let ack = stream
                .sequence
                .direction(Direction::ConnectorToRelay)
                .recv_contiguous();
            let frame = Frame::data(
                key.epoch,
                generation,
                stream_id,
                sequence,
                ack,
                chunk.to_vec(),
            );
            if !reserve_m2_bytes(&queue_budget, stream, chunk.len()) {
                let _ =
                    response
                        .take()
                        .expect("response available")
                        .send(Err(EchoOutcome::Failure {
                            code: "RESOURCE_EXHAUSTED",
                            execution: "not_dispatched",
                        }));
                return;
            }
            if stream
                .sequence
                .send_frame(Direction::RelayToConnector, &frame)
                .is_err()
            {
                release_m2_bytes(&queue_budget, stream, chunk.len());
                let _ =
                    response
                        .take()
                        .expect("response available")
                        .send(Err(EchoOutcome::Failure {
                            code: "RESOURCE_EXHAUSTED",
                            execution: "not_dispatched",
                        }));
                return;
            }
            let Ok(encoded) = frame.encode() else {
                let _ =
                    response
                        .take()
                        .expect("response available")
                        .send(Err(EchoOutcome::Failure {
                            code: "FRAME_LIMIT",
                            execution: "not_dispatched",
                        }));
                return;
            };
            if queue_data(&data_tx, &queue_budget, encoded).is_err() {
                let _ =
                    response
                        .take()
                        .expect("response available")
                        .send(Err(EchoOutcome::Failure {
                            code: "REVERSE_CHANNEL_UNAVAILABLE",
                            execution: "unknown",
                        }));
                return;
            }
        }
        stream.send_bytes = stream.send_bytes.saturating_add(body.len());
        stream
            .response_records
            .push_back(response.take().expect("response available"));
    }

    fn close_echo_stream(&mut self, key: &SessionKey, stream_id: u64, operation_id: &str) {
        let Some(session) = self.session_mut(key) else {
            return;
        };
        let Some(data_tx) = session.data_tx.clone() else {
            return;
        };
        let queue_budget = session.queue_budget.clone();
        let generation = session.generation;
        let Some(stream) = session.streams.get_mut(&stream_id) else {
            return;
        };
        if stream.operation_id != operation_id || stream.terminal {
            return;
        }
        let Some(sequence) = stream
            .sequence
            .direction(Direction::RelayToConnector)
            .last_emitted()
            .checked_add(1)
        else {
            return;
        };
        let ack = stream
            .sequence
            .direction(Direction::ConnectorToRelay)
            .recv_contiguous();
        let frame = Frame::fin(key.epoch, generation, stream_id, sequence, ack);
        if stream
            .sequence
            .send_frame(Direction::RelayToConnector, &frame)
            .is_ok()
            && let Ok(encoded) = frame.encode()
            && queue_data(&data_tx, &queue_budget, encoded).is_ok()
        {
            stream.terminal = true;
            stream.closed.cancel();
        }
    }

    fn start_rotation(
        &mut self,
        key: &SessionKey,
        reply_to: Option<String>,
        reason: &str,
    ) -> Option<String> {
        let now_ms = monotonic_millis();
        let journal_bytes = self.options.limits.max_queue_bytes.min(4 * 1024 * 1024);
        let (attempt, ticket, prepare_message_id, encoded, owner, spki, control_tx, budget) = {
            let session = self.session_mut(key)?;
            if !session.profile.supports_rotation()
                || session.data_tx.is_none()
                || session.rotation.as_ref().is_some_and(|rotation| {
                    !matches!(rotation.state.phase(), RotationPhase::Active)
                })
            {
                return None;
            }
            let rotation = session.rotation.as_mut()?;
            if !Self::rotation_tombstone_capacity_available(rotation, now_ms) {
                return None;
            }
            let overlap_ms = rotation.state.config().overlap_timeout_ms;
            let new_generation = rotation.state.generation_high_watermark().checked_add(1)?;
            let rotation_id = wire::random_token();
            let new_connection_id = wire::random_token();
            let attempt = RotationAttemptIdentity::new(
                session.key.session_id.clone(),
                session.key.epoch,
                runtime::owner_id(&session.owner),
                rotation_id,
                session.generation,
                new_generation,
                session.connection_id.clone(),
                new_connection_id,
            );
            if rotation.state.prepare(attempt.clone(), now_ms).is_err() {
                return None;
            }
            // Journal retention belongs to this attempt, not to the session
            // admission instant.  A session may remain active past the
            // previous overlap deadline before its policy timer fires; using
            // that stale journal would silently drop the connector's phase
            // acknowledgements as expired.
            let journal_deadline = rotation.state.status().deadline_ms.unwrap_or(now_ms);
            let Ok(journal) = ControlJournal::new(128, journal_bytes, now_ms, journal_deadline)
            else {
                return None;
            };
            rotation.journal = journal;
            rotation.attempt_deadline_ms = Some(journal_deadline);
            let ticket = wire::random_token();
            let prepare = wire::rotate_prepare(
                reply_to.as_deref().unwrap_or(""),
                attempt.clone(),
                tunnel_protocol::rotation_control::DataAttachmentPurpose::RotationCandidate,
                &ticket,
                overlap_ms,
            );
            let Ok(encoded) = wire::encode_control_message(&prepare) else {
                return None;
            };
            let prepare_message_id = prepare.message_id().to_owned();
            (
                attempt,
                ticket,
                prepare_message_id,
                encoded,
                session.owner.clone(),
                session.identity.spki_fingerprint.clone(),
                session.control_tx.clone(),
                session.queue_budget.clone(),
            )
        };
        let issued_at_wall = Utc::now();
        let expires_at_wall = issued_at_wall
            + ChronoDuration::from_std(wire::TICKET_TTL)
                .unwrap_or_else(|_| ChronoDuration::seconds(10));
        self.tickets.insert(
            ticket.clone(),
            Ticket {
                value: ticket.clone(),
                device_id: key.device_id,
                spki,
                session_id: key.session_id.clone(),
                epoch: key.epoch,
                generation: attempt.new_generation,
                welcome_message_id: prepare_message_id.clone(),
                connection_id: attempt.new_connection_id.clone(),
                issued_at_wall,
                expires_at_wall,
                expires_at: Instant::now() + wire::TICKET_TTL,
                consuming: false,
                owner,
                candidate: true,
                attachment_purpose: DataAttachmentPurpose::RotationCandidate,
            },
        );
        let journal_response = encoded.clone();
        if queue_control(&control_tx, &budget, encoded).is_err() {
            self.tickets.remove(&ticket);
            return None;
        }
        let new_generation = attempt.new_generation;
        if let Some(session) = self.session_mut(key)
            && let Some(rotation) = session.rotation.as_mut()
        {
            rotation.attempt = Some(attempt);
            rotation.snapshot_id.clear();
            rotation.old_connection_id = session.connection_id.clone();
            rotation.prepare_message_id = prepare_message_id.clone();
            rotation.last_message_id = prepare_message_id.clone();
            rotation.abort_message_id = None;
            rotation.peer_message_id = reply_to.unwrap_or_default();
            rotation.pending_abort_ack = None;
            Self::clear_phase_message_ids(rotation);
            rotation.remote_fences = [None, None];
            rotation.own_fence = None;
        }
        tracing::info!(
            device_id = %key.device_id,
            session_id = %key.session_id,
            epoch = key.epoch,
            generation = new_generation,
            reason = %reason,
            phase = "rotation_prepare",
        );
        Some(journal_response)
    }

    /// Start the coordinator-owned retained recovery episode after a physical
    /// data carrier disappears.  The pure rotation state is advanced before a
    /// control message is queued: the old carrier is released with explicit
    /// closure evidence, the immutable roster is captured, and one fresh
    /// generation/connection identity is reserved for this episode.
    fn begin_recovery_after_loss(&mut self, key: &SessionKey, old_connection_id: &str) -> bool {
        let now_ms = monotonic_millis();
        let maximum_streams = self.options.limits.max_streams_per_device.min(128);
        let journal_bytes = self.options.limits.max_queue_bytes.min(4 * 1024 * 1024);
        let prepared = {
            let Some(session) = self.session_mut(key) else {
                return false;
            };
            if !session.profile.supports_rotation() || session.data_tx.is_some() {
                return false;
            }
            let Some(rotation) = session.rotation.as_mut() else {
                return false;
            };
            if !Self::rotation_tombstone_capacity_available(rotation, now_ms) {
                return false;
            }
            if rotation.state.phase() != RotationPhase::Active
                || rotation.state.active_connection_id() != old_connection_id
            {
                return false;
            }
            let mut stream_ids: Vec<u64> = session.streams.keys().copied().collect();
            stream_ids.sort_unstable();
            if stream_ids.len() > maximum_streams {
                return false;
            }
            let snapshot_id = wire::random_token();
            let roster = StreamRoster::new(snapshot_id.clone(), stream_ids);
            let Some(new_generation) = rotation.state.generation_high_watermark().checked_add(1)
            else {
                return false;
            };
            let attempt = RotationAttemptIdentity::new(
                session.key.session_id.clone(),
                session.key.epoch,
                runtime::owner_id(&session.owner),
                wire::random_token(),
                session.generation,
                new_generation,
                old_connection_id.to_owned(),
                wire::random_token(),
            );
            let Some(episode_deadline_ms) =
                now_ms.checked_add(rotation.state.config().recovery_timeout_ms)
            else {
                return false;
            };
            if rotation
                .state
                .transport_lost(&attempt, now_ms, RecoveryReason::OldTransportLost)
                .is_err()
                || rotation
                    .state
                    .close_for_recovery(
                        old_connection_id,
                        ClosureEvidence::closed(old_connection_id),
                        now_ms,
                    )
                    .is_err()
                || rotation
                    .state
                    .begin_recovery(
                        attempt.clone(),
                        roster.clone(),
                        now_ms,
                        RecoveryReason::OldTransportLost,
                        episode_deadline_ms,
                    )
                    .is_err()
            {
                return false;
            }
            let begin = wire::recovery_begin(
                "",
                attempt.clone(),
                &snapshot_id,
                1,
                roster.clone(),
                episode_deadline_ms.saturating_sub(now_ms),
            );
            let begin_id = begin.message_id().to_owned();
            let mut local_closed = RecoveryClosed {
                message_id: wire::random_token(),
                reply_to: begin_id.clone(),
                attempt: attempt.clone(),
                episode_id: snapshot_id.clone(),
                attempt_no: 1,
                closed_connection_ids: vec![old_connection_id.to_owned()],
                closure_digest: String::new(),
            };
            let Ok(local_digest) = local_closed.closure_digest_for(RecoverySide::Relay) else {
                return false;
            };
            local_closed.closure_digest = local_digest;
            let closed = wire::recovery_closed(
                &begin_id,
                attempt.clone(),
                &snapshot_id,
                1,
                local_closed.closed_connection_ids.clone(),
                &local_closed.closure_digest,
            );
            let Ok(begin) = wire::encode_control_message(&begin) else {
                return false;
            };
            let Ok(closed) = wire::encode_control_message(&closed) else {
                return false;
            };
            rotation.attempt = Some(attempt);
            rotation.snapshot_id = snapshot_id;
            rotation.prepare_message_id = begin_id.clone();
            rotation.last_message_id = begin_id;
            rotation.abort_message_id = None;
            rotation.peer_message_id.clear();
            rotation.pending_abort_ack = None;
            Self::clear_phase_message_ids(rotation);
            rotation.remote_fences = [None, None];
            rotation.own_fence = None;
            rotation.barrier_rx = None;
            rotation.candidate = None;
            rotation.recovery = Some(RecoveryRuntime {
                episode_id: local_closed.episode_id.clone(),
                attempt_no: 1,
                episode_deadline_ms,
                roster,
                expected_closed_connection_ids: local_closed.closed_connection_ids.clone(),
                local_closed: Some(local_closed.clone()),
                peer_closed: None,
                closure_digest: Some(local_closed.closure_digest.clone()),
                candidate_ready: false,
                resume_message_ids: [None, None],
                snapshot_reply_ids: [None, None],
                local_snapshots: [Vec::new(), Vec::new()],
                ready_snapshots: [Vec::new(), Vec::new()],
                ready_message_ids: [None, None],
                remote_snapshots: [HashMap::new(), HashMap::new()],
                ready_remote_snapshots: [HashMap::new(), HashMap::new()],
                remote_ready: [false, false],
                local_plans: HashMap::new(),
                ready_sent: [false, false],
                deferred_frames: VecDeque::new(),
                deferred_bytes: 0,
                activated: false,
            });
            // Recovery has its own immutable retention window.  This journal
            // cannot silently inherit an expired overlap deadline.
            if let Ok(journal) =
                ControlJournal::new(128, journal_bytes, now_ms, episode_deadline_ms)
            {
                rotation.journal = journal;
                rotation.attempt_deadline_ms = Some(episode_deadline_ms);
            }
            Some((
                session.control_tx.clone(),
                session.queue_budget.clone(),
                begin,
                closed,
            ))
        };
        let Some((control_tx, budget, begin, closed)) = prepared else {
            return false;
        };
        queue_control(&control_tx, &budget, begin).is_ok()
            && queue_control(&control_tx, &budget, closed).is_ok()
    }

    fn recovery_remaining_ms(rotation: &RotationRuntime, now_ms: u64) -> u64 {
        rotation
            .state
            .status()
            .deadline_ms
            .unwrap_or(now_ms)
            .saturating_sub(now_ms)
    }

    fn recovery_local_entries(
        session: &DeviceSession,
        roster: &StreamRoster,
        direction: Direction,
    ) -> Result<Vec<ResumeDirectionState>, RelayError> {
        let mut entries = Vec::with_capacity(roster.stream_ids.len());
        for stream_id in &roster.stream_ids {
            let Some(stream) = session.streams.get(stream_id) else {
                return Err(RelayError::Conflict(
                    "recovery roster stream is unavailable",
                ));
            };
            let snapshot = stream.sequence.snapshot();
            let entry = ResumeDirectionState::from_sequence_snapshot(
                *stream_id,
                snapshot.direction(direction),
            )
            .map_err(|error| RelayError::Protocol(error.to_string()))?;
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Consume one physical recovery candidate and start the next attempt
    /// under the same absolute episode deadline.  The old logical carrier ID
    /// remains the recovery anchor while every candidate gets a fresh ID and
    /// generation; the closure roster is carried forward before resources are
    /// removed from the actor.
    fn retry_recovery_after_candidate_loss(
        &mut self,
        key: &SessionKey,
        failed_connection_id: &str,
    ) -> bool {
        let now_ms = monotonic_millis();
        let journal_bytes = self.options.limits.max_queue_bytes.min(4 * 1024 * 1024);
        let prepared = {
            let Some(session) = self.session_mut(key) else {
                return false;
            };
            let Some(rotation) = session.rotation.as_mut() else {
                return false;
            };
            if !Self::rotation_tombstone_capacity_available(rotation, now_ms) {
                return false;
            }
            let Some(previous_attempt) = rotation.attempt.clone() else {
                return false;
            };
            let Some(previous_recovery) = rotation.recovery.as_ref() else {
                return false;
            };
            if rotation.state.phase() != RotationPhase::Recovering
                || !previous_recovery.candidate_ready
            {
                return false;
            }
            let previous_episode_id = previous_recovery.episode_id.clone();
            let previous_attempt_no = previous_recovery.attempt_no;
            let previous_deadline = previous_recovery.episode_deadline_ms;
            let roster = previous_recovery.roster.clone();
            let mut expected = previous_recovery.expected_closed_connection_ids.clone();
            if !expected.iter().any(|id| id == failed_connection_id) {
                expected.push(failed_connection_id.to_owned());
                expected.sort();
            }
            if expected.len() > 2
                || rotation
                    .state
                    .close_for_recovery(
                        failed_connection_id,
                        ClosureEvidence::closed(failed_connection_id),
                        now_ms,
                    )
                    .is_err()
            {
                return false;
            }
            let Some(new_generation) = rotation.state.generation_high_watermark().checked_add(1)
            else {
                return false;
            };
            let Some(attempt_no) = previous_attempt_no.checked_add(1) else {
                return false;
            };
            if attempt_no > 3 {
                return false;
            }
            let attempt = RotationAttemptIdentity::new(
                session.key.session_id.clone(),
                session.key.epoch,
                runtime::owner_id(&session.owner),
                wire::random_token(),
                previous_attempt.old_generation,
                new_generation,
                previous_attempt.old_connection_id.clone(),
                wire::random_token(),
            );
            if rotation
                .state
                .begin_recovery(
                    attempt.clone(),
                    roster.clone(),
                    now_ms,
                    RecoveryReason::CandidateTransportLost,
                    previous_deadline,
                )
                .is_err()
            {
                return false;
            }
            let begin = wire::recovery_begin(
                "",
                attempt.clone(),
                &previous_episode_id,
                attempt_no,
                roster.clone(),
                previous_deadline.saturating_sub(now_ms),
            );
            let begin_id = begin.message_id().to_owned();
            let mut local_closed = RecoveryClosed {
                message_id: wire::random_token(),
                reply_to: begin_id.clone(),
                attempt: attempt.clone(),
                episode_id: previous_episode_id.clone(),
                attempt_no,
                closed_connection_ids: expected.clone(),
                closure_digest: String::new(),
            };
            let Ok(digest) = local_closed.closure_digest_for(RecoverySide::Relay) else {
                return false;
            };
            local_closed.closure_digest = digest;
            let closed = wire::recovery_closed(
                &begin_id,
                attempt.clone(),
                &previous_episode_id,
                attempt_no,
                expected.clone(),
                &local_closed.closure_digest,
            );
            let Ok(begin) = wire::encode_control_message(&begin) else {
                return false;
            };
            let Ok(closed) = wire::encode_control_message(&closed) else {
                return false;
            };
            rotation.attempt = Some(attempt);
            rotation.candidate = None;
            rotation.prepare_message_id = begin_id.clone();
            rotation.last_message_id = begin_id;
            rotation.abort_message_id = None;
            rotation.peer_message_id.clear();
            rotation.pending_abort_ack = None;
            Self::clear_phase_message_ids(rotation);
            rotation.snapshot_id = roster.snapshot_id.clone();
            rotation.recovery = Some(RecoveryRuntime {
                episode_id: previous_episode_id,
                attempt_no,
                episode_deadline_ms: previous_deadline,
                roster,
                expected_closed_connection_ids: expected,
                local_closed: Some(local_closed),
                peer_closed: None,
                closure_digest: None,
                candidate_ready: false,
                resume_message_ids: [None, None],
                snapshot_reply_ids: [None, None],
                local_snapshots: [Vec::new(), Vec::new()],
                ready_snapshots: [Vec::new(), Vec::new()],
                ready_message_ids: [None, None],
                remote_snapshots: [HashMap::new(), HashMap::new()],
                ready_remote_snapshots: [HashMap::new(), HashMap::new()],
                remote_ready: [false, false],
                local_plans: HashMap::new(),
                ready_sent: [false, false],
                deferred_frames: VecDeque::new(),
                deferred_bytes: 0,
                activated: false,
            });
            if let Ok(journal) = ControlJournal::new(128, journal_bytes, now_ms, previous_deadline)
            {
                rotation.journal = journal;
                rotation.attempt_deadline_ms = Some(previous_deadline);
            }
            Some((
                session.control_tx.clone(),
                session.queue_budget.clone(),
                begin,
                closed,
            ))
        };
        let Some((control_tx, budget, begin, closed)) = prepared else {
            return false;
        };
        queue_control(&control_tx, &budget, begin).is_ok()
            && queue_control(&control_tx, &budget, closed).is_ok()
    }

    fn begin_rotation_quiesce(&mut self, key: &SessionKey) {
        let maximum_streams = self.options.limits.max_streams_per_device.min(128);
        let (attempt, roster, quiesce, active_tx) = {
            let Some(session) = self.session_for(key) else {
                return;
            };
            let Some(rotation) = session.rotation.as_ref() else {
                return;
            };
            let Some(attempt) = rotation.attempt.clone() else {
                return;
            };
            if !matches!(rotation.state.phase(), RotationPhase::Preparing) {
                return;
            }
            let mut stream_ids: Vec<u64> = session
                .pending
                .keys()
                .chain(session.streams.keys())
                .copied()
                .collect();
            stream_ids.sort_unstable();
            stream_ids.dedup();
            if stream_ids.len() > maximum_streams {
                return;
            }
            let snapshot_id = wire::random_token();
            let roster = StreamRoster::new(snapshot_id.clone(), stream_ids);
            let now_ms = monotonic_millis();
            let remaining_ms = rotation
                .state
                .status()
                .deadline_ms
                .unwrap_or(now_ms)
                .saturating_sub(now_ms);
            let quiesce = wire::rotate_quiesce(
                &rotation.prepare_message_id,
                attempt.clone(),
                roster.clone(),
                remaining_ms,
            );
            let Some(active) = session.active_carrier.as_ref() else {
                return;
            };
            (attempt, roster, quiesce, active.tx.clone())
        };
        let Ok(encoded) = wire::encode_control_message(&quiesce) else {
            return;
        };
        let Some(session) = self.session_mut(key) else {
            return;
        };
        let Some(rotation) = session.rotation.as_mut() else {
            return;
        };
        if rotation
            .state
            .quiesce(&attempt, roster, monotonic_millis())
            .is_err()
        {
            return;
        }
        if let ControlMessage::RotateQuiesce(ref value) = quiesce {
            rotation.snapshot_id = value.roster.snapshot_id.clone();
        }
        if queue_control(&session.control_tx, &session.queue_budget, encoded).is_err() {
            return;
        }
        rotation.last_message_id = quiesce.message_id().to_owned();
        rotation.quiesce_message_id = quiesce.message_id().to_owned();
        rotation.frozen_message_id.clear();
        rotation.commit_message_id.clear();
        rotation.retire_message_id.clear();
        let (barrier_tx, barrier_rx) = oneshot::channel();
        if active_tx
            .try_send(DataOutbound::Barrier(barrier_tx))
            .is_err()
        {
            return;
        }
        rotation.barrier_rx = Some(barrier_rx);
    }

    /// Poll the one in-flight writer barrier from the actor loop.  The
    /// channel is bounded to one receiver per rotation attempt, and the
    /// absolute attempt deadline is checked on every maintenance tick.
    fn poll_rotation_barrier(&mut self, key: &SessionKey) {
        let mut ready = false;
        let mut expired = false;
        {
            let Some(session) = self.session_mut(key) else {
                return;
            };
            let Some(rotation) = session.rotation.as_mut() else {
                return;
            };
            let Some(result) = rotation
                .barrier_rx
                .as_mut()
                .map(|receiver| receiver.try_recv())
            else {
                return;
            };
            match result {
                Ok(()) => {
                    ready = true;
                    rotation.barrier_rx = None;
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {
                    if rotation
                        .state
                        .status()
                        .deadline_ms
                        .is_some_and(|deadline| monotonic_millis() >= deadline)
                    {
                        expired = true;
                        rotation.barrier_rx = None;
                        let _ = rotation.state.tick(monotonic_millis());
                    }
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                    expired = true;
                    rotation.barrier_rx = None;
                    let _ = rotation.state.tick(monotonic_millis());
                }
            }
        }
        if !ready || expired {
            return;
        }
        let Some((attempt, carrier)) = self.session_for(key).and_then(|session| {
            let attempt = session
                .rotation
                .as_ref()
                .and_then(|rotation| rotation.attempt.clone())?;
            let active = session.active_carrier.as_ref()?;
            Some((
                attempt,
                CarrierKey {
                    session: key.clone(),
                    generation: active.context.generation,
                    connection_id: active.context.connection_id.clone(),
                },
            ))
        }) else {
            return;
        };
        self.finish_rotation_barrier(key, &attempt, &carrier);
    }

    fn finish_rotation_barrier(
        &mut self,
        key: &SessionKey,
        attempt: &RotationAttemptIdentity,
        carrier: &CarrierKey,
    ) {
        let Some(session) = self.session_for(key) else {
            return;
        };
        let Some(rotation) = session.rotation.as_ref() else {
            return;
        };
        if rotation.attempt.as_ref() != Some(attempt)
            || !session.active_carrier.as_ref().is_some_and(|active| {
                active.context.generation == carrier.generation
                    && active.context.connection_id == carrier.connection_id
            })
        {
            return;
        }
        let snapshot =
            Self::build_fence_snapshot(session, &rotation.snapshot_id, Direction::RelayToConnector);
        if let Err(error) = self.with_rotation_mut(key, |_session, rotation| {
            rotation.state.frozen(
                attempt,
                snapshot.clone(),
                Direction::RelayToConnector,
                monotonic_millis(),
            )?;
            rotation.own_fence = Some(snapshot.clone());
            Ok::<(), tunnel_protocol::rotation::RotationError>(())
        }) {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                phase = ?self
                    .session_for(key)
                    .and_then(|session| session.rotation.as_ref())
                    .map(|rotation| rotation.state.phase()),
                stage = "relay_frozen",
                error = %error,
            );
            return;
        }
        if let Err(error) = self.progress_rotation_drain(key) {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                phase = ?self
                    .session_for(key)
                    .and_then(|session| session.rotation.as_ref())
                    .map(|rotation| rotation.state.phase()),
                stage = "drain_progress_after_barrier",
                error = %error,
            );
        }
    }

    /// Re-evaluate the coordinator's drain proof and commit decision after
    /// every fence, barrier, ACK, and data-delivery event.  Control messages
    /// can cross the writer barrier, so a single FROZEN or DRAINED callback
    /// cannot be the only place that attempts the next phase.
    fn progress_rotation_drain(
        &mut self,
        key: &SessionKey,
    ) -> Result<(), tunnel_protocol::rotation::RotationError> {
        if self
            .session_for(key)
            .is_none_or(|session| session.rotation.is_none())
        {
            return Ok(());
        }
        self.with_rotation_mut(key, |session, rotation| {
            let status = rotation.state.status();
            if status.phase == RotationPhase::Draining && rotation.frozen_message_id.is_empty() {
                let source = rotation.peer_message_id.clone();
                if source.is_empty() {
                    return Err(tunnel_protocol::rotation::RotationError::MissingAttempt);
                }
                let attempt = rotation
                    .attempt
                    .clone()
                    .ok_or(tunnel_protocol::rotation::RotationError::MissingAttempt)?;
                let snapshot = rotation.own_fence.clone().ok_or(
                    tunnel_protocol::rotation::RotationError::MissingFrozenFence {
                        direction: Direction::RelayToConnector,
                    },
                )?;
                let message = wire::rotate_frozen(&source, attempt, snapshot);
                let encoded = wire::encode_control_message(&message)
                    .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
                Self::complete_rotation_reply(rotation, &message, &encoded)
                    .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
                queue_control(&session.control_tx, &session.queue_budget, encoded)
                    .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
                rotation.frozen_message_id = message.message_id().to_owned();
                rotation.last_message_id = message.message_id().to_owned();
            }
            if status.phase == RotationPhase::Draining
                && !status.drain_proofs[direction_index(Direction::ConnectorToRelay)]
            {
                let direction = Direction::ConnectorToRelay;
                let Some(fences) = rotation.remote_fences[direction_index(direction)].clone()
                else {
                    return Ok::<(), tunnel_protocol::rotation::RotationError>(());
                };
                let fence_digest = fences.digest().map_err(|_| {
                    tunnel_protocol::rotation::RotationError::FenceDigestUnavailable
                })?;
                let mut acks = Vec::with_capacity(fences.entries.len());
                for fence in &fences.entries {
                    let acknowledged = session
                        .streams
                        .get(&fence.stream_id)
                        .map(|stream| {
                            stream
                                .sequence
                                .direction(Direction::ConnectorToRelay)
                                .recv_contiguous()
                        })
                        .or_else(|| {
                            session
                                .pending
                                .get(&fence.stream_id)
                                .map(|pending| pending.response_sequence)
                        })
                        .unwrap_or_default();
                    acks.push(tunnel_protocol::rotation_control::StreamAck::new(
                        fence.stream_id,
                        acknowledged,
                    ));
                }
                let proof =
                    DrainProof::new(rotation.snapshot_id.clone(), fence_digest, direction, acks);
                let attempt = rotation
                    .attempt
                    .clone()
                    .ok_or(tunnel_protocol::rotation::RotationError::MissingAttempt)?;
                rotation
                    .state
                    .drained(&attempt, proof.clone(), monotonic_millis())?;
                let source = rotation.peer_message_id.clone();
                if source.is_empty() {
                    return Err(tunnel_protocol::rotation::RotationError::MissingAttempt);
                }
                let message = wire::rotate_drained(&source, attempt, proof);
                let encoded = wire::encode_control_message(&message)
                    .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
                Self::complete_rotation_reply(rotation, &message, &encoded)
                    .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
                queue_control(&session.control_tx, &session.queue_budget, encoded)
                    .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
                rotation.last_message_id = message.message_id().to_owned();
            }

            let status = rotation.state.status();
            if status.phase == RotationPhase::Committing && !status.commit_sent {
                let attempt = rotation
                    .attempt
                    .clone()
                    .ok_or(tunnel_protocol::rotation::RotationError::MissingAttempt)?;
                let drain_set = rotation.state.drain_set(&attempt)?;
                rotation.state.commit(&attempt, monotonic_millis())?;
                let refs = vec![
                    DrainProofRef {
                        snapshot_id: drain_set.relay_to_connector.snapshot_id.clone(),
                        fence_digest: drain_set.relay_to_connector.fence_digest.clone(),
                        direction: Direction::RelayToConnector,
                    },
                    DrainProofRef {
                        snapshot_id: drain_set.connector_to_relay.snapshot_id.clone(),
                        fence_digest: drain_set.connector_to_relay.fence_digest.clone(),
                        direction: Direction::ConnectorToRelay,
                    },
                ];
                let source = rotation.peer_message_id.clone();
                if source.is_empty() {
                    return Err(tunnel_protocol::rotation::RotationError::MissingAttempt);
                }
                let message = wire::rotate_commit(&source, attempt, &rotation.snapshot_id, refs);
                let encoded = wire::encode_control_message(&message)
                    .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
                Self::complete_rotation_reply(rotation, &message, &encoded)
                    .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
                queue_control(&session.control_tx, &session.queue_budget, encoded)
                    .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
                rotation.commit_message_id = message.message_id().to_owned();
                rotation.last_message_id = message.message_id().to_owned();
            }
            Ok::<(), tunnel_protocol::rotation::RotationError>(())
        })
    }

    fn build_fence_snapshot(
        session: &DeviceSession,
        snapshot_id: &str,
        direction: Direction,
    ) -> FenceSnapshot {
        let mut entries = Vec::new();
        for (stream_id, pending) in &session.pending {
            if direction == Direction::RelayToConnector {
                entries.push(StreamFence::new(
                    *stream_id,
                    direction,
                    pending.send_sequence,
                ));
            } else {
                entries.push(StreamFence::new(
                    *stream_id,
                    direction,
                    pending.response_sequence,
                ));
            }
        }
        for (stream_id, stream) in &session.streams {
            let last = stream.sequence.direction(direction).last_emitted();
            entries.push(StreamFence::new(*stream_id, direction, last));
        }
        entries.sort_by_key(|entry| entry.stream_id);
        entries.dedup_by_key(|entry| entry.stream_id);
        FenceSnapshot::new(snapshot_id, entries)
    }

    fn observe_rotation_message(
        &mut self,
        key: &SessionKey,
        message: &ControlMessage,
    ) -> RotationJournalDecision {
        let Some(session) = self.session_mut(key) else {
            return RotationJournalDecision::Error(JournalError::MissingMessage);
        };
        let Some(rotation) = session.rotation.as_mut() else {
            return RotationJournalDecision::Error(JournalError::MissingMessage);
        };
        Self::observe_rotation_journal(rotation, message, monotonic_millis())
    }

    fn observe_rotation_journal(
        rotation: &mut RotationRuntime,
        message: &ControlMessage,
        now: u64,
    ) -> RotationJournalDecision {
        let Ok(canonical) = wire::encode_control_message(message) else {
            return RotationJournalDecision::Error(JournalError::OversizedMessage);
        };
        Self::prune_rotation_tombstones(rotation, now);
        let journal = if let Some(attempt) = Self::message_attempt(message) {
            if rotation.attempt.as_ref() == Some(attempt) {
                &mut rotation.journal
            } else if let Some(tombstone) = rotation
                .tombstones
                .iter_mut()
                .find(|tombstone| tombstone.attempt == *attempt)
            {
                &mut tombstone.journal
            } else {
                return RotationJournalDecision::Error(JournalError::MissingMessage);
            }
        } else {
            &mut rotation.journal
        };
        match journal.observe(message.idempotency_key(), canonical.as_bytes(), now) {
            Ok(JournalObservation::New) => RotationJournalDecision::New,
            Ok(JournalObservation::PendingDuplicate) => RotationJournalDecision::PendingDuplicate,
            Ok(JournalObservation::CompletedDuplicate) => {
                match journal.responses(message.idempotency_key(), now) {
                    Ok(Some(responses)) => RotationJournalDecision::CompletedDuplicate(
                        responses
                            .into_iter()
                            .map(|response| response.to_vec())
                            .collect(),
                    ),
                    Ok(None) => RotationJournalDecision::PendingDuplicate,
                    Err(error) => RotationJournalDecision::Error(error),
                }
            }
            Err(error) => RotationJournalDecision::Error(error),
        }
    }

    /// Cache the exact encoded reply for an inbound journaled message.  Some
    /// rotation replies reference an owner-generated message rather than an
    /// inbound request; `MissingMessage` is therefore intentionally benign.
    /// Every other journal failure remains visible to the caller so a reply
    /// cannot silently lose its idempotency record.
    fn complete_rotation_reply(
        rotation: &mut RotationRuntime,
        response: &ControlMessage,
        encoded: &str,
    ) -> Result<(), JournalError> {
        let Some(reply_to) = response.reply_to().filter(|value| !value.is_empty()) else {
            return Ok(());
        };
        match rotation.journal.append_response(
            reply_to,
            response.message_id(),
            encoded.as_bytes(),
            monotonic_millis(),
        ) {
            Ok(()) | Err(JournalError::MissingMessage) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn complete_rotation_entry(
        rotation: &mut RotationRuntime,
        message_id: &str,
        response: &[u8],
    ) -> Result<(), JournalError> {
        match rotation
            .journal
            .complete(message_id, response, monotonic_millis())
        {
            Ok(()) | Err(JournalError::MissingMessage) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn record_rotation_request_response(
        &mut self,
        key: &SessionKey,
        request: &ControlMessage,
        response: &str,
    ) -> Result<(), JournalError> {
        let canonical =
            wire::encode_control_message(request).map_err(|_| JournalError::OversizedMessage)?;
        let Some(session) = self.session_mut(key) else {
            return Err(JournalError::MissingMessage);
        };
        let Some(rotation) = session.rotation.as_mut() else {
            return Err(JournalError::MissingMessage);
        };
        let now = monotonic_millis();
        match rotation
            .journal
            .observe(request.idempotency_key(), canonical.as_bytes(), now)?
        {
            JournalObservation::New => {}
            JournalObservation::PendingDuplicate | JournalObservation::CompletedDuplicate => {
                return Err(JournalError::ConflictingMessage);
            }
        }
        rotation
            .journal
            .complete(request.idempotency_key(), response.as_bytes(), now)
    }

    fn attempt_matches(rotation: &RotationRuntime, attempt: &RotationAttemptIdentity) -> bool {
        rotation.attempt.as_ref() == Some(attempt)
    }

    fn clear_phase_message_ids(rotation: &mut RotationRuntime) {
        rotation.quiesce_message_id.clear();
        rotation.frozen_message_id.clear();
        rotation.commit_message_id.clear();
        rotation.retire_message_id.clear();
        rotation.peer_frozen_message_id = None;
        rotation.peer_drained_message_id = None;
        rotation.peer_committed_message_id = None;
        rotation.peer_retired_message_id = None;
        rotation.peer_aborted_message_id = None;
    }

    fn peer_message_id_is_acceptable(pinned: Option<&str>, incoming: &str) -> bool {
        !incoming.is_empty() && pinned.is_none_or(|existing| existing == incoming)
    }

    fn pin_peer_message_id(pinned: &mut Option<String>, incoming: &str) -> bool {
        if !Self::peer_message_id_is_acceptable(pinned.as_deref(), incoming) {
            return false;
        }
        if pinned.is_none() {
            *pinned = Some(incoming.to_owned());
        }
        true
    }

    fn placeholder_journal() -> ControlJournal {
        ControlJournal::new(128, 4 * 1024 * 1024, 0, u64::MAX)
            .expect("bounded placeholder journal limits")
    }

    fn prune_rotation_tombstones(rotation: &mut RotationRuntime, now_ms: u64) {
        rotation
            .tombstones
            .retain(|tombstone| tombstone.deadline_ms > now_ms);
    }

    fn rotation_tombstone_capacity_available(rotation: &mut RotationRuntime, now_ms: u64) -> bool {
        Self::prune_rotation_tombstones(rotation, now_ms);
        rotation.tombstones.len() < MAX_ROTATION_TOMBSTONES
    }

    fn retain_rotation_tombstone(rotation: &mut RotationRuntime) -> bool {
        let Some(attempt) = rotation.attempt.clone() else {
            return false;
        };
        let Some(deadline_ms) = rotation.attempt_deadline_ms else {
            return false;
        };
        if rotation.tombstones.len() >= MAX_ROTATION_TOMBSTONES {
            // The caller must reject the next attempt before allocating a new
            // generation.  Evicting a live tombstone would make an old
            // message indistinguishable from a fresh attempt and permit
            // duplicate side effects after the retention window is full.
            return false;
        };
        let journal = std::mem::replace(&mut rotation.journal, Self::placeholder_journal());
        rotation.tombstones.push_back(RotationTombstone {
            attempt,
            deadline_ms,
            journal,
        });
        true
    }

    fn message_attempt(message: &ControlMessage) -> Option<&RotationAttemptIdentity> {
        match message {
            ControlMessage::RotatePrepare(value) => Some(&value.attempt),
            ControlMessage::RotateQuiesce(value) => Some(&value.attempt),
            ControlMessage::RotateFrozen(value) => Some(&value.attempt),
            ControlMessage::RotateDrained(value) => Some(&value.attempt),
            ControlMessage::RotateCommit(value) => Some(&value.attempt),
            ControlMessage::RotateCommitted(value) => Some(&value.attempt),
            ControlMessage::RotateRetire(value) => Some(&value.attempt),
            ControlMessage::RotateRetired(value) => Some(&value.attempt),
            ControlMessage::RotateComplete(value) => Some(&value.attempt),
            ControlMessage::RotateAbort(value) => Some(&value.attempt),
            ControlMessage::RotateAborted(value) => Some(&value.attempt),
            ControlMessage::RecoveryBegin(value) => Some(&value.attempt),
            ControlMessage::RecoveryClosed(value) => Some(&value.attempt),
            ControlMessage::Resume(value) => Some(&value.attempt),
            ControlMessage::Resumed(value) => Some(&value.attempt),
            _ => None,
        }
    }

    fn pending_abort_ack_if_active(
        phase: RotationPhase,
        pending: &Option<tunnel_protocol::rotation_control::RotateAborted>,
    ) -> Option<tunnel_protocol::rotation_control::RotateAborted> {
        (phase == RotationPhase::Active)
            .then(|| pending.clone())
            .flatten()
    }

    async fn handle_rotate_frozen(
        &mut self,
        key: &SessionKey,
        frozen: tunnel_protocol::rotation_control::RotateFrozen,
    ) {
        let Some(session) = self.session_for(key) else {
            return;
        };
        let Some(rotation) = session.rotation.as_ref() else {
            return;
        };
        if !Self::attempt_matches(rotation, &frozen.attempt)
            || frozen.attempt.session_id != key.session_id
            || frozen.attempt.epoch != key.epoch
            || frozen.attempt.owner_id != runtime::owner_id(&session.owner)
            || frozen.reply_to != rotation.quiesce_message_id
            || !Self::peer_message_id_is_acceptable(
                rotation.peer_frozen_message_id.as_deref(),
                &frozen.message_id,
            )
        {
            return;
        }
        // The relay receives the connector's fence, so the direction is
        // authenticated by endpoint role rather than inferred from entries.
        // Empty rosters therefore remain unambiguous and every non-empty
        // entry is checked by the pure state machine against this direction.
        let direction = Direction::ConnectorToRelay;
        let result = self.with_rotation_mut(key, |_session, rotation| {
            rotation.state.frozen(
                &frozen.attempt,
                frozen.snapshot.clone(),
                direction,
                monotonic_millis(),
            )?;
            if !Self::pin_peer_message_id(&mut rotation.peer_frozen_message_id, &frozen.message_id)
            {
                return Err(tunnel_protocol::rotation::RotationError::AttemptMismatch);
            }
            rotation.remote_fences[direction_index(direction)] = Some(frozen.snapshot.clone());
            rotation.peer_message_id = frozen.message_id.clone();
            Ok::<(), tunnel_protocol::rotation::RotationError>(())
        });
        if let Err(error) = result {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                phase = ?self
                    .session_for(key)
                    .and_then(|session| session.rotation.as_ref())
                    .map(|rotation| rotation.state.phase()),
                stage = "connector_frozen",
                error = %error,
            );
            return;
        }
        if let Err(error) = self.progress_rotation_drain(key) {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                phase = ?self
                    .session_for(key)
                    .and_then(|session| session.rotation.as_ref())
                    .map(|rotation| rotation.state.phase()),
                stage = "drain_progress_after_connector_frozen",
                error = %error,
            );
        }
    }

    async fn handle_rotate_drained(
        &mut self,
        key: &SessionKey,
        drained: tunnel_protocol::rotation_control::RotateDrained,
    ) {
        let Some(session) = self.session_for(key) else {
            return;
        };
        let Some(rotation) = session.rotation.as_ref() else {
            return;
        };
        if !Self::attempt_matches(rotation, &drained.attempt)
            || drained.reply_to != rotation.frozen_message_id
            || !Self::peer_message_id_is_acceptable(
                rotation.peer_drained_message_id.as_deref(),
                &drained.message_id,
            )
        {
            return;
        }
        let result = self.with_rotation_mut(key, |_session, rotation| {
            rotation
                .state
                .drained(&drained.attempt, drained.proof.clone(), monotonic_millis())?;
            if !Self::pin_peer_message_id(
                &mut rotation.peer_drained_message_id,
                &drained.message_id,
            ) {
                return Err(tunnel_protocol::rotation::RotationError::AttemptMismatch);
            }
            // The coordinator's COMMIT must reply to the connector's proof
            // when that proof is the event that completes both directions.
            rotation.peer_message_id = drained.message_id.clone();
            Ok::<(), tunnel_protocol::rotation::RotationError>(())
        });
        if let Err(error) = result {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                phase = ?self
                    .session_for(key)
                    .and_then(|session| session.rotation.as_ref())
                    .map(|rotation| rotation.state.phase()),
                stage = "connector_drained",
                error = %error,
            );
            return;
        }
        if let Err(error) = self.progress_rotation_drain(key) {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                phase = ?self
                    .session_for(key)
                    .and_then(|session| session.rotation.as_ref())
                    .map(|rotation| rotation.state.phase()),
                stage = "drain_progress_after_connector_drained",
                error = %error,
            );
        }
    }

    async fn handle_rotate_committed(
        &mut self,
        key: &SessionKey,
        committed: tunnel_protocol::rotation_control::RotateCommitted,
    ) {
        let Some(session) = self.session_for(key) else {
            return;
        };
        let Some(rotation) = session.rotation.as_ref() else {
            return;
        };
        if !Self::attempt_matches(rotation, &committed.attempt)
            || committed.reply_to != rotation.commit_message_id
            || !Self::peer_message_id_is_acceptable(
                rotation.peer_committed_message_id.as_deref(),
                &committed.message_id,
            )
        {
            return;
        }
        let _ = self.with_rotation_mut(key, |session, rotation| {
            if !Self::peer_message_id_is_acceptable(
                rotation.peer_committed_message_id.as_deref(),
                &committed.message_id,
            ) {
                return Err(tunnel_protocol::rotation::RotationError::AttemptMismatch);
            }
            rotation
                .state
                .committed(&committed.attempt, monotonic_millis())?;
            if !Self::pin_peer_message_id(
                &mut rotation.peer_committed_message_id,
                &committed.message_id,
            ) {
                return Err(tunnel_protocol::rotation::RotationError::AttemptMismatch);
            }
            let Some(candidate) = rotation.candidate.take() else {
                return Err(tunnel_protocol::rotation::RotationError::CandidateNotReady);
            };
            let old = session.active_carrier.take();
            session.active_carrier = Some(candidate);
            session.data_tx = session
                .active_carrier
                .as_ref()
                .map(|carrier| carrier.tx.clone());
            session.generation = committed.attempt.new_generation;
            session.connection_id = committed.attempt.new_connection_id.clone();
            if let Some(old) = old {
                let _ = old.tx.try_send(DataOutbound::Close);
            }
            rotation
                .state
                .retire(&committed.attempt, monotonic_millis())?;
            let message = wire::rotate_retire(
                &committed.message_id,
                committed.attempt.clone(),
                &rotation.snapshot_id,
            );
            let encoded = wire::encode_control_message(&message)
                .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
            Self::complete_rotation_reply(rotation, &message, &encoded)
                .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
            queue_control(&session.control_tx, &session.queue_budget, encoded)
                .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
            rotation.retire_message_id = message.message_id().to_owned();
            rotation.last_message_id = message.message_id().to_owned();
            Ok::<(), tunnel_protocol::rotation::RotationError>(())
        });
    }

    async fn handle_rotate_retired(
        &mut self,
        key: &SessionKey,
        retired: tunnel_protocol::rotation_control::RotateRetired,
    ) {
        let Some(session) = self.session_for(key) else {
            return;
        };
        let Some(rotation) = session.rotation.as_ref() else {
            return;
        };
        if !Self::attempt_matches(rotation, &retired.attempt)
            || retired.reply_to != rotation.retire_message_id
            || !Self::peer_message_id_is_acceptable(
                rotation.peer_retired_message_id.as_deref(),
                &retired.message_id,
            )
        {
            return;
        }
        let _ = self.with_rotation_mut(key, |_session, rotation| {
            if !Self::peer_message_id_is_acceptable(
                rotation.peer_retired_message_id.as_deref(),
                &retired.message_id,
            ) {
                return Err(tunnel_protocol::rotation::RotationError::AttemptMismatch);
            }
            rotation.state.retired(
                &retired.attempt,
                tunnel_protocol::rotation::RotationSide::Connector,
                tunnel_protocol::rotation::ClosureEvidence::closed(
                    retired.closed_connection_id.clone(),
                ),
                monotonic_millis(),
            )?;
            if !Self::pin_peer_message_id(
                &mut rotation.peer_retired_message_id,
                &retired.message_id,
            ) {
                return Err(tunnel_protocol::rotation::RotationError::AttemptMismatch);
            }
            // The connector's RETIRED is only one half of physical closure.
            // Keep the attempt and immutable roster until the old relay-side
            // WebSocket reports its own close; `finish_rotation_if_ready`
            // emits COMPLETE exactly once after both proofs are present.
            rotation.peer_message_id = retired.message_id;
            Ok::<(), tunnel_protocol::rotation::RotationError>(())
        });
        self.finish_rotation_if_ready(key);
    }

    fn finish_rotation_if_ready(&mut self, key: &SessionKey) {
        let _ = self.with_rotation_mut(key, |session, rotation| {
            if rotation.state.phase() != RotationPhase::Active {
                return Ok::<(), tunnel_protocol::rotation::RotationError>(());
            }
            let Some(attempt) = rotation.attempt.clone() else {
                return Ok::<(), tunnel_protocol::rotation::RotationError>(());
            };
            let forced = rotation.state.status().deadline_forced_retirement;
            let source = if rotation.peer_message_id.is_empty() {
                return Ok::<(), tunnel_protocol::rotation::RotationError>(());
            } else {
                rotation.peer_message_id.clone()
            };
            let message = wire::rotate_complete(
                &source,
                attempt,
                &rotation.snapshot_id,
                forced,
                forced.then(|| "overlap deadline forced retirement".to_owned()),
            );
            let encoded = wire::encode_control_message(&message)
                .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
            Self::complete_rotation_reply(rotation, &message, &encoded)
                .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
            queue_control(&session.control_tx, &session.queue_budget, encoded)
                .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
            rotation.last_message_id = message.message_id().to_owned();
            Self::retain_rotation_tombstone(rotation);
            rotation.attempt = None;
            rotation.attempt_deadline_ms = None;
            rotation.snapshot_id.clear();
            rotation.abort_message_id = None;
            rotation.peer_message_id.clear();
            rotation.pending_abort_ack = None;
            Self::clear_phase_message_ids(rotation);
            rotation.remote_fences = [None, None];
            rotation.own_fence = None;
            session.rotations_completed = session.rotations_completed.saturating_add(1);
            session.last_rotation = Instant::now();
            Ok::<(), tunnel_protocol::rotation::RotationError>(())
        });
    }

    /// Advance the attempt deadline independently of the writer barrier.  A
    /// candidate dial can fail before it is registered as a data carrier, so
    /// no disconnect event will ever arrive to drive the owner decision.  The
    /// coordinator therefore polls the pure state clock on every maintenance
    /// tick and emits one unsolicited ABORT as soon as the handshake budget
    /// expires.  Once the absolute overlap budget expires, fail closed rather
    /// than leaving an old or candidate carrier allocated indefinitely.
    fn poll_rotation_deadline(&mut self, key: &SessionKey) -> bool {
        let now_ms = monotonic_millis();
        let mut send_abort = false;
        let mut expired = false;
        let result = self.with_rotation_mut(key, |_session, rotation| {
            let Some(deadline_ms) = rotation.state.status().deadline_ms else {
                return Ok::<(), tunnel_protocol::rotation::RotationError>(());
            };
            if now_ms >= deadline_ms {
                expired = true;
                return Ok::<(), tunnel_protocol::rotation::RotationError>(());
            }
            if rotation.abort_message_id.is_none()
                && rotation.state.phase() == RotationPhase::Preparing
            {
                let _ = rotation.state.tick(now_ms);
            }
            send_abort = rotation.abort_message_id.is_none()
                && rotation.state.phase() == RotationPhase::Aborting;
            Ok::<(), tunnel_protocol::rotation::RotationError>(())
        });
        if result.is_err() {
            return false;
        }
        if send_abort {
            self.emit_rotation_abort(key, "candidate handshake timeout");
        }
        expired
    }

    /// Queue the coordinator's physical-failure decision exactly once.  The
    /// empty reply target is intentional: a timeout is an owner-generated
    /// decision and must not overwrite a cached FROZEN/DRAINED journal reply.
    fn emit_rotation_abort(&mut self, key: &SessionKey, reason: &str) {
        let Some((attempt, remaining_ms, control_tx, budget)) =
            self.session_for(key).and_then(|session| {
                let rotation = session.rotation.as_ref()?;
                if rotation.abort_message_id.is_some()
                    || rotation.state.phase() != RotationPhase::Aborting
                {
                    return None;
                }
                let attempt = rotation.attempt.clone()?;
                let remaining_ms = rotation
                    .state
                    .status()
                    .deadline_ms
                    .unwrap_or_default()
                    .saturating_sub(monotonic_millis());
                Some((
                    attempt,
                    remaining_ms,
                    session.control_tx.clone(),
                    session.queue_budget.clone(),
                ))
            })
        else {
            return;
        };
        if remaining_ms == 0 {
            return;
        }
        let message = wire::rotate_abort("", attempt.clone(), reason, remaining_ms);
        let Ok(encoded) = wire::encode_control_message(&message) else {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                stage = "rotation_abort_encode",
            );
            return;
        };
        if queue_control(&control_tx, &budget, encoded).is_err() {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                stage = "rotation_abort_queue",
            );
            return;
        }
        let ticket_matches_attempt = |ticket: &Ticket| {
            ticket.device_id == key.device_id
                && ticket.session_id == key.session_id
                && ticket.epoch == key.epoch
                && ticket.generation == attempt.new_generation
                && ticket.connection_id == attempt.new_connection_id
                && ticket.candidate
        };
        // Reject any still-unconsumed candidate ticket before claiming the
        // relay side has no outstanding attachment.  An accepted candidate
        // is closed only by its physical DisconnectData event below.
        self.tickets
            .retain(|_, ticket| !ticket_matches_attempt(ticket));
        if let Some(session) = self.session_mut(key)
            && let Some(rotation) = session.rotation.as_mut()
            && rotation.attempt.as_ref() == Some(&attempt)
            && rotation.state.phase() == RotationPhase::Aborting
            && rotation.abort_message_id.is_none()
        {
            if rotation.candidate.is_some() {
                if let Some(candidate) = rotation.candidate.as_ref() {
                    let _ = candidate.tx.try_send(DataOutbound::Close);
                }
            } else if rotation
                .state
                .candidate_closed(
                    &attempt,
                    RotationSide::Owner,
                    ClosureEvidence::closed(attempt.new_connection_id.clone()),
                    monotonic_millis(),
                )
                .is_err()
            {
                tracing::warn!(
                    device_id = %key.device_id,
                    session_id = %key.session_id,
                    epoch = key.epoch,
                    stage = "rotation_abort_owner_closure",
                );
                return;
            }
            rotation.abort_message_id = Some(message.message_id().to_owned());
            rotation.last_message_id = message.message_id().to_owned();
        }
    }

    fn finish_rotation_abort_if_ready(
        &mut self,
        key: &SessionKey,
    ) -> Result<(), tunnel_protocol::rotation::RotationError> {
        self.with_rotation_mut(key, |session, rotation| {
            if rotation.state.phase() != RotationPhase::Active {
                return Ok(());
            }
            let Some(aborted) = Self::pending_abort_ack_if_active(
                rotation.state.phase(),
                &rotation.pending_abort_ack,
            ) else {
                return Ok(());
            };
            let response = wire::rotate_aborted(
                &aborted.message_id,
                aborted.attempt.clone(),
                &aborted.reason,
            );
            let encoded = wire::encode_control_message(&response)
                .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
            Self::complete_rotation_reply(rotation, &response, &encoded)
                .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
            queue_control(&session.control_tx, &session.queue_budget, encoded)
                .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
            Self::retain_rotation_tombstone(rotation);
            rotation.pending_abort_ack = None;
            rotation.candidate = None;
            rotation.attempt = None;
            rotation.attempt_deadline_ms = None;
            rotation.snapshot_id.clear();
            rotation.prepare_message_id.clear();
            rotation.last_message_id = response.message_id().to_owned();
            rotation.abort_message_id = None;
            rotation.peer_message_id.clear();
            Self::clear_phase_message_ids(rotation);
            rotation.remote_fences = [None, None];
            rotation.own_fence = None;
            rotation.barrier_rx = None;
            session.last_rotation = Instant::now();
            Ok(())
        })
    }

    async fn handle_rotate_aborted(
        &mut self,
        key: &SessionKey,
        aborted: tunnel_protocol::rotation_control::RotateAborted,
    ) {
        let result = self.with_rotation_mut(key, |_session, rotation| {
            if !Self::attempt_matches(rotation, &aborted.attempt) {
                return Err(tunnel_protocol::rotation::RotationError::MissingAttempt);
            }
            if rotation.abort_message_id.as_deref() != Some(aborted.reply_to.as_str()) {
                return Err(tunnel_protocol::rotation::RotationError::AttemptMismatch);
            }
            if !Self::peer_message_id_is_acceptable(
                rotation.peer_aborted_message_id.as_deref(),
                &aborted.message_id,
            ) {
                return Err(tunnel_protocol::rotation::RotationError::AttemptMismatch);
            }
            rotation.state.aborted(
                &aborted.attempt,
                tunnel_protocol::rotation::RotationSide::Connector,
                tunnel_protocol::rotation::ClosureEvidence::closed(
                    aborted.closed_connection_id.clone(),
                ),
                monotonic_millis(),
            )?;
            if !Self::pin_peer_message_id(
                &mut rotation.peer_aborted_message_id,
                &aborted.message_id,
            ) {
                return Err(tunnel_protocol::rotation::RotationError::AttemptMismatch);
            }
            // Keep the inbound journal entry pending until the owner's local
            // closure proof is also present.  The final owner response is
            // emitted by the shared helper, either now or after the local
            // DisconnectData event.
            rotation.pending_abort_ack = Some(aborted.clone());
            Ok::<(), tunnel_protocol::rotation::RotationError>(())
        });
        if let Err(error) = result {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                phase = ?self
                    .session_for(key)
                    .and_then(|session| session.rotation.as_ref())
                    .map(|rotation| rotation.state.phase()),
                stage = "connector_aborted",
                error = %error,
            );
        } else if let Err(error) = self.finish_rotation_abort_if_ready(key) {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                stage = "owner_aborted",
                error = %error,
            );
        }
    }

    /// Complete the coordinator side of the recovery closure handshake.  A
    /// recovery ticket is minted only after the connector's role-bound record
    /// matches the exact physical IDs captured before teardown and combines
    /// with the relay record under the immutable attempt context.
    async fn handle_recovery_closed(&mut self, key: &SessionKey, closed: RecoveryClosed) {
        let Some(session) = self.session_for(key) else {
            return;
        };
        let Some(rotation) = session.rotation.as_ref() else {
            return;
        };
        let Some(attempt) = rotation.attempt.as_ref().cloned() else {
            return;
        };
        let Some(recovery) = rotation.recovery.as_ref() else {
            return;
        };
        if rotation.state.phase() != RotationPhase::Recovering
            || closed.attempt != attempt
            || closed.episode_id != recovery.episode_id
            || closed.attempt_no != recovery.attempt_no
            || closed.reply_to != rotation.last_message_id
            || closed.closed_connection_ids != recovery.expected_closed_connection_ids
            || closed
                .verify_closure_digest(RecoverySide::Connector)
                .is_err()
            || recovery.peer_closed.is_some()
        {
            return;
        }
        let Some(local_closed) = recovery.local_closed.as_ref() else {
            return;
        };
        let episode_id = recovery.episode_id.clone();
        let attempt_no = recovery.attempt_no;
        let Ok(combined_digest) = tunnel_protocol::combined_closure_digest(local_closed, &closed)
        else {
            return;
        };
        let ticket = wire::random_token();
        let remaining_ms = Self::recovery_remaining_ms(rotation, monotonic_millis());
        if remaining_ms == 0 {
            return;
        }
        let prepare = wire::rotate_prepare(
            &closed.message_id,
            attempt.clone(),
            DataAttachmentPurpose::Recovery {
                episode_id: episode_id.clone(),
                attempt_no,
                closure_digest: combined_digest.clone(),
            },
            &ticket,
            remaining_ms,
        );
        let Ok(encoded) = wire::encode_control_message(&prepare) else {
            return;
        };
        let prepare_message_id = prepare.message_id().to_owned();
        let (owner, spki, control_tx, budget) = (
            session.owner.clone(),
            session.identity.spki_fingerprint.clone(),
            session.control_tx.clone(),
            session.queue_budget.clone(),
        );
        if let Some(session) = self.session_mut(key)
            && let Some(rotation) = session.rotation.as_mut()
            && Self::complete_rotation_reply(rotation, &prepare, &encoded).is_err()
        {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                stage = "recovery_journal_complete_prepare",
            );
            return;
        }
        let issued_at_wall = Utc::now();
        let expires_at_wall = issued_at_wall
            + ChronoDuration::from_std(wire::TICKET_TTL)
                .unwrap_or_else(|_| ChronoDuration::seconds(10));
        if queue_control(&control_tx, &budget, encoded).is_err() {
            return;
        }
        self.tickets.insert(
            ticket.clone(),
            Ticket {
                value: ticket.clone(),
                device_id: key.device_id,
                spki,
                session_id: key.session_id.clone(),
                epoch: key.epoch,
                generation: attempt.new_generation,
                welcome_message_id: prepare_message_id.clone(),
                connection_id: attempt.new_connection_id.clone(),
                issued_at_wall,
                expires_at_wall,
                expires_at: Instant::now() + wire::TICKET_TTL,
                consuming: false,
                owner,
                candidate: true,
                attachment_purpose: DataAttachmentPurpose::Recovery {
                    episode_id: episode_id.clone(),
                    attempt_no,
                    closure_digest: combined_digest.clone(),
                },
            },
        );
        if let Some(session) = self.session_mut(key)
            && let Some(rotation) = session.rotation.as_mut()
            && let Some(recovery) = rotation.recovery.as_mut()
        {
            recovery.peer_closed = Some(closed);
            recovery.closure_digest = Some(combined_digest);
            rotation.prepare_message_id = prepare_message_id.clone();
            rotation.last_message_id = prepare_message_id;
            rotation.abort_message_id = None;
            rotation.pending_abort_ack = None;
            Self::clear_phase_message_ids(rotation);
        }
    }

    /// Send both immutable relay snapshots after the recovery candidate is
    /// authenticated.  Snapshot construction is bounded by the roster and
    /// happens before any candidate payload can be admitted.
    fn start_recovery_snapshots(&mut self, key: &SessionKey) {
        let prepared = {
            let Some(session) = self.session_for(key) else {
                return;
            };
            let Some(rotation) = session.rotation.as_ref() else {
                return;
            };
            let Some(attempt) = rotation.attempt.clone() else {
                return;
            };
            let Some(recovery) = rotation.recovery.as_ref() else {
                return;
            };
            if rotation.state.phase() != RotationPhase::Recovering
                || !recovery.candidate_ready
                || rotation.candidate.is_none()
            {
                return;
            }
            let roster = recovery.roster.clone();
            let relay_entries = match [
                Self::recovery_local_entries(session, &roster, Direction::RelayToConnector),
                Self::recovery_local_entries(session, &roster, Direction::ConnectorToRelay),
            ] {
                [Ok(relay), Ok(connector)] => [relay, connector],
                _ => return,
            };
            let remaining_ms = Self::recovery_remaining_ms(rotation, monotonic_millis());
            if remaining_ms == 0 {
                return;
            }
            let mut messages = Vec::with_capacity(2);
            for direction in [Direction::RelayToConnector, Direction::ConnectorToRelay] {
                let message = wire::resume(
                    &rotation.prepare_message_id,
                    attempt.clone(),
                    &roster.snapshot_id,
                    ResumeStage::Snapshot,
                    direction,
                    relay_entries[direction_index(direction)].clone(),
                    remaining_ms,
                );
                let Ok(encoded) = wire::encode_control_message(&message) else {
                    return;
                };
                messages.push((message.message_id().to_owned(), encoded));
            }
            Some((
                attempt,
                roster,
                relay_entries,
                messages,
                session.control_tx.clone(),
                session.queue_budget.clone(),
            ))
        };
        let Some((attempt, roster, relay_entries, messages, control_tx, budget)) = prepared else {
            return;
        };
        for (_, encoded) in &messages {
            if queue_control(&control_tx, &budget, encoded.clone()).is_err() {
                return;
            }
        }
        if let Some(session) = self.session_mut(key)
            && let Some(rotation) = session.rotation.as_mut()
            && rotation.attempt.as_ref() == Some(&attempt)
            && let Some(recovery) = rotation.recovery.as_mut()
        {
            recovery.local_snapshots = relay_entries;
            recovery.resume_message_ids =
                [Some(messages[0].0.clone()), Some(messages[1].0.clone())];
            recovery.snapshot_reply_ids = [None, None];
            recovery.ready_snapshots = [Vec::new(), Vec::new()];
            recovery.ready_message_ids = [None, None];
            recovery.remote_snapshots = [HashMap::new(), HashMap::new()];
            recovery.ready_remote_snapshots = [HashMap::new(), HashMap::new()];
            recovery.remote_ready = [false, false];
            recovery.local_plans.clear();
            recovery.ready_sent = [false, false];
            rotation.last_message_id = messages[1].0.clone();
            rotation.snapshot_id = roster.snapshot_id;
        }
    }

    /// Convert a connector RESUMED snapshot into a bounded map and ensure it
    /// is exactly the immutable stream roster.  This rejects omission,
    /// duplication and cross-stream injection before sequence reconciliation.
    fn recovery_entries_map(
        entries: &[ResumeDirectionState],
        roster: &StreamRoster,
    ) -> Option<HashMap<u64, ResumeDirectionState>> {
        if entries.len() != roster.stream_ids.len() {
            return None;
        }
        let mut result = HashMap::with_capacity(entries.len());
        let mut previous = 0;
        for entry in entries {
            if entry.stream_id <= previous
                || roster.stream_ids.binary_search(&entry.stream_id).is_err()
                || result.insert(entry.stream_id, entry.clone()).is_some()
            {
                return None;
            }
            previous = entry.stream_id;
        }
        Some(result)
    }

    /// Reconcile again immediately before READY.  The initial SNAPSHOT pair
    /// is only a fence for retained replay; ACKs, windows, and peer-prefix
    /// replay may advance the local sequence state before the coordinator can
    /// commit candidate reception.  READY therefore carries a fresh cursor
    /// pair and is withheld while either direction still needs peer data.
    fn send_recovery_ready(
        &mut self,
        key: &SessionKey,
    ) -> Result<RecoveryReadyProgress, RelayError> {
        let prepared = {
            let Some(session) = self.session_for(key) else {
                return Err(RelayError::NotFound);
            };
            let Some(rotation) = session.rotation.as_ref() else {
                return Err(RelayError::Conflict("recovery state is unavailable"));
            };
            let Some(recovery) = rotation.recovery.as_ref() else {
                return Err(RelayError::Conflict("recovery state is unavailable"));
            };
            if rotation.state.phase() != RotationPhase::Recovering
                || recovery.snapshot_reply_ids.iter().any(Option::is_none)
                || recovery.ready_sent != [false, false]
            {
                return Ok(RecoveryReadyProgress::Pending);
            }
            let Some(attempt) = rotation.attempt.clone() else {
                return Err(RelayError::Conflict("recovery attempt is unavailable"));
            };
            let roster = recovery.roster.clone();
            let remote_snapshots = recovery.remote_snapshots.clone();
            let sources = recovery
                .snapshot_reply_ids
                .clone()
                .map(|value| value.unwrap_or_else(|| rotation.prepare_message_id.clone()));
            let mut entries = [
                Vec::with_capacity(roster.stream_ids.len()),
                Vec::with_capacity(roster.stream_ids.len()),
            ];
            for stream_id in &roster.stream_ids {
                let Some(stream) = session.streams.get(stream_id) else {
                    return Err(RelayError::Conflict(
                        "recovery roster stream is unavailable",
                    ));
                };
                let Some(relay_entry) = remote_snapshots[0].get(stream_id) else {
                    return Ok(RecoveryReadyProgress::Pending);
                };
                let Some(connector_entry) = remote_snapshots[1].get(stream_id) else {
                    return Ok(RecoveryReadyProgress::Pending);
                };
                let snapshot = stream.sequence.snapshot();
                // These are the immutable obligations established by the
                // initial pair.  Do not feed stale peer snapshots back into
                // `reconcile`: ACKs received after SNAPSHOT are legitimate
                // progress, not an ACK regression.
                for (direction, remote) in [
                    (Direction::RelayToConnector, relay_entry),
                    (Direction::ConnectorToRelay, connector_entry),
                ] {
                    let local = snapshot.direction(direction);
                    if local.recv_contiguous < remote.last_emitted
                        || local.peer_acked < local.last_emitted
                    {
                        // The peer prefix or our sender ACK obligation is not
                        // complete yet.  Housekeeping and retained replay are
                        // handled by the normal candidate path; retry here
                        // after each accepted frame.
                        return Ok(RecoveryReadyProgress::Pending);
                    }
                }
                entries[0].push(
                    ResumeDirectionState::from_sequence_snapshot(
                        *stream_id,
                        snapshot.direction(Direction::RelayToConnector),
                    )
                    .map_err(|error| RelayError::Protocol(error.to_string()))?,
                );
                entries[1].push(
                    ResumeDirectionState::from_sequence_snapshot(
                        *stream_id,
                        snapshot.direction(Direction::ConnectorToRelay),
                    )
                    .map_err(|error| RelayError::Protocol(error.to_string()))?,
                );
            }
            let remaining_ms = Self::recovery_remaining_ms(rotation, monotonic_millis());
            if remaining_ms == 0 {
                return Err(RelayError::Conflict("recovery deadline elapsed"));
            }
            let mut messages = Vec::with_capacity(2);
            for direction in [Direction::RelayToConnector, Direction::ConnectorToRelay] {
                let index = direction_index(direction);
                let message = wire::resume(
                    &sources[index],
                    attempt.clone(),
                    &roster.snapshot_id,
                    ResumeStage::Ready,
                    direction,
                    entries[index].clone(),
                    remaining_ms,
                );
                let encoded = wire::encode_control_message(&message)
                    .map_err(|error| RelayError::Protocol(error.to_string()))?;
                messages.push((index, message, encoded));
            }
            Some((attempt, entries, messages))
        };
        let Some((attempt, entries, messages)) = prepared else {
            return Ok(RecoveryReadyProgress::Pending);
        };
        let Some(session) = self.session_mut(key) else {
            return Err(RelayError::NotFound);
        };
        let Some(rotation) = session.rotation.as_mut() else {
            return Err(RelayError::Conflict("recovery state is unavailable"));
        };
        if rotation.attempt.as_ref() != Some(&attempt) {
            return Ok(RecoveryReadyProgress::Pending);
        }
        if rotation.recovery.is_none() {
            return Err(RelayError::Conflict("recovery state is unavailable"));
        }
        for (_, message, encoded) in &messages {
            Self::complete_rotation_reply(rotation, message, encoded)
                .map_err(|error| RelayError::Protocol(error.to_string()))?;
            queue_control(&session.control_tx, &session.queue_budget, encoded.clone())
                .map_err(|_| RelayError::Overloaded("control queue is full"))?;
        }
        let recovery = rotation.recovery.as_mut().expect("recovery checked above");
        recovery.ready_snapshots = entries;
        recovery.ready_message_ids = [
            Some(messages[0].1.message_id().to_owned()),
            Some(messages[1].1.message_id().to_owned()),
        ];
        recovery.ready_sent = [true, true];
        rotation.last_message_id = messages[1].1.message_id().to_owned();
        Ok(RecoveryReadyProgress::Sent)
    }

    async fn handle_recovery_resumed(
        &mut self,
        key: &SessionKey,
        resumed: tunnel_protocol::rotation_control::Resumed,
    ) {
        let Some(session) = self.session_for(key) else {
            return;
        };
        let Some(rotation) = session.rotation.as_ref() else {
            return;
        };
        let Some(attempt) = rotation.attempt.as_ref() else {
            return;
        };
        let Some(recovery) = rotation.recovery.as_ref() else {
            return;
        };
        let index = direction_index(resumed.direction);
        let expected_reply_to = match resumed.stage {
            ResumeStage::Snapshot => recovery.resume_message_ids[index].as_deref(),
            ResumeStage::Ready => recovery.ready_message_ids[index].as_deref(),
        }
        .unwrap_or_default();
        if rotation.state.phase() != RotationPhase::Recovering
            || resumed.attempt != *attempt
            || resumed.snapshot_id != recovery.roster.snapshot_id
            || resumed.reply_to != expected_reply_to
        {
            return;
        }
        let Some(entries) = Self::recovery_entries_map(&resumed.entries, &recovery.roster) else {
            return;
        };
        match resumed.stage {
            ResumeStage::Snapshot => {
                // The empty roster is valid. Key duplicate detection by the
                // retained reply id, otherwise the first empty RESUMED is
                // mistaken for a duplicate and READY is never sent.
                if recovery.snapshot_reply_ids[index].is_some() {
                    if recovery.remote_snapshots[index] != entries {
                        return;
                    }
                    return;
                }
                if !recovery.remote_snapshots[index].is_empty() {
                    return;
                }
                let reply_id = resumed.message_id.clone();
                if let Some(session) = self.session_mut(key)
                    && let Some(rotation) = session.rotation.as_mut()
                    && let Some(recovery) = rotation.recovery.as_mut()
                {
                    recovery.remote_snapshots[index] = entries;
                    recovery.snapshot_reply_ids[index] = Some(reply_id);
                }
                let snapshot_ready = self.session_for(key).is_some_and(|session| {
                    session
                        .rotation
                        .as_ref()
                        .and_then(|rotation| rotation.recovery.as_ref())
                        .is_some_and(|recovery| {
                            recovery.snapshot_reply_ids.iter().all(Option::is_some)
                        })
                });
                if snapshot_ready {
                    self.prepare_recovery_plans(key).await;
                }
            }
            ResumeStage::Ready => {
                if !recovery.ready_sent[index] || recovery.remote_ready[index] {
                    return;
                }
                if let Some(session) = self.session_mut(key)
                    && let Some(rotation) = session.rotation.as_mut()
                    && let Some(recovery) = rotation.recovery.as_mut()
                {
                    recovery.ready_remote_snapshots[index] = entries;
                    recovery.remote_ready[index] = true;
                }
                let ready_pair = self.session_for(key).is_some_and(|session| {
                    session
                        .rotation
                        .as_ref()
                        .and_then(|rotation| rotation.recovery.as_ref())
                        .is_some_and(|recovery| recovery.remote_ready == [true, true])
                });
                if !ready_pair {
                    return;
                }
                let plans = {
                    let Some(session) = self.session_for(key) else {
                        return;
                    };
                    let Some(rotation) = session.rotation.as_ref() else {
                        return;
                    };
                    let Some(recovery) = rotation.recovery.as_ref() else {
                        return;
                    };
                    let mut plans = HashMap::with_capacity(recovery.roster.stream_ids.len());
                    let mut failed = false;
                    for stream_id in &recovery.roster.stream_ids {
                        let Some(stream) = session.streams.get(stream_id) else {
                            failed = true;
                            break;
                        };
                        let Some(relay_entry) = recovery.ready_remote_snapshots[0].get(stream_id)
                        else {
                            failed = true;
                            break;
                        };
                        let Some(connector_entry) =
                            recovery.ready_remote_snapshots[1].get(stream_id)
                        else {
                            failed = true;
                            break;
                        };
                        let peer = StreamSnapshot {
                            stream_id: *stream_id,
                            directions: [
                                direction_snapshot_from_resume(relay_entry),
                                direction_snapshot_from_resume(connector_entry),
                            ],
                        };
                        let Ok(plan) = stream.sequence.reconcile(&peer) else {
                            failed = true;
                            break;
                        };
                        if [Direction::RelayToConnector, Direction::ConnectorToRelay]
                            .into_iter()
                            .any(|direction| plan.peer_missing(direction).is_some())
                        {
                            failed = true;
                            break;
                        }
                        plans.insert(*stream_id, plan);
                    }
                    (!failed).then_some(plans)
                };
                let Some(plans) = plans else {
                    self.close_session(key, "RECOVERY_READY_CONFLICT").await;
                    return;
                };
                if let Some(session) = self.session_mut(key)
                    && let Some(rotation) = session.rotation.as_mut()
                    && let Some(recovery) = rotation.recovery.as_mut()
                {
                    recovery.local_plans = plans;
                }
                self.activate_recovery(key).await;
            }
        }
    }

    /// Reconcile both directions against the immutable connector snapshots,
    /// queue only retained relay-to-connector frames, and issue both READY
    /// decisions.  All work is actor-local and bounded; no application waiter
    /// or socket writer is awaited here.
    async fn prepare_recovery_plans(&mut self, key: &SessionKey) {
        let prepared = {
            let Some(session) = self.session_for(key) else {
                return;
            };
            let Some(rotation) = session.rotation.as_ref() else {
                return;
            };
            let Some(recovery) = rotation.recovery.as_ref() else {
                return;
            };
            if recovery.remote_snapshots.iter().any(HashMap::is_empty)
                && !recovery.roster.stream_ids.is_empty()
            {
                return;
            }
            if recovery.ready_sent != [false, false] {
                return;
            }
            let mut plans = HashMap::with_capacity(recovery.roster.stream_ids.len());
            for stream_id in &recovery.roster.stream_ids {
                let Some(stream) = session.streams.get(stream_id) else {
                    return;
                };
                let Some(relay_entry) = recovery.remote_snapshots[0].get(stream_id) else {
                    return;
                };
                let Some(connector_entry) = recovery.remote_snapshots[1].get(stream_id) else {
                    return;
                };
                let peer = StreamSnapshot {
                    stream_id: *stream_id,
                    directions: [
                        direction_snapshot_from_resume(relay_entry),
                        direction_snapshot_from_resume(connector_entry),
                    ],
                };
                let Ok(plan) = stream.sequence.reconcile(&peer) else {
                    return;
                };
                plans.insert(*stream_id, plan);
            }
            let Some(candidate) = rotation.candidate.as_ref() else {
                return;
            };
            let Some(attempt) = rotation.attempt.clone() else {
                return;
            };
            Some((
                plans,
                candidate.tx.clone(),
                session.queue_budget.clone(),
                session.key.epoch,
                attempt,
            ))
        };
        let Some((plans, candidate_tx, budget, epoch, attempt)) = prepared else {
            return;
        };
        let mut replayed = 0_u64;
        for plan in plans.values() {
            for frame in plan.replay(Direction::RelayToConnector) {
                let mut frame = frame.clone();
                frame.epoch = epoch;
                frame.generation = attempt.new_generation;
                let Ok(encoded) = frame.encode() else {
                    return;
                };
                if queue_data(&candidate_tx, &budget, encoded).is_err() {
                    return;
                }
                replayed = replayed.saturating_add(1);
            }
        }
        {
            let Some(session) = self.session_mut(key) else {
                return;
            };
            let Some(rotation) = session.rotation.as_mut() else {
                return;
            };
            if rotation.recovery.is_none() {
                return;
            }
            rotation
                .recovery
                .as_mut()
                .expect("recovery checked above")
                .local_plans = plans;
            rotation.replayed_frames = rotation.replayed_frames.saturating_add(replayed);
            session.total_replayed_frames = session.total_replayed_frames.saturating_add(replayed);
        }
        if let Err(error) = self.send_recovery_ready(key) {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                stage = "recovery_ready",
                error = %error,
            );
            self.close_session(key, "RECOVERY_READY_FAILED").await;
        }
    }

    /// Activate a recovered candidate only after both READY acknowledgements.
    /// Deferred candidate frames are released into sequence state afterwards,
    /// preserving the immutable snapshot verdicts used by the rotation model.
    async fn activate_recovery(&mut self, key: &SessionKey) {
        let verdicts = {
            let Some(session) = self.session_for(key) else {
                return;
            };
            let Some(rotation) = session.rotation.as_ref() else {
                return;
            };
            let Some(recovery) = rotation.recovery.as_ref() else {
                return;
            };
            recovery
                .local_plans
                .values()
                .map(ValidatedRecovery::from_sequence_plan)
                .collect::<Result<Vec<_>, _>>()
        };
        let Ok(verdicts) = verdicts else {
            self.close_session(key, "RECOVERY_STATE_LOST").await;
            return;
        };
        let Some((attempt, peer_snapshots)) = self.session_for(key).and_then(|session| {
            let rotation = session.rotation.as_ref()?;
            let recovery = rotation.recovery.as_ref()?;
            Some((
                rotation.attempt.clone()?,
                recovery.ready_remote_snapshots.clone(),
            ))
        }) else {
            return;
        };
        let mut deferred = VecDeque::new();
        let mut sequence_state_lost = false;
        if let Some(session) = self.session_mut(key)
            && let Some(rotation) = session.rotation.as_mut()
            && let Some(recovery) = rotation.recovery.as_mut()
        {
            if recovery.activated {
                return;
            }
            recovery.activated = true;
            deferred = std::mem::take(&mut recovery.deferred_frames);
            recovery.deferred_bytes = 0;
            for (stream_id, stream) in &mut session.streams {
                let Some(relay_entry) = peer_snapshots[0].get(stream_id) else {
                    continue;
                };
                let Some(connector_entry) = peer_snapshots[1].get(stream_id) else {
                    continue;
                };
                let peer = StreamSnapshot {
                    stream_id: *stream_id,
                    directions: [
                        direction_snapshot_from_resume(relay_entry),
                        direction_snapshot_from_resume(connector_entry),
                    ],
                };
                if stream.sequence.reconcile_and_apply(&peer).is_err() {
                    sequence_state_lost = true;
                    break;
                }
            }
        }
        if sequence_state_lost {
            self.close_session(key, "RECOVERY_STATE_LOST").await;
            return;
        }
        let recovery_ok = self.with_rotation_mut(key, |_session, rotation| {
            rotation
                .state
                .reconcile_validated(&attempt, verdicts, monotonic_millis())
                .map(|_| ())
                .map_err(|_| tunnel_protocol::rotation::RotationError::RecoveryReplayPending)
        });
        if recovery_ok.is_err() {
            self.close_session(key, "RECOVERY_STATE_LOST").await;
            return;
        }
        if let Some(session) = self.session_mut(key)
            && let Some(rotation) = session.rotation.as_mut()
            && let Some(candidate_carrier) = rotation.candidate.take()
        {
            session.active_carrier = Some(candidate_carrier);
            session.data_tx = session
                .active_carrier
                .as_ref()
                .map(|carrier| carrier.tx.clone());
            session.generation = attempt.new_generation;
            session.connection_id = attempt.new_connection_id.clone();
            Self::retain_rotation_tombstone(rotation);
            rotation.recovery = None;
            rotation.attempt = None;
            rotation.attempt_deadline_ms = None;
            rotation.snapshot_id.clear();
            rotation.prepare_message_id.clear();
            rotation.last_message_id.clear();
            rotation.abort_message_id = None;
            rotation.peer_message_id.clear();
            rotation.pending_abort_ack = None;
            Self::clear_phase_message_ids(rotation);
            rotation.remote_fences = [None, None];
            rotation.own_fence = None;
            session.last_rotation = Instant::now();
        }
        for (carrier, frame, charged) in deferred {
            if let Some(session) = self.session_mut(key)
                && let Some(stream) = session.streams.get_mut(&frame.stream_id)
            {
                release_m2_bytes(&session.queue_budget, stream, charged);
            }
            self.inbound_m2_stream_data(carrier, frame, false).await;
        }
        self.flush_recovered_records(key);
    }

    fn flush_recovered_records(&mut self, key: &SessionKey) {
        let mut queued = Vec::new();
        if let Some(session) = self.session_mut(key) {
            for (stream_id, stream) in &mut session.streams {
                queued.extend(
                    stream
                        .authorized_until
                        .filter(|deadline| *deadline > Instant::now())
                        .map(|_| {
                            std::mem::take(&mut stream.pending_records)
                                .into_iter()
                                .map(|(body, waiter)| (*stream_id, body, waiter))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default(),
                );
                stream.pending_record_bytes = 0;
            }
        }
        for (stream_id, body, waiter) in queued {
            let operation_id = self
                .session_for(key)
                .and_then(|session| session.streams.get(&stream_id))
                .map(|stream| stream.operation_id.clone())
                .unwrap_or_default();
            self.write_echo_stream(key.clone(), stream_id, operation_id, body, waiter);
        }
    }

    async fn handle_resumed(
        &mut self,
        key: &SessionKey,
        resumed: tunnel_protocol::rotation_control::Resumed,
    ) {
        self.handle_recovery_resumed(key, resumed).await;
    }

    fn handle_stream_forget(
        &mut self,
        key: &SessionKey,
        forget: tunnel_protocol::rotation_control::StreamForget,
    ) {
        if forget.session_id != key.session_id || forget.epoch != key.epoch {
            return;
        }
        let mut removed = false;
        if let Some(session) = self.session_mut(key)
            && let Some(stream) = session.streams.get(&forget.stream_id)
        {
            if stream.operation_id != forget.operation_id
                || forget.final_state.stream_id != forget.stream_id
                || (forget.final_state.send_terminal.is_none()
                    && forget.final_state.receive_terminal.is_none())
            {
                return;
            }
            let snapshot = stream.sequence.snapshot();
            let Ok(expected) = ResumeDirectionState::from_sequence_snapshot(
                forget.stream_id,
                snapshot.direction(forget.direction),
            ) else {
                return;
            };
            if expected != forget.final_state {
                return;
            }
            if let Some(mut removed_stream) = session.streams.remove(&forget.stream_id) {
                removed = true;
                removed_stream.closed.cancel();
                session.queue_budget.release(removed_stream.budget_bytes);
                removed_stream.budget_bytes = 0;
                for (_, waiter) in removed_stream.pending_records.drain(..) {
                    let _ = waiter.send(Err(EchoOutcome::Failure {
                        code: "STREAM_FORGOTTEN",
                        execution: "unknown",
                    }));
                }
                for waiter in removed_stream.response_records.drain(..) {
                    let _ = waiter.send(Err(EchoOutcome::Failure {
                        code: "STREAM_FORGOTTEN",
                        execution: "unknown",
                    }));
                }
            }
        }
        if removed
            && let Some(session) = self.session_mut(key)
            && let Some(rotation) = session.rotation.as_mut()
            && Self::complete_rotation_entry(rotation, &forget.message_id, &[]).is_err()
        {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                stage = "stream_forget_journal_complete",
            );
        }
    }

    fn with_rotation_mut<T>(
        &mut self,
        key: &SessionKey,
        function: impl FnOnce(
            &mut DeviceSession,
            &mut RotationRuntime,
        ) -> Result<T, tunnel_protocol::rotation::RotationError>,
    ) -> Result<T, tunnel_protocol::rotation::RotationError> {
        let session = self
            .sessions
            .get_mut(&key.device_id)
            .filter(|session| session.key == *key)
            .ok_or(tunnel_protocol::rotation::RotationError::Closed)?;
        let rotation = session
            .rotation
            .take()
            .ok_or(tunnel_protocol::rotation::RotationError::Closed)?;
        let mut rotation = rotation;
        let result = function(session, &mut rotation);
        session.rotation = Some(rotation);
        result
    }

    async fn inbound_control(&mut self, key: SessionKey, message: ControlMessage) {
        if self.session_for(&key).is_none() {
            return;
        }
        let starts_new_rotation = matches!(&message, ControlMessage::RotateRequest(_))
            && self.session_for(&key).is_some_and(|session| {
                session.rotation.as_ref().is_some_and(|rotation| {
                    rotation.attempt.is_none() && rotation.state.phase() == RotationPhase::Active
                })
            });
        if is_rotation_message(&message) {
            if !self.rotation_context_is_valid(&key, &message) {
                return;
            }
            // The first request of a new attempt must be journaled after
            // `start_rotation` installs that attempt's fresh deadline.  The
            // admission journal may have expired while the session remained
            // idle; observing it first would incorrectly reject a valid new
            // request and then reset the journal underneath the transition.
            if !starts_new_rotation {
                match self.observe_rotation_message(&key, &message) {
                    RotationJournalDecision::New => {}
                    RotationJournalDecision::PendingDuplicate => return,
                    RotationJournalDecision::CompletedDuplicate(responses) => {
                        // Some phase acknowledgements have no wire reply;
                        // their completed empty journal value is still useful
                        // for suppressing redispatch, but there is nothing to
                        // enqueue on the control socket.  Progressive replies
                        // are replayed in their original append order.
                        for response in responses {
                            if response.is_empty() {
                                continue;
                            }
                            let Ok(text) = String::from_utf8(response) else {
                                self.protocol_failure(&key, "ROTATION_JOURNAL_RESPONSE")
                                    .await;
                                return;
                            };
                            let queued = self
                                .session_for(&key)
                                .map(|session| {
                                    queue_control(&session.control_tx, &session.queue_budget, text)
                                        .is_ok()
                                })
                                .unwrap_or(false);
                            if !queued {
                                self.protocol_failure(&key, "ROTATION_JOURNAL_REPLAY").await;
                                return;
                            }
                        }
                        return;
                    }
                    RotationJournalDecision::Error(error) => {
                        tracing::warn!(
                            device_id = %key.device_id,
                            session_id = %key.session_id,
                            epoch = key.epoch,
                            phase = ?self
                                .session_for(&key)
                                .and_then(|session| session.rotation.as_ref())
                                .map(|rotation| rotation.state.phase()),
                            stage = "rotation_journal_observe",
                            error = %error,
                        );
                        self.protocol_failure(&key, "ROTATION_JOURNAL_INVALID")
                            .await;
                        return;
                    }
                }
            }
        }
        match message {
            ControlMessage::AuthorizationChallenge(challenge) => {
                self.begin_device_challenge(key, challenge);
            }
            ControlMessage::Opened(opened) => {
                if opened.session_id != key.session_id || opened.epoch != key.epoch {
                    self.protocol_failure(&key, "STALE_CONTROL").await;
                }
            }
            ControlMessage::Pong(pong) => {
                if pong.session_id != key.session_id || pong.epoch != key.epoch {
                    self.protocol_failure(&key, "STALE_CONTROL").await;
                }
            }
            ControlMessage::Rejected(rejected) => {
                if rejected.session_id != key.session_id || rejected.epoch != key.epoch {
                    return;
                }
                if let Some(session) = self.session_mut(&key)
                    && session
                        .pending
                        .get(&rejected.stream_id)
                        .is_some_and(|pending| pending.operation_id == rejected.operation_id)
                    && let Some(pending) = session.pending.remove(&rejected.stream_id)
                {
                    tracing::debug!(
                        tenant_id = %session.identity.tenant_id,
                        device_id = %key.device_id,
                        session_id = %key.session_id,
                        epoch = key.epoch,
                        stream_id = rejected.stream_id,
                        operation_id = %rejected.operation_id,
                        phase = "stream_rejected",
                    );
                    release_pending_budget(session, &pending);
                    let _ = pending.response.send(EchoOutcome::Failure {
                        code: "DEVICE_REJECTED",
                        execution: "not_dispatched",
                    });
                }
            }
            ControlMessage::AuthorizationInvalidated(invalidated) => {
                if invalidated.session_id != key.session_id || invalidated.epoch != key.epoch {
                    return;
                }
                if let Some(session) = self.session_mut(&key)
                    && session
                        .pending
                        .get(&invalidated.stream_id)
                        .is_some_and(|pending| {
                            pending.challenge_id.as_deref()
                                == Some(invalidated.challenge_id.as_str())
                                && pending.grant.revision == invalidated.grant_revision
                        })
                    && let Some(pending) = session.pending.remove(&invalidated.stream_id)
                {
                    release_pending_budget(session, &pending);
                    let _ = pending.response.send(EchoOutcome::Failure {
                        code: "AUTHORIZATION_REVOKED",
                        execution: "not_dispatched",
                    });
                }
            }
            ControlMessage::Cancel(cancel) => {
                if cancel.session_id != key.session_id || cancel.epoch != key.epoch {
                    return;
                }
                self.cancel(&key, cancel.stream_id, cancel.operation_id);
            }
            ControlMessage::RotateRequest(request) => {
                if request.session_id == key.session_id {
                    let request_message = ControlMessage::RotateRequest(request.clone());
                    let response = self.start_rotation(
                        &key,
                        Some(request.message_id.clone()),
                        "client_request",
                    );
                    if starts_new_rotation {
                        match response {
                            Some(response) => {
                                if let Err(error) = self.record_rotation_request_response(
                                    &key,
                                    &request_message,
                                    &response,
                                ) {
                                    tracing::warn!(
                                        device_id = %key.device_id,
                                        session_id = %key.session_id,
                                        epoch = key.epoch,
                                        phase = ?self
                                            .session_for(&key)
                                            .and_then(|session| session.rotation.as_ref())
                                            .map(|rotation| rotation.state.phase()),
                                        stage = "rotation_journal_complete_request",
                                        error = %error,
                                    );
                                    self.protocol_failure(&key, "ROTATION_JOURNAL_INVALID")
                                        .await;
                                }
                            }
                            None => {
                                self.protocol_failure(&key, "ROTATION_START_FAILED").await;
                            }
                        }
                    } else if response.is_some() {
                        self.protocol_failure(&key, "ROTATION_DUPLICATE_STATE")
                            .await;
                    }
                }
            }
            ControlMessage::RotateFrozen(frozen) => {
                self.handle_rotate_frozen(&key, frozen).await;
            }
            ControlMessage::RotateDrained(drained) => {
                self.handle_rotate_drained(&key, drained).await;
            }
            ControlMessage::RotateCommitted(committed) => {
                self.handle_rotate_committed(&key, committed).await;
            }
            ControlMessage::RotateRetired(retired) => {
                self.handle_rotate_retired(&key, retired).await;
            }
            ControlMessage::RotateAbort(_) => {
                // The relay is the owner and the only endpoint permitted to
                // decide ABORT.  An authenticated connector must acknowledge
                // our decision with ROTATE_ABORTED; an inbound ABORT is a
                // protocol violation rather than a second state transition.
                self.protocol_failure(&key, "UNEXPECTED_ROTATE_ABORT").await;
            }
            ControlMessage::RotateAborted(aborted) => {
                self.handle_rotate_aborted(&key, aborted).await;
            }
            ControlMessage::RecoveryClosed(closed) => {
                self.handle_recovery_closed(&key, closed).await;
            }
            ControlMessage::RecoveryBegin(_) => {
                // The relay is the recovery coordinator.  A connector cannot
                // introduce a second episode or replace the immutable roster.
                self.protocol_failure(&key, "UNEXPECTED_RECOVERY_BEGIN")
                    .await;
            }
            ControlMessage::Resumed(resumed) => {
                self.handle_resumed(&key, resumed).await;
            }
            ControlMessage::StreamForget(forget) => {
                self.handle_stream_forget(&key, forget);
            }
            ControlMessage::Ping(ping) => {
                if ping.session_id != key.session_id || ping.epoch != key.epoch {
                    self.protocol_failure(&key, "STALE_CONTROL").await;
                } else {
                    let pong = ControlMessage::Pong(tunnel_protocol::Pong::new(
                        wire::random_token(),
                        ping.message_id,
                        key.session_id.clone(),
                        key.epoch,
                        ping.nonce,
                    ));
                    let _ = self.send_control(&key, pong);
                }
            }
            _ => {
                let _ = self.send_control(
                    &key,
                    wire::rejected(
                        &wire::random_token(),
                        &key.session_id,
                        key.epoch,
                        1,
                        "control",
                        "UNKNOWN_CONTROL",
                        "unsupported control message",
                    ),
                );
            }
        }
    }

    fn rotation_context_is_valid(&self, key: &SessionKey, message: &ControlMessage) -> bool {
        let Some(session) = self.session_for(key) else {
            return false;
        };
        let Some(rotation) = session.rotation.as_ref() else {
            return false;
        };
        if let Some(attempt) = Self::message_attempt(message) {
            if attempt.session_id != key.session_id
                || attempt.epoch != key.epoch
                || attempt.owner_id != runtime::owner_id(&session.owner)
            {
                return false;
            }
            let now_ms = monotonic_millis();
            return rotation.attempt.as_ref() == Some(attempt)
                || rotation.tombstones.iter().any(|tombstone| {
                    tombstone.deadline_ms > now_ms && tombstone.attempt == *attempt
                });
        }
        match message {
            ControlMessage::RotateRequest(request) => {
                request.session_id == key.session_id
                    && request.epoch == key.epoch
                    && request.owner_id == runtime::owner_id(&session.owner)
                    && request.generation == session.generation
                    && request.connection_id == session.connection_id
            }
            ControlMessage::StreamForget(value) => {
                value.session_id == key.session_id && value.epoch == key.epoch
            }
            _ => false,
        }
    }

    fn begin_device_challenge(&mut self, key: SessionKey, message: AuthorizationChallenge) {
        if message.session_id != key.session_id || message.epoch != key.epoch {
            return;
        }
        let service_id = message.service_id.clone();
        let challenge = DeviceChallenge {
            message_id: message.message_id,
            stream_id: message.stream_id,
            service_id,
            challenge_id: message.challenge_id,
            nonce: message.nonce,
            permission_digest: message.permission_digest,
            grant_revision: message.grant_revision,
            received_at: Instant::now(),
            lifetime: self.options.challenge_interval.min(AUTHORIZATION_LIFETIME),
        };
        let Some(session) = self.session_mut(&key) else {
            return;
        };
        let (consumer, service_id, read_started_at, spki) =
            if let Some(pending) = session.pending.get_mut(&message.stream_id) {
                if pending.dispatched || pending.authorization_in_flight {
                    return;
                }
                let expected_digest =
                    wire::permission_digest(&pending.grant, &pending.service_id.to_string());
                if challenge.permission_digest != expected_digest
                    || challenge.grant_revision != pending.grant.revision
                    || challenge.service_id != pending.service_id.to_string()
                {
                    return;
                }
                pending.authorization_in_flight = true;
                pending.challenge_id = Some(challenge.challenge_id.clone());
                (
                    pending.consumer.clone(),
                    pending.service_id,
                    pending.grant.read_started_at,
                    session.identity.spki_fingerprint.clone(),
                )
            } else if let Some(stream) = session.streams.get_mut(&message.stream_id) {
                if stream.authorization_in_flight || stream.terminal {
                    return;
                }
                let expected_digest =
                    wire::permission_digest(&stream.grant, &stream.service_id.to_string());
                if challenge.permission_digest != expected_digest
                    || challenge.grant_revision != stream.grant.revision
                    || challenge.service_id != stream.service_id.to_string()
                {
                    return;
                }
                stream.authorization_in_flight = true;
                stream.challenge_id = Some(challenge.challenge_id.clone());
                (
                    stream.consumer.clone(),
                    stream.service_id,
                    // A streaming challenge is a fresh authorization read.
                    // Redis bounds the catalog read to five seconds from
                    // `read_started_at`; reusing the initial grant's start
                    // time would make every later refresh appear stale even
                    // when the consumer and grant are still valid.
                    Utc::now(),
                    session.identity.spki_fingerprint.clone(),
                )
            } else {
                return;
            };
        let catalog = self.catalog.clone();
        let command_tx = self.command_tx.clone();
        tokio::spawn(async move {
            let result = async {
                let current = catalog
                    .authorize(
                        &consumer,
                        key.device_id,
                        service_id,
                        read_started_at,
                        Utc::now(),
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let Some(current) = current else {
                    return Ok((None, None, None, None));
                };
                let owner = catalog
                    .current_owner(current.tenant_id, key.device_id, Utc::now())
                    .await
                    .map_err(|error| error.to_string())?;
                let owner_deadline = owner.as_ref().and_then(|claim| {
                    (claim.lease_expires_at - Utc::now())
                        .to_std()
                        .ok()
                        .and_then(|remaining| remaining.checked_sub(OWNER_LEASE_SAFETY_MARGIN))
                        .map(|remaining| Instant::now() + remaining)
                });
                let identity = catalog
                    .resolve_device(&spki, Utc::now())
                    .await
                    .map_err(|error| error.to_string())?;
                Ok((Some(current), owner, identity, owner_deadline))
            }
            .await;
            let _ = command_tx
                .send(Command::ChallengeAuthorized {
                    key,
                    challenge,
                    result,
                })
                .await;
        });
    }

    fn finish_device_challenge(
        &mut self,
        key: SessionKey,
        challenge: DeviceChallenge,
        result: ChallengeAuthorizationResult,
    ) {
        let pending_exists = self
            .session_for(&key)
            .is_some_and(|session| session.pending.contains_key(&challenge.stream_id));
        if !pending_exists {
            self.finish_stream_challenge(key, challenge, result);
            return;
        }
        let Some(session) = self.session_for(&key) else {
            return;
        };
        let Some(pending) = session.pending.get(&challenge.stream_id) else {
            return;
        };
        if !pending.authorization_in_flight
            || pending.dispatched
            || pending.grant.revision != challenge.grant_revision
            || pending.service_id.to_string() != challenge.service_id
        {
            return;
        }
        let consumer_expires_at = pending.consumer_expires_at;
        let (current, owner, identity, owner_deadline) = match result {
            Ok(value) => value,
            Err(_) => {
                self.invalidate_pending(
                    &key,
                    challenge.stream_id,
                    &challenge,
                    "authorization unavailable",
                );
                return;
            }
        };
        let Some(current) = current else {
            self.invalidate_pending(&key, challenge.stream_id, &challenge, "grant unavailable");
            return;
        };
        let Some(owner) = owner else {
            self.invalidate_pending(&key, challenge.stream_id, &challenge, "owner unavailable");
            return;
        };
        let Some(identity) = identity else {
            self.invalidate_pending(
                &key,
                challenge.stream_id,
                &challenge,
                "device authorization unavailable",
            );
            return;
        };
        let now_wall = Utc::now();
        let Some(session) = self.session_for(&key) else {
            return;
        };
        if owner.token != session.owner
            || identity.device_id != key.device_id
            || identity.spki_fingerprint != session.identity.spki_fingerprint
            || identity.device_version != session.identity.device_version
            || identity.owner_epoch != session.owner.epoch
            || !identity.device_active
            || !identity.credential_active
            || identity.credential_revoked_at.is_some()
            || identity.expires_at <= now_wall
            || current.revision != challenge.grant_revision
            || wire::permission_digest(&current, &challenge.service_id)
                != challenge.permission_digest
            || current.valid_until <= now_wall
        {
            self.invalidate_pending(
                &key,
                challenge.stream_id,
                &challenge,
                "authorization changed",
            );
            return;
        }
        let challenge_remaining = challenge
            .lifetime
            .checked_sub(challenge.received_at.elapsed())
            .unwrap_or_default();
        let snapshot_remaining = (current.valid_until - now_wall)
            .to_std()
            .unwrap_or_default();
        let token_remaining = (consumer_expires_at - now_wall)
            .to_std()
            .unwrap_or_default();
        let owner_remaining = owner_deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_default();
        let credential_remaining = (identity.expires_at - now_wall)
            .to_std()
            .unwrap_or_default();
        let remaining = challenge_remaining
            .min(snapshot_remaining)
            .min(token_remaining)
            .min(owner_remaining)
            .min(credential_remaining);
        let remaining_ms = remaining.as_millis().min(5_000) as u64;
        if remaining_ms == 0 {
            self.invalidate_pending(
                &key,
                challenge.stream_id,
                &challenge,
                "authorization expired",
            );
            return;
        }
        let dispatch_deadline = Instant::now() + Duration::from_millis(remaining_ms);
        let owner_safe_until = owner.lease_expires_at
            - ChronoDuration::from_std(OWNER_LEASE_SAFETY_MARGIN)
                .unwrap_or_else(|_| ChronoDuration::seconds(5));
        let grant_read_started_at = current.read_started_at;
        let authorization_is_live = || {
            let now = Utc::now();
            Instant::now() < dispatch_deadline
                && now >= grant_read_started_at
                && now < current.valid_until
                && now < consumer_expires_at
                && now < identity.expires_at
                && now < owner_safe_until
        };

        if self
            .session_for(&key)
            .and_then(|session| session.data_tx.as_ref())
            .is_none()
        {
            self.fail_pending(
                &key,
                challenge.stream_id,
                "DEVICE_OFFLINE",
                "not_dispatched",
            );
            return;
        }
        let (control_tx, data_tx, queue_budget, generation, send_sequence, body) = {
            let Some(session) = self.session_for(&key) else {
                return;
            };
            let Some(pending) = session.pending.get(&challenge.stream_id) else {
                return;
            };
            let data_tx = session.data_tx.clone().expect("data socket checked above");
            (
                session.control_tx.clone(),
                data_tx,
                session.queue_budget.clone(),
                session.generation,
                pending.send_sequence,
                pending.body.clone(),
            )
        };
        if data_tx.is_closed() {
            self.fail_pending(
                &key,
                challenge.stream_id,
                "DEVICE_OFFLINE",
                "not_dispatched",
            );
            return;
        }
        let confirmed = wire::authorization_confirmed(wire::AuthorizationConfirmation {
            reply_to: &challenge.message_id,
            session_id: &key.session_id,
            epoch: key.epoch,
            stream_id: challenge.stream_id,
            challenge_id: &challenge.challenge_id,
            nonce: &challenge.nonce,
            permission_digest: &challenge.permission_digest,
            grant_revision: challenge.grant_revision,
            remaining_ms,
        });
        let Ok(confirmed) = wire::encode_control_message(&confirmed) else {
            self.fail_pending(&key, challenge.stream_id, "CONTROL_LIMIT", "not_dispatched");
            return;
        };
        let frame = match wire::data_frame(
            key.epoch,
            generation,
            challenge.stream_id,
            send_sequence,
            body,
        ) {
            Ok(frame) => frame,
            Err(_) => {
                self.fail_pending(&key, challenge.stream_id, "FRAME_LIMIT", "not_dispatched");
                return;
            }
        };
        let fin_sequence = match send_sequence.checked_add(1) {
            Some(sequence) => sequence,
            None => {
                self.fail_pending(&key, challenge.stream_id, "STREAM_LIMIT", "not_dispatched");
                return;
            }
        };
        let fin = match wire::fin_frame(key.epoch, generation, challenge.stream_id, fin_sequence) {
            Ok(frame) => frame,
            Err(_) => {
                self.fail_pending(&key, challenge.stream_id, "FRAME_LIMIT", "not_dispatched");
                return;
            }
        };
        if !authorization_is_live() {
            self.invalidate_pending(
                &key,
                challenge.stream_id,
                &challenge,
                "authorization expired",
            );
            return;
        }
        if queue_control(&control_tx, &queue_budget, confirmed).is_err() {
            self.fail_pending(
                &key,
                challenge.stream_id,
                "CONTROL_UNAVAILABLE",
                "not_dispatched",
            );
            return;
        }
        if !authorization_is_live() {
            self.invalidate_pending(
                &key,
                challenge.stream_id,
                &challenge,
                "authorization expired",
            );
            return;
        }
        if queue_data(&data_tx, &queue_budget, frame).is_err() {
            self.fail_pending(
                &key,
                challenge.stream_id,
                "REVERSE_CHANNEL_UNAVAILABLE",
                "unknown",
            );
            let _ = data_tx.try_send(DataOutbound::Close);
            let _ = control_tx.try_send(ControlOutbound::Close);
            let _ = self
                .command_tx
                .try_send(Command::DisconnectControl(key.clone()));
            return;
        }
        if queue_data(&data_tx, &queue_budget, fin).is_err() {
            self.fail_pending(
                &key,
                challenge.stream_id,
                "REVERSE_CHANNEL_UNAVAILABLE",
                "unknown",
            );
            let _ = data_tx.try_send(DataOutbound::Close);
            let _ = control_tx.try_send(ControlOutbound::Close);
            let _ = self
                .command_tx
                .try_send(Command::DisconnectControl(key.clone()));
            return;
        }
        if let Some(session) = self.session_mut(&key)
            && let Some(pending) = session.pending.get_mut(&challenge.stream_id)
        {
            let body_len = pending.body.len();
            pending.body.clear();
            pending.authorization_in_flight = false;
            pending.dispatched = true;
            session.queued_bytes = session.queued_bytes.saturating_sub(body_len);
            session.queue_budget.release(body_len);
        }
    }

    fn finish_stream_challenge(
        &mut self,
        key: SessionKey,
        challenge: DeviceChallenge,
        result: ChallengeAuthorizationResult,
    ) {
        let Some((grant, consumer_expires_at, challenge_id)) = self
            .session_for(&key)
            .and_then(|session| session.streams.get(&challenge.stream_id))
            .filter(|stream| {
                stream.authorization_in_flight
                    && !stream.terminal
                    && stream.grant.revision == challenge.grant_revision
                    && stream.service_id.to_string() == challenge.service_id
            })
            .map(|stream| {
                (
                    stream.grant.clone(),
                    stream.consumer_expires_at,
                    stream.challenge_id.clone(),
                )
            })
        else {
            return;
        };
        if challenge_id.as_deref() != Some(challenge.challenge_id.as_str()) {
            return;
        }
        let (current, owner, identity, owner_deadline) = match result {
            Ok(value) => value,
            Err(_) => {
                self.invalidate_stream_challenge(&key, &challenge, "authorization unavailable");
                return;
            }
        };
        let Some(current) = current else {
            self.invalidate_stream_challenge(&key, &challenge, "grant unavailable");
            return;
        };
        let Some(owner) = owner else {
            self.invalidate_stream_challenge(&key, &challenge, "owner unavailable");
            return;
        };
        let Some(identity) = identity else {
            self.invalidate_stream_challenge(&key, &challenge, "device authorization unavailable");
            return;
        };
        let now_wall = Utc::now();
        let valid = self.session_for(&key).is_some_and(|session| {
            owner.token == session.owner
                && identity.device_id == key.device_id
                && identity.spki_fingerprint == session.identity.spki_fingerprint
                && identity.device_version == session.identity.device_version
                && identity.owner_epoch == session.owner.epoch
                && identity.device_active
                && identity.credential_active
                && identity.credential_revoked_at.is_none()
                && identity.expires_at > now_wall
                && current.revision == challenge.grant_revision
                && wire::permission_digest(&current, &challenge.service_id)
                    == challenge.permission_digest
                && current.valid_until > now_wall
                && grant.tenant_id == current.tenant_id
                && grant.service_id == current.service_id
        });
        if !valid {
            self.invalidate_stream_challenge(&key, &challenge, "authorization changed");
            return;
        }
        let challenge_remaining = challenge
            .lifetime
            .checked_sub(challenge.received_at.elapsed())
            .unwrap_or_default();
        let snapshot_remaining = (current.valid_until - now_wall)
            .to_std()
            .unwrap_or_default();
        let token_remaining = (consumer_expires_at - now_wall)
            .to_std()
            .unwrap_or_default();
        let owner_remaining = owner_deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_default();
        let credential_remaining = (identity.expires_at - now_wall)
            .to_std()
            .unwrap_or_default();
        let remaining_ms = challenge_remaining
            .min(snapshot_remaining)
            .min(token_remaining)
            .min(owner_remaining)
            .min(credential_remaining)
            .as_millis()
            .min(5_000) as u64;
        if remaining_ms == 0 {
            self.invalidate_stream_challenge(&key, &challenge, "authorization expired");
            return;
        }
        let confirmation = wire::authorization_confirmed(wire::AuthorizationConfirmation {
            reply_to: &challenge.message_id,
            session_id: &key.session_id,
            epoch: key.epoch,
            stream_id: challenge.stream_id,
            challenge_id: &challenge.challenge_id,
            nonce: &challenge.nonce,
            permission_digest: &challenge.permission_digest,
            grant_revision: challenge.grant_revision,
            remaining_ms,
        });
        if self.send_control(&key, confirmation).is_err() {
            self.invalidate_stream_challenge(&key, &challenge, "control unavailable");
            return;
        }
        let pending = if let Some(session) = self.session_mut(&key)
            && let Some(stream) = session.streams.get_mut(&challenge.stream_id)
        {
            stream.authorization_in_flight = false;
            stream.authorized_until = Some(Instant::now() + Duration::from_millis(remaining_ms));
            stream.challenge_id = Some(challenge.challenge_id);
            stream.grant = current;
            let pending_bytes = stream.pending_record_bytes;
            stream.pending_record_bytes = 0;
            session.queue_budget.release(pending_bytes);
            stream.budget_bytes = stream.budget_bytes.saturating_sub(pending_bytes);
            std::mem::take(&mut stream.pending_records)
        } else {
            VecDeque::new()
        };
        let operation_id = self
            .session_for(&key)
            .and_then(|session| session.streams.get(&challenge.stream_id))
            .map(|stream| stream.operation_id.clone())
            .unwrap_or_default();
        for (body, waiter) in pending {
            self.write_echo_stream(
                key.clone(),
                challenge.stream_id,
                operation_id.clone(),
                body,
                waiter,
            );
        }
    }

    fn invalidate_stream_challenge(
        &mut self,
        key: &SessionKey,
        challenge: &DeviceChallenge,
        reason: &str,
    ) {
        let _ = self.send_control(
            key,
            wire::authorization_invalidated(
                &key.session_id,
                key.epoch,
                challenge.stream_id,
                &challenge.challenge_id,
                challenge.grant_revision,
                reason,
            ),
        );
        if let Some(session) = self.session_mut(key)
            && let Some(stream) = session.streams.get_mut(&challenge.stream_id)
        {
            stream.authorization_in_flight = false;
            stream.authorized_until = None;
            stream.terminal = true;
            let pending_bytes = stream.pending_record_bytes;
            stream.pending_record_bytes = 0;
            let response_bytes = stream.response_bytes.len();
            stream.response_bytes.clear();
            session
                .queue_budget
                .release(pending_bytes.saturating_add(response_bytes));
            stream.budget_bytes = stream
                .budget_bytes
                .saturating_sub(pending_bytes.saturating_add(response_bytes));
            for (_, waiter) in std::mem::take(&mut stream.pending_records) {
                let _ = waiter.send(Err(EchoOutcome::Failure {
                    code: "AUTHORIZATION_REVOKED",
                    execution: "not_dispatched",
                }));
            }
            for waiter in std::mem::take(&mut stream.response_records) {
                let _ = waiter.send(Err(EchoOutcome::Failure {
                    code: "AUTHORIZATION_REVOKED",
                    execution: "unknown",
                }));
            }
            stream.closed.cancel();
        }
    }

    async fn inbound_data(&mut self, carrier: CarrierKey, bytes: Vec<u8>) {
        let key = carrier.session.clone();
        if bytes.len() > tunnel_protocol::frame::MAX_FRAME_LEN {
            return self.protocol_failure(&key, "FRAME_LIMIT").await;
        }
        let frame = match wire::decode_frame(&bytes) {
            Ok(frame) => frame,
            Err(_) => return self.protocol_failure(&key, "INVALID_FRAME").await,
        };
        let Some(session) = self.session_for(&key) else {
            return;
        };
        if frame.epoch != key.epoch
            || frame.generation != carrier.generation
            || frame.generation != session.generation
                && session
                    .active_carrier
                    .as_ref()
                    .is_some_and(|active| active.context.connection_id == carrier.connection_id)
        {
            return self.protocol_failure(&key, "STALE_DATA").await;
        }
        let carrier_is_active = session
            .active_carrier
            .as_ref()
            .is_some_and(|active| active.context == carrier.context());
        let carrier_is_candidate = session
            .rotation
            .as_ref()
            .and_then(|rotation| rotation.candidate.as_ref())
            .is_some_and(|candidate| candidate.context == carrier.context());
        if !carrier_is_active && !carrier_is_candidate {
            // Delayed bytes from a retired generation are ignored at the
            // carrier boundary; they cannot reach stream state.
            return;
        }
        if session.profile.supports_rotation()
            && self
                .session_for(&key)
                .is_some_and(|session| session.streams.contains_key(&frame.stream_id))
        {
            self.inbound_m2_stream_data(carrier, frame, carrier_is_candidate)
                .await;
            return;
        }
        let stream_id = frame.stream_id;
        let max_response_bytes = self
            .options
            .limits
            .max_body_bytes
            .saturating_add(MAX_ECHO_RESPONSE_EXTRA_BYTES);
        match frame.kind {
            FrameKind::Data | FrameKind::Fin => {
                if !self
                    .session_for(&key)
                    .is_some_and(|session| session.pending.contains_key(&stream_id))
                {
                    return self.protocol_failure(&key, "UNKNOWN_STREAM").await;
                }
                let (update, data_tx, queue_budget, tenant_id, operation_id) = {
                    let Some(session) = self.session_mut(&key) else {
                        return;
                    };
                    let Some(pending) = session.pending.get_mut(&stream_id) else {
                        return;
                    };
                    let data_tx = if carrier_is_candidate {
                        session
                            .rotation
                            .as_ref()
                            .and_then(|rotation| rotation.candidate.as_ref())
                            .map(|candidate| candidate.tx.clone())
                    } else {
                        session.data_tx.clone()
                    };
                    let queue_budget = session.queue_budget.clone();
                    let tenant_id = session.identity.tenant_id;
                    let operation_id = pending.operation_id.clone();
                    let invalid_frame = !pending.dispatched
                        || frame.ack > pending.send_sequence.saturating_add(1)
                        || frame.sequence <= pending.response_sequence
                        || frame.sequence != pending.response_sequence.saturating_add(1)
                        || (frame.kind == FrameKind::Data
                            && (pending
                                .response_body
                                .len()
                                .saturating_add(frame.payload.len())
                                > max_response_bytes
                                || !queue_budget.reserve(frame.payload.len())));
                    if invalid_frame {
                        (
                            ResponseFrameUpdate::Invalid,
                            data_tx,
                            queue_budget,
                            tenant_id,
                            operation_id,
                        )
                    } else {
                        pending.response_sequence = frame.sequence;
                        if frame.kind == FrameKind::Data {
                            pending.response_body.extend_from_slice(&frame.payload);
                            (
                                ResponseFrameUpdate::Accepted,
                                data_tx,
                                queue_budget,
                                tenant_id,
                                operation_id,
                            )
                        } else {
                            let body = std::mem::take(&mut pending.response_body);
                            let pending = session
                                .pending
                                .remove(&stream_id)
                                .expect("pending entry exists");
                            let released = pending.body.len().saturating_add(body.len());
                            session.queued_bytes = session.queued_bytes.saturating_sub(released);
                            session.queue_budget.release(released);
                            (
                                ResponseFrameUpdate::Complete(body, pending.response),
                                data_tx,
                                queue_budget,
                                tenant_id,
                                operation_id,
                            )
                        }
                    }
                };
                if matches!(&update, ResponseFrameUpdate::Accepted)
                    && let Some(session) = self.session_mut(&key)
                {
                    session.queued_bytes = session.queued_bytes.saturating_add(frame.payload.len());
                }
                let ack_sequence = match &update {
                    ResponseFrameUpdate::Accepted | ResponseFrameUpdate::Complete(_, _) => {
                        frame.sequence
                    }
                    ResponseFrameUpdate::Invalid => {
                        self.protocol_failure(&key, "INVALID_SEQUENCE").await;
                        return;
                    }
                };
                let Some(data_tx) = data_tx else {
                    if let ResponseFrameUpdate::Complete(_, response) = update {
                        let _ = response.send(EchoOutcome::Failure {
                            code: "DEVICE_OFFLINE",
                            execution: "unknown",
                        });
                    }
                    self.protocol_failure(&key, "DEVICE_OFFLINE").await;
                    return;
                };
                let Ok(ack) = tunnel_protocol::Frame::ack(
                    key.epoch,
                    carrier.generation,
                    stream_id,
                    ack_sequence,
                )
                .encode() else {
                    self.protocol_failure(&key, "FRAME_LIMIT").await;
                    return;
                };
                if queue_data(&data_tx, &queue_budget, ack).is_err() {
                    if let ResponseFrameUpdate::Complete(_, response) = update {
                        let _ = response.send(EchoOutcome::Failure {
                            code: "REVERSE_CHANNEL_UNAVAILABLE",
                            execution: "unknown",
                        });
                    }
                    self.protocol_failure(&key, "REVERSE_CHANNEL_UNAVAILABLE")
                        .await;
                    return;
                }
                if let ResponseFrameUpdate::Complete(body, response) = update {
                    let response_bytes = body.len();
                    let _ = response.send(EchoOutcome::Success(body));
                    tracing::debug!(
                        tenant_id = %tenant_id,
                        device_id = %key.device_id,
                        session_id = %key.session_id,
                        epoch = key.epoch,
                        stream_id,
                        operation_id = %operation_id,
                        bytes = response_bytes,
                        phase = "stream_completed",
                    );
                }
            }
            FrameKind::Ack => {
                let stale_ack = self
                    .session_for(&key)
                    .and_then(|session| session.pending.get(&stream_id))
                    .is_some_and(|pending| {
                        !pending.dispatched || frame.ack > pending.send_sequence.saturating_add(1)
                    });
                if stale_ack {
                    self.protocol_failure(&key, "STALE_ACK").await;
                }
            }
            FrameKind::WindowUpdate => {
                // M1 has no receive-window state to update; the bounded queue is
                // governed by the per-session budget and the frame size limit.
            }
            FrameKind::Reset => {
                let valid_reset = self
                    .session_for(&key)
                    .and_then(|session| session.pending.get(&stream_id))
                    .is_some_and(|pending| {
                        pending.dispatched
                            && frame.ack <= pending.send_sequence.saturating_add(1)
                            && pending.response_sequence.checked_add(1) == Some(frame.sequence)
                    });
                if valid_reset {
                    self.fail_pending(&key, stream_id, "DEVICE_RESET", "unknown");
                } else {
                    self.protocol_failure(&key, "INVALID_RESET").await;
                }
            }
        }
    }

    /// Apply one connector-to-relay M2 frame to the pure stream state, parse
    /// complete length-prefixed response records, and acknowledge receipt on
    /// the same physical carrier.  This method never waits for a consumer or
    /// socket writer; both response delivery and ACKs use bounded channels.
    async fn inbound_m2_stream_data(
        &mut self,
        carrier: CarrierKey,
        frame: Frame,
        carrier_is_candidate: bool,
    ) {
        let key = carrier.session.clone();
        let mut invalid = false;
        let mut deferred_rejected = false;
        let deferred_limit = self.options.limits.max_queue_messages;
        let mut queue: Option<(mpsc::Sender<DataOutbound>, QueueBudget, Vec<u8>)> = None;
        let mut window_queue: Option<(mpsc::Sender<DataOutbound>, QueueBudget, Vec<u8>)> = None;
        let mut released_receive_bytes = 0usize;
        let mut replayed_inbound = false;
        'data: {
            let Some(session) = self.session_mut(&key) else {
                return;
            };
            let defer_candidate_data = carrier_is_candidate
                && matches!(
                    frame.kind,
                    FrameKind::Data | FrameKind::Fin | FrameKind::Reset
                )
                && session
                    .rotation
                    .as_ref()
                    .and_then(|rotation| rotation.recovery.as_ref())
                    .is_some_and(|recovery| {
                        if recovery.activated {
                            return false;
                        }
                        let immutable_fence = recovery.remote_snapshots
                            [direction_index(Direction::ConnectorToRelay)]
                        .get(&frame.stream_id)
                        .map(|entry| entry.last_emitted);
                        let beyond_fence = immutable_fence
                            .is_none_or(|last_emitted| frame.sequence > last_emitted);
                        if !beyond_fence {
                            return false;
                        }
                        // New DATA beyond the connector's immutable
                        // snapshot is legal only after the coordinator has
                        // issued both READY decisions.  Before that point a
                        // frame would be an unaccounted application write.
                        recovery.ready_sent == [true, true]
                    });
            if carrier_is_candidate
                && matches!(
                    frame.kind,
                    FrameKind::Data | FrameKind::Fin | FrameKind::Reset
                )
                && !defer_candidate_data
                && session
                    .rotation
                    .as_ref()
                    .and_then(|rotation| rotation.recovery.as_ref())
                    .is_some_and(|recovery| {
                        !recovery.activated
                            && recovery.remote_snapshots
                                [direction_index(Direction::ConnectorToRelay)]
                            .get(&frame.stream_id)
                            .is_none_or(|entry| frame.sequence > entry.last_emitted)
                            && recovery.ready_sent != [true, true]
                    })
            {
                deferred_rejected = true;
                break 'data;
            }
            if defer_candidate_data {
                let queue_budget = session.queue_budget.clone();
                let input_bytes = frame.payload.len();
                let deferred_available = session
                    .rotation
                    .as_ref()
                    .and_then(|rotation| rotation.recovery.as_ref())
                    .is_some_and(|recovery| recovery.deferred_frames.len() < deferred_limit);
                let Some(stream) = session.streams.get_mut(&frame.stream_id) else {
                    return;
                };
                let can_charge =
                    deferred_available && reserve_m2_bytes(&queue_budget, stream, input_bytes);
                if !can_charge {
                    deferred_rejected = true;
                } else if let Some(rotation) = session.rotation.as_mut()
                    && let Some(recovery) = rotation.recovery.as_mut()
                {
                    recovery.deferred_bytes = recovery.deferred_bytes.saturating_add(input_bytes);
                    recovery
                        .deferred_frames
                        .push_back((carrier, frame, input_bytes));
                }
                if !deferred_rejected {
                    return;
                }
                break 'data;
            }
            let data_tx = if carrier_is_candidate {
                session
                    .rotation
                    .as_ref()
                    .and_then(|rotation| rotation.candidate.as_ref())
                    .map(|candidate| candidate.tx.clone())
            } else {
                session.data_tx.clone()
            };
            let Some(data_tx) = data_tx else {
                return;
            };
            let queue_budget = session.queue_budget.clone();
            let input_bytes = frame.payload.len();
            let is_retained_replay = carrier_is_candidate
                && matches!(
                    frame.kind,
                    FrameKind::Data | FrameKind::Fin | FrameKind::Reset
                )
                && session
                    .rotation
                    .as_ref()
                    .and_then(|rotation| rotation.recovery.as_ref())
                    .and_then(|recovery| {
                        recovery.remote_snapshots[direction_index(Direction::ConnectorToRelay)]
                            .get(&frame.stream_id)
                    })
                    .is_some_and(|entry| frame.sequence <= entry.last_emitted);
            let Some(stream) = session.streams.get_mut(&frame.stream_id) else {
                return;
            };
            let charged_input = reserve_m2_bytes(&queue_budget, stream, input_bytes);
            let replay_before = stream
                .sequence
                .direction(Direction::RelayToConnector)
                .replay_bytes();
            let disposition = if !charged_input {
                invalid = true;
                ReceiveDisposition::Duplicate
            } else {
                match stream
                    .sequence
                    .receive_frame(Direction::ConnectorToRelay, &frame)
                {
                    Ok(disposition) => disposition,
                    Err(error) => {
                        let receive = stream
                            .sequence
                            .direction(Direction::ConnectorToRelay)
                            .snapshot();
                        let send = stream
                            .sequence
                            .direction(Direction::RelayToConnector)
                            .snapshot();
                        tracing::warn!(
                            device_id = %key.device_id,
                            session_id = %key.session_id,
                            epoch = key.epoch,
                            stream_id = frame.stream_id,
                            carrier_generation = carrier.generation,
                            carrier_connection_id = %carrier.connection_id,
                            frame_kind = ?frame.kind,
                            frame_sequence = frame.sequence,
                            frame_ack = frame.ack,
                            receive_contiguous = receive.recv_contiguous,
                            send_last_emitted = send.last_emitted,
                            error = %error,
                            stage = "m2_receive_sequence",
                        );
                        invalid = true;
                        ReceiveDisposition::Duplicate
                    }
                }
            };
            let replay_after = stream
                .sequence
                .direction(Direction::RelayToConnector)
                .replay_bytes();
            if replay_before > replay_after {
                release_m2_bytes(&queue_budget, stream, replay_before - replay_after);
            }
            if charged_input && (disposition == ReceiveDisposition::Duplicate || invalid) {
                release_m2_bytes(&queue_budget, stream, input_bytes);
            }
            if !invalid && disposition != ReceiveDisposition::Duplicate {
                replayed_inbound = is_retained_replay;
                let ready = stream.sequence.ready_frames(Direction::ConnectorToRelay);
                let mut delivered_through = None;
                for ready_frame in ready {
                    delivered_through = Some(ready_frame.sequence);
                    if ready_frame.kind == FrameKind::Data {
                        if stream
                            .response_bytes
                            .len()
                            .saturating_add(ready_frame.payload.len())
                            > wire::MAX_BODY_BYTES
                                .saturating_add(MAX_ECHO_RESPONSE_EXTRA_BYTES)
                                .saturating_add(4)
                        {
                            invalid = true;
                            break;
                        }
                        stream
                            .response_bytes
                            .extend_from_slice(&ready_frame.payload);
                    }
                    if ready_frame.kind == FrameKind::Fin {
                        stream.terminal = true;
                    }
                }
                if let Some(through) = delivered_through
                    && stream
                        .sequence
                        .mark_delivered(Direction::ConnectorToRelay, through)
                        .is_err()
                {
                    invalid = true;
                }
                while !invalid && stream.response_bytes.len() >= 4 {
                    let declared = u32::from_be_bytes([
                        stream.response_bytes[0],
                        stream.response_bytes[1],
                        stream.response_bytes[2],
                        stream.response_bytes[3],
                    ]) as usize;
                    if declared > wire::MAX_BODY_BYTES.saturating_add(MAX_ECHO_RESPONSE_EXTRA_BYTES)
                    {
                        invalid = true;
                        break;
                    }
                    let total = match declared.checked_add(4) {
                        Some(total) => total,
                        None => {
                            invalid = true;
                            break;
                        }
                    };
                    if stream.response_bytes.len() < total {
                        break;
                    }
                    let record: Vec<u8> = stream.response_bytes.drain(..total).collect();
                    let Some(waiter) = stream.response_records.pop_front() else {
                        invalid = true;
                        break;
                    };
                    release_m2_bytes(&queue_budget, stream, total);
                    stream.receive_bytes = stream.receive_bytes.saturating_add(declared);
                    released_receive_bytes = match released_receive_bytes.checked_add(total) {
                        Some(bytes) => bytes,
                        None => {
                            invalid = true;
                            break;
                        }
                    };
                    let _ = waiter.send(Ok(record));
                }
            }
            if !invalid {
                let ack_sequence = stream
                    .sequence
                    .direction(Direction::ConnectorToRelay)
                    .recv_contiguous();
                let ack = Frame::ack(key.epoch, carrier.generation, frame.stream_id, ack_sequence);
                if let Ok(bytes) = ack.encode() {
                    queue = Some((data_tx.clone(), queue_budget.clone(), bytes));
                } else {
                    invalid = true;
                }
                if released_receive_bytes > 0 {
                    let released = match u64::try_from(released_receive_bytes) {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            invalid = true;
                            0
                        }
                    };
                    let current_credit = stream
                        .sequence
                        .direction(Direction::ConnectorToRelay)
                        .receive_credit();
                    let limit = match current_credit.checked_add(released) {
                        Some(limit) => limit,
                        None => {
                            invalid = true;
                            0
                        }
                    };
                    let update =
                        Frame::window_update(key.epoch, carrier.generation, frame.stream_id, limit);
                    if !invalid
                        && stream
                            .sequence
                            .send_frame(Direction::RelayToConnector, &update)
                            .is_ok()
                    {
                        match update.encode() {
                            Ok(bytes) => {
                                window_queue = Some((data_tx, queue_budget, bytes));
                            }
                            Err(_) => invalid = true,
                        }
                    }
                }
            }
        }
        if deferred_rejected {
            self.protocol_failure(&key, "RECOVERY_QUEUE_LIMIT").await;
            return;
        }
        if invalid {
            self.protocol_failure(&key, "INVALID_SEQUENCE").await;
            return;
        }
        if replayed_inbound && let Some(session) = self.session_mut(&key) {
            if let Some(rotation) = session.rotation.as_mut() {
                rotation.replayed_frames = rotation.replayed_frames.saturating_add(1);
            }
            session.total_replayed_frames = session.total_replayed_frames.saturating_add(1);
        }
        if let Some((data_tx, budget, bytes)) = queue
            && queue_data(&data_tx, &budget, bytes).is_err()
        {
            self.protocol_failure(&key, "REVERSE_CHANNEL_UNAVAILABLE")
                .await;
            return;
        }
        if let Some((data_tx, budget, bytes)) = window_queue
            && queue_data(&data_tx, &budget, bytes).is_err()
        {
            self.protocol_failure(&key, "REVERSE_CHANNEL_UNAVAILABLE")
                .await;
            return;
        }
        if carrier_is_candidate
            && self.session_for(&key).is_some_and(|session| {
                session
                    .rotation
                    .as_ref()
                    .is_some_and(|rotation| rotation.recovery.is_some())
            })
            && let Err(error) = self.send_recovery_ready(&key)
        {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                stage = "recovery_ready_after_frame",
                error = %error,
            );
            self.close_session(&key, "RECOVERY_READY_FAILED").await;
            return;
        }
        if let Err(error) = self.progress_rotation_drain(&key) {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                phase = ?self
                    .session_for(&key)
                    .and_then(|session| session.rotation.as_ref())
                    .map(|rotation| rotation.state.phase()),
                stage = "drain_progress_after_data",
                error = %error,
            );
        }
    }

    fn cancel(&mut self, key: &SessionKey, stream_id: u64, operation_id: String) {
        if let Some(session) = self.session_mut(key)
            && session
                .pending
                .get(&stream_id)
                .is_some_and(|pending| pending.operation_id == operation_id)
            && let Some(pending) = session.pending.remove(&stream_id)
        {
            release_pending_budget(session, &pending);
            let _ = pending.response.send(EchoOutcome::Failure {
                code: "CANCELLED",
                execution: "unknown",
            });
            if let Ok(message) = wire::encode_control_message(&wire::cancel(
                &key.session_id,
                key.epoch,
                stream_id,
                &operation_id,
            )) {
                let _ = queue_control(&session.control_tx, &session.queue_budget, message);
            }
        }
    }

    async fn tick(&mut self) {
        let now = Instant::now();
        let keys: Vec<_> = self
            .sessions
            .values()
            .map(|session| session.key.clone())
            .collect();
        for key in keys {
            if self.poll_rotation_deadline(&key) {
                self.close_session(&key, "ROTATION_DEADLINE_EXPIRED").await;
                continue;
            }
            self.poll_rotation_barrier(&key);
            if let Err(error) = self.progress_rotation_drain(&key) {
                tracing::warn!(
                    device_id = %key.device_id,
                    session_id = %key.session_id,
                    epoch = key.epoch,
                    phase = ?self
                        .session_for(&key)
                        .and_then(|session| session.rotation.as_ref())
                        .map(|rotation| rotation.state.phase()),
                    stage = "drain_progress_tick",
                    error = %error,
                );
            }
            let rotation_due = self.session_for(&key).is_some_and(|session| {
                session.profile.supports_rotation()
                    && session.data_tx.is_some()
                    && session.rotation.as_ref().is_some_and(|rotation| {
                        matches!(rotation.state.phase(), RotationPhase::Active)
                            && session.last_rotation.elapsed()
                                >= Duration::from_millis(
                                    rotation.state.config().rotation_interval_ms,
                                )
                    })
            });
            if rotation_due {
                let _ = self.start_rotation(&key, None, "policy_timer");
            }
            let expired: Vec<_> = self
                .session_for(&key)
                .map(|session| {
                    session
                        .pending
                        .iter()
                        .filter(|(_, pending)| {
                            pending.response.is_closed()
                                || pending.created_at.elapsed()
                                    > self.options.limits.operation_timeout
                        })
                        .map(|(stream_id, _)| *stream_id)
                        .collect()
                })
                .unwrap_or_default();
            for stream_id in expired {
                self.fail_pending(&key, stream_id, "REVERSE_CHANNEL_INTERRUPTED", "unknown");
            }
            let Some(snapshot) = self.session_for(&key).map(|session| {
                (
                    session.identity.spki_fingerprint.clone(),
                    session.identity.device_version,
                    session.owner.clone(),
                    session.last_lease_renewal,
                    session.maintenance_in_flight,
                )
            }) else {
                continue;
            };
            if snapshot.4 {
                continue;
            }
            if let Some(session) = self.session_mut(&key) {
                session.maintenance_in_flight = true;
            }
            let catalog = self.catalog.clone();
            let command_tx = self.command_tx.clone();
            let owner_lease = self.options.owner_lease;
            let renew = snapshot.3.elapsed() >= owner_lease / 3;
            tokio::spawn(async move {
                let renewed = if renew {
                    let lease_expires_at = Utc::now()
                        + ChronoDuration::from_std(owner_lease)
                            .unwrap_or_else(|_| ChronoDuration::seconds(30));
                    Some(
                        catalog
                            .renew_owner(&snapshot.2, lease_expires_at)
                            .await
                            .map_err(|error| error.to_string()),
                    )
                } else {
                    None
                };
                let identity = catalog
                    .resolve_device(&snapshot.0, Utc::now())
                    .await
                    .map_err(|error| error.to_string());
                let _ = command_tx
                    .send(Command::MaintenanceResult {
                        key,
                        renewed,
                        identity,
                    })
                    .await;
            });
        }
        let wall_now = Utc::now();
        self.tickets.retain(|_, ticket| {
            ticket.expires_at > now
                && wall_now >= ticket.issued_at_wall
                && wall_now < ticket.expires_at_wall
        });
    }

    async fn finish_maintenance(
        &mut self,
        key: SessionKey,
        renewed: Option<Result<bool, String>>,
        identity: Result<Option<DeviceIdentity>, String>,
    ) {
        let mut close_reason = None;
        if let Some(session) = self.sessions.get_mut(&key.device_id) {
            if session.key != key {
                return;
            }
            session.maintenance_in_flight = false;
            if let Some(renewed) = renewed {
                match renewed {
                    Ok(true) => session.last_lease_renewal = Instant::now(),
                    _ => close_reason = Some("OWNER_FENCED"),
                }
            }
            match identity {
                Ok(Some(current))
                    if current.device_id == key.device_id
                        && current.device_version == session.identity.device_version
                        && current.spki_fingerprint == session.identity.spki_fingerprint
                        && current.device_active
                        && current.credential_active
                        && current.credential_revoked_at.is_none() => {}
                _ => {
                    if close_reason.is_none() {
                        close_reason = Some("AUTHORIZATION_REVOKED");
                    }
                }
            };
        }
        if let Some(reason) = close_reason {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                reason = %reason,
                phase = "owner_check_failed",
            );
            self.close_session(&key, reason).await;
        }
    }

    async fn disconnect_control(&mut self, key: SessionKey) {
        let matches = self
            .sessions
            .get(&key.device_id)
            .is_some_and(|session| session.key == key);
        if !matches {
            return;
        }
        self.close_session(&key, "CONTROL_CLOSED").await;
    }

    async fn disconnect_data(&mut self, carrier: CarrierKey) {
        let key = carrier.session.clone();
        let mut old_closed = false;
        let mut active_lost = false;
        let mut recovery_candidate_lost = false;
        let mut candidate_abort: Option<(RotationAttemptIdentity, String, u64)> = None;
        let mut candidate_failure = false;
        if let Some(session) = self.sessions.get_mut(&key.device_id) {
            if session.key != key {
                return;
            }
            let active = session
                .active_carrier
                .as_ref()
                .is_some_and(|active| active.context == carrier.context());
            let candidate = session
                .rotation
                .as_ref()
                .and_then(|rotation| rotation.candidate.as_ref())
                .is_some_and(|candidate| candidate.context == carrier.context());
            let retiring_old = session.rotation.as_ref().is_some_and(|rotation| {
                rotation.old_connection_id == carrier.connection_id
                    && matches!(rotation.state.phase(), RotationPhase::Retiring)
            });
            if !active && !candidate && !retiring_old {
                return;
            }
            if active {
                session.data_tx = None;
                session.active_carrier = None;
                active_lost = true;
            }
            if candidate && let Some(rotation) = session.rotation.as_mut() {
                if rotation.recovery.is_some() {
                    // Recovery retries carry the immutable episode roster and
                    // close evidence into a fresh attempt.  They never reuse
                    // this candidate's generation or connection identity.
                    rotation.candidate = None;
                    recovery_candidate_lost = true;
                } else {
                    let now_ms = monotonic_millis();
                    let phase = rotation.state.phase();
                    let known_uncommitted = matches!(
                        phase,
                        RotationPhase::Preparing
                            | RotationPhase::Quiescing
                            | RotationPhase::Draining
                            | RotationPhase::Aborting
                    );
                    if let Some(attempt) = rotation.attempt.clone() {
                        if !known_uncommitted {
                            // Once COMMIT has been sent or accepted, a vanished
                            // candidate is ambiguous.  Do not restore the old
                            // carrier or silently continue with a partial handover.
                            candidate_failure = true;
                            rotation.candidate = None;
                        } else {
                            if phase != RotationPhase::Aborting
                                && rotation
                                    .state
                                    .abort(&attempt, now_ms, RecoveryReason::CandidateTransportLost)
                                    .is_err()
                            {
                                candidate_failure = true;
                            }
                            if !candidate_failure
                                && rotation
                                    .state
                                    .candidate_closed(
                                        &attempt,
                                        RotationSide::Owner,
                                        ClosureEvidence::closed(carrier.connection_id.clone()),
                                        now_ms,
                                    )
                                    .is_err()
                            {
                                candidate_failure = true;
                            }
                            rotation.candidate = None;
                            if !candidate_failure && phase != RotationPhase::Aborting {
                                let remaining_ms = rotation
                                    .state
                                    .status()
                                    .deadline_ms
                                    .unwrap_or(now_ms)
                                    .saturating_sub(now_ms);
                                // Physical candidate loss is an unsolicited
                                // owner decision.  It must not reuse a peer
                                // phase id that may already have a cached
                                // DRAINED reply; an empty reply_to keeps the
                                // abort journal-independent.
                                candidate_abort = Some((attempt, String::new(), remaining_ms));
                            }
                        }
                    } else {
                        candidate_failure = true;
                        // There is no authenticated attempt identity to
                        // coordinate a bilateral abort with.
                        rotation.candidate = None;
                    }
                }
            }
            if retiring_old {
                let attempt = session
                    .rotation
                    .as_ref()
                    .and_then(|rotation| rotation.attempt.clone());
                if let Some(attempt) = attempt
                    && let Some(rotation) = session.rotation.as_mut()
                {
                    old_closed = rotation
                        .state
                        .old_socket_closed(
                            &attempt,
                            RotationSide::Owner,
                            ClosureEvidence::closed(carrier.connection_id.clone()),
                            monotonic_millis(),
                        )
                        .is_ok();
                }
            }
            if active {
                let pending = std::mem::take(&mut session.pending);
                session.queued_bytes = 0;
                for (_, pending) in pending {
                    release_pending_budget(session, &pending);
                    let _ = pending.response.send(EchoOutcome::Failure {
                        code: "REVERSE_CHANNEL_INTERRUPTED",
                        execution: "unknown",
                    });
                }
            }
        }
        if let Some((attempt, reply_to, remaining_ms)) = candidate_abort {
            if remaining_ms == 0 {
                candidate_failure = true;
            } else {
                let message = wire::rotate_abort(
                    &reply_to,
                    attempt,
                    "candidate transport lost",
                    remaining_ms,
                );
                match wire::encode_control_message(&message) {
                    Ok(encoded) => {
                        let queued = self
                            .session_for(&key)
                            .map(|session| {
                                queue_control(
                                    &session.control_tx,
                                    &session.queue_budget,
                                    encoded.clone(),
                                )
                                .is_ok()
                            })
                            .unwrap_or(false);
                        if queued {
                            if let Some(session) = self.session_mut(&key)
                                && let Some(rotation) = session.rotation.as_mut()
                            {
                                if Self::complete_rotation_reply(rotation, &message, &encoded)
                                    .is_err()
                                {
                                    candidate_failure = true;
                                } else {
                                    rotation.abort_message_id =
                                        Some(message.message_id().to_owned());
                                    rotation.last_message_id = message.message_id().to_owned();
                                }
                            } else {
                                candidate_failure = true;
                            }
                        } else {
                            candidate_failure = true;
                        }
                    }
                    Err(_) => {
                        // The message is bounded by the wire encoder; an
                        // encode failure cannot be recovered by retrying this
                        // attempt.
                        candidate_failure = true;
                    }
                }
            }
        }
        if candidate_failure {
            self.close_session(&key, "ROTATION_CANDIDATE_FAILED").await;
            return;
        }
        if let Err(error) = self.finish_rotation_abort_if_ready(&key) {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                stage = "owner_aborted_after_candidate_close",
                error = %error,
            );
        }
        if old_closed {
            self.finish_rotation_if_ready(&key);
        }
        if active_lost
            && self
                .session_for(&key)
                .is_some_and(|session| session.profile.supports_rotation())
            && !self.begin_recovery_after_loss(&key, &carrier.connection_id)
        {
            self.close_session(&key, "RECOVERY_START_FAILED").await;
        }
        if recovery_candidate_lost
            && !self.retry_recovery_after_candidate_loss(&key, &carrier.connection_id)
        {
            self.close_session(&key, "RECOVERY_CANDIDATE_FAILED").await;
        }
    }

    async fn close_session(&mut self, key: &SessionKey, reason: &str) {
        if !self
            .sessions
            .get(&key.device_id)
            .is_some_and(|session| session.key == *key)
        {
            return;
        }
        let Some(mut session) = self.sessions.remove(&key.device_id) else {
            return;
        };
        if session.closed {
            return;
        }
        session.closed = true;
        tracing::info!(
            tenant_id = %session.identity.tenant_id,
            device_id = %key.device_id,
            session_id = %key.session_id,
            epoch = key.epoch,
            reason = %reason,
            phase = "session_closed",
        );
        let rejected = wire::rejected(
            &wire::random_token(),
            &session.key.session_id,
            session.key.epoch,
            1,
            "session",
            reason,
            "device session closed",
        );
        if let Ok(text) = wire::encode_control_message(&rejected) {
            let _ = queue_control(&session.control_tx, &session.queue_budget, text);
        }
        let _ = session.control_tx.try_send(ControlOutbound::Close);
        if let Some(data) = session.data_tx.take() {
            let _ = data.try_send(DataOutbound::Close);
        }
        if let Some(rotation) = session.rotation.as_ref()
            && let Some(candidate) = rotation.candidate.as_ref()
        {
            let _ = candidate.tx.try_send(DataOutbound::Close);
        }
        let queue_budget = session.queue_budget.clone();
        for (_, pending) in session.pending.drain() {
            let bytes = pending
                .body
                .len()
                .saturating_add(pending.response_body.len());
            queue_budget.release(bytes);
            let _ = pending.response.send(EchoOutcome::Failure {
                code: "REVERSE_CHANNEL_INTERRUPTED",
                execution: "unknown",
            });
        }
        for (_, mut stream) in session.streams.drain() {
            stream.closed.cancel();
            queue_budget.release(stream.budget_bytes);
            stream.budget_bytes = 0;
            for (_, waiter) in stream.pending_records.drain(..) {
                let _ = waiter.send(Err(EchoOutcome::Failure {
                    code: "REVERSE_CHANNEL_INTERRUPTED",
                    execution: "unknown",
                }));
            }
            for waiter in stream.response_records.drain(..) {
                let _ = waiter.send(Err(EchoOutcome::Failure {
                    code: "REVERSE_CHANNEL_INTERRUPTED",
                    execution: "unknown",
                }));
            }
        }
        self.tickets
            .retain(|_, ticket| ticket.session_id != key.session_id || ticket.epoch != key.epoch);
        let catalog = self.catalog.clone();
        let owner = session.owner.clone();
        self.cleanup_tasks.push(tokio::spawn(async move {
            let _ = catalog.release_owner(&owner).await;
        }));
    }

    async fn close_all(&mut self) {
        let keys: Vec<_> = self
            .sessions
            .values()
            .map(|session| session.key.clone())
            .collect();
        for key in keys {
            self.close_session(&key, "SHUTDOWN").await;
        }
        self.tickets.clear();
        while let Some(task) = self.cleanup_tasks.pop() {
            let _ = task.await;
        }
    }

    async fn protocol_failure(&mut self, key: &SessionKey, code: &str) {
        self.close_session(key, code).await;
    }

    fn snapshot(&self) -> RelaySnapshot {
        let mut sessions = Vec::with_capacity(self.sessions.len());
        for session in self.sessions.values() {
            let status = session
                .rotation
                .as_ref()
                .map(|rotation| rotation.state.status());
            let phase = status
                .as_ref()
                .map(|status| runtime::phase_name(status.phase))
                .unwrap_or_else(|| "active".to_owned());
            let active_generation = status
                .as_ref()
                .map_or(session.generation, |status| status.active_generation);
            let active_connection_id = status.as_ref().map_or_else(
                || session.connection_id.clone(),
                |status| status.active_connection_id.clone(),
            );
            let (candidate_generation, candidate_connection_id) = status
                .as_ref()
                .and_then(|status| status.attempt.as_ref())
                .map(|attempt| {
                    (
                        Some(attempt.new_generation),
                        Some(attempt.new_connection_id.clone()),
                    )
                })
                .unwrap_or((None, None));
            let drain_fences = status.as_ref().map_or(0, |status| {
                status
                    .writers_frozen
                    .iter()
                    .filter(|frozen| **frozen)
                    .count()
            });
            let drain_proofs = status.as_ref().map_or(0, |status| {
                status.drain_proofs.iter().filter(|proof| **proof).count()
            });
            let sockets = status
                .as_ref()
                .map_or(if session.data_tx.is_some() { 2 } else { 1 }, |status| {
                    status.socket_count
                });
            let mut streams = Vec::with_capacity(session.pending.len() + session.streams.len());
            let mut replay_frames = 0usize;
            let mut replay_bytes = 0usize;
            for (stream_id, pending) in &session.pending {
                streams.push(RelayStreamSnapshot {
                    stream_id: *stream_id,
                    operation_id: pending.operation_id.clone(),
                    last_emitted_relay_to_connector: pending.send_sequence,
                    peer_acked_relay_to_connector: 0,
                    recv_contiguous_connector_to_relay: pending.response_sequence,
                    delivered_contiguous_connector_to_relay: pending.response_sequence,
                    replay_frames_relay_to_connector: 0,
                    replay_bytes_relay_to_connector: 0,
                    queue_bytes: pending
                        .body
                        .len()
                        .saturating_add(pending.response_body.len()),
                    terminal: false,
                });
            }
            for (stream_id, stream) in &session.streams {
                let stream_snapshot = stream.sequence.snapshot();
                let relay = stream_snapshot.direction(Direction::RelayToConnector);
                let connector = stream_snapshot.direction(Direction::ConnectorToRelay);
                let stream_replay_frames = relay
                    .last_emitted
                    .saturating_sub(relay.peer_acked)
                    .try_into()
                    .unwrap_or(usize::MAX);
                let stream_replay_bytes = relay.replay_bytes;
                replay_frames = replay_frames.saturating_add(stream_replay_frames);
                replay_bytes = replay_bytes.saturating_add(stream_replay_bytes);
                streams.push(RelayStreamSnapshot {
                    stream_id: *stream_id,
                    operation_id: stream.operation_id.clone(),
                    last_emitted_relay_to_connector: relay.last_emitted,
                    peer_acked_relay_to_connector: relay.peer_acked,
                    recv_contiguous_connector_to_relay: connector.recv_contiguous,
                    delivered_contiguous_connector_to_relay: connector.delivered_contiguous,
                    replay_frames_relay_to_connector: stream_replay_frames,
                    replay_bytes_relay_to_connector: stream_replay_bytes,
                    queue_bytes: stream.budget_bytes,
                    terminal: stream.terminal,
                });
            }
            streams.sort_by_key(|stream| stream.stream_id);
            sessions.push(RelaySessionSnapshot {
                device_id: session.identity.device_id.to_string(),
                session_id: session.key.session_id.clone(),
                epoch: session.key.epoch,
                profile: session.profile.as_str(),
                phase,
                active_generation,
                active_connection_id,
                candidate_generation,
                candidate_connection_id,
                sockets,
                queue_bytes: session.queue_budget.used(),
                queue_messages: session.pending.len() + session.streams.len(),
                drain_fences,
                drain_proofs,
                replay_frames,
                replay_bytes,
                rotations_completed: session.rotations_completed,
                total_replayed_frames: session.total_replayed_frames,
                streams,
            });
        }
        sessions.sort_by(|left, right| left.device_id.cmp(&right.device_id));
        RelaySnapshot { sessions }
    }

    fn session_for(&self, key: &SessionKey) -> Option<&DeviceSession> {
        self.sessions
            .get(&key.device_id)
            .filter(|session| session.key == *key)
    }

    fn ticket_matches(&self, ticket: &Ticket) -> bool {
        self.tickets.get(&ticket.value).is_some_and(|pending| {
            pending.value == ticket.value
                && pending.session_id == ticket.session_id
                && pending.epoch == ticket.epoch
                && pending.generation == ticket.generation
                && pending.connection_id == ticket.connection_id
                && pending.candidate == ticket.candidate
                && pending.attachment_purpose == ticket.attachment_purpose
                && pending.consuming
                && pending.expires_at == ticket.expires_at
                && pending.expires_at_wall == ticket.expires_at_wall
        })
    }

    fn remove_ticket_if_matches(&mut self, ticket: &Ticket) {
        if self.ticket_matches(ticket) {
            self.tickets.remove(&ticket.value);
        }
    }

    fn session_mut(&mut self, key: &SessionKey) -> Option<&mut DeviceSession> {
        self.sessions
            .get_mut(&key.device_id)
            .filter(|session| session.key == *key)
    }

    fn fail_pending(
        &mut self,
        key: &SessionKey,
        stream_id: u64,
        code: &'static str,
        execution: &'static str,
    ) {
        if let Some(session) = self.session_mut(key)
            && let Some(pending) = session.pending.remove(&stream_id)
        {
            release_pending_budget(session, &pending);
            let _ = pending
                .response
                .send(EchoOutcome::Failure { code, execution });
        }
    }

    fn invalidate_pending(
        &mut self,
        key: &SessionKey,
        stream_id: u64,
        challenge: &DeviceChallenge,
        reason: &str,
    ) {
        let _ = self.send_control(
            key,
            wire::authorization_invalidated(
                &key.session_id,
                key.epoch,
                stream_id,
                &challenge.challenge_id,
                challenge.grant_revision,
                reason,
            ),
        );
        self.fail_pending(key, stream_id, "AUTHORIZATION_REVOKED", "not_dispatched");
    }

    fn send_control(&self, key: &SessionKey, message: ControlMessage) -> Result<(), RelayError> {
        let text = wire::encode_control_message(&message)
            .map_err(|error| RelayError::Protocol(error.to_string()))?;
        let session = self.session_for(key).ok_or(RelayError::NotFound)?;
        queue_control(&session.control_tx, &session.queue_budget, text)
            .map_err(|_| RelayError::Overloaded("control queue is full"))
    }
}

fn allocate_stream_id(next: &mut u64) -> Option<u64> {
    if *next == 0 {
        return None;
    }
    let following = next.checked_add(1)?;
    let allocated = *next;
    *next = following;
    Some(allocated)
}

fn direction_index(direction: Direction) -> usize {
    match direction {
        Direction::RelayToConnector => 0,
        Direction::ConnectorToRelay => 1,
    }
}

fn direction_snapshot_from_resume(
    entry: &ResumeDirectionState,
) -> tunnel_protocol::sequence::DirectionSnapshot {
    tunnel_protocol::sequence::DirectionSnapshot {
        last_emitted: entry.last_emitted,
        peer_acked: entry.peer_acked,
        recv_contiguous: entry.recv_contiguous,
        delivered_contiguous: entry.delivered_contiguous,
        send_credit: entry.send_credit,
        sent_bytes: entry.sent_bytes,
        receive_credit: entry.receive_credit,
        received_bytes: entry.received_bytes,
        send_terminal: entry.send_terminal.map(Into::into),
        send_terminal_sequence: entry.send_terminal_sequence(),
        receive_terminal: entry.receive_terminal.map(Into::into),
        receive_terminal_sequence: entry.receive_terminal_sequence(),
        replay_floor: entry.replay_floor,
        replay_bytes: 0,
        reorder_frames: 0,
        reorder_bytes: 0,
    }
}

fn is_rotation_message(message: &ControlMessage) -> bool {
    matches!(
        message,
        ControlMessage::RotateRequest(_)
            | ControlMessage::RotatePrepare(_)
            | ControlMessage::RotateQuiesce(_)
            | ControlMessage::RotateFrozen(_)
            | ControlMessage::RotateDrained(_)
            | ControlMessage::RotateCommit(_)
            | ControlMessage::RotateCommitted(_)
            | ControlMessage::RotateRetire(_)
            | ControlMessage::RotateRetired(_)
            | ControlMessage::RotateComplete(_)
            | ControlMessage::RotateAbort(_)
            | ControlMessage::RotateAborted(_)
            | ControlMessage::RecoveryBegin(_)
            | ControlMessage::RecoveryClosed(_)
            | ControlMessage::Resume(_)
            | ControlMessage::Resumed(_)
            | ControlMessage::StreamForget(_)
    )
}

fn monotonic_millis() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn release_pending_budget(session: &mut DeviceSession, pending: &PendingEcho) {
    let bytes = pending
        .body
        .len()
        .saturating_add(pending.response_body.len());
    session.queued_bytes = session.queued_bytes.saturating_sub(bytes);
    session.queue_budget.release(bytes);
}

fn reserve_m2_bytes(budget: &QueueBudget, stream: &mut M2Stream, bytes: usize) -> bool {
    if bytes == 0 {
        return true;
    }
    if !budget.reserve(bytes) {
        return false;
    }
    stream.budget_bytes = stream.budget_bytes.saturating_add(bytes);
    true
}

fn release_m2_bytes(budget: &QueueBudget, stream: &mut M2Stream, bytes: usize) {
    if bytes == 0 {
        return;
    }
    let released = bytes.min(stream.budget_bytes);
    stream.budget_bytes = stream.budget_bytes.saturating_sub(released);
    budget.release(released);
}

fn queue_control(
    sender: &mpsc::Sender<ControlOutbound>,
    budget: &QueueBudget,
    text: String,
) -> Result<(), ()> {
    let bytes = text.len();
    if !budget.reserve(bytes) {
        return Err(());
    }
    if sender.try_send(ControlOutbound::Text(text)).is_err() {
        budget.release(bytes);
        return Err(());
    }
    Ok(())
}

fn queue_data(
    sender: &mpsc::Sender<DataOutbound>,
    budget: &QueueBudget,
    bytes: Vec<u8>,
) -> Result<(), ()> {
    let length = bytes.len();
    if !budget.reserve(length) {
        return Err(());
    }
    if sender.try_send(DataOutbound::Binary(bytes)).is_err() {
        budget.release(length);
        return Err(());
    }
    Ok(())
}

fn validate_hello(message: &Hello, device_id: Uuid) -> Result<(), RelayError> {
    if message.protocol_major != u16::from(crate::PROTOCOL_MAJOR) {
        return Err(RelayError::Protocol("unsupported protocol major".into()));
    }
    if message.connector_id.parse::<Uuid>().ok() != Some(device_id) {
        return Err(RelayError::Unauthorized);
    }
    let supports_echo = message.features.iter().any(|value| value == "echo")
        || message
            .services
            .iter()
            .any(|service| service.service_type == crate::ECHO_SERVICE_TYPE);
    if !supports_echo {
        return Err(RelayError::Protocol(
            "device did not advertise fixed echo export".into(),
        ));
    }
    Ok(())
}

/// A running relay owns its two transport listener tasks and actor.  Dropping
/// a running value requests cancellation; callers should prefer `shutdown`
/// to observe all joins and catalog lease cleanup.
pub struct RunningRelay {
    pub(crate) handle: RelayHandle,
    cancel: CancellationToken,
    consumer_task: JoinHandle<Result<(), tunnel_transport::TransportError>>,
    device_task: JoinHandle<Result<(), tunnel_transport::TransportError>>,
    pub consumer_addr: std::net::SocketAddr,
    pub device_addr: std::net::SocketAddr,
}

impl RunningRelay {
    /// Return the same redacted, in-process diagnostics as [`RelayHandle`].
    /// The listener wrapper intentionally adds no unauthenticated debug
    /// route; harnesses holding the running value can inspect counters
    /// directly.
    pub async fn snapshot(&self) -> Result<RelaySnapshot, RelayError> {
        self.handle.snapshot().await
    }

    pub async fn shutdown(self) -> Result<(), RelayError> {
        self.cancel.cancel();
        let _ = self.handle.shutdown().await;
        self.consumer_task
            .await
            .map_err(|error| RelayError::Transport(error.to_string()))?
            .map_err(|error| RelayError::Transport(error.to_string()))?;
        self.device_task
            .await
            .map_err(|error| RelayError::Transport(error.to_string()))?
            .map_err(|error| RelayError::Transport(error.to_string()))?;
        Ok(())
    }
}

/// Relay construction and listener startup.
pub struct Relay;

impl Relay {
    pub async fn start(
        options: RelayOptions,
        catalog: SharedCatalog,
        consumer_listener: TcpListener,
        device_listener: TcpListener,
        consumer_tls: Arc<rustls::ServerConfig>,
        device_tls: Arc<rustls::ServerConfig>,
    ) -> Result<RunningRelay, RelayError> {
        options
            .validate()
            .map_err(|error| RelayError::Config(error.to_string()))?;
        let handle = RelayHandle::spawn(options.clone(), catalog.clone());
        let cancel = options.shutdown.clone();
        let consumer_addr = consumer_listener
            .local_addr()
            .map_err(|error| RelayError::Transport(error.to_string()))?;
        let device_addr = device_listener
            .local_addr()
            .map_err(|error| RelayError::Transport(error.to_string()))?;
        let consumer_router = http::consumer_router(
            handle.clone(),
            catalog.clone(),
            options.oidc.clone(),
            options.limits.clone(),
        );
        let device_router = http::device_router(handle.clone(), options.limits.clone());
        let consumer_cancel = cancel.child_token();
        let device_cancel = cancel.child_token();
        let consumer_task = tokio::spawn(async move {
            tunnel_transport::serve(
                consumer_listener,
                consumer_router,
                consumer_tls,
                consumer_cancel,
            )
            .await
        });
        let device_task = tokio::spawn(async move {
            tunnel_transport::serve(device_listener, device_router, device_tls, device_cancel).await
        });
        Ok(RunningRelay {
            handle,
            cancel,
            consumer_task,
            device_task,
            consumer_addr,
            device_addr,
        })
    }

    pub async fn spawn(
        options: RelayOptions,
        catalog: SharedCatalog,
    ) -> Result<RelayHandle, RelayError> {
        options
            .validate()
            .map_err(|error| RelayError::Config(error.to_string()))?;
        Ok(RelayHandle::spawn(options, catalog))
    }

    pub fn router(
        handle: RelayHandle,
        catalog: SharedCatalog,
        oidc: Arc<tunnel_catalog::OidcVerifier>,
        limits: RelayLimits,
    ) -> Router {
        http::router(handle, catalog, oidc, limits)
    }
}

#[cfg(test)]
mod stream_identity_tests {
    use std::collections::VecDeque;

    use super::{
        MAX_ROTATION_TOMBSTONES, RelayActor, RotationJournalDecision, RotationRuntime,
        allocate_stream_id,
    };
    use tunnel_protocol::ControlMessage;
    use tunnel_protocol::control_journal::ControlJournal;
    use tunnel_protocol::rotation::{RotationConfig, RotationPhase, RotationState};
    use tunnel_protocol::rotation_control::{RotateAborted, RotationAttemptIdentity};

    #[test]
    fn allocation_never_wraps_or_reuses_an_exhausted_identity() {
        let mut next = 1;
        assert_eq!(allocate_stream_id(&mut next), Some(1));
        assert_eq!(allocate_stream_id(&mut next), Some(2));
        next = u64::MAX - 1;
        assert_eq!(allocate_stream_id(&mut next), Some(u64::MAX - 1));
        assert_eq!(allocate_stream_id(&mut next), None);
        assert_eq!(allocate_stream_id(&mut next), None);
        assert_eq!(next, u64::MAX);
        next = 0;
        assert_eq!(allocate_stream_id(&mut next), None);
    }

    #[test]
    fn abort_ack_waits_for_actual_owner_closure() {
        let pending = Some(RotateAborted::default());
        assert!(
            RelayActor::pending_abort_ack_if_active(RotationPhase::Aborting, &pending).is_none()
        );
        assert!(pending.is_some());
        assert!(RelayActor::pending_abort_ack_if_active(RotationPhase::Active, &pending).is_some());
    }

    fn test_attempt(label: &str, generation: u64) -> RotationAttemptIdentity {
        RotationAttemptIdentity::new(
            "session",
            1,
            "owner",
            format!("rotation-{label}"),
            generation,
            generation + 1,
            format!("old-{label}"),
            format!("new-{label}"),
        )
    }

    fn test_rotation_runtime(
        now: u64,
        attempt: RotationAttemptIdentity,
        deadline: u64,
    ) -> RotationRuntime {
        RotationRuntime {
            state: RotationState::new(
                "session",
                "owner",
                1,
                attempt.old_generation,
                attempt.old_connection_id.clone(),
                RotationConfig::default(),
            )
            .expect("test rotation state"),
            attempt: Some(attempt),
            attempt_deadline_ms: Some(deadline),
            snapshot_id: String::new(),
            barrier_rx: None,
            candidate: None,
            old_connection_id: String::new(),
            prepare_message_id: String::new(),
            last_message_id: String::new(),
            abort_message_id: None,
            peer_message_id: String::new(),
            quiesce_message_id: String::new(),
            frozen_message_id: String::new(),
            commit_message_id: String::new(),
            retire_message_id: String::new(),
            peer_frozen_message_id: None,
            peer_drained_message_id: None,
            peer_committed_message_id: None,
            peer_retired_message_id: None,
            peer_aborted_message_id: None,
            pending_abort_ack: None,
            tombstones: VecDeque::new(),
            remote_fences: [None, None],
            own_fence: None,
            replayed_frames: 0,
            journal: ControlJournal::new(128, 4 * 1024 * 1024, now, deadline)
                .expect("test journal"),
            recovery: None,
        }
    }

    fn retired_message(attempt: RotationAttemptIdentity, message_id: &str) -> ControlMessage {
        ControlMessage::RotateRetired(tunnel_protocol::rotation_control::RotateRetired {
            message_id: message_id.to_owned(),
            reply_to: "relay-retire".to_owned(),
            closed_connection_id: attempt.old_connection_id.clone(),
            attempt,
            snapshot_id: "snapshot".to_owned(),
        })
    }

    #[test]
    fn completed_rotation_journal_replays_after_attempt_clear_and_new_attempt() {
        let now = 1_000;
        let deadline_a = 2_000;
        let attempt_a = test_attempt("a", 1);
        let retired = retired_message(attempt_a.clone(), "retired-a");
        let mut rotation = test_rotation_runtime(now, attempt_a.clone(), deadline_a);
        match RelayActor::observe_rotation_journal(&mut rotation, &retired, now + 1) {
            RotationJournalDecision::New => {}
            other => panic!("expected new retired request, got {other:?}"),
        }
        let complete = super::wire::rotate_complete(
            retired.message_id(),
            attempt_a.clone(),
            "snapshot",
            false,
            None,
        );
        let complete_bytes = super::wire::encode_control_message(&complete)
            .expect("encoded completion")
            .into_bytes();
        rotation
            .journal
            .complete(retired.message_id(), &complete_bytes, now + 2)
            .expect("complete retired journal entry");
        assert!(RelayActor::retain_rotation_tombstone(&mut rotation));
        rotation.attempt = None;
        rotation.attempt_deadline_ms = None;
        rotation.attempt = Some(test_attempt("b", 2));
        rotation.attempt_deadline_ms = Some(3_000);
        rotation.journal =
            ControlJournal::new(128, 4 * 1024 * 1024, now + 2, 3_000).expect("new attempt journal");

        for retry_now in [now + 3, now + 4] {
            match RelayActor::observe_rotation_journal(&mut rotation, &retired, retry_now) {
                RotationJournalDecision::CompletedDuplicate(response) => {
                    assert_eq!(response, vec![complete_bytes.clone()]);
                }
                other => panic!("expected cached completion, got {other:?}"),
            }
        }
        assert_eq!(rotation.tombstones.len(), 1);
        RelayActor::prune_rotation_tombstones(&mut rotation, deadline_a);
        assert!(matches!(
            RelayActor::observe_rotation_journal(&mut rotation, &retired, deadline_a),
            RotationJournalDecision::Error(
                tunnel_protocol::control_journal::JournalError::MissingMessage
            )
        ));
    }

    #[test]
    fn rotation_tombstone_capacity_rejects_without_evicting_live_history() {
        let now = 10_000;
        let mut rotation = test_rotation_runtime(now, test_attempt("0", 1), 20_000);
        for index in 0..MAX_ROTATION_TOMBSTONES {
            let generation = (index as u64) + 1;
            let attempt = test_attempt(&index.to_string(), generation);
            rotation.attempt = Some(attempt);
            rotation.attempt_deadline_ms = Some(20_000 + generation);
            rotation.journal = ControlJournal::new(128, 4 * 1024 * 1024, now, 20_000 + generation)
                .expect("bounded attempt journal");
            assert!(RelayActor::retain_rotation_tombstone(&mut rotation));
        }
        let oldest = rotation
            .tombstones
            .front()
            .map(|tombstone| tombstone.attempt.clone())
            .expect("oldest tombstone");
        rotation.attempt = Some(test_attempt("overflow", 20));
        rotation.attempt_deadline_ms = Some(30_000);
        assert!(!RelayActor::rotation_tombstone_capacity_available(
            &mut rotation,
            now,
        ));
        assert!(!RelayActor::retain_rotation_tombstone(&mut rotation));
        assert_eq!(rotation.tombstones.len(), MAX_ROTATION_TOMBSTONES);
        assert_eq!(
            rotation.tombstones.front().map(|item| &item.attempt),
            Some(&oldest)
        );
    }

    #[test]
    fn progressive_rotation_replay_preserves_frozen_then_drained_replies() {
        let now = 40_000;
        let attempt = test_attempt("progressive", 1);
        let request = retired_message(attempt.clone(), "shared-request");
        let snapshot = tunnel_protocol::rotation_control::FenceSnapshot::new("snapshot", vec![]);
        let proof = tunnel_protocol::rotation_control::DrainProof::new(
            "snapshot",
            snapshot.digest().expect("snapshot digest"),
            tunnel_protocol::Direction::ConnectorToRelay,
            vec![],
        );
        let frozen = super::wire::rotate_frozen(request.message_id(), attempt.clone(), snapshot);
        let drained = super::wire::rotate_drained(request.message_id(), attempt, proof);
        let frozen_bytes = super::wire::encode_control_message(&frozen)
            .expect("encoded frozen")
            .into_bytes();
        let drained_bytes = super::wire::encode_control_message(&drained)
            .expect("encoded drained")
            .into_bytes();
        let mut rotation = test_rotation_runtime(now, test_attempt("progressive", 1), 50_000);
        match RelayActor::observe_rotation_journal(&mut rotation, &request, now + 1) {
            RotationJournalDecision::New => {}
            other => panic!("expected new shared request, got {other:?}"),
        }
        rotation
            .journal
            .append_response(
                request.message_id(),
                frozen.message_id(),
                &frozen_bytes,
                now + 2,
            )
            .expect("append frozen response");
        rotation
            .journal
            .append_response(
                request.message_id(),
                drained.message_id(),
                &drained_bytes,
                now + 3,
            )
            .expect("append drained response");
        match RelayActor::observe_rotation_journal(&mut rotation, &request, now + 4) {
            RotationJournalDecision::CompletedDuplicate(responses) => {
                assert_eq!(responses, vec![frozen_bytes, drained_bytes]);
            }
            other => panic!("expected progressive replay, got {other:?}"),
        }
    }

    #[test]
    fn peer_phase_message_ids_reject_fresh_same_attempt_messages() {
        for first in ["frozen-first", "retired-first", "aborted-first"] {
            let mut pinned = None;
            assert!(RelayActor::pin_peer_message_id(&mut pinned, first));
            assert!(RelayActor::peer_message_id_is_acceptable(
                pinned.as_deref(),
                first,
            ));
            assert!(!RelayActor::peer_message_id_is_acceptable(
                pinned.as_deref(),
                "fresh-conflicting-id",
            ));
            assert!(!RelayActor::pin_peer_message_id(
                &mut pinned,
                "fresh-conflicting-id",
            ));
            assert_eq!(pinned.as_deref(), Some(first));
        }
    }
}
