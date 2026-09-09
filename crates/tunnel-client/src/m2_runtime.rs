//! M2 connector runtime.
//!
//! This module is intentionally an actor around the protocol crate's pure
//! sequence and rotation state.  WebSocket readers and writers only report
//! typed events; the actor owns logical stream counters, carrier identity,
//! rotation phase, and all bounded queues.  A physical data connection is
//! never allowed to create a new logical sequence space.

use super::{
    AuthContext, BufferedInput, ClientError, ClientSink, ClientStream, ClientWebSocket,
    ConnectionHandle, ConnectionLifecycle, ConnectionStatus, DualDeadline, OutboundQueue,
    QueueBudget, Readiness, RuntimeConfig, SessionInfo, WriterKind, data_url_for, encode_control,
    message_id, open_socket, sanitize_error, send_control_direct,
};
use futures_util::{SinkExt, StreamExt};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use tunnel_protocol::control_journal::{ControlJournal, Observation as JournalObservation};
use tunnel_protocol::rotation::{
    ClosureEvidence, RecoveryReason, RotationConfig, RotationPhase, RotationSide, RotationState,
    ValidatedRecovery,
};
use tunnel_protocol::rotation_control::{
    DataAttachmentPurpose, FenceSnapshot, RecoveryBegin, RecoveryClosed, RecoverySide, Resume,
    ResumeDirectionState, ResumeStage, Resumed, RotationAttemptIdentity, StreamAck, StreamFence,
    combined_closure_digest,
};
use tunnel_protocol::sequence::{
    DirectionSnapshot, RecoveryPlan, SequenceLimits, StreamSnapshot, StreamState,
};
use tunnel_protocol::{
    AuthorizationChallenge, AuthorizationConfirmed, AuthorizationInvalidated, Cancel,
    ControlMessage, DataReady, Direction, Frame, FrameKind, Hello, MAX_CONTROL_MESSAGE_BYTES,
    MAX_FRAME_LEN, MAX_PAYLOAD_LEN, Open, Opened, Ping, Pong, Rejected, RotateAbort, RotateAborted,
    RotateCommit, RotateCommitted, RotateComplete, RotateDrained, RotateFrozen, RotatePrepare,
    RotateQuiesce, RotateRequest, RotateRetire, RotateRetired, decode_control,
};
use url::Url;

const M2_FEATURE: &str = "ordered-rotation-v1";
const M1_FEATURES: [&str; 3] = ["m1-control-data", "authorization-challenge", "echo"];
const M2_CONTROL_QUEUE_BYTES: usize = 64 * 1024;
const M2_WRITER_TIMEOUT: Duration = Duration::from_secs(5);
const M2_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
const M2_DEADLINE_POLL: Duration = Duration::from_millis(100);
const M2_EVENT_CAPACITY: usize = 256;
const M2_CARRIER_QUEUE_FRAMES: usize = 128;
const M2_MAX_RECORD_BYTES: usize = 64 * 1024;
const M2_MAX_CANARY_BYTES: usize = 256;
const M2_RECORD_HEADER_BYTES: usize = 4;
const M2_MAX_STREAM_RESPONSE_BYTES: usize =
    M2_RECORD_HEADER_BYTES + M2_MAX_RECORD_BYTES + M2_MAX_CANARY_BYTES;
const M2_MAX_REASSEMBLY_BYTES: usize =
    M2_RECORD_HEADER_BYTES + M2_MAX_RECORD_BYTES + MAX_PAYLOAD_LEN;
const M2_MAX_RESPONSE_BATCH_BYTES: usize = M2_MAX_REASSEMBLY_BYTES;
/// Refresh stream authorization before its five-second confirmation window
/// expires.  The relay still validates every new challenge against its live
/// grant and device identity; this margin only prevents a long-lived stream
/// from dispatching at the exact expiry boundary.
const M2_AUTH_REFRESH_MARGIN: Duration = Duration::from_millis(1_500);
const M2_RESET_AUTH_EXPIRED: u16 = 4_001;
const M2_RESET_PROTOCOL: u16 = 4_002;
const M2_RESET_RECORD_LIMIT: u16 = 4_003;

type M2SupervisorJoin = JoinHandle<Result<(), ClientError>>;

/// Establish an M2 control/data session and hand ownership to the actor.
pub(super) async fn connect_m2(
    options: super::ConnectOptions,
) -> Result<ConnectionHandle, ClientError> {
    options.config.validate()?;
    if options.cancellation.is_cancelled() {
        return Err(ClientError::Cancelled);
    }
    let tls =
        super::load_client_config(&options.config.credentials).map_err(ClientError::Credential)?;
    let control_url = Url::parse(&options.config.relay_url)
        .map_err(|_| ClientError::Invalid("relay_url is not a valid URL"))?;
    let (readiness_tx, readiness_rx) = watch::channel(Readiness::Connecting);
    let (status_tx, status_rx) = watch::channel(ConnectionStatus::default());
    let mut control = open_socket(
        &control_url,
        tls.clone(),
        None,
        super::CONTROL_SUBPROTOCOL,
        MAX_CONTROL_MESSAGE_BYTES,
        &options.cancellation,
    )
    .await?;
    readiness_tx
        .send(Readiness::ControlOpen)
        .map_err(|_| ClientError::Cancelled)?;
    let hello = m2_hello(&options.config);
    tokio::select! {
        _ = options.cancellation.cancelled() => return Err(ClientError::Cancelled),
        result = send_control_direct(&mut control, &hello) => result?,
    }
    let welcome =
        super::receive_welcome(&mut control, hello.message_id(), &options.cancellation).await?;
    if welcome.protocol_major != super::PROTOCOL_MAJOR {
        return Err(ClientError::Protocol(format!(
            "relay selected unsupported protocol major {}",
            welcome.protocol_major
        )));
    }
    if !welcome
        .supported_features
        .iter()
        .any(|feature| feature == M2_FEATURE)
    {
        return Err(ClientError::Protocol(
            "relay did not negotiate ordered-rotation-v1".to_owned(),
        ));
    }
    let session = SessionInfo {
        session_id: welcome.session_id.clone(),
        epoch: welcome.epoch,
        generation: welcome.generation,
    };
    let data_url = data_url_for(&control_url);
    readiness_tx
        .send(Readiness::DataOpening)
        .map_err(|_| ClientError::Cancelled)?;
    let data = open_socket(
        &data_url,
        tls.clone(),
        Some(&welcome.attachment_ticket),
        super::DATA_SUBPROTOCOL,
        MAX_FRAME_LEN,
        &options.cancellation,
    )
    .await?;
    let data_ready = super::receive_data_ready(&mut control, &options.cancellation).await?;
    validate_data_ready_m2(&data_ready, &session, &welcome)?;
    let owner_id = welcome
        .owner_id
        .clone()
        .ok_or_else(|| ClientError::Protocol("M2 WELCOME omitted owner identity".to_owned()))?;
    let rotation_config = negotiated_rotation_config(&options.config, &welcome)?;
    let control_local_addr = super::socket_local_addr(&control);
    let active_local_addr = super::socket_local_addr(&data);
    let (control_sink, control_stream) = control.split();
    let (data_sink, data_stream) = data.split();
    let ready_info = SessionInfo {
        session_id: data_ready.session_id.clone(),
        epoch: data_ready.epoch,
        generation: data_ready.generation,
    };
    let cancellation = options.cancellation.clone();
    let actor_cancel = cancellation.clone();
    let actor_readiness = readiness_tx.clone();
    let actor_config = options.config.clone();
    let mut initial_status = status_rx.borrow().clone();
    initial_status.phase = "active".to_owned();
    initial_status.session_id = Some(session.session_id.clone());
    initial_status.epoch = Some(session.epoch);
    initial_status.active_generation = Some(session.generation);
    initial_status.active_connection_id = Some(welcome.connection_id.clone());
    initial_status.control_local_addr = control_local_addr;
    initial_status.active_local_addr = active_local_addr;
    let _ = status_tx.send(initial_status);
    let actor_status = status_tx.clone();
    let join: M2SupervisorJoin = tokio::spawn(async move {
        run_m2_session(
            actor_config,
            session,
            welcome,
            owner_id,
            rotation_config,
            control_sink,
            control_stream,
            data_sink,
            data_stream,
            actor_cancel,
            actor_readiness,
            actor_status,
            control_local_addr,
            active_local_addr,
        )
        .await
    });
    readiness_tx
        .send(Readiness::Ready(ready_info.clone()))
        .map_err(|_| ClientError::Cancelled)?;
    let lifecycle = Arc::new(ConnectionLifecycle {
        cancellation,
        join: tokio::sync::Mutex::new(Some(join)),
    });
    Ok(ConnectionHandle {
        readiness: readiness_rx,
        status: status_rx,
        lifecycle,
    })
}

fn m2_hello(config: &RuntimeConfig) -> ControlMessage {
    let mut features = M1_FEATURES
        .iter()
        .map(|feature| (*feature).to_owned())
        .collect::<Vec<_>>();
    features.push(M2_FEATURE.to_owned());
    let hello = Hello {
        message_id: message_id(),
        connector_id: config.device_id.clone(),
        protocol_major: super::PROTOCOL_MAJOR,
        protocol_minor: super::PROTOCOL_MINOR,
        features,
        services: super::configured_services(config),
        rotation_policy: Some(tunnel_protocol::control::RotationPolicy::new(
            config.rotation.interval_seconds.saturating_mul(1_000),
            config
                .rotation
                .handshake_timeout_seconds
                .saturating_mul(1_000),
            config.rotation.overlap_seconds.saturating_mul(1_000),
        )),
    };
    ControlMessage::Hello(hello)
}

fn negotiated_rotation_config(
    local: &RuntimeConfig,
    welcome: &tunnel_protocol::Welcome,
) -> Result<RotationConfig, ClientError> {
    let interval_ms = welcome
        .rotation_interval_ms
        .unwrap_or(local.rotation.interval_seconds.saturating_mul(1_000));
    let handshake_ms = welcome.rotation_handshake_timeout_ms.unwrap_or(
        local
            .rotation
            .handshake_timeout_seconds
            .saturating_mul(1_000),
    );
    let overlap_ms = welcome
        .rotation_overlap_timeout_ms
        .unwrap_or(local.rotation.overlap_seconds.saturating_mul(1_000));
    let mut config =
        RotationConfig::new(interval_ms, handshake_ms, overlap_ms).map_err(|error| {
            ClientError::Protocol(format!("invalid negotiated rotation policy: {error}"))
        })?;
    if let Some(recovery_ms) = welcome.rotation_recovery_timeout_ms {
        config.recovery_timeout_ms = recovery_ms;
        config.validate().map_err(|error| {
            ClientError::Protocol(format!("invalid negotiated recovery policy: {error}"))
        })?;
    }
    Ok(config)
}

fn validate_data_ready_m2(
    ready: &DataReady,
    session: &SessionInfo,
    welcome: &tunnel_protocol::Welcome,
) -> Result<(), ClientError> {
    ready
        .validate_context(
            &session.session_id,
            session.epoch,
            welcome.generation,
            &welcome.connection_id,
        )
        .map_err(|error| ClientError::Protocol(error.to_string()))?;
    if ready.reply_to != welcome.message_id {
        return Err(ClientError::Protocol(
            "DATA_READY reply_to mismatch".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CarrierKey {
    generation: u64,
    connection_id: String,
}

impl CarrierKey {
    fn new(generation: u64, connection_id: impl Into<String>) -> Self {
        Self {
            generation,
            connection_id: connection_id.into(),
        }
    }

    fn matches(&self, generation: u64, connection_id: &str) -> bool {
        self.generation == generation && self.connection_id == connection_id
    }
}

#[derive(Debug)]
enum CarrierCommand {
    Frame(QueuedCarrierFrame),
    Message(Message),
    Barrier,
    Close(oneshot::Sender<()>),
}

struct QueuedCarrierFrame {
    bytes: Vec<u8>,
    bytes_len: usize,
    budget: Arc<QueueBudget>,
}

impl std::fmt::Debug for QueuedCarrierFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QueuedCarrierFrame")
            .field("bytes_len", &self.bytes_len)
            .finish_non_exhaustive()
    }
}

impl Drop for QueuedCarrierFrame {
    fn drop(&mut self) {
        self.budget.release(self.bytes_len);
    }
}

#[derive(Debug)]
enum CarrierEvent {
    Message {
        key: CarrierKey,
        message: Box<Message>,
    },
    ReaderClosed {
        key: CarrierKey,
        peer_closed: bool,
    },
    WriterClosed {
        key: CarrierKey,
    },
    WriterFailed {
        key: CarrierKey,
        detail: &'static str,
    },
    BarrierComplete {
        key: CarrierKey,
    },
    CandidateOpened {
        attempt: RotationAttemptIdentity,
        socket: Box<ClientWebSocket>,
        local_addr: Option<std::net::SocketAddr>,
    },
    CandidateFailed {
        attempt: RotationAttemptIdentity,
    },
}

struct Carrier {
    key: CarrierKey,
    local_addr: Option<std::net::SocketAddr>,
    tx: mpsc::Sender<CarrierCommand>,
    reader_cancel: CancellationToken,
    reader: Option<JoinHandle<()>>,
    writer: Option<JoinHandle<()>>,
}

struct PendingCandidate {
    attempt: RotationAttemptIdentity,
    prepare_message_id: String,
    recovery: bool,
    /// Absolute actor-clock deadline for this physical dial.  Recovery keeps
    /// its episode deadline immutable; a peer-provided remaining budget may
    /// only shorten this particular candidate attempt.
    deadline_ms: u64,
    socket: Option<ClientWebSocket>,
    local_addr: Option<std::net::SocketAddr>,
    ready: bool,
    dial: Option<JoinHandle<()>>,
}

/// Actor-owned recovery episode.  All maps are bounded by the authenticated
/// roster, and contain only sequence metadata; payloads remain in
/// `StreamState`'s bounded replay buffers.
struct RecoveryRuntime {
    begin: RecoveryBegin,
    local_closed: RecoveryClosed,
    prepare_message_id: Option<String>,
    peer_closed: Option<RecoveryClosed>,
    combined_digest: Option<String>,
    deadline_ms: u64,
    /// The current recovery candidate's bounded attachment/phase deadline.
    /// This is separate from the immutable episode deadline and survives the
    /// pending-candidate bookkeeping until the recovery handshake activates.
    attempt_deadline_ms: Option<u64>,
    local_snapshots: [BTreeMap<u64, ResumeDirectionState>; 2],
    remote_snapshots: [BTreeMap<u64, ResumeDirectionState>; 2],
    /// Fresh peer snapshots carried by the READY pair.  The initial
    /// snapshots above remain immutable recovery obligations and are never
    /// re-used as mutable ACK state after replay starts.
    remote_ready_snapshots: [BTreeMap<u64, ResumeDirectionState>; 2],
    remote_snapshot_message_ids: [Option<String>; 2],
    snapshot_reply_message_ids: [Option<String>; 2],
    snapshot_reply_messages: [Option<Resumed>; 2],
    remote_ready_message_ids: [Option<String>; 2],
    remote_ready: [bool; 2],
    local_plans: BTreeMap<u64, RecoveryPlan>,
    peer_snapshots: BTreeMap<u64, StreamSnapshot>,
    snapshot_replies: [bool; 2],
    ready_replies: [bool; 2],
    ready_reply_messages: [Option<Resumed>; 2],
    fresh_reconciled: bool,
}

/// One completed rotation attempt retained until its immutable overlap
/// deadline.  Duplicate phase messages can therefore receive the original
/// response after the active carrier has already moved on.
struct RotationJournalTombstone {
    attempt: RotationAttemptIdentity,
    deadline_ms: u64,
    prepare_message_id: Option<String>,
    journal: ControlJournal,
    replies: BTreeMap<String, ControlMessage>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RotationJournalScope {
    Active,
    Completed,
}

#[derive(Debug)]
struct PendingOutput {
    stream_id: u64,
    kind: FrameKind,
    payload: Vec<u8>,
    reset_reason: Option<u16>,
}

#[derive(Debug)]
struct M2Stream {
    export: super::ExportConfig,
    operation_id: String,
    service_id: String,
    operation: String,
    auth: AuthContext,
    sequence: StreamState,
    pending: VecDeque<BufferedInput>,
    pending_bytes: usize,
    record_buffer: Vec<u8>,
    record_expected: Option<usize>,
    input_fin: bool,
    input_reset: bool,
    output_fin: bool,
    output_reset: bool,
    /// Set as soon as a RESET is admitted to the actor or deferred queue.
    /// This makes repeated CANCEL/auth-expiry paths idempotent before the
    /// terminal frame reaches the active carrier.
    reset_queued: bool,
}

/// Consume as many complete length-prefixed echo records as are available.
/// The buffer is the logical stream reassembly buffer, so an outer DATA frame
/// may contain a record tail, a complete record, and the start of the next
/// record.  Only the incomplete suffix remains retained after this function.
fn parse_echo_records(
    buffer: &mut Vec<u8>,
    expected: &mut Option<usize>,
    canary: &str,
    payload: &[u8],
) -> Result<Vec<Vec<u8>>, ()> {
    buffer.extend_from_slice(payload);
    let mut responses = Vec::new();
    let mut response_bytes = 0_usize;
    loop {
        let record_length = match *expected {
            Some(length) => length,
            None => {
                if buffer.len() < M2_RECORD_HEADER_BYTES {
                    break;
                }
                let length =
                    u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
                if length > M2_MAX_RECORD_BYTES {
                    return Err(());
                }
                *expected = Some(length);
                length
            }
        };
        let complete_length = M2_RECORD_HEADER_BYTES.saturating_add(record_length);
        if buffer.len() < complete_length {
            break;
        }
        let record = buffer[M2_RECORD_HEADER_BYTES..complete_length].to_vec();
        buffer.drain(..complete_length);
        *expected = None;
        let response_length = canary.len().saturating_add(record.len());
        if response_length > M2_MAX_RECORD_BYTES.saturating_add(M2_MAX_CANARY_BYTES) {
            return Err(());
        }
        let total_response_length = M2_RECORD_HEADER_BYTES.saturating_add(response_length);
        response_bytes = response_bytes.saturating_add(total_response_length);
        if response_bytes > M2_MAX_RESPONSE_BATCH_BYTES {
            return Err(());
        }
        let mut response = Vec::with_capacity(total_response_length);
        response.extend_from_slice(&(response_length as u32).to_be_bytes());
        response.extend_from_slice(canary.as_bytes());
        response.extend_from_slice(&record);
        responses.push(response);
    }
    if buffer.len() > M2_MAX_REASSEMBLY_BYTES {
        return Err(());
    }
    Ok(responses)
}

impl M2Stream {
    fn is_streaming(&self) -> bool {
        self.operation == "echo_stream"
    }

    fn terminal(&self) -> bool {
        self.output_fin || self.output_reset
    }
}

fn queue_reset_once(stream: &mut M2Stream) -> bool {
    if stream.terminal() || stream.reset_queued {
        return false;
    }
    stream.reset_queued = true;
    true
}

fn physical_key_is_tracked(
    key: &CarrierKey,
    active: Option<&CarrierKey>,
    candidate: Option<&CarrierKey>,
    retiring: Option<&CarrierKey>,
) -> bool {
    [active, candidate, retiring]
        .into_iter()
        .flatten()
        .any(|tracked| tracked == key)
}

fn attempt_key_is_tracked(key: &CarrierKey, attempt: &RotationAttemptIdentity) -> bool {
    (attempt.old_generation == key.generation && attempt.old_connection_id == key.connection_id)
        || (attempt.new_generation == key.generation
            && attempt.new_connection_id == key.connection_id)
}

fn bounded_candidate_deadline(
    now_ms: u64,
    remaining_ms: u64,
    episode_deadline_ms: u64,
) -> Result<u64, ClientError> {
    let wire_deadline = now_ms
        .checked_add(remaining_ms)
        .ok_or_else(|| ClientError::Protocol("recovery prepare deadline overflow".to_owned()))?;
    let deadline = wire_deadline.min(episode_deadline_ms);
    if deadline <= now_ms {
        return Err(ClientError::Protocol(
            "recovery prepare deadline expired".to_owned(),
        ));
    }
    Ok(deadline)
}

#[derive(Debug)]
enum ActorEvent {
    Data(CarrierEvent),
}

struct M2Actor {
    config: RuntimeConfig,
    session: SessionInfo,
    owner_id: String,
    rotation: RotationState,
    control_queue: OutboundQueue,
    data_budget: Arc<QueueBudget>,
    events: mpsc::Sender<ActorEvent>,
    active: Carrier,
    candidate: Option<Carrier>,
    retiring: Option<Carrier>,
    pending_candidate: Option<PendingCandidate>,
    pending_candidate_close: Option<(RotationAttemptIdentity, ClosureEvidence)>,
    recovery: Option<RecoveryRuntime>,
    /// Retain the completed recovery handshake until its immutable episode
    /// deadline so duplicate READY/SNAPSHOT requests can be answered from the
    /// same bounded messages after activation.
    completed_recovery: Option<RecoveryRuntime>,
    control_journal: Option<ControlJournal>,
    rotation_journal: Option<ControlJournal>,
    rotation_journal_attempt: Option<RotationAttemptIdentity>,
    rotation_journal_deadline_ms: Option<u64>,
    rotation_prepare_message_id: Option<String>,
    local_frozen_message_id: Option<String>,
    local_drained_message_id: Option<String>,
    local_committed_message_id: Option<String>,
    local_retired_message_id: Option<String>,
    peer_drained_message_id: Option<String>,
    peer_committed_message_id: Option<String>,
    peer_retire_message_id: Option<String>,
    peer_abort_message_id: Option<String>,
    rotation_reply_cache: BTreeMap<String, ControlMessage>,
    completed_rotation: Option<RotationJournalTombstone>,
    pending_abort_reply_id: Option<String>,
    recovery_requested: bool,
    closed_for_recovery: BTreeMap<String, ClosureEvidence>,
    streams: BTreeMap<u64, M2Stream>,
    accepting: bool,
    writes_frozen: bool,
    pending_outputs: VecDeque<PendingOutput>,
    pending_output_bytes: usize,
    peer_fence: Option<FenceSnapshot>,
    local_fence: Option<FenceSnapshot>,
    sent_drain_proof: bool,
    pending_quiesce: Option<RotateQuiesce>,
    peer_fence_message_id: Option<String>,
    rotation_started: Instant,
    rotations_completed: u64,
    status: watch::Sender<ConnectionStatus>,
    cancellation: CancellationToken,
    control_local_addr: Option<std::net::SocketAddr>,
}

#[allow(clippy::too_many_arguments)]
async fn run_m2_session(
    config: RuntimeConfig,
    session: SessionInfo,
    welcome: tunnel_protocol::Welcome,
    owner_id: String,
    rotation_config: RotationConfig,
    control_sink: ClientSink,
    mut control_stream: ClientStream,
    data_sink: ClientSink,
    data_stream: ClientStream,
    cancellation: CancellationToken,
    readiness: watch::Sender<Readiness>,
    status: watch::Sender<ConnectionStatus>,
    control_local_addr: Option<std::net::SocketAddr>,
    active_local_addr: Option<std::net::SocketAddr>,
) -> Result<(), ClientError> {
    let (events_tx, mut events_rx) = mpsc::channel(M2_EVENT_CAPACITY);
    let (writer_failure_tx, mut writer_failure_rx) = mpsc::channel(2);
    let (control_queue, control_receiver) = OutboundQueue::new(
        config.limits.max_queue_frames.min(16),
        M2_CONTROL_QUEUE_BYTES.min(config.limits.max_queue_bytes),
        cancellation.clone(),
    );
    let control_writer = tokio::spawn(super::writer_loop(
        WriterKind::Control,
        control_sink,
        control_receiver,
        writer_failure_tx.clone(),
        cancellation.clone(),
    ));
    let data_budget = Arc::new(QueueBudget {
        bytes: std::sync::atomic::AtomicUsize::new(0),
        maximum: config.limits.max_queue_bytes,
    });
    let active_key = CarrierKey::new(session.generation, welcome.connection_id.clone());
    let active = spawn_carrier(
        active_key,
        data_sink,
        data_stream,
        data_budget.clone(),
        events_tx.clone(),
        cancellation.clone(),
        active_local_addr,
    );
    let rotation = RotationState::new(
        session.session_id.clone(),
        owner_id.clone(),
        session.epoch,
        session.generation,
        welcome.connection_id.clone(),
        rotation_config,
    )
    .map_err(|error| ClientError::Protocol(format!("invalid rotation state: {error}")))?;
    let mut actor = M2Actor {
        config,
        session,
        owner_id,
        rotation,
        control_queue,
        data_budget,
        events: events_tx.clone(),
        active,
        candidate: None,
        retiring: None,
        pending_candidate: None,
        pending_candidate_close: None,
        recovery: None,
        completed_recovery: None,
        control_journal: None,
        rotation_journal: None,
        rotation_journal_attempt: None,
        rotation_journal_deadline_ms: None,
        rotation_prepare_message_id: None,
        local_frozen_message_id: None,
        local_drained_message_id: None,
        local_committed_message_id: None,
        local_retired_message_id: None,
        peer_drained_message_id: None,
        peer_committed_message_id: None,
        peer_retire_message_id: None,
        peer_abort_message_id: None,
        rotation_reply_cache: BTreeMap::new(),
        completed_rotation: None,
        pending_abort_reply_id: None,
        recovery_requested: false,
        closed_for_recovery: BTreeMap::new(),
        streams: BTreeMap::new(),
        accepting: true,
        writes_frozen: false,
        pending_outputs: VecDeque::new(),
        pending_output_bytes: 0,
        peer_fence: None,
        local_fence: None,
        sent_drain_proof: false,
        pending_quiesce: None,
        peer_fence_message_id: None,
        rotation_started: Instant::now(),
        rotations_completed: 0,
        status,
        cancellation: cancellation.clone(),
        control_local_addr,
    };
    actor.publish_status();
    let mut deadline_timer = tokio::time::interval_at(
        tokio::time::Instant::now() + M2_DEADLINE_POLL,
        M2_DEADLINE_POLL,
    );
    deadline_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let result = loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break Ok(()),
            Some(failure) = writer_failure_rx.recv() => break Err(ClientError::Transport {
                scope: match failure.0 {
                    WriterKind::Control => "control writer",
                    WriterKind::Data => "data writer",
                },
                detail: "writer stopped".to_owned(),
            }),
            _ = deadline_timer.tick() => {
                if let Err(error) = actor.refresh_authorizations().await {
                    break Err(error);
                }
                if let Err(error) = actor.handle_rotation_deadline().await {
                    break Err(error);
                }
            }
            control = control_stream.next() => {
            match control {
                    Some(Ok(message)) => {
                        if let Err(error) = actor.handle_control_message(message).await {
                            break Err(error);
                        }
                    }
                    Some(Err(error)) => break Err(ClientError::Transport { scope: "control read", detail: sanitize_error(&error.to_string()) }),
                    None => break Err(ClientError::Transport { scope: "control read", detail: "control socket closed".to_owned() }),
                }
            }
            event = events_rx.recv() => {
                let Some(event) = event else { break Err(ClientError::Transport { scope: "data actor", detail: "event channel closed".to_owned() }); };
                if let Err(error) = actor.handle_event(event).await {
                    break Err(error);
                }
            }
        }
    };
    readiness.send(Readiness::Stopping).ok();
    cancellation.cancel();
    actor.close_all_carriers().await;
    let _ = control_writer.await;
    let reason = match &result {
        Ok(()) => "stopped".to_owned(),
        Err(ClientError::Cancelled) => "cancelled".to_owned(),
        Err(error) => error.safe_message(),
    };
    actor.publish_closed(reason.clone());
    readiness.send(Readiness::Closed { reason }).ok();
    result
}

fn spawn_carrier(
    key: CarrierKey,
    socket_sink: ClientSink,
    socket_stream: ClientStream,
    budget: Arc<QueueBudget>,
    events: mpsc::Sender<ActorEvent>,
    cancellation: CancellationToken,
    local_addr: Option<std::net::SocketAddr>,
) -> Carrier {
    let (tx, receiver) = mpsc::channel(M2_CARRIER_QUEUE_FRAMES);
    let reader_key = key.clone();
    let reader_events = events.clone();
    let reader_cancel = cancellation.child_token();
    let reader_cancel_for_carrier = reader_cancel.clone();
    let reader = tokio::spawn(async move {
        carrier_reader_loop(reader_key, socket_stream, reader_events, reader_cancel).await;
    });
    let writer_key = key.clone();
    let writer_events = events;
    let writer_cancel = cancellation;
    let writer = tokio::spawn(async move {
        carrier_writer_loop(
            writer_key,
            socket_sink,
            receiver,
            writer_events,
            writer_cancel,
        )
        .await;
    });
    let _ = budget;
    Carrier {
        key,
        local_addr,
        tx,
        reader_cancel: reader_cancel_for_carrier,
        reader: Some(reader),
        writer: Some(writer),
    }
}

async fn send_carrier_event(
    events: &mpsc::Sender<ActorEvent>,
    event: ActorEvent,
    cancellation: &CancellationToken,
) -> bool {
    tokio::select! {
        _ = cancellation.cancelled() => false,
        result = events.send(event) => result.is_ok(),
    }
}

async fn carrier_reader_loop(
    key: CarrierKey,
    mut stream: ClientStream,
    events: mpsc::Sender<ActorEvent>,
    cancellation: CancellationToken,
) {
    let mut peer_closed = false;
    loop {
        let next = tokio::select! {
            _ = cancellation.cancelled() => break,
            item = stream.next() => item,
        };
        match next {
            Some(Ok(Message::Close(_))) => {
                peer_closed = true;
                break;
            }
            Some(Ok(message)) => {
                if !send_carrier_event(
                    &events,
                    ActorEvent::Data(CarrierEvent::Message {
                        key: key.clone(),
                        message: Box::new(message),
                    }),
                    &cancellation,
                )
                .await
                {
                    return;
                }
            }
            Some(Err(_)) | None => break,
        }
    }
    let _ = send_carrier_event(
        &events,
        ActorEvent::Data(CarrierEvent::ReaderClosed { key, peer_closed }),
        &cancellation,
    )
    .await;
}

async fn carrier_writer_loop(
    key: CarrierKey,
    mut sink: ClientSink,
    mut receiver: mpsc::Receiver<CarrierCommand>,
    events: mpsc::Sender<ActorEvent>,
    cancellation: CancellationToken,
) {
    let mut explicit_close = false;
    loop {
        let command = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                let _ = tokio::time::timeout(M2_CLOSE_TIMEOUT, sink.close()).await;
                break;
            }
            command = receiver.recv() => command,
        };
        let Some(command) = command else {
            let _ = tokio::time::timeout(M2_CLOSE_TIMEOUT, sink.close()).await;
            break;
        };
        match command {
            CarrierCommand::Frame(mut frame) => {
                let bytes = std::mem::take(&mut frame.bytes);
                let result = tokio::time::timeout(
                    M2_WRITER_TIMEOUT,
                    sink.send(Message::Binary(bytes.into())),
                )
                .await;
                match result {
                    Ok(Ok(())) => {}
                    _ => {
                        let _ = tokio::select! {
                            _ = cancellation.cancelled() => false,
                            result = events.send(ActorEvent::Data(CarrierEvent::WriterFailed {
                                key: key.clone(),
                                detail: "data writer stopped",
                            })) => result.is_ok(),
                        };
                        return;
                    }
                }
            }
            CarrierCommand::Message(message) => {
                let result = tokio::time::timeout(M2_WRITER_TIMEOUT, sink.send(message)).await;
                if !matches!(result, Ok(Ok(()))) {
                    let _ = tokio::select! {
                        _ = cancellation.cancelled() => false,
                        result = events.send(ActorEvent::Data(CarrierEvent::WriterFailed {
                            key: key.clone(),
                            detail: "data writer stopped",
                        })) => result.is_ok(),
                    };
                    return;
                }
            }
            CarrierCommand::Barrier => {
                let _ = send_carrier_event(
                    &events,
                    ActorEvent::Data(CarrierEvent::BarrierComplete { key: key.clone() }),
                    &cancellation,
                )
                .await;
            }
            CarrierCommand::Close(reply) => {
                explicit_close = true;
                let _ = tokio::time::timeout(M2_CLOSE_TIMEOUT, sink.close()).await;
                let _ = reply.send(());
                break;
            }
        }
    }
    if !explicit_close {
        let _ = send_carrier_event(
            &events,
            ActorEvent::Data(CarrierEvent::WriterClosed { key }),
            &cancellation,
        )
        .await;
    }
}

impl M2Actor {
    fn now_ms(&self) -> u64 {
        self.rotation_started
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64
    }

    /// Return the aggregate bytes retained by every M2 data path.  Sequence
    /// replay, receive gaps/ready frames, authorization buffering, record
    /// reassembly, deferred output and carrier queues all draw from the same
    /// configured ceiling; per-stream sequence limits are only a second,
    /// local guard.
    fn aggregate_retained_bytes(&self) -> usize {
        let mut total = self
            .data_budget
            .current()
            .saturating_add(self.pending_output_bytes);
        for stream in self.streams.values() {
            total = total
                .saturating_add(stream.pending_bytes)
                .saturating_add(stream.record_buffer.len());
            for direction in [Direction::ConnectorToRelay, Direction::RelayToConnector] {
                let state = stream.sequence.direction(direction);
                total = total
                    .saturating_add(state.replay_bytes())
                    .saturating_add(state.reorder_bytes())
                    .saturating_add(state.ready_bytes());
            }
        }
        total
    }

    fn ensure_retained_capacity(&self, additional: usize) -> Result<(), ClientError> {
        if self
            .aggregate_retained_bytes()
            .checked_add(additional)
            .is_none_or(|total| total > self.config.limits.max_queue_bytes)
        {
            return Err(ClientError::QueueLimit);
        }
        Ok(())
    }

    async fn handle_rotation_deadline(&mut self) -> Result<(), ClientError> {
        let now = self.now_ms();
        if self
            .pending_candidate
            .as_ref()
            .is_some_and(|pending| now >= pending.deadline_ms)
        {
            return self.expire_pending_candidate().await;
        }
        if self.recovery.as_ref().is_some_and(|recovery| {
            recovery
                .attempt_deadline_ms
                .is_some_and(|deadline| now >= deadline)
        }) {
            if self.pending_candidate.is_some() {
                return self.expire_pending_candidate().await;
            }
            return Err(ClientError::Transport {
                scope: "retained recovery",
                detail: "recovery candidate phase deadline expired".to_owned(),
            });
        }
        let before = self.rotation.phase();
        let after = self.rotation.tick(now);
        match after {
            RotationPhase::Aborting if before != RotationPhase::Aborting => {
                // The owner still decides whether the known-uncommitted
                // attempt is aborted.  Freeze old writes until that decision
                // arrives; the overlap deadline must never revive them.
                self.accepting = false;
                self.writes_frozen = true;
                self.publish_status();
            }
            RotationPhase::Recovering
                if before != RotationPhase::Recovering && self.recovery.is_none() =>
            {
                return Err(ClientError::Transport {
                    scope: "data rotation",
                    detail: if self.pending_candidate_close.is_some() {
                        "candidate abort owner decision not received before overlap deadline"
                    } else {
                        "rotation deadline requires retained recovery"
                    }
                    .to_owned(),
                });
            }
            RotationPhase::Recovering
                if self
                    .recovery
                    .as_ref()
                    .is_some_and(|recovery| self.now_ms() >= recovery.deadline_ms) =>
            {
                return Err(ClientError::Transport {
                    scope: "retained recovery",
                    detail: "recovery episode deadline expired".to_owned(),
                });
            }
            RotationPhase::Closed => {
                return Err(ClientError::Transport {
                    scope: "data rotation",
                    detail: "rotation state closed".to_owned(),
                });
            }
            _ => {}
        }
        Ok(())
    }

    fn publish_status(&self) {
        let rotation_status = self.rotation.status();
        let mut emitted = 0_u64;
        let mut received = 0_u64;
        let mut replay_frames = 0_usize;
        let mut replay_bytes = 0_usize;
        for stream in self.streams.values() {
            for direction in [Direction::ConnectorToRelay, Direction::RelayToConnector] {
                let state = stream.sequence.direction(direction);
                emitted = emitted.saturating_add(state.last_emitted());
                received = received.saturating_add(state.recv_contiguous());
                replay_frames = replay_frames.saturating_add(state.replay_len());
                replay_bytes = replay_bytes.saturating_add(state.replay_bytes());
            }
        }
        let candidate = self
            .candidate
            .as_ref()
            .map(|carrier| (carrier.key.generation, carrier.key.connection_id.clone()));
        let pending_candidate = self.pending_candidate.as_ref().map(|pending| {
            (
                pending.attempt.new_generation,
                pending.attempt.new_connection_id.clone(),
            )
        });
        let candidate = candidate.or(pending_candidate);
        let candidate_local_addr = self
            .candidate
            .as_ref()
            .and_then(|carrier| carrier.local_addr)
            .or_else(|| {
                self.pending_candidate
                    .as_ref()
                    .and_then(|pending| pending.local_addr)
            });
        let phase = match rotation_status.phase {
            RotationPhase::Active => "active",
            RotationPhase::Preparing => "preparing",
            RotationPhase::Quiescing => "quiescing",
            RotationPhase::Draining => "draining",
            RotationPhase::Committing => "committing",
            RotationPhase::Retiring => "retiring",
            RotationPhase::Aborting => "aborting",
            RotationPhase::Recovering => "recovering",
            RotationPhase::Closed => "closed",
        };
        let status = ConnectionStatus {
            phase: phase.to_owned(),
            session_id: Some(self.session.session_id.clone()),
            epoch: Some(self.session.epoch),
            active_generation: Some(rotation_status.active_generation),
            active_connection_id: Some(rotation_status.active_connection_id.clone()),
            candidate_generation: candidate.as_ref().map(|(generation, _)| *generation),
            candidate_connection_id: candidate.map(|(_, connection_id)| connection_id),
            rotation_id: rotation_status
                .attempt
                .as_ref()
                .map(|attempt| attempt.rotation_id.clone()),
            streams: self.streams.len(),
            emitted_sequences: emitted,
            received_sequences: received,
            drain_fences: rotation_status
                .writers_frozen
                .iter()
                .filter(|frozen| **frozen)
                .count(),
            drain_acks: rotation_status
                .drain_proofs
                .iter()
                .filter(|drained| **drained)
                .count(),
            replay_frames,
            replay_bytes,
            queue_frames: self.pending_outputs.len(),
            queue_bytes: self.aggregate_retained_bytes(),
            rotations_completed: self.rotations_completed,
            control_local_addr: self.control_local_addr,
            active_local_addr: self.active.local_addr,
            candidate_local_addr,
        };
        let _ = self.status.send(status);
    }

    fn publish_closed(&self, reason: String) {
        let mut status = self.status.borrow().clone();
        status.phase = if reason == "stopped" || reason == "cancelled" {
            "closed".to_owned()
        } else {
            "failed".to_owned()
        };
        let _ = self.status.send(status);
    }

    fn send_control(
        &self,
        message: ControlMessage,
        deadline: Option<DualDeadline>,
    ) -> Result<(), ClientError> {
        let bytes =
            encode_control(&message).map_err(|error| ClientError::Protocol(error.to_string()))?;
        let text = String::from_utf8(bytes).map_err(|_| {
            ClientError::Protocol("control codec produced non-UTF-8 JSON".to_owned())
        })?;
        self.control_queue
            .try_send_with_deadline(Message::Text(text.into()), deadline)
    }

    fn is_rotation_journal_message(message: &ControlMessage) -> bool {
        matches!(
            message,
            ControlMessage::DataReady(_)
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
        )
    }

    fn should_journal_rotation(&self, message: &ControlMessage) -> bool {
        if !Self::is_rotation_journal_message(message) {
            return false;
        }
        match message {
            // Recovery has its own immutable episode journal.  A recovery
            // candidate must not leave a normal-rotation journal anchored to
            // its greater generation after the episode returns to Active.
            ControlMessage::RotatePrepare(prepare) => matches!(
                &prepare.attachment_purpose,
                DataAttachmentPurpose::RotationCandidate
            ),
            ControlMessage::DataReady(_) => !self.is_recovery_rotation_message(message),
            _ => true,
        }
    }

    fn is_recovery_rotation_message(&self, message: &ControlMessage) -> bool {
        match message {
            ControlMessage::RotatePrepare(prepare) => matches!(
                &prepare.attachment_purpose,
                DataAttachmentPurpose::Recovery { .. }
            ),
            ControlMessage::DataReady(ready) => {
                let active = self.pending_candidate.as_ref().is_some_and(|pending| {
                    pending.recovery
                        && pending.attempt.new_generation == ready.generation
                        && pending.attempt.new_connection_id == ready.connection_id
                        && pending.prepare_message_id == ready.reply_to
                });
                let completed = self.completed_recovery.as_ref().is_some_and(|recovery| {
                    recovery
                        .prepare_message_id
                        .as_deref()
                        .is_some_and(|prepare_id| prepare_id == ready.reply_to)
                        && recovery.begin.attempt.new_generation == ready.generation
                        && recovery.begin.attempt.new_connection_id == ready.connection_id
                });
                active || completed
            }
            _ => false,
        }
    }

    fn rotation_message_attempt(
        &self,
        message: &ControlMessage,
    ) -> Option<RotationAttemptIdentity> {
        match message {
            ControlMessage::RotatePrepare(value) => Some(value.attempt.clone()),
            ControlMessage::RotateQuiesce(value) => Some(value.attempt.clone()),
            ControlMessage::RotateFrozen(value) => Some(value.attempt.clone()),
            ControlMessage::RotateDrained(value) => Some(value.attempt.clone()),
            ControlMessage::RotateCommit(value) => Some(value.attempt.clone()),
            ControlMessage::RotateCommitted(value) => Some(value.attempt.clone()),
            ControlMessage::RotateRetire(value) => Some(value.attempt.clone()),
            ControlMessage::RotateRetired(value) => Some(value.attempt.clone()),
            ControlMessage::RotateComplete(value) => Some(value.attempt.clone()),
            ControlMessage::RotateAbort(value) => Some(value.attempt.clone()),
            ControlMessage::RotateAborted(value) => Some(value.attempt.clone()),
            _ => None,
        }
    }

    fn rotation_message_remaining(message: &ControlMessage) -> Option<u64> {
        match message {
            ControlMessage::RotatePrepare(value) => Some(value.remaining_ms),
            ControlMessage::RotateQuiesce(value) => Some(value.remaining_ms),
            ControlMessage::RotateAbort(value) => Some(value.remaining_ms),
            _ => None,
        }
    }

    fn validate_rotation_deadline(
        &self,
        message: &ControlMessage,
        scope: RotationJournalScope,
    ) -> Result<(), ClientError> {
        let Some(remaining_ms) = Self::rotation_message_remaining(message) else {
            return Ok(());
        };
        let now = self.now_ms();
        if remaining_ms == 0 {
            return Err(ClientError::Protocol(
                "rotation message has an empty remaining deadline".to_owned(),
            ));
        }
        let _deadline = match scope {
            RotationJournalScope::Active => self
                .rotation_journal_deadline_ms
                .or_else(|| self.rotation.status().deadline_ms)
                .or_else(|| match message {
                    ControlMessage::RotatePrepare(prepare) => {
                        self.rotation_deadline_cap(now, prepare.remaining_ms)
                    }
                    _ => None,
                }),
            RotationJournalScope::Completed => self
                .completed_rotation
                .as_ref()
                .map(|completed| completed.deadline_ms),
        }
        .ok_or_else(|| {
            ClientError::Protocol("rotation message has no immutable deadline".to_owned())
        })?;
        // `remaining_ms` is measured by the sender and can be slightly later
        // than this actor's monotonic sample after transit.  The journal's
        // first local deadline remains authoritative; later values are never
        // used to extend it.  Only the first PREPARE needs an overflow check
        // because it establishes that immutable local deadline.
        if matches!(message, ControlMessage::RotatePrepare(_))
            && self.rotation_journal_deadline_ms.is_none()
            && self.rotation.status().deadline_ms.is_none()
        {
            self.rotation_deadline_cap(now, remaining_ms)
                .ok_or_else(|| {
                    ClientError::Protocol("rotation message deadline overflow".to_owned())
                })?;
        }
        Ok(())
    }

    fn rotation_deadline_cap(&self, now_ms: u64, remaining_ms: u64) -> Option<u64> {
        now_ms.checked_add(remaining_ms.min(self.rotation.config().overlap_timeout_ms))
    }

    /// Validate the complete physical/session identity before the message ID
    /// enters the rotation journal.  This keeps a stale message from filling
    /// the bounded journal and, more importantly, prevents a duplicate ID from
    /// being used to bypass a newer attempt's phase checks.
    fn rotation_journal_scope(
        &self,
        message: &ControlMessage,
    ) -> Result<RotationJournalScope, ClientError> {
        let now = self.now_ms();
        if let ControlMessage::DataReady(ready) = message {
            if ready.session_id != self.session.session_id || ready.epoch != self.session.epoch {
                return Err(ClientError::Protocol(
                    "DATA_READY session identity mismatch".to_owned(),
                ));
            }
            if let Some(pending) = self.pending_candidate.as_ref()
                && ready.generation == pending.attempt.new_generation
                && ready.connection_id == pending.attempt.new_connection_id
                && ready.reply_to == pending.prepare_message_id
                && self
                    .rotation
                    .status()
                    .attempt
                    .as_ref()
                    .is_some_and(|attempt| attempt == &pending.attempt)
            {
                return Ok(RotationJournalScope::Active);
            }
            if let Some(completed) = self.completed_rotation.as_ref()
                && now < completed.deadline_ms
                && ready.generation == completed.attempt.new_generation
                && ready.connection_id == completed.attempt.new_connection_id
                && completed
                    .prepare_message_id
                    .as_deref()
                    .is_some_and(|prepare_id| prepare_id == ready.reply_to)
            {
                return Ok(RotationJournalScope::Completed);
            }
            return Err(ClientError::Protocol(
                "DATA_READY does not bind a known rotation candidate".to_owned(),
            ));
        }

        let attempt = self.rotation_message_attempt(message).ok_or_else(|| {
            ClientError::Protocol("rotation journal received an untyped message".to_owned())
        })?;
        if attempt.session_id != self.session.session_id
            || attempt.epoch != self.session.epoch
            || attempt.owner_id != self.owner_id
        {
            return Err(ClientError::Protocol(
                "rotation message session identity mismatch".to_owned(),
            ));
        }
        if let Some(completed) = self.completed_rotation.as_ref()
            && completed.attempt == attempt
        {
            if now >= completed.deadline_ms {
                return Err(ClientError::Protocol(
                    "rotation duplicate arrived after its retention deadline".to_owned(),
                ));
            }
            return Ok(RotationJournalScope::Completed);
        }
        if self
            .rotation
            .status()
            .attempt
            .as_ref()
            .is_some_and(|current| current == &attempt)
        {
            return Ok(RotationJournalScope::Active);
        }

        // The first PREPARE arrives while RotationState is still Active; it
        // is the message that creates the state-machine attempt.
        if matches!(message, ControlMessage::RotatePrepare(_))
            && self.rotation.phase() == RotationPhase::Active
            && attempt.old_generation == self.rotation.active_generation()
            && attempt.old_connection_id == self.rotation.active_connection_id()
        {
            if self
                .completed_rotation
                .as_ref()
                .is_some_and(|completed| now < completed.deadline_ms)
            {
                return Err(ClientError::Protocol(
                    "previous rotation journal is still retained".to_owned(),
                ));
            }
            return Ok(RotationJournalScope::Active);
        }
        Err(ClientError::Protocol(
            "rotation message does not bind the active attempt".to_owned(),
        ))
    }

    fn observe_rotation_message(
        &mut self,
        message: &ControlMessage,
        scope: RotationJournalScope,
    ) -> Result<JournalObservation, ClientError> {
        let canonical =
            encode_control(message).map_err(|error| ClientError::Protocol(error.to_string()))?;
        let now = self.now_ms();
        match scope {
            RotationJournalScope::Completed => {
                let completed = self.completed_rotation.as_mut().ok_or_else(|| {
                    ClientError::Protocol("completed rotation journal disappeared".to_owned())
                })?;
                completed
                    .journal
                    .observe(message.message_id(), &canonical, now)
                    .map_err(|error| {
                        ClientError::Protocol(format!("rotation journal rejected: {error}"))
                    })
            }
            RotationJournalScope::Active => {
                let attempt = self
                    .rotation_message_attempt(message)
                    .or_else(|| {
                        self.pending_candidate
                            .as_ref()
                            .map(|pending| pending.attempt.clone())
                    })
                    .ok_or_else(|| {
                        ClientError::Protocol(
                            "active rotation message has no attempt identity".to_owned(),
                        )
                    })?;
                if let Some(existing) = self.rotation_journal_attempt.as_ref()
                    && existing != &attempt
                {
                    return Err(ClientError::Protocol(
                        "rotation journal attempt changed".to_owned(),
                    ));
                }
                if self.rotation_journal.is_none() {
                    // A stale completed tombstone may safely be released only
                    // when its immutable overlap deadline has elapsed.
                    if self
                        .completed_rotation
                        .as_ref()
                        .is_some_and(|completed| now >= completed.deadline_ms)
                    {
                        self.completed_rotation = None;
                    }
                    let deadline = self
                        .rotation_journal_deadline_ms
                        .or_else(|| self.rotation.status().deadline_ms)
                        .or_else(|| match message {
                            ControlMessage::RotatePrepare(prepare) => {
                                self.rotation_deadline_cap(now, prepare.remaining_ms)
                            }
                            _ => None,
                        })
                        .ok_or_else(|| {
                            ClientError::Protocol(
                                "rotation journal has no immutable deadline".to_owned(),
                            )
                        })?;
                    if deadline <= now {
                        return Err(ClientError::Protocol(
                            "rotation journal deadline already expired".to_owned(),
                        ));
                    }
                    let max_bytes = self.config.limits.max_queue_bytes.min(4 * 1024 * 1024);
                    let journal =
                        ControlJournal::new(128, max_bytes, now, deadline).map_err(|error| {
                            ClientError::Protocol(format!("rotation journal unavailable: {error}"))
                        })?;
                    self.rotation_journal = Some(journal);
                    self.rotation_journal_attempt = Some(attempt);
                    self.rotation_journal_deadline_ms = Some(deadline);
                }
                self.rotation_journal
                    .as_mut()
                    .expect("rotation journal initialized above")
                    .observe(message.message_id(), &canonical, now)
                    .map_err(|error| {
                        ClientError::Protocol(format!("rotation journal rejected: {error}"))
                    })
            }
        }
    }

    fn complete_rotation_message(
        &mut self,
        request_id: &str,
        response: Option<&ControlMessage>,
    ) -> Result<(), ClientError> {
        let encoded = match response {
            Some(response) => encode_control(response)
                .map_err(|error| ClientError::Protocol(error.to_string()))?,
            None => Vec::new(),
        };
        let now = self.now_ms();
        let Some(journal) = self.rotation_journal.as_mut() else {
            return Err(ClientError::Protocol(
                "rotation response was not journaled".to_owned(),
            ));
        };
        journal
            .complete(request_id, &encoded, now)
            .map_err(|error| {
                ClientError::Protocol(format!("rotation journal completion failed: {error}"))
            })
    }

    fn send_rotation_reply(
        &mut self,
        request_id: &str,
        response: ControlMessage,
    ) -> Result<(), ClientError> {
        self.rotation_reply_cache
            .insert(request_id.to_owned(), response.clone());
        // Complete the journal before queueing the reply.  If the queue is
        // already closing, the actor fails and no later duplicate can apply
        // the transition a second time.
        self.complete_rotation_message(request_id, Some(&response))?;
        self.send_control(response, None)
    }

    fn resend_rotation_reply(
        &mut self,
        message_id: &str,
        scope: RotationJournalScope,
    ) -> Result<(), ClientError> {
        let response = match scope {
            RotationJournalScope::Active => self.rotation_reply_cache.get(message_id).cloned(),
            RotationJournalScope::Completed => self
                .completed_rotation
                .as_ref()
                .and_then(|completed| completed.replies.get(message_id).cloned()),
        };
        if let Some(response) = response {
            self.send_control(response, None)?;
        }
        Ok(())
    }

    fn finish_rotation_tombstone(&mut self) -> Result<(), ClientError> {
        let Some(journal) = self.rotation_journal.take() else {
            return Ok(());
        };
        let attempt = self.rotation_journal_attempt.take().ok_or_else(|| {
            ClientError::Protocol("rotation journal lost its attempt identity".to_owned())
        })?;
        let deadline_ms = self.rotation_journal_deadline_ms.take().ok_or_else(|| {
            ClientError::Protocol("rotation journal lost its deadline".to_owned())
        })?;
        if self
            .completed_rotation
            .as_ref()
            .is_some_and(|completed| self.now_ms() < completed.deadline_ms)
        {
            return Err(ClientError::Protocol(
                "completed rotation journal would be evicted before its deadline".to_owned(),
            ));
        }
        let replies = std::mem::take(&mut self.rotation_reply_cache);
        let prepare_message_id = self.rotation_prepare_message_id.take();
        self.local_frozen_message_id = None;
        self.local_drained_message_id = None;
        self.local_committed_message_id = None;
        self.local_retired_message_id = None;
        self.peer_drained_message_id = None;
        self.peer_committed_message_id = None;
        self.peer_retire_message_id = None;
        self.peer_abort_message_id = None;
        self.pending_abort_reply_id = None;
        self.completed_rotation = Some(RotationJournalTombstone {
            attempt,
            deadline_ms,
            prepare_message_id,
            journal,
            replies,
        });
        Ok(())
    }

    async fn handle_rotation_control(
        &mut self,
        message: ControlMessage,
    ) -> Result<(), ClientError> {
        let scope = self.rotation_journal_scope(&message)?;
        self.validate_rotation_deadline(&message, scope)?;
        let observation = self.observe_rotation_message(&message, scope)?;
        match observation {
            JournalObservation::CompletedDuplicate => {
                self.resend_rotation_reply(message.message_id(), scope)?;
                return Ok(());
            }
            JournalObservation::PendingDuplicate => return Ok(()),
            JournalObservation::New => {
                if scope == RotationJournalScope::Completed {
                    return Err(ClientError::Protocol(
                        "new message arrived for a completed rotation".to_owned(),
                    ));
                }
            }
        }
        let request_id = message.message_id().to_owned();
        self.handle_control_unjournaled(message.clone()).await?;
        // Replies sent asynchronously by the barrier/drain path have already
        // completed this entry.  All other phase messages are one-way and get
        // an explicit empty completion so a retry never invokes the handler.
        if !self.rotation_reply_cache.contains_key(&request_id) {
            match message {
                ControlMessage::RotateQuiesce(_) | ControlMessage::RotateFrozen(_) => {}
                _ => self.complete_rotation_message(&request_id, None)?,
            }
        }
        if matches!(
            message,
            ControlMessage::RotateComplete(_) | ControlMessage::RotateAborted(_)
        ) {
            self.finish_rotation_tombstone()?;
        }
        Ok(())
    }

    /// Observe a fully validated recovery request before mutating any actor
    /// state.  The journal has the same immutable episode deadline as the
    /// rotation state and retains bounded canonical fingerprints so a retry
    /// can be answered without applying its effects a second time.
    fn observe_recovery_message(
        &mut self,
        message: &ControlMessage,
        deadline_ms: u64,
    ) -> Result<JournalObservation, ClientError> {
        let canonical =
            encode_control(message).map_err(|error| ClientError::Protocol(error.to_string()))?;
        let now = self.now_ms();
        if self.control_journal.is_none() {
            let max_bytes = self.config.limits.max_queue_bytes.min(4 * 1024 * 1024);
            self.control_journal = Some(
                ControlJournal::new(128, max_bytes, now, deadline_ms).map_err(|error| {
                    ClientError::Protocol(format!("control journal unavailable: {error}"))
                })?,
            );
        }
        self.control_journal
            .as_mut()
            .expect("control journal was initialized above")
            .observe(message.message_id(), &canonical, now)
            .map_err(|error| ClientError::Protocol(format!("control journal rejected: {error}")))
    }

    fn complete_recovery_message(
        &mut self,
        request_id: &str,
        response: Option<&ControlMessage>,
    ) -> Result<(), ClientError> {
        let encoded = match response {
            Some(response) => encode_control(response)
                .map_err(|error| ClientError::Protocol(error.to_string()))?,
            None => Vec::new(),
        };
        let now = self.now_ms();
        let Some(journal) = self.control_journal.as_mut() else {
            return Err(ClientError::Protocol(
                "recovery response was not journaled".to_owned(),
            ));
        };
        journal
            .complete(request_id, &encoded, now)
            .map_err(|error| {
                ClientError::Protocol(format!("control journal completion failed: {error}"))
            })
    }

    fn recovery_rotation_scope(
        &self,
        message: &ControlMessage,
    ) -> Result<RotationJournalScope, ClientError> {
        let now = self.now_ms();
        match message {
            ControlMessage::RotatePrepare(prepare) => {
                let DataAttachmentPurpose::Recovery {
                    episode_id,
                    attempt_no,
                    closure_digest,
                } = &prepare.attachment_purpose
                else {
                    return Err(ClientError::Protocol(
                        "ordinary rotation message entered recovery journal".to_owned(),
                    ));
                };
                if let Some(recovery) = self.recovery.as_ref()
                    && now < recovery.deadline_ms
                    && prepare.attempt == recovery.begin.attempt
                    && prepare.reply_to == recovery.local_closed.message_id.as_str()
                    && episode_id == &recovery.begin.episode_id
                    && *attempt_no == recovery.begin.attempt_no
                    && recovery.combined_digest.as_deref() == Some(closure_digest.as_str())
                {
                    return Ok(RotationJournalScope::Active);
                }
                if let Some(recovery) = self.completed_recovery.as_ref()
                    && now < recovery.deadline_ms
                    && prepare.attempt == recovery.begin.attempt
                    && prepare.reply_to == recovery.local_closed.message_id.as_str()
                    && episode_id == &recovery.begin.episode_id
                    && *attempt_no == recovery.begin.attempt_no
                    && recovery.combined_digest.as_deref() == Some(closure_digest.as_str())
                {
                    return Ok(RotationJournalScope::Completed);
                }
                Err(ClientError::Protocol(
                    "recovery candidate PREPARE does not bind the episode".to_owned(),
                ))
            }
            ControlMessage::DataReady(ready) => {
                if ready.session_id != self.session.session_id || ready.epoch != self.session.epoch
                {
                    return Err(ClientError::Protocol(
                        "recovery DATA_READY session identity mismatch".to_owned(),
                    ));
                }
                if let Some(pending) = self.pending_candidate.as_ref()
                    && pending.recovery
                    && pending.attempt.new_generation == ready.generation
                    && pending.attempt.new_connection_id == ready.connection_id
                    && pending.prepare_message_id == ready.reply_to
                    && self
                        .recovery
                        .as_ref()
                        .is_some_and(|recovery| now < recovery.deadline_ms)
                {
                    return Ok(RotationJournalScope::Active);
                }
                if let Some(recovery) = self.completed_recovery.as_ref()
                    && now < recovery.deadline_ms
                    && recovery.begin.attempt.new_generation == ready.generation
                    && recovery.begin.attempt.new_connection_id == ready.connection_id
                    && recovery
                        .prepare_message_id
                        .as_deref()
                        .is_some_and(|prepare_id| prepare_id == ready.reply_to)
                {
                    return Ok(RotationJournalScope::Completed);
                }
                Err(ClientError::Protocol(
                    "recovery DATA_READY does not bind the candidate".to_owned(),
                ))
            }
            _ => Err(ClientError::Protocol(
                "unexpected recovery rotation message".to_owned(),
            )),
        }
    }

    async fn handle_recovery_rotation_control(
        &mut self,
        message: ControlMessage,
    ) -> Result<(), ClientError> {
        let scope = self.recovery_rotation_scope(&message)?;
        let deadline_ms = match scope {
            RotationJournalScope::Active => self
                .recovery
                .as_ref()
                .map(|recovery| recovery.deadline_ms)
                .ok_or_else(|| {
                    ClientError::Protocol("active recovery journal disappeared".to_owned())
                })?,
            RotationJournalScope::Completed => self
                .completed_recovery
                .as_ref()
                .map(|recovery| recovery.deadline_ms)
                .ok_or_else(|| {
                    ClientError::Protocol("completed recovery journal disappeared".to_owned())
                })?,
        };
        let observation = self.observe_recovery_message(&message, deadline_ms)?;
        match observation {
            JournalObservation::CompletedDuplicate | JournalObservation::PendingDuplicate => {
                return Ok(());
            }
            JournalObservation::New if scope == RotationJournalScope::Completed => {
                return Err(ClientError::Protocol(
                    "new message arrived for a completed recovery candidate".to_owned(),
                ));
            }
            JournalObservation::New => {}
        }
        let request_id = message.message_id().to_owned();
        self.handle_control_unjournaled(message).await?;
        self.complete_recovery_message(&request_id, None)
    }

    fn resend_recovery_reply(&self, message: &ControlMessage) -> Result<(), ClientError> {
        let recovery = self.recovery.as_ref().or(self.completed_recovery.as_ref());
        let reply = match message {
            ControlMessage::RecoveryBegin(_) => recovery
                .map(|recovery| ControlMessage::RecoveryClosed(recovery.local_closed.clone())),
            ControlMessage::Resume(resume) => recovery.and_then(|recovery| {
                let index = direction_index(resume.direction);
                match resume.stage {
                    ResumeStage::Snapshot => recovery.snapshot_reply_messages[index]
                        .clone()
                        .map(ControlMessage::Resumed),
                    ResumeStage::Ready => recovery.ready_reply_messages[index]
                        .clone()
                        .map(ControlMessage::Resumed),
                }
            }),
            _ => None,
        };
        if let Some(reply) = reply {
            self.send_control(reply, None)?;
        }
        Ok(())
    }

    async fn handle_event(&mut self, event: ActorEvent) -> Result<(), ClientError> {
        match event {
            ActorEvent::Data(event) => self.handle_carrier_event(event).await,
        }
    }

    async fn handle_control_message(&mut self, message: Message) -> Result<(), ClientError> {
        match message {
            Message::Text(text) => {
                let control = decode_control(text.as_bytes())
                    .map_err(|error| ClientError::Protocol(error.to_string()))?;
                self.handle_control(control).await
            }
            Message::Binary(_) => Err(ClientError::Protocol(
                "binary message on control socket".to_owned(),
            )),
            Message::Ping(payload) => self.control_queue.try_send(Message::Pong(payload)),
            Message::Pong(_) | Message::Frame(_) => Ok(()),
            Message::Close(_) => Err(ClientError::Transport {
                scope: "control read",
                detail: "control socket closed".to_owned(),
            }),
        }
    }

    async fn handle_control(&mut self, message: ControlMessage) -> Result<(), ClientError> {
        if self.is_recovery_rotation_message(&message) {
            return self.handle_recovery_rotation_control(message).await;
        }
        if self.should_journal_rotation(&message) {
            return self.handle_rotation_control(message).await;
        }
        self.handle_control_unjournaled(message).await
    }

    async fn handle_control_unjournaled(
        &mut self,
        message: ControlMessage,
    ) -> Result<(), ClientError> {
        match message {
            ControlMessage::Open(open) => self.handle_open(open).await,
            ControlMessage::AuthorizationConfirmed(confirmed) => {
                self.handle_authorization_confirmed(confirmed).await
            }
            ControlMessage::AuthorizationInvalidated(invalidated) => {
                self.handle_authorization_invalidated(invalidated).await
            }
            ControlMessage::Cancel(cancel) => self.handle_cancel(cancel).await,
            ControlMessage::Ping(ping) => self.handle_ping(ping),
            ControlMessage::DataReady(ready) => self.handle_candidate_ready(ready).await,
            ControlMessage::RotatePrepare(prepare) => self.handle_rotate_prepare(prepare).await,
            ControlMessage::RotateQuiesce(quiesce) => self.handle_rotate_quiesce(quiesce),
            ControlMessage::RotateFrozen(frozen) => self.handle_rotate_frozen(frozen),
            ControlMessage::RotateDrained(drained) => self.handle_rotate_drained(drained),
            ControlMessage::RotateCommit(commit) => self.handle_rotate_commit(commit).await,
            ControlMessage::RotateCommitted(committed) => self.handle_rotate_committed(committed),
            ControlMessage::RotateRetire(retire) => self.handle_rotate_retire(retire).await,
            ControlMessage::RotateRetired(retired) => self.handle_rotate_retired(retired),
            ControlMessage::RotateComplete(complete) => self.handle_rotate_complete(complete).await,
            ControlMessage::RotateAbort(abort) => self.handle_rotate_abort(abort).await,
            ControlMessage::RotateAborted(aborted) => self.handle_rotate_aborted(aborted).await,
            ControlMessage::Resume(resume) => self.handle_resume(resume).await,
            ControlMessage::Resumed(resumed) => self.handle_resumed(resumed),
            ControlMessage::GoAway(goaway) => {
                if goaway.session_id == self.session.session_id
                    && goaway.epoch == self.session.epoch
                {
                    self.accepting = false;
                }
                Ok(())
            }
            ControlMessage::Welcome(_)
            | ControlMessage::Opened(_)
            | ControlMessage::Rejected(_)
            | ControlMessage::Hello(_)
            | ControlMessage::Pong(_)
            | ControlMessage::AuthorizationChallenge(_) => Ok(()),
            ControlMessage::StreamForget(forget) => self.handle_stream_forget(forget),
            ControlMessage::RecoveryBegin(begin) => self.handle_recovery_begin(begin).await,
            ControlMessage::RecoveryClosed(closed) => self.handle_recovery_closed(closed),
            ControlMessage::RotateRequest(_) => Err(ClientError::Protocol(
                "connector received an unsolicited ROTATE_REQUEST".to_owned(),
            )),
        }
    }

    async fn handle_recovery_begin(&mut self, begin: RecoveryBegin) -> Result<(), ClientError> {
        if begin.attempt.session_id != self.session.session_id
            || begin.attempt.epoch != self.session.epoch
            || begin.attempt.owner_id != self.owner_id
        {
            return Err(ClientError::Protocol(
                "RECOVERY_BEGIN session identity mismatch".to_owned(),
            ));
        }
        let now = self.now_ms();
        if begin.remaining_ms == 0
            || begin.remaining_ms > self.rotation.config().recovery_timeout_ms
        {
            return Err(ClientError::Protocol(
                "RECOVERY_BEGIN exceeds the local recovery budget".to_owned(),
            ));
        }
        // A completed episode is retained as a bounded tombstone.  An exact
        // retransmission gets the cached closure record; a mutation of that
        // episode/attempt is stale and cannot start another teardown.  A
        // different episode may begin only after the active carrier is back.
        if let Some(completed) = self.completed_recovery.as_ref() {
            if begin.episode_id == completed.begin.episode_id {
                if begin == completed.begin {
                    if now >= completed.deadline_ms {
                        return Err(ClientError::Protocol(
                            "RECOVERY_BEGIN arrived after the retained episode deadline".to_owned(),
                        ));
                    }
                    self.resend_recovery_reply(&ControlMessage::RecoveryBegin(begin))?;
                    return Ok(());
                }
                return Err(ClientError::Protocol(
                    "RECOVERY_BEGIN changed a completed recovery episode".to_owned(),
                ));
            }
            if self.rotation.phase() != RotationPhase::Active {
                return Err(ClientError::Protocol(
                    "RECOVERY_BEGIN changed while a recovery episode is active".to_owned(),
                ));
            }
            self.completed_recovery = None;
            self.control_journal = None;
        }
        if let Some(existing) = self.recovery.as_ref() {
            if begin.episode_id != existing.begin.episode_id
                || begin.roster != existing.begin.roster
            {
                return Err(ClientError::Protocol(
                    "RECOVERY_BEGIN changed the immutable episode roster".to_owned(),
                ));
            }
            if begin.attempt_no < existing.begin.attempt_no
                || (begin.attempt_no == existing.begin.attempt_no && begin != existing.begin)
                || begin.attempt_no > existing.begin.attempt_no.saturating_add(1)
            {
                return Err(ClientError::Protocol(
                    "RECOVERY_BEGIN attempt is not the current retry".to_owned(),
                ));
            }
            if begin.attempt_no > existing.begin.attempt_no
                && (begin.attempt.old_generation != existing.begin.attempt.old_generation
                    || begin.attempt.old_connection_id != existing.begin.attempt.old_connection_id)
            {
                return Err(ClientError::Protocol(
                    "RECOVERY_BEGIN changed the retained transport anchor".to_owned(),
                ));
            }
        }
        let previous_deadline = self.recovery.as_ref().map(|recovery| recovery.deadline_ms);
        let exact_existing = self
            .recovery
            .as_ref()
            .is_some_and(|recovery| recovery.begin == begin);
        let episode_deadline_ms = match previous_deadline {
            Some(deadline) => {
                if now >= deadline
                    || (!exact_existing && begin.remaining_ms > deadline.saturating_sub(now))
                {
                    return Err(ClientError::Protocol(
                        "RECOVERY_BEGIN extends the existing recovery deadline".to_owned(),
                    ));
                }
                deadline
            }
            None => now
                .checked_add(begin.remaining_ms)
                .ok_or_else(|| ClientError::Protocol("recovery deadline overflow".to_owned()))?,
        };
        let observed = self.observe_recovery_message(
            &ControlMessage::RecoveryBegin(begin.clone()),
            episode_deadline_ms,
        )?;
        if !matches!(observed, JournalObservation::New) {
            if self
                .recovery
                .as_ref()
                .is_some_and(|recovery| recovery.begin == begin)
            {
                self.resend_recovery_reply(&ControlMessage::RecoveryBegin(begin))?;
                return Ok(());
            }
            return Err(ClientError::Protocol(
                "RECOVERY_BEGIN duplicate has no matching retained state".to_owned(),
            ));
        }
        let previous_closed_ids = if let Some(existing) = self.recovery.as_ref() {
            if self.rotation.phase() != RotationPhase::Recovering {
                return Err(ClientError::Protocol(
                    "RECOVERY_BEGIN changed an active recovery episode".to_owned(),
                ));
            }
            existing.local_closed.closed_connection_ids.clone()
        } else {
            Vec::new()
        };

        // A recovery begin is the authenticated handoff point.  The state
        // machine must first enter Recovering, then every old carrier and
        // reserved candidate must be joined and released before the new
        // attempt is allocated.
        if self.rotation.phase() == RotationPhase::Active {
            self.rotation
                .transport_lost(&begin.attempt, now, RecoveryReason::OldTransportLost)
                .map_err(|error| {
                    ClientError::Protocol(format!("recovery transport loss rejected: {error}"))
                })?;
        } else if self.rotation.phase() != RotationPhase::Recovering {
            let current = self.rotation.status().attempt.ok_or_else(|| {
                ClientError::Protocol("recovery begin without a rotation anchor".to_owned())
            })?;
            self.rotation
                .transport_lost(&current, now, RecoveryReason::OldTransportLost)
                .map_err(|error| {
                    ClientError::Protocol(format!("recovery transport loss rejected: {error}"))
                })?;
        }

        let closed = self.close_all_carriers_for_recovery().await?;
        let mut closed_connection_ids = Vec::with_capacity(closed.len());
        for (connection_id, evidence) in &closed {
            if previous_closed_ids.iter().any(|id| id == connection_id) {
                closed_connection_ids.push(connection_id.clone());
                continue;
            }
            self.rotation
                .close_for_recovery(connection_id.clone(), evidence.clone(), self.now_ms())
                .map_err(|error| {
                    ClientError::Protocol(format!("recovery closure rejected: {error}"))
                })?;
            closed_connection_ids.push(connection_id.clone());
        }
        closed_connection_ids.sort();
        self.recovery = None;
        self.rotation
            .begin_recovery(
                begin.attempt.clone(),
                begin.roster.clone(),
                self.now_ms(),
                RecoveryReason::OldTransportLost,
                episode_deadline_ms,
            )
            .map_err(|error| ClientError::Protocol(format!("recovery begin rejected: {error}")))?;

        let local_snapshots = self.local_resume_snapshots(&begin.roster)?;
        let mut local_closed = RecoveryClosed {
            message_id: message_id(),
            reply_to: begin.message_id.clone(),
            attempt: begin.attempt.clone(),
            episode_id: begin.episode_id.clone(),
            attempt_no: begin.attempt_no,
            closed_connection_ids,
            closure_digest: String::new(),
        };
        local_closed.closure_digest = local_closed
            .closure_digest_for(RecoverySide::Connector)
            .map_err(|error| ClientError::Protocol(error.to_string()))?;
        let recovery = RecoveryRuntime {
            begin: begin.clone(),
            local_closed: local_closed.clone(),
            prepare_message_id: None,
            peer_closed: None,
            combined_digest: None,
            deadline_ms: episode_deadline_ms,
            local_snapshots,
            remote_snapshots: [BTreeMap::new(), BTreeMap::new()],
            remote_ready_snapshots: [BTreeMap::new(), BTreeMap::new()],
            remote_snapshot_message_ids: [None, None],
            snapshot_reply_message_ids: [None, None],
            snapshot_reply_messages: [None, None],
            remote_ready_message_ids: [None, None],
            remote_ready: [false, false],
            local_plans: BTreeMap::new(),
            peer_snapshots: BTreeMap::new(),
            snapshot_replies: [false, false],
            ready_replies: [false, false],
            ready_reply_messages: [None, None],
            fresh_reconciled: false,
            attempt_deadline_ms: None,
        };
        self.closed_for_recovery = closed;
        self.recovery = Some(recovery);
        self.recovery_requested = false;
        self.accepting = false;
        self.writes_frozen = true;
        let response = ControlMessage::RecoveryClosed(local_closed);
        self.send_control(response.clone(), None)?;
        self.complete_recovery_message(&begin.message_id, Some(&response))?;
        self.publish_status();
        Ok(())
    }

    fn handle_recovery_closed(&mut self, closed: RecoveryClosed) -> Result<(), ClientError> {
        if self.recovery.is_none() {
            let Some(completed) = self.completed_recovery.as_ref() else {
                return Err(ClientError::Protocol(
                    "RECOVERY_CLOSED without RECOVERY_BEGIN".to_owned(),
                ));
            };
            if self.now_ms() >= completed.deadline_ms
                || closed.reply_to != completed.begin.message_id
                || closed.attempt != completed.begin.attempt
                || closed.episode_id != completed.begin.episode_id
                || closed.attempt_no != completed.begin.attempt_no
                || closed.closed_connection_ids != completed.local_closed.closed_connection_ids
            {
                return Err(ClientError::Protocol(
                    "RECOVERY_CLOSED changed the completed recovery episode".to_owned(),
                ));
            }
            closed
                .verify_closure_digest(RecoverySide::Relay)
                .map_err(|error| ClientError::Protocol(error.to_string()))?;
            let deadline_ms = completed.deadline_ms;
            let observed = self
                .observe_recovery_message(&ControlMessage::RecoveryClosed(closed), deadline_ms)?;
            if !matches!(observed, JournalObservation::New) {
                return Ok(());
            }
            return Err(ClientError::Protocol(
                "completed RECOVERY_CLOSED was not retained in the journal".to_owned(),
            ));
        }
        let Some(recovery) = self.recovery.as_ref() else {
            return Err(ClientError::Protocol(
                "RECOVERY_CLOSED without RECOVERY_BEGIN".to_owned(),
            ));
        };
        if closed.reply_to != recovery.begin.message_id
            || closed.attempt != recovery.begin.attempt
            || closed.episode_id != recovery.begin.episode_id
            || closed.attempt_no != recovery.begin.attempt_no
        {
            return Err(ClientError::Protocol(
                "RECOVERY_CLOSED context mismatch".to_owned(),
            ));
        }
        // The digest authenticates the peer's record, while the actor-owned
        // closure map proves which physical IDs this endpoint actually
        // allocated before teardown.  Require the peer to attest that exact
        // sorted set; accepting a digest for an extra, omitted, or duplicated
        // ID would let a failed candidate be silently dropped from the
        // bilateral closure proof.
        let mut expected_ids = self.closed_for_recovery.keys().cloned().collect::<Vec<_>>();
        expected_ids.sort();
        let mut peer_ids = closed.closed_connection_ids.clone();
        peer_ids.sort();
        if peer_ids != expected_ids {
            return Err(ClientError::Protocol(
                "RECOVERY_CLOSED physical connection set mismatch".to_owned(),
            ));
        }
        closed
            .verify_closure_digest(RecoverySide::Relay)
            .map_err(|error| ClientError::Protocol(error.to_string()))?;
        let observed = self.observe_recovery_message(
            &ControlMessage::RecoveryClosed(closed.clone()),
            recovery.deadline_ms,
        )?;
        if !matches!(observed, JournalObservation::New) {
            return Ok(());
        }
        let closed_message_id = {
            let recovery = self
                .recovery
                .as_mut()
                .expect("recovery context was checked above");
            if recovery.peer_closed.is_some() {
                return Err(ClientError::Protocol(
                    "RECOVERY_CLOSED changed after acknowledgement".to_owned(),
                ));
            }
            let digest = combined_closure_digest(&closed, &recovery.local_closed)
                .map_err(|error| ClientError::Protocol(error.to_string()))?;
            let message_id = closed.message_id.clone();
            recovery.peer_closed = Some(closed);
            recovery.combined_digest = Some(digest);
            message_id
        };
        self.complete_recovery_message(&closed_message_id, None)?;
        self.publish_status();
        Ok(())
    }

    fn local_resume_snapshots(
        &self,
        roster: &tunnel_protocol::rotation_control::StreamRoster,
    ) -> Result<[BTreeMap<u64, ResumeDirectionState>; 2], ClientError> {
        let mut snapshots = [BTreeMap::new(), BTreeMap::new()];
        for stream_id in &roster.stream_ids {
            let stream = self.streams.get(stream_id).ok_or_else(|| {
                ClientError::Protocol(format!(
                    "recovery roster contains unknown stream {stream_id}"
                ))
            })?;
            let snapshot = stream.sequence.snapshot();
            for direction in [Direction::RelayToConnector, Direction::ConnectorToRelay] {
                let state = ResumeDirectionState::from_sequence_snapshot(
                    *stream_id,
                    snapshot.direction(direction),
                )
                .map_err(|error| ClientError::Protocol(error.to_string()))?;
                snapshots[direction_index(direction)].insert(*stream_id, state);
            }
        }
        Ok(snapshots)
    }

    async fn handle_open(&mut self, open: Open) -> Result<(), ClientError> {
        if open.session_id != self.session.session_id || open.epoch != self.session.epoch {
            return Err(ClientError::Protocol(
                "OPEN context does not match the authenticated session".to_owned(),
            ));
        }
        if !self.accepting {
            return self.send_rejected(&open, "GOAWAY", "connector is draining");
        }
        if self.streams.len() >= self.config.limits.max_streams {
            return self.send_rejected(&open, "RESOURCE_EXHAUSTED", "stream limit reached");
        }
        let Some(export) = self.config.exports.get(&open.service_id).cloned() else {
            return self.send_rejected(
                &open,
                "EXPORT_DENIED",
                "service is not locally allowlisted",
            );
        };
        if export.kind != super::ExportKind::Echo
            || !matches!(open.operation.as_str(), "echo" | "echo_stream")
        {
            return self.send_rejected(
                &open,
                "OPERATION_DENIED",
                "only the local echo operations are enabled",
            );
        }
        if self.streams.contains_key(&open.stream_id) {
            return self.send_rejected(&open, "STREAM_EXISTS", "stream ID is already active");
        }
        let started = Instant::now();
        let started_wall = SystemTime::now();
        let challenge_id = message_id();
        let nonce = message_id();
        let permission_digest = open
            .metadata
            .get("permission_digest")
            .cloned()
            .unwrap_or_else(|| "m2-echo".to_owned());
        let grant_revision = open
            .metadata
            .get("grant_revision")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let auth_deadline = DualDeadline::new(
            started,
            started_wall,
            Duration::from_millis(self.config.limits.grant_timeout_ms),
        )
        .ok_or_else(|| ClientError::Protocol("authorization deadline overflow".to_owned()))?;
        let operation_deadline = DualDeadline::new(
            started,
            started_wall,
            if open.operation == "echo_stream" {
                // A stream is bounded by transport/session lifetime.  Its
                // individual dispatches still require fresh five-second
                // authorization confirmations; this deadline only protects
                // the finite echo operation from a forgotten peer.
                Duration::from_secs(24 * 60 * 60)
            } else {
                Duration::from_millis(self.config.limits.operation_timeout_ms)
            },
        )
        .ok_or_else(|| ClientError::Protocol("operation deadline overflow".to_owned()))?;
        let opened = ControlMessage::Opened(Opened::new(
            message_id(),
            open.message_id.clone(),
            self.session.session_id.clone(),
            self.session.epoch,
            open.stream_id,
            open.operation_id.clone(),
            open.initial_receive_window,
            open.initial_send_window,
        ));
        self.send_control(opened, None)?;
        let challenge = ControlMessage::AuthorizationChallenge(AuthorizationChallenge::new(
            message_id(),
            self.session.session_id.clone(),
            self.session.epoch,
            open.stream_id,
            challenge_id.clone(),
            nonce.clone(),
            open.service_id.clone(),
            permission_digest.clone(),
            grant_revision,
        ));
        let initial_credit = open.initial_send_window.min(8 * 1024 * 1024);
        let receive_credit = open.initial_receive_window.min(8 * 1024 * 1024);
        // Partition the one session replay/reorder budget across the maximum
        // number of admitted streams. This keeps the aggregate retained
        // history bounded when several streams are active concurrently; a
        // per-stream default must never multiply the configured memory cap.
        let stream_slots = self.config.limits.max_streams.max(1);
        let replay_bytes = (self.config.limits.max_queue_bytes / stream_slots).max(1);
        let replay_frames = (self.config.limits.max_queue_frames / stream_slots).max(1);
        let limits = SequenceLimits::new(
            tunnel_protocol::sequence::DEFAULT_MAX_REPLAY_FRAMES.min(replay_frames),
            tunnel_protocol::sequence::DEFAULT_MAX_REPLAY_BYTES.min(replay_bytes),
            tunnel_protocol::sequence::DEFAULT_MAX_REORDER_FRAMES.min(replay_frames),
            tunnel_protocol::sequence::DEFAULT_MAX_REORDER_BYTES.min(replay_bytes),
        );
        let sequence = StreamState::with_credits_and_limits(
            open.stream_id,
            initial_credit,
            receive_credit,
            limits,
        )
        .map_err(|error| ClientError::Protocol(error.to_string()))?;
        self.streams.insert(
            open.stream_id,
            M2Stream {
                export,
                operation_id: open.operation_id,
                service_id: open.service_id,
                operation: open.operation,
                auth: AuthContext {
                    challenge_id,
                    nonce,
                    permission_digest,
                    grant_revision,
                    deadline: auth_deadline,
                    operation_deadline,
                    confirmed: false,
                    refresh_in_flight: true,
                    invalidated: false,
                },
                sequence,
                pending: VecDeque::new(),
                pending_bytes: 0,
                record_buffer: Vec::new(),
                record_expected: None,
                input_fin: false,
                input_reset: false,
                output_fin: false,
                output_reset: false,
                reset_queued: false,
            },
        );
        self.publish_status();
        self.send_control(challenge, Some(auth_deadline))
    }

    fn send_rejected(&self, open: &Open, code: &str, reason: &str) -> Result<(), ClientError> {
        self.send_control(
            ControlMessage::Rejected(Rejected::new(
                message_id(),
                open.message_id.clone(),
                self.session.session_id.clone(),
                self.session.epoch,
                open.stream_id,
                open.operation_id.clone(),
                code,
                reason,
            )),
            None,
        )
    }

    fn handle_rotate_drained(&mut self, drained: RotateDrained) -> Result<(), ClientError> {
        let Some(current) = self.rotation.status().attempt else {
            return Err(ClientError::Protocol(
                "ROTATE_DRAINED without an attempt".to_owned(),
            ));
        };
        if current != drained.attempt {
            return Err(ClientError::Protocol(
                "ROTATE_DRAINED attempt mismatch".to_owned(),
            ));
        }
        if self.local_frozen_message_id.as_deref() != Some(drained.reply_to.as_str()) {
            return Err(ClientError::Protocol(
                "ROTATE_DRAINED reply correlation mismatch".to_owned(),
            ));
        }
        if let Some(existing) = self.peer_drained_message_id.as_ref()
            && existing != &drained.message_id
        {
            return Err(ClientError::Protocol(
                "ROTATE_DRAINED semantic duplicate changed message ID".to_owned(),
            ));
        }
        if self.rotation.phase() == RotationPhase::Committing {
            return Ok(());
        }
        self.rotation
            .drained(&drained.attempt, drained.proof, self.now_ms())
            .map_err(|error| ClientError::Protocol(format!("remote drain rejected: {error}")))?;
        self.peer_drained_message_id = Some(drained.message_id);
        // The relay owns the session and is the sole commit coordinator.  A
        // connector records the second proof and waits for the owner's
        // ROTATE_COMMIT; emitting a commit here would be an unsolicited
        // control request (the relay has no connector-initiated commit arm)
        // and could race the owner's decision.
        Ok(())
    }

    async fn handle_rotate_commit(&mut self, commit: RotateCommit) -> Result<(), ClientError> {
        let Some(current) = self.rotation.status().attempt else {
            return Err(ClientError::Protocol(
                "ROTATE_COMMIT without an attempt".to_owned(),
            ));
        };
        if current != commit.attempt {
            return Err(ClientError::Protocol(
                "ROTATE_COMMIT attempt mismatch".to_owned(),
            ));
        }
        if self.local_drained_message_id.as_deref() != Some(commit.reply_to.as_str()) {
            return Err(ClientError::Protocol(
                "ROTATE_COMMIT reply correlation mismatch".to_owned(),
            ));
        }
        if let Some(existing) = self.peer_committed_message_id.as_ref()
            && existing != &commit.message_id
        {
            return Err(ClientError::Protocol(
                "ROTATE_COMMIT semantic duplicate changed message ID".to_owned(),
            ));
        }
        if commit.snapshot_id
            != self
                .local_fence
                .as_ref()
                .map(|fence| fence.snapshot_id.as_str())
                .unwrap_or_default()
        {
            return Err(ClientError::Protocol(
                "ROTATE_COMMIT snapshot mismatch".to_owned(),
            ));
        }
        self.rotation
            .commit(&commit.attempt, self.now_ms())
            .map_err(|error| ClientError::Protocol(format!("commit decision rejected: {error}")))?;
        self.rotation
            .committed(&commit.attempt, self.now_ms())
            .map_err(|error| {
                ClientError::Protocol(format!("candidate activation rejected: {error}"))
            })?;
        let candidate = self.candidate.take().ok_or_else(|| {
            ClientError::Protocol("ROTATE_COMMIT without candidate carrier".to_owned())
        })?;
        if !candidate.key.matches(
            commit.attempt.new_generation,
            &commit.attempt.new_connection_id,
        ) {
            return Err(ClientError::Protocol(
                "candidate carrier identity mismatch".to_owned(),
            ));
        }
        let old = std::mem::replace(&mut self.active, candidate);
        self.retiring = Some(old);
        self.pending_quiesce = None;
        let can_resume = self.rotation.phase() == RotationPhase::Active;
        self.accepting = can_resume;
        self.writes_frozen = !can_resume;
        self.rotation
            .retire(&commit.attempt, self.now_ms())
            .map_err(|error| {
                ClientError::Protocol(format!("retire transition rejected: {error}"))
            })?;
        self.peer_committed_message_id = Some(commit.message_id.clone());
        if can_resume {
            self.flush_pending_outputs().await?;
        }
        let response = ControlMessage::RotateCommitted(RotateCommitted {
            message_id: message_id(),
            reply_to: commit.message_id.clone(),
            attempt: commit.attempt,
            snapshot_id: commit.snapshot_id,
        });
        self.local_committed_message_id = Some(response.message_id().to_owned());
        self.send_rotation_reply(&commit.message_id, response)?;
        self.publish_status();
        Ok(())
    }

    fn handle_rotate_committed(&mut self, _committed: RotateCommitted) -> Result<(), ClientError> {
        Err(ClientError::Protocol(
            "connector received unexpected ROTATE_COMMITTED".to_owned(),
        ))
    }

    async fn handle_authorization_confirmed(
        &mut self,
        confirmed: AuthorizationConfirmed,
    ) -> Result<(), ClientError> {
        if confirmed.session_id != self.session.session_id || confirmed.epoch != self.session.epoch
        {
            return Err(ClientError::Protocol(
                "authorization confirmation context mismatch".to_owned(),
            ));
        }
        let stream_id = confirmed.stream_id;
        let (pending, pending_bytes) = {
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                return Ok(());
            };
            if stream.auth.confirmed && !stream.auth.refresh_in_flight {
                return Ok(());
            }
            let now = Instant::now();
            let wall_now = SystemTime::now();
            let valid = stream.auth.challenge_id == confirmed.challenge_id
                && stream.auth.nonce == confirmed.nonce
                && stream.auth.permission_digest == confirmed.permission_digest
                && stream.auth.grant_revision == confirmed.grant_revision
                && stream.auth.refresh_in_flight
                && !stream.auth.invalidated
                && (1..=5_000).contains(&confirmed.remaining_ms)
                && !stream.auth.deadline.expired_at(now, wall_now)
                && !stream.auth.operation_deadline.expired_at(now, wall_now);
            if !valid {
                (VecDeque::new(), 0)
            } else {
                // The challenge deadline was created before its fresh nonce
                // was sent. Confirmation may shorten that immutable window to
                // the relay's grant, but can never move it forward. The
                // separate operation deadline remains unchanged below.
                match stream.auth.deadline.shorten(Duration::from_millis(
                    confirmed
                        .remaining_ms
                        .min(self.config.limits.grant_timeout_ms),
                )) {
                    Some(deadline) => {
                        stream.auth.deadline = deadline;
                        stream.auth.confirmed = true;
                        stream.auth.refresh_in_flight = false;
                        stream.auth.nonce.clear();
                        (std::mem::take(&mut stream.pending), stream.pending_bytes)
                    }
                    None => (VecDeque::new(), 0),
                }
            }
        };
        if pending.is_empty() && pending_bytes == 0 {
            let valid = self
                .streams
                .get(&stream_id)
                .is_some_and(|stream| stream.auth.confirmed);
            if !valid {
                return self.expire_stream(stream_id).await;
            }
        }
        self.pending_output_bytes = self.pending_output_bytes.saturating_sub(pending_bytes);
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.pending_bytes = 0;
        }
        for item in pending {
            match item {
                BufferedInput::Data(payload) => self.dispatch_payload(stream_id, payload).await?,
                BufferedInput::Fin => self.dispatch_fin(stream_id).await?,
            }
        }
        Ok(())
    }

    /// Keep long-lived echo streams authorized without extending either the
    /// operation deadline or a prior authorization confirmation. Each refresh
    /// gets a fresh challenge and nonce, and dispatch remains buffered while
    /// the bounded confirmation window is in flight.
    async fn refresh_authorizations(&mut self) -> Result<(), ClientError> {
        let now = Instant::now();
        let wall_now = SystemTime::now();
        let expired_ids: Vec<u64> = self
            .streams
            .iter()
            .filter_map(|(&stream_id, stream)| {
                (stream.auth.deadline.expired_at(now, wall_now)
                    || stream.auth.operation_deadline.expired_at(now, wall_now))
                .then_some(stream_id)
            })
            .collect();
        for stream_id in expired_ids {
            self.expire_stream(stream_id).await?;
        }
        let refresh_ids: Vec<(u64, String, String, u64)> = self
            .streams
            .iter()
            .filter_map(|(&stream_id, stream)| {
                if stream.operation != "echo_stream"
                    || !stream.auth.confirmed
                    || stream.auth.refresh_in_flight
                    || stream.auth.invalidated
                    || stream.auth.operation_deadline.expired_at(now, wall_now)
                    || stream.auth.deadline.remaining(now) > M2_AUTH_REFRESH_MARGIN
                {
                    return None;
                }
                Some((
                    stream_id,
                    stream.service_id.clone(),
                    stream.auth.permission_digest.clone(),
                    stream.auth.grant_revision,
                ))
            })
            .collect();

        for (stream_id, service_id, permission_digest, grant_revision) in refresh_ids {
            let Some(auth_deadline) = DualDeadline::new(
                now,
                wall_now,
                Duration::from_millis(self.config.limits.grant_timeout_ms),
            ) else {
                return Err(ClientError::Protocol(
                    "authorization refresh deadline overflow".to_owned(),
                ));
            };
            let challenge_id = message_id();
            let nonce = message_id();
            let challenge = ControlMessage::AuthorizationChallenge(AuthorizationChallenge::new(
                message_id(),
                self.session.session_id.clone(),
                self.session.epoch,
                stream_id,
                challenge_id.clone(),
                nonce.clone(),
                service_id,
                permission_digest,
                grant_revision,
            ));
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                continue;
            };
            if stream.operation != "echo_stream"
                || !stream.auth.confirmed
                || stream.auth.refresh_in_flight
                || stream.auth.invalidated
            {
                continue;
            }
            stream.auth.challenge_id = challenge_id;
            stream.auth.nonce = nonce;
            stream.auth.deadline = auth_deadline;
            stream.auth.refresh_in_flight = true;
            stream.auth.confirmed = false;
            self.send_control(challenge, Some(auth_deadline))?;
        }
        Ok(())
    }

    async fn handle_authorization_invalidated(
        &mut self,
        invalidated: AuthorizationInvalidated,
    ) -> Result<(), ClientError> {
        if invalidated.session_id != self.session.session_id
            || invalidated.epoch != self.session.epoch
        {
            return Err(ClientError::Protocol(
                "authorization invalidation context mismatch".to_owned(),
            ));
        }
        if self
            .streams
            .get(&invalidated.stream_id)
            .is_some_and(|stream| stream.auth.challenge_id == invalidated.challenge_id)
        {
            self.expire_stream(invalidated.stream_id).await?;
        }
        Ok(())
    }

    async fn handle_cancel(&mut self, cancel: Cancel) -> Result<(), ClientError> {
        if cancel.session_id != self.session.session_id || cancel.epoch != self.session.epoch {
            return Err(ClientError::Protocol("CANCEL context mismatch".to_owned()));
        }
        let matches_operation = self.streams.get(&cancel.stream_id).is_some_and(|stream| {
            stream.operation_id == cancel.operation_id
                && self.config.exports.contains_key(&stream.service_id)
        });
        if matches_operation {
            let pending_bytes = {
                let stream = self
                    .streams
                    .get_mut(&cancel.stream_id)
                    .expect("operation match checked above");
                stream.input_reset = true;
                stream.auth.invalidated = true;
                stream.record_buffer.clear();
                stream.record_expected = None;
                stream.pending.clear();
                let pending_bytes = stream.pending_bytes;
                stream.pending_bytes = 0;
                pending_bytes
            };
            self.pending_output_bytes = self.pending_output_bytes.saturating_sub(pending_bytes);
            self.emit_or_defer(PendingOutput {
                stream_id: cancel.stream_id,
                kind: FrameKind::Reset,
                payload: Vec::new(),
                reset_reason: Some(M2_RESET_PROTOCOL),
            })
            .await?;
        }
        Ok(())
    }

    fn handle_stream_forget(
        &mut self,
        forget: tunnel_protocol::rotation_control::StreamForget,
    ) -> Result<(), ClientError> {
        if forget.session_id != self.session.session_id || forget.epoch != self.session.epoch {
            return Err(ClientError::Protocol(
                "STREAM_FORGET context mismatch".to_owned(),
            ));
        }
        let Some(stream) = self.streams.get(&forget.stream_id) else {
            return Ok(());
        };
        if stream.operation_id != forget.operation_id
            || forget.final_state.stream_id != forget.stream_id
            || (forget.final_state.send_terminal.is_none()
                && forget.final_state.receive_terminal.is_none())
            || !self.config.exports.contains_key(&stream.service_id)
        {
            return Err(ClientError::Protocol(
                "STREAM_FORGET operation or terminal evidence mismatch".to_owned(),
            ));
        }
        let expected = ResumeDirectionState::from_sequence_snapshot(
            forget.stream_id,
            stream.sequence.snapshot().direction(forget.direction),
        )
        .map_err(|error| ClientError::Protocol(error.to_string()))?;
        if expected != forget.final_state {
            return Err(ClientError::Protocol(
                "STREAM_FORGET final cursor mismatch".to_owned(),
            ));
        }
        self.streams.remove(&forget.stream_id);
        self.publish_status();
        Ok(())
    }

    fn handle_ping(&self, ping: Ping) -> Result<(), ClientError> {
        if ping.session_id != self.session.session_id || ping.epoch != self.session.epoch {
            return Err(ClientError::Protocol("PING context mismatch".to_owned()));
        }
        self.send_control(
            ControlMessage::Pong(Pong::new(
                message_id(),
                ping.message_id,
                self.session.session_id.clone(),
                self.session.epoch,
                ping.nonce,
            )),
            None,
        )
    }

    async fn handle_carrier_event(&mut self, event: CarrierEvent) -> Result<(), ClientError> {
        match event {
            CarrierEvent::Message { key, message } => {
                self.handle_carrier_message(key, *message).await
            }
            CarrierEvent::ReaderClosed { key, peer_closed } => {
                self.mark_carrier_closed(&key, false, peer_closed).await
            }
            CarrierEvent::WriterClosed { key } => self.mark_carrier_closed(&key, true, false).await,
            CarrierEvent::WriterFailed { key, detail } => {
                // Reader/writer tasks can race their terminal event with
                // replacement retirement.  Fence every physical identity
                // already owned by this actor; a late failure from a
                // retired carrier must never tear down the healthy session.
                let known_carrier = physical_key_is_tracked(
                    &key,
                    Some(&self.active.key),
                    self.candidate.as_ref().map(|candidate| &candidate.key),
                    self.retiring.as_ref().map(|retiring| &retiring.key),
                ) || self.pending_candidate.as_ref().is_some_and(|pending| {
                    pending.attempt.new_generation == key.generation
                        && pending.attempt.new_connection_id == key.connection_id
                }) || self.pending_candidate_close.as_ref().is_some_and(
                    |(attempt, _)| {
                        attempt.new_generation == key.generation
                            && attempt.new_connection_id == key.connection_id
                    },
                ) || self
                    .rotation
                    .status()
                    .attempt
                    .as_ref()
                    .is_some_and(|attempt| attempt_key_is_tracked(&key, attempt))
                    || self.completed_rotation.as_ref().is_some_and(|completed| {
                        self.now_ms() < completed.deadline_ms
                            && attempt_key_is_tracked(&key, &completed.attempt)
                    })
                    || self.closed_for_recovery.contains_key(&key.connection_id);
                self.mark_carrier_closed(&key, false, false).await?;
                if known_carrier {
                    return Ok(());
                }
                Err(ClientError::Transport {
                    scope: "data writer",
                    detail: detail.to_owned(),
                })
            }
            CarrierEvent::BarrierComplete { key } => self.handle_barrier_complete(&key),
            CarrierEvent::CandidateOpened {
                attempt,
                socket,
                local_addr,
            } => {
                if self
                    .pending_candidate
                    .as_ref()
                    .is_some_and(|pending| pending.attempt == attempt)
                {
                    if self
                        .pending_candidate
                        .as_ref()
                        .is_some_and(|pending| self.now_ms() >= pending.deadline_ms)
                    {
                        if let Some(pending) = self.pending_candidate.as_mut() {
                            pending.socket = Some(*socket);
                            pending.local_addr = local_addr;
                        }
                        return self.expire_pending_candidate().await;
                    }
                    if let Some(pending) = self.pending_candidate.as_mut() {
                        pending.socket = Some(*socket);
                        pending.local_addr = local_addr;
                    }
                    self.maybe_install_candidate()?;
                    self.publish_status();
                    Ok(())
                } else {
                    // A timed-out attempt can finish its TLS handshake after
                    // the actor moved on. Drop the socket without allocating
                    // a new carrier or exposing its identity.
                    let _ = close_unattached_socket(*socket, attempt.new_connection_id).await;
                    Ok(())
                }
            }
            CarrierEvent::CandidateFailed { attempt } => {
                if self
                    .pending_candidate
                    .as_ref()
                    .is_some_and(|pending| pending.attempt == attempt)
                {
                    let mut pending = self
                        .pending_candidate
                        .take()
                        .expect("candidate checked above");
                    let recovery_candidate = pending.recovery;
                    let connection_id = pending.attempt.new_connection_id.clone();
                    if let Some(dial) = pending.dial.take() {
                        let _ = tokio::time::timeout(M2_CLOSE_TIMEOUT, dial).await;
                    }
                    let evidence = if let Some(socket) = pending.socket.take() {
                        close_unattached_socket(socket, connection_id.clone()).await
                    } else {
                        ClosureEvidence {
                            connection_id,
                            local_closed: true,
                            peer_closed: false,
                        }
                    };
                    if recovery_candidate {
                        return self
                            .finish_recovery_candidate_loss(pending.attempt, evidence)
                            .await;
                    }
                    self.defer_candidate_abort(pending.attempt, evidence)?;
                    return Ok(());
                }
                Ok(())
            }
        }
    }

    async fn handle_carrier_message(
        &mut self,
        key: CarrierKey,
        message: Message,
    ) -> Result<(), ClientError> {
        let is_active = self.active.key == key;
        let is_candidate = self
            .candidate
            .as_ref()
            .is_some_and(|carrier| carrier.key == key);
        if !is_active && !is_candidate {
            // The event belongs to a physically closed/stale carrier. Do not
            // let an old generation mutate stream state.
            return Ok(());
        }
        match message {
            Message::Binary(bytes) => {
                let recovery_candidate = is_candidate
                    && self.rotation.phase() == RotationPhase::Recovering
                    && self.recovery.is_some();
                if is_candidate
                    && self.rotation.phase() != RotationPhase::Active
                    && !recovery_candidate
                {
                    return Err(ClientError::Protocol(
                        "candidate emitted payload before ROTATE_COMMIT".to_owned(),
                    ));
                }
                let frame = Frame::decode(&bytes)
                    .map_err(|error| ClientError::Protocol(error.to_string()))?;
                if frame.epoch != self.session.epoch || frame.generation != key.generation {
                    return Err(ClientError::Protocol(
                        "data frame context does not match physical carrier".to_owned(),
                    ));
                }
                self.handle_frame(key, frame).await
            }
            Message::Ping(payload) => self.send_carrier_message(&key, Message::Pong(payload)),
            Message::Pong(_) | Message::Frame(_) => Ok(()),
            Message::Text(_) => Err(ClientError::Protocol(
                "text message on data socket".to_owned(),
            )),
            Message::Close(_) => self.mark_carrier_closed(&key, false, true).await,
        }
    }

    async fn handle_frame(&mut self, key: CarrierKey, frame: Frame) -> Result<(), ClientError> {
        let stream_id = frame.stream_id;
        let payload_bytes = frame.payload.len();
        if payload_bytes > 0 {
            self.ensure_retained_capacity(payload_bytes)?;
        }
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return self.send_raw_reset(&key, stream_id, M2_RESET_PROTOCOL, 0);
        };
        let disposition = stream
            .sequence
            .receive_frame(Direction::RelayToConnector, &frame)
            .map_err(|error| ClientError::Protocol(error.to_string()))?;
        let received_cursor = stream
            .sequence
            .direction(Direction::RelayToConnector)
            .recv_contiguous();
        let ready = if disposition != tunnel_protocol::ReceiveDisposition::Duplicate {
            stream.sequence.ready_frames(Direction::RelayToConnector)
        } else {
            Vec::new()
        };
        let confirmed = stream.auth.confirmed;
        let mut reset_ready = false;
        let mut reset_delivered = false;
        // Sequence byte credit is cumulative.  Once a DATA frame has been
        // handed to the bounded adapter/pending queue, its payload no longer
        // occupies the sequence ready set and that exact number of bytes can
        // be returned to the peer's send window.  Count payload bytes here
        // rather than logical records: the sequence layer charges encoded
        // DATA payloads, including a length prefix or a fragmented record.
        let mut released_receive_bytes = 0usize;
        if !confirmed {
            for ready_frame in &ready {
                let sequence = ready_frame.sequence;
                let payload = ready_frame.payload.clone();
                stream
                    .sequence
                    .mark_delivered(Direction::RelayToConnector, sequence)
                    .map_err(|error| ClientError::Protocol(error.to_string()))?;
                if ready_frame.kind == FrameKind::Data {
                    released_receive_bytes = released_receive_bytes
                        .checked_add(ready_frame.payload.len())
                        .ok_or_else(|| {
                            ClientError::Protocol("receive byte counter exhausted".to_owned())
                        })?;
                }
                match ready_frame.kind {
                    FrameKind::Data => {
                        if stream.pending_bytes.saturating_add(payload.len())
                            > self.config.limits.max_queue_bytes
                        {
                            return self.expire_stream(stream_id).await;
                        }
                        stream.pending_bytes += payload.len();
                        stream.pending.push_back(BufferedInput::Data(payload));
                    }
                    FrameKind::Fin => stream.pending.push_back(BufferedInput::Fin),
                    FrameKind::Reset => {
                        stream.input_reset = true;
                        reset_ready = true;
                    }
                    FrameKind::Ack | FrameKind::WindowUpdate => {}
                }
            }
        } else {
            // Copy the bounded ready set before releasing the stream borrow;
            // dispatch can enqueue frames and therefore mutably borrow the
            // actor again.
            let ready = ready
                .into_iter()
                .map(|ready_frame| (ready_frame.sequence, ready_frame.kind, ready_frame.payload))
                .collect::<Vec<_>>();
            let _ = stream;
            for (sequence, kind, payload) in ready {
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    stream
                        .sequence
                        .mark_delivered(Direction::RelayToConnector, sequence)
                        .map_err(|error| ClientError::Protocol(error.to_string()))?;
                }
                if kind == FrameKind::Data {
                    released_receive_bytes = released_receive_bytes
                        .checked_add(payload.len())
                        .ok_or_else(|| {
                            ClientError::Protocol("receive byte counter exhausted".to_owned())
                        })?;
                }
                match kind {
                    FrameKind::Data => self.dispatch_payload(stream_id, payload).await?,
                    FrameKind::Fin => self.dispatch_fin(stream_id).await?,
                    FrameKind::Reset => {
                        self.handle_peer_reset(stream_id).await?;
                        reset_delivered = true;
                    }
                    FrameKind::Ack | FrameKind::WindowUpdate => {}
                }
            }
        }
        if reset_ready && !reset_delivered {
            self.handle_peer_reset(stream_id).await?;
        }
        self.send_ack(&key, stream_id, received_cursor)?;
        if released_receive_bytes > 0 {
            self.send_receive_window_update(&key, stream_id, released_receive_bytes)?;
        }
        self.maybe_send_drain_proof()?;
        // Recovery READY may arrive before the peer's retained replay.  A
        // contiguous replayed prefix is the event that makes the previously
        // pending sequence plan activatable; keep the episode bounded and
        // retry the pure reconciliation after each delivered DATA frame.
        if self.recovery.is_some() {
            self.maybe_finish_recovery().await?;
        }
        self.publish_status();
        Ok(())
    }

    async fn handle_peer_reset(&mut self, stream_id: u64) -> Result<(), ClientError> {
        let should_emit = self.streams.get_mut(&stream_id).is_some_and(|stream| {
            stream.input_reset = true;
            !stream.output_reset && !stream.output_fin
        });
        if should_emit {
            self.emit_or_defer(PendingOutput {
                stream_id,
                kind: FrameKind::Reset,
                payload: Vec::new(),
                reset_reason: Some(M2_RESET_PROTOCOL),
            })
            .await?;
        }
        Ok(())
    }

    fn send_ack(
        &self,
        key: &CarrierKey,
        stream_id: u64,
        acknowledged: u64,
    ) -> Result<(), ClientError> {
        let frame = Frame::ack(self.session.epoch, key.generation, stream_id, acknowledged);
        let encoded = frame
            .encode()
            .map_err(|error| ClientError::Protocol(error.to_string()))?;
        self.queue_carrier_bytes(key, encoded)
    }

    /// Return byte credit for DATA that has left the sequence ready set.
    ///
    /// Window updates are absolute and monotonic.  The local sequence state
    /// is advanced before enqueueing the frame so duplicate or delayed
    /// updates cannot reduce the advertised limit; if the bounded carrier
    /// queue is unavailable the actor fails the session instead of silently
    /// claiming credit it could not transmit.
    fn send_receive_window_update(
        &mut self,
        key: &CarrierKey,
        stream_id: u64,
        released_bytes: usize,
    ) -> Result<(), ClientError> {
        let released_bytes = u64::try_from(released_bytes)
            .map_err(|_| ClientError::Protocol("receive byte counter exhausted".to_owned()))?;
        let current_credit = self
            .streams
            .get(&stream_id)
            .ok_or_else(|| ClientError::Protocol("window update for unknown stream".to_owned()))?
            .sequence
            .direction(Direction::RelayToConnector)
            .receive_credit();
        let limit = current_credit
            .checked_add(released_bytes)
            .ok_or_else(|| ClientError::Protocol("receive credit exhausted".to_owned()))?;
        let frame = Frame::window_update(self.session.epoch, key.generation, stream_id, limit);
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream
                .sequence
                .send_frame(Direction::ConnectorToRelay, &frame)
                .map_err(|error| ClientError::Protocol(error.to_string()))?;
        } else {
            return Err(ClientError::Protocol(
                "window update for unknown stream".to_owned(),
            ));
        }
        let encoded = frame
            .encode()
            .map_err(|error| ClientError::Protocol(error.to_string()))?;
        self.queue_carrier_bytes(key, encoded)
    }

    fn send_raw_reset(
        &self,
        key: &CarrierKey,
        stream_id: u64,
        reason: u16,
        ack: u64,
    ) -> Result<(), ClientError> {
        let frame = Frame::reset(
            self.session.epoch,
            key.generation,
            stream_id.max(1),
            1,
            ack,
            reason,
        );
        let encoded = frame
            .encode()
            .map_err(|error| ClientError::Protocol(error.to_string()))?;
        self.queue_carrier_bytes(key, encoded)
    }

    fn send_carrier_message(&self, key: &CarrierKey, message: Message) -> Result<(), ClientError> {
        let carrier = if self.active.key == *key {
            &self.active
        } else if self
            .candidate
            .as_ref()
            .is_some_and(|carrier| carrier.key == *key)
        {
            self.candidate.as_ref().expect("candidate checked")
        } else {
            return Ok(());
        };
        carrier
            .tx
            .try_send(CarrierCommand::Message(message))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ClientError::QueueLimit,
                mpsc::error::TrySendError::Closed(_) => ClientError::Transport {
                    scope: "data writer",
                    detail: "data writer stopped".to_owned(),
                },
            })
    }

    fn queue_carrier_bytes(&self, key: &CarrierKey, bytes: Vec<u8>) -> Result<(), ClientError> {
        let carrier = if self.active.key == *key {
            &self.active
        } else if self
            .candidate
            .as_ref()
            .is_some_and(|carrier| carrier.key == *key)
        {
            self.candidate.as_ref().expect("candidate checked")
        } else {
            return Err(ClientError::Protocol("stale data carrier".to_owned()));
        };
        let length = bytes.len();
        self.data_budget.reserve(length)?;
        let item = QueuedCarrierFrame {
            bytes,
            bytes_len: length,
            budget: self.data_budget.clone(),
        };
        carrier
            .tx
            .try_send(CarrierCommand::Frame(item))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ClientError::QueueLimit,
                mpsc::error::TrySendError::Closed(_) => ClientError::Transport {
                    scope: "data writer",
                    detail: "data writer stopped".to_owned(),
                },
            })
    }

    async fn dispatch_payload(
        &mut self,
        stream_id: u64,
        payload: Vec<u8>,
    ) -> Result<(), ClientError> {
        let Some(stream) = self.streams.get(&stream_id) else {
            return Ok(());
        };
        if !stream.auth.confirmed
            || stream.auth.invalidated
            || stream.input_fin
            || stream.input_reset
        {
            return Ok(());
        }
        let deadline = stream.auth.deadline.min(stream.auth.operation_deadline);
        let streaming = stream.is_streaming();
        if deadline.expired() {
            return self.expire_stream(stream_id).await;
        }
        if streaming {
            self.dispatch_stream_records(stream_id, payload).await
        } else {
            let canary = self
                .streams
                .get(&stream_id)
                .and_then(|stream| stream.export.device_canary.clone())
                .unwrap_or_default();
            let mut output = Vec::with_capacity(canary.len().saturating_add(payload.len()));
            output.extend_from_slice(canary.as_bytes());
            output.extend_from_slice(&payload);
            self.emit_payload(stream_id, output).await
        }
    }

    async fn dispatch_stream_records(
        &mut self,
        stream_id: u64,
        payload: Vec<u8>,
    ) -> Result<(), ClientError> {
        if !payload.is_empty() {
            self.ensure_retained_capacity(payload.len())?;
        }
        let responses = {
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                return Ok(());
            };
            let canary = stream.export.device_canary.clone().unwrap_or_default();
            parse_echo_records(
                &mut stream.record_buffer,
                &mut stream.record_expected,
                &canary,
                &payload,
            )
        };
        let Ok(responses) = responses else {
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.record_buffer.clear();
                stream.record_expected = None;
            }
            return self
                .emit_or_defer(PendingOutput {
                    stream_id,
                    kind: FrameKind::Reset,
                    payload: Vec::new(),
                    reset_reason: Some(M2_RESET_RECORD_LIMIT),
                })
                .await;
        };
        for response in responses {
            self.emit_payload(stream_id, response).await?;
        }
        Ok(())
    }

    async fn dispatch_fin(&mut self, stream_id: u64) -> Result<(), ClientError> {
        let Some(stream) = self.streams.get(&stream_id) else {
            return Ok(());
        };
        let (blocked, incomplete_record) = (
            stream.auth.invalidated
                || !stream.auth.confirmed
                || stream.input_fin
                || stream.output_fin
                || stream.output_reset,
            stream.is_streaming()
                && (stream.record_expected.is_some() || !stream.record_buffer.is_empty()),
        );
        if blocked {
            return Ok(());
        }
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.input_fin = true;
        }
        if incomplete_record {
            return self
                .emit_or_defer(PendingOutput {
                    stream_id,
                    kind: FrameKind::Reset,
                    payload: Vec::new(),
                    reset_reason: Some(M2_RESET_RECORD_LIMIT),
                })
                .await;
        }
        self.emit_or_defer(PendingOutput {
            stream_id,
            kind: FrameKind::Fin,
            payload: Vec::new(),
            reset_reason: None,
        })
        .await
    }

    async fn emit_payload(&mut self, stream_id: u64, output: Vec<u8>) -> Result<(), ClientError> {
        if output.is_empty() {
            return Ok(());
        }
        if output.len() > M2_MAX_STREAM_RESPONSE_BYTES
            && self
                .streams
                .get(&stream_id)
                .is_some_and(M2Stream::is_streaming)
        {
            return Err(ClientError::Protocol(
                "echo record output exceeded bound".to_owned(),
            ));
        }
        for chunk in output.chunks(MAX_PAYLOAD_LEN) {
            self.emit_or_defer(PendingOutput {
                stream_id,
                kind: FrameKind::Data,
                payload: chunk.to_vec(),
                reset_reason: None,
            })
            .await?;
        }
        Ok(())
    }

    async fn emit_or_defer(&mut self, output: PendingOutput) -> Result<(), ClientError> {
        let is_reset = output.kind == FrameKind::Reset;
        let stream_terminal = self
            .streams
            .get(&output.stream_id)
            .is_none_or(M2Stream::terminal);
        if stream_terminal {
            return Ok(());
        }
        if is_reset {
            let Some(stream) = self.streams.get_mut(&output.stream_id) else {
                return Ok(());
            };
            if !queue_reset_once(stream) {
                return Ok(());
            }
        }
        if self.writes_frozen {
            if self.pending_outputs.len() >= self.config.limits.max_queue_frames.max(1) {
                if is_reset && let Some(stream) = self.streams.get_mut(&output.stream_id) {
                    stream.reset_queued = false;
                }
                return Err(ClientError::QueueLimit);
            }
            let bytes = output.payload.len();
            if let Err(error) = self.ensure_retained_capacity(bytes) {
                if is_reset && let Some(stream) = self.streams.get_mut(&output.stream_id) {
                    stream.reset_queued = false;
                }
                return Err(error);
            }
            self.pending_output_bytes = self.pending_output_bytes.saturating_add(bytes);
            self.pending_outputs.push_back(output);
            self.publish_status();
            return Ok(());
        }
        self.emit_output_now(output)
    }

    fn emit_output_now(&mut self, output: PendingOutput) -> Result<(), ClientError> {
        self.ensure_retained_capacity(output.payload.len())?;
        let (generation, key) = {
            let key = self.active.key.clone();
            (key.generation, key)
        };
        let encoded = {
            let Some(stream) = self.streams.get_mut(&output.stream_id) else {
                return Ok(());
            };
            if stream.terminal() {
                if output.kind == FrameKind::Reset {
                    stream.reset_queued = false;
                }
                return Ok(());
            }
            if output.kind == FrameKind::Reset {
                // Every RESET reaches this function through emit_or_defer,
                // which marks it before either immediate send or deferral.
                // A missing marker means a stale/internal duplicate and is
                // therefore suppressed rather than allocating a sequence.
                if !stream.reset_queued {
                    return Ok(());
                }
                stream.reset_queued = false;
            }
            let direction = Direction::ConnectorToRelay;
            let sequence = match output.kind {
                FrameKind::Ack | FrameKind::WindowUpdate => 0,
                FrameKind::Data | FrameKind::Fin | FrameKind::Reset => stream
                    .sequence
                    .direction(direction)
                    .last_emitted()
                    .checked_add(1)
                    .ok_or_else(|| {
                        ClientError::Protocol("outbound sequence exhausted".to_owned())
                    })?,
            };
            let ack = stream
                .sequence
                .direction(Direction::RelayToConnector)
                .recv_contiguous();
            let frame = match output.kind {
                FrameKind::Data => Frame::data(
                    self.session.epoch,
                    generation,
                    output.stream_id,
                    sequence,
                    ack,
                    output.payload,
                ),
                FrameKind::Fin => Frame::fin(
                    self.session.epoch,
                    generation,
                    output.stream_id,
                    sequence,
                    ack,
                ),
                FrameKind::Reset => Frame::reset(
                    self.session.epoch,
                    generation,
                    output.stream_id,
                    sequence,
                    ack,
                    output.reset_reason.unwrap_or(M2_RESET_PROTOCOL),
                ),
                FrameKind::Ack => Frame::ack(self.session.epoch, generation, output.stream_id, ack),
                FrameKind::WindowUpdate => {
                    Frame::window_update(self.session.epoch, generation, output.stream_id, 0)
                }
            };
            stream
                .sequence
                .send_frame(direction, &frame)
                .map_err(|error| ClientError::Protocol(error.to_string()))?;
            if output.kind == FrameKind::Fin {
                stream.output_fin = true;
            }
            if output.kind == FrameKind::Reset {
                stream.output_reset = true;
            }
            frame
                .encode()
                .map_err(|error| ClientError::Protocol(error.to_string()))?
        };
        self.ensure_retained_capacity(encoded.len())?;
        self.queue_carrier_bytes(&key, encoded)?;
        self.publish_status();
        Ok(())
    }

    async fn handle_rotate_prepare(&mut self, prepare: RotatePrepare) -> Result<(), ClientError> {
        if prepare.attempt.session_id != self.session.session_id
            || prepare.attempt.epoch != self.session.epoch
            || prepare.attempt.owner_id != self.owner_id
            || prepare.attempt.old_generation != self.rotation.active_generation()
            || prepare.attempt.old_connection_id != self.rotation.active_connection_id()
        {
            return Err(ClientError::Protocol(
                "ROTATE_PREPARE identity mismatch".to_owned(),
            ));
        }
        if let Some(pending) = self.pending_candidate.as_ref() {
            if pending.attempt == prepare.attempt {
                return Ok(());
            }
            return Err(ClientError::Protocol(
                "ROTATE_PREPARE changed while a candidate is pending".to_owned(),
            ));
        }
        let now = self.now_ms();
        let (recovery, candidate_deadline_ms) = match &prepare.attachment_purpose {
            DataAttachmentPurpose::RotationCandidate => {
                if self.recovery.is_some() || self.rotation.phase() != RotationPhase::Active {
                    return Err(ClientError::Protocol(
                        "ordinary ROTATE_PREPARE during retained recovery".to_owned(),
                    ));
                }
                let deadline_cap = self
                    .rotation_deadline_cap(now, prepare.remaining_ms)
                    .ok_or_else(|| {
                        ClientError::Protocol("rotation prepare deadline overflow".to_owned())
                    })?;
                let prepare_result = self
                    .rotation
                    .prepare_with_deadline_cap(prepare.attempt.clone(), now, deadline_cap)
                    .map_err(|error| {
                        ClientError::Protocol(format!("rotation prepare rejected: {error}"))
                    })?;
                if matches!(
                    prepare_result,
                    tunnel_protocol::rotation::PrepareResult::Coalesced
                ) {
                    return Ok(());
                }
                (false, deadline_cap)
            }
            DataAttachmentPurpose::Recovery {
                episode_id,
                attempt_no,
                closure_digest,
            } => {
                let Some(recovery) = self.recovery.as_ref() else {
                    return Err(ClientError::Protocol(
                        "recovery attachment without RECOVERY_BEGIN".to_owned(),
                    ));
                };
                let candidate_deadline =
                    bounded_candidate_deadline(now, prepare.remaining_ms, recovery.deadline_ms)?;
                if recovery.begin.attempt != prepare.attempt
                    || recovery.begin.episode_id != *episode_id
                    || recovery.begin.attempt_no != *attempt_no
                    || recovery.combined_digest.as_deref() != Some(closure_digest.as_str())
                    || prepare.reply_to != recovery.local_closed.message_id
                    || now >= candidate_deadline
                {
                    return Err(ClientError::Protocol(
                        "recovery attachment binding mismatch".to_owned(),
                    ));
                }
                self.rotation
                    .reserve_recovery_socket(now)
                    .map_err(|error| {
                        ClientError::Protocol(format!(
                            "recovery candidate reservation rejected: {error}"
                        ))
                    })?;
                if let Some(recovery) = self.recovery.as_mut() {
                    recovery.prepare_message_id = Some(prepare.message_id.clone());
                    recovery.attempt_deadline_ms = Some(candidate_deadline);
                }
                (true, candidate_deadline)
            }
        };
        self.pending_candidate = Some(PendingCandidate {
            attempt: prepare.attempt.clone(),
            prepare_message_id: prepare.message_id.clone(),
            recovery,
            deadline_ms: candidate_deadline_ms,
            socket: None,
            local_addr: None,
            ready: false,
            dial: None,
        });
        self.rotation_prepare_message_id = Some(prepare.message_id.clone());
        self.local_frozen_message_id = None;
        self.local_drained_message_id = None;
        self.local_committed_message_id = None;
        self.local_retired_message_id = None;
        self.peer_drained_message_id = None;
        self.peer_committed_message_id = None;
        self.peer_retire_message_id = None;
        self.peer_abort_message_id = None;
        self.pending_abort_reply_id = None;
        self.peer_fence = None;
        self.peer_fence_message_id = None;
        self.local_fence = None;
        self.sent_drain_proof = false;
        let config = self.config.clone();
        let attempt = prepare.attempt;
        let ticket = prepare.attachment_ticket;
        let event_tx = self.events.clone();
        let cancellation = self.cancellation.clone();
        let dial_timeout = Duration::from_millis(candidate_deadline_ms.saturating_sub(now).max(1));
        let dial = tokio::spawn(async move {
            let tls = match super::load_client_config(&config.credentials) {
                Ok(tls) => tls,
                Err(_) => {
                    let _ = send_carrier_event(
                        &event_tx,
                        ActorEvent::Data(CarrierEvent::CandidateFailed { attempt }),
                        &cancellation,
                    )
                    .await;
                    return;
                }
            };
            let control_url = match Url::parse(&config.relay_url) {
                Ok(url) => url,
                Err(_) => {
                    let _ = send_carrier_event(
                        &event_tx,
                        ActorEvent::Data(CarrierEvent::CandidateFailed { attempt }),
                        &cancellation,
                    )
                    .await;
                    return;
                }
            };
            let data_url = data_url_for(&control_url);
            match tokio::time::timeout(
                dial_timeout,
                open_socket(
                    &data_url,
                    tls,
                    Some(&ticket),
                    super::DATA_SUBPROTOCOL,
                    MAX_FRAME_LEN,
                    &cancellation,
                ),
            )
            .await
            {
                Ok(Ok(socket)) => {
                    let local_addr = super::socket_local_addr(&socket);
                    let _ = send_carrier_event(
                        &event_tx,
                        ActorEvent::Data(CarrierEvent::CandidateOpened {
                            attempt,
                            socket: Box::new(socket),
                            local_addr,
                        }),
                        &cancellation,
                    )
                    .await;
                }
                Ok(Err(_)) | Err(_) => {
                    let _ = send_carrier_event(
                        &event_tx,
                        ActorEvent::Data(CarrierEvent::CandidateFailed { attempt }),
                        &cancellation,
                    )
                    .await;
                }
            }
        });
        if let Some(pending) = self.pending_candidate.as_mut() {
            pending.dial = Some(dial);
        }
        self.publish_status();
        Ok(())
    }

    async fn handle_candidate_ready(&mut self, ready: DataReady) -> Result<(), ClientError> {
        if self
            .pending_candidate
            .as_ref()
            .is_some_and(|pending| self.now_ms() >= pending.deadline_ms)
        {
            self.expire_pending_candidate().await?;
            return Ok(());
        }
        let Some(pending) = self.pending_candidate.as_mut() else {
            // The initial DATA_READY is consumed before the actor starts. A
            // stale candidate readiness must not attach an untracked socket.
            return Err(ClientError::Protocol("unexpected DATA_READY".to_owned()));
        };
        ready
            .validate_context(
                &self.session.session_id,
                self.session.epoch,
                pending.attempt.new_generation,
                &pending.attempt.new_connection_id,
            )
            .map_err(|error| ClientError::Protocol(error.to_string()))?;
        if ready.reply_to != pending.prepare_message_id {
            return Err(ClientError::Protocol(
                "candidate DATA_READY reply_to mismatch".to_owned(),
            ));
        }
        pending.ready = true;
        self.maybe_install_candidate()
    }

    fn maybe_install_candidate(&mut self) -> Result<(), ClientError> {
        let Some(pending) = self.pending_candidate.as_ref() else {
            return Ok(());
        };
        if !pending.ready || pending.socket.is_none() || self.candidate.is_some() {
            return Ok(());
        }
        let attempt = pending.attempt.clone();
        let recovery = pending.recovery;
        let socket = self
            .pending_candidate
            .as_mut()
            .and_then(|pending| pending.socket.take())
            .ok_or_else(|| ClientError::Protocol("candidate socket disappeared".to_owned()))?;
        let local_addr = super::socket_local_addr(&socket);
        if !recovery {
            self.rotation
                .candidate_ready(&attempt, self.now_ms())
                .map_err(|error| {
                    ClientError::Protocol(format!("candidate readiness rejected: {error}"))
                })?;
        } else if self.rotation.phase() != RotationPhase::Recovering {
            return Err(ClientError::Protocol(
                "recovery candidate installed outside recovery phase".to_owned(),
            ));
        }
        let (sink, stream) = socket.split();
        let carrier = spawn_carrier(
            CarrierKey::new(attempt.new_generation, attempt.new_connection_id.clone()),
            sink,
            stream,
            self.data_budget.clone(),
            self.events.clone(),
            self.cancellation.clone(),
            local_addr,
        );
        self.candidate = Some(carrier);
        if recovery {
            self.maybe_prepare_recovery_plans(true)?;
        } else {
            self.apply_pending_quiesce()?;
        }
        self.publish_status();
        Ok(())
    }

    fn handle_rotate_quiesce(&mut self, quiesce: RotateQuiesce) -> Result<(), ClientError> {
        if self.rotation_prepare_message_id.as_deref() != Some(quiesce.reply_to.as_str()) {
            return Err(ClientError::Protocol(
                "ROTATE_QUIESCE reply correlation mismatch".to_owned(),
            ));
        }
        if let Some(existing) = self.pending_quiesce.as_ref() {
            if existing.message_id != quiesce.message_id {
                return Err(ClientError::Protocol(
                    "ROTATE_QUIESCE semantic duplicate changed message ID".to_owned(),
                ));
            }
            if existing.attempt != quiesce.attempt {
                return Err(ClientError::Protocol(
                    "ROTATE_QUIESCE attempt changed while a barrier is pending".to_owned(),
                ));
            }
            return Ok(());
        }
        if self.rotation.phase() != RotationPhase::Preparing {
            return Err(ClientError::Protocol(
                "ROTATE_QUIESCE in the wrong phase".to_owned(),
            ));
        }
        let pending_attempt_matches = self
            .pending_candidate
            .as_ref()
            .is_some_and(|pending| pending.attempt == quiesce.attempt);
        let candidate_attempt_matches = self.candidate.as_ref().is_some_and(|candidate| {
            candidate.key.matches(
                quiesce.attempt.new_generation,
                &quiesce.attempt.new_connection_id,
            )
        });
        if !pending_attempt_matches && !candidate_attempt_matches {
            return Err(ClientError::Protocol(
                "ROTATE_QUIESCE candidate identity mismatch".to_owned(),
            ));
        }
        self.accepting = false;
        self.writes_frozen = true;
        self.pending_quiesce = Some(quiesce.clone());
        self.apply_pending_quiesce()?;
        self.publish_status();
        Ok(())
    }

    /// Apply a queued QUIESCE only after the candidate has completed its
    /// authenticated DATA_READY exchange.  Control delivery can beat the
    /// socket reader event, so the immutable barrier is deliberately deferred
    /// until both pieces of readiness are owned by this actor.
    fn apply_pending_quiesce(&mut self) -> Result<(), ClientError> {
        if self.rotation.phase() != RotationPhase::Preparing
            || self.candidate.is_none()
            || self.pending_quiesce.is_none()
        {
            return Ok(());
        }
        let quiesce = self
            .pending_quiesce
            .as_ref()
            .expect("pending quiesce checked")
            .clone();
        self.rotation
            .quiesce(&quiesce.attempt, quiesce.roster, self.now_ms())
            .map_err(|error| {
                ClientError::Protocol(format!("rotation quiesce rejected: {error}"))
            })?;
        self.active
            .tx
            .try_send(CarrierCommand::Barrier)
            .map_err(|error| ClientError::Transport {
                scope: "active data writer",
                detail: format!("unable to schedule immutable fence barrier: {error}"),
            })
    }

    fn handle_barrier_complete(&mut self, key: &CarrierKey) -> Result<(), ClientError> {
        if self.active.key != *key {
            return Ok(());
        }
        let Some(quiesce) = self.pending_quiesce.take() else {
            return Ok(());
        };
        let now = self.now_ms();
        let entries = quiesce
            .roster
            .stream_ids
            .iter()
            .map(|stream_id| {
                let last = self
                    .streams
                    .get(stream_id)
                    .map(|stream| {
                        stream
                            .sequence
                            .direction(Direction::ConnectorToRelay)
                            .last_emitted()
                    })
                    .unwrap_or(0);
                StreamFence::new(*stream_id, Direction::ConnectorToRelay, last)
            })
            .collect::<Vec<_>>();
        let snapshot = FenceSnapshot::new(quiesce.roster.snapshot_id.clone(), entries);
        self.rotation
            .frozen(
                &quiesce.attempt,
                snapshot.clone(),
                Direction::ConnectorToRelay,
                now,
            )
            .map_err(|error| ClientError::Protocol(format!("local freeze rejected: {error}")))?;
        self.local_fence = Some(snapshot.clone());
        let response = ControlMessage::RotateFrozen(RotateFrozen {
            message_id: message_id(),
            reply_to: quiesce.message_id.clone(),
            attempt: quiesce.attempt,
            snapshot,
        });
        self.local_frozen_message_id = Some(response.message_id().to_owned());
        self.send_rotation_reply(&quiesce.message_id, response)?;
        self.maybe_send_drain_proof()?;
        self.publish_status();
        Ok(())
    }

    fn handle_rotate_frozen(&mut self, frozen: RotateFrozen) -> Result<(), ClientError> {
        if self.local_frozen_message_id.as_deref() != Some(frozen.reply_to.as_str()) {
            return Err(ClientError::Protocol(
                "ROTATE_FROZEN reply correlation mismatch".to_owned(),
            ));
        }
        if let Some(existing) = self.peer_fence_message_id.as_ref()
            && existing != &frozen.message_id
        {
            return Err(ClientError::Protocol(
                "ROTATE_FROZEN semantic duplicate changed message ID".to_owned(),
            ));
        }
        let now = self.now_ms();
        let peer_fence_message_id = frozen.message_id.clone();
        self.rotation
            .frozen(
                &frozen.attempt,
                frozen.snapshot.clone(),
                Direction::RelayToConnector,
                now,
            )
            .map_err(|error| ClientError::Protocol(format!("peer freeze rejected: {error}")))?;
        self.peer_fence = Some(frozen.snapshot);
        self.peer_fence_message_id = Some(peer_fence_message_id);
        self.maybe_send_drain_proof()?;
        self.publish_status();
        Ok(())
    }

    fn maybe_send_drain_proof(&mut self) -> Result<(), ClientError> {
        if self.sent_drain_proof || self.rotation.phase() != RotationPhase::Draining {
            return Ok(());
        }
        let Some(fence) = self.peer_fence.clone() else {
            return Ok(());
        };
        let mut acks = Vec::with_capacity(fence.entries.len());
        for entry in &fence.entries {
            let Some(stream) = self.streams.get(&entry.stream_id) else {
                return Ok(());
            };
            let ack = stream
                .sequence
                .direction(Direction::RelayToConnector)
                .recv_contiguous();
            if ack < entry.last_emitted {
                return Ok(());
            }
            acks.push(StreamAck::new(entry.stream_id, ack));
        }
        let digest = fence
            .digest()
            .map_err(|error| ClientError::Protocol(error.to_string()))?;
        let proof = tunnel_protocol::rotation_control::DrainProof::new(
            fence.snapshot_id.clone(),
            digest,
            Direction::RelayToConnector,
            acks,
        );
        let attempt = self
            .rotation
            .status()
            .attempt
            .ok_or_else(|| ClientError::Protocol("missing rotation attempt".to_owned()))?;
        let reply_to = self
            .peer_fence_message_id
            .clone()
            .ok_or_else(|| ClientError::Protocol("missing peer freeze message".to_owned()))?;
        self.rotation
            .drained(&attempt, proof.clone(), self.now_ms())
            .map_err(|error| ClientError::Protocol(format!("local drain rejected: {error}")))?;
        self.sent_drain_proof = true;
        let request_id = reply_to.clone();
        let response = ControlMessage::RotateDrained(RotateDrained {
            message_id: message_id(),
            reply_to,
            attempt,
            proof,
        });
        self.local_drained_message_id = Some(response.message_id().to_owned());
        self.send_rotation_reply(&request_id, response)
    }

    async fn handle_rotate_retire(&mut self, retire: RotateRetire) -> Result<(), ClientError> {
        let Some(current) = self.rotation.status().attempt else {
            return Err(ClientError::Protocol(
                "ROTATE_RETIRE without an attempt".to_owned(),
            ));
        };
        if current != retire.attempt {
            return Err(ClientError::Protocol(
                "ROTATE_RETIRE attempt mismatch".to_owned(),
            ));
        }
        if self.local_committed_message_id.as_deref() != Some(retire.reply_to.as_str()) {
            return Err(ClientError::Protocol(
                "ROTATE_RETIRE reply correlation mismatch".to_owned(),
            ));
        }
        if let Some(existing) = self.peer_retire_message_id.as_ref()
            && existing != &retire.message_id
        {
            return Err(ClientError::Protocol(
                "ROTATE_RETIRE semantic duplicate changed message ID".to_owned(),
            ));
        }
        if self.rotation.phase() != RotationPhase::Retiring {
            return Err(ClientError::Protocol(
                "ROTATE_RETIRE in the wrong phase".to_owned(),
            ));
        }
        if retire.snapshot_id
            != self
                .local_fence
                .as_ref()
                .map(|fence| fence.snapshot_id.as_str())
                .unwrap_or_default()
        {
            return Err(ClientError::Protocol(
                "ROTATE_RETIRE snapshot mismatch".to_owned(),
            ));
        }
        let old = self
            .retiring
            .take()
            .ok_or_else(|| ClientError::Protocol("ROTATE_RETIRE without old carrier".to_owned()))?;
        let old_id = old.key.connection_id.clone();
        let evidence = close_carrier(old).await;
        if !evidence.is_complete() {
            return Err(ClientError::Transport {
                scope: "retired data carrier",
                detail: "old data carrier closure was not confirmed".to_owned(),
            });
        }
        self.rotation
            .retired(
                &retire.attempt,
                RotationSide::Connector,
                evidence,
                self.now_ms(),
            )
            .map_err(|error| {
                ClientError::Protocol(format!("retirement evidence rejected: {error}"))
            })?;
        self.peer_retire_message_id = Some(retire.message_id.clone());
        let response = ControlMessage::RotateRetired(RotateRetired {
            message_id: message_id(),
            reply_to: retire.message_id.clone(),
            attempt: retire.attempt,
            snapshot_id: retire.snapshot_id,
            closed_connection_id: old_id,
        });
        self.local_retired_message_id = Some(response.message_id().to_owned());
        self.send_rotation_reply(&retire.message_id, response)?;
        self.publish_status();
        Ok(())
    }

    fn handle_rotate_retired(&mut self, _retired: RotateRetired) -> Result<(), ClientError> {
        Err(ClientError::Protocol(
            "connector received unexpected ROTATE_RETIRED".to_owned(),
        ))
    }

    async fn handle_rotate_complete(
        &mut self,
        complete: RotateComplete,
    ) -> Result<(), ClientError> {
        let Some(current) = self.rotation.status().attempt else {
            return Err(ClientError::Protocol(
                "ROTATE_COMPLETE without an attempt".to_owned(),
            ));
        };
        if current != complete.attempt
            || complete.snapshot_id
                != self
                    .local_fence
                    .as_ref()
                    .map(|fence| fence.snapshot_id.as_str())
                    .unwrap_or_default()
        {
            return Err(ClientError::Protocol(
                "ROTATE_COMPLETE identity mismatch".to_owned(),
            ));
        }
        if self.local_retired_message_id.as_deref() != Some(complete.reply_to.as_str()) {
            return Err(ClientError::Protocol(
                "ROTATE_COMPLETE reply correlation mismatch".to_owned(),
            ));
        }
        if self.rotation.phase() == RotationPhase::Retiring {
            self.rotation
                .retired(
                    &complete.attempt,
                    RotationSide::Owner,
                    ClosureEvidence::closed(complete.attempt.old_connection_id.clone()),
                    self.now_ms(),
                )
                .map_err(|error| {
                    ClientError::Protocol(format!("complete retirement rejected: {error}"))
                })?;
        }
        if self.rotation.phase() != RotationPhase::Active {
            return Err(ClientError::Protocol(
                "ROTATE_COMPLETE did not activate carrier".to_owned(),
            ));
        }
        self.pending_candidate = None;
        self.peer_fence = None;
        self.peer_fence_message_id = None;
        self.local_fence = None;
        self.sent_drain_proof = false;
        self.pending_quiesce = None;
        self.local_frozen_message_id = None;
        self.local_drained_message_id = None;
        self.local_committed_message_id = None;
        self.local_retired_message_id = None;
        self.peer_drained_message_id = None;
        self.peer_committed_message_id = None;
        self.peer_retire_message_id = None;
        self.peer_abort_message_id = None;
        self.pending_abort_reply_id = None;
        self.accepting = true;
        self.writes_frozen = false;
        self.rotations_completed = self.rotations_completed.saturating_add(1);
        self.flush_pending_outputs().await?;
        self.publish_status();
        Ok(())
    }

    async fn handle_rotate_abort(&mut self, abort: RotateAbort) -> Result<(), ClientError> {
        if !abort.reply_to.is_empty() {
            return Err(ClientError::Protocol(
                "ROTATE_ABORT reply correlation mismatch".to_owned(),
            ));
        }
        let Some(current) = self.rotation.status().attempt else {
            return Err(ClientError::Protocol(
                "ROTATE_ABORT without an attempt".to_owned(),
            ));
        };
        if current != abort.attempt {
            return Err(ClientError::Protocol(
                "ROTATE_ABORT attempt mismatch".to_owned(),
            ));
        }
        if let Some(existing) = self.peer_abort_message_id.as_ref()
            && existing != &abort.message_id
        {
            return Err(ClientError::Protocol(
                "ROTATE_ABORT semantic duplicate changed message ID".to_owned(),
            ));
        }
        let reason = if abort.reason.to_ascii_lowercase().contains("deadline") {
            RecoveryReason::Deadline
        } else {
            RecoveryReason::CandidateTransportLost
        };
        if self.rotation.phase() != RotationPhase::Aborting {
            self.rotation
                .abort(&abort.attempt, self.now_ms(), reason)
                .map_err(|error| ClientError::Protocol(format!("abort rejected: {error}")))?;
        }
        self.peer_abort_message_id = Some(abort.message_id.clone());
        self.accepting = false;
        self.writes_frozen = true;
        let closure = if let Some((closed_attempt, evidence)) = self.pending_candidate_close.take()
        {
            if closed_attempt != abort.attempt {
                return Err(ClientError::Protocol(
                    "ROTATE_ABORT candidate closure attempt mismatch".to_owned(),
                ));
            }
            evidence
        } else {
            self.close_candidate_resources()
                .await
                .ok_or_else(|| ClientError::Transport {
                    scope: "candidate data carrier",
                    detail: "candidate closure was not evidenced".to_owned(),
                })?
        };
        if !closure.local_closed {
            return Err(ClientError::Transport {
                scope: "candidate data carrier",
                detail: "candidate local closure was not confirmed".to_owned(),
            });
        }
        self.rotation
            .aborted(
                &abort.attempt,
                RotationSide::Connector,
                closure,
                self.now_ms(),
            )
            .map_err(|error| {
                ClientError::Protocol(format!("candidate closure rejected: {error}"))
            })?;
        self.pending_quiesce = None;
        self.peer_fence_message_id = None;
        self.pending_candidate = None;
        let response = ControlMessage::RotateAborted(RotateAborted {
            message_id: message_id(),
            reply_to: abort.message_id.clone(),
            attempt: abort.attempt,
            reason: abort.reason,
            closed_connection_id: current.new_connection_id,
        });
        let response_message_id = response.message_id().to_owned();
        self.pending_abort_reply_id = Some(response_message_id);
        self.send_rotation_reply(&abort.message_id, response)?;
        // The owner sends a final ROTATE_ABORTED after it records this
        // connector acknowledgement and its own candidate closure.  Keep
        // admission and old writes frozen until that owner-side evidence is
        // received and RotationState reaches Active.
        self.accepting = false;
        self.writes_frozen = true;
        self.publish_status();
        Ok(())
    }

    async fn handle_rotate_aborted(&mut self, aborted: RotateAborted) -> Result<(), ClientError> {
        let Some(current) = self.rotation.status().attempt else {
            return Err(ClientError::Protocol(
                "ROTATE_ABORTED without an active abort attempt".to_owned(),
            ));
        };
        if current != aborted.attempt {
            return Err(ClientError::Protocol(
                "ROTATE_ABORTED attempt mismatch".to_owned(),
            ));
        }
        if self.rotation.phase() != RotationPhase::Aborting {
            return Err(ClientError::Protocol(
                "ROTATE_ABORTED outside the abort phase".to_owned(),
            ));
        }
        if self.pending_abort_reply_id.as_deref() != Some(aborted.reply_to.as_str()) {
            return Err(ClientError::Protocol(
                "ROTATE_ABORTED reply correlation mismatch".to_owned(),
            ));
        }
        self.rotation
            .aborted(
                &aborted.attempt,
                RotationSide::Owner,
                ClosureEvidence::closed(aborted.closed_connection_id),
                self.now_ms(),
            )
            .map_err(|error| ClientError::Protocol(format!("ROTATE_ABORTED rejected: {error}")))?;
        if self.rotation.phase() != RotationPhase::Active {
            return Err(ClientError::Protocol(
                "ROTATE_ABORTED did not complete bilateral closure".to_owned(),
            ));
        }
        self.pending_abort_reply_id = None;
        self.accepting = true;
        self.writes_frozen = false;
        self.flush_pending_outputs().await?;
        self.publish_status();
        Ok(())
    }

    async fn handle_resume(&mut self, resume: Resume) -> Result<(), ClientError> {
        let index = direction_index(resume.direction);
        let now = self.now_ms();
        let entries = resume
            .entries
            .iter()
            .map(|entry| (entry.stream_id, entry.clone()))
            .collect::<BTreeMap<_, _>>();
        if self.recovery.is_none() {
            let Some(completed) = self.completed_recovery.as_ref() else {
                return Err(ClientError::Protocol(
                    "RESUME without RECOVERY_BEGIN".to_owned(),
                ));
            };
            if now >= completed.deadline_ms
                || resume.attempt != completed.begin.attempt
                || resume.snapshot_id != completed.begin.roster.snapshot_id
                || resume.remaining_ms == 0
                || resume.remaining_ms > completed.deadline_ms.saturating_sub(now)
                || entries.keys().copied().collect::<Vec<_>>() != completed.begin.roster.stream_ids
            {
                return Err(ClientError::Protocol(
                    "RESUME does not bind the completed recovery episode".to_owned(),
                ));
            }
            let known_message_id = match resume.stage {
                ResumeStage::Snapshot => {
                    completed.remote_snapshot_message_ids[index].as_deref()
                        == Some(resume.message_id.as_str())
                }
                ResumeStage::Ready => {
                    completed.remote_ready_message_ids[index].as_deref()
                        == Some(resume.message_id.as_str())
                }
            };
            if !known_message_id {
                return Err(ClientError::Protocol(
                    "RESUME changed a completed recovery request".to_owned(),
                ));
            }
            let deadline_ms = completed.deadline_ms;
            let observed = self
                .observe_recovery_message(&ControlMessage::Resume(resume.clone()), deadline_ms)?;
            if !matches!(observed, JournalObservation::New) {
                self.resend_recovery_reply(&ControlMessage::Resume(resume))?;
                return Ok(());
            }
            return Err(ClientError::Protocol(
                "completed recovery request was not retained in the journal".to_owned(),
            ));
        }
        let (expected_stream_ids, valid_reply) = {
            let Some(recovery) = self.recovery.as_ref() else {
                return Err(ClientError::Protocol(
                    "RESUME without RECOVERY_BEGIN".to_owned(),
                ));
            };
            if resume.attempt != recovery.begin.attempt
                || resume.snapshot_id != recovery.begin.roster.snapshot_id
                || resume.remaining_ms == 0
                || resume.remaining_ms > recovery.deadline_ms.saturating_sub(now)
            {
                return Err(ClientError::Protocol(
                    "RESUME recovery context or deadline mismatch".to_owned(),
                ));
            }
            let valid_reply = if resume.stage == ResumeStage::Snapshot {
                recovery
                    .prepare_message_id
                    .as_deref()
                    .is_some_and(|message_id| resume.reply_to == message_id)
            } else {
                recovery.snapshot_reply_message_ids[index]
                    .as_deref()
                    .is_some_and(|message_id| message_id == resume.reply_to)
            };
            (recovery.begin.roster.stream_ids.clone(), valid_reply)
        };
        if !valid_reply {
            return Err(ClientError::Protocol(
                "RESUME reply_to does not bind the recovery stage".to_owned(),
            ));
        }
        if entries.keys().copied().collect::<Vec<_>>() != expected_stream_ids {
            return Err(ClientError::Protocol(
                "RESUME entries do not match the immutable roster".to_owned(),
            ));
        }
        let deadline_ms = self
            .recovery
            .as_ref()
            .expect("recovery context was checked above")
            .deadline_ms;
        let observed =
            self.observe_recovery_message(&ControlMessage::Resume(resume.clone()), deadline_ms)?;
        if !matches!(observed, JournalObservation::New) {
            self.resend_recovery_reply(&ControlMessage::Resume(resume))?;
            return Ok(());
        }
        match resume.stage {
            ResumeStage::Snapshot => {
                let duplicate = {
                    let recovery = self
                        .recovery
                        .as_mut()
                        .expect("recovery context checked above");
                    if let Some(existing_id) = recovery.remote_snapshot_message_ids[index].as_ref()
                    {
                        if existing_id == &resume.message_id
                            && recovery.remote_snapshots[index] == entries
                        {
                            true
                        } else {
                            return Err(ClientError::Protocol(
                                "duplicate RESUME snapshot changed its message".to_owned(),
                            ));
                        }
                    } else {
                        recovery.remote_snapshot_message_ids[index] =
                            Some(resume.message_id.clone());
                        recovery.remote_snapshots[index] = entries;
                        false
                    }
                };
                if duplicate {
                    self.resend_recovery_reply(&ControlMessage::Resume(resume))?;
                    return Ok(());
                }
                self.maybe_prepare_recovery_plans(true)?;
                self.send_recovery_snapshot_replies()?;
            }
            ResumeStage::Ready => {
                let duplicate = {
                    let recovery = self
                        .recovery
                        .as_mut()
                        .expect("recovery context checked above");
                    if let Some(existing_id) = recovery.remote_ready_message_ids[index].as_ref() {
                        if existing_id == &resume.message_id
                            && recovery.remote_ready_snapshots[index] == entries
                        {
                            true
                        } else {
                            return Err(ClientError::Protocol(
                                "duplicate RESUME ready changed its message".to_owned(),
                            ));
                        }
                    } else {
                        recovery.remote_ready_message_ids[index] = Some(resume.message_id.clone());
                        recovery.remote_ready_snapshots[index] = entries;
                        recovery.remote_ready[index] = true;
                        false
                    }
                };
                if duplicate {
                    self.resend_recovery_reply(&ControlMessage::Resume(resume))?;
                    return Ok(());
                }
                self.maybe_finish_recovery().await?;
            }
        }
        Ok(())
    }

    fn handle_resumed(&mut self, _resumed: Resumed) -> Result<(), ClientError> {
        // RESUMED is connector-originated in the M2 recovery handshake.  A
        // peer-originated copy cannot advance any local state; accepting it
        // would make the two endpoints disagree about which side supplied a
        // snapshot or readiness proof.
        if self.recovery.is_some() {
            return Err(ClientError::Protocol(
                "connector received peer-originated RESUMED".to_owned(),
            ));
        }
        Err(ClientError::Protocol(
            "RESUMED without retained recovery".to_owned(),
        ))
    }

    fn maybe_prepare_recovery_plans(&mut self, queue_replay: bool) -> Result<(), ClientError> {
        let (attempt, stream_ids, use_ready_snapshots) = {
            let Some(recovery) = self.recovery.as_ref() else {
                return Ok(());
            };
            if recovery.remote_snapshots.iter().any(BTreeMap::is_empty)
                && !recovery.begin.roster.stream_ids.is_empty()
            {
                return Ok(());
            }
            (
                recovery.begin.attempt.clone(),
                recovery.begin.roster.stream_ids.clone(),
                !queue_replay && recovery.remote_ready.iter().all(|ready| *ready),
            )
        };
        let peer_snapshots = self.recovery_peer_snapshots(use_ready_snapshots)?;
        let mut plans = BTreeMap::new();
        for stream_id in stream_ids {
            let peer = peer_snapshots.get(&stream_id).ok_or_else(|| {
                ClientError::Protocol(format!("recovery peer snapshot omitted stream {stream_id}"))
            })?;
            let stream = self.streams.get_mut(&stream_id).ok_or_else(|| {
                ClientError::Protocol(format!(
                    "recovery roster contains unknown stream {stream_id}"
                ))
            })?;
            let plan = stream
                .sequence
                .reconcile_for_carrier(peer, self.session.epoch, attempt.new_generation)
                .map_err(|error| ClientError::Protocol(error.to_string()))?;
            // Advance only the immutable peer ACK cursor.  Logical sequence
            // counters and terminal state remain owned by StreamState.
            stream
                .sequence
                .reconcile_and_apply(peer)
                .map_err(|error| ClientError::Protocol(error.to_string()))?;
            plans.insert(stream_id, plan);
        }
        if queue_replay {
            let candidate_key = self
                .candidate
                .as_ref()
                .map(|candidate| candidate.key.clone())
                .ok_or_else(|| {
                    ClientError::Protocol(
                        "recovery snapshots arrived before candidate carrier".to_owned(),
                    )
                })?;
            for plan in plans.values() {
                for frame in plan.replay(Direction::ConnectorToRelay) {
                    let encoded = frame
                        .encode()
                        .map_err(|error| ClientError::Protocol(error.to_string()))?;
                    self.ensure_retained_capacity(encoded.len())?;
                    self.queue_carrier_bytes(&candidate_key, encoded)?;
                }
            }
        }
        if let Some(recovery) = self.recovery.as_mut() {
            recovery.peer_snapshots = peer_snapshots;
            recovery.local_plans = plans;
        }
        Ok(())
    }

    fn recovery_peer_snapshots(
        &self,
        ready_snapshots: bool,
    ) -> Result<BTreeMap<u64, StreamSnapshot>, ClientError> {
        let recovery = self
            .recovery
            .as_ref()
            .ok_or_else(|| ClientError::Protocol("missing recovery state".to_owned()))?;
        let peer_entries = if ready_snapshots {
            &recovery.remote_ready_snapshots
        } else {
            &recovery.remote_snapshots
        };
        let mut snapshots = BTreeMap::new();
        for stream_id in &recovery.begin.roster.stream_ids {
            let relay_to_connector = peer_entries[direction_index(Direction::RelayToConnector)]
                .get(stream_id)
                .ok_or_else(|| {
                    ClientError::Protocol(format!(
                        "recovery peer snapshot omitted stream {stream_id}"
                    ))
                })?;
            let connector_to_relay = peer_entries[direction_index(Direction::ConnectorToRelay)]
                .get(stream_id)
                .ok_or_else(|| {
                    ClientError::Protocol(format!(
                        "recovery peer snapshot omitted stream {stream_id}"
                    ))
                })?;
            snapshots.insert(
                *stream_id,
                StreamSnapshot {
                    stream_id: *stream_id,
                    directions: [
                        direction_snapshot_from_resume(relay_to_connector),
                        direction_snapshot_from_resume(connector_to_relay),
                    ],
                },
            );
        }
        Ok(snapshots)
    }

    fn send_recovery_snapshot_replies(&mut self) -> Result<(), ClientError> {
        let outbound = {
            let Some(recovery) = self.recovery.as_mut() else {
                return Ok(());
            };
            if recovery
                .remote_snapshots
                .iter()
                .any(|entries| entries.len() != recovery.begin.roster.stream_ids.len())
            {
                return Ok(());
            }
            let attempt = recovery.begin.attempt.clone();
            let snapshot_id = recovery.begin.roster.snapshot_id.clone();
            let mut outbound = Vec::new();
            for direction in [Direction::RelayToConnector, Direction::ConnectorToRelay] {
                let index = direction_index(direction);
                if recovery.snapshot_replies[index] {
                    continue;
                }
                let Some(reply_to) = recovery.remote_snapshot_message_ids[index].clone() else {
                    continue;
                };
                let request_id = reply_to.clone();
                let entries = recovery.local_snapshots[index]
                    .values()
                    .cloned()
                    .collect::<Vec<_>>();
                let replay = recovery
                    .local_plans
                    .values()
                    .map(|plan| {
                        ValidatedRecovery::from_sequence_plan(plan)
                            .map(|verdict| {
                                verdict
                                    .replay_ranges()
                                    .iter()
                                    .filter(|range| range.direction == direction)
                                    .map(|range| tunnel_protocol::rotation_control::ReplayRange {
                                        stream_id: range.stream_id,
                                        direction: range.direction,
                                        from: range.first_sequence,
                                        through: range.last_sequence,
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .map_err(|error| ClientError::Protocol(error.to_string()))
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();
                let message_id_value = message_id();
                recovery.snapshot_reply_message_ids[index] = Some(message_id_value.clone());
                recovery.snapshot_replies[index] = true;
                let message = ControlMessage::Resumed(Resumed {
                    message_id: message_id_value,
                    reply_to,
                    attempt: attempt.clone(),
                    snapshot_id: snapshot_id.clone(),
                    stage: ResumeStage::Snapshot,
                    direction,
                    entries,
                    replay,
                });
                if let ControlMessage::Resumed(resumed) = &message {
                    recovery.snapshot_reply_messages[index] = Some(resumed.clone());
                }
                outbound.push((message, request_id));
            }
            outbound
        };
        for (message, request_id) in outbound {
            let response = message.clone();
            self.send_control(message, None)?;
            self.complete_recovery_message(&request_id, Some(&response))?;
        }
        Ok(())
    }

    fn recovery_obligations_satisfied(&self) -> bool {
        let Some(recovery) = self.recovery.as_ref() else {
            return false;
        };
        for stream_id in &recovery.begin.roster.stream_ids {
            let Some(stream) = self.streams.get(stream_id) else {
                return false;
            };
            for direction in [Direction::RelayToConnector, Direction::ConnectorToRelay] {
                let index = direction_index(direction);
                let Some(peer_snapshot) = recovery.remote_snapshots[index].get(stream_id) else {
                    return false;
                };
                let Some(local_snapshot) = recovery.local_snapshots[index].get(stream_id) else {
                    return false;
                };
                let state = stream.sequence.direction(direction);
                if state.recv_contiguous() < peer_snapshot.last_emitted
                    || state.peer_acked() < local_snapshot.last_emitted
                {
                    return false;
                }
            }
        }
        true
    }

    async fn maybe_finish_recovery(&mut self) -> Result<(), ClientError> {
        if self.recovery.as_ref().is_some_and(|recovery| {
            recovery
                .attempt_deadline_ms
                .is_some_and(|deadline| self.now_ms() >= deadline)
        }) {
            if self.pending_candidate.is_some() {
                return self.expire_pending_candidate().await;
            }
            return Err(ClientError::Transport {
                scope: "retained recovery",
                detail: "recovery candidate phase deadline expired".to_owned(),
            });
        }
        let ready_to_finish = self.recovery.as_ref().is_some_and(|recovery| {
            recovery.remote_ready.iter().all(|ready| *ready)
                && recovery.local_plans.len() == recovery.begin.roster.stream_ids.len()
        });
        if !ready_to_finish || self.candidate.is_none() {
            return Ok(());
        }
        if !self.recovery_obligations_satisfied() {
            return Ok(());
        }
        let needs_fresh_reconcile = self
            .recovery
            .as_ref()
            .is_some_and(|recovery| !recovery.fresh_reconciled);
        if needs_fresh_reconcile {
            // The initial snapshots are immutable obligations. Reconcile only
            // once against the fresh READY pair after replay and ACK progress;
            // feeding the stale initial pair back into StreamState would look
            // like an ACK regression.
            self.maybe_prepare_recovery_plans(false)?;
            if let Some(recovery) = self.recovery.as_mut() {
                recovery.fresh_reconciled = true;
            }
        }
        let (attempt, roster, remote_ready_message_ids, already_ready) = {
            let recovery = self
                .recovery
                .as_ref()
                .ok_or_else(|| ClientError::Protocol("recovery state disappeared".to_owned()))?;
            (
                recovery.begin.attempt.clone(),
                recovery.begin.roster.clone(),
                recovery.remote_ready_message_ids.clone(),
                recovery.ready_replies,
            )
        };
        let verdicts = {
            let recovery = self
                .recovery
                .as_ref()
                .ok_or_else(|| ClientError::Protocol("recovery state disappeared".to_owned()))?;
            let mut verdicts = Vec::new();
            for stream_id in &roster.stream_ids {
                let plan = recovery.local_plans.get(stream_id).ok_or_else(|| {
                    ClientError::Protocol(format!("missing recovery plan for stream {stream_id}"))
                })?;
                let verdict = ValidatedRecovery::from_sequence_plan(plan)
                    .map_err(|error| ClientError::Protocol(error.to_string()))?;
                if !verdict.is_ready() {
                    return Ok(());
                }
                verdicts.push(verdict);
            }
            verdicts
        };
        let frozen_snapshots = self.local_resume_snapshots(&roster)?;
        self.rotation
            .reconcile_validated(&attempt, verdicts, self.now_ms())
            .map_err(|error| {
                ClientError::Protocol(format!("recovery activation rejected: {error}"))
            })?;
        let candidate = self
            .candidate
            .take()
            .ok_or_else(|| ClientError::Protocol("recovery candidate disappeared".to_owned()))?;
        if !candidate
            .key
            .matches(attempt.new_generation, &attempt.new_connection_id)
        {
            return Err(ClientError::Protocol(
                "recovery candidate identity mismatch".to_owned(),
            ));
        }
        let old = std::mem::replace(&mut self.active, candidate);
        if old.reader.is_some() || old.writer.is_some() {
            let evidence = close_carrier(old).await;
            if !evidence.is_complete() {
                return Err(ClientError::Transport {
                    scope: "recovery old carrier",
                    detail: "old carrier remained live during recovery activation".to_owned(),
                });
            }
        }
        let mut ready_messages = Vec::new();
        for direction in [Direction::RelayToConnector, Direction::ConnectorToRelay] {
            let index = direction_index(direction);
            if already_ready[index] {
                continue;
            }
            let Some(reply_to) = remote_ready_message_ids[index].clone() else {
                continue;
            };
            let message = ControlMessage::Resumed(Resumed {
                message_id: message_id(),
                reply_to,
                attempt: attempt.clone(),
                snapshot_id: roster.snapshot_id.clone(),
                stage: ResumeStage::Ready,
                direction,
                entries: frozen_snapshots[index].values().cloned().collect(),
                replay: Vec::new(),
            });
            let request_id = match &message {
                ControlMessage::Resumed(resumed) => resumed.reply_to.clone(),
                _ => unreachable!("recovery ready response is RESUMED"),
            };
            if let ControlMessage::Resumed(resumed) = &message
                && let Some(recovery) = self.recovery.as_mut()
            {
                recovery.ready_reply_messages[index] = Some(resumed.clone());
            }
            ready_messages.push((message, request_id));
            if let Some(recovery) = self.recovery.as_mut() {
                recovery.ready_replies[index] = true;
            }
        }
        for (message, request_id) in &ready_messages {
            let response = message.clone();
            self.send_control(response.clone(), None)?;
            self.complete_recovery_message(request_id, Some(&response))?;
        }
        if let Some(completed) = self.recovery.take() {
            self.completed_recovery = Some(completed);
        }
        self.pending_candidate = None;
        self.recovery_requested = false;
        self.accepting = true;
        self.writes_frozen = false;
        self.rotations_completed = self.rotations_completed.saturating_add(1);
        self.flush_pending_outputs().await?;
        self.publish_status();
        Ok(())
    }

    async fn expire_stream(&mut self, stream_id: u64) -> Result<(), ClientError> {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.auth.invalidated = true;
            let pending_bytes = stream.pending_bytes;
            stream.pending.clear();
            stream.pending_bytes = 0;
            self.pending_output_bytes = self.pending_output_bytes.saturating_sub(pending_bytes);
        }
        self.emit_or_defer(PendingOutput {
            stream_id,
            kind: FrameKind::Reset,
            payload: Vec::new(),
            reset_reason: Some(M2_RESET_AUTH_EXPIRED),
        })
        .await
    }

    async fn flush_pending_outputs(&mut self) -> Result<(), ClientError> {
        while !self.writes_frozen {
            let Some(output) = self.pending_outputs.pop_front() else {
                break;
            };
            self.pending_output_bytes = self
                .pending_output_bytes
                .saturating_sub(output.payload.len());
            self.emit_output_now(output)?;
        }
        self.publish_status();
        Ok(())
    }

    async fn expire_pending_candidate(&mut self) -> Result<(), ClientError> {
        let Some(pending) = self.pending_candidate.as_ref() else {
            return Ok(());
        };
        let attempt = pending.attempt.clone();
        let recovery = pending.recovery;
        let evidence =
            self.close_candidate_resources()
                .await
                .ok_or_else(|| ClientError::Transport {
                    scope: "candidate data carrier",
                    detail: "candidate deadline elapsed without closure evidence".to_owned(),
                })?;
        if recovery {
            self.finish_recovery_candidate_loss(attempt, evidence).await
        } else {
            self.defer_candidate_abort(attempt, evidence)
        }
    }

    async fn close_candidate_resources(&mut self) -> Option<ClosureEvidence> {
        let mut evidence = None;
        if let Some(candidate) = self.candidate.take() {
            evidence = Some(close_carrier(candidate).await);
        }
        if let Some(mut pending) = self.pending_candidate.take() {
            if let Some(dial) = pending.dial.take() {
                dial.abort();
                let _ = dial.await;
            }
            if let Some(socket) = pending.socket.take() {
                evidence = Some(
                    close_unattached_socket(socket, pending.attempt.new_connection_id.clone())
                        .await,
                );
            } else if evidence.is_none() {
                // Joining the dial task proves that any socket owned inside
                // the handshake future has been dropped.  It cannot prove a
                // peer close, so retain that distinction in diagnostics.
                evidence = Some(ClosureEvidence {
                    connection_id: pending.attempt.new_connection_id,
                    local_closed: true,
                    peer_closed: false,
                });
            }
        }
        evidence
    }

    async fn close_all_carriers_for_recovery(
        &mut self,
    ) -> Result<BTreeMap<String, ClosureEvidence>, ClientError> {
        let mut evidence = std::mem::take(&mut self.closed_for_recovery);
        if let Some((_, closed)) = self.pending_candidate_close.take() {
            evidence.insert(closed.connection_id.clone(), closed);
        }
        if let Some(candidate) = self.candidate.take() {
            let closed = close_carrier(candidate).await;
            if !closed.is_complete() {
                return Err(ClientError::Transport {
                    scope: "recovery candidate",
                    detail: "candidate local close could not be joined".to_owned(),
                });
            }
            evidence.insert(closed.connection_id.clone(), closed);
        }
        if let Some(retiring) = self.retiring.take() {
            let closed = close_carrier(retiring).await;
            if !closed.is_complete() {
                return Err(ClientError::Transport {
                    scope: "recovery retiring carrier",
                    detail: "retiring local close could not be joined".to_owned(),
                });
            }
            evidence.insert(closed.connection_id.clone(), closed);
        }
        let active = std::mem::replace(
            &mut self.active,
            Carrier {
                key: CarrierKey::new(0, "recovery-placeholder"),
                local_addr: None,
                tx: mpsc::channel(1).0,
                reader_cancel: CancellationToken::new(),
                reader: None,
                writer: None,
            },
        );
        if active.reader.is_some() || active.writer.is_some() {
            let closed = close_carrier(active).await;
            if !closed.is_complete() {
                return Err(ClientError::Transport {
                    scope: "recovery active carrier",
                    detail: "active local close could not be joined".to_owned(),
                });
            }
            evidence.insert(closed.connection_id.clone(), closed);
        }
        if let Some(mut pending) = self.pending_candidate.take() {
            if let Some(dial) = pending.dial.take() {
                dial.abort();
                let _ = dial.await;
                // A cancelled and joined dial owns no socket.  It still has
                // a reserved physical identity in RotationState and must be
                // included in the bilateral closure attestation.
                evidence
                    .entry(pending.attempt.new_connection_id.clone())
                    .or_insert(ClosureEvidence {
                        connection_id: pending.attempt.new_connection_id.clone(),
                        local_closed: true,
                        peer_closed: false,
                    });
            }
            if let Some(socket) = pending.socket.take() {
                let closed =
                    close_unattached_socket(socket, pending.attempt.new_connection_id.clone())
                        .await;
                if !closed.is_complete() {
                    return Err(ClientError::Transport {
                        scope: "recovery pending carrier",
                        detail: "pending local close could not be joined".to_owned(),
                    });
                }
                evidence.insert(closed.connection_id.clone(), closed);
            }
        }
        Ok(evidence)
    }

    fn defer_candidate_abort(
        &mut self,
        attempt: RotationAttemptIdentity,
        evidence: ClosureEvidence,
    ) -> Result<(), ClientError> {
        if !evidence.local_closed {
            return Err(ClientError::Transport {
                scope: "candidate data carrier",
                detail: "candidate local closure was not confirmed".to_owned(),
            });
        }
        if self
            .rotation
            .status()
            .attempt
            .as_ref()
            .is_none_or(|current| current != &attempt)
        {
            return Err(ClientError::Protocol(
                "candidate closure attempt no longer matches rotation".to_owned(),
            ));
        }
        if !matches!(
            self.rotation.phase(),
            RotationPhase::Preparing
                | RotationPhase::Quiescing
                | RotationPhase::Draining
                | RotationPhase::Aborting
        ) {
            return Err(ClientError::Transport {
                scope: "candidate data carrier",
                detail: "candidate closed after activation decision".to_owned(),
            });
        }
        if let Some((existing, _)) = self.pending_candidate_close.as_ref()
            && existing != &attempt
        {
            return Err(ClientError::Protocol(
                "multiple candidate closures share one rotation attempt".to_owned(),
            ));
        }
        self.pending_candidate_close = Some((attempt, evidence));
        self.pending_candidate = None;
        // The old carrier remains authoritative, but no new sequenced frame
        // may pass while the owner decides ABORT.  Bounded adapter output is
        // retained in the existing queue and control/auth traffic continues.
        self.accepting = false;
        self.writes_frozen = true;
        self.publish_status();
        Ok(())
    }

    async fn finish_recovery_candidate_loss(
        &mut self,
        attempt: RotationAttemptIdentity,
        evidence: ClosureEvidence,
    ) -> Result<(), ClientError> {
        if self.recovery.is_none() || self.rotation.phase() != RotationPhase::Recovering {
            return Err(ClientError::Transport {
                scope: "recovery candidate",
                detail: "candidate carrier closed outside recovery".to_owned(),
            });
        }
        if !evidence.is_complete() {
            return Err(ClientError::Transport {
                scope: "recovery candidate",
                detail: "candidate local close could not be joined".to_owned(),
            });
        }
        self.rotation
            .candidate_closed(
                &attempt,
                RotationSide::Connector,
                evidence.clone(),
                self.now_ms(),
            )
            .map_err(|error| {
                ClientError::Protocol(format!("recovery candidate closure rejected: {error}"))
            })?;
        self.closed_for_recovery
            .insert(evidence.connection_id.clone(), evidence);
        if let Some(mut pending) = self.pending_candidate.take() {
            if let Some(dial) = pending.dial.take() {
                dial.abort();
                let _ = dial.await;
            }
            if let Some(socket) = pending.socket.take() {
                let _ = close_unattached_socket(socket, pending.attempt.new_connection_id.clone())
                    .await;
            }
        }
        self.accepting = false;
        self.writes_frozen = true;
        self.publish_status();
        Ok(())
    }

    async fn mark_carrier_closed(
        &mut self,
        key: &CarrierKey,
        _local_closed: bool,
        _peer_closed: bool,
    ) -> Result<(), ClientError> {
        if self
            .retiring
            .as_ref()
            .is_some_and(|carrier| carrier.key == *key)
        {
            return Ok(());
        }
        if self
            .candidate
            .as_ref()
            .is_some_and(|carrier| carrier.key == *key)
        {
            let candidate = self.candidate.take().expect("candidate checked above");
            let attempt = self
                .pending_candidate
                .as_ref()
                .map(|pending| pending.attempt.clone())
                .or_else(|| self.rotation.status().attempt)
                .ok_or_else(|| {
                    ClientError::Protocol("candidate closed without an attempt".to_owned())
                })?;
            let mut evidence = close_carrier(candidate).await;
            evidence.peer_closed |= _peer_closed;
            if self.recovery.is_some() {
                return self.finish_recovery_candidate_loss(attempt, evidence).await;
            }
            return self.defer_candidate_abort(attempt, evidence);
        }
        if self.active.key == *key {
            let active = std::mem::replace(
                &mut self.active,
                Carrier {
                    key: CarrierKey::new(0, "recovery-placeholder"),
                    local_addr: None,
                    tx: mpsc::channel(1).0,
                    reader_cancel: CancellationToken::new(),
                    reader: None,
                    writer: None,
                },
            );
            let evidence = close_carrier(active).await;
            if !evidence.is_complete() {
                return Err(ClientError::Transport {
                    scope: "active data carrier",
                    detail: "active carrier close could not be joined".to_owned(),
                });
            }
            self.closed_for_recovery
                .insert(evidence.connection_id.clone(), evidence);
            if !self.recovery_requested && self.rotation.phase() == RotationPhase::Active {
                self.recovery_requested = true;
                self.accepting = false;
                self.writes_frozen = true;
                let request = ControlMessage::RotateRequest(RotateRequest {
                    message_id: message_id(),
                    reply_to: String::new(),
                    session_id: self.session.session_id.clone(),
                    epoch: self.session.epoch,
                    owner_id: self.owner_id.clone(),
                    generation: key.generation,
                    connection_id: key.connection_id.clone(),
                    desired_interval_ms: None,
                    reason: Some("data_loss".to_owned()),
                });
                self.send_control(request, None)?;
            }
            self.publish_status();
            return Ok(());
        }
        Ok(())
    }

    async fn close_all_carriers(&mut self) {
        if let Some(candidate) = self.candidate.take() {
            let _ = close_carrier(candidate).await;
        }
        if let Some(retiring) = self.retiring.take() {
            let _ = close_carrier(retiring).await;
        }
        let active = std::mem::replace(
            &mut self.active,
            Carrier {
                key: CarrierKey::new(0, "shutdown"),
                local_addr: None,
                tx: mpsc::channel(1).0,
                reader_cancel: CancellationToken::new(),
                reader: None,
                writer: None,
            },
        );
        let _ = close_carrier(active).await;
        if let Some(mut pending) = self.pending_candidate.take() {
            if let Some(dial) = pending.dial.take() {
                dial.abort();
                let _ = dial.await;
            }
            if let Some(socket) = pending.socket.take() {
                let _ = close_unattached_socket(socket, pending.attempt.new_connection_id).await;
            }
        }
    }
}

async fn close_unattached_socket(
    mut socket: ClientWebSocket,
    connection_id: String,
) -> ClosureEvidence {
    let close_completed = tokio::time::timeout(M2_CLOSE_TIMEOUT, socket.close(None))
        .await
        .is_ok();
    // Dropping the owned socket after the bounded close attempt is the local
    // teardown proof even when the peer does not complete a WebSocket close
    // handshake.  Keep the graceful result separate for diagnostics.
    let local_closed = true;
    let peer_closed = if close_completed {
        matches!(
            tokio::time::timeout(M2_CLOSE_TIMEOUT, async {
                loop {
                    match socket.next().await {
                        Some(Ok(Message::Close(_))) | None => break true,
                        Some(Ok(_)) => continue,
                        Some(Err(_)) => break true,
                    }
                }
            })
            .await,
            Ok(true)
        )
    } else {
        false
    };
    ClosureEvidence {
        connection_id,
        local_closed,
        peer_closed,
    }
}

fn direction_index(direction: Direction) -> usize {
    match direction {
        Direction::RelayToConnector => 0,
        Direction::ConnectorToRelay => 1,
    }
}

fn direction_snapshot_from_resume(state: &ResumeDirectionState) -> DirectionSnapshot {
    DirectionSnapshot {
        last_emitted: state.last_emitted,
        peer_acked: state.peer_acked,
        recv_contiguous: state.recv_contiguous,
        delivered_contiguous: state.delivered_contiguous,
        send_credit: state.send_credit,
        sent_bytes: state.sent_bytes,
        receive_credit: state.receive_credit,
        received_bytes: state.received_bytes,
        send_terminal: state.send_terminal.map(Into::into),
        send_terminal_sequence: state.send_terminal_sequence(),
        receive_terminal: state.receive_terminal.map(Into::into),
        receive_terminal_sequence: state.receive_terminal_sequence(),
        replay_floor: state.replay_floor,
        replay_bytes: 0,
        reorder_frames: 0,
        reorder_bytes: 0,
    }
}

async fn join_carrier_task(mut task: JoinHandle<()>) -> bool {
    join_carrier_task_with_timeout(&mut task, M2_CLOSE_TIMEOUT).await
}

async fn join_carrier_task_with_timeout(task: &mut JoinHandle<()>, timeout: Duration) -> bool {
    match tokio::time::timeout(timeout, &mut *task).await {
        Ok(_) => true,
        Err(_) => {
            // A timed-out task still owns the sink until it is explicitly
            // aborted and joined.  Dropping the handle here would detach the
            // task and invalidate the local-closure evidence.
            task.abort();
            let _ = task.await;
            true
        }
    }
}

async fn close_carrier(mut carrier: Carrier) -> ClosureEvidence {
    let connection_id = carrier.key.connection_id.clone();
    carrier.reader_cancel.cancel();
    let (reply, wait) = oneshot::channel();
    let sent_close = matches!(
        tokio::time::timeout(
            M2_CLOSE_TIMEOUT,
            carrier.tx.send(CarrierCommand::Close(reply))
        )
        .await,
        Ok(Ok(()))
    );
    let _writer_closed = if sent_close {
        tokio::time::timeout(M2_CLOSE_TIMEOUT, wait).await.is_ok()
    } else {
        false
    };
    let writer_joined = if let Some(writer) = carrier.writer.take() {
        join_carrier_task(writer).await
    } else {
        true
    };
    let reader_joined = if let Some(reader) = carrier.reader.take() {
        join_carrier_task(reader).await
    } else {
        true
    };
    ClosureEvidence {
        connection_id,
        // Joining both carrier tasks proves that no local task still owns the
        // socket.  This remains true for the forced abort path above; peer
        // closure is tracked separately by the protocol handshake.
        local_closed: writer_joined && reader_joined,
        peer_closed: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(body: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(M2_RECORD_HEADER_BYTES + body.len());
        encoded.extend_from_slice(&(body.len() as u32).to_be_bytes());
        encoded.extend_from_slice(body);
        encoded
    }

    #[test]
    fn parser_consumes_a_complete_record_in_one_outer_frame() {
        let mut buffer = Vec::new();
        let mut expected = None;
        let responses = parse_echo_records(&mut buffer, &mut expected, "canary", &record(b"abc"))
            .expect("complete record parses");
        assert_eq!(responses.len(), 1);
        assert_eq!(&responses[0][..4], &(9_u32.to_be_bytes()));
        assert_eq!(&responses[0][4..], b"canaryabc");
        assert!(buffer.is_empty());
        assert_eq!(expected, None);
    }

    #[test]
    fn parser_retains_split_header_and_payload_until_complete() {
        let encoded = record(b"split");
        let mut buffer = Vec::new();
        let mut expected = None;
        assert!(
            parse_echo_records(&mut buffer, &mut expected, "", &encoded[..2])
                .expect("header fragment parses")
                .is_empty()
        );
        let responses = parse_echo_records(&mut buffer, &mut expected, "", &encoded[2..])
            .expect("payload fragment parses");
        assert_eq!(responses.len(), 1);
        assert_eq!(&responses[0][..], &record(b"split"));
        assert!(buffer.is_empty());
        assert_eq!(expected, None);
    }

    #[test]
    fn parser_consumes_coalesced_and_empty_records() {
        let mut payload = record(b"first");
        payload.extend_from_slice(&record(b""));
        payload.extend_from_slice(&record(b"third"));
        let mut buffer = Vec::new();
        let mut expected = None;
        let responses = parse_echo_records(&mut buffer, &mut expected, "x", &payload)
            .expect("coalesced records parse");
        assert_eq!(responses.len(), 3);
        assert_eq!(&responses[1][..], &record(b"x"));
        assert!(buffer.is_empty());
        assert_eq!(expected, None);
    }

    #[test]
    fn parser_accepts_maximum_record_and_canary() {
        let body = vec![0x5a; M2_MAX_RECORD_BYTES];
        let canary = "c".repeat(M2_MAX_CANARY_BYTES);
        let encoded = record(&body);
        let mut buffer = Vec::new();
        let mut expected = None;
        let responses = parse_echo_records(&mut buffer, &mut expected, &canary, &encoded)
            .expect("maximum bounded record parses");
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].len(), M2_MAX_STREAM_RESPONSE_BYTES);
        assert!(buffer.is_empty());
    }

    #[test]
    fn parser_rejects_record_length_above_bound() {
        let mut buffer = Vec::new();
        let mut expected = None;
        let invalid = (M2_MAX_RECORD_BYTES as u32 + 1).to_be_bytes();
        assert!(parse_echo_records(&mut buffer, &mut expected, "", &invalid).is_err());
    }

    fn test_stream() -> M2Stream {
        let started = Instant::now();
        let deadline = DualDeadline::new(started, SystemTime::now(), Duration::from_secs(1))
            .expect("test deadline");
        M2Stream {
            export: super::super::ExportConfig::default(),
            operation_id: "operation".to_owned(),
            service_id: "echo".to_owned(),
            operation: "echo_stream".to_owned(),
            auth: AuthContext {
                challenge_id: "challenge".to_owned(),
                nonce: "nonce".to_owned(),
                permission_digest: "permission".to_owned(),
                grant_revision: 1,
                deadline,
                operation_deadline: deadline,
                confirmed: false,
                refresh_in_flight: true,
                invalidated: false,
            },
            sequence: StreamState::new(1, 1024).expect("test sequence"),
            pending: VecDeque::new(),
            pending_bytes: 0,
            record_buffer: Vec::new(),
            record_expected: None,
            input_fin: false,
            input_reset: false,
            output_fin: false,
            output_reset: false,
            reset_queued: false,
        }
    }

    #[test]
    fn reset_admission_is_idempotent_before_and_after_flush() {
        let mut stream = test_stream();
        assert!(queue_reset_once(&mut stream));
        assert!(!queue_reset_once(&mut stream));
        assert!(stream.reset_queued);

        stream.reset_queued = false;
        stream.output_reset = true;
        assert!(!queue_reset_once(&mut stream));
    }

    #[test]
    fn retired_physical_writer_events_remain_fenced() {
        let active = CarrierKey::new(3, "active");
        let retired = CarrierKey::new(2, "retired");
        let unknown = CarrierKey::new(9, "unknown");
        let attempt = RotationAttemptIdentity::new(
            "session",
            1,
            "owner",
            "rotation",
            retired.generation,
            active.generation,
            retired.connection_id.clone(),
            active.connection_id.clone(),
        );
        assert!(physical_key_is_tracked(
            &retired,
            Some(&active),
            None,
            Some(&retired),
        ));
        assert!(attempt_key_is_tracked(&retired, &attempt));
        assert!(attempt_key_is_tracked(&active, &attempt));
        assert!(!physical_key_is_tracked(
            &unknown,
            Some(&active),
            None,
            Some(&retired),
        ));
        assert!(!attempt_key_is_tracked(&unknown, &attempt));
    }

    #[test]
    fn recovery_candidate_deadline_is_bounded_by_episode() {
        assert_eq!(
            bounded_candidate_deadline(100, 50, 120).expect("shorter wire cap"),
            120
        );
        assert_eq!(
            bounded_candidate_deadline(100, 5_000, 250).expect("episode cap"),
            250
        );
        assert!(bounded_candidate_deadline(100, 0, 250).is_err());
        assert!(bounded_candidate_deadline(u64::MAX, 1, u64::MAX).is_err());
    }

    #[tokio::test]
    async fn full_event_queue_send_cancels_without_detaching() {
        let (events, _receiver) = mpsc::channel(1);
        events
            .try_send(ActorEvent::Data(CarrierEvent::WriterClosed {
                key: CarrierKey::new(1, "filled"),
            }))
            .expect("fill event queue");
        let cancellation = CancellationToken::new();
        let send_cancellation = cancellation.clone();
        let send = tokio::spawn(async move {
            send_carrier_event(
                &events,
                ActorEvent::Data(CarrierEvent::WriterClosed {
                    key: CarrierKey::new(2, "blocked"),
                }),
                &send_cancellation,
            )
            .await
        });
        tokio::task::yield_now().await;
        cancellation.cancel();
        assert!(!send.await.expect("event sender joined"));
    }

    #[tokio::test]
    async fn timed_out_carrier_task_is_aborted_and_joined() {
        let (dropped, dropped_rx) = oneshot::channel::<()>();
        let mut task = tokio::spawn(async move {
            let _dropped = dropped;
            std::future::pending::<()>().await;
        });
        assert!(join_carrier_task_with_timeout(&mut task, Duration::from_millis(1)).await);
        assert!(dropped_rx.await.is_err());
        assert!(task.is_finished());
    }
}
