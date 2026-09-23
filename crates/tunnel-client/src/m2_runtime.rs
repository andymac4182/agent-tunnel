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
    collections::{BTreeMap, BTreeSet, VecDeque},
    mem::size_of,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use tunnel_protocol::control::{MAX_METADATA_VALUE_BYTES, MAX_ROTATION_RECOVERY_TIMEOUT_MS};
use tunnel_protocol::control_journal::{
    ControlJournal, MAX_JOURNAL_BYTES, MAX_JOURNAL_ENTRIES, Observation as JournalObservation,
};
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
    MAX_FRAME_LEN, MAX_PAYLOAD_LEN, Open, Opened, OwnerFence, OwnerFenceState, Ping, Pong,
    Rejected, RotateAbort, RotateAborted, RotateCommit, RotateCommitted, RotateComplete,
    RotateDrained, RotateFrozen, RotatePrepare, RotateQuiesce, RotateRequest, RotateRetire,
    RotateRetired, decode_control,
};
use url::Url;

#[path = "m2_http.rs"]
mod m2_http;
use crate::http_forward::{HttpActorRequest, HttpHandlers};
use m2_http::{DeviceHttpState, FS_STREAM_OPERATION, HTTP_FORWARD_OPERATION};

const M2_FEATURE: &str = "ordered-rotation-v1";
const OWNER_FENCING_FEATURE: &str = "owner-fencing-v1";
const M1_FEATURES: [&str; 3] = ["m1-control-data", "authorization-challenge", "echo"];
const M2_CONTROL_QUEUE_BYTES: usize = 64 * 1024;
// Deferred critical replies use a separate, explicit spill bound alongside
// the fixed writer queue: at most four messages and one maximum protocol
// control frame (96 KiB aggregate with the 64 KiB writer queue). This is the
// smallest spill that can retain any valid control response without silently
// duplicating the full writer queue.
const M2_PENDING_CRITICAL_CONTROL_FRAMES: usize = 4;
const M2_PENDING_CRITICAL_CONTROL_BYTES: usize = MAX_CONTROL_MESSAGE_BYTES;
const M2_CRITICAL_CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
// A control STREAM_FORGET can legitimately overtake the final data-channel
// ACK. Keep the authenticated terminal proof pending for one bounded window
// while that ACK arrives; the final validator still runs before reclamation.
const M2_STREAM_FORGET_REVALIDATION_TIMEOUT: Duration = M2_CRITICAL_CONTROL_TIMEOUT;
const M2_WRITER_TIMEOUT: Duration = Duration::from_secs(5);
const M2_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
const M2_DEADLINE_POLL: Duration = Duration::from_millis(100);
const M2_RECOVERY_RESET_FENCED_SUCCESSOR: &str = "fenced_successor_activated";
const M2_EVENT_CAPACITY: usize = 256;
const M2_CARRIER_QUEUE_FRAMES: usize = 128;
const M2_MAX_WEBSOCKET_CONTROL_PAYLOAD: usize = 125;
// Keep a small part of the existing carrier queue available for cumulative
// control and terminal frames while bulk DATA is backpressured.  This is a
// reservation inside the fixed queue, not additional capacity.
const M2_CARRIER_RESERVED_FRAMES: usize = 4;
const M2_CARRIER_RESERVED_BYTES: usize = 256 * 1024;
const M2_MAX_RECORD_BYTES: usize = 64 * 1024;
const M2_MAX_CANARY_BYTES: usize = 256;
const M2_RECORD_HEADER_BYTES: usize = 4;
const M2_MAX_STREAM_RESPONSE_BYTES: usize =
    M2_RECORD_HEADER_BYTES + M2_MAX_RECORD_BYTES + M2_MAX_CANARY_BYTES;
// A terminal M2 stream remains in the connector table until authenticated
// STREAM_FORGET evidence arrives.  Keep the same bounded retained-table
// factor as the relay: terminal entries do not consume active capacity, but
// active plus retained entries may never exceed two times the live stream
// ceiling (or the protocol journal bound).
const M2_RETAINED_STREAM_FACTOR: usize = 2;

fn retained_stream_limit(max_streams: usize) -> usize {
    max_streams
        .saturating_mul(M2_RETAINED_STREAM_FACTOR)
        .min(M2_OPEN_JOURNAL_MAX_ENTRIES)
}

const M2_MAX_REASSEMBLY_BYTES: usize =
    M2_RECORD_HEADER_BYTES + M2_MAX_RECORD_BYTES + MAX_PAYLOAD_LEN;
const M2_MAX_RESPONSE_BATCH_BYTES: usize = M2_MAX_REASSEMBLY_BYTES;
// A deferred OPEN keeps its decoded request tree separately from the wire
// journal.  Charge a conservative estimate for parsed strings, BTreeMap
// nodes, allocator slack, and the authorization strings prepared before the
// atomic OPENED/challenge pair is admitted.  The estimate is deliberately
// independent of the journal's canonical-byte charge.
const M2_PENDING_OPEN_GENERATED_ID_BYTES: usize = 36; // UUID v4 text
const M2_PENDING_OPEN_METADATA_NODE_BYTES: usize = 192;
const M2_PENDING_OPEN_STRING_HEADROOM_BYTES: usize = 64;
const M2_PENDING_OPEN_CONTAINER_HEADROOM_BYTES: usize = 4 * 1024;
const M2_PENDING_OPEN_MAX_ESTIMATE: usize = 2 * MAX_CONTROL_MESSAGE_BYTES
    + 2 * MAX_METADATA_VALUE_BYTES
    + 8 * M2_PENDING_OPEN_GENERATED_ID_BYTES
    + 64 * M2_PENDING_OPEN_METADATA_NODE_BYTES
    + 138 * M2_PENDING_OPEN_STRING_HEADROOM_BYTES
    + M2_PENDING_OPEN_CONTAINER_HEADROOM_BYTES;
/// Refresh stream authorization before its five-second confirmation window
/// expires.  The relay still validates every new challenge against its live
/// grant and device identity; this margin only prevents a long-lived stream
/// from dispatching at the exact expiry boundary.
const M2_AUTH_REFRESH_MARGIN: Duration = Duration::from_millis(1_500);
const M2_RESET_AUTH_EXPIRED: u16 = tunnel_protocol::reset_reason::AUTHORIZATION_EXPIRED;
const M2_RESET_PROTOCOL: u16 = tunnel_protocol::reset_reason::PROTOCOL;
const M2_RESET_RECORD_LIMIT: u16 = tunnel_protocol::reset_reason::RECORD_LIMIT;
const OWNER_FENCE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

fn critical_reserved_bytes(max_queue_bytes: usize) -> usize {
    // Keep the reserve bounded at one quarter of the configured budget.  The
    // minimum accepted budget is 256 KiB, so bulk still has 192 KiB for a
    // maximum record plus its bounded sequence/reassembly copies while the
    // critical path retains a useful 64 KiB floor.  Larger configurations
    // retain the fixed 256 KiB reserve requested by the runtime contract.
    M2_CARRIER_RESERVED_BYTES.min(max_queue_bytes / 4)
}

fn is_closed_data_writer(error: &ClientError) -> bool {
    matches!(
        error,
        ClientError::Transport {
            scope: "data writer",
            detail,
        } if detail == "data writer stopped"
    )
}

/// The first carrier event that caused this M2 epoch to enter recovery.  The
/// event class is deliberately closed and payload-free: the final CLI
/// diagnostic must distinguish the physical failure that started recovery
/// without copying a tungstenite error, endpoint, or frame into user output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryTriggerClass {
    WriterFailed,
    ReaderClosed,
    WriterClosed,
}

impl RecoveryTriggerClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::WriterFailed => "data_writer_failed",
            Self::ReaderClosed => "data_reader_closed",
            Self::WriterClosed => "data_writer_closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CarrierRole {
    Active,
    Candidate,
    Retiring,
    PendingCandidate,
    PendingCandidateClose,
    RecoveryClosed,
    Unknown,
}

impl CarrierRole {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Candidate => "candidate",
            Self::Retiring => "retiring",
            Self::PendingCandidate => "pending_candidate",
            Self::PendingCandidateClose => "pending_candidate_close",
            Self::RecoveryClosed => "recovery_closed",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecoveryTrigger {
    class: RecoveryTriggerClass,
    role: CarrierRole,
    generation: u64,
}

impl RecoveryTrigger {
    fn append_to(self, detail: &str) -> String {
        format!(
            "{detail}; recovery_trigger={}; recovery_role={}; recovery_generation={}",
            self.class.as_str(),
            self.role.as_str(),
            self.generation,
        )
    }
}

type M2SupervisorJoin = JoinHandle<Result<(), ClientError>>;

/// Establish an M2 control/data session and hand ownership to the actor.
pub(super) async fn connect_m2(
    options: super::ConnectOptions,
    http_handlers: HttpHandlers,
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
    let owner_id = welcome
        .owner_id
        .clone()
        .ok_or_else(|| ClientError::Protocol("M2 WELCOME omitted owner identity".to_owned()))?;
    let owner_fence = if owner_fencing_selected(&welcome) {
        Some(complete_owner_fence(&mut control, &welcome, &owner_id, &options.cancellation).await?)
    } else {
        None
    };
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
            owner_fence,
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
            None,
            http_handlers,
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
    features.push(OWNER_FENCING_FEATURE.to_owned());
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

fn owner_fencing_selected(welcome: &tunnel_protocol::Welcome) -> bool {
    welcome
        .supported_features
        .iter()
        .any(|feature| feature == OWNER_FENCING_FEATURE)
}

fn validate_owner_fence_context(
    fence: &OwnerFence,
    welcome: &tunnel_protocol::Welcome,
    owner_id: &str,
) -> Result<(), ClientError> {
    fence
        .validate()
        .map_err(|error| ClientError::Protocol(format!("invalid OWNER_FENCE: {error}")))?;
    if fence.session_id != welcome.session_id {
        return Err(ClientError::Protocol(
            "OWNER_FENCE session identity mismatch".to_owned(),
        ));
    }
    if fence.epoch != welcome.epoch {
        return Err(ClientError::Protocol(
            "OWNER_FENCE epoch does not match WELCOME".to_owned(),
        ));
    }
    if fence.owner_id != owner_id {
        return Err(ClientError::Protocol(
            "OWNER_FENCE owner identity does not match WELCOME".to_owned(),
        ));
    }
    Ok(())
}

async fn send_control_before_deadline(
    socket: &mut ClientWebSocket,
    message: &ControlMessage,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
) -> Result<(), ClientError> {
    tokio::select! {
        _ = cancellation.cancelled() => Err(ClientError::Cancelled),
        result = tokio::time::timeout_at(deadline, send_control_direct(socket, message)) => {
            result.map_err(|_| ClientError::HandshakeTimeout)?
        }
    }
}

async fn complete_owner_fence(
    socket: &mut ClientWebSocket,
    welcome: &tunnel_protocol::Welcome,
    owner_id: &str,
    cancellation: &CancellationToken,
) -> Result<OwnerFenceState, ClientError> {
    // This is the only bootstrap path that can transition a fresh control
    // session into an owner-authorized state.  No data carrier has been
    // allocated yet, so a prior local owner has no resources to retain or
    // accidentally reuse.  The typed state transition still invalidates any
    // prior owner before the acknowledgement is sent.
    let mut state = OwnerFenceState::new(welcome.session_id.clone())
        .map_err(|error| ClientError::Protocol(format!("invalid owner-fence session: {error}")))?;
    let started = Instant::now();
    let deadline = tokio::time::Instant::now() + OWNER_FENCE_HANDSHAKE_TIMEOUT;
    let timeout = tokio::time::sleep_until(deadline);
    tokio::pin!(timeout);
    loop {
        let next = tokio::select! {
            _ = &mut timeout => return Err(ClientError::HandshakeTimeout),
            _ = cancellation.cancelled() => return Err(ClientError::Cancelled),
            item = socket.next() => item,
        };
        match next {
            Some(Ok(Message::Text(text))) => {
                let message = decode_control(text.as_bytes())
                    .map_err(|error| ClientError::Protocol(error.to_string()))?;
                match message {
                    ControlMessage::OwnerFence(fence) => {
                        validate_owner_fence_context(&fence, welcome, owner_id)?;
                        let now_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
                        let acknowledgement = state
                            .accept_fence(&fence, message_id(), now_ms)
                            .map_err(|error| {
                                ClientError::Protocol(format!("OWNER_FENCE rejected: {error}"))
                            })?;
                        let message = ControlMessage::OwnerFenced(acknowledgement.clone());
                        send_control_before_deadline(socket, &message, deadline, cancellation)
                            .await?;
                        let acknowledged_at =
                            started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
                        state
                            .acknowledgement_sent(&acknowledgement, acknowledged_at)
                            .map_err(|error| {
                                ClientError::Protocol(format!(
                                    "OWNER_FENCED acknowledgement expired: {error}"
                                ))
                            })?;
                        return Ok(state);
                    }
                    ControlMessage::Ping(ping) => {
                        let pong = ControlMessage::Pong(Pong::new(
                            message_id(),
                            ping.message_id,
                            ping.session_id,
                            ping.epoch,
                            ping.nonce,
                        ));
                        send_control_before_deadline(socket, &pong, deadline, cancellation).await?;
                    }
                    other => {
                        return Err(ClientError::Protocol(format!(
                            "expected OWNER_FENCE before data attachment, received {}",
                            other.kind_name()
                        )));
                    }
                }
            }
            Some(Ok(Message::Ping(payload))) => {
                tokio::select! {
                    _ = cancellation.cancelled() => return Err(ClientError::Cancelled),
                    result = tokio::time::timeout_at(deadline, socket.send(Message::Pong(payload))) => {
                        result
                            .map_err(|_| ClientError::HandshakeTimeout)?
                            .map_err(|error| ClientError::Transport {
                                scope: "control pong",
                                detail: sanitize_error(&error.to_string()),
                            })?;
                    }
                }
            }
            Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
            Some(Ok(Message::Close(_))) | None => {
                return Err(ClientError::Transport {
                    scope: "owner fencing handshake",
                    detail: "relay closed the control socket".to_owned(),
                });
            }
            Some(Ok(Message::Binary(_))) => {
                return Err(ClientError::Protocol(
                    "binary message on control socket during owner fencing".to_owned(),
                ));
            }
            Some(Err(error)) => {
                return Err(ClientError::Transport {
                    scope: "control read",
                    detail: sanitize_error(&error.to_string()),
                });
            }
        }
    }
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
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

/// What one deadline-forced closure of the old carrier released: the closed
/// connection identifier, and the owner `ROTATE_RETIRE` that was still
/// deferred when the deadline arrived, if any.
struct ForcedRetirement {
    old_connection_id: String,
    deferred_retire: Option<RotateRetire>,
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
    pending_controls: BTreeMap<u64, PendingCarrierControl>,
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
    /// Connection IDs whose closure was already authenticated by the prior
    /// RECOVERY_CLOSED pair in this episode. They remain in the local fence
    /// map for stale-event rejection but are omitted from the next bounded
    /// wire closure list.
    authenticated_closed_connection_ids: BTreeSet<String>,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResumeContextMismatch {
    Attempt,
    Snapshot,
    RemainingZero,
    RemainingExceedsProtocolBound,
    DeadlineExpired,
}

impl ResumeContextMismatch {
    const fn detail(self) -> &'static str {
        match self {
            Self::Attempt => "RESUME recovery attempt mismatch",
            Self::Snapshot => "RESUME recovery snapshot mismatch",
            Self::RemainingZero => "RESUME recovery remaining budget is zero",
            Self::RemainingExceedsProtocolBound => {
                "RESUME recovery remaining budget exceeds protocol bound"
            }
            Self::DeadlineExpired => "RESUME recovery local deadline expired",
        }
    }
}

fn resume_context_mismatch(
    resume: &Resume,
    recovery: &RecoveryRuntime,
    now_ms: u64,
) -> Option<ResumeContextMismatch> {
    if resume.attempt != recovery.begin.attempt {
        return Some(ResumeContextMismatch::Attempt);
    }
    if resume.snapshot_id != recovery.begin.roster.snapshot_id {
        return Some(ResumeContextMismatch::Snapshot);
    }
    if resume.remaining_ms == 0 {
        return Some(ResumeContextMismatch::RemainingZero);
    }
    if resume.remaining_ms > MAX_ROTATION_RECOVERY_TIMEOUT_MS {
        return Some(ResumeContextMismatch::RemainingExceedsProtocolBound);
    }
    if now_ms >= recovery.deadline_ms {
        return Some(ResumeContextMismatch::DeadlineExpired);
    }
    // The sender samples remaining_ms before its control item reaches this
    // actor.  Keep the receiver's episode deadline authoritative instead of
    // rejecting a slightly larger stale duration or using it as an extension.
    None
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

/// The first response pair prepared for a deferred OPEN.  The IDs and grant
/// deadline are retained so a retry cannot refresh an authorization window or
/// nonce while waiting for bounded writer capacity.
#[derive(Debug)]
struct PendingAuthorization {
    opened_message_id: String,
    challenge_message_id: String,
    challenge_id: String,
    nonce: String,
    permission_digest: String,
    grant_revision: u64,
    auth_deadline: DualDeadline,
}

/// An owned reservation in the parsed-OPEN pool. Keeping the reservation on
/// the deferred item makes every move/drop path release exactly once,
/// including an admission error after the item has been removed from the
/// actor's head or FIFO. The underscore marks this field as intentionally
/// drop-owned; it must not be manually read or released by admission code.
struct PendingOpenReservation {
    budget: Arc<QueueBudget>,
    bytes: usize,
}

impl std::fmt::Debug for PendingOpenReservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingOpenReservation")
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl Drop for PendingOpenReservation {
    fn drop(&mut self) {
        self.budget.release(self.bytes);
    }
}

/// One OPEN whose bounded response admission was deferred. The actor keeps a
/// single head for the atomic response pair and a bounded FIFO behind it, so
/// later control reads cannot overwrite the head or turn a normal burst into
/// a session-fatal protocol error. The operation deadline starts when the
/// OPEN is received; authorization timing starts when its first challenge is
/// prepared and is retained across retries.
#[derive(Debug)]
struct PendingOpen {
    open: Open,
    operation_deadline: DualDeadline,
    authorization: Option<PendingAuthorization>,
    _reservation: PendingOpenReservation,
}

fn pending_open_budget_max(max_streams: usize, max_queue_bytes: usize) -> usize {
    // This is an independent parsed-OPEN pool. It is capped by the same
    // configured ceiling, but is intentionally not folded into the journal
    // or M2 data/output aggregate; each bounded pool accounts for its own
    // representation and cannot borrow another pool's allowance.
    max_queue_bytes.min(max_streams.saturating_mul(M2_PENDING_OPEN_MAX_ESTIMATE))
}

/// Estimate the retained heap for one decoded OPEN plus the authorization
/// strings that may be prepared before its atomic response pair is admitted.
/// The canonical wire bytes are charged separately by OpenJournal; this pool
/// covers the second parsed representation and allocator/container headroom.
fn pending_open_retained_bytes(open: &Open) -> Option<usize> {
    let open_string_bytes = [
        open.message_id.len(),
        open.session_id.len(),
        open.operation_id.len(),
        open.service_id.len(),
        open.operation.len(),
    ]
    .into_iter()
    .try_fold(0usize, |total, bytes| total.checked_add(bytes))?
    .checked_add(
        open.metadata
            .iter()
            .try_fold(0usize, |total, (key, value)| {
                total
                    .checked_add(key.len())
                    .and_then(|total| total.checked_add(value.len()))
            })?,
    )?;
    let metadata_nodes = open
        .metadata
        .len()
        .checked_mul(M2_PENDING_OPEN_METADATA_NODE_BYTES)?;
    let permission_digest_bytes = open
        .metadata
        .get("permission_digest")
        .map_or(0, String::len);
    let generated_id_bytes = 4usize.checked_mul(M2_PENDING_OPEN_GENERATED_ID_BYTES)?;
    let authorization_payload = permission_digest_bytes.checked_add(generated_id_bytes)?;
    let retained_string_slots = 5usize
        .checked_add(open.metadata.len().checked_mul(2)?)?
        .checked_add(5)?;
    let string_headroom =
        retained_string_slots.checked_mul(M2_PENDING_OPEN_STRING_HEADROOM_BYTES)?;
    let payload_headroom = open_string_bytes
        .checked_add(authorization_payload)?
        .checked_mul(2)?;
    size_of::<PendingOpen>()
        .checked_add(metadata_nodes)
        .and_then(|total| total.checked_add(M2_PENDING_OPEN_CONTAINER_HEADROOM_BYTES))
        .and_then(|total| total.checked_add(string_headroom))
        .and_then(|total| total.checked_add(payload_headroom))
}

const M2_OPEN_JOURNAL_MAX_ENTRIES: usize = MAX_JOURNAL_ENTRIES;
/// Retired stream IDs are kept as disjoint inclusive ranges.  The range count
/// is not derived from the retained-entry cap: a gap can be a stream the
/// session still retains, but it can equally be an ID the owner allocated and
/// never named in an OPEN or a STREAM_FORGET, so sustained control-queue
/// pressure can open arbitrarily many.  The bound is enforced by coalescing
/// instead, which is safe because every absorbed ID is below the reclamation
/// watermark and therefore already benign.
const M2_RETIRED_STREAM_RANGES: usize = M2_OPEN_JOURNAL_MAX_ENTRIES + 64;
// The journal retains encoded wire messages and deadline metadata rather than
// parsed response trees. Keep a conservative fixed charge for the enclosing
// BTree/String/Vec/Message allocations in addition to their encoded bytes.
const M2_OPEN_JOURNAL_ENTRY_OVERHEAD: usize = 256;
const M2_OPEN_JOURNAL_RESPONSE_OVERHEAD: usize = 256;

#[derive(Clone, Debug)]
enum OpenJournalState {
    Pending,
    Completed {
        // Retain the exact outbound wire messages so replay does not retain
        // an uncharged parsed control tree or regenerate response identities.
        responses: Vec<Message>,
        deadlines: Vec<Option<DualDeadline>>,
    },
    Tombstone,
}

#[derive(Debug)]
struct OpenJournalEntry {
    canonical: Vec<u8>,
    stream_id: u64,
    operation_id: String,
    /// Receive order is independent of the BTreeMap message-ID order.  It
    /// reserves the first request for a stream for the whole session,
    /// including rejected and compacted entries.
    receive_ordinal: u64,
    /// The fixed request charge admitted by `observe`, retained so that
    /// reclamation releases exactly what the entry reserved.
    request_bytes: usize,
    response_bytes: usize,
    state: OpenJournalState,
}

#[derive(Debug)]
enum OpenJournalObservation {
    New,
    PendingDuplicate,
    CompletedDuplicate {
        responses: Vec<Message>,
        deadlines: Vec<Option<DualDeadline>>,
    },
    Tombstone,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenJournalError {
    Capacity,
    ConflictingMessage,
    MissingMessage,
    ConflictingResponse,
    TombstoneCapacity,
}

#[derive(Debug)]
struct OpenJournal {
    entries: BTreeMap<String, OpenJournalEntry>,
    next_receive_ordinal: u64,
    active_entries: usize,
    tombstones: usize,
    used_bytes: usize,
    max_active_entries: usize,
    max_bytes: usize,
}

impl OpenJournal {
    fn new(max_active_entries: usize, max_bytes: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            next_receive_ordinal: 0,
            active_entries: 0,
            tombstones: 0,
            used_bytes: 0,
            max_active_entries: max_active_entries.max(1),
            max_bytes,
        }
    }

    fn observe(
        &mut self,
        message_id: &str,
        canonical: &[u8],
        stream_id: u64,
        operation_id: &str,
    ) -> Result<OpenJournalObservation, OpenJournalError> {
        if let Some(entry) = self.entries.get(message_id) {
            if entry.canonical != canonical {
                return Err(OpenJournalError::ConflictingMessage);
            }
            return Ok(match &entry.state {
                OpenJournalState::Pending => OpenJournalObservation::PendingDuplicate,
                OpenJournalState::Completed {
                    responses,
                    deadlines,
                } => OpenJournalObservation::CompletedDuplicate {
                    responses: responses.clone(),
                    deadlines: deadlines.clone(),
                },
                OpenJournalState::Tombstone => OpenJournalObservation::Tombstone,
            });
        }
        // Keep the total retained table bounded by the tombstone budget.  An
        // active entry consumes one of the same fixed slots that its future
        // tombstone needs, so every admitted stream can still complete
        // STREAM_FORGET without discovering that no retention slot remains.
        if self.active_entries >= self.max_active_entries
            || self.entries.len() >= M2_OPEN_JOURNAL_MAX_ENTRIES
        {
            return Err(OpenJournalError::Capacity);
        }
        let charge = M2_OPEN_JOURNAL_ENTRY_OVERHEAD
            .checked_add(message_id.len())
            .and_then(|value| value.checked_add(canonical.len()))
            .and_then(|value| value.checked_add(operation_id.len()))
            .ok_or(OpenJournalError::Capacity)?;
        if charge > self.max_bytes.saturating_sub(self.used_bytes) {
            return Err(OpenJournalError::Capacity);
        }
        let receive_ordinal = self.next_receive_ordinal;
        self.next_receive_ordinal = self
            .next_receive_ordinal
            .checked_add(1)
            .ok_or(OpenJournalError::Capacity)?;
        self.entries.insert(
            message_id.to_owned(),
            OpenJournalEntry {
                canonical: canonical.to_vec(),
                stream_id,
                operation_id: operation_id.to_owned(),
                receive_ordinal,
                request_bytes: charge,
                response_bytes: 0,
                state: OpenJournalState::Pending,
            },
        );
        self.active_entries += 1;
        self.used_bytes += charge;
        Ok(OpenJournalObservation::New)
    }

    fn ensure_response_capacity(
        &self,
        message_id: &str,
        response_bytes: usize,
    ) -> Result<(), OpenJournalError> {
        let Some(entry) = self.entries.get(message_id) else {
            return Err(OpenJournalError::MissingMessage);
        };
        if !matches!(&entry.state, OpenJournalState::Pending) {
            return Err(OpenJournalError::ConflictingResponse);
        }
        if response_bytes > self.max_bytes.saturating_sub(self.used_bytes) {
            return Err(OpenJournalError::Capacity);
        }
        Ok(())
    }

    fn complete(
        &mut self,
        message_id: &str,
        responses: Vec<Message>,
        deadlines: Vec<Option<DualDeadline>>,
        response_bytes: usize,
    ) -> Result<(), OpenJournalError> {
        if responses.is_empty() || responses.len() != deadlines.len() {
            return Err(OpenJournalError::ConflictingResponse);
        }
        self.ensure_response_capacity(message_id, response_bytes)?;
        let entry = self
            .entries
            .get_mut(message_id)
            .ok_or(OpenJournalError::MissingMessage)?;
        entry.response_bytes = response_bytes;
        entry.state = OpenJournalState::Completed {
            responses,
            deadlines,
        };
        self.used_bytes += response_bytes;
        Ok(())
    }

    fn compact(&mut self, message_id: &str) -> Result<(), OpenJournalError> {
        if !self.entries.contains_key(message_id) {
            return Ok(());
        }
        if self
            .entries
            .get(message_id)
            .is_some_and(|entry| matches!(&entry.state, OpenJournalState::Tombstone))
        {
            return Ok(());
        }
        if self.tombstones >= M2_OPEN_JOURNAL_MAX_ENTRIES {
            return Err(OpenJournalError::TombstoneCapacity);
        }
        let released = {
            let entry = self
                .entries
                .get_mut(message_id)
                .expect("OPEN journal entry was checked above");
            let released = entry.response_bytes;
            entry.response_bytes = 0;
            entry.state = OpenJournalState::Tombstone;
            released
        };
        self.used_bytes = self.used_bytes.saturating_sub(released);
        self.active_entries = self.active_entries.saturating_sub(1);
        self.tombstones += 1;
        Ok(())
    }

    /// Release every entry bound to `stream_id`/`operation_id` once the
    /// owner's `STREAM_FORGET` for that exact identity has completed its
    /// carrier barriers.  This is the OPEN retry horizon in
    /// [protocol.md](../../../docs/protocol.md): the owner has asserted the
    /// entry is reclaimed and can never retry that message ID, so the journal
    /// stops paying for it.  The caller records the stream ID as retired, and
    /// the retired record — not the released entry — refuses a late retry and
    /// absorbs a repeated `STREAM_FORGET`.
    ///
    /// Returns the number of released entries.
    fn release_matching(&mut self, stream_id: u64, operation_id: &str) -> usize {
        let matching = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.stream_id == stream_id && entry.operation_id == operation_id)
            .map(|(message_id, _)| message_id.clone())
            .collect::<Vec<_>>();
        let mut released = 0;
        for message_id in matching {
            let Some(entry) = self.entries.remove(&message_id) else {
                continue;
            };
            self.used_bytes = self
                .used_bytes
                .saturating_sub(entry.request_bytes)
                .saturating_sub(entry.response_bytes);
            if matches!(&entry.state, OpenJournalState::Tombstone) {
                self.tombstones = self.tombstones.saturating_sub(1);
            } else {
                self.active_entries = self.active_entries.saturating_sub(1);
            }
            released += 1;
        }
        released
    }

    fn entry_count(&self) -> usize {
        self.entries.len()
    }

    fn stream_message_is_reserved_by_other(&self, stream_id: u64, message_id: &str) -> bool {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.stream_id == stream_id)
            .min_by_key(|(_, entry)| entry.receive_ordinal)
            .is_some_and(|(first_message_id, _)| first_message_id != message_id)
    }

    fn retained_operation_matches(&self, stream_id: u64, operation_id: &str) -> Option<bool> {
        let mut found = false;
        for entry in self.entries.values() {
            if entry.stream_id == stream_id && !matches!(&entry.state, OpenJournalState::Tombstone)
            {
                found = true;
                if entry.operation_id == operation_id {
                    return Some(true);
                }
            }
        }
        found.then_some(false)
    }

    #[cfg(test)]
    fn used_bytes(&self) -> usize {
        self.used_bytes
    }
}

/// The session's monotonic record of stream IDs whose OPEN state has been
/// reclaimed: either the owner's `STREAM_FORGET` completed its barriers, or
/// the connector refused the request without journaling it because retention
/// was exhausted.  Its job is the second case, which the `forgotten_stream_through`
/// watermark cannot cover: nothing was ever forgotten for those IDs, so they
/// can sit above the watermark.  A later `STREAM_FORGET` naming one of them,
/// or naming anything at or below the watermark, is benign; one naming an
/// unretained ID above the watermark stays the protocol error it is.
///
/// IDs are kept as sorted, disjoint, non-adjacent inclusive ranges.  The
/// range count is bounded by coalescing the lowest gap, not by an invariant:
/// a gap can be an ID the owner allocated but never named in an OPEN or a
/// STREAM_FORGET (a failed control encode, or a full control queue), so
/// sustained control-queue pressure can open more gaps than retained entries.
/// Coalescing is counted, and is safe in both directions: it can only make
/// the record more permissive about an ID it never saw, never less, it never
/// makes an ID admissible, and every ID it absorbs lies below the watermark
/// and is therefore already benign for reclamation.
#[derive(Debug, Default)]
struct RetiredStreamIds {
    ranges: Vec<(u64, u64)>,
    coalesced_gaps: u64,
}

impl RetiredStreamIds {
    fn contains(&self, stream_id: u64) -> bool {
        self.ranges
            .binary_search_by(|range| {
                if range.1 < stream_id {
                    std::cmp::Ordering::Less
                } else if range.0 > stream_id {
                    std::cmp::Ordering::Greater
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    fn insert(&mut self, stream_id: u64) {
        let position = self.ranges.binary_search_by(|range| {
            if range.1.saturating_add(1) < stream_id {
                std::cmp::Ordering::Less
            } else if range.0.saturating_sub(1) > stream_id {
                std::cmp::Ordering::Greater
            } else {
                // Contains `stream_id` or is adjacent to it.
                std::cmp::Ordering::Equal
            }
        });
        match position {
            Ok(index) => {
                let range = &mut self.ranges[index];
                range.0 = range.0.min(stream_id);
                range.1 = range.1.max(stream_id);
                // One insert can bridge at most one neighbour on each side.
                if index + 1 < self.ranges.len()
                    && self.ranges[index].1.saturating_add(1) >= self.ranges[index + 1].0
                {
                    let next = self.ranges.remove(index + 1);
                    self.ranges[index].1 = self.ranges[index].1.max(next.1);
                }
                if index > 0 && self.ranges[index - 1].1.saturating_add(1) >= self.ranges[index].0 {
                    let current = self.ranges.remove(index);
                    self.ranges[index - 1].1 = self.ranges[index - 1].1.max(current.1);
                }
            }
            Err(index) => self.ranges.insert(index, (stream_id, stream_id)),
        }
        while self.ranges.len() > M2_RETIRED_STREAM_RANGES {
            let absorbed = self.ranges.remove(1);
            self.ranges[0].1 = self.ranges[0].1.max(absorbed.1);
            self.coalesced_gaps = self.coalesced_gaps.saturating_add(1);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.ranges.len()
    }

    /// The number of retired IDs, saturating.  Diagnostics only.
    fn retired_count(&self) -> u64 {
        self.ranges.iter().fold(0_u64, |total, range| {
            total.saturating_add(range.1.saturating_sub(range.0).saturating_add(1))
        })
    }
}

/// A refresh challenge prepared before the bounded control writer had room.
/// The challenge and its absolute deadline are retained so a retry neither
/// refreshes the authorization window nor marks a stream in-flight before its
/// challenge is actually queued.
#[derive(Debug)]
struct PendingAuthorizationRefresh {
    challenge: AuthorizationChallenge,
    auth_deadline: DualDeadline,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PendingCarrierControl {
    acknowledged: Option<u64>,
    released_window_bytes: usize,
    window_limit: Option<u64>,
}

#[derive(Clone, Debug)]
struct PendingStreamForget {
    forget: tunnel_protocol::rotation_control::StreamForget,
    carriers: Vec<CarrierKey>,
    barriers_queued: BTreeSet<CarrierKey>,
    barriers_completed: BTreeSet<CarrierKey>,
    /// The owner control message may arrive before the independent data
    /// carrier delivers the final ACK. While this is set, late ACK/control
    /// progress remains processable. The full proof is revalidated before
    /// removal and expires at this absolute deadline if channels never
    /// converge.
    proof_pending: bool,
    proof_deadline: Option<Instant>,
    /// A FORGET received after QUIESCE must remain in the immutable roster
    /// until the rotation returns to Active.  The stream can drain its
    /// carriers now, but reclamation waits for the roster reference to end.
    defer_reclamation: bool,
}

impl PendingCarrierControl {
    fn record_ack(&mut self, acknowledged: u64) {
        self.acknowledged = Some(
            self.acknowledged
                .map_or(acknowledged, |current| current.max(acknowledged)),
        );
    }

    fn record_window(&mut self, released_bytes: usize) -> Result<(), ClientError> {
        self.released_window_bytes = self
            .released_window_bytes
            .checked_add(released_bytes)
            .ok_or_else(|| ClientError::Protocol("receive byte counter exhausted".to_owned()))?;
        Ok(())
    }

    fn record_window_limit(&mut self, limit: u64) {
        self.window_limit = Some(
            self.window_limit
                .map_or(limit, |current| current.max(limit)),
        );
    }

    const fn is_empty(self) -> bool {
        self.acknowledged.is_none()
            && self.released_window_bytes == 0
            && self.window_limit.is_none()
    }
}

fn has_pending_output_for_stream(
    pending_outputs: &VecDeque<PendingOutput>,
    stream_id: u64,
) -> bool {
    pending_outputs
        .iter()
        .any(|output| output.stream_id == stream_id)
}

fn should_ack_incoming_frame(kind: FrameKind) -> bool {
    matches!(kind, FrameKind::Data | FrameKind::Fin | FrameKind::Reset)
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
    /// Present for a raw bidirectional stream — `http-forward/1` or a
    /// filesystem 9P session; see `m2_http`.
    http: Option<DeviceHttpState>,
    /// Present only for a filesystem stream: the live authorization the
    /// provider reads before every host call.
    ///
    /// The connector confirms and invalidates it from the same places it moves
    /// `auth` below, so the provider's recheck after a queue wait sees exactly
    /// what the actor sees, without the provider ever holding the actor's lock
    /// or caching a decision.
    fs_authority: Option<std::sync::Arc<crate::fs_export::StreamAuthority>>,
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

/// Whether a new output of `kind` must be suppressed because the connector
/// already ended its direction.  Only an HTTP stream's RESET may follow its
/// FIN.
fn output_blocked(stream: &M2Stream, kind: FrameKind) -> bool {
    if stream.is_http() && kind == FrameKind::Reset {
        stream.output_reset
    } else {
        stream.terminal()
    }
}

fn queue_reset_once(stream: &mut M2Stream) -> bool {
    // An HTTP response may complete (FIN) before its upload is aborted; the
    // protocol lets RESET follow FIN solely to reset the stream.
    let terminal = if stream.is_http() {
        stream.output_reset
    } else {
        stream.terminal()
    };
    if terminal || stream.reset_queued {
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
    owner_fence: Option<OwnerFenceState>,
    rotation: RotationState,
    control_queue: OutboundQueue,
    pending_critical_controls: VecDeque<PendingCriticalControl>,
    pending_critical_control_bytes: usize,
    data_budget: Arc<QueueBudget>,
    events: mpsc::Sender<ActorEvent>,
    /// Registered in-process HTTP exports and their diagnostics.
    http_handlers: HttpHandlers,
    /// Bounded request channel from HTTP exchange tasks to this actor.
    http_requests: mpsc::Sender<HttpActorRequest>,
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
    /// The first active-carrier terminal event that started this recovery
    /// episode.  It is retained until verified activation so a later
    /// retained-recovery failure can explain the original data-loss trigger.
    first_recovery_trigger: Option<RecoveryTrigger>,
    /// Physical IDs released by RotationState during the current recovery
    /// episode. Closure evidence remains in `closed_for_recovery` for late
    /// event fencing, while this set prevents a later attempt from trying to
    /// release an already released historical carrier again.
    released_recovery_connections: BTreeSet<String>,
    /// The last recovery reset that crossed the fenced successor activation
    /// boundary.  This is retained as bounded identity metadata for the CLI
    /// status stream; it is cleared when a new recovery episode begins.
    last_recovery_reset_reason: Option<&'static str>,
    last_recovery_successor: Option<RotationAttemptIdentity>,
    /// Retain only the last bounded attempt timing after a verified reset so
    /// a coalesced watch stream still carries terminal recovery metadata.
    last_recovery_attempt: Option<u64>,
    last_recovery_attempt_started_at_ms: Option<u64>,
    last_recovery_attempt_deadline_ms: Option<u64>,
    closed_for_recovery: BTreeMap<String, ClosureEvidence>,
    streams: BTreeMap<u64, M2Stream>,
    open_journal: OpenJournal,
    // Parsed deferred OPEN trees are charged in a separate pool from the
    // canonical wire journal and released by their owned reservation token.
    pending_open_budget: Arc<QueueBudget>,
    pending_open: Option<PendingOpen>,
    // The head is retried atomically; later OPENs retain their receive-time
    // operation deadlines in FIFO order and are bounded by max_streams.
    pending_open_queue: VecDeque<PendingOpen>,
    // At most one prepared refresh exists per admitted stream, so this map is
    // bounded by the configured stream cap and cannot retain an unbounded
    // control burst.
    pending_authorization_refreshes: BTreeMap<u64, PendingAuthorizationRefresh>,
    accepting: bool,
    writes_frozen: bool,
    /// Streams ended because their operation authorization lapsed.
    auth_expired_streams: u64,
    /// Every `expire_stream` call, for the M6-C88 regression test.
    #[cfg(test)]
    expire_stream_calls: u64,
    pending_outputs: VecDeque<PendingOutput>,
    pending_output_bytes: usize,
    peer_fence: Option<FenceSnapshot>,
    local_fence: Option<FenceSnapshot>,
    sent_drain_proof: bool,
    pending_quiesce: Option<RotateQuiesce>,
    barrier_queued: bool,
    pending_retire: Option<RotateRetire>,
    pending_pongs: BTreeMap<CarrierKey, Message>,
    pending_forgets: BTreeMap<u64, PendingStreamForget>,
    /// Highest terminal stream ID whose carrier barriers have completed.
    /// Relay stream IDs are allocated monotonically for a session, so this
    /// scalar keeps late frames from forgotten streams from creating an
    /// unknown-stream RESET without retaining an unbounded tombstone set.
    forgotten_stream_through: u64,
    /// Stream IDs whose OPEN journal state the session has reclaimed at the
    /// OPEN retry horizon, or refused without journaling.  A `STREAM_FORGET`
    /// naming one of these is benign; one naming an ID that was never here
    /// stays a protocol error.
    retired_streams: RetiredStreamIds,
    peer_fence_message_id: Option<String>,
    rotation_started: Instant,
    rotations_completed: u64,
    /// The filesystem mutation ledger, summed over completed exchanges.
    ///
    /// Folded in at `HttpActorRequest::Done`, which is the one place a
    /// filesystem exchange's own counters reach the actor, and published in
    /// every status snapshot from there on.
    fs_counters: crate::FsCounters,
    status: watch::Sender<ConnectionStatus>,
    cancellation: CancellationToken,
    control_local_addr: Option<std::net::SocketAddr>,
}

struct PendingCriticalControl {
    message: Message,
    deadline: DualDeadline,
    bytes: usize,
}

#[allow(clippy::too_many_arguments)]
async fn run_m2_session(
    config: RuntimeConfig,
    session: SessionInfo,
    welcome: tunnel_protocol::Welcome,
    owner_id: String,
    owner_fence: Option<OwnerFenceState>,
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
    test_writer_gate: Option<super::WriterTestGate>,
    http_handlers: HttpHandlers,
) -> Result<(), ClientError> {
    let (events_tx, mut events_rx) = mpsc::channel(M2_EVENT_CAPACITY);
    // Each HTTP exchange task holds at most one outstanding request.
    let (http_requests_tx, mut http_requests_rx) =
        mpsc::channel(config.limits.max_streams.max(1).saturating_mul(2));
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
        test_writer_gate,
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
    let open_journal = OpenJournal::new(
        retained_stream_limit(config.limits.max_streams).max(1),
        config.limits.max_queue_bytes.min(MAX_JOURNAL_BYTES),
    );
    let pending_open_budget = Arc::new(QueueBudget {
        bytes: std::sync::atomic::AtomicUsize::new(0),
        maximum: pending_open_budget_max(config.limits.max_streams, config.limits.max_queue_bytes),
    });
    let mut actor = M2Actor {
        config,
        session,
        owner_id,
        owner_fence,
        rotation,
        control_queue,
        pending_critical_controls: VecDeque::new(),
        pending_critical_control_bytes: 0,
        data_budget,
        events: events_tx.clone(),
        http_handlers,
        http_requests: http_requests_tx,
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
        first_recovery_trigger: None,
        released_recovery_connections: BTreeSet::new(),
        last_recovery_reset_reason: None,
        last_recovery_successor: None,
        last_recovery_attempt: None,
        last_recovery_attempt_started_at_ms: None,
        last_recovery_attempt_deadline_ms: None,
        closed_for_recovery: BTreeMap::new(),
        streams: BTreeMap::new(),
        open_journal,
        pending_open_budget,
        pending_open: None,
        pending_open_queue: VecDeque::new(),
        pending_authorization_refreshes: BTreeMap::new(),
        accepting: true,
        writes_frozen: false,
        auth_expired_streams: 0,
        #[cfg(test)]
        expire_stream_calls: 0,
        pending_outputs: VecDeque::new(),
        pending_output_bytes: 0,
        peer_fence: None,
        local_fence: None,
        sent_drain_proof: false,
        pending_quiesce: None,
        barrier_queued: false,
        pending_retire: None,
        pending_pongs: BTreeMap::new(),
        pending_forgets: BTreeMap::new(),
        forgotten_stream_through: 0,
        retired_streams: RetiredStreamIds::default(),
        peer_fence_message_id: None,
        rotation_started: Instant::now(),
        rotations_completed: 0,
        fs_counters: crate::FsCounters::default(),
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
                if let Err(error) = actor.flush_pending_open() {
                    break Err(error);
                }
                if let Err(error) = actor.flush_pending_critical_controls() {
                    break Err(error);
                }
                if let Err(error) = actor.flush_pending_pongs() {
                    break Err(error);
                }
                if let Err(error) = actor.flush_pending_carrier_controls() {
                    break Err(error);
                }
                if let Err(error) = actor.flush_pending_outputs().await {
                    break Err(error);
                }
                if let Err(error) = actor.retry_all_http_parked().await {
                    break Err(error);
                }
                if let Err(error) = actor.apply_pending_quiesce() {
                    break Err(error);
                }
                if actor.pending_open.is_none()
                    && let Err(error) = actor.retry_pending_retire().await
                {
                    break Err(error);
                }
                if let Err(error) = actor.retry_pending_forget_barriers() {
                    break Err(error);
                }
                // A deferred OPEN retains its own pair and deadline, while
                // maintenance and inbound critical controls continue to make
                // bounded progress. Refresh admission handles queue pressure
                // without changing a stream's authorization state early.
                if let Err(error) = actor.refresh_authorizations().await {
                    break Err(error);
                }
                if let Err(error) = actor.handle_rotation_deadline().await {
                    break Err(error);
                }
            }
            control = control_stream.next() => {
                if let Err(error) = actor.flush_pending_open() {
                    break Err(error);
                }
                if let Err(error) = actor.flush_pending_critical_controls() {
                    break Err(error);
                }
                match control {
                    Some(Ok(message)) => {
                        if let Err(error) = actor.handle_control_message(message).await {
                            break Err(error);
                        }
                    }
                    Some(Err(error)) => break Err(actor.control_lost_error(sanitize_error(&error.to_string()))),
                    None => break Err(actor.control_lost_error("control socket closed".to_owned())),
                }
            }
            Some(request) = http_requests_rx.recv() => {
                if let Err(error) = actor.handle_http_request(request).await {
                    break Err(error);
                }
            }
            event = events_rx.recv() => {
                let Some(event) = event else { break Err(ClientError::Transport { scope: "data actor", detail: "event channel closed".to_owned() }); };
                if let Err(error) = actor.handle_event(event).await {
                    break Err(error);
                }
            }
        }
        // HTTP exchanges' progress clocks pause for exactly the writer
        // freeze this event may have started or ended.
        actor.publish_http_freeze();
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
        pending_controls: BTreeMap::new(),
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

    fn carrier_role(&self, key: &CarrierKey) -> CarrierRole {
        if self.active.key == *key {
            return CarrierRole::Active;
        }
        if self
            .candidate
            .as_ref()
            .is_some_and(|carrier| carrier.key == *key)
        {
            return CarrierRole::Candidate;
        }
        if self
            .retiring
            .as_ref()
            .is_some_and(|carrier| carrier.key == *key)
        {
            return CarrierRole::Retiring;
        }
        if self.pending_candidate.as_ref().is_some_and(|pending| {
            pending.attempt.new_generation == key.generation
                && pending.attempt.new_connection_id == key.connection_id
        }) {
            return CarrierRole::PendingCandidate;
        }
        if self
            .pending_candidate_close
            .as_ref()
            .is_some_and(|(attempt, _)| {
                attempt.new_generation == key.generation
                    && attempt.new_connection_id == key.connection_id
            })
        {
            return CarrierRole::PendingCandidateClose;
        }
        if self.closed_for_recovery.contains_key(&key.connection_id) {
            return CarrierRole::RecoveryClosed;
        }
        CarrierRole::Unknown
    }

    /// Record only the first active-carrier terminal event while the session
    /// is still healthy.  Candidate/retiring events belong to a rotation
    /// attempt and must never be reported as the cause of a later recovery.
    fn remember_recovery_trigger(&mut self, class: RecoveryTriggerClass, key: &CarrierKey) {
        if self.first_recovery_trigger.is_some()
            || self.recovery_requested
            || self.recovery.is_some()
            || self.rotation.phase() != RotationPhase::Active
        {
            return;
        }
        let role = self.carrier_role(key);
        if role != CarrierRole::Active {
            return;
        }
        self.first_recovery_trigger = Some(RecoveryTrigger {
            class,
            role,
            generation: key.generation,
        });
    }

    fn retained_recovery_detail(&self, detail: &str) -> String {
        self.first_recovery_trigger
            .map_or_else(|| detail.to_owned(), |trigger| trigger.append_to(detail))
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
                .saturating_add(stream.record_buffer.len())
                .saturating_add(
                    stream
                        .http
                        .as_ref()
                        .map_or(0, DeviceHttpState::retained_bytes),
                );
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

    fn ensure_bulk_retained_capacity(&self, additional: usize) -> Result<(), ClientError> {
        self.ensure_retained_capacity_with_reserve(additional, true)
    }

    fn ensure_retained_capacity_with_reserve(
        &self,
        additional: usize,
        preserve_critical_bytes: bool,
    ) -> Result<(), ClientError> {
        let reserved = if preserve_critical_bytes {
            critical_reserved_bytes(self.config.limits.max_queue_bytes)
        } else {
            0
        };
        let maximum = self.config.limits.max_queue_bytes.saturating_sub(reserved);
        if self
            .aggregate_retained_bytes()
            .checked_add(additional)
            .is_none_or(|total| total > maximum)
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
                detail: self.retained_recovery_detail("recovery candidate phase deadline expired"),
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
                    detail: self.retained_recovery_detail("recovery episode deadline expired"),
                });
            }
            RotationPhase::Retiring
                if self.retiring.is_some() && self.rotation.status().deadline_forced_retirement =>
            {
                // protocol.md, absolute overlap deadline: "after commit,
                // forcibly close any old transport still lingering".  The
                // machine records the forced retirement without leaving
                // `Retiring`; the connector releases its own half here rather
                // than waiting for the owner's forced COMPLETE.  The carrier
                // guard makes this arm fire exactly once per attempt.
                self.force_retire_at_overlap_deadline().await?;
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
        let recovery_attempt = self
            .recovery
            .as_ref()
            .map(|recovery| recovery.begin.attempt_no)
            .or(self.last_recovery_attempt);
        // These timestamps come directly from RotationState::status().  The
        // state machine caps every recovery attempt with the immutable
        // episode deadline, so diagnostics can measure observed spacing
        // without mirroring a documented delay constant.
        let recovery_attempt_started_at_ms = self
            .recovery
            .as_ref()
            .and(rotation_status.started_at_ms)
            .or(self.last_recovery_attempt_started_at_ms);
        let recovery_attempt_deadline_ms = self
            .recovery
            .as_ref()
            .and(rotation_status.deadline_ms)
            .or(self.last_recovery_attempt_deadline_ms);
        let recovery_episode_deadline_ms = self
            .recovery
            .as_ref()
            .map(|recovery| recovery.deadline_ms)
            .or_else(|| {
                self.completed_recovery
                    .as_ref()
                    .map(|recovery| recovery.deadline_ms)
            });
        let recovery_closed_connection_ids = self
            .recovery
            .as_ref()
            .map(|recovery| recovery.local_closed.closed_connection_ids.clone())
            .or_else(|| {
                self.completed_recovery
                    .as_ref()
                    .map(|recovery| recovery.local_closed.closed_connection_ids.clone())
            })
            .unwrap_or_default();
        let recovery_identity = self
            .recovery
            .as_ref()
            .map(|recovery| recovery.begin.attempt.clone())
            .or_else(|| self.last_recovery_successor.clone());
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
            open_journal_entries: self.open_journal.entry_count(),
            open_streams_retired: self.retired_streams.retired_count(),
            open_retired_ranges_coalesced: self.retired_streams.coalesced_gaps,
            emitted_sequences: emitted,
            received_sequences: received,
            stream_auth: crate::StreamAuthCounters {
                unconfirmed_streams: self
                    .streams
                    .values()
                    .filter(|stream| !stream.auth.confirmed)
                    .count(),
                refreshes_in_flight: self
                    .streams
                    .values()
                    .filter(|stream| stream.auth.refresh_in_flight)
                    .count(),
                buffered_inputs: self
                    .streams
                    .values()
                    .map(|stream| stream.pending.len())
                    .sum(),
                expired_streams: self.auth_expired_streams,
            },
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
            fs: self.fs_counters,
            recovery_attempt,
            recovery_attempt_started_at_ms,
            recovery_attempt_deadline_ms,
            recovery_episode_deadline_ms,
            recovery_closed_connection_ids,
            recovery_reset_reason: self.last_recovery_reset_reason,
            recovery_old_generation: recovery_identity
                .as_ref()
                .map(|attempt| attempt.old_generation),
            recovery_old_connection_id: recovery_identity
                .as_ref()
                .map(|attempt| attempt.old_connection_id.clone()),
            recovery_successor_generation: recovery_identity
                .as_ref()
                .map(|attempt| attempt.new_generation),
            recovery_successor_connection_id: recovery_identity
                .as_ref()
                .map(|attempt| attempt.new_connection_id.clone()),
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

    fn encode_control_message(message: &ControlMessage) -> Result<Message, ClientError> {
        let bytes =
            encode_control(message).map_err(|error| ClientError::Protocol(error.to_string()))?;
        let text = String::from_utf8(bytes).map_err(|_| {
            ClientError::Protocol("control codec produced non-UTF-8 JSON".to_owned())
        })?;
        Ok(Message::Text(text.into()))
    }

    fn send_control(
        &self,
        message: ControlMessage,
        deadline: Option<DualDeadline>,
    ) -> Result<(), ClientError> {
        // Preserve the response order established by a deferred OPEN or a
        // previously spilled critical response. Callers that already have a
        // bounded retry path (notably authorization refresh) convert this
        // queue-full result into their retained state.
        if self.pending_open.is_some() || !self.pending_critical_controls.is_empty() {
            return Err(ClientError::QueueLimit);
        }
        self.control_queue
            .try_send_with_deadline(Self::encode_control_message(&message)?, deadline)
    }

    fn critical_control_deadline(&self) -> Result<DualDeadline, ClientError> {
        DualDeadline::new(
            Instant::now(),
            SystemTime::now(),
            M2_CRITICAL_CONTROL_TIMEOUT,
        )
        .ok_or_else(|| ClientError::Protocol("critical control deadline overflow".to_owned()))
    }

    /// Queue a response that must remain ordered behind a deferred OPEN. The
    /// writer queue stays fixed at its configured bound; only a bounded,
    /// byte-accounted spill is retained while the atomic OPEN pair waits for
    /// two permits. A full spill still fails closed instead of growing with
    /// inbound control traffic. Every spilled response has an absolute
    /// fallback deadline, including responses whose caller did not already
    /// carry an authorization deadline.
    fn send_critical_control(
        &mut self,
        message: ControlMessage,
        deadline: Option<DualDeadline>,
    ) -> Result<(), ClientError> {
        self.send_critical_message(Self::encode_control_message(&message)?, deadline)
    }

    fn send_critical_message(
        &mut self,
        encoded: Message,
        deadline: Option<DualDeadline>,
    ) -> Result<(), ClientError> {
        if self.pending_open.is_some() || !self.pending_critical_controls.is_empty() {
            let deadline = match deadline {
                Some(deadline) => deadline,
                None => self.critical_control_deadline()?,
            };
            return self.defer_critical_control(encoded, deadline);
        }
        match self
            .control_queue
            .try_send_with_deadline(encoded.clone(), deadline)
        {
            Ok(()) => Ok(()),
            Err(ClientError::QueueLimit) => {
                let deadline = match deadline {
                    Some(deadline) => deadline,
                    None => self.critical_control_deadline()?,
                };
                self.defer_critical_control(encoded, deadline)
            }
            Err(error) => Err(error),
        }
    }

    fn defer_critical_control(
        &mut self,
        message: Message,
        deadline: DualDeadline,
    ) -> Result<(), ClientError> {
        let bytes = super::message_size(&message);
        if self.pending_critical_controls.len() >= M2_PENDING_CRITICAL_CONTROL_FRAMES
            || self
                .pending_critical_control_bytes
                .checked_add(bytes)
                .is_none_or(|total| total > M2_PENDING_CRITICAL_CONTROL_BYTES)
        {
            return Err(ClientError::QueueLimit);
        }
        self.pending_critical_control_bytes =
            self.pending_critical_control_bytes.saturating_add(bytes);
        self.pending_critical_controls
            .push_back(PendingCriticalControl {
                message,
                deadline,
                bytes,
            });
        Ok(())
    }

    fn open_response_bytes(responses: &[Message]) -> Result<usize, ClientError> {
        responses.iter().try_fold(0_usize, |total, response| {
            total
                .checked_add(M2_OPEN_JOURNAL_RESPONSE_OVERHEAD)
                .and_then(|value| value.checked_add(super::message_size(response)))
                .ok_or(ClientError::QueueLimit)
        })
    }

    fn complete_open_journal(
        &mut self,
        request_id: &str,
        responses: Vec<Message>,
        deadlines: Vec<Option<DualDeadline>>,
    ) -> Result<(), ClientError> {
        let response_bytes = match Self::open_response_bytes(&responses) {
            Ok(response_bytes) => response_bytes,
            Err(ClientError::QueueLimit) => {
                return Err(self.open_retention_failure(request_id));
            }
            Err(error) => return Err(error),
        };
        match self
            .open_journal
            .complete(request_id, responses, deadlines, response_bytes)
        {
            Ok(()) => Ok(()),
            Err(OpenJournalError::Capacity | OpenJournalError::TombstoneCapacity) => {
                Err(self.open_retention_failure(request_id))
            }
            Err(
                OpenJournalError::ConflictingMessage
                | OpenJournalError::MissingMessage
                | OpenJournalError::ConflictingResponse,
            ) => Err(ClientError::Protocol(
                "OPEN journal completion changed after response admission".to_owned(),
            )),
        }
    }

    fn open_retention_failure(&mut self, request_id: &str) -> ClientError {
        match self.open_journal.compact(request_id) {
            Ok(()) => ClientError::OpenRetentionFull,
            Err(_) => ClientError::Protocol("OPEN journal retention transition failed".to_owned()),
        }
    }

    fn replay_open_responses(
        &mut self,
        responses: Vec<Message>,
        deadlines: Vec<Option<DualDeadline>>,
    ) -> Result<(), ClientError> {
        if responses.len() != 1 || deadlines.len() != 1 {
            return Err(ClientError::Protocol(
                "OPEN journal retained an invalid completed response".to_owned(),
            ));
        }
        let response = responses
            .into_iter()
            .next()
            .expect("one response was checked above");
        self.send_critical_message(response, deadlines[0])
    }

    /// Inspect deferred critical controls for expiry even while a pending OPEN
    /// remains the head. Enqueue them only after that atomic pair is admitted,
    /// preserving inbound response order and preventing one-slot
    /// PONG/rotation replies from starving the two-slot OPEN reservation;
    /// expired spill is reported as a bounded control failure rather than
    /// being reported as delivered.
    fn flush_pending_critical_controls(&mut self) -> Result<(), ClientError> {
        loop {
            if self
                .pending_critical_controls
                .front()
                .is_some_and(|pending| pending.deadline.expired())
            {
                let pending = self
                    .pending_critical_controls
                    .pop_front()
                    .expect("critical spill front was checked above");
                self.pending_critical_control_bytes = self
                    .pending_critical_control_bytes
                    .saturating_sub(pending.bytes);
                return Err(ClientError::Transport {
                    scope: "control response",
                    detail: "critical response deadline expired".to_owned(),
                });
            }
            if self.pending_open.is_some() {
                return Ok(());
            }
            let Some(pending) = self.pending_critical_controls.pop_front() else {
                return Ok(());
            };
            match self
                .control_queue
                .try_send_with_deadline(pending.message.clone(), Some(pending.deadline))
            {
                Ok(()) => {
                    self.pending_critical_control_bytes = self
                        .pending_critical_control_bytes
                        .saturating_sub(pending.bytes);
                }
                Err(ClientError::QueueLimit) => {
                    self.pending_critical_controls.push_front(pending);
                    return Ok(());
                }
                Err(error) => {
                    self.pending_critical_control_bytes = self
                        .pending_critical_control_bytes
                        .saturating_sub(pending.bytes);
                    return Err(error);
                }
            }
        }
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
        self.send_critical_control(response, None)
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
            self.send_critical_control(response, None)?;
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

    fn resend_recovery_reply(&mut self, message: &ControlMessage) -> Result<(), ClientError> {
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
            self.send_critical_control(reply, None)?;
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
            Message::Ping(payload) => self.send_critical_message(Message::Pong(payload), None),
            Message::Pong(_) | Message::Frame(_) => Ok(()),
            Message::Close(_) => Err(self.control_lost_error("control socket closed".to_owned())),
        }
    }

    /// Classify a lost control socket.  Outside recovery it is the generic
    /// control transport failure.  During a retained recovery episode the
    /// coordinator (relay) is the only endpoint that can end the episode,
    /// for example after the last permitted candidate attempt failed, so
    /// the terminal diagnostic must keep the original data-carrier trigger
    /// and the attempt number instead of collapsing into an anonymous
    /// control failure that looks like a fresh abnormal close.
    fn control_lost_error(&self, detail: String) -> ClientError {
        let Some(recovery) = self.recovery.as_ref() else {
            return ClientError::Transport {
                scope: "control read",
                detail,
            };
        };
        let detail =
            self.retained_recovery_detail("control socket closed during retained recovery");
        ClientError::Transport {
            scope: "retained recovery",
            detail: format!("{detail}; recovery_attempt={}", recovery.begin.attempt_no),
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
            ControlMessage::Open(open) => self.handle_open(open),
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
            ControlMessage::OwnerFence(_) | ControlMessage::OwnerFenced(_) => {
                if self.owner_fence.is_some() {
                    Err(ClientError::Protocol(
                        "owner fencing requires a fresh control session".to_owned(),
                    ))
                } else {
                    Err(ClientError::Protocol(
                        "OWNER_FENCE was not negotiated for this session".to_owned(),
                    ))
                }
            }
            ControlMessage::RotateRequest(_) => Err(ClientError::Protocol(
                "connector received an unsolicited ROTATE_REQUEST".to_owned(),
            )),
            // Only the device reports adapter outcomes; the owner never sends
            // RESULT_STATUS to a connector.
            ControlMessage::ResultStatus(_) => Err(ClientError::Protocol(
                "connector received an unsolicited RESULT_STATUS".to_owned(),
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
        let episode_deadline_ms = match previous_deadline {
            Some(deadline) => {
                if now >= deadline {
                    return Err(ClientError::Protocol(
                        "RECOVERY_BEGIN arrived after the retained episode deadline".to_owned(),
                    ));
                }
                // The retained absolute episode deadline is authoritative and
                // is returned unchanged, so a retry's remaining-duration
                // sample can never extend this endpoint's budget; it is
                // clamped here instead of failing the session.  The two
                // endpoints keep independent monotonic clocks, and each
                // attempt's RECOVERY_BEGIN is processed with its own latency
                // -- attempt one is the slowest, because this actor is still
                // releasing the lost carrier's reader/writer tasks while it
                // arrives.  Comparing a later sample against the remaining
                // budget therefore measures latency skew, not a coordinator
                // trying to win more time.  `remaining_ms` is still required
                // to be nonzero and within the protocol recovery bound above,
                // and an already-expired episode still fails closed.
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
        let previous_authenticated_closed_ids = if let Some(existing) = self.recovery.as_ref() {
            if self.rotation.phase() != RotationPhase::Recovering {
                return Err(ClientError::Protocol(
                    "RECOVERY_BEGIN changed an active recovery episode".to_owned(),
                ));
            }
            existing.authenticated_closed_connection_ids.clone()
        } else {
            BTreeSet::new()
        };
        let released_before_begin = self.released_recovery_connections.clone();

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
        for (connection_id, evidence) in &closed {
            if released_before_begin.contains(connection_id) {
                continue;
            }
            self.rotation
                .close_for_recovery(connection_id.clone(), evidence.clone(), self.now_ms())
                .map_err(|error| {
                    ClientError::Protocol(format!("recovery closure rejected: {error}"))
                })?;
            self.released_recovery_connections
                .insert(connection_id.clone());
        }
        let mut closed_connection_ids = closed
            .keys()
            .filter(|connection_id| {
                !previous_authenticated_closed_ids.contains(connection_id.as_str())
            })
            .cloned()
            .collect::<Vec<_>>();
        if closed_connection_ids.len() > 2 {
            return Err(ClientError::Protocol(
                "recovery closure set exceeds the current physical bound".to_owned(),
            ));
        }
        closed_connection_ids.sort();
        // A new episode invalidates the previous reset marker.  The status
        // stream must describe the current attempt until a new fenced
        // successor crosses the activation boundary.
        self.last_recovery_reset_reason = None;
        self.last_recovery_successor = None;
        self.last_recovery_attempt = None;
        self.last_recovery_attempt_started_at_ms = None;
        self.last_recovery_attempt_deadline_ms = None;
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
            authenticated_closed_connection_ids: previous_authenticated_closed_ids,
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
        self.send_critical_control(response.clone(), None)?;
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
        let mut expected_ids = recovery.local_closed.closed_connection_ids.clone();
        expected_ids.sort();
        let mut peer_ids = closed.closed_connection_ids.clone();
        peer_ids.sort();
        if peer_ids != expected_ids
            || expected_ids
                .iter()
                .any(|connection_id| !self.closed_for_recovery.contains_key(connection_id))
        {
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
            recovery
                .authenticated_closed_connection_ids
                .extend(closed.closed_connection_ids.iter().cloned());
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

    fn validate_open_context(&self, open: &Open) -> Result<(), ClientError> {
        if open.session_id != self.session.session_id || open.epoch != self.session.epoch {
            return Err(ClientError::Protocol(
                "OPEN context does not match the authenticated session".to_owned(),
            ));
        }
        Ok(())
    }

    fn reserve_pending_open(&self, open: &Open) -> Result<PendingOpenReservation, ClientError> {
        let bytes = pending_open_retained_bytes(open).ok_or(ClientError::QueueLimit)?;
        self.pending_open_budget.reserve(bytes)?;
        Ok(PendingOpenReservation {
            budget: Arc::clone(&self.pending_open_budget),
            bytes,
        })
    }

    fn prepare_pending_open(
        &self,
        open: Open,
        reservation: PendingOpenReservation,
    ) -> Result<PendingOpen, ClientError> {
        self.validate_open_context(&open)?;
        let started = Instant::now();
        let started_wall = SystemTime::now();
        let operation_deadline = DualDeadline::new(
            started,
            started_wall,
            if open.operation == "echo_stream" {
                Duration::from_secs(24 * 60 * 60)
            } else {
                Duration::from_millis(self.config.limits.operation_timeout_ms)
            },
        )
        .ok_or_else(|| ClientError::Protocol("operation deadline overflow".to_owned()))?;
        Ok(PendingOpen {
            open,
            operation_deadline,
            authorization: None,
            _reservation: reservation,
        })
    }

    fn send_open_rejected_journaled(
        &mut self,
        open: &Open,
        code: &str,
        reason: &str,
    ) -> Result<(), ClientError> {
        let response = ControlMessage::Rejected(Rejected::new(
            message_id(),
            open.message_id.clone(),
            self.session.session_id.clone(),
            self.session.epoch,
            open.stream_id,
            open.operation_id.clone(),
            code,
            reason,
        ));
        let response = Self::encode_control_message(&response)?;
        let response_bytes = match Self::open_response_bytes(std::slice::from_ref(&response)) {
            Ok(response_bytes) => response_bytes,
            Err(ClientError::QueueLimit) => {
                return Err(self.open_retention_failure(&open.message_id));
            }
            Err(error) => return Err(error),
        };
        match self
            .open_journal
            .ensure_response_capacity(&open.message_id, response_bytes)
        {
            Ok(()) => {}
            Err(OpenJournalError::Capacity | OpenJournalError::TombstoneCapacity) => {
                return Err(self.open_retention_failure(&open.message_id));
            }
            Err(
                OpenJournalError::ConflictingMessage
                | OpenJournalError::MissingMessage
                | OpenJournalError::ConflictingResponse,
            ) => {
                return Err(ClientError::Protocol(
                    "OPEN journal rejected its response transition".to_owned(),
                ));
            }
        }
        self.send_critical_message(response.clone(), None)?;
        self.complete_open_journal(&open.message_id, vec![response], vec![None])
    }

    /// Whether this OPEN names a stream ID whose state the session has
    /// already reclaimed and holds nothing for.  The predicate is the
    /// monotonic forgotten-stream watermark, not the retired-stream record:
    /// a stream ID refused before it could be journaled was never forgotten,
    /// and its OPEN stays retryable with its own typed refusal.
    fn open_is_past_retry_horizon(&self, open: &Open) -> bool {
        open.stream_id <= self.forgotten_stream_through
            && !self.streams.contains_key(&open.stream_id)
            && self
                .open_journal
                .retained_operation_matches(open.stream_id, &open.operation_id)
                .is_none()
    }

    fn active_stream_count(&self) -> usize {
        self.streams
            .values()
            .filter(|stream| !stream.terminal())
            .count()
    }

    fn handle_open(&mut self, open: Open) -> Result<(), ClientError> {
        self.validate_open_context(&open)?;
        // Past the OPEN retry horizon this connector holds no entry for the
        // request, so journaling the refusal would retain a fresh entry for a
        // stream the owner has already forgotten and will never forget again:
        // the owner ignores a REJECTED naming a stream it no longer tracks,
        // so nothing would ever release it.  Refuse without journaling, the
        // same shape as the retention-exhausted refusal below.  The journaled
        // STREAM_EXISTS path in `try_admit_open` stays for a stream ID this
        // session still retains, whose own STREAM_FORGET releases it.
        if self.open_is_past_retry_horizon(&open) {
            return self.send_rejected(
                &open,
                "STREAM_EXISTS",
                "stream ID was already forgotten; start a fresh session",
            );
        }
        let canonical = encode_control(&ControlMessage::Open(open.clone()))
            .map_err(|error| ClientError::Protocol(error.to_string()))?;
        let observation = match self.open_journal.observe(
            &open.message_id,
            &canonical,
            open.stream_id,
            &open.operation_id,
        ) {
            Ok(observation) => observation,
            Err(OpenJournalError::ConflictingMessage) => {
                return Err(ClientError::Protocol(
                    "OPEN message ID reused with different contents".to_owned(),
                ));
            }
            Err(OpenJournalError::Capacity | OpenJournalError::TombstoneCapacity) => {
                // This refusal is not journaled, so nothing would answer the
                // owner's later STREAM_FORGET for the stream it allocated.
                // Record the ID as retired: the stream never existed here, so
                // reclaiming it is benign rather than a session-fatal unknown
                // stream.  Admission is untouched, so a retry still receives
                // the same typed refusal while the journal is full.
                self.retired_streams.insert(open.stream_id);
                return self.send_rejected(
                    &open,
                    "RESOURCE_EXHAUSTED",
                    "OPEN idempotency retention is full; start a fresh session",
                );
            }
            Err(OpenJournalError::MissingMessage | OpenJournalError::ConflictingResponse) => {
                return Err(ClientError::Protocol(
                    "OPEN journal observation failed".to_owned(),
                ));
            }
        };
        match observation {
            OpenJournalObservation::PendingDuplicate => return Ok(()),
            OpenJournalObservation::CompletedDuplicate {
                responses,
                deadlines,
            } => return self.replay_open_responses(responses, deadlines),
            OpenJournalObservation::Tombstone => {
                return self.send_rejected(
                    &open,
                    "STALE_REQUEST",
                    "OPEN was already forgotten; start a fresh session",
                );
            }
            OpenJournalObservation::New => {}
        }

        let reservation = match self.reserve_pending_open(&open) {
            Ok(reservation) => reservation,
            Err(ClientError::QueueLimit) => {
                return self.send_open_rejected_journaled(
                    &open,
                    "RESOURCE_EXHAUSTED",
                    "parsed OPEN retention is full; start a fresh session",
                );
            }
            Err(error) => return Err(error),
        };
        let mut pending = self.prepare_pending_open(open, reservation)?;
        let pending_count =
            self.pending_open_queue.len() + if self.pending_open.is_some() { 1 } else { 0 };
        if pending_count > 0 || !self.pending_critical_controls.is_empty() {
            let active_streams = self.active_stream_count();
            let retained_limit = retained_stream_limit(self.config.limits.max_streams);
            if active_streams.saturating_add(pending_count) >= self.config.limits.max_streams
                || self.streams.len().saturating_add(pending_count) >= retained_limit
            {
                return self.send_open_rejected_journaled(
                    &pending.open,
                    "RESOURCE_EXHAUSTED",
                    "bounded OPEN admission is full",
                );
            }
            self.pending_open_queue.push_back(pending);
            return Ok(());
        }
        match self.try_admit_open(&mut pending) {
            Ok(()) => Ok(()),
            Err(ClientError::QueueLimit) => {
                self.pending_open = Some(pending);
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// Retry the one deferred OPEN after the writer has made room. The
    /// operation and first authorization deadlines are retained in the
    /// pending item, so retries cannot extend either bounded lifetime.
    fn flush_pending_open(&mut self) -> Result<(), ClientError> {
        if self.pending_open.is_none() && self.pending_critical_controls.is_empty() {
            self.pending_open = self.pending_open_queue.pop_front();
        }
        let Some(pending) = self.pending_open.take() else {
            return Ok(());
        };
        let mut pending = pending;
        match self.try_admit_open(&mut pending) {
            Ok(()) => Ok(()),
            Err(ClientError::QueueLimit) => {
                self.pending_open = Some(pending);
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// Validate and prepare an OPEN before publishing any state. Both
    /// control responses are reserved atomically; a queue-full result leaves
    /// the actor with neither a visible stream nor a half-written response.
    fn try_admit_open(&mut self, pending: &mut PendingOpen) -> Result<(), ClientError> {
        let open = &pending.open;
        if !self.accepting {
            return self.send_open_rejected_journaled(open, "GOAWAY", "connector is draining");
        }
        if self.active_stream_count() >= self.config.limits.max_streams
            || self.streams.len() >= retained_stream_limit(self.config.limits.max_streams)
        {
            return self.send_open_rejected_journaled(
                open,
                "RESOURCE_EXHAUSTED",
                "stream limit reached",
            );
        }
        let Some(export) = self.config.exports.get(&open.service_id).cloned() else {
            return self.send_open_rejected_journaled(
                open,
                "EXPORT_DENIED",
                "service is not locally allowlisted",
            );
        };
        // An HTTP export needs both the local allowlist entry and a
        // registered in-process handler; the OPEN cannot select anything else.
        let http_export = (export.kind == super::ExportKind::HttpForward
            && open.operation == HTTP_FORWARD_OPERATION)
            .then(|| self.http_handlers.export(&open.service_id).cloned())
            .flatten();
        // A filesystem export needs the local allowlist entry, the operator's
        // own `[exports.<service>.fs]` root, and an OPEN naming the filesystem
        // adapter.  The capabilities the OPEN carries are intersected with the
        // configured ones when the exchange starts, so the relay can narrow
        // this export but never widen it.
        let fs_export = (export.kind == super::ExportKind::Fs
            && open.operation == FS_STREAM_OPERATION)
            .then(|| export.fs.clone())
            .flatten()
            .map(|settings| {
                (
                    crate::fs_export::FsExport {
                        root: settings.root,
                        allowed: tunnel_fs_core::CapabilitySet::from_slice(
                            &settings
                                .capabilities
                                .iter()
                                .filter_map(|name| tunnel_fs_core::Capability::parse(name))
                                .collect::<Vec<_>>(),
                        ),
                        features: crate::fs_export::parse_features(&settings.features),
                        limits: tunnel_fs_provider::default_limits(),
                    },
                    // Narrowed here, not later: the stream's authority holds
                    // this set and the provider rechecks every queued request
                    // against it, so it has to be the **effective** grant and
                    // not the wider one the relay named.
                    crate::fs_export::intersect(
                        crate::fs_export::parse_capabilities(
                            open.metadata
                                .get("fs_capabilities")
                                .map_or("", String::as_str),
                        ),
                        tunnel_fs_core::CapabilitySet::from_slice(
                            &settings
                                .capabilities
                                .iter()
                                .filter_map(|name| tunnel_fs_core::Capability::parse(name))
                                .collect::<Vec<_>>(),
                        ),
                    ),
                )
            });
        let echo = export.kind == super::ExportKind::Echo
            && matches!(open.operation.as_str(), "echo" | "echo_stream");
        if !echo && http_export.is_none() && fs_export.is_none() {
            return self.send_open_rejected_journaled(
                open,
                "OPERATION_DENIED",
                "only the local echo operations are enabled",
            );
        }
        // The first received OPEN reserves a stream ID for the session even
        // when it is rejected or later compacted. Compare its receive ordinal,
        // not the journal's lexicographic message-ID order, so a later queued
        // request cannot displace the original pending head.
        if self.streams.contains_key(&open.stream_id)
            || open.stream_id <= self.forgotten_stream_through
            || self
                .open_journal
                .stream_message_is_reserved_by_other(open.stream_id, &open.message_id)
        {
            return self.send_open_rejected_journaled(
                open,
                "STREAM_EXISTS",
                "stream ID is already active or was already forgotten",
            );
        }
        if pending.operation_deadline.expired() {
            return self.send_open_rejected_journaled(
                open,
                "AUTHORIZATION_EXPIRED",
                "OPEN authorization window expired before admission",
            );
        }
        if pending.authorization.is_none() {
            let started = Instant::now();
            let started_wall = SystemTime::now();
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
            pending.authorization = Some(PendingAuthorization {
                opened_message_id: message_id(),
                challenge_message_id: message_id(),
                challenge_id: message_id(),
                nonce: message_id(),
                permission_digest,
                grant_revision,
                auth_deadline,
            });
        }
        let authorization = pending
            .authorization
            .as_ref()
            .expect("OPEN authorization was prepared above");
        if authorization.auth_deadline.expired() || pending.operation_deadline.expired() {
            return self.send_open_rejected_journaled(
                open,
                "AUTHORIZATION_EXPIRED",
                "OPEN authorization window expired before admission",
            );
        }
        let auth_deadline = authorization.auth_deadline;
        let operation_deadline = pending.operation_deadline;
        let opened = ControlMessage::Opened(Opened::new(
            authorization.opened_message_id.clone(),
            open.message_id.clone(),
            self.session.session_id.clone(),
            self.session.epoch,
            open.stream_id,
            open.operation_id.clone(),
            open.initial_receive_window,
            open.initial_send_window,
        ));
        let challenge = ControlMessage::AuthorizationChallenge(AuthorizationChallenge::new(
            authorization.challenge_message_id.clone(),
            self.session.session_id.clone(),
            self.session.epoch,
            open.stream_id,
            authorization.challenge_id.clone(),
            authorization.nonce.clone(),
            open.service_id.clone(),
            authorization.permission_digest.clone(),
            authorization.grant_revision,
        ));
        let opened_message = Self::encode_control_message(&opened)?;
        let challenge_message = Self::encode_control_message(&challenge)?;
        // The initial challenge is an independent grant-freshness event. Keep
        // only OPENED in the completed OPEN journal so a retry after the
        // stream is confirmed cannot accidentally trigger authorization
        // refresh; the original atomic pair still owns first delivery.
        let response_bytes = match Self::open_response_bytes(std::slice::from_ref(&opened_message))
        {
            Ok(response_bytes) => response_bytes,
            Err(ClientError::QueueLimit) => {
                return Err(self.open_retention_failure(&open.message_id));
            }
            Err(error) => return Err(error),
        };
        match self
            .open_journal
            .ensure_response_capacity(&open.message_id, response_bytes)
        {
            Ok(()) => {}
            Err(OpenJournalError::Capacity | OpenJournalError::TombstoneCapacity) => {
                return Err(self.open_retention_failure(&open.message_id));
            }
            Err(
                OpenJournalError::ConflictingMessage
                | OpenJournalError::MissingMessage
                | OpenJournalError::ConflictingResponse,
            ) => {
                return Err(ClientError::Protocol(
                    "OPEN journal admission changed before response reservation".to_owned(),
                ));
            }
        }
        let initial_credit = open.initial_send_window.min(8 * 1024 * 1024);
        let receive_credit = open.initial_receive_window.min(8 * 1024 * 1024);
        // Partition the one session replay/reorder budget across the maximum
        // number of admitted streams. This keeps the aggregate retained
        // history bounded when several streams are active concurrently; a
        // per-stream default must never multiply the configured memory cap.
        let stream_slots = self.config.limits.max_streams.max(1);
        let replay_bytes = (self.config.limits.max_queue_bytes / stream_slots).max(1);
        let replay_frames = (self.config.limits.max_queue_frames / stream_slots).max(1);
        // An HTTP response is written independently of the request, so its
        // replay and reorder capacity must cover the whole window (the owner
        // acknowledges on receipt); credit alone then parks a write.
        let (replay_bytes, replay_frames) = if http_export.is_some() || fs_export.is_some() {
            let window = usize::try_from(initial_credit.max(receive_credit)).unwrap_or(usize::MAX);
            (
                replay_bytes.max(window),
                replay_frames.max(window.div_ceil(MAX_PAYLOAD_LEN).saturating_add(2)),
            )
        } else {
            (replay_bytes, replay_frames)
        };
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
        let stream = M2Stream {
            export,
            operation_id: open.operation_id.clone(),
            service_id: open.service_id.clone(),
            operation: open.operation.clone(),
            auth: AuthContext {
                challenge_id: authorization.challenge_id.clone(),
                nonce: authorization.nonce.clone(),
                permission_digest: authorization.permission_digest.clone(),
                grant_revision: authorization.grant_revision,
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
            http: None,
            fs_authority: None,
        };
        let mut stream = stream;
        if let Some(http_export) = http_export {
            stream.http = Some(self.start_http_exchange(
                open.stream_id,
                &open.service_id,
                http_export,
                receive_credit,
            ));
        } else if let Some((settings, granted)) = fs_export {
            // The authority the provider reads before every host call.  It is
            // created confirmed, because the OPEN only reaches here after the
            // stream's authorization context was admitted; every later
            // confirmation and every invalidation moves it.
            let authority = std::sync::Arc::new(crate::fs_export::StreamAuthority::new(
                authorization.grant_revision,
                granted,
            ));
            stream.fs_authority = Some(std::sync::Arc::clone(&authority));
            stream.http = Some(self.start_fs_exchange(
                open.stream_id,
                settings,
                granted,
                authority,
                receive_credit,
            ));
        }
        self.control_queue.try_send_pair(
            opened_message.clone(),
            None,
            challenge_message,
            Some(auth_deadline),
        )?;
        self.complete_open_journal(&open.message_id, vec![opened_message], vec![None])?;
        self.streams.insert(open.stream_id, stream);
        self.publish_status();
        Ok(())
    }

    fn send_rejected(&mut self, open: &Open, code: &str, reason: &str) -> Result<(), ClientError> {
        self.send_critical_control(
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
        let candidate_matches = self.candidate.as_ref().is_some_and(|candidate| {
            candidate.key.matches(
                commit.attempt.new_generation,
                &commit.attempt.new_connection_id,
            )
        });
        if !candidate_matches {
            return Err(ClientError::Protocol(
                "ROTATE_COMMIT without matching candidate carrier".to_owned(),
            ));
        }
        // Flush any cumulative ACK/window debt while the old carrier is
        // still active.  If its bounded writer queue is temporarily full,
        // the debt remains attached to the carrier and the timer can finish
        // it after the carrier becomes retiring; it must never migrate to
        // the new generation.  A writer that has already closed is the
        // explicit handoff case: the candidate is still authoritative after
        // commit, and `reissue_active_receive_controls` below sends the
        // cumulative state there.  Other transport failures remain fatal.
        let active_key = self.active.key.clone();
        if let Err(error) = self.flush_pending_carrier_controls_for_key(&active_key)
            && !is_closed_data_writer(&error)
        {
            return Err(error);
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
        let old = std::mem::replace(&mut self.active, candidate);
        self.retiring = Some(old);
        // Reissue absolute receive state on the activated carrier.  The old
        // writer may have accepted a control frame into its bounded queue and
        // then failed before the peer observed it; retiring that carrier
        // without this replay would silently lose credit/ACK progress.
        self.reissue_active_receive_controls()?;
        self.pending_quiesce = None;
        self.barrier_queued = false;
        self.pending_retire = None;
        let can_resume = self.rotation.phase() == RotationPhase::Active;
        // OPEN admission resumes at COMMIT, on the activated carrier, which is
        // when the owner resumes it too: the owner's admission freeze ends at
        // COMMITTED (`rotation_frozen` on the relay excludes `Retiring`, task
        // row M7-C37), and `RotationState::old_socket_closed` records that
        // "payload admission already resumed on the new generation at
        // COMMIT".  `committed()` has just moved the phase to `Retiring`, so
        // gating admission on `Active` (as `can_resume` does) kept it closed
        // until ROTATE_COMPLETE, and an OPEN the owner admitted inside that
        // window was refused `GOAWAY` "connector is draining" -- a
        // `503 DEVICE_REJECTED` for a consumer of a healthy session (task row
        // M7-C97).  The writer resumption below is deliberately unchanged.
        self.accepting = matches!(
            self.rotation.phase(),
            RotationPhase::Active | RotationPhase::Retiring
        );
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
                        // The provider reads this before every host call, so a
                        // renewed confirmation reaches it at the same instant
                        // the actor takes it.
                        if let Some(authority) = stream.fs_authority.as_ref() {
                            authority
                                .confirm(stream.auth.grant_revision, authority.current_grant());
                        }
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
        self.flush_pending_authorization_refreshes(now, wall_now)
            .await?;
        // A stream `expire_stream` already invalidated is not selected again
        // (task row M6-C88): before this, every tick re-ran the expiry for
        // it until the stream was forgotten.
        let expired_ids: Vec<u64> = self
            .streams
            .iter()
            .filter_map(|(&stream_id, stream)| {
                (!stream.auth.invalidated
                    && (stream.auth.deadline.expired_at(now, wall_now)
                        || stream.auth.operation_deadline.expired_at(now, wall_now)))
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
                if !matches!(
                    stream.operation.as_str(),
                    "echo_stream" | HTTP_FORWARD_OPERATION | FS_STREAM_OPERATION
                ) || !stream.auth.confirmed
                    || stream.auth.refresh_in_flight
                    || stream.auth.invalidated
                    || self.http_stream_settled(stream_id)
                    || self
                        .pending_authorization_refreshes
                        .contains_key(&stream_id)
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
            let challenge = AuthorizationChallenge::new(
                message_id(),
                self.session.session_id.clone(),
                self.session.epoch,
                stream_id,
                challenge_id.clone(),
                nonce.clone(),
                service_id,
                permission_digest,
                grant_revision,
            );
            let Some(stream) = self.streams.get(&stream_id) else {
                continue;
            };
            // This must name exactly the operations the selection above
            // names.  A stream selected for refresh and then dropped here has
            // its challenge built and discarded on every tick, so its grant
            // is never renewed and it expires mid-use (docs/tasks.md M4-22).
            if !matches!(
                stream.operation.as_str(),
                "echo_stream" | HTTP_FORWARD_OPERATION | FS_STREAM_OPERATION
            ) || !stream.auth.confirmed
                || stream.auth.refresh_in_flight
                || stream.auth.invalidated
            {
                continue;
            }
            match self.send_control(
                ControlMessage::AuthorizationChallenge(challenge.clone()),
                Some(auth_deadline),
            ) {
                Ok(()) => {
                    let Some(stream) = self.streams.get_mut(&stream_id) else {
                        continue;
                    };
                    stream.auth.challenge_id = challenge_id;
                    stream.auth.nonce = nonce;
                    stream.auth.deadline = auth_deadline;
                    stream.auth.refresh_in_flight = true;
                    stream.auth.confirmed = false;
                }
                Err(ClientError::QueueLimit) => {
                    self.pending_authorization_refreshes.insert(
                        stream_id,
                        PendingAuthorizationRefresh {
                            challenge,
                            auth_deadline,
                        },
                    );
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Retry prepared refreshes in stream order after the writer has drained.
    /// A refresh remains confirmed until its challenge is actually queued, so
    /// queue pressure cannot create a phantom in-flight authorization.
    async fn flush_pending_authorization_refreshes(
        &mut self,
        now: Instant,
        wall_now: SystemTime,
    ) -> Result<(), ClientError> {
        let stream_ids = self
            .pending_authorization_refreshes
            .keys()
            .copied()
            .collect::<Vec<_>>();
        for stream_id in stream_ids {
            let Some(pending) = self.pending_authorization_refreshes.remove(&stream_id) else {
                continue;
            };
            let Some(stream) = self.streams.get(&stream_id) else {
                continue;
            };
            // Same closed operation list as the selection and re-validation
            // in `refresh_authorizations`: a deferred filesystem refresh that
            // is dropped here never reaches the relay (docs/tasks.md M4-22).
            if !matches!(
                stream.operation.as_str(),
                "echo_stream" | HTTP_FORWARD_OPERATION | FS_STREAM_OPERATION
            ) || !stream.auth.confirmed
                || stream.auth.refresh_in_flight
                || stream.auth.invalidated
            {
                continue;
            }
            if stream.auth.deadline.expired_at(now, wall_now)
                || stream.auth.operation_deadline.expired_at(now, wall_now)
                || pending.auth_deadline.expired_at(now, wall_now)
            {
                self.expire_stream(stream_id).await?;
                continue;
            }
            match self.send_control(
                ControlMessage::AuthorizationChallenge(pending.challenge.clone()),
                Some(pending.auth_deadline),
            ) {
                Ok(()) => {
                    let Some(stream) = self.streams.get_mut(&stream_id) else {
                        continue;
                    };
                    stream.auth.challenge_id = pending.challenge.challenge_id;
                    stream.auth.nonce = pending.challenge.nonce;
                    stream.auth.deadline = pending.auth_deadline;
                    stream.auth.refresh_in_flight = true;
                    stream.auth.confirmed = false;
                }
                Err(ClientError::QueueLimit) => {
                    self.pending_authorization_refreshes
                        .insert(stream_id, pending);
                    break;
                }
                Err(error) => return Err(error),
            }
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

    /// Remove deferred OPENs for the operation being forgotten before its
    /// journal entries are released at the OPEN retry horizon.  A pending
    /// OPEN has no stream to validate after the carrier barrier, so leaving
    /// it queued would admit a request for a stream the owner has already
    /// forgotten.  Keep all other operations in their original FIFO order
    /// and deadlines.
    fn remove_pending_open_for_forget(&mut self, stream_id: u64, operation_id: &str) {
        let matches = |pending: &PendingOpen| {
            pending.open.stream_id == stream_id && pending.open.operation_id == operation_id
        };
        if self.pending_open.as_ref().is_some_and(matches) {
            self.pending_open = None;
        }
        self.pending_open_queue.retain(|pending| !matches(pending));
    }

    fn remove_pending_open_for_cancel(&mut self, cancel: &Cancel) -> Result<(), ClientError> {
        let matches = |pending: &PendingOpen| {
            pending.open.stream_id == cancel.stream_id
                && pending.open.operation_id == cancel.operation_id
        };
        let mut removed_message_ids = Vec::new();
        if self.pending_open.as_ref().is_some_and(matches)
            && let Some(pending) = self.pending_open.take()
        {
            removed_message_ids.push(pending.open.message_id);
        }
        self.pending_open_queue.retain(|pending| {
            if matches(pending) {
                removed_message_ids.push(pending.open.message_id.clone());
                false
            } else {
                true
            }
        });
        for message_id in removed_message_ids {
            self.open_journal
                .compact(&message_id)
                .map_err(|error| match error {
                    OpenJournalError::TombstoneCapacity | OpenJournalError::Capacity => {
                        ClientError::QueueLimit
                    }
                    OpenJournalError::ConflictingMessage
                    | OpenJournalError::MissingMessage
                    | OpenJournalError::ConflictingResponse => {
                        ClientError::Protocol("OPEN cancellation journal cleanup failed".to_owned())
                    }
                })?;
        }
        Ok(())
    }

    async fn handle_cancel(&mut self, cancel: Cancel) -> Result<(), ClientError> {
        if cancel.session_id != self.session.session_id || cancel.epoch != self.session.epoch {
            return Err(ClientError::Protocol("CANCEL context mismatch".to_owned()));
        }
        // A deferred OPEN has not created a stream or emitted OPENED yet, so
        // cancellation removes only the matching admission state.  Keep the
        // active-stream path below intact for a reused stream ID, and require
        // the operation ID to match before dropping any pending request.
        self.remove_pending_open_for_cancel(&cancel)?;
        let matches_operation = self.streams.get(&cancel.stream_id).is_some_and(|stream| {
            stream.operation_id == cancel.operation_id
                && self.config.exports.contains_key(&stream.service_id)
        });
        let http_stream = self
            .streams
            .get(&cancel.stream_id)
            .is_some_and(M2Stream::is_http);
        if matches_operation && http_stream {
            // An owner CANCEL for an HTTP stream stops the handler out of
            // band at once.  The bridge then emits the stream's ordered
            // RESET(CANCELLED) with its RESULT_STATUS; only an exchange that
            // already ended needs the RESET here, and a settled exchange
            // (both FINs, the response FIN possibly still deferred) needs
            // none: a RESET after its FIN would trail a stream the owner is
            // already reclaiming, and the owner never acknowledges it.
            if self.http_cancel(cancel.stream_id) && !self.http_stream_settled(cancel.stream_id) {
                self.emit_or_defer(PendingOutput {
                    stream_id: cancel.stream_id,
                    kind: FrameKind::Reset,
                    payload: Vec::new(),
                    reset_reason: Some(tunnel_protocol::reset_reason::CANCELLED),
                })
                .await?;
            }
            return Ok(());
        }
        if matches_operation {
            self.http_abort(cancel.stream_id, tunnel_protocol::reset_reason::CANCELLED);
            let pending_bytes = {
                let stream = self
                    .streams
                    .get_mut(&cancel.stream_id)
                    .expect("operation match checked above");
                stream.input_reset = true;
                stream.auth.invalidated = true;
                if let Some(authority) = stream.fs_authority.as_ref() {
                    authority.invalidate();
                }
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
        // Authenticate before deciding anything, including benignity: a
        // message from another session or a stale epoch is a protocol error
        // whatever stream ID it names.
        if forget.session_id != self.session.session_id || forget.epoch != self.session.epoch {
            return Err(ClientError::Protocol(
                "STREAM_FORGET context mismatch".to_owned(),
            ));
        }
        // A STREAM_FORGET for a stream this session has already reclaimed, for
        // one refused without journaling because its retention was exhausted,
        // or for any ID at or below the forgotten-stream watermark, is benign
        // and idempotent.  The watermark is kept as its own condition because
        // the owner allocates stream IDs monotonically and can consume one
        // without ever naming it in an OPEN, so an ID below the watermark was
        // allocated by this owner in this session even when the connector
        // never saw it.  An ID above the watermark that this session never
        // retained stays the protocol error it is.
        if (self.retired_streams.contains(forget.stream_id)
            || forget.stream_id <= self.forgotten_stream_through)
            && !self.streams.contains_key(&forget.stream_id)
            && self
                .open_journal
                .retained_operation_matches(forget.stream_id, &forget.operation_id)
                .is_none()
        {
            return Ok(());
        }
        if let Some(pending) = self.pending_forgets.get(&forget.stream_id) {
            if pending.forget == forget {
                return Ok(());
            }
            return Err(ClientError::Protocol(
                "STREAM_FORGET changed while carrier barriers were pending".to_owned(),
            ));
        }
        // The control and data sockets are independent. An owner can publish
        // a fully authenticated FORGET after it has observed the peer's
        // terminal/ACK while this connector has not yet observed the final ACK
        // carried by the peer's terminal frame.
        // Keep the final validator strict, but retain this exact message for
        // one bounded revalidation window instead of turning that legal
        // cross-channel ordering into PROTOCOL_ERROR.
        let (proof_pending, proof_deadline) = match self.validate_stream_forget(&forget) {
            Ok(()) => (false, None),
            Err(_error) if self.stream_forget_proof_may_converge(&forget) => (
                true,
                Some(Instant::now() + M2_STREAM_FORGET_REVALIDATION_TIMEOUT),
            ),
            Err(error) => return Err(error),
        };
        let defer_reclamation = !matches!(
            self.rotation.phase(),
            RotationPhase::Active | RotationPhase::Preparing
        );
        let mut carriers = vec![self.active.key.clone()];
        if let Some(candidate) = self.candidate.as_ref() {
            carriers.push(candidate.key.clone());
        }
        if let Some(retiring) = self.retiring.as_ref() {
            carriers.push(retiring.key.clone());
        }
        carriers.sort();
        carriers.dedup();
        self.pending_forgets.insert(
            forget.stream_id,
            PendingStreamForget {
                forget,
                carriers,
                barriers_queued: BTreeSet::new(),
                barriers_completed: BTreeSet::new(),
                proof_pending,
                proof_deadline,
                defer_reclamation,
            },
        );
        self.retry_pending_forget_barriers()?;
        self.publish_status();
        Ok(())
    }

    /// Return whether a failed STREAM_FORGET proof can still become valid from
    /// already authenticated data/control progress. This is intentionally
    /// narrower than accepting arbitrary proof changes: immutable identity and
    /// both terminal directions must already be valid, while only the final
    /// ACK/replay release or bounded carrier-control debt may be pending.
    fn stream_forget_proof_may_converge(
        &self,
        forget: &tunnel_protocol::rotation_control::StreamForget,
    ) -> bool {
        let Some(stream) = self.streams.get(&forget.stream_id) else {
            return false;
        };
        if forget.session_id != self.session.session_id
            || forget.epoch != self.session.epoch
            || stream.operation_id != forget.operation_id
            || forget.final_state.stream_id != forget.stream_id
            || forget.direction != Direction::RelayToConnector
            || (forget.final_state.send_terminal.is_none()
                || forget.final_state.peer_acked != forget.final_state.last_emitted
                || forget.final_state.replay_floor.is_some()
                || forget.final_state.recv_contiguous != 0
                || forget.final_state.delivered_contiguous != 0
                || forget.final_state.received_bytes != 0
                || forget.final_state.receive_terminal.is_some())
            || !self.config.exports.contains_key(&stream.service_id)
        {
            return false;
        }
        // Adapter input debt is a local reclamation invariant, rather than
        // cross-channel progress. Preserve the immediate fail-closed result
        // for this case; only sequence/control evidence may converge here.
        if !stream.pending.is_empty()
            || stream.pending_bytes != 0
            || !stream.record_buffer.is_empty()
            || stream.record_expected.is_some()
            || has_pending_output_for_stream(&self.pending_outputs, forget.stream_id)
        {
            return false;
        }

        let local = stream.sequence.snapshot();
        let owner_sender = direction_snapshot_from_resume(&forget.final_state);
        let local_receiver = local.direction(Direction::RelayToConnector);
        // The owner can only publish this proof after the connector has
        // acknowledged the owner's R2C terminal.  Its receive cursor, byte
        // count, terminal, delivery cursor, and reorder state must therefore
        // already match; deferring missing R2C receipt would accept a proof
        // whose immutable sender evidence is not yet locally represented.
        if owner_sender.last_emitted != local_receiver.recv_contiguous
            || owner_sender.sent_bytes != local_receiver.received_bytes
            || owner_sender.send_terminal != local_receiver.receive_terminal
            || owner_sender.send_terminal_sequence != local_receiver.receive_terminal_sequence
            || owner_sender.receive_credit < local_receiver.send_credit
            || owner_sender.send_credit > local_receiver.receive_credit
            || local_receiver.delivered_contiguous != local_receiver.recv_contiguous
            || local_receiver.reorder_frames != 0
            || local_receiver.reorder_bytes != 0
            || !stream
                .sequence
                .ready_frames(Direction::RelayToConnector)
                .is_empty()
        {
            return false;
        }

        let local_sender = local.direction(Direction::ConnectorToRelay);
        // The connector must already have emitted its own terminal.  Only the
        // relay's final ACK/replay release and bounded carrier debt may still
        // converge on this side of the independent data/control channels.
        if local_sender.send_terminal.is_none()
            || local_sender.send_terminal_sequence != Some(local_sender.last_emitted)
            || local_sender.reorder_frames != 0
            || local_sender.reorder_bytes != 0
            || !stream
                .sequence
                .ready_frames(Direction::ConnectorToRelay)
                .is_empty()
        {
            return false;
        }
        let sender_ack_pending = local_sender.peer_acked < local_sender.last_emitted
            || local_sender.replay_floor.is_some()
            || local_sender.replay_bytes != 0;
        let carrier_work_pending =
            self.active.pending_controls.contains_key(&forget.stream_id)
                || self.candidate.as_ref().is_some_and(|carrier| {
                    carrier.pending_controls.contains_key(&forget.stream_id)
                })
                || self.retiring.as_ref().is_some_and(|carrier| {
                    carrier.pending_controls.contains_key(&forget.stream_id)
                });

        sender_ack_pending || carrier_work_pending
    }

    fn validate_stream_forget(
        &self,
        forget: &tunnel_protocol::rotation_control::StreamForget,
    ) -> Result<(), ClientError> {
        if forget.session_id != self.session.session_id || forget.epoch != self.session.epoch {
            return Err(ClientError::Protocol(
                "STREAM_FORGET context mismatch".to_owned(),
            ));
        }
        let Some(stream) = self.streams.get(&forget.stream_id) else {
            match self
                .open_journal
                .retained_operation_matches(forget.stream_id, &forget.operation_id)
            {
                Some(true) => {}
                Some(false) => {
                    return Err(ClientError::Protocol(
                        "STREAM_FORGET operation identity mismatch".to_owned(),
                    ));
                }
                None => {
                    return Err(ClientError::Protocol(
                        "STREAM_FORGET unknown stream or OPEN journal entry".to_owned(),
                    ));
                }
            }
            if forget.direction != Direction::RelayToConnector
                || forget.final_state != no_stream_forget_state(forget.stream_id)
            {
                return Err(ClientError::Protocol(
                    "STREAM_FORGET no-stream evidence mismatch".to_owned(),
                ));
            }
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
        Self::validate_owner_stream_forget_state(
            &stream.sequence,
            forget.direction,
            &forget.final_state,
        )?;
        if !stream.pending.is_empty()
            || stream.pending_bytes != 0
            || !stream.record_buffer.is_empty()
            || stream.record_expected.is_some()
        {
            return Err(ClientError::Protocol(
                "STREAM_FORGET before local adapter input debt drained".to_owned(),
            ));
        }
        if has_pending_output_for_stream(&self.pending_outputs, forget.stream_id)
            || self.active.pending_controls.contains_key(&forget.stream_id)
            || self
                .candidate
                .as_ref()
                .is_some_and(|carrier| carrier.pending_controls.contains_key(&forget.stream_id))
            || self
                .retiring
                .as_ref()
                .is_some_and(|carrier| carrier.pending_controls.contains_key(&forget.stream_id))
        {
            return Err(ClientError::Protocol(
                "STREAM_FORGET before deferred output and control debt drained".to_owned(),
            ));
        }
        Ok(())
    }

    /// Validate the owner's sender-direction proof against the connector's local
    /// receiver-direction state.  `ResumeDirectionState` is a snapshot from the
    /// relay's perspective: for `RelayToConnector`, its `last_emitted`, sent
    /// bytes, and send terminal must match the connector's receive cursor,
    /// received bytes, and receive terminal.  Comparing the wire value with the
    /// same local direction would compare sender fields with receiver fields and
    /// reject every real terminal exchange.
    fn validate_owner_stream_forget_state(
        sequence: &StreamState,
        direction: Direction,
        final_state: &ResumeDirectionState,
    ) -> Result<(), ClientError> {
        if direction != Direction::RelayToConnector {
            return Err(ClientError::Protocol(
                "STREAM_FORGET owner direction mismatch".to_owned(),
            ));
        }
        if final_state.stream_id != sequence.stream_id()
            || final_state.send_terminal.is_none()
            || final_state.peer_acked != final_state.last_emitted
            || final_state.replay_floor.is_some()
            || final_state.recv_contiguous != 0
            || final_state.delivered_contiguous != 0
            || final_state.received_bytes != 0
            || final_state.receive_terminal.is_some()
        {
            return Err(ClientError::Protocol(
                "STREAM_FORGET owner sender evidence is incomplete".to_owned(),
            ));
        }

        let local = sequence.snapshot();
        let owner_sender = direction_snapshot_from_resume(final_state);
        let local_receiver = local.direction(Direction::RelayToConnector);
        if owner_sender.last_emitted != local_receiver.recv_contiguous
            || owner_sender.sent_bytes != local_receiver.received_bytes
            || owner_sender.send_terminal != local_receiver.receive_terminal
            || owner_sender.send_terminal_sequence != local_receiver.receive_terminal_sequence
            || local_receiver.delivered_contiguous != local_receiver.recv_contiguous
            || local_receiver.reorder_frames != 0
            || local_receiver.reorder_bytes != 0
            || !sequence
                .ready_frames(Direction::RelayToConnector)
                .is_empty()
        {
            return Err(ClientError::Protocol(
                "STREAM_FORGET owner and connector receive evidence mismatch".to_owned(),
            ));
        }

        let local_sender = local.direction(Direction::ConnectorToRelay);
        if local_sender.send_terminal.is_none()
            || local_sender.peer_acked != local_sender.last_emitted
            || local_sender.replay_floor.is_some()
            || local_sender.reorder_frames != 0
            || local_sender.reorder_bytes != 0
            || !sequence
                .ready_frames(Direction::ConnectorToRelay)
                .is_empty()
        {
            return Err(ClientError::Protocol(
                "STREAM_FORGET connector sender evidence is incomplete".to_owned(),
            ));
        }

        // Reconcile the owner proof through the pure sequence validator as well.
        // The wire message carries only the owner's R2C sender direction. The
        // omitted C2R peer snapshot is synthesized from the connector's own
        // fully acknowledged sender state only to exercise local consistency;
        // it is not remote-direction proof. The relay must independently prove
        // its C2R receive terminal and delivery before emitting STREAM_FORGET.
        let opposite = local_sender;
        let peer_opposite = DirectionSnapshot {
            last_emitted: 0,
            peer_acked: 0,
            recv_contiguous: opposite.last_emitted,
            delivered_contiguous: opposite.last_emitted,
            send_credit: opposite.receive_credit,
            sent_bytes: 0,
            receive_credit: opposite.send_credit,
            received_bytes: opposite.sent_bytes,
            send_terminal: None,
            send_terminal_sequence: None,
            receive_terminal: opposite.send_terminal,
            receive_terminal_sequence: opposite.send_terminal_sequence,
            replay_floor: None,
            replay_bytes: 0,
            reorder_frames: 0,
            reorder_bytes: 0,
        };
        let mut peer = local.clone();
        peer.directions[direction_index(Direction::RelayToConnector)] = owner_sender;
        peer.directions[direction_index(Direction::ConnectorToRelay)] = peer_opposite;
        sequence.reconcile(&peer).map_err(|error| {
            ClientError::Protocol(format!("STREAM_FORGET sequence mismatch: {error}"))
        })?;
        Ok(())
    }

    /// Revalidate deferred proofs independently of rotation reclamation. A
    /// stream may become fully proven while QUIESCING or DRAINING still owns
    /// the immutable roster; in that case clear only the proof lease and keep
    /// the physical barriers/tombstone until the phase permits removal.
    fn refresh_pending_forget_proofs(&mut self) -> Result<(), ClientError> {
        let stream_ids = self
            .pending_forgets
            .iter()
            .filter_map(|(&stream_id, pending)| pending.proof_pending.then_some(stream_id))
            .collect::<Vec<_>>();
        let now = Instant::now();
        for stream_id in stream_ids {
            let Some((forget, deadline)) = self
                .pending_forgets
                .get(&stream_id)
                .map(|pending| (pending.forget.clone(), pending.proof_deadline))
            else {
                continue;
            };
            if deadline.is_none_or(|deadline| now >= deadline) {
                return Err(ClientError::Protocol(
                    "STREAM_FORGET terminal proof did not converge before its deadline".to_owned(),
                ));
            }
            match self.validate_stream_forget(&forget) {
                Ok(()) => {
                    if let Some(pending) = self.pending_forgets.get_mut(&stream_id) {
                        pending.proof_pending = false;
                        pending.proof_deadline = None;
                    }
                }
                Err(_) if self.stream_forget_proof_may_converge(&forget) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn retry_pending_forget_barriers(&mut self) -> Result<(), ClientError> {
        self.refresh_pending_forget_proofs()?;
        let stream_ids = self.pending_forgets.keys().copied().collect::<Vec<_>>();
        for stream_id in stream_ids {
            let carriers = self
                .pending_forgets
                .get(&stream_id)
                .map(|pending| pending.carriers.clone())
                .unwrap_or_default();
            for key in carriers {
                if self
                    .pending_forgets
                    .get(&stream_id)
                    .is_some_and(|pending| pending.barriers_queued.contains(&key))
                {
                    continue;
                }
                // A rotation barrier already queued on the active carrier
                // must complete first.  This keeps BarrierComplete events
                // unambiguous and lets QUIESCE be retried after FORGET has
                // drained every carrier, including a ready candidate.
                if key == self.active.key && self.barrier_queued {
                    continue;
                }
                let Some(tx) = self.carrier_for_key(&key).map(|carrier| carrier.tx.clone()) else {
                    return Err(ClientError::Transport {
                        scope: "stream forget barrier",
                        detail: "carrier disappeared before barrier completion".to_owned(),
                    });
                };
                let permit = match tx.try_reserve_owned() {
                    Ok(permit) => permit,
                    Err(mpsc::error::TrySendError::Full(_)) => continue,
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        return Err(ClientError::Transport {
                            scope: "stream forget barrier",
                            detail: "data writer stopped before barrier completion".to_owned(),
                        });
                    }
                };
                permit.send(CarrierCommand::Barrier);
                if let Some(pending) = self.pending_forgets.get_mut(&stream_id) {
                    pending.barriers_queued.insert(key);
                }
            }
        }
        Ok(())
    }

    fn complete_pending_stream_forgets(&mut self, key: &CarrierKey) -> Result<(), ClientError> {
        self.complete_pending_stream_forgets_matching(Some(key))
    }

    fn complete_ready_stream_forgets(&mut self) -> Result<(), ClientError> {
        self.complete_pending_stream_forgets_matching(None)
    }

    fn complete_pending_stream_forgets_matching(
        &mut self,
        key: Option<&CarrierKey>,
    ) -> Result<(), ClientError> {
        self.refresh_pending_forget_proofs()?;
        let phase = self.rotation.phase();
        let ready = self
            .pending_forgets
            .iter()
            .filter_map(|(&stream_id, pending)| {
                (key.is_none_or(|key| pending.carriers.contains(key))
                    && key.is_none_or(|key| pending.barriers_queued.contains(key))
                    && key.is_none_or(|key| pending.barriers_completed.contains(key))
                    && pending
                        .carriers
                        .iter()
                        .all(|carrier| pending.barriers_completed.contains(carrier))
                    && matches!(phase, RotationPhase::Active | RotationPhase::Preparing)
                    && (!pending.defer_reclamation || phase == RotationPhase::Active))
                    .then_some(stream_id)
            })
            .collect::<Vec<_>>();
        let had_ready = !ready.is_empty();
        for stream_id in ready {
            let Some((forget, proof_pending, proof_deadline)) =
                self.pending_forgets.get(&stream_id).map(|pending| {
                    (
                        pending.forget.clone(),
                        pending.proof_pending,
                        pending.proof_deadline,
                    )
                })
            else {
                continue;
            };
            if let Err(error) = self.validate_stream_forget(&forget) {
                let can_retry = proof_pending
                    && proof_deadline.is_some_and(|deadline| Instant::now() < deadline)
                    && self.stream_forget_proof_may_converge(&forget);
                if !can_retry {
                    return Err(error);
                }
                // The barrier proved the current carrier ordering, but the
                // independent data event/ACK has not converged yet. Reset the
                // bounded barrier set; the existing deadline tick retries it
                // without an immediate barrier/requeue loop.
                if let Some(pending) = self.pending_forgets.get_mut(&stream_id) {
                    pending.barriers_queued.clear();
                    pending.barriers_completed.clear();
                }
                continue;
            }
            let operation_id = forget.operation_id.clone();
            self.remove_pending_open_for_forget(stream_id, &operation_id);
            // The OPEN retry horizon: the owner has asserted this entry is
            // reclaimed and can never retry its message ID, so release the
            // canonical request and its retained reply instead of keeping a
            // tombstone for the session's lifetime.  The retired record below
            // is what refuses a late retry and absorbs a repeated
            // STREAM_FORGET, so the journal stays bounded by the streams the
            // session still holds rather than by the streams it has served.
            self.open_journal.release_matching(stream_id, &operation_id);
            self.streams.remove(&stream_id);
            self.pending_forgets.remove(&stream_id);
            self.forgotten_stream_through = self.forgotten_stream_through.max(stream_id);
            self.retired_streams.insert(stream_id);
        }
        if had_ready {
            self.publish_status();
        }
        Ok(())
    }

    fn mark_pending_forget_barrier_complete(&mut self, key: &CarrierKey) -> bool {
        let mut matched = false;
        for pending in self.pending_forgets.values_mut() {
            if pending.barriers_queued.contains(key)
                && pending.barriers_completed.insert(key.clone())
            {
                matched = true;
            }
        }
        matched
    }

    fn has_pre_quiesce_forgets(&self) -> bool {
        self.pending_forgets
            .values()
            .any(|pending| !pending.defer_reclamation)
    }

    fn carrier_has_pending_forget_barrier(&self, key: &CarrierKey) -> bool {
        self.pending_forgets.values().any(|pending| {
            pending.carriers.contains(key) && !pending.barriers_completed.contains(key)
        })
    }

    fn handle_ping(&mut self, ping: Ping) -> Result<(), ClientError> {
        if ping.session_id != self.session.session_id || ping.epoch != self.session.epoch {
            return Err(ClientError::Protocol("PING context mismatch".to_owned()));
        }
        self.send_critical_control(
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
                self.remember_recovery_trigger(RecoveryTriggerClass::ReaderClosed, &key);
                self.mark_carrier_closed(&key, false, peer_closed).await
            }
            CarrierEvent::WriterClosed { key } => {
                self.remember_recovery_trigger(RecoveryTriggerClass::WriterClosed, &key);
                self.mark_carrier_closed(&key, true, false).await
            }
            CarrierEvent::WriterFailed { key, detail } => {
                self.remember_recovery_trigger(RecoveryTriggerClass::WriterFailed, &key);
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
            Message::Close(_) => {
                self.remember_recovery_trigger(RecoveryTriggerClass::ReaderClosed, &key);
                self.mark_carrier_closed(&key, false, true).await
            }
        }
    }

    async fn handle_frame(&mut self, key: CarrierKey, frame: Frame) -> Result<(), ClientError> {
        let stream_id = frame.stream_id;
        // Once terminal cursor evidence has started STREAM_FORGET cleanup,
        // late duplicate frames must not create fresh ACK/WINDOW debt or
        // application output behind the physical drain barriers.
        if self
            .pending_forgets
            .get(&stream_id)
            .is_some_and(|pending| !pending.proof_pending)
            || (stream_id <= self.forgotten_stream_through
                && !self.streams.contains_key(&stream_id))
        {
            return Ok(());
        }
        let acknowledge_frame = should_ack_incoming_frame(frame.kind);
        let payload_bytes = frame.payload.len();
        if payload_bytes > 0 {
            self.ensure_bulk_retained_capacity(payload_bytes)?;
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
        // An invalidated authorization can never be confirmed, so nothing
        // will ever drain this stream's buffered input: `dispatch_payload`
        // and `dispatch_fin` refuse an invalidated stream, and a later
        // confirmation is rejected for the same reason.  Buffering here would
        // therefore retain permanent adapter input debt on a stream the
        // connector has already reset, which the owner's STREAM_FORGET proof
        // then rejects as undrained.  The frames are still marked delivered
        // and acknowledged below, so the sequence evidence both sides compare
        // is unchanged.
        let invalidated = stream.auth.invalidated;
        // HTTP request bytes release receive credit only when the handler
        // side reads them (see `m2_http`), never on hand-off.
        let http_stream = stream.is_http();
        let mut peer_reset_reason = None;
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
                if ready_frame.kind == FrameKind::Reset {
                    peer_reset_reason = ready_frame.reset_reason().ok().flatten();
                }
                if ready_frame.kind == FrameKind::Data && !http_stream {
                    released_receive_bytes = released_receive_bytes
                        .checked_add(ready_frame.payload.len())
                        .ok_or_else(|| {
                            ClientError::Protocol("receive byte counter exhausted".to_owned())
                        })?;
                }
                match ready_frame.kind {
                    FrameKind::Data if invalidated => {}
                    FrameKind::Data => {
                        if stream.pending_bytes.saturating_add(payload.len())
                            > self.config.limits.max_queue_bytes
                        {
                            return self.expire_stream(stream_id).await;
                        }
                        stream.pending_bytes += payload.len();
                        stream.pending.push_back(BufferedInput::Data(payload));
                    }
                    FrameKind::Fin if invalidated => {}
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
                if kind == FrameKind::Data && !http_stream {
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
                        if http_stream && payload.len() == 2 {
                            self.http_abort(
                                stream_id,
                                u16::from_be_bytes([payload[0], payload[1]]),
                            );
                        }
                        self.handle_peer_reset(stream_id).await?;
                        reset_delivered = true;
                    }
                    FrameKind::Ack | FrameKind::WindowUpdate => {}
                }
            }
        }
        if reset_ready && !reset_delivered {
            if http_stream {
                self.http_abort(stream_id, peer_reset_reason.unwrap_or(M2_RESET_PROTOCOL));
            }
            self.handle_peer_reset(stream_id).await?;
        }
        if http_stream && matches!(frame.kind, FrameKind::Ack | FrameKind::WindowUpdate) {
            self.retry_http_parked(stream_id).await?;
        }
        if acknowledge_frame {
            self.defer_ack(&key, stream_id, received_cursor)?;
        }
        if released_receive_bytes > 0 {
            self.defer_window_update(&key, stream_id, released_receive_bytes)?;
        }
        self.maybe_send_drain_proof()?;
        // Recovery READY may arrive before the peer's retained replay.  A
        // contiguous replayed prefix is the event that makes the previously
        // pending sequence plan activatable; keep the episode bounded and
        // retry the pure reconciliation after each delivered DATA frame.
        if self.recovery.is_some() {
            self.maybe_finish_recovery().await?;
        }
        self.refresh_pending_forget_proofs()?;
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

    fn carrier_for_key(&self, key: &CarrierKey) -> Option<&Carrier> {
        if self.active.key == *key {
            Some(&self.active)
        } else if self
            .candidate
            .as_ref()
            .is_some_and(|carrier| carrier.key == *key)
        {
            self.candidate.as_ref()
        } else {
            self.retiring.as_ref().filter(|carrier| carrier.key == *key)
        }
    }

    fn carrier_for_key_mut(&mut self, key: &CarrierKey) -> Option<&mut Carrier> {
        if self.active.key == *key {
            Some(&mut self.active)
        } else if self
            .candidate
            .as_ref()
            .is_some_and(|carrier| carrier.key == *key)
        {
            self.candidate.as_mut()
        } else {
            self.retiring.as_mut().filter(|carrier| carrier.key == *key)
        }
    }

    fn defer_ack(
        &mut self,
        key: &CarrierKey,
        stream_id: u64,
        acknowledged: u64,
    ) -> Result<(), ClientError> {
        let carrier = self
            .carrier_for_key_mut(key)
            .ok_or_else(|| ClientError::Protocol("stale data carrier".to_owned()))?;
        carrier
            .pending_controls
            .entry(stream_id)
            .or_default()
            .record_ack(acknowledged);
        Ok(())
    }

    fn defer_window_update(
        &mut self,
        key: &CarrierKey,
        stream_id: u64,
        released_bytes: usize,
    ) -> Result<(), ClientError> {
        if !self.streams.contains_key(&stream_id) {
            return Err(ClientError::Protocol(
                "window update for unknown stream".to_owned(),
            ));
        }
        let carrier = self
            .carrier_for_key_mut(key)
            .ok_or_else(|| ClientError::Protocol("stale data carrier".to_owned()))?;
        carrier
            .pending_controls
            .entry(stream_id)
            .or_default()
            .record_window(released_bytes)
    }

    /// Capture the absolute receive state that must survive a carrier
    /// replacement.  A window update may already have advanced the logical
    /// sequence state when it was accepted by the old writer queue, yet the
    /// writer can still fail before putting that frame on the socket.  The
    /// new carrier therefore receives the current cumulative ACK and credit
    /// again; both are monotonic and idempotent on the wire.
    fn snapshot_receive_controls(
        &self,
    ) -> Result<BTreeMap<u64, PendingCarrierControl>, ClientError> {
        let mut snapshot = BTreeMap::new();
        for (&stream_id, stream) in &self.streams {
            if self
                .pending_forgets
                .get(&stream_id)
                .is_some_and(|pending| !pending.proof_pending)
            {
                continue;
            }
            let direction = stream.sequence.direction(Direction::RelayToConnector);
            let mut control = PendingCarrierControl::default();
            if direction.recv_contiguous() > 0 {
                control.record_ack(direction.recv_contiguous());
            }
            if direction.receive_credit() > 0 {
                control.record_window_limit(direction.receive_credit());
            }
            for carrier in [
                Some(&self.active),
                self.candidate.as_ref(),
                self.retiring.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                let Some(pending) = carrier.pending_controls.get(&stream_id) else {
                    continue;
                };
                if let Some(acknowledged) = pending.acknowledged {
                    control.record_ack(acknowledged);
                }
                let released = u64::try_from(pending.released_window_bytes).map_err(|_| {
                    ClientError::Protocol("receive byte counter exhausted".to_owned())
                })?;
                let current = direction.receive_credit();
                let released_limit = current
                    .checked_add(released)
                    .ok_or_else(|| ClientError::Protocol("receive credit exhausted".to_owned()))?;
                if pending.window_limit.is_some() || released > 0 {
                    control.record_window_limit(
                        pending
                            .window_limit
                            .unwrap_or(released_limit)
                            .max(released_limit),
                    );
                }
            }
            if !control.is_empty() {
                snapshot.insert(stream_id, control);
            }
        }
        Ok(snapshot)
    }

    fn reissue_active_receive_controls(&mut self) -> Result<(), ClientError> {
        let snapshot = self.snapshot_receive_controls()?;
        let stream_ids = snapshot.keys().copied().collect::<Vec<_>>();
        for (stream_id, pending) in snapshot {
            let control = self.active.pending_controls.entry(stream_id).or_default();
            if let Some(acknowledged) = pending.acknowledged {
                control.record_ack(acknowledged);
            }
            if let Some(limit) = pending.window_limit {
                control.record_window_limit(limit);
            }
        }
        let active_key = self.active.key.clone();
        self.flush_pending_carrier_controls_for_key(&active_key)?;
        // Retiring debt is cleared per stream and per control kind.  A
        // bounded active queue may accept stream A's cumulative ACK while
        // retaining stream B's controls; waiting for the entire active map to
        // empty would replay A's relative window delta on every timer tick.
        for stream_id in stream_ids {
            let active_pending = self
                .active
                .pending_controls
                .get(&stream_id)
                .copied()
                .unwrap_or_default();
            if let Some(retiring) = self.retiring.as_mut()
                && let Some(control) = retiring.pending_controls.get_mut(&stream_id)
            {
                if active_pending.acknowledged.is_none() {
                    control.acknowledged = None;
                }
                if active_pending.released_window_bytes == 0
                    && active_pending.window_limit.is_none()
                {
                    control.released_window_bytes = 0;
                    control.window_limit = None;
                }
                let control_empty = control.is_empty();
                if control_empty {
                    retiring.pending_controls.remove(&stream_id);
                }
            }
        }
        Ok(())
    }

    fn flush_pending_carrier_controls(&mut self) -> Result<(), ClientError> {
        let mut keys = Vec::new();
        if let Some(retiring) = self.retiring.as_ref() {
            keys.push(retiring.key.clone());
        }
        keys.push(self.active.key.clone());
        if let Some(candidate) = self.candidate.as_ref() {
            keys.push(candidate.key.clone());
        }
        for key in keys {
            self.flush_pending_carrier_controls_for_key(&key)?;
        }
        Ok(())
    }

    fn flush_pending_carrier_controls_for_key(
        &mut self,
        key: &CarrierKey,
    ) -> Result<(), ClientError> {
        let stream_ids = self
            .carrier_for_key(key)
            .map(|carrier| carrier.pending_controls.keys().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        for stream_id in stream_ids {
            let Some(pending) = self
                .carrier_for_key(key)
                .and_then(|carrier| carrier.pending_controls.get(&stream_id).copied())
            else {
                continue;
            };
            if !self.streams.contains_key(&stream_id) {
                if let Some(carrier) = self.carrier_for_key_mut(key) {
                    carrier.pending_controls.remove(&stream_id);
                }
                continue;
            }

            if let Some(acknowledged) = pending.acknowledged {
                let frame = Frame::ack(self.session.epoch, key.generation, stream_id, acknowledged);
                let encoded = frame
                    .encode()
                    .map_err(|error| ClientError::Protocol(error.to_string()))?;
                match self.queue_reserved_carrier_bytes(key, encoded) {
                    Ok(()) => {
                        if let Some(carrier) = self.carrier_for_key_mut(key)
                            && let Some(control) = carrier.pending_controls.get_mut(&stream_id)
                            && control.acknowledged == Some(acknowledged)
                        {
                            control.acknowledged = None;
                        }
                    }
                    Err(ClientError::QueueLimit) => continue,
                    Err(error) => return Err(error),
                }
            }

            if pending.released_window_bytes > 0 || pending.window_limit.is_some() {
                let released_bytes =
                    u64::try_from(pending.released_window_bytes).map_err(|_| {
                        ClientError::Protocol("receive byte counter exhausted".to_owned())
                    })?;
                let current_credit = self
                    .streams
                    .get(&stream_id)
                    .ok_or_else(|| {
                        ClientError::Protocol("window update for unknown stream".to_owned())
                    })?
                    .sequence
                    .direction(Direction::RelayToConnector)
                    .receive_credit();
                let released_limit = current_credit
                    .checked_add(released_bytes)
                    .ok_or_else(|| ClientError::Protocol("receive credit exhausted".to_owned()))?;
                let limit = pending
                    .window_limit
                    .unwrap_or(current_credit)
                    .max(released_limit);
                let frame =
                    Frame::window_update(self.session.epoch, key.generation, stream_id, limit);
                let encoded = frame
                    .encode()
                    .map_err(|error| ClientError::Protocol(error.to_string()))?;
                let encoded_len = encoded.len();
                let (permit, budget) = match self.reserve_carrier_frame(key, encoded_len, false) {
                    Ok(reservation) => reservation,
                    Err(ClientError::QueueLimit) => continue,
                    Err(error) => return Err(error),
                };
                {
                    let Some(stream) = self.streams.get_mut(&stream_id) else {
                        budget.release(encoded_len);
                        drop(permit);
                        return Err(ClientError::Protocol(
                            "window update for unknown stream".to_owned(),
                        ));
                    };
                    if let Err(error) = stream
                        .sequence
                        .send_frame(Direction::ConnectorToRelay, &frame)
                    {
                        budget.release(encoded_len);
                        drop(permit);
                        return Err(ClientError::Protocol(error.to_string()));
                    }
                }
                permit.send(CarrierCommand::Frame(QueuedCarrierFrame {
                    bytes: encoded,
                    bytes_len: encoded_len,
                    budget,
                }));
                if let Some(carrier) = self.carrier_for_key_mut(key)
                    && let Some(control) = carrier.pending_controls.get_mut(&stream_id)
                    && control.released_window_bytes == pending.released_window_bytes
                {
                    control.released_window_bytes = 0;
                    if control.window_limit == pending.window_limit {
                        control.window_limit = None;
                    }
                }
            }

            if let Some(carrier) = self.carrier_for_key_mut(key)
                && carrier
                    .pending_controls
                    .get(&stream_id)
                    .is_some_and(|control| control.is_empty())
            {
                carrier.pending_controls.remove(&stream_id);
            }
        }
        Ok(())
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
        self.queue_reserved_carrier_bytes(key, encoded)
    }

    fn send_carrier_message(
        &mut self,
        key: &CarrierKey,
        message: Message,
    ) -> Result<(), ClientError> {
        if let Message::Pong(payload) = &message
            && payload.len() > M2_MAX_WEBSOCKET_CONTROL_PAYLOAD
        {
            return Err(ClientError::Protocol(
                "data ping payload exceeds websocket control bound".to_owned(),
            ));
        }
        let Some(tx) = self.carrier_for_key(key).map(|carrier| carrier.tx.clone()) else {
            return Ok(());
        };
        // Heartbeats may use ordinary queue capacity, but never consume the
        // four slots reserved for ACK/WINDOW/terminal traffic.  If the
        // ordinary portion is full, retain only the latest bounded Pong and
        // let the timer retry it after the writer drains.
        let is_pong = matches!(&message, Message::Pong(_));
        if is_pong && tx.capacity() <= M2_CARRIER_RESERVED_FRAMES {
            self.pending_pongs.insert(key.clone(), message);
            return Ok(());
        }
        match tx.try_reserve_owned() {
            Ok(permit) => {
                permit.send(CarrierCommand::Message(message));
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) if is_pong => {
                self.pending_pongs.insert(key.clone(), message);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => Err(ClientError::QueueLimit),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(ClientError::Transport {
                scope: "data writer",
                detail: "data writer stopped".to_owned(),
            }),
        }
    }

    fn flush_pending_pongs(&mut self) -> Result<(), ClientError> {
        let pending = std::mem::take(&mut self.pending_pongs);
        for (key, message) in pending {
            let Some(tx) = self.carrier_for_key(&key).map(|carrier| carrier.tx.clone()) else {
                continue;
            };
            if tx.capacity() <= M2_CARRIER_RESERVED_FRAMES {
                self.pending_pongs.insert(key, message);
                continue;
            }
            match tx.try_reserve_owned() {
                Ok(permit) => {
                    permit.send(CarrierCommand::Message(message));
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.pending_pongs.insert(key, message);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(ClientError::Transport {
                        scope: "data writer",
                        detail: "data writer stopped".to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    fn queue_carrier_bytes(&self, key: &CarrierKey, bytes: Vec<u8>) -> Result<(), ClientError> {
        self.send_reserved_carrier_bytes(key, bytes, true)
    }

    fn queue_reserved_carrier_bytes(
        &self,
        key: &CarrierKey,
        bytes: Vec<u8>,
    ) -> Result<(), ClientError> {
        self.send_reserved_carrier_bytes(key, bytes, false)
    }

    fn reserve_carrier_frame(
        &self,
        key: &CarrierKey,
        bytes_len: usize,
        preserve_reserved_slots: bool,
    ) -> Result<(mpsc::OwnedPermit<CarrierCommand>, Arc<QueueBudget>), ClientError> {
        let carrier = self
            .carrier_for_key(key)
            .ok_or_else(|| ClientError::Protocol("stale data carrier".to_owned()))?;
        if preserve_reserved_slots && carrier.tx.capacity() <= M2_CARRIER_RESERVED_FRAMES {
            return Err(ClientError::QueueLimit);
        }
        let permit = carrier
            .tx
            .clone()
            .try_reserve_owned()
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ClientError::QueueLimit,
                mpsc::error::TrySendError::Closed(_) => ClientError::Transport {
                    scope: "data writer",
                    detail: "data writer stopped".to_owned(),
                },
            })?;
        if let Err(error) = self.reserve_carrier_budget(bytes_len, preserve_reserved_slots) {
            drop(permit);
            return Err(error);
        }
        Ok((permit, self.data_budget.clone()))
    }

    fn reserve_carrier_budget(
        &self,
        bytes_len: usize,
        preserve_critical_bytes: bool,
    ) -> Result<(), ClientError> {
        let reserved = if preserve_critical_bytes {
            critical_reserved_bytes(self.data_budget.maximum)
        } else {
            0
        };
        let maximum = self.data_budget.maximum.saturating_sub(reserved);
        if bytes_len > maximum {
            return Err(ClientError::QueueLimit);
        }
        let mut current = self.data_budget.bytes.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(bytes_len) else {
                return Err(ClientError::QueueLimit);
            };
            if next > maximum {
                return Err(ClientError::QueueLimit);
            }
            match self.data_budget.bytes.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(observed) => current = observed,
            }
        }
    }

    fn send_reserved_carrier_bytes(
        &self,
        key: &CarrierKey,
        bytes: Vec<u8>,
        preserve_reserved_slots: bool,
    ) -> Result<(), ClientError> {
        let bytes_len = bytes.len();
        let (permit, budget) =
            self.reserve_carrier_frame(key, bytes_len, preserve_reserved_slots)?;
        let item = QueuedCarrierFrame {
            bytes,
            bytes_len,
            budget,
        };
        permit.send(CarrierCommand::Frame(item));
        Ok(())
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
        let http = stream.is_http();
        if deadline.expired() {
            return self.expire_stream(stream_id).await;
        }
        if http {
            self.http_dispatch_payload(stream_id, payload);
            Ok(())
        } else if streaming {
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
            self.ensure_bulk_retained_capacity(payload.len())?;
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
        // An HTTP response may finish before the upload does, so only the
        // request direction's own terminal state blocks its FIN.
        let http_blocked = stream.auth.invalidated
            || !stream.auth.confirmed
            || stream.input_fin
            || stream.output_reset;
        if stream.is_http() {
            if http_blocked {
                return Ok(());
            }
            // The request FIN half-closes only the request direction.
            self.http_dispatch_fin(stream_id);
            return Ok(());
        }
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
        if self
            .pending_forgets
            .get(&output.stream_id)
            .is_some_and(|pending| !pending.proof_pending)
        {
            return Ok(());
        }
        let is_reset = output.kind == FrameKind::Reset;
        let stream_terminal = self
            .streams
            .get(&output.stream_id)
            .is_none_or(|stream| output_blocked(stream, output.kind));
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
        // A same-stream output already retained for the carrier must be sent
        // first.  Keeping the new output deferred preserves sequence order;
        // otherwise a newly available carrier slot could let FIN/RESET or a
        // later DATA overtake the retained prefix.
        if has_pending_output_for_stream(&self.pending_outputs, output.stream_id) {
            return self.defer_pending_output(output);
        }
        if self.writes_frozen {
            return self.defer_pending_output(output);
        }
        match self.emit_output_now(&output) {
            Ok(()) => Ok(()),
            Err(ClientError::QueueLimit) => self.defer_pending_output(output),
            Err(error) => {
                if is_reset && let Some(stream) = self.streams.get_mut(&output.stream_id) {
                    stream.reset_queued = false;
                }
                Err(error)
            }
        }
    }

    fn defer_pending_output(&mut self, output: PendingOutput) -> Result<(), ClientError> {
        if self.pending_outputs.len() >= self.config.limits.max_queue_frames.max(1) {
            if output.kind == FrameKind::Reset
                && let Some(stream) = self.streams.get_mut(&output.stream_id)
            {
                stream.reset_queued = false;
            }
            return Err(ClientError::QueueLimit);
        }
        let bytes = output.payload.len();
        let critical = matches!(
            output.kind,
            FrameKind::Ack | FrameKind::WindowUpdate | FrameKind::Fin | FrameKind::Reset
        );
        if let Err(error) = self.ensure_retained_capacity_with_reserve(bytes, !critical) {
            if output.kind == FrameKind::Reset
                && let Some(stream) = self.streams.get_mut(&output.stream_id)
            {
                stream.reset_queued = false;
            }
            return Err(error);
        }
        self.pending_output_bytes = self.pending_output_bytes.saturating_add(bytes);
        self.pending_outputs.push_back(output);
        self.publish_status();
        Ok(())
    }

    fn emit_output_now(&mut self, output: &PendingOutput) -> Result<(), ClientError> {
        let critical = matches!(
            output.kind,
            FrameKind::Ack | FrameKind::WindowUpdate | FrameKind::Fin | FrameKind::Reset
        );
        self.ensure_retained_capacity_with_reserve(output.payload.len(), !critical)?;
        let (generation, key) = {
            let key = self.active.key.clone();
            (key.generation, key)
        };
        let frame = {
            let Some(stream) = self.streams.get(&output.stream_id) else {
                return Ok(());
            };
            if output_blocked(stream, output.kind) {
                return Ok(());
            }
            if output.kind == FrameKind::Reset && !stream.reset_queued {
                // Every RESET reaches this function through emit_or_defer,
                // which marks it before either immediate send or deferral.
                // A missing marker means a stale/internal duplicate and is
                // therefore suppressed rather than allocating a sequence.
                return Ok(());
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
            match output.kind {
                FrameKind::Data => Frame::data(
                    self.session.epoch,
                    generation,
                    output.stream_id,
                    sequence,
                    ack,
                    output.payload.clone(),
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
            }
        };
        let encoded = frame
            .encode()
            .map_err(|error| ClientError::Protocol(error.to_string()))?;
        self.ensure_retained_capacity_with_reserve(encoded.len(), !critical)?;
        let (permit, budget) = self.reserve_carrier_frame(&key, encoded.len(), !critical)?;
        {
            let Some(stream) = self.streams.get_mut(&output.stream_id) else {
                budget.release(encoded.len());
                drop(permit);
                return Ok(());
            };
            if let Err(error) = stream
                .sequence
                .send_frame(Direction::ConnectorToRelay, &frame)
            {
                budget.release(encoded.len());
                drop(permit);
                return Err(ClientError::Protocol(error.to_string()));
            }
            if output.kind == FrameKind::Fin {
                stream.output_fin = true;
            }
            if output.kind == FrameKind::Reset {
                stream.output_reset = true;
                stream.reset_queued = false;
            }
        }
        let encoded_len = encoded.len();
        permit.send(CarrierCommand::Frame(QueuedCarrierFrame {
            bytes: encoded,
            bytes_len: encoded_len,
            budget,
        }));
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
            // A recovery candidate can attach at the relay and then be lost
            // before its handshake response reaches this connector.  The
            // relay's DATA_READY for that exact released candidate is then
            // late, not foreign: it names a carrier this episode already
            // closed, so it is ignored and the retry proceeds.  Any other
            // readiness without a pending candidate remains a protocol
            // violation; the initial DATA_READY is consumed before the actor
            // starts and a stale readiness must not attach an untracked
            // socket.
            let released_recovery_candidate = self.recovery.is_some()
                && ready.session_id == self.session.session_id
                && ready.epoch == self.session.epoch
                && self
                    .closed_for_recovery
                    .contains_key(ready.connection_id.as_str());
            if released_recovery_candidate {
                return Ok(());
            }
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
            // The candidate carrier is now installed.  Re-drive any recovery
            // snapshot work that deferred while control RESUME was ahead of
            // this data socket, then flush the snapshot replies it was
            // waiting to back with a real carrier.
            self.maybe_prepare_recovery_plans(true)?;
            self.send_recovery_snapshot_replies()?;
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
        if !matches!(
            self.rotation.phase(),
            RotationPhase::Preparing | RotationPhase::Quiescing
        ) || self.candidate.is_none()
            || self.pending_quiesce.is_none()
            || self.has_pre_quiesce_forgets()
        {
            return Ok(());
        }
        let quiesce = self
            .pending_quiesce
            .as_ref()
            .expect("pending quiesce checked")
            .clone();
        if self.rotation.phase() == RotationPhase::Preparing {
            self.rotation
                .quiesce(&quiesce.attempt, quiesce.roster, self.now_ms())
                .map_err(|error| {
                    ClientError::Protocol(format!("rotation quiesce rejected: {error}"))
                })?;
        }
        if self.barrier_queued {
            return Ok(());
        }
        let permit = match self.active.tx.clone().try_reserve_owned() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(_)) => return Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(ClientError::Transport {
                    scope: "active data writer",
                    detail: "unable to schedule immutable fence barrier: writer stopped".to_owned(),
                });
            }
        };
        // Barrier carries no payload and intentionally bypasses the byte
        // budget; its bounded queue permit still preserves frame ordering.
        permit.send(CarrierCommand::Barrier);
        self.barrier_queued = true;
        Ok(())
    }

    fn handle_barrier_complete(&mut self, key: &CarrierKey) -> Result<(), ClientError> {
        let forget_barrier = self.mark_pending_forget_barrier_complete(key);
        if self.active.key != *key {
            self.complete_pending_stream_forgets(key)?;
            if !self.has_pre_quiesce_forgets() {
                self.apply_pending_quiesce()?;
            }
            return Ok(());
        }

        // An active barrier is a rotation fence only while `barrier_queued` is
        // set.  Forget barriers are queued after that fence has drained, and
        // must never consume a pending QUIESCE as if they were the immutable
        // rotation fence.
        if !self.barrier_queued {
            if forget_barrier {
                self.complete_pending_stream_forgets(key)?;
                if !self.has_pre_quiesce_forgets() {
                    self.apply_pending_quiesce()?;
                }
            }
            return Ok(());
        }

        self.barrier_queued = false;
        if self.has_pre_quiesce_forgets() {
            // STREAM_FORGET may arrive after the rotation barrier was queued.
            // The physical barrier has drained, but the stream must be removed
            // before taking the immutable roster snapshot.  Keep QUIESCE
            // pending and retry the forget barriers first.
            self.retry_pending_forget_barriers()?;
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
        self.flush_pending_carrier_controls()?;
        self.retry_pending_forget_barriers()?;
        if self.retiring.as_ref().is_some_and(|carrier| {
            !carrier.pending_controls.is_empty()
                || self.carrier_has_pending_forget_barrier(&carrier.key)
        }) {
            self.pending_retire = Some(retire);
            return Ok(());
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

    /// Force-close the lingering old carrier and submit this connector's own
    /// retirement evidence for `attempt`.
    ///
    /// This is the connector half of the absolute overlap deadline: unlike
    /// [`Self::handle_rotate_retire`] it never waits for pending carrier
    /// controls or forget barriers, because protocol.md is explicit that "no
    /// slow stream, retransmission, close handshake or duplicate message
    /// extends the budget".  It is a no-op when the carrier is already gone,
    /// so the deadline timer and a forced COMPLETE can both call it.
    async fn force_close_retiring_carrier(
        &mut self,
        attempt: &RotationAttemptIdentity,
    ) -> Result<Option<ForcedRetirement>, ClientError> {
        let Some(old) = self.retiring.take() else {
            return Ok(None);
        };
        // A deferred RETIRE can no longer be answered on the ordinary path;
        // the forced closure replaces it.
        let deferred_retire = self.pending_retire.take();
        let old_connection_id = old.key.connection_id.clone();
        let evidence = close_carrier(old).await;
        if !evidence.is_complete() {
            return Err(ClientError::Transport {
                scope: "forced retired data carrier",
                detail: "forced old data carrier closure was not confirmed".to_owned(),
            });
        }
        self.rotation
            .retired(attempt, RotationSide::Connector, evidence, self.now_ms())
            .map_err(|error| {
                ClientError::Protocol(format!("forced retirement evidence rejected: {error}"))
            })?;
        Ok(Some(ForcedRetirement {
            old_connection_id,
            deferred_retire,
        }))
    }

    /// Whether the control writer half is still attached.  A forced closure at
    /// the deadline must still release the carrier when it is not, so the
    /// attestation is best effort while the closure is not.
    fn control_socket_is_live(&self) -> bool {
        !self.control_queue.sender.is_closed() && !self.cancellation.is_cancelled()
    }

    /// The connector's own arm of the absolute overlap deadline.  The pure
    /// rotation machine latches `deadline_forced_retirement` in `Retiring` and
    /// leaves the phase alone so this runtime can release the old carrier.
    /// The closure and its evidence are unconditional; the `ROTATE_RETIRED`
    /// attestation is sent only when there is a live control socket and an
    /// owner `ROTATE_RETIRE` to correlate to, because the wire requires a
    /// bound reply target on that message.
    async fn force_retire_at_overlap_deadline(&mut self) -> Result<(), ClientError> {
        let Some(attempt) = self.rotation.status().attempt else {
            return Ok(());
        };
        let Some(forced) = self.force_close_retiring_carrier(&attempt).await? else {
            return Ok(());
        };
        if let Some(retire) = forced.deferred_retire
            && self.control_socket_is_live()
        {
            let response = ControlMessage::RotateRetired(RotateRetired {
                message_id: message_id(),
                reply_to: retire.message_id.clone(),
                attempt: retire.attempt,
                snapshot_id: retire.snapshot_id,
                closed_connection_id: forced.old_connection_id,
            });
            self.local_retired_message_id = Some(response.message_id().to_owned());
            self.peer_retire_message_id = Some(retire.message_id.clone());
            self.send_rotation_reply(&retire.message_id, response)?;
        }
        self.publish_status();
        Ok(())
    }

    async fn retry_pending_retire(&mut self) -> Result<(), ClientError> {
        let Some(retire) = self.pending_retire.take() else {
            return Ok(());
        };
        self.flush_pending_carrier_controls()?;
        self.retry_pending_forget_barriers()?;
        if self.retiring.as_ref().is_some_and(|carrier| {
            !carrier.pending_controls.is_empty()
                || self.carrier_has_pending_forget_barrier(&carrier.key)
        }) {
            self.pending_retire = Some(retire);
            return Ok(());
        }
        self.handle_rotate_retire(retire).await
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
        // protocol.md, reply-target table: "Owner COMPLETE | Connector
        // RETIRED; empty only for a forced completion whose connector RETIRED
        // never arrived".  The strict equality below is this endpoint's
        // anti-spoofing guard, so it is relaxed only for the forced shape the
        // wire permits, and only to the empty target or to the very message
        // this connector sent if its RETIRED crossed the owner's grace.  A
        // forced COMPLETE naming any other target is still refused.  The
        // attempt identity and snapshot checks above run first either way, so
        // a forced COMPLETE must still name the exact in-flight attempt
        // (session, epoch, owner, rotation, both generations and both
        // connection identifiers) and this connector's own fence snapshot.
        if complete.forced {
            if !complete.reply_to.is_empty()
                && self.local_retired_message_id.as_deref() != Some(complete.reply_to.as_str())
            {
                return Err(ClientError::Protocol(
                    "ROTATE_COMPLETE forced reply correlation mismatch".to_owned(),
                ));
            }
        } else if self.local_retired_message_id.as_deref() != Some(complete.reply_to.as_str()) {
            return Err(ClientError::Protocol(
                "ROTATE_COMPLETE reply correlation mismatch".to_owned(),
            ));
        }
        // protocol.md, Retire: "after a forced completion the owner's old
        // transport resources are already released, and a connector that still
        // holds its half is required by its own deadline to force-close it
        // before the next attempt".  Release it here so the attempt reaches
        // Active from this connector's own closure evidence rather than from
        // the owner's message alone.
        if complete.forced && self.rotation.phase() == RotationPhase::Retiring {
            self.force_close_retiring_carrier(&complete.attempt).await?;
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
        self.barrier_queued = false;
        self.pending_retire = None;
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
        self.complete_ready_stream_forgets()?;
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
        self.barrier_queued = false;
        self.pending_retire = None;
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
        self.complete_ready_stream_forgets()?;
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
                || resume.remaining_ms > MAX_ROTATION_RECOVERY_TIMEOUT_MS
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
            if let Some(mismatch) = resume_context_mismatch(&resume, recovery, now) {
                return Err(ClientError::Protocol(
                    self.retained_recovery_detail(mismatch.detail()),
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
        // Control input can win the select before the maintenance tick. An
        // expired candidate must not journal a new snapshot or emit replay.
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
                detail: self.retained_recovery_detail("recovery candidate phase deadline expired"),
            });
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
        if queue_replay && self.candidate.is_none() {
            // Control RESUME can win the select against the candidate data
            // socket's own handshake completion, so snapshots can arrive
            // before this actor has installed the candidate carrier that
            // must carry the replay frames.  Defer replay queuing and the
            // snapshot replies rather than failing the session: the install
            // path (`maybe_install_candidate`) re-drives this, and if the
            // candidate never attaches the episode's candidate deadline
            // converts the stall into a clean candidate loss and retry.
            return Ok(());
        }
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
                    self.ensure_bulk_retained_capacity(encoded.len())?;
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
        // A snapshot reply commits to the replay ranges this connector will
        // push over the candidate carrier, so it must not be sent until that
        // carrier is installed.  When control RESUME raced ahead of the data
        // socket, the reply is deferred here and re-driven once the candidate
        // installs; an unattached candidate therefore produces a clean
        // candidate-deadline loss instead of a premature, unbacked reply.
        if self.candidate.is_none() {
            return Ok(());
        }
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
            self.send_critical_control(message, None)?;
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
                detail: self.retained_recovery_detail("recovery candidate phase deadline expired"),
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
        let recovery_attempt_started_at_ms = self.rotation.status().started_at_ms;
        let recovery_attempt_deadline_ms = self.rotation.status().deadline_ms;
        let recovery_attempt = self
            .recovery
            .as_ref()
            .map(|recovery| recovery.begin.attempt_no);
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
            self.send_critical_control(response.clone(), None)?;
            self.complete_recovery_message(request_id, Some(&response))?;
        }
        if let Some(completed) = self.recovery.take() {
            self.completed_recovery = Some(completed);
        }
        // The completed journal retains its immutable attestation and digest,
        // while closure evidence belongs only to the episode that just ended.
        // Clear it at the verified activation boundary so a later recovery
        // cannot submit historical connection IDs to RotationState.
        self.closed_for_recovery.clear();
        self.released_recovery_connections.clear();
        self.first_recovery_trigger = None;
        self.pending_candidate = None;
        self.recovery_requested = false;
        self.accepting = true;
        self.writes_frozen = false;
        self.rotations_completed = self.rotations_completed.saturating_add(1);
        self.complete_ready_stream_forgets()?;
        self.flush_pending_outputs().await?;
        // Only this path has completed sequence reconciliation, candidate
        // identity validation, old-carrier closure, and both READY replies.
        // Record the reset after the final flush so a failed activation cannot
        // look like a successful recovery in the CLI status stream.
        self.last_recovery_reset_reason = Some(M2_RECOVERY_RESET_FENCED_SUCCESSOR);
        self.last_recovery_successor = Some(attempt);
        self.last_recovery_attempt = recovery_attempt;
        self.last_recovery_attempt_started_at_ms = recovery_attempt_started_at_ms;
        self.last_recovery_attempt_deadline_ms = recovery_attempt_deadline_ms;
        self.publish_status();
        Ok(())
    }

    async fn expire_stream(&mut self, stream_id: u64) -> Result<(), ClientError> {
        #[cfg(test)]
        {
            self.expire_stream_calls = self.expire_stream_calls.saturating_add(1);
        }
        if self.http_stream_settled(stream_id) {
            // Both terminals are in place; only the owner's STREAM_FORGET
            // remains, and a RESET now would be one it never acknowledges.
            return Ok(());
        }
        self.http_abort(stream_id, M2_RESET_AUTH_EXPIRED);
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            // Counted once per stream: `expire_stream` is currently re-run on
            // every tick for a stream already expired (task row M6-C88).
            if !stream.auth.invalidated {
                self.auth_expired_streams = self.auth_expired_streams.saturating_add(1);
            }
            stream.auth.invalidated = true;
            // An expired authorization deadline stops filesystem dispatch at
            // the provider too: its next host call closes the session instead.
            if let Some(authority) = stream.fs_authority.as_ref() {
                authority.invalidate();
            }
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
            let output_bytes = output.payload.len();
            self.pending_output_bytes = self.pending_output_bytes.saturating_sub(output_bytes);
            match self.emit_output_now(&output) {
                Ok(()) => {}
                Err(ClientError::QueueLimit) => {
                    self.pending_output_bytes =
                        self.pending_output_bytes.saturating_add(output_bytes);
                    self.pending_outputs.push_front(output);
                    break;
                }
                Err(error) => return Err(error),
            }
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
                pending_controls: BTreeMap::new(),
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
        // `candidate_closed` records only this connector's side of the
        // bilateral closure.  RotationState still owns the physical
        // allocation until the next RECOVERY_BEGIN consumes this evidence via
        // `close_for_recovery`; do not mark it released before that handoff.
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
                    pending_controls: BTreeMap::new(),
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
            // Nothing can serve a new stream once the active carrier is gone:
            // it has been replaced by a placeholder until recovery.  Refuse
            // admission in every phase, not only `Active` -- since M7-C97 the
            // `Retiring` phase admits too, and a candidate that died after
            // COMMIT would otherwise keep admitting until RECOVERY_BEGIN.
            self.accepting = false;
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
                self.send_critical_control(request, None)?;
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
                pending_controls: BTreeMap::new(),
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

fn no_stream_forget_state(stream_id: u64) -> ResumeDirectionState {
    ResumeDirectionState {
        stream_id,
        ..ResumeDirectionState::default()
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
    use crate::test_hooks;
    use futures_util::{SinkExt, StreamExt};
    use std::sync::{Arc, atomic::AtomicBool};
    use tokio::{
        net::{TcpListener, TcpStream},
        sync::{Notify, watch},
        time::timeout,
    };
    use tokio_tungstenite::{WebSocketStream, accept_async, connect_async};

    const TEST_OWNER_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn owner_fence_welcome() -> tunnel_protocol::Welcome {
        let mut welcome = tunnel_protocol::Welcome::new(
            "welcome",
            "hello",
            "session",
            7,
            1,
            "connection",
            "ticket",
            "reconnect",
        );
        welcome.owner_id = Some(TEST_OWNER_ID.to_owned());
        welcome.supported_features = vec![M2_FEATURE.to_owned(), OWNER_FENCING_FEATURE.to_owned()];
        welcome
    }

    fn record(body: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(M2_RECORD_HEADER_BYTES + body.len());
        encoded.extend_from_slice(&(body.len() as u32).to_be_bytes());
        encoded.extend_from_slice(body);
        encoded
    }

    fn test_open(stream_id: u64) -> Open {
        Open::new(
            format!("open-message-{stream_id}"),
            "session",
            1,
            stream_id,
            format!("operation-{stream_id}"),
            "echo",
            "echo_stream",
            1_024,
            1_024,
        )
    }

    fn drain_control_messages(
        receiver: &mut mpsc::Receiver<crate::QueuedMessage>,
    ) -> Vec<ControlMessage> {
        let mut messages = Vec::new();
        while let Ok(item) = receiver.try_recv() {
            let Message::Text(text) = &item.message else {
                continue;
            };
            messages.push(decode_control(text.as_bytes()).expect("queued control should decode"));
        }
        messages
    }

    fn test_actor_with_carrier(
        capacity: usize,
    ) -> (
        M2Actor,
        CarrierKey,
        mpsc::Receiver<CarrierCommand>,
        mpsc::Receiver<crate::QueuedMessage>,
    ) {
        test_actor_with_control_capacity(capacity, 8)
    }

    fn test_actor_with_control_capacity(
        capacity: usize,
        control_capacity: usize,
    ) -> (
        M2Actor,
        CarrierKey,
        mpsc::Receiver<CarrierCommand>,
        mpsc::Receiver<crate::QueuedMessage>,
    ) {
        let cancellation = CancellationToken::new();
        let config = RuntimeConfig::default();
        let session = SessionInfo {
            session_id: "session".to_owned(),
            epoch: 1,
            generation: 1,
        };
        let owner_id = "owner".to_owned();
        let active_key = CarrierKey::new(session.generation, "active");
        let (tx, receiver) = mpsc::channel(capacity);
        let active = Carrier {
            key: active_key.clone(),
            local_addr: None,
            tx,
            pending_controls: BTreeMap::new(),
            reader_cancel: CancellationToken::new(),
            reader: None,
            writer: None,
        };
        let rotation = RotationState::new(
            session.session_id.clone(),
            owner_id.clone(),
            session.epoch,
            session.generation,
            active_key.connection_id.clone(),
            RotationConfig::default(),
        )
        .expect("test rotation state");
        let (control_queue, control_receiver) = OutboundQueue::new(
            control_capacity,
            M2_CONTROL_QUEUE_BYTES,
            cancellation.clone(),
        );
        let data_budget = Arc::new(QueueBudget {
            bytes: std::sync::atomic::AtomicUsize::new(0),
            maximum: config.limits.max_queue_bytes,
        });
        let (status, _status_receiver) = watch::channel(ConnectionStatus::default());
        let (events, _event_receiver) = mpsc::channel(M2_EVENT_CAPACITY);
        let open_journal = OpenJournal::new(
            retained_stream_limit(config.limits.max_streams).max(1),
            config.limits.max_queue_bytes.min(MAX_JOURNAL_BYTES),
        );
        let pending_open_budget = Arc::new(QueueBudget {
            bytes: std::sync::atomic::AtomicUsize::new(0),
            maximum: pending_open_budget_max(
                config.limits.max_streams,
                config.limits.max_queue_bytes,
            ),
        });
        let actor = M2Actor {
            config,
            session,
            owner_id,
            owner_fence: None,
            rotation,
            control_queue,
            pending_critical_controls: VecDeque::new(),
            pending_critical_control_bytes: 0,
            data_budget,
            events,
            http_handlers: HttpHandlers::default(),
            http_requests: mpsc::channel(1).0,
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
            first_recovery_trigger: None,
            released_recovery_connections: BTreeSet::new(),
            last_recovery_reset_reason: None,
            last_recovery_successor: None,
            last_recovery_attempt: None,
            last_recovery_attempt_started_at_ms: None,
            last_recovery_attempt_deadline_ms: None,
            closed_for_recovery: BTreeMap::new(),
            streams: BTreeMap::new(),
            open_journal,
            pending_open_budget,
            pending_open: None,
            pending_open_queue: VecDeque::new(),
            pending_authorization_refreshes: BTreeMap::new(),
            accepting: true,
            writes_frozen: false,
            auth_expired_streams: 0,
            #[cfg(test)]
            expire_stream_calls: 0,
            pending_outputs: VecDeque::new(),
            pending_output_bytes: 0,
            peer_fence: None,
            local_fence: None,
            sent_drain_proof: false,
            pending_quiesce: None,
            barrier_queued: false,
            pending_retire: None,
            pending_pongs: BTreeMap::new(),
            pending_forgets: BTreeMap::new(),
            forgotten_stream_through: 0,
            retired_streams: RetiredStreamIds::default(),
            peer_fence_message_id: None,
            rotation_started: Instant::now(),
            rotations_completed: 0,
            fs_counters: crate::FsCounters::default(),
            status,
            cancellation,
            control_local_addr: None,
        };
        (actor, active_key, receiver, control_receiver)
    }

    async fn fill_control_queue_before_open(actor: &mut M2Actor) -> Result<(), ClientError> {
        actor.streams.insert(1, test_stream());
        for stream_id in 2..=8 {
            actor
                .handle_control(ControlMessage::Open(test_open(stream_id)))
                .await?;
        }
        // Seven accepted OPENs consume fourteen bounded response slots.  A
        // heartbeat reply occupies the fifteenth slot, making the next OPEN
        // cross the exact two-response admission boundary.
        actor
            .handle_control(ControlMessage::Ping(Ping::new("ping", "session", 1, 1)))
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn terminal_stream_does_not_consume_active_open_capacity() {
        let (mut actor, _active_key, _carrier_receiver, _control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        let mut terminal = test_stream();
        terminal.output_fin = true;
        actor.streams.insert(1, terminal);
        for stream_id in 2..=64 {
            actor.streams.insert(stream_id, test_stream());
        }
        assert_eq!(actor.streams.len(), 64);
        assert_eq!(
            actor
                .streams
                .values()
                .filter(|stream| !stream.terminal())
                .count(),
            63
        );
        for stream_id in 1..=64 {
            let open = test_open(stream_id);
            let canonical = encode_control(&ControlMessage::Open(open.clone()))
                .expect("test OPEN should encode");
            assert!(matches!(
                actor.open_journal.observe(
                    &open.message_id,
                    &canonical,
                    open.stream_id,
                    &open.operation_id,
                ),
                Ok(OpenJournalObservation::New)
            ));
        }
        assert_eq!(actor.open_journal.active_entries, 64);

        let open = test_open(65);
        actor
            .handle_control(ControlMessage::Open(open.clone()))
            .await
            .expect("one terminal entry must leave one active OPEN slot");
        assert!(actor.streams.contains_key(&open.stream_id));
    }

    #[tokio::test]
    async fn retained_terminal_table_has_a_separate_bounded_limit() {
        let (mut actor, _active_key, _carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        for stream_id in 1..=128 {
            let mut stream = test_stream();
            if stream_id > 63 {
                stream.output_fin = true;
            }
            actor.streams.insert(stream_id, stream);
        }
        assert_eq!(
            actor
                .streams
                .values()
                .filter(|stream| !stream.terminal())
                .count(),
            63
        );
        assert_eq!(actor.streams.len(), 128);

        let open = test_open(129);
        actor
            .handle_control(ControlMessage::Open(open.clone()))
            .await
            .expect("retained-table exhaustion must be a typed rejection");
        assert!(!actor.streams.contains_key(&open.stream_id));
        assert!(matches!(
            drain_control_messages(&mut control_receiver).last(),
            Some(ControlMessage::Rejected(rejected))
                if rejected.code == "RESOURCE_EXHAUSTED"
                    && rejected.stream_id == open.stream_id
        ));
    }

    #[tokio::test]
    async fn open_burst_defers_without_half_admission_and_delivers_after_writer_drain() {
        let (mut actor, active_key, mut carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        fill_control_queue_before_open(&mut actor)
            .await
            .expect("initial OPEN burst should be admitted");
        assert_eq!(control_receiver.len(), 15);
        let queued_bytes_before_open = actor.control_queue.budget.current();
        let result = actor
            .handle_control(ControlMessage::Open(test_open(9)))
            .await;
        result.expect("queue pressure should defer one bounded OPEN");
        assert_eq!(control_receiver.len(), 15);
        assert_eq!(
            actor.control_queue.budget.current(),
            queued_bytes_before_open
        );
        assert_eq!(actor.streams.len(), 8);
        assert!(actor.streams.contains_key(&1));
        assert!(!actor.streams.contains_key(&9));
        assert!(actor.pending_open.is_some());
        let pending_auth_deadline = actor
            .pending_open
            .as_ref()
            .and_then(|pending| pending.authorization.as_ref())
            .map(|authorization| authorization.auth_deadline.monotonic)
            .expect("valid deferred OPEN should retain its challenge deadline");
        let pending_operation_deadline = actor
            .pending_open
            .as_ref()
            .expect("pending OPEN should retain its operation deadline")
            .operation_deadline
            .monotonic;
        assert_eq!(actor.active.key, active_key);
        assert!(actor.candidate.is_none());
        assert!(actor.retiring.is_none());

        // The carrier remains live while the control writer drains the two
        // slots required by one OPEN. The operation deadline is anchored at
        // receipt, and the first challenge deadline is retained rather than
        // regenerated while the pair waits for bounded queue capacity.
        assert!(matches!(
            carrier_receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        control_receiver
            .try_recv()
            .expect("first queued control response should drain");
        control_receiver
            .try_recv()
            .expect("second queued control response should drain");
        assert_eq!(control_receiver.len(), 13);
        actor
            .flush_pending_open()
            .expect("drained queue should admit the deferred OPEN");
        assert!(actor.pending_open.is_none());
        assert_eq!(actor.streams.len(), 9);
        assert!(actor.streams.contains_key(&9));
        assert_eq!(control_receiver.len(), 15);
        assert_eq!(actor.active.key, active_key);
        assert!(matches!(
            carrier_receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        let stream = actor.streams.get(&9).expect("deferred stream admitted");
        assert!(stream.auth.refresh_in_flight);
        assert_eq!(
            stream.auth.deadline.monotonic, pending_auth_deadline,
            "admission retry must not refresh the authorization deadline"
        );
        assert_eq!(
            stream.auth.operation_deadline.monotonic, pending_operation_deadline,
            "admission retry must not refresh the operation deadline"
        );
        assert!(
            !stream
                .auth
                .deadline
                .expired_at(Instant::now(), SystemTime::now())
        );

        let mut queued_messages = Vec::new();
        while let Ok(item) = control_receiver.try_recv() {
            let Message::Text(text) = &item.message else {
                continue;
            };
            queued_messages
                .push(decode_control(text.as_bytes()).expect("queued control JSON should decode"));
        }
        assert!(matches!(
            queued_messages.get(queued_messages.len().saturating_sub(2)),
            Some(ControlMessage::Opened(opened)) if opened.stream_id == 9
        ));
        assert!(matches!(
            queued_messages.last(),
            Some(ControlMessage::AuthorizationChallenge(challenge)) if challenge.stream_id == 9
        ));
        assert_eq!(actor.control_queue.budget.current(), 0);
    }

    #[tokio::test]
    async fn pending_open_fifo_preserves_deadlines_and_admits_without_protocol_failure() {
        let (mut actor, _active_key, _carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        fill_control_queue_before_open(&mut actor)
            .await
            .expect("initial OPEN burst should be admitted");
        actor
            .handle_control(ControlMessage::Open(test_open(9)))
            .await
            .expect("first OPEN should be retained at the atomic pair boundary");
        let first_deadline = actor
            .pending_open
            .as_ref()
            .expect("first deferred OPEN should occupy the atomic head")
            .operation_deadline
            .monotonic;

        actor
            .handle_control(ControlMessage::Open(test_open(10)))
            .await
            .expect("second OPEN should enter the bounded FIFO");
        assert_eq!(actor.pending_open_queue.len(), 1);
        let second_deadline = actor
            .pending_open_queue
            .front()
            .expect("second OPEN should retain its queue entry")
            .operation_deadline
            .monotonic;
        assert!(
            second_deadline >= first_deadline,
            "each queued OPEN must retain its receive-time operation deadline"
        );
        assert_eq!(actor.streams.len(), 8);

        control_receiver
            .try_recv()
            .expect("first queued control response should drain");
        control_receiver
            .try_recv()
            .expect("second queued control response should drain");
        actor
            .flush_pending_open()
            .expect("head OPEN should admit after its pair has room");
        assert!(actor.pending_open.is_none());
        assert_eq!(actor.pending_open_queue.len(), 1);
        assert_eq!(actor.streams.len(), 9);
        assert_eq!(
            actor
                .streams
                .get(&9)
                .expect("head OPEN should be admitted")
                .auth
                .operation_deadline
                .monotonic,
            first_deadline
        );

        control_receiver
            .try_recv()
            .expect("first admitted pair should drain before the FIFO head");
        control_receiver
            .try_recv()
            .expect("second admitted pair should drain before the FIFO head");
        actor
            .flush_pending_open()
            .expect("FIFO OPEN should admit after its pair has room");
        assert!(actor.pending_open.is_none());
        assert!(actor.pending_open_queue.is_empty());
        assert_eq!(actor.streams.len(), 10);
        assert_eq!(
            actor
                .streams
                .get(&10)
                .expect("FIFO OPEN should be admitted")
                .auth
                .operation_deadline
                .monotonic,
            second_deadline
        );
    }

    #[tokio::test]
    async fn deferred_open_refuses_after_drain_without_closing_existing_carrier() {
        let (mut actor, active_key, mut carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        fill_control_queue_before_open(&mut actor)
            .await
            .expect("initial OPEN burst should be admitted");
        let queued_bytes_before_open = actor.control_queue.budget.current();
        let result = actor
            .handle_control(ControlMessage::Open(test_open(9)))
            .await;
        result.expect("queue pressure should defer one bounded OPEN");
        assert_eq!(control_receiver.len(), 15);
        assert_eq!(
            actor.control_queue.budget.current(),
            queued_bytes_before_open
        );
        assert_eq!(actor.streams.len(), 8);
        assert!(actor.streams.contains_key(&1));
        assert!(actor.pending_open.is_some());
        control_receiver
            .try_recv()
            .expect("first queued control response should drain");
        control_receiver
            .try_recv()
            .expect("second queued control response should drain");
        actor.accepting = false;
        actor
            .flush_pending_open()
            .expect("drained queue should emit a bounded refusal");
        assert!(actor.pending_open.is_none());
        assert_eq!(actor.streams.len(), 8);
        assert!(!actor.streams.contains_key(&9));
        assert_eq!(control_receiver.len(), 14);
        assert_eq!(actor.active.key, active_key);
        assert!(actor.candidate.is_none());
        assert!(actor.retiring.is_none());
        assert!(matches!(
            carrier_receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        let mut rejected_stream = false;
        while let Ok(item) = control_receiver.try_recv() {
            let Message::Text(text) = &item.message else {
                continue;
            };
            if let ControlMessage::Rejected(rejected) =
                decode_control(text.as_bytes()).expect("queued control JSON should decode")
                && rejected.stream_id == 9
            {
                assert_eq!(rejected.code, "GOAWAY");
                rejected_stream = true;
            }
        }
        assert!(
            rejected_stream,
            "deferred OPEN should receive a typed refusal"
        );
        assert_eq!(actor.control_queue.budget.current(), 0);
    }

    #[tokio::test]
    async fn deferred_open_expiry_emits_bounded_refusal_without_admission() {
        let (mut actor, active_key, mut carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        fill_control_queue_before_open(&mut actor)
            .await
            .expect("initial OPEN burst should be admitted");
        actor
            .handle_control(ControlMessage::Open(test_open(9)))
            .await
            .expect("queue pressure should defer one bounded OPEN");
        let pending = actor
            .pending_open
            .as_mut()
            .expect("queue pressure should retain the OPEN");
        let expired_started = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("test instant should support a bounded subtraction");
        let expired_wall = SystemTime::now()
            .checked_sub(Duration::from_secs(1))
            .expect("test wall clock should support a bounded subtraction");
        pending
            .authorization
            .as_mut()
            .expect("valid deferred OPEN should retain its challenge")
            .auth_deadline =
            DualDeadline::new(expired_started, expired_wall, Duration::from_millis(1))
                .expect("expired test deadline should be representable");

        control_receiver
            .try_recv()
            .expect("first queued control response should drain");
        control_receiver
            .try_recv()
            .expect("second queued control response should drain");
        actor
            .flush_pending_open()
            .expect("expired OPEN should receive a bounded refusal");
        assert!(actor.pending_open.is_none());
        assert_eq!(actor.streams.len(), 8);
        assert!(!actor.streams.contains_key(&9));
        assert_eq!(control_receiver.len(), 14);
        assert_eq!(actor.active.key, active_key);
        assert!(matches!(
            carrier_receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        let mut saw_expired = false;
        while let Ok(item) = control_receiver.try_recv() {
            let Message::Text(text) = &item.message else {
                continue;
            };
            if let ControlMessage::Rejected(rejected) =
                decode_control(text.as_bytes()).expect("queued control JSON should decode")
                && rejected.stream_id == 9
            {
                assert_eq!(rejected.code, "AUTHORIZATION_EXPIRED");
                saw_expired = true;
            }
        }
        assert!(saw_expired, "expired OPEN should receive a typed refusal");
        assert_eq!(actor.control_queue.budget.current(), 0);
    }

    /// M6-C88: a stream whose authorization has lapsed is expired once.
    /// Before the fix every later tick selected it again, because the
    /// selection never checked `auth.invalidated`, and re-ran the expiry
    /// until the stream was forgotten -- 235 times for one stream in the
    /// M6-C84 reproduction.
    #[tokio::test]
    async fn a_lapsed_stream_is_expired_once_not_on_every_tick() {
        let (mut actor, _active_key, _carrier_receiver, _control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        let mut stream = test_stream();
        stream.sequence = StreamState::new(7, 1_024).expect("test stream sequence");
        stream.auth.confirmed = true;
        stream.auth.refresh_in_flight = false;
        let past = Instant::now()
            .checked_sub(Duration::from_millis(10))
            .expect("a monotonic instant 10 ms ago");
        stream.auth.deadline = DualDeadline::new(past, SystemTime::now(), Duration::from_millis(1))
            .expect("an already-lapsed deadline");
        actor.streams.insert(7, stream);

        for _ in 0..5 {
            actor
                .refresh_authorizations()
                .await
                .expect("a refresh tick over a lapsed stream");
        }
        assert_eq!(actor.expire_stream_calls, 1, "expired once, then skipped");
        assert_eq!(actor.auth_expired_streams, 1);
        assert!(
            actor
                .streams
                .get(&7)
                .is_none_or(|stream| stream.auth.invalidated)
        );
    }

    #[tokio::test]
    async fn refresh_burst_does_not_fail_on_bounded_control_queue() {
        let (mut actor, _active_key, _carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        let operation_deadline =
            DualDeadline::new(Instant::now(), SystemTime::now(), Duration::from_secs(60))
                .expect("test operation deadline");
        for stream_id in 1..=20 {
            let mut stream = test_stream();
            stream.sequence = StreamState::new(stream_id, 1_024).expect("test stream sequence");
            stream.auth.confirmed = true;
            stream.auth.refresh_in_flight = false;
            stream.auth.operation_deadline = operation_deadline;
            actor.streams.insert(stream_id, stream);
        }

        let result = actor.refresh_authorizations().await;
        assert!(
            result.is_ok(),
            "refreshing many established streams must defer bounded queue pressure, got {result:?}"
        );
        assert_eq!(actor.streams.len(), 20);
        assert_eq!(control_receiver.len(), 16);
        assert_eq!(actor.pending_authorization_refreshes.len(), 1);
        let first_pending_deadline = actor
            .pending_authorization_refreshes
            .get(&17)
            .expect("the first deferred refresh should belong to stream 17")
            .auth_deadline
            .monotonic;

        let mut queued_refresh_ids = BTreeSet::new();
        for _ in 0..4 {
            let item = control_receiver
                .try_recv()
                .expect("one queued challenge should drain before each retry");
            let Message::Text(text) = &item.message else {
                panic!("queued refresh should be a text control message");
            };
            if let ControlMessage::AuthorizationChallenge(challenge) =
                decode_control(text.as_bytes()).expect("queued challenge should decode")
            {
                queued_refresh_ids.insert(challenge.stream_id);
            }
            actor
                .refresh_authorizations()
                .await
                .expect("a drained control slot should release one refresh");
            assert!(actor.pending_authorization_refreshes.len() <= 1);
        }
        while let Ok(item) = control_receiver.try_recv() {
            let Message::Text(text) = &item.message else {
                continue;
            };
            if let ControlMessage::AuthorizationChallenge(challenge) =
                decode_control(text.as_bytes()).expect("queued challenge should decode")
            {
                queued_refresh_ids.insert(challenge.stream_id);
            }
        }
        assert!(
            actor.pending_authorization_refreshes.is_empty(),
            "all prepared refreshes should drain without extending their deadlines"
        );
        assert_eq!(queued_refresh_ids.len(), 20);
        assert_eq!(
            actor
                .streams
                .get(&17)
                .expect("stream 17 remains established")
                .auth
                .deadline
                .monotonic,
            first_pending_deadline,
            "a deferred refresh must retain its original absolute deadline"
        );
        for (&stream_id, stream) in &actor.streams {
            assert!(
                stream.auth.refresh_in_flight && queued_refresh_ids.contains(&stream_id),
                "stream {stream_id} was not marked in-flight only after its challenge queued"
            );
        }
        assert_eq!(actor.control_queue.budget.current(), 0);
    }

    /// A filesystem stream's authorization refresh must actually be sent.
    ///
    /// `refresh_authorizations` selects `FS_STREAM_OPERATION` alongside
    /// `echo_stream` and `HTTP_FORWARD_OPERATION`, builds the challenge, and
    /// then re-validates the stream before queueing it.  When that second
    /// match omitted the filesystem operation the challenge was built and
    /// silently dropped every tick, so a filesystem session could never renew
    /// its grant and expired at its admission deadline while it was still in
    /// use.  This is the regression test for docs/tasks.md row **M4-22**.
    #[tokio::test]
    async fn filesystem_stream_authorization_refresh_is_queued() {
        let (mut actor, _active_key, _carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        let operation_deadline =
            DualDeadline::new(Instant::now(), SystemTime::now(), Duration::from_secs(60))
                .expect("test operation deadline");
        let mut stream = test_stream();
        stream.operation = FS_STREAM_OPERATION.to_owned();
        stream.sequence = StreamState::new(1, 1_024).expect("test stream sequence");
        stream.auth.confirmed = true;
        stream.auth.refresh_in_flight = false;
        stream.auth.operation_deadline = operation_deadline;
        actor.streams.insert(1, stream);

        actor
            .refresh_authorizations()
            .await
            .expect("refreshing a filesystem stream must not fail");

        let mut challenged = BTreeSet::new();
        while let Ok(item) = control_receiver.try_recv() {
            let Message::Text(text) = &item.message else {
                continue;
            };
            if let ControlMessage::AuthorizationChallenge(challenge) =
                decode_control(text.as_bytes()).expect("queued challenge should decode")
            {
                challenged.insert(challenge.stream_id);
            }
        }
        assert!(
            challenged.contains(&1),
            "a filesystem stream's refresh challenge must reach the control queue, \
             otherwise the session expires at its admission deadline and cannot renew"
        );
        assert!(
            actor
                .streams
                .get(&1)
                .expect("the filesystem stream remains established")
                .auth
                .refresh_in_flight,
            "the filesystem stream must be marked in flight once its challenge queued"
        );
    }

    /// The deferred half of the same rule: a filesystem refresh that hit
    /// bounded control-queue pressure must still be sent once a slot frees.
    /// `flush_pending_authorization_refreshes` re-validates the operation the
    /// same way, and omitted the filesystem operation for the same reason.
    /// Also docs/tasks.md row **M4-22**.
    #[tokio::test]
    async fn deferred_filesystem_authorization_refresh_is_flushed() {
        let (mut actor, _active_key, _carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        let operation_deadline =
            DualDeadline::new(Instant::now(), SystemTime::now(), Duration::from_secs(60))
                .expect("test operation deadline");
        let mut stream = test_stream();
        stream.operation = FS_STREAM_OPERATION.to_owned();
        stream.sequence = StreamState::new(1, 1_024).expect("test stream sequence");
        stream.auth.confirmed = true;
        stream.auth.refresh_in_flight = false;
        stream.auth.operation_deadline = operation_deadline;
        actor.streams.insert(1, stream);

        let auth_deadline =
            DualDeadline::new(Instant::now(), SystemTime::now(), Duration::from_secs(5))
                .expect("test auth deadline");
        let challenge = AuthorizationChallenge::new(
            message_id(),
            actor.session.session_id.clone(),
            actor.session.epoch,
            1,
            "challenge".to_owned(),
            "nonce".to_owned(),
            "echo".to_owned(),
            "permission".to_owned(),
            1,
        );
        actor.pending_authorization_refreshes.insert(
            1,
            PendingAuthorizationRefresh {
                challenge,
                auth_deadline,
            },
        );

        actor
            .flush_pending_authorization_refreshes(Instant::now(), SystemTime::now())
            .await
            .expect("flushing a deferred filesystem refresh must not fail");

        let mut challenged = BTreeSet::new();
        while let Ok(item) = control_receiver.try_recv() {
            let Message::Text(text) = &item.message else {
                continue;
            };
            if let ControlMessage::AuthorizationChallenge(challenge) =
                decode_control(text.as_bytes()).expect("queued challenge should decode")
            {
                challenged.insert(challenge.stream_id);
            }
        }
        assert!(
            challenged.contains(&1),
            "a deferred filesystem refresh must be queued once control capacity frees"
        );
        assert!(
            actor.pending_authorization_refreshes.is_empty(),
            "the deferred filesystem refresh must not be left pending forever"
        );
    }

    #[tokio::test]
    async fn saturated_carrier_keeps_critical_slots_and_cancellation_responsive() {
        let (sender, mut receiver) = mpsc::channel(M2_CARRIER_QUEUE_FRAMES);
        for _ in 0..(M2_CARRIER_QUEUE_FRAMES - M2_CARRIER_RESERVED_FRAMES) {
            sender
                .try_send(CarrierCommand::Barrier)
                .expect("bulk queue should accept its non-reserved capacity");
        }
        assert_eq!(sender.capacity(), M2_CARRIER_RESERVED_FRAMES);

        let mut pending = PendingCarrierControl::default();
        for acknowledged in 0..1_024 {
            pending.record_ack(acknowledged);
            pending
                .record_window(1)
                .expect("bounded test counter cannot overflow");
        }
        assert_eq!(pending.acknowledged, Some(1_023));
        assert_eq!(pending.released_window_bytes, 1_024);

        // Critical control messages can still make progress from the reserved
        // part of the fixed carrier queue while bulk work remains saturated.
        for _ in 0..M2_CARRIER_RESERVED_FRAMES {
            sender
                .try_send(CarrierCommand::Message(Message::Pong(Vec::new().into())))
                .expect("reserved carrier slot should accept control traffic");
        }
        assert_eq!(sender.capacity(), 0);
        assert!(
            sender.try_send(CarrierCommand::Barrier).is_err(),
            "the fixed queue must remain bounded"
        );

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(cancellation.is_cancelled());

        drop(sender);
        while receiver.recv().await.is_some() {}
    }

    #[tokio::test]
    async fn pong_flood_coalesces_without_consuming_critical_slots() {
        let (mut actor, key, mut receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        for _ in 0..(M2_CARRIER_QUEUE_FRAMES - M2_CARRIER_RESERVED_FRAMES) {
            actor
                .active
                .tx
                .try_send(CarrierCommand::Barrier)
                .expect("bulk queue should accept its non-reserved capacity");
        }
        actor
            .send_carrier_message(&key, Message::Pong(vec![1].into()))
            .expect("first full heartbeat is deferred");
        actor
            .send_carrier_message(&key, Message::Pong(vec![2].into()))
            .expect("later heartbeat replaces the pending one");
        assert_eq!(actor.pending_pongs.len(), 1);

        let ack = Frame::ack(1, 1, 1, 1).encode().expect("ACK frame encodes");
        for _ in 0..M2_CARRIER_RESERVED_FRAMES {
            actor
                .queue_reserved_carrier_bytes(&key, ack.clone())
                .expect("critical ACK uses the reserved slot");
        }
        assert_eq!(actor.active.tx.capacity(), 0);
        assert_eq!(actor.pending_pongs.len(), 1);

        drop(actor);
        while receiver.recv().await.is_some() {}
    }

    /// A relay FIN can arrive after the connector has already reset a stream
    /// whose authorization was invalidated: the invalidation travels on the
    /// control socket while the FIN travels on the data carrier.  That FIN
    /// must not be retained as adapter input debt.  An invalidated stream can
    /// never be confirmed, so nothing would ever drain it, and the owner's
    /// STREAM_FORGET proof rejects a stream still holding undrained input,
    /// which fails the whole session with a protocol error.
    #[tokio::test]
    async fn invalidated_stream_retains_no_undrainable_input_debt() {
        let (mut actor, key, mut receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        let mut stream = test_stream();
        stream.sequence = StreamState::new(7, 1_024).expect("test stream sequence");
        actor.streams.insert(7, stream);
        actor
            .expire_stream(7)
            .await
            .expect("an invalidated stream resets");
        assert!(actor.streams[&7].auth.invalidated);
        actor
            .handle_frame(key.clone(), Frame::fin(1, 1, 7, 1, 0))
            .await
            .expect("a late relay FIN is accepted");
        let stream = &actor.streams[&7];
        assert!(
            stream.pending.is_empty() && stream.pending_bytes == 0,
            "an invalidated stream must not retain input nothing can drain"
        );

        drop(actor);
        while receiver.recv().await.is_some() {}
    }

    #[tokio::test]
    async fn saturated_carrier_preserves_data_fifo_and_reserved_feedback() {
        let (mut actor, key, mut receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        for _ in 0..(M2_CARRIER_QUEUE_FRAMES - M2_CARRIER_RESERVED_FRAMES) {
            actor
                .active
                .tx
                .try_send(CarrierCommand::Barrier)
                .expect("bulk carrier queue should accept its non-reserved capacity");
        }

        let mut stream = test_stream();
        stream.sequence = StreamState::new(7, 1_024).expect("test stream sequence");
        stream.auth.confirmed = true;
        stream.auth.refresh_in_flight = false;
        actor.streams.insert(7, stream);
        let first = record(b"first");
        let second = record(b"second");

        // Exercise the authenticated inbound path rather than appending
        // PendingOutput values directly. The full carrier leaves only reserved
        // capacity, so both DATA responses and the terminal FIN are retained
        // in the same-stream FIFO while ACK/WINDOW feedback is coalesced.
        actor
            .handle_frame(key.clone(), Frame::data(1, 1, 7, 1, 0, first.clone()))
            .await
            .expect("first DATA should defer under carrier pressure");
        actor
            .handle_frame(key.clone(), Frame::data(1, 1, 7, 2, 0, second.clone()))
            .await
            .expect("second DATA should defer behind the first");
        actor
            .handle_frame(key.clone(), Frame::fin(1, 1, 7, 3, 0))
            .await
            .expect("FIN should defer behind both DATA records");

        assert_eq!(actor.pending_outputs.len(), 3);
        assert_eq!(
            actor
                .pending_outputs
                .iter()
                .map(|output| output.kind)
                .collect::<Vec<_>>(),
            vec![FrameKind::Data, FrameKind::Data, FrameKind::Fin]
        );
        let pending_control = actor
            .active
            .pending_controls
            .get(&7)
            .expect("inbound DATA/FIN should retain feedback for the full carrier");
        assert_eq!(pending_control.acknowledged, Some(3));
        assert_eq!(
            pending_control.released_window_bytes,
            first.len() + second.len()
        );

        while receiver.try_recv().is_ok() {}
        actor
            .flush_pending_outputs()
            .await
            .expect("drained carrier should flush the retained FIFO");
        actor
            .flush_pending_carrier_controls()
            .expect("reserved ACK/WINDOW feedback should flush after the FIFO");
        assert!(actor.pending_outputs.is_empty());
        assert!(actor.active.pending_controls.is_empty());

        let mut frames = Vec::new();
        while let Ok(command) = receiver.try_recv() {
            if let CarrierCommand::Frame(frame) = command {
                frames.push(Frame::decode(&frame.bytes).expect("deferred frame should decode"));
            }
        }
        assert_eq!(frames.len(), 5);
        assert_eq!(frames[0].kind, FrameKind::Data);
        assert_eq!(frames[1].kind, FrameKind::Data);
        assert_eq!(frames[2].kind, FrameKind::Fin);
        assert_eq!(frames[0].sequence, 1);
        assert_eq!(frames[1].sequence, 2);
        assert_eq!(frames[2].sequence, 3);
        assert_eq!(frames[0].payload, first);
        assert_eq!(frames[1].payload, second);
        assert_eq!(frames[3].kind, FrameKind::Ack);
        assert_eq!(frames[3].ack, 3);
        assert_eq!(frames[4].kind, FrameKind::WindowUpdate);
        assert_eq!(
            frames[4].window,
            1_024 + first.len() as u64 + second.len() as u64
        );
    }

    #[test]
    fn retained_same_stream_outputs_cannot_be_overtaken_by_terminal_frame() {
        let mut pending = VecDeque::from([PendingOutput {
            stream_id: 7,
            kind: FrameKind::Data,
            payload: vec![1],
            reset_reason: None,
        }]);
        assert!(has_pending_output_for_stream(&pending, 7));
        assert!(!has_pending_output_for_stream(&pending, 8));

        pending.push_back(PendingOutput {
            stream_id: 7,
            kind: FrameKind::Data,
            payload: vec![2],
            reset_reason: None,
        });
        pending.push_back(PendingOutput {
            stream_id: 7,
            kind: FrameKind::Fin,
            payload: Vec::new(),
            reset_reason: None,
        });
        assert_eq!(
            pending.iter().map(|output| output.kind).collect::<Vec<_>>(),
            vec![FrameKind::Data, FrameKind::Data, FrameKind::Fin]
        );
    }

    #[tokio::test]
    async fn housekeeping_frames_do_not_generate_ack_feedback() {
        let (mut actor, key, _receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        actor.streams.insert(1, test_stream());
        actor
            .handle_frame(key.clone(), Frame::ack(1, 1, 1, 0))
            .await
            .expect("ACK is accepted without feedback");
        actor
            .handle_frame(key, Frame::window_update(1, 1, 1, 2_048))
            .await
            .expect("WINDOW_UPDATE is accepted without feedback");
        assert!(actor.active.pending_controls.is_empty());
    }

    #[test]
    fn minimum_queue_budget_retains_bulk_and_critical_capacity() {
        let minimum = 256 * 1024;
        let reserved = critical_reserved_bytes(minimum);
        assert_eq!(reserved, minimum / 4);
        let maximum_record = Frame::data(1, 1, 1, 1, 0, vec![0x5a; MAX_PAYLOAD_LEN])
            .encode()
            .expect("maximum record frame fits protocol bound");
        assert!(
            minimum - reserved >= maximum_record.len().saturating_mul(2),
            "minimum budget must retain a record and its bounded carrier copy"
        );
        assert_eq!(
            critical_reserved_bytes(8 * 1024 * 1024),
            M2_CARRIER_RESERVED_BYTES
        );
    }

    #[test]
    fn m2_hello_advertises_owner_fencing_opt_in() {
        let ControlMessage::Hello(hello) = m2_hello(&RuntimeConfig::default()) else {
            panic!("M2 hello must be HELLO");
        };
        assert!(
            hello
                .features
                .iter()
                .any(|feature| feature == OWNER_FENCING_FEATURE)
        );
    }

    #[test]
    fn owner_fence_context_rejects_stale_welcome_identity() {
        let welcome = owner_fence_welcome();
        let fence = OwnerFence::new(
            "fence",
            "session",
            7,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "nonce",
            20_000,
        );
        assert!(validate_owner_fence_context(&fence, &welcome, TEST_OWNER_ID).is_err());
    }

    #[test]
    fn owner_fence_gate_blocks_admission_until_acknowledgement() {
        let welcome = owner_fence_welcome();
        let fence = OwnerFence::new(
            "fence",
            welcome.session_id.clone(),
            welcome.epoch,
            TEST_OWNER_ID,
            "nonce",
            20_000,
        );
        validate_owner_fence_context(&fence, &welcome, TEST_OWNER_ID).expect("fence context");
        let mut state = OwnerFenceState::new(welcome.session_id.clone()).expect("state");
        let acknowledgement = state.accept_fence(&fence, "ack", 100).expect("fence");
        assert!(state.authorize(TEST_OWNER_ID, welcome.epoch, 101).is_err());
        state
            .acknowledgement_sent(&acknowledgement, 102)
            .expect("acknowledgement");
        state
            .authorize(TEST_OWNER_ID, welcome.epoch, 20_000)
            .expect("latched owner remains authorized");
    }

    #[test]
    fn owner_fence_late_ack_is_rejected_without_data_admission() {
        let welcome = owner_fence_welcome();
        let fence = OwnerFence::new(
            "fence",
            welcome.session_id.clone(),
            welcome.epoch,
            TEST_OWNER_ID,
            "nonce",
            1,
        );
        let mut state = OwnerFenceState::new(welcome.session_id.clone()).expect("state");
        let acknowledgement = state.accept_fence(&fence, "ack", 100).expect("fence");
        assert!(state.acknowledgement_sent(&acknowledgement, 101).is_err());
        assert!(state.authorize(TEST_OWNER_ID, welcome.epoch, 102).is_err());
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

    #[tokio::test]
    async fn non_stream_echo_maximum_body_with_canary_stays_within_credit() {
        let (mut actor, _active_key, mut carrier_receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        let mut stream = test_stream();
        stream.operation = "echo".to_owned();
        stream.export.device_canary = Some("c".repeat(M2_MAX_CANARY_BYTES));
        stream.auth.confirmed = true;
        stream.auth.refresh_in_flight = false;
        stream.sequence = StreamState::with_credits(
            1,
            (M2_MAX_RECORD_BYTES + M2_MAX_CANARY_BYTES) as u64,
            (M2_MAX_RECORD_BYTES + M2_MAX_CANARY_BYTES) as u64,
        )
        .expect("maximum non-stream echo credit is valid");
        actor.streams.insert(1, stream);

        actor
            .dispatch_payload(1, vec![0x5a; M2_MAX_RECORD_BYTES])
            .await
            .expect("maximum non-stream echo should emit both response frames");

        let mut frames = Vec::new();
        while let Ok(command) = carrier_receiver.try_recv() {
            if let CarrierCommand::Frame(frame) = command {
                frames.push(Frame::decode(&frame.bytes).expect("response frame decodes"));
            }
        }
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].kind, FrameKind::Data);
        assert_eq!(frames[1].kind, FrameKind::Data);
        assert_eq!(frames[0].payload.len(), MAX_PAYLOAD_LEN);
        assert_eq!(frames[1].payload.len(), M2_MAX_CANARY_BYTES);
        assert_eq!(frames[0].sequence, 1);
        assert_eq!(frames[1].sequence, 2);
        assert_eq!(
            frames
                .iter()
                .map(|frame| frame.payload.len())
                .sum::<usize>(),
            M2_MAX_RECORD_BYTES + M2_MAX_CANARY_BYTES
        );
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
            http: None,
            fs_authority: None,
        }
    }

    fn test_owner_forget_sequence(stream_id: u64) -> (StreamState, ResumeDirectionState) {
        let mut relay = StreamState::new(stream_id, 1_024).expect("relay sequence");
        let mut connector = StreamState::new(stream_id, 1_024).expect("connector sequence");
        let connector_fin = Frame::fin(1, 1, stream_id, 1, 0);
        connector
            .send_frame(Direction::ConnectorToRelay, &connector_fin)
            .expect("connector FIN is admitted");
        relay
            .receive_frame(Direction::ConnectorToRelay, &connector_fin)
            .expect("relay receives connector FIN");
        relay
            .mark_delivered(Direction::ConnectorToRelay, 1)
            .expect("relay delivers connector FIN");
        let relay_fin = Frame::fin(1, 1, stream_id, 1, 1);
        relay
            .send_frame(Direction::RelayToConnector, &relay_fin)
            .expect("relay FIN is admitted");
        connector
            .receive_frame(Direction::RelayToConnector, &relay_fin)
            .expect("connector receives relay FIN");
        connector
            .mark_delivered(Direction::RelayToConnector, 1)
            .expect("connector delivers relay FIN");
        let connector_ack = Frame::ack(1, 1, stream_id, 1);
        connector
            .send_frame(Direction::ConnectorToRelay, &connector_ack)
            .expect("connector ACK is admitted");
        relay
            .receive_frame(Direction::ConnectorToRelay, &connector_ack)
            .expect("relay receives connector ACK");
        let owner_state = ResumeDirectionState::from_sequence_snapshot(
            stream_id,
            relay.snapshot().direction(Direction::RelayToConnector),
        )
        .expect("relay sender snapshot encodes");
        (connector, owner_state)
    }

    fn test_stream_with_owner_forget_proof(stream_id: u64) -> (M2Stream, ResumeDirectionState) {
        let (sequence, final_state) = test_owner_forget_sequence(stream_id);
        let mut stream = test_stream();
        stream.sequence = sequence;
        stream.input_fin = true;
        stream.output_fin = true;
        (stream, final_state)
    }

    fn test_owner_forget_before_owner_ack(stream_id: u64) -> (StreamState, ResumeDirectionState) {
        let mut relay = StreamState::new(stream_id, 1_024).expect("relay sequence");
        let mut connector = StreamState::new(stream_id, 1_024).expect("connector sequence");

        let connector_fin = Frame::fin(1, 1, stream_id, 1, 0);
        connector
            .send_frame(Direction::ConnectorToRelay, &connector_fin)
            .expect("connector FIN is admitted");
        relay
            .receive_frame(Direction::ConnectorToRelay, &connector_fin)
            .expect("relay receives connector FIN");
        relay
            .mark_delivered(Direction::ConnectorToRelay, 1)
            .expect("relay delivers connector FIN");

        // Keep the relay FIN's ACK cursor at zero. This leaves the connector's
        // C2R sender awaiting the owner's data-channel ACK while the connector
        // can still return its final C2R ACK to the owner.
        let relay_fin = Frame::fin(1, 1, stream_id, 1, 0);
        relay
            .send_frame(Direction::RelayToConnector, &relay_fin)
            .expect("relay FIN is admitted");
        connector
            .receive_frame(Direction::RelayToConnector, &relay_fin)
            .expect("connector receives relay FIN");
        connector
            .mark_delivered(Direction::RelayToConnector, 1)
            .expect("connector delivers relay FIN");

        let connector_ack = Frame::ack(1, 1, stream_id, 1);
        connector
            .send_frame(Direction::ConnectorToRelay, &connector_ack)
            .expect("connector final C2R ACK is admitted");
        relay
            .receive_frame(Direction::ConnectorToRelay, &connector_ack)
            .expect("relay observes final C2R ACK");
        let owner_state = ResumeDirectionState::from_sequence_snapshot(
            stream_id,
            relay.snapshot().direction(Direction::RelayToConnector),
        )
        .expect("owner terminal snapshot encodes");
        (connector, owner_state)
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
    fn stream_forget_accepts_complementary_sender_receiver_state() {
        let stream_id = 7;
        let mut relay = StreamState::new(stream_id, 128).expect("relay sequence");
        let mut connector = StreamState::new(stream_id, 128).expect("connector sequence");

        let request = Frame::data(1, 1, stream_id, 1, 0, b"req".to_vec());
        connector
            .send_frame(Direction::ConnectorToRelay, &request)
            .expect("connector DATA is admitted");
        relay
            .receive_frame(Direction::ConnectorToRelay, &request)
            .expect("relay receives connector DATA");
        let request_fin = Frame::fin(1, 1, stream_id, 2, 0);
        connector
            .send_frame(Direction::ConnectorToRelay, &request_fin)
            .expect("connector FIN is admitted");
        relay
            .receive_frame(Direction::ConnectorToRelay, &request_fin)
            .expect("relay receives connector FIN");
        relay
            .mark_delivered(Direction::ConnectorToRelay, 2)
            .expect("relay delivers connector request");

        let response = Frame::data(1, 1, stream_id, 1, 2, b"resp".to_vec());
        relay
            .send_frame(Direction::RelayToConnector, &response)
            .expect("relay DATA is admitted");
        connector
            .receive_frame(Direction::RelayToConnector, &response)
            .expect("connector receives relay DATA");
        let response_fin = Frame::fin(1, 1, stream_id, 2, 2);
        relay
            .send_frame(Direction::RelayToConnector, &response_fin)
            .expect("relay FIN is admitted");
        connector
            .receive_frame(Direction::RelayToConnector, &response_fin)
            .expect("connector receives relay FIN");
        connector
            .mark_delivered(Direction::RelayToConnector, 2)
            .expect("connector delivers relay response");

        let final_ack = Frame::ack(1, 1, stream_id, 2);
        connector
            .send_frame(Direction::ConnectorToRelay, &final_ack)
            .expect("connector ACK is admitted");
        relay
            .receive_frame(Direction::ConnectorToRelay, &final_ack)
            .expect("relay receives connector ACK");

        let owner_state = ResumeDirectionState::from_sequence_snapshot(
            stream_id,
            relay.snapshot().direction(Direction::RelayToConnector),
        )
        .expect("relay sender snapshot encodes");
        M2Actor::validate_owner_stream_forget_state(
            &connector,
            Direction::RelayToConnector,
            &owner_state,
        )
        .expect("complementary endpoint state is valid");

        let mut byte_mismatch = owner_state.clone();
        byte_mismatch.sent_bytes += 1;
        assert!(
            M2Actor::validate_owner_stream_forget_state(
                &connector,
                Direction::RelayToConnector,
                &byte_mismatch,
            )
            .is_err()
        );

        let mut terminal_mismatch = owner_state.clone();
        terminal_mismatch.send_terminal =
            Some(tunnel_protocol::rotation_control::TerminalState::Reset { reason: 9 });
        assert!(
            M2Actor::validate_owner_stream_forget_state(
                &connector,
                Direction::RelayToConnector,
                &terminal_mismatch,
            )
            .is_err()
        );

        let mut replay_gap = owner_state.clone();
        replay_gap.peer_acked = replay_gap.last_emitted - 1;
        replay_gap.replay_floor = Some(replay_gap.last_emitted);
        assert!(
            M2Actor::validate_owner_stream_forget_state(
                &connector,
                Direction::RelayToConnector,
                &replay_gap,
            )
            .is_err()
        );

        let mut wrong_direction = owner_state;
        assert!(
            M2Actor::validate_owner_stream_forget_state(
                &connector,
                Direction::ConnectorToRelay,
                &wrong_direction,
            )
            .is_err()
        );
        wrong_direction.stream_id = stream_id + 1;
        assert!(
            M2Actor::validate_owner_stream_forget_state(
                &connector,
                Direction::RelayToConnector,
                &wrong_direction,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn stream_forget_waits_for_owner_ack_on_independent_data_channel() {
        let stream_id = 41;
        let mut relay = StreamState::new(stream_id, 1_024).expect("relay sequence");
        let mut connector = StreamState::new(stream_id, 1_024).expect("connector sequence");

        // Complete both terminal directions, but deliberately send the relay's
        // terminal frame without an ACK for the connector's C2R FIN. The
        // connector can therefore send its final C2R ACK to the owner while
        // its local C2R sender still has peer_acked < last_emitted. The owner
        // observes that ACK and may publish STREAM_FORGET before its separate
        // data-channel ACK reaches the connector.
        let connector_fin = Frame::fin(1, 1, stream_id, 1, 0);
        connector
            .send_frame(Direction::ConnectorToRelay, &connector_fin)
            .expect("connector FIN is admitted");
        relay
            .receive_frame(Direction::ConnectorToRelay, &connector_fin)
            .expect("relay receives connector FIN");
        relay
            .mark_delivered(Direction::ConnectorToRelay, 1)
            .expect("relay delivers connector FIN");

        let relay_fin = Frame::fin(1, 1, stream_id, 1, 0);
        relay
            .send_frame(Direction::RelayToConnector, &relay_fin)
            .expect("relay FIN is admitted");
        connector
            .receive_frame(Direction::RelayToConnector, &relay_fin)
            .expect("connector receives relay FIN");
        connector
            .mark_delivered(Direction::RelayToConnector, 1)
            .expect("connector delivers relay FIN");

        let connector_ack = Frame::ack(1, 1, stream_id, 1);
        connector
            .send_frame(Direction::ConnectorToRelay, &connector_ack)
            .expect("connector final C2R ACK is admitted");
        relay
            .receive_frame(Direction::ConnectorToRelay, &connector_ack)
            .expect("relay observes the final C2R ACK");

        let relay_snapshot = relay.snapshot();
        assert_eq!(
            relay_snapshot
                .direction(Direction::ConnectorToRelay)
                .receive_terminal,
            Some(tunnel_protocol::sequence::Terminal::Fin)
        );
        assert_eq!(
            relay_snapshot
                .direction(Direction::ConnectorToRelay)
                .delivered_contiguous,
            1
        );
        let owner_state = ResumeDirectionState::from_sequence_snapshot(
            stream_id,
            relay_snapshot.direction(Direction::RelayToConnector),
        )
        .expect("owner terminal snapshot encodes");
        assert_eq!(owner_state.stream_id, stream_id);
        assert_eq!(
            owner_state.send_terminal,
            Some(tunnel_protocol::rotation_control::TerminalState::Fin)
        );
        assert_eq!(owner_state.peer_acked, owner_state.last_emitted);
        assert_eq!(
            connector
                .direction(Direction::ConnectorToRelay)
                .peer_acked(),
            0,
            "the connector has sent its final C2R ACK, but the owner's data ACK has not arrived"
        );
        assert_eq!(
            connector
                .direction(Direction::ConnectorToRelay)
                .send_terminal(),
            Some(tunnel_protocol::sequence::Terminal::Fin)
        );
        assert_eq!(
            connector
                .direction(Direction::RelayToConnector)
                .receive_terminal(),
            Some(tunnel_protocol::sequence::Terminal::Fin)
        );

        assert!(
            M2Actor::validate_owner_stream_forget_state(
                &connector,
                Direction::RelayToConnector,
                &owner_state,
            )
            .is_err(),
            "the owner proof is valid while the connector sender is still awaiting its data ACK"
        );

        let (mut actor, key, mut carrier_receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        let mut stream = test_stream();
        stream.sequence = connector;
        stream.input_fin = true;
        stream.output_fin = true;
        actor.streams.insert(stream_id, stream);
        let forget = tunnel_protocol::rotation_control::StreamForget {
            message_id: "forget-before-owner-ack".to_owned(),
            reply_to: String::new(),
            session_id: "session".to_owned(),
            epoch: 1,
            stream_id,
            operation_id: "operation".to_owned(),
            direction: Direction::RelayToConnector,
            final_state: owner_state,
        };
        assert_eq!(forget.session_id, "session");
        assert_eq!(forget.epoch, 1);
        assert_eq!(forget.stream_id, stream_id);
        assert_eq!(forget.operation_id, "operation");
        assert_eq!(
            actor
                .streams
                .get(&stream_id)
                .expect("stream identity is retained")
                .operation_id,
            forget.operation_id
        );

        // This is the independent control-channel overtaking point. The proof
        // is authenticated and terminal, but local C2R peer_acked is still
        // behind; the staged runtime must retain the stream for revalidation.
        actor
            .handle_control(ControlMessage::StreamForget(forget))
            .await
            .expect("overtaking STREAM_FORGET enters bounded proof-pending state");
        assert!(actor.streams.contains_key(&stream_id));
        assert!(
            actor
                .pending_forgets
                .get(&stream_id)
                .is_some_and(|pending| {
                    pending.barriers_queued.contains(&key) && pending.barriers_completed.is_empty()
                })
        );
        assert!(matches!(
            carrier_receiver
                .try_recv()
                .expect("proof-pending FORGET queues a carrier barrier"),
            CarrierCommand::Barrier
        ));

        // The owner's final data-channel ACK arrives after STREAM_FORGET. It
        // closes the exact C2R sender proof without changing the terminal
        // identity or either stream cursor.
        actor
            .handle_frame(key.clone(), Frame::ack(1, 1, stream_id, 1))
            .await
            .expect("later owner ACK must converge the local sender proof");
        let local = actor
            .streams
            .get(&stream_id)
            .expect("stream remains until its barrier completes")
            .sequence
            .snapshot();
        assert_eq!(
            local.direction(Direction::ConnectorToRelay).peer_acked,
            local.direction(Direction::ConnectorToRelay).last_emitted
        );
        assert_eq!(
            local.direction(Direction::ConnectorToRelay).send_terminal,
            Some(tunnel_protocol::sequence::Terminal::Fin)
        );
        assert_eq!(
            local
                .direction(Direction::RelayToConnector)
                .receive_terminal,
            Some(tunnel_protocol::sequence::Terminal::Fin)
        );
        assert!(actor.streams.contains_key(&stream_id));
        let pending_proof = actor
            .pending_forgets
            .get(&stream_id)
            .expect("proof remains retained until the barrier completes");
        M2Actor::validate_owner_stream_forget_state(
            &actor
                .streams
                .get(&stream_id)
                .expect("stream remains for final validation")
                .sequence,
            Direction::RelayToConnector,
            &pending_proof.forget.final_state,
        )
        .expect("the later owner ACK completes the exact terminal proof");

        actor
            .handle_barrier_complete(&key)
            .expect("the retained carrier barrier completes after the ACK");
        assert!(
            !actor.streams.contains_key(&stream_id),
            "reclamation must wait for both the later ACK and the carrier barrier"
        );
        assert!(!actor.pending_forgets.contains_key(&stream_id));
        assert_eq!(actor.forgotten_stream_through, stream_id);
    }

    /// An HTTP stream whose request FIN was received in order.
    fn http_stream_with_request_fin(stream_id: u64) -> M2Stream {
        let (notifier, _signal) = tunnel_http_bridge::reset_signal_pair();
        let mut stream = test_stream();
        stream.operation = HTTP_FORWARD_OPERATION.to_owned();
        stream.operation_id = format!("http-operation-{stream_id}");
        stream.sequence = StreamState::new(stream_id, 1024).expect("test sequence");
        stream.http = Some(m2_http::DeviceHttpState::new(
            notifier,
            1024,
            tunnel_http_bridge::PauseController::new(false),
            None,
        ));
        stream
            .sequence
            .receive_frame(
                Direction::RelayToConnector,
                &Frame::fin(1, 1, stream_id, 1, 0),
            )
            .expect("request FIN");
        stream
    }

    fn cancel_for(stream_id: u64) -> Cancel {
        Cancel::new(
            format!("cancel-{stream_id}"),
            "session",
            1,
            stream_id,
            format!("http-operation-{stream_id}"),
        )
    }

    /// Review item 2: an owner CANCEL for an exchange whose response FIN is
    /// already sequenced, or already retained behind a writer freeze, must not
    /// queue a RESET after that FIN: the owner reclaims the stream on both
    /// FINs and never acknowledges the trailing RESET.
    #[tokio::test]
    async fn owner_cancel_after_a_settled_http_exchange_emits_no_reset() {
        let (mut actor, _key, mut carrier_receiver, _control) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);

        let sequenced = 11;
        let mut stream = http_stream_with_request_fin(sequenced);
        stream.output_fin = true;
        actor.streams.insert(sequenced, stream);
        actor
            .handle_cancel(cancel_for(sequenced))
            .await
            .expect("cancel is accepted");
        let stream = actor.streams.get(&sequenced).expect("stream retained");
        assert!(
            !stream.output_reset && !stream.reset_queued,
            "no RESET after the sequenced FIN"
        );
        assert!(carrier_receiver.try_recv().is_err(), "nothing was queued");
        assert!(
            stream
                .http
                .as_ref()
                .is_some_and(|http| http.cancel_received)
        );

        let deferred = 13;
        actor
            .streams
            .insert(deferred, http_stream_with_request_fin(deferred));
        actor.writes_frozen = true;
        actor
            .emit_or_defer(PendingOutput {
                stream_id: deferred,
                kind: FrameKind::Fin,
                payload: Vec::new(),
                reset_reason: None,
            })
            .await
            .expect("FIN deferred behind the freeze");
        actor
            .handle_cancel(cancel_for(deferred))
            .await
            .expect("cancel is accepted");
        let kinds = actor
            .pending_outputs
            .iter()
            .filter(|output| output.stream_id == deferred)
            .map(|output| output.kind)
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            vec![FrameKind::Fin],
            "no RESET behind the deferred FIN"
        );
        let stream = actor.streams.get(&deferred).expect("stream retained");
        assert!(!stream.reset_queued);

        // Expiry follows the same rule for the deferred FIN.
        actor
            .expire_stream(deferred)
            .await
            .expect("expiry of a settled exchange is a no-op");
        assert_eq!(
            actor
                .pending_outputs
                .iter()
                .filter(|output| output.stream_id == deferred)
                .count(),
            1
        );

        // An unfinished exchange is still reset by the CANCEL.
        let unfinished = 15;
        let mut stream = http_stream_with_request_fin(unfinished);
        stream.sequence = StreamState::new(unfinished, 1024).expect("test sequence");
        actor.streams.insert(unfinished, stream);
        actor
            .handle_cancel(cancel_for(unfinished))
            .await
            .expect("cancel is accepted");
        assert!(
            actor
                .pending_outputs
                .iter()
                .any(|output| output.stream_id == unfinished && output.kind == FrameKind::Reset),
            "an unfinished exchange still gets its RESET"
        );
    }

    #[tokio::test]
    async fn stream_forget_proof_deadline_is_absolute_and_not_reset_by_retry() {
        let stream_id = 42;
        let (sequence, final_state) = test_owner_forget_before_owner_ack(stream_id);
        let (mut actor, key, mut carrier_receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        let mut stream = test_stream();
        stream.sequence = sequence;
        stream.input_fin = true;
        stream.output_fin = true;
        actor.streams.insert(stream_id, stream);
        let forget = tunnel_protocol::rotation_control::StreamForget {
            message_id: "forget-deadline-fixed".to_owned(),
            reply_to: String::new(),
            session_id: "session".to_owned(),
            epoch: 1,
            stream_id,
            operation_id: "operation".to_owned(),
            direction: Direction::RelayToConnector,
            final_state,
        };

        actor
            .handle_control(ControlMessage::StreamForget(forget.clone()))
            .await
            .expect("incomplete but convergent proof is retained");
        let initial_deadline = actor
            .pending_forgets
            .get(&stream_id)
            .and_then(|pending| pending.proof_deadline)
            .expect("proof-pending FORGET has an absolute deadline");
        assert!(matches!(
            carrier_receiver
                .try_recv()
                .expect("initial FORGET barrier is queued"),
            CarrierCommand::Barrier
        ));

        actor
            .handle_control(ControlMessage::StreamForget(forget))
            .await
            .expect("same proof is idempotent while it remains pending");
        assert_eq!(
            actor
                .pending_forgets
                .get(&stream_id)
                .and_then(|pending| pending.proof_deadline),
            Some(initial_deadline),
            "a duplicate control message must not extend the proof window"
        );

        // Completing the physical barrier before the missing ACK only resets
        // the bounded carrier barrier set; it must not renew the proof clock.
        actor
            .handle_barrier_complete(&key)
            .expect("premature barrier completion remains bounded");
        assert!(actor.streams.contains_key(&stream_id));
        assert_eq!(
            actor
                .pending_forgets
                .get(&stream_id)
                .and_then(|pending| pending.proof_deadline),
            Some(initial_deadline),
            "barrier retry must retain the original absolute deadline"
        );
        assert!(
            actor
                .pending_forgets
                .get(&stream_id)
                .is_some_and(|pending| pending.barriers_queued.is_empty())
        );

        actor
            .pending_forgets
            .get_mut(&stream_id)
            .expect("pending proof remains retained")
            .proof_deadline = Some(Instant::now() - Duration::from_millis(1));
        let error = actor
            .retry_pending_forget_barriers()
            .expect_err("an expired proof must fail closed");
        assert!(matches!(
            error,
            ClientError::Protocol(message)
                if message == "STREAM_FORGET terminal proof did not converge before its deadline"
        ));
        assert!(actor.streams.contains_key(&stream_id));
        assert!(actor.pending_forgets.contains_key(&stream_id));
    }

    #[tokio::test]
    async fn stream_forget_late_owner_ack_after_expiry_cannot_rescue_stream() {
        let stream_id = 43;
        let (sequence, final_state) = test_owner_forget_before_owner_ack(stream_id);
        let (mut actor, key, mut carrier_receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        let mut stream = test_stream();
        stream.sequence = sequence;
        stream.input_fin = true;
        stream.output_fin = true;
        actor.streams.insert(stream_id, stream);
        actor
            .handle_stream_forget(tunnel_protocol::rotation_control::StreamForget {
                message_id: "forget-late-ack-after-expiry".to_owned(),
                reply_to: String::new(),
                session_id: "session".to_owned(),
                epoch: 1,
                stream_id,
                operation_id: "operation".to_owned(),
                direction: Direction::RelayToConnector,
                final_state,
            })
            .expect("incomplete but convergent proof is retained");
        assert!(matches!(
            carrier_receiver
                .try_recv()
                .expect("initial FORGET barrier is queued"),
            CarrierCommand::Barrier
        ));
        actor
            .pending_forgets
            .get_mut(&stream_id)
            .expect("proof remains retained")
            .proof_deadline = Some(Instant::now() - Duration::from_millis(1));

        let error = actor
            .handle_frame(key, Frame::ack(1, 1, stream_id, 1))
            .await
            .expect_err("an ACK after the fixed deadline must not rescue the proof");
        assert!(matches!(
            error,
            ClientError::Protocol(message)
                if message == "STREAM_FORGET terminal proof did not converge before its deadline"
        ));
        let stream = actor
            .streams
            .get(&stream_id)
            .expect("late ACK cannot reclaim the stream");
        assert_eq!(
            stream
                .sequence
                .direction(Direction::ConnectorToRelay)
                .peer_acked(),
            stream
                .sequence
                .direction(Direction::ConnectorToRelay)
                .last_emitted(),
            "the ACK may be observed, but expiry remains terminal"
        );
        assert!(actor.pending_forgets.contains_key(&stream_id));
        assert_eq!(actor.forgotten_stream_through, 0);
    }

    #[tokio::test]
    async fn stream_forget_clears_ack_deadline_but_waits_for_active_roster_and_barriers() {
        let (mut actor, active_key, mut active_receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        let candidate_key = CarrierKey::new(2, "candidate");
        let (candidate_tx, mut candidate_receiver) = mpsc::channel(M2_CARRIER_QUEUE_FRAMES);
        actor.candidate = Some(Carrier {
            key: candidate_key.clone(),
            local_addr: None,
            tx: candidate_tx,
            pending_controls: BTreeMap::new(),
            reader_cancel: CancellationToken::new(),
            reader: None,
            writer: None,
        });
        let attempt = RotationAttemptIdentity::new(
            "session",
            1,
            "owner",
            "rotation",
            active_key.generation,
            candidate_key.generation,
            active_key.connection_id.clone(),
            candidate_key.connection_id.clone(),
        );
        let now = actor.now_ms();
        actor
            .rotation
            .prepare(attempt.clone(), now)
            .expect("rotation prepares");
        actor
            .rotation
            .candidate_ready(&attempt, now)
            .expect("candidate is ready");
        actor
            .rotation
            .quiesce(
                &attempt,
                tunnel_protocol::rotation_control::StreamRoster::new("snapshot", vec![1]),
                now,
            )
            .expect("rotation enters quiescing");

        let (sequence, final_state) = test_owner_forget_before_owner_ack(1);
        let mut stream = test_stream();
        stream.sequence = sequence;
        stream.input_fin = true;
        stream.output_fin = true;
        actor.streams.insert(1, stream);
        actor
            .handle_stream_forget(tunnel_protocol::rotation_control::StreamForget {
                message_id: "forget-converged-before-active".to_owned(),
                reply_to: String::new(),
                session_id: "session".to_owned(),
                epoch: 1,
                stream_id: 1,
                operation_id: "operation".to_owned(),
                direction: Direction::RelayToConnector,
                final_state,
            })
            .expect("proof-pending FORGET queues both immutable barriers");
        let pending = actor
            .pending_forgets
            .get(&1)
            .expect("proof remains roster-retained");
        assert!(pending.proof_pending);
        assert!(pending.proof_deadline.is_some());
        assert!(pending.defer_reclamation);
        assert_eq!(pending.barriers_queued.len(), 2);
        assert!(matches!(
            active_receiver
                .try_recv()
                .expect("active carrier barrier is queued"),
            CarrierCommand::Barrier
        ));
        assert!(matches!(
            candidate_receiver
                .try_recv()
                .expect("candidate carrier barrier is queued"),
            CarrierCommand::Barrier
        ));

        // The ACK converges the proof while the rotation still owns the
        // immutable roster. Refresh must clear only the proof lease; the
        // stream and both original carrier barriers remain retained.
        actor
            .handle_frame(active_key.clone(), Frame::ack(1, 1, 1, 1))
            .await
            .expect("timely owner ACK converges the proof");
        let pending = actor
            .pending_forgets
            .get(&1)
            .expect("proof remains retained after ACK");
        assert!(!pending.proof_pending);
        assert!(pending.proof_deadline.is_none());
        assert!(actor.streams.contains_key(&1));

        actor
            .handle_barrier_complete(&candidate_key)
            .expect("candidate barrier completes while quiescing");
        actor
            .handle_barrier_complete(&active_key)
            .expect("active barrier completes while quiescing");
        assert!(actor.streams.contains_key(&1));
        let pending = actor
            .pending_forgets
            .get(&1)
            .expect("stream remains in immutable roster");
        assert!(pending.defer_reclamation);
        assert!(pending.proof_deadline.is_none());
        assert_eq!(pending.barriers_queued, pending.barriers_completed);
        assert_eq!(actor.rotation.phase(), RotationPhase::Quiescing);

        actor
            .rotation
            .abort(&attempt, actor.now_ms(), RecoveryReason::ControlLost)
            .expect("test rotation aborts before commit");
        let close_time = actor.now_ms();
        actor
            .rotation
            .candidate_closed(
                &attempt,
                RotationSide::Connector,
                ClosureEvidence::closed(candidate_key.connection_id.clone()),
                close_time,
            )
            .expect("connector candidate closure is recorded");
        actor
            .rotation
            .candidate_closed(
                &attempt,
                RotationSide::Owner,
                ClosureEvidence::closed(candidate_key.connection_id),
                close_time,
            )
            .expect("owner candidate closure activates the old carrier");
        assert_eq!(actor.rotation.phase(), RotationPhase::Active);
        actor
            .complete_ready_stream_forgets()
            .expect("active phase permits completed roster cleanup");
        assert!(!actor.streams.contains_key(&1));
        assert!(!actor.pending_forgets.contains_key(&1));
        assert_eq!(actor.forgotten_stream_through, 1);
    }

    #[test]
    fn stream_forget_rejects_immutable_nonconvergent_terminal_proof() {
        let (mut actor, _key, mut carrier_receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        let (sequence, mut final_state) = test_owner_forget_before_owner_ack(1);
        let mut stream = test_stream();
        stream.sequence = sequence;
        stream.input_fin = true;
        stream.output_fin = true;
        final_state.send_terminal =
            Some(tunnel_protocol::rotation_control::TerminalState::Reset { reason: 77 });
        actor.streams.insert(1, stream);
        let error = actor
            .handle_stream_forget(tunnel_protocol::rotation_control::StreamForget {
                message_id: "forget-immutable-terminal-mismatch".to_owned(),
                reply_to: String::new(),
                session_id: "session".to_owned(),
                epoch: 1,
                stream_id: 1,
                operation_id: "operation".to_owned(),
                direction: Direction::RelayToConnector,
                final_state,
            })
            .expect_err("a terminal mismatch cannot converge from later ACK progress");
        assert!(matches!(error, ClientError::Protocol(_)));
        assert!(actor.streams.contains_key(&1));
        assert!(actor.pending_forgets.is_empty());
        assert!(carrier_receiver.try_recv().is_err());
    }

    #[test]
    fn stream_forget_rejects_immutable_credit_mismatch() {
        let (mut actor, _key, mut carrier_receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        let (sequence, mut final_state) = test_owner_forget_before_owner_ack(1);
        let mut stream = test_stream();
        stream.sequence = sequence;
        stream.input_fin = true;
        stream.output_fin = true;
        final_state.send_credit = final_state
            .send_credit
            .checked_add(1)
            .expect("test credit remains bounded");
        actor.streams.insert(1, stream);
        let error = actor
            .handle_stream_forget(tunnel_protocol::rotation_control::StreamForget {
                message_id: "forget-immutable-credit-mismatch".to_owned(),
                reply_to: String::new(),
                session_id: "session".to_owned(),
                epoch: 1,
                stream_id: 1,
                operation_id: "operation".to_owned(),
                direction: Direction::RelayToConnector,
                final_state,
            })
            .expect_err("a credit mismatch cannot converge from later ACK progress");
        assert!(matches!(error, ClientError::Protocol(_)));
        assert!(actor.streams.contains_key(&1));
        assert!(actor.pending_forgets.is_empty());
        assert!(carrier_receiver.try_recv().is_err());
    }

    #[test]
    fn stream_forget_rejects_local_adapter_input_debt() {
        for debt in 0..4 {
            let (mut actor, _key, mut carrier_receiver, _control_receiver) =
                test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
            let (mut stream, final_state) = test_stream_with_owner_forget_proof(1);
            match debt {
                0 => {
                    stream.pending.push_back(BufferedInput::Fin);
                    stream.pending_bytes = 1;
                }
                1 => stream.pending_bytes = 1,
                2 => stream.record_buffer.push(0),
                3 => stream.record_expected = Some(1),
                _ => unreachable!(),
            }
            actor.streams.insert(1, stream);
            let error = actor
                .handle_stream_forget(tunnel_protocol::rotation_control::StreamForget {
                    message_id: format!("adapter-debt-{debt}"),
                    reply_to: String::new(),
                    session_id: "session".to_owned(),
                    epoch: 1,
                    stream_id: 1,
                    operation_id: "operation".to_owned(),
                    direction: Direction::RelayToConnector,
                    final_state,
                })
                .expect_err("local adapter debt must block physical reclamation");
            assert!(matches!(error, ClientError::Protocol(_)));
            assert!(actor.pending_forgets.is_empty());
            assert!(carrier_receiver.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn stream_forget_waits_for_carrier_barrier_before_removal() {
        let (mut actor, key, mut receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        let (stream, final_state) = test_stream_with_owner_forget_proof(1);
        actor.streams.insert(1, stream);
        let forget = tunnel_protocol::rotation_control::StreamForget {
            message_id: "forget".to_owned(),
            reply_to: String::new(),
            session_id: "session".to_owned(),
            epoch: 1,
            stream_id: 1,
            operation_id: "operation".to_owned(),
            direction: Direction::RelayToConnector,
            final_state,
        };
        actor
            .handle_stream_forget(forget)
            .expect("forget barrier is scheduled");
        assert!(actor.streams.contains_key(&1));
        assert!(matches!(
            receiver.try_recv().expect("barrier queued"),
            CarrierCommand::Barrier
        ));

        actor
            .handle_barrier_complete(&key)
            .expect("completed barrier proves carrier drain");
        assert!(!actor.streams.contains_key(&1));
        actor
            .handle_frame(key, Frame::data(1, 1, 1, 1, 0, vec![0x5a]))
            .await
            .expect("late forgotten frame is ignored");
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn stream_forget_drains_a_ready_candidate_before_removal() {
        let (mut actor, active_key, mut active_receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        let candidate_key = CarrierKey::new(2, "candidate");
        let (candidate_tx, mut candidate_receiver) = mpsc::channel(M2_CARRIER_QUEUE_FRAMES);
        actor.candidate = Some(Carrier {
            key: candidate_key.clone(),
            local_addr: None,
            tx: candidate_tx,
            pending_controls: BTreeMap::new(),
            reader_cancel: CancellationToken::new(),
            reader: None,
            writer: None,
        });

        let (stream, final_state) = test_stream_with_owner_forget_proof(1);
        actor.streams.insert(1, stream);
        let forget = tunnel_protocol::rotation_control::StreamForget {
            message_id: "forget-candidate".to_owned(),
            reply_to: String::new(),
            session_id: "session".to_owned(),
            epoch: 1,
            stream_id: 1,
            operation_id: "operation".to_owned(),
            direction: Direction::RelayToConnector,
            final_state,
        };
        actor
            .handle_stream_forget(forget)
            .expect("forget barriers include candidate");
        assert!(matches!(
            active_receiver.try_recv().expect("active barrier queued"),
            CarrierCommand::Barrier
        ));
        assert!(matches!(
            candidate_receiver
                .try_recv()
                .expect("candidate barrier queued"),
            CarrierCommand::Barrier
        ));

        actor
            .handle_barrier_complete(&candidate_key)
            .expect("candidate barrier proves candidate drain");
        assert!(actor.streams.contains_key(&1));
        actor
            .handle_barrier_complete(&active_key)
            .expect("active barrier completes forget");
        assert!(!actor.streams.contains_key(&1));
    }

    #[test]
    fn stream_forget_after_quiesce_stays_in_immutable_roster() {
        let (mut actor, active_key, mut active_receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        let candidate_key = CarrierKey::new(2, "candidate");
        let (candidate_tx, mut candidate_receiver) = mpsc::channel(M2_CARRIER_QUEUE_FRAMES);
        actor.candidate = Some(Carrier {
            key: candidate_key.clone(),
            local_addr: None,
            tx: candidate_tx,
            pending_controls: BTreeMap::new(),
            reader_cancel: CancellationToken::new(),
            reader: None,
            writer: None,
        });

        let attempt = RotationAttemptIdentity::new(
            "session",
            1,
            "owner",
            "rotation",
            active_key.generation,
            candidate_key.generation,
            active_key.connection_id.clone(),
            candidate_key.connection_id.clone(),
        );
        let now = actor.now_ms();
        actor
            .rotation
            .prepare(attempt.clone(), now)
            .expect("rotation prepares");
        actor
            .rotation
            .candidate_ready(&attempt, now)
            .expect("candidate is ready");
        actor
            .rotation
            .quiesce(
                &attempt,
                tunnel_protocol::rotation_control::StreamRoster::new("snapshot", vec![1]),
                now,
            )
            .expect("rotation enters quiescing");

        let (stream, final_state) = test_stream_with_owner_forget_proof(1);
        actor.streams.insert(1, stream);
        let forget = tunnel_protocol::rotation_control::StreamForget {
            message_id: "forget-after-quiesce".to_owned(),
            reply_to: String::new(),
            session_id: "session".to_owned(),
            epoch: 1,
            stream_id: 1,
            operation_id: "operation".to_owned(),
            direction: Direction::RelayToConnector,
            final_state,
        };
        actor
            .handle_stream_forget(forget)
            .expect("post-quiesce forget barriers are scheduled");
        assert!(matches!(
            active_receiver.try_recv().expect("active barrier queued"),
            CarrierCommand::Barrier
        ));
        assert!(matches!(
            candidate_receiver
                .try_recv()
                .expect("candidate barrier queued"),
            CarrierCommand::Barrier
        ));

        actor
            .handle_barrier_complete(&candidate_key)
            .expect("candidate barrier completes");
        actor
            .handle_barrier_complete(&active_key)
            .expect("active barrier completes");
        assert!(actor.streams.contains_key(&1));
        assert!(
            actor
                .pending_forgets
                .get(&1)
                .is_some_and(|pending| pending.defer_reclamation)
        );
    }

    #[test]
    fn receive_credit_is_reissued_after_old_writer_debt() {
        let (mut actor, old_key, _old_receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        actor.streams.insert(1, test_stream());
        actor
            .active
            .pending_controls
            .entry(1)
            .or_default()
            .record_window(64)
            .expect("test credit remains bounded");

        let new_key = CarrierKey::new(2, "candidate");
        let (new_tx, mut new_receiver) = mpsc::channel(M2_CARRIER_QUEUE_FRAMES);
        let new_carrier = Carrier {
            key: new_key,
            local_addr: None,
            tx: new_tx,
            pending_controls: BTreeMap::new(),
            reader_cancel: CancellationToken::new(),
            reader: None,
            writer: None,
        };
        let old = std::mem::replace(&mut actor.active, new_carrier);
        assert_eq!(old.key, old_key);
        actor.retiring = Some(old);
        actor
            .reissue_active_receive_controls()
            .expect("new carrier accepts absolute credit replay");

        let CarrierCommand::Frame(frame) = new_receiver
            .try_recv()
            .expect("reissued window update queued")
        else {
            panic!("expected a reissued window update frame");
        };
        let decoded = Frame::decode(&frame.bytes).expect("window update decodes");
        assert_eq!(decoded.kind, FrameKind::WindowUpdate);
        assert!(decoded.window >= 1_088);
        assert!(
            actor
                .retiring
                .as_ref()
                .expect("old carrier retained for retirement")
                .pending_controls
                .is_empty()
        );
    }

    #[test]
    fn partial_receive_control_migration_clears_only_accepted_stream_debt() {
        let (mut actor, old_key, _old_receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        actor.streams.insert(1, test_stream());
        let mut stream_two = test_stream();
        stream_two.sequence = StreamState::new(2, 1_024).expect("second stream sequence");
        actor.streams.insert(2, stream_two);
        for stream_id in [1, 2] {
            let pending = actor.active.pending_controls.entry(stream_id).or_default();
            pending.record_ack(1);
            pending
                .record_window(64)
                .expect("test credit remains bounded");
        }

        let new_key = CarrierKey::new(2, "candidate");
        let (new_tx, mut new_receiver) = mpsc::channel(1);
        let new_carrier = Carrier {
            key: new_key,
            local_addr: None,
            tx: new_tx,
            pending_controls: BTreeMap::new(),
            reader_cancel: CancellationToken::new(),
            reader: None,
            writer: None,
        };
        let old = std::mem::replace(&mut actor.active, new_carrier);
        assert_eq!(old.key, old_key);
        actor.retiring = Some(old);

        actor
            .reissue_active_receive_controls()
            .expect("partial active queue remains a bounded retry");
        let CarrierCommand::Frame(first) = new_receiver
            .try_recv()
            .expect("first stream ACK is accepted")
        else {
            panic!("expected first cumulative ACK");
        };
        assert_eq!(
            Frame::decode(&first.bytes)
                .expect("first ACK decodes")
                .stream_id,
            1
        );
        let retiring = actor.retiring.as_ref().expect("retiring carrier retained");
        let stream_one = retiring
            .pending_controls
            .get(&1)
            .expect("stream one window remains until accepted");
        assert!(stream_one.acknowledged.is_none());
        assert!(stream_one.released_window_bytes > 0);
        assert!(
            retiring
                .pending_controls
                .get(&2)
                .is_some_and(|control| control.acknowledged.is_some())
        );

        actor
            .reissue_active_receive_controls()
            .expect("stream one window retries independently");
        let CarrierCommand::Frame(second) = new_receiver
            .try_recv()
            .expect("stream one window is accepted")
        else {
            panic!("expected stream one window update");
        };
        assert_eq!(
            Frame::decode(&second.bytes)
                .expect("stream one window decodes")
                .stream_id,
            1
        );
        assert!(
            !actor
                .retiring
                .as_ref()
                .expect("retiring carrier retained")
                .pending_controls
                .contains_key(&1)
        );
        assert!(
            actor
                .retiring
                .as_ref()
                .expect("retiring carrier retained")
                .pending_controls
                .contains_key(&2)
        );
    }

    #[tokio::test]
    async fn rotate_commit_hands_off_after_closed_old_writer() {
        let (mut actor, old_key, old_receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        drop(old_receiver);
        actor.streams.insert(1, test_stream());
        actor
            .active
            .pending_controls
            .entry(1)
            .or_default()
            .record_ack(1);

        let candidate_key = CarrierKey::new(2, "candidate");
        let (candidate_tx, mut candidate_receiver) = mpsc::channel(M2_CARRIER_QUEUE_FRAMES);
        actor.candidate = Some(Carrier {
            key: candidate_key.clone(),
            local_addr: None,
            tx: candidate_tx,
            pending_controls: BTreeMap::new(),
            reader_cancel: CancellationToken::new(),
            reader: None,
            writer: None,
        });

        let attempt = RotationAttemptIdentity::new(
            "session",
            1,
            "owner",
            "rotation",
            old_key.generation,
            candidate_key.generation,
            old_key.connection_id.clone(),
            candidate_key.connection_id.clone(),
        );
        let now = actor.now_ms();
        actor
            .rotation
            .prepare(attempt.clone(), now)
            .expect("rotation prepares");
        actor
            .rotation
            .candidate_ready(&attempt, now)
            .expect("candidate is ready");
        actor
            .rotation
            .quiesce(
                &attempt,
                tunnel_protocol::rotation_control::StreamRoster::new("snapshot", vec![1]),
                now,
            )
            .expect("rotation quiesces");
        let local_fence = FenceSnapshot::new(
            "snapshot",
            vec![tunnel_protocol::rotation_control::StreamFence::new(
                1,
                Direction::ConnectorToRelay,
                0,
            )],
        );
        let peer_fence = FenceSnapshot::new(
            "snapshot",
            vec![tunnel_protocol::rotation_control::StreamFence::new(
                1,
                Direction::RelayToConnector,
                0,
            )],
        );
        actor
            .rotation
            .frozen(
                &attempt,
                local_fence.clone(),
                Direction::ConnectorToRelay,
                now,
            )
            .expect("local fence is accepted");
        actor
            .rotation
            .frozen(
                &attempt,
                peer_fence.clone(),
                Direction::RelayToConnector,
                now,
            )
            .expect("peer fence is accepted");
        actor
            .rotation
            .drained(
                &attempt,
                tunnel_protocol::rotation_control::DrainProof::new(
                    "snapshot",
                    peer_fence.digest().expect("peer fence digest"),
                    Direction::RelayToConnector,
                    vec![tunnel_protocol::rotation_control::StreamAck::new(1, 0)],
                ),
                now,
            )
            .expect("peer drain proof is accepted");
        actor
            .rotation
            .drained(
                &attempt,
                tunnel_protocol::rotation_control::DrainProof::new(
                    "snapshot",
                    local_fence.digest().expect("local fence digest"),
                    Direction::ConnectorToRelay,
                    vec![tunnel_protocol::rotation_control::StreamAck::new(1, 0)],
                ),
                now,
            )
            .expect("local drain proof is accepted");
        actor.local_fence = Some(local_fence.clone());
        actor.local_drained_message_id = Some("drained".to_owned());

        let commit = RotateCommit {
            message_id: "commit".to_owned(),
            reply_to: "drained".to_owned(),
            attempt,
            snapshot_id: "snapshot".to_owned(),
            drain_proofs: vec![
                tunnel_protocol::rotation_control::DrainProofRef {
                    snapshot_id: "snapshot".to_owned(),
                    fence_digest: local_fence.digest().expect("local fence digest"),
                    direction: Direction::ConnectorToRelay,
                },
                tunnel_protocol::rotation_control::DrainProofRef {
                    snapshot_id: "snapshot".to_owned(),
                    fence_digest: peer_fence.digest().expect("peer fence digest"),
                    direction: Direction::RelayToConnector,
                },
            ],
        };
        let scope = actor
            .rotation_journal_scope(&ControlMessage::RotateCommit(commit.clone()))
            .expect("commit belongs to active rotation");
        actor
            .observe_rotation_message(&ControlMessage::RotateCommit(commit.clone()), scope)
            .expect("commit is journaled");
        actor
            .handle_rotate_commit(commit)
            .await
            .expect("closed old writer is handed off to candidate");

        assert_eq!(actor.active.key, candidate_key);
        assert_eq!(
            actor
                .retiring
                .as_ref()
                .expect("old carrier remains owned for joined retirement")
                .key,
            old_key
        );
        assert!(
            actor
                .retiring
                .as_ref()
                .expect("old carrier remains owned for joined retirement")
                .pending_controls
                .is_empty()
        );
        assert!(matches!(
            candidate_receiver
                .try_recv()
                .expect("absolute credit reissued"),
            CarrierCommand::Frame(_)
        ));
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

    #[test]
    fn first_recovery_trigger_is_specific_and_stable() {
        let (mut actor, active_key, _receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        actor.remember_recovery_trigger(RecoveryTriggerClass::WriterFailed, &active_key);
        actor.remember_recovery_trigger(RecoveryTriggerClass::ReaderClosed, &active_key);
        assert_eq!(
            actor.first_recovery_trigger,
            Some(RecoveryTrigger {
                class: RecoveryTriggerClass::WriterFailed,
                role: CarrierRole::Active,
                generation: active_key.generation,
            })
        );
        let detail = actor.retained_recovery_detail("recovery episode deadline expired");
        assert_eq!(
            detail,
            format!(
                "recovery episode deadline expired; recovery_trigger=data_writer_failed; recovery_role=active; recovery_generation={}",
                active_key.generation,
            )
        );
        assert_eq!(
            ClientError::Transport {
                scope: "retained recovery",
                detail,
            }
            .to_string(),
            format!(
                "retained recovery failed: recovery episode deadline expired; recovery_trigger=data_writer_failed; recovery_role=active; recovery_generation={}",
                active_key.generation,
            )
        );
    }

    /// Build a minimal retained-recovery context for attempt `attempt_no`
    /// whose first candidate `closed_candidate` has already been released.
    fn installed_recovery_context(
        actor: &mut M2Actor,
        active_key: &CarrierKey,
        attempt_no: u64,
        closed_candidate: &str,
    ) {
        let attempt = RotationAttemptIdentity::new(
            "session",
            1,
            "owner",
            format!("control-lost-{attempt_no}"),
            active_key.generation,
            active_key.generation + attempt_no,
            active_key.connection_id.clone(),
            format!("candidate-{attempt_no}"),
        );
        let roster =
            tunnel_protocol::rotation_control::StreamRoster::new("control-lost-snapshot", vec![]);
        let now = actor.now_ms();
        let begin = RecoveryBegin {
            message_id: format!("control-lost-begin-{attempt_no}"),
            reply_to: String::new(),
            attempt: attempt.clone(),
            episode_id: "control-lost-episode".to_owned(),
            attempt_no,
            roster: roster.clone(),
            remaining_ms: 1_000,
        };
        let local_closed = RecoveryClosed {
            message_id: format!("control-lost-closed-{attempt_no}"),
            reply_to: begin.message_id.clone(),
            attempt,
            episode_id: begin.episode_id.clone(),
            attempt_no,
            closed_connection_ids: vec![closed_candidate.to_owned()],
            closure_digest: "control-lost-digest".to_owned(),
        };
        actor.recovery = Some(RecoveryRuntime {
            begin,
            local_closed,
            prepare_message_id: None,
            peer_closed: None,
            combined_digest: None,
            deadline_ms: now.checked_add(1_000).expect("deadline"),
            attempt_deadline_ms: None,
            authenticated_closed_connection_ids: BTreeSet::new(),
            local_snapshots: [BTreeMap::new(), BTreeMap::new()],
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
        });
        actor.closed_for_recovery.insert(
            closed_candidate.to_owned(),
            ClosureEvidence::closed(closed_candidate),
        );
    }

    /// EC-058: a retry's RECOVERY_BEGIN carries the coordinator's own
    /// remaining-duration sample, taken on the coordinator's monotonic clock.
    /// Attempt one is processed slowest here, because this actor is still
    /// releasing the lost carrier's reader/writer tasks while it arrives, so a
    /// later attempt's sample can legitimately exceed this endpoint's own
    /// remaining budget by that latency difference.  The retained absolute
    /// episode deadline must win by clamping rather than by failing the
    /// session; an already-expired episode still fails closed.
    /// Fixed gap between the first episode sample and a retry's larger
    /// sample, so the clamp is exercised without depending on elapsed time.
    const CLAMP_SAMPLE_GAP_MS: u64 = 500;

    #[tokio::test]
    async fn recovery_retry_clamps_a_larger_remaining_sample_to_the_retained_deadline() {
        let (mut actor, active_key, active_receiver, mut control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        drop(active_receiver);
        let (active_tx, mut active_commands) = mpsc::channel(M2_CARRIER_QUEUE_FRAMES);
        let reader_cancel = actor.active.reader_cancel.clone();
        actor.active.tx = active_tx;
        actor.active.reader = Some(tokio::spawn(async move {
            reader_cancel.cancelled().await;
        }));
        actor.active.writer = Some(tokio::spawn(async move {
            while let Some(command) = active_commands.recv().await {
                if let CarrierCommand::Close(reply) = command {
                    let _ = reply.send(());
                    break;
                }
            }
        }));
        actor.remember_recovery_trigger(RecoveryTriggerClass::ReaderClosed, &active_key);

        let roster = tunnel_protocol::rotation_control::StreamRoster::new("clamp-snapshot", vec![]);
        let episode_id = "clamp-episode".to_owned();
        let budget = actor.rotation.config().recovery_timeout_ms;
        // Attempt one establishes the retained deadline from a sample that is
        // deliberately shorter than the coordinator's full budget, so the retry
        // below presents a larger sample by construction.  Deriving the gap
        // from elapsed wall-clock time instead makes the precondition vanish on
        // a fast machine, which is how this test failed in the workspace run.
        let first_sample = budget - CLAMP_SAMPLE_GAP_MS;
        let first_attempt = RotationAttemptIdentity::new(
            "session",
            1,
            "owner",
            "clamp-one",
            active_key.generation,
            active_key.generation + 1,
            active_key.connection_id.clone(),
            "clamp-candidate-one",
        );
        actor
            .handle_recovery_begin(RecoveryBegin {
                message_id: "clamp-begin-one".to_owned(),
                reply_to: String::new(),
                attempt: first_attempt.clone(),
                episode_id: episode_id.clone(),
                attempt_no: 1,
                roster: roster.clone(),
                remaining_ms: first_sample,
            })
            .await
            .expect("attempt one establishes the retained episode deadline");
        let retained_deadline = actor
            .recovery
            .as_ref()
            .expect("attempt one recovery context")
            .deadline_ms;
        let _ = drain_control_messages(&mut control_receiver);

        let first_peer_closed = {
            let recovery = actor.recovery.as_ref().expect("recovery context");
            let mut closed = RecoveryClosed {
                message_id: "clamp-closed-one".to_owned(),
                reply_to: recovery.begin.message_id.clone(),
                attempt: recovery.begin.attempt.clone(),
                episode_id: recovery.begin.episode_id.clone(),
                attempt_no: recovery.begin.attempt_no,
                closed_connection_ids: recovery.local_closed.closed_connection_ids.clone(),
                closure_digest: String::new(),
            };
            closed.closure_digest = closed
                .closure_digest_for(RecoverySide::Relay)
                .expect("relay closure digest");
            closed
        };
        actor
            .handle_recovery_closed(first_peer_closed)
            .expect("owner closure proof authenticates the first pair");
        let reserve_now = actor.now_ms();
        actor
            .rotation
            .reserve_recovery_socket(reserve_now)
            .expect("attempt one reserves the recovery socket");
        actor
            .finish_recovery_candidate_loss(
                first_attempt,
                ClosureEvidence::closed("clamp-candidate-one"),
            )
            .await
            .expect("attempt one candidate loss records local closure");

        // The coordinator's attempt-two sample is its full remaining budget,
        // which exceeds this endpoint's remaining budget by the time attempt
        // one spent being processed here.
        let second_attempt = RotationAttemptIdentity::new(
            "session",
            1,
            "owner",
            "clamp-two",
            active_key.generation,
            active_key.generation + 2,
            active_key.connection_id.clone(),
            "clamp-candidate-two",
        );
        assert!(
            budget > retained_deadline.saturating_sub(actor.now_ms()),
            "the retry sample must exceed the retained remaining budget for this test to bite"
        );
        assert_eq!(
            budget - first_sample,
            CLAMP_SAMPLE_GAP_MS,
            "the gap between the two samples is fixed, not a function of elapsed time"
        );
        actor
            .handle_recovery_begin(RecoveryBegin {
                message_id: "clamp-begin-two".to_owned(),
                reply_to: String::new(),
                attempt: second_attempt,
                episode_id,
                attempt_no: 2,
                roster,
                remaining_ms: budget,
            })
            .await
            .expect("a larger retry sample is clamped, not rejected");
        assert_eq!(
            actor
                .recovery
                .as_ref()
                .expect("attempt two recovery context")
                .deadline_ms,
            retained_deadline,
            "the retained absolute episode deadline is never extended"
        );
    }

    /// EC-057/IN-09: the coordinator ends an exhausted episode by closing
    /// control.  The connector must keep the data-carrier trigger and the
    /// attempt number in its typed terminal diagnostic instead of reporting
    /// an anonymous control failure; outside recovery the generic control
    /// diagnostic is unchanged.
    #[test]
    fn control_loss_during_retained_recovery_keeps_trigger_and_attempt() {
        let (mut actor, active_key, _receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        assert_eq!(
            actor
                .control_lost_error("control socket closed".to_owned())
                .to_string(),
            "control read failed"
        );
        actor.remember_recovery_trigger(RecoveryTriggerClass::ReaderClosed, &active_key);
        installed_recovery_context(&mut actor, &active_key, 3, "candidate-2");
        let error = actor.control_lost_error("control socket closed".to_owned());
        assert_eq!(error.code(), "TRANSPORT_ERROR");
        assert_eq!(
            error.to_string(),
            format!(
                "retained recovery failed: control socket closed during retained recovery; recovery_trigger=data_reader_closed; recovery_role=active; recovery_generation={}; recovery_attempt=3",
                active_key.generation,
            )
        );
        // An out-of-range attempt in a detail string cannot leak through the
        // closed diagnostic set.
        assert_eq!(
            ClientError::Transport {
                scope: "retained recovery",
                detail: "control socket closed during retained recovery; recovery_trigger=data_reader_closed; recovery_role=active; recovery_generation=1; recovery_attempt=4".to_owned(),
            }
            .to_string(),
            "retained recovery failed: control socket closed during retained recovery"
        );
    }

    /// A DATA_READY for a recovery candidate this connector already released
    /// (the relay attached it before the handshake response was lost) is late
    /// rather than foreign and must not end the session; readiness for any
    /// unknown carrier without a pending candidate remains a violation.
    #[tokio::test]
    async fn late_data_ready_for_released_recovery_candidate_is_ignored() {
        let (mut actor, active_key, _receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        installed_recovery_context(&mut actor, &active_key, 2, "candidate-1");
        assert!(actor.pending_candidate.is_none());
        let released = DataReady {
            message_id: "late-ready".to_owned(),
            reply_to: "late-prepare".to_owned(),
            session_id: "session".to_owned(),
            epoch: 1,
            generation: active_key.generation + 1,
            connection_id: "candidate-1".to_owned(),
        };
        actor
            .handle_candidate_ready(released.clone())
            .await
            .expect("late readiness for a released candidate is ignored");
        assert!(actor.candidate.is_none() && actor.pending_candidate.is_none());
        let foreign = DataReady {
            connection_id: "candidate-9".to_owned(),
            ..released.clone()
        };
        assert!(matches!(
            actor.handle_candidate_ready(foreign).await,
            Err(ClientError::Protocol(message)) if message == "unexpected DATA_READY"
        ));
        let other_session = DataReady {
            session_id: "other-session".to_owned(),
            ..released.clone()
        };
        assert!(matches!(
            actor.handle_candidate_ready(other_session).await,
            Err(ClientError::Protocol(message)) if message == "unexpected DATA_READY"
        ));
        actor.recovery = None;
        assert!(matches!(
            actor.handle_candidate_ready(released).await,
            Err(ClientError::Protocol(message)) if message == "unexpected DATA_READY"
        ));
    }

    #[tokio::test]
    async fn resume_context_mismatch_reports_wire_bound_category_and_first_trigger() {
        let (mut actor, active_key, _receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        let candidate_key = CarrierKey::new(active_key.generation + 1, "candidate");
        let (candidate_tx, _candidate_receiver) = mpsc::channel(M2_CARRIER_QUEUE_FRAMES);
        actor.candidate = Some(Carrier {
            key: candidate_key.clone(),
            local_addr: None,
            tx: candidate_tx,
            pending_controls: BTreeMap::new(),
            reader_cancel: CancellationToken::new(),
            reader: None,
            writer: None,
        });
        actor.remember_recovery_trigger(RecoveryTriggerClass::WriterFailed, &active_key);

        let attempt = RotationAttemptIdentity::new(
            "session",
            1,
            "owner",
            "resume-context-red",
            active_key.generation,
            candidate_key.generation,
            active_key.connection_id.clone(),
            candidate_key.connection_id.clone(),
        );
        let roster =
            tunnel_protocol::rotation_control::StreamRoster::new("resume-context-snapshot", vec![]);
        let now = actor.now_ms();
        let recovery_deadline = now
            .checked_add(1_000)
            .expect("test recovery deadline does not overflow");
        let begin = RecoveryBegin {
            message_id: "resume-context-begin".to_owned(),
            reply_to: String::new(),
            attempt: attempt.clone(),
            episode_id: "resume-context-episode".to_owned(),
            attempt_no: 1,
            roster: roster.clone(),
            remaining_ms: 1_000,
        };
        let local_closed = RecoveryClosed {
            message_id: "resume-context-closed".to_owned(),
            reply_to: begin.message_id.clone(),
            attempt: attempt.clone(),
            episode_id: begin.episode_id.clone(),
            attempt_no: begin.attempt_no,
            closed_connection_ids: vec![active_key.connection_id.clone()],
            closure_digest: "resume-context-digest".to_owned(),
        };
        actor.recovery = Some(RecoveryRuntime {
            begin,
            local_closed,
            prepare_message_id: Some("resume-context-prepare".to_owned()),
            peer_closed: None,
            combined_digest: None,
            deadline_ms: recovery_deadline,
            attempt_deadline_ms: None,
            authenticated_closed_connection_ids: BTreeSet::new(),
            local_snapshots: [BTreeMap::new(), BTreeMap::new()],
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
        });

        let error = actor
            .handle_resume(Resume {
                message_id: "resume-context-request".to_owned(),
                reply_to: "resume-context-prepare".to_owned(),
                attempt,
                snapshot_id: roster.snapshot_id,
                stage: ResumeStage::Snapshot,
                direction: Direction::RelayToConnector,
                reconnect_credential: None,
                entries: Vec::new(),
                remaining_ms: MAX_ROTATION_RECOVERY_TIMEOUT_MS + 1,
            })
            .await
            .expect_err("the Resume budget must exceed the wire recovery bound");
        assert_eq!(
            error.to_string(),
            format!(
                "RESUME recovery remaining budget exceeds protocol bound; recovery_trigger=data_writer_failed; recovery_role=active; recovery_generation={}",
                active_key.generation,
            )
        );
        let rendered = error.to_string();
        assert!(!rendered.contains("resume-context"));
        assert!(!rendered.contains("candidate"));
    }

    #[tokio::test]
    async fn resume_accepts_bounded_queue_staleness_without_extending_deadline() {
        let (mut actor, active_key, _receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        let (candidate_tx, _candidate_receiver) = mpsc::channel(M2_CARRIER_QUEUE_FRAMES);
        actor.candidate = Some(Carrier {
            key: CarrierKey::new(active_key.generation + 1, "candidate"),
            local_addr: None,
            tx: candidate_tx,
            pending_controls: BTreeMap::new(),
            reader_cancel: CancellationToken::new(),
            reader: None,
            writer: None,
        });
        actor.remember_recovery_trigger(RecoveryTriggerClass::WriterFailed, &active_key);

        let attempt = RotationAttemptIdentity::new(
            "session",
            1,
            "owner",
            "resume-stale-valid",
            active_key.generation,
            active_key.generation + 1,
            active_key.connection_id.clone(),
            "candidate",
        );
        let roster =
            tunnel_protocol::rotation_control::StreamRoster::new("resume-stale-snapshot", vec![]);
        let now = actor.now_ms();
        let local_deadline = now
            .checked_add(1_000)
            .expect("test recovery deadline does not overflow");
        let begin = RecoveryBegin {
            message_id: "resume-stale-begin".to_owned(),
            reply_to: String::new(),
            attempt: attempt.clone(),
            episode_id: "resume-stale-episode".to_owned(),
            attempt_no: 1,
            roster: roster.clone(),
            remaining_ms: 1_000,
        };
        let local_closed = RecoveryClosed {
            message_id: "resume-stale-closed".to_owned(),
            reply_to: begin.message_id.clone(),
            attempt: attempt.clone(),
            episode_id: begin.episode_id.clone(),
            attempt_no: begin.attempt_no,
            closed_connection_ids: vec![active_key.connection_id.clone()],
            closure_digest: "resume-stale-digest".to_owned(),
        };
        let closed_evidence = ClosureEvidence::closed(active_key.connection_id.clone());
        actor
            .rotation
            .transport_lost(&attempt, now, RecoveryReason::OldTransportLost)
            .expect("valid fixture enters recovery from the active carrier");
        actor
            .rotation
            .close_for_recovery(
                active_key.connection_id.clone(),
                closed_evidence.clone(),
                now,
            )
            .expect("valid fixture records old-carrier closure");
        actor
            .rotation
            .begin_recovery(
                attempt.clone(),
                roster.clone(),
                now,
                RecoveryReason::OldTransportLost,
                local_deadline,
            )
            .expect("valid fixture starts the retained recovery episode");
        actor
            .rotation
            .reserve_recovery_socket(now)
            .expect("valid fixture reserves the candidate carrier");
        actor
            .closed_for_recovery
            .insert(active_key.connection_id.clone(), closed_evidence);
        actor.recovery = Some(RecoveryRuntime {
            begin,
            local_closed,
            prepare_message_id: Some("resume-stale-prepare".to_owned()),
            peer_closed: None,
            combined_digest: None,
            deadline_ms: local_deadline,
            attempt_deadline_ms: None,
            authenticated_closed_connection_ids: BTreeSet::new(),
            local_snapshots: [BTreeMap::new(), BTreeMap::new()],
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
        });

        // The relay sampled 1,001 ms before its bounded control queue delay;
        // the connector still has a live 1,000 ms local deadline.  Accepting
        // this exact identity/roster message must not move that local cap.
        actor
            .handle_resume(Resume {
                message_id: "resume-stale-request".to_owned(),
                reply_to: "resume-stale-prepare".to_owned(),
                attempt,
                snapshot_id: roster.snapshot_id,
                stage: ResumeStage::Snapshot,
                direction: Direction::RelayToConnector,
                reconnect_credential: None,
                entries: Vec::new(),
                remaining_ms: 1_001,
            })
            .await
            .expect("bounded sender queue staleness must not extend or fail the local deadline");
        assert_eq!(
            actor
                .recovery
                .as_ref()
                .expect("recovery remains active")
                .deadline_ms,
            local_deadline
        );
        assert!(
            actor
                .recovery
                .as_ref()
                .expect("recovery remains active")
                .snapshot_replies[0]
        );
    }

    #[tokio::test]
    async fn resume_rejects_expired_candidate_before_deadline_tick() {
        let (mut actor, active_key, _receiver, mut control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        let candidate_key = CarrierKey::new(active_key.generation + 1, "candidate-expired");
        let (candidate_tx, _candidate_receiver) = mpsc::channel(M2_CARRIER_QUEUE_FRAMES);
        actor.candidate = Some(Carrier {
            key: candidate_key.clone(),
            local_addr: None,
            tx: candidate_tx,
            pending_controls: BTreeMap::new(),
            reader_cancel: CancellationToken::new(),
            reader: None,
            writer: None,
        });
        actor.remember_recovery_trigger(RecoveryTriggerClass::WriterFailed, &active_key);

        let attempt = RotationAttemptIdentity::new(
            "session",
            1,
            "owner",
            "resume-expired-candidate",
            active_key.generation,
            candidate_key.generation,
            active_key.connection_id.clone(),
            candidate_key.connection_id.clone(),
        );
        let roster = tunnel_protocol::rotation_control::StreamRoster::new(
            "expired-candidate-snapshot",
            vec![],
        );
        let now = actor.now_ms();
        let episode_deadline = now
            .checked_add(1_000)
            .expect("test recovery deadline does not overflow");
        let begin = RecoveryBegin {
            message_id: "expired-candidate-begin".to_owned(),
            reply_to: String::new(),
            attempt: attempt.clone(),
            episode_id: "expired-candidate-episode".to_owned(),
            attempt_no: 1,
            roster: roster.clone(),
            remaining_ms: 1_000,
        };
        let local_closed = RecoveryClosed {
            message_id: "expired-candidate-closed".to_owned(),
            reply_to: begin.message_id.clone(),
            attempt: attempt.clone(),
            episode_id: begin.episode_id.clone(),
            attempt_no: begin.attempt_no,
            closed_connection_ids: vec![active_key.connection_id.clone()],
            closure_digest: "expired-candidate-digest".to_owned(),
        };
        let closed_evidence = ClosureEvidence::closed(active_key.connection_id.clone());
        actor
            .rotation
            .transport_lost(&attempt, now, RecoveryReason::OldTransportLost)
            .expect("fixture enters recovery from the active carrier");
        actor
            .rotation
            .close_for_recovery(
                active_key.connection_id.clone(),
                closed_evidence.clone(),
                now,
            )
            .expect("fixture records old-carrier closure");
        actor
            .rotation
            .begin_recovery(
                attempt.clone(),
                roster.clone(),
                now,
                RecoveryReason::OldTransportLost,
                episode_deadline,
            )
            .expect("fixture starts the retained recovery episode");
        actor
            .rotation
            .reserve_recovery_socket(now)
            .expect("fixture reserves the matching candidate carrier");
        actor
            .closed_for_recovery
            .insert(active_key.connection_id.clone(), closed_evidence);
        let immutable_episode_deadline = actor
            .rotation
            .status()
            .deadline_ms
            .expect("recovery episode retains its absolute deadline");
        assert_eq!(immutable_episode_deadline, episode_deadline);
        actor.recovery = Some(RecoveryRuntime {
            begin,
            local_closed,
            prepare_message_id: Some("expired-candidate-prepare".to_owned()),
            peer_closed: None,
            combined_digest: None,
            deadline_ms: episode_deadline,
            attempt_deadline_ms: Some(now.saturating_sub(1)),
            authenticated_closed_connection_ids: BTreeSet::new(),
            local_snapshots: [BTreeMap::new(), BTreeMap::new()],
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
        });

        let error = actor
            .handle_resume(Resume {
                message_id: "expired-candidate-request".to_owned(),
                reply_to: "expired-candidate-prepare".to_owned(),
                attempt,
                snapshot_id: roster.snapshot_id,
                stage: ResumeStage::Snapshot,
                direction: Direction::RelayToConnector,
                reconnect_credential: None,
                entries: Vec::new(),
                remaining_ms: 900,
            })
            .await
            .expect_err("an expired candidate must fail before the next deadline tick");
        match error {
            ClientError::Transport { scope, detail } => {
                assert_eq!(scope, "retained recovery");
                assert!(detail.contains("recovery candidate phase deadline expired"));
            }
            other => panic!("expired candidate returned the wrong error category: {other:?}"),
        }
        assert_eq!(
            actor
                .recovery
                .as_ref()
                .expect("recovery remains active")
                .deadline_ms,
            episode_deadline
        );
        assert_eq!(
            actor.rotation.status().deadline_ms,
            Some(immutable_episode_deadline)
        );
        let recovery = actor.recovery.as_ref().expect("recovery remains active");
        assert!(
            recovery
                .remote_snapshot_message_ids
                .iter()
                .all(Option::is_none)
        );
        assert!(recovery.snapshot_replies.iter().all(|replied| !replied));
        assert!(recovery.snapshot_reply_messages.iter().all(Option::is_none));
        assert!(recovery.local_plans.is_empty());
        assert!(actor.control_journal.is_none());
        assert!(actor.pending_candidate.is_none());
        assert_eq!(
            actor.candidate.as_ref().map(|candidate| &candidate.key),
            Some(&candidate_key)
        );
        assert!(matches!(
            control_receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn resume_rejects_stale_budget_after_local_deadline_expires() {
        let (mut actor, active_key, _receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        let attempt = RotationAttemptIdentity::new(
            "session",
            1,
            "owner",
            "resume-expired-local",
            active_key.generation,
            active_key.generation + 1,
            active_key.connection_id.clone(),
            "candidate",
        );
        let roster =
            tunnel_protocol::rotation_control::StreamRoster::new("resume-expired-snapshot", vec![]);
        let now = actor.now_ms();
        let begin = RecoveryBegin {
            message_id: "resume-expired-begin".to_owned(),
            reply_to: String::new(),
            attempt: attempt.clone(),
            episode_id: "resume-expired-episode".to_owned(),
            attempt_no: 1,
            roster: roster.clone(),
            remaining_ms: 1,
        };
        let local_closed = RecoveryClosed {
            message_id: "resume-expired-closed".to_owned(),
            reply_to: begin.message_id.clone(),
            attempt: attempt.clone(),
            episode_id: begin.episode_id.clone(),
            attempt_no: begin.attempt_no,
            closed_connection_ids: vec![active_key.connection_id.clone()],
            closure_digest: "resume-expired-digest".to_owned(),
        };
        actor.recovery = Some(RecoveryRuntime {
            begin,
            local_closed,
            prepare_message_id: Some("resume-expired-prepare".to_owned()),
            peer_closed: None,
            combined_digest: None,
            deadline_ms: now.saturating_sub(1),
            attempt_deadline_ms: None,
            authenticated_closed_connection_ids: BTreeSet::new(),
            local_snapshots: [BTreeMap::new(), BTreeMap::new()],
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
        });

        let error = actor
            .handle_resume(Resume {
                message_id: "resume-expired-request".to_owned(),
                reply_to: "resume-expired-prepare".to_owned(),
                attempt,
                snapshot_id: roster.snapshot_id,
                stage: ResumeStage::Snapshot,
                direction: Direction::RelayToConnector,
                reconnect_credential: None,
                entries: Vec::new(),
                remaining_ms: 1,
            })
            .await
            .expect_err("expired local deadline must fail closed");
        assert!(
            error
                .to_string()
                .contains("RESUME recovery local deadline expired")
        );
    }

    #[tokio::test]
    async fn recovery_candidate_loss_releases_each_retry_before_next_begin() {
        let (mut actor, active_key, active_receiver, mut control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        // The production close path emits local closure evidence only for a
        // carrier with owned reader/writer tasks.  The generic unit fixture has
        // an intentionally task-free carrier, so install real joinable tasks
        // rather than treating a dropped synthetic queue receiver as a close
        // proof.
        drop(active_receiver);
        let (active_tx, mut active_commands) = mpsc::channel(M2_CARRIER_QUEUE_FRAMES);
        let reader_cancel = actor.active.reader_cancel.clone();
        actor.active.tx = active_tx;
        actor.active.reader = Some(tokio::spawn(async move {
            reader_cancel.cancelled().await;
        }));
        actor.active.writer = Some(tokio::spawn(async move {
            while let Some(command) = active_commands.recv().await {
                if let CarrierCommand::Close(reply) = command {
                    let _ = reply.send(());
                    break;
                }
            }
        }));
        actor.remember_recovery_trigger(RecoveryTriggerClass::WriterFailed, &active_key);

        let roster =
            tunnel_protocol::rotation_control::StreamRoster::new("retry-release-snapshot", vec![]);
        let episode_id = "retry-release-episode".to_owned();
        let first_attempt = RotationAttemptIdentity::new(
            "session",
            1,
            "owner",
            "retry-release-one",
            active_key.generation,
            active_key.generation + 1,
            active_key.connection_id.clone(),
            "candidate-one",
        );
        let recovery_timeout_ms = actor.rotation.config().recovery_timeout_ms;
        let first_begin = RecoveryBegin {
            message_id: "retry-release-begin-one".to_owned(),
            reply_to: String::new(),
            attempt: first_attempt.clone(),
            episode_id: episode_id.clone(),
            attempt_no: 1,
            roster: roster.clone(),
            remaining_ms: recovery_timeout_ms,
        };
        actor
            .handle_recovery_begin(first_begin)
            .await
            .expect("first recovery begin closes the active carrier");
        assert_eq!(
            actor
                .recovery
                .as_ref()
                .expect("first recovery remains active")
                .local_closed
                .closed_connection_ids,
            vec![active_key.connection_id.clone()]
        );
        let _ = drain_control_messages(&mut control_receiver);

        // Authenticate the owner's matching closure record before the first
        // candidate is lost.  The next wire roster must then contain only the
        // newly failed candidate, while the old ID remains fenced locally.
        let relay_closed = |actor: &M2Actor, message_id: &str| {
            let recovery = actor.recovery.as_ref().expect("recovery context");
            let mut closed = RecoveryClosed {
                message_id: message_id.to_owned(),
                reply_to: recovery.begin.message_id.clone(),
                attempt: recovery.begin.attempt.clone(),
                episode_id: recovery.begin.episode_id.clone(),
                attempt_no: recovery.begin.attempt_no,
                closed_connection_ids: recovery.local_closed.closed_connection_ids.clone(),
                closure_digest: String::new(),
            };
            closed.closure_digest = closed
                .closure_digest_for(RecoverySide::Relay)
                .expect("relay closure digest");
            closed
        };
        let first_peer_closed = relay_closed(&actor, "retry-release-closed-one");
        actor
            .handle_recovery_closed(first_peer_closed)
            .expect("owner closure proof authenticates the first pair");

        let first_candidate = first_attempt.new_connection_id.clone();
        let first_reserve_now = actor.now_ms();
        actor
            .rotation
            .reserve_recovery_socket(first_reserve_now)
            .expect("first candidate reserves the recovery socket");
        actor
            .finish_recovery_candidate_loss(
                first_attempt.clone(),
                ClosureEvidence::closed(first_candidate.clone()),
            )
            .await
            .expect("first candidate loss records local closure");
        assert!(
            actor
                .rotation
                .status()
                .attempt
                .as_ref()
                .is_some_and(|attempt| attempt.new_connection_id == first_candidate)
        );

        let second_candidate = "candidate-two".to_owned();
        let second_attempt = RotationAttemptIdentity::new(
            "session",
            1,
            "owner",
            "retry-release-two",
            active_key.generation,
            active_key.generation + 2,
            active_key.connection_id.clone(),
            second_candidate.clone(),
        );
        let second_begin = RecoveryBegin {
            message_id: "retry-release-begin-two".to_owned(),
            reply_to: String::new(),
            attempt: second_attempt.clone(),
            episode_id: episode_id.clone(),
            attempt_no: 2,
            roster: roster.clone(),
            remaining_ms: actor
                .recovery
                .as_ref()
                .expect("first recovery deadline")
                .deadline_ms
                .saturating_sub(actor.now_ms())
                .max(1),
        };
        actor
            .handle_recovery_begin(second_begin)
            .await
            .expect("attempt two releases the failed candidate before allocation");
        assert_eq!(
            actor
                .recovery
                .as_ref()
                .expect("second recovery remains active")
                .local_closed
                .closed_connection_ids,
            vec![first_candidate.clone()]
        );
        assert!(
            actor
                .released_recovery_connections
                .contains(&first_candidate),
            "attempt two must mark the first candidate released only after close_for_recovery"
        );
        let _ = drain_control_messages(&mut control_receiver);
        let second_peer_closed = relay_closed(&actor, "retry-release-closed-two");
        actor
            .handle_recovery_closed(second_peer_closed)
            .expect("owner closure proof authenticates attempt two");

        let second_reserve_now = actor.now_ms();
        actor
            .rotation
            .reserve_recovery_socket(second_reserve_now)
            .expect("second candidate reserves the recovery socket");
        actor
            .finish_recovery_candidate_loss(
                second_attempt.clone(),
                ClosureEvidence::closed(second_candidate.clone()),
            )
            .await
            .expect("second candidate loss records local closure");

        let third_candidate = "candidate-three".to_owned();
        let third_attempt = RotationAttemptIdentity::new(
            "session",
            1,
            "owner",
            "retry-release-three",
            active_key.generation,
            active_key.generation + 3,
            active_key.connection_id.clone(),
            third_candidate,
        );
        let third_begin = RecoveryBegin {
            message_id: "retry-release-begin-three".to_owned(),
            reply_to: String::new(),
            attempt: third_attempt,
            episode_id,
            attempt_no: 3,
            roster,
            remaining_ms: actor
                .recovery
                .as_ref()
                .expect("second recovery deadline")
                .deadline_ms
                .saturating_sub(actor.now_ms())
                .max(1),
        };
        actor
            .handle_recovery_begin(third_begin)
            .await
            .expect("attempt three releases the second failed candidate before allocation");
        assert_eq!(
            actor
                .recovery
                .as_ref()
                .expect("third recovery remains active")
                .begin
                .attempt_no,
            3
        );
        assert_eq!(
            actor
                .recovery
                .as_ref()
                .expect("third recovery closure roster")
                .local_closed
                .closed_connection_ids,
            vec![second_candidate]
        );
    }

    #[tokio::test]
    async fn successive_recovery_does_not_reuse_completed_episode_closures() {
        let (mut actor, old_key, _old_receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        let candidate_key = CarrierKey::new(2, "candidate");
        let (candidate_tx, candidate_receiver) = mpsc::channel(M2_CARRIER_QUEUE_FRAMES);
        actor.candidate = Some(Carrier {
            key: candidate_key.clone(),
            local_addr: None,
            tx: candidate_tx,
            pending_controls: BTreeMap::new(),
            reader_cancel: CancellationToken::new(),
            reader: None,
            writer: None,
        });
        actor.remember_recovery_trigger(RecoveryTriggerClass::WriterFailed, &old_key);

        let first_attempt = RotationAttemptIdentity::new(
            "session",
            1,
            "owner",
            "recovery-one",
            old_key.generation,
            candidate_key.generation,
            old_key.connection_id.clone(),
            candidate_key.connection_id.clone(),
        );
        let first_roster =
            tunnel_protocol::rotation_control::StreamRoster::new("recovery-one-snapshot", vec![]);
        let now = actor.now_ms();
        let recovery_timeout_ms = actor.rotation.config().recovery_timeout_ms;
        let first_deadline = now
            .checked_add(recovery_timeout_ms)
            .expect("test recovery deadline does not overflow");
        actor
            .rotation
            .transport_lost(&first_attempt, now, RecoveryReason::OldTransportLost)
            .expect("first carrier loss enters recovery");
        let first_closed_evidence = ClosureEvidence::closed(old_key.connection_id.clone());
        actor
            .rotation
            .close_for_recovery(
                old_key.connection_id.clone(),
                first_closed_evidence.clone(),
                now,
            )
            .expect("first carrier closure releases its rotation allocation");
        actor
            .rotation
            .begin_recovery(
                first_attempt.clone(),
                first_roster.clone(),
                now,
                RecoveryReason::OldTransportLost,
                first_deadline,
            )
            .expect("first recovery attempt starts");
        actor
            .rotation
            .reserve_recovery_socket(now)
            .expect("first replacement is reserved");

        let first_begin = RecoveryBegin {
            message_id: "recovery-one-begin".to_owned(),
            reply_to: String::new(),
            attempt: first_attempt,
            episode_id: "recovery-one-episode".to_owned(),
            attempt_no: 1,
            roster: first_roster,
            remaining_ms: recovery_timeout_ms,
        };
        let first_closed = RecoveryClosed {
            message_id: "recovery-one-closed".to_owned(),
            reply_to: first_begin.message_id.clone(),
            attempt: first_begin.attempt.clone(),
            episode_id: first_begin.episode_id.clone(),
            attempt_no: first_begin.attempt_no,
            closed_connection_ids: vec![old_key.connection_id.clone()],
            closure_digest: "recovery-one-digest".to_owned(),
        };
        actor
            .closed_for_recovery
            .insert(old_key.connection_id.clone(), first_closed_evidence);
        actor.recovery = Some(RecoveryRuntime {
            begin: first_begin,
            local_closed: first_closed.clone(),
            prepare_message_id: None,
            peer_closed: None,
            combined_digest: Some("recovery-one-combined".to_owned()),
            deadline_ms: first_deadline,
            attempt_deadline_ms: None,
            authenticated_closed_connection_ids: BTreeSet::new(),
            local_snapshots: [BTreeMap::new(), BTreeMap::new()],
            remote_snapshots: [BTreeMap::new(), BTreeMap::new()],
            remote_ready_snapshots: [BTreeMap::new(), BTreeMap::new()],
            remote_snapshot_message_ids: [None, None],
            snapshot_reply_message_ids: [None, None],
            snapshot_reply_messages: [None, None],
            remote_ready_message_ids: [None, None],
            remote_ready: [true, true],
            local_plans: BTreeMap::new(),
            peer_snapshots: BTreeMap::new(),
            snapshot_replies: [true, true],
            ready_replies: [true, true],
            ready_reply_messages: [None, None],
            fresh_reconciled: true,
        });

        actor
            .maybe_finish_recovery()
            .await
            .expect("first recovery activates its replacement");
        let completed = actor
            .completed_recovery
            .as_ref()
            .expect("first recovery attestation is retained after activation");
        assert_eq!(completed.local_closed, first_closed);
        assert!(
            actor.closed_for_recovery.is_empty(),
            "closure evidence from the completed episode must not enter the next episode"
        );
        assert!(
            actor.first_recovery_trigger.is_none(),
            "the next recovery must observe a new physical trigger"
        );

        // There is no carrier writer task in this unit fixture.  Drop the
        // command receiver before the second close so `close_carrier` records
        // immediate local teardown instead of waiting for an absent close ACK.
        drop(candidate_receiver);
        let second_old_key = actor.active.key.clone();
        actor
            .mark_carrier_closed(&second_old_key, false, false)
            .await
            .expect("second active carrier records local closure");
        let second_candidate_key = CarrierKey::new(3, "second-candidate");
        let second_attempt = RotationAttemptIdentity::new(
            "session",
            1,
            "owner",
            "recovery-two",
            second_old_key.generation,
            second_candidate_key.generation,
            second_old_key.connection_id.clone(),
            second_candidate_key.connection_id.clone(),
        );
        let second_begin = RecoveryBegin {
            message_id: "recovery-two-begin".to_owned(),
            reply_to: String::new(),
            attempt: second_attempt,
            episode_id: "recovery-two-episode".to_owned(),
            attempt_no: 1,
            roster: tunnel_protocol::rotation_control::StreamRoster::new(
                "recovery-two-snapshot",
                vec![],
            ),
            remaining_ms: recovery_timeout_ms,
        };
        actor
            .handle_recovery_begin(second_begin.clone())
            .await
            .expect("second recovery starts from only the current closure");
        let second_recovery = actor
            .recovery
            .as_ref()
            .expect("second recovery remains in flight");
        assert_eq!(second_recovery.begin, second_begin);
        assert_eq!(
            second_recovery.local_closed.closed_connection_ids,
            vec![second_old_key.connection_id]
        );
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

    #[tokio::test]
    async fn critical_control_spill_waits_for_pending_open_pair() {
        let (mut actor, _active_key, _carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        fill_control_queue_before_open(&mut actor)
            .await
            .expect("initial OPEN burst should be admitted");
        actor
            .handle_control(ControlMessage::Open(test_open(9)))
            .await
            .expect("queue pressure should defer one bounded OPEN");
        actor
            .handle_control(ControlMessage::Ping(Ping::new(
                "ping-spill",
                "session",
                1,
                1,
            )))
            .await
            .expect("critical PING should spill while the OPEN pair waits");
        assert!(actor.pending_open.is_some());
        assert_eq!(actor.pending_critical_controls.len(), 1);
        let critical_deadline = actor
            .pending_critical_controls
            .front()
            .expect("spilled PONG should have a retained deadline")
            .deadline;
        assert!(!critical_deadline.expired());
        assert!(critical_deadline.remaining(Instant::now()) <= M2_CRITICAL_CONTROL_TIMEOUT);
        assert_eq!(control_receiver.len(), 15);

        control_receiver
            .try_recv()
            .expect("first queued response should drain");
        control_receiver
            .try_recv()
            .expect("second queued response should drain");
        actor
            .flush_pending_open()
            .expect("drained queue should admit the deferred OPEN");
        actor
            .flush_pending_critical_controls()
            .expect("critical response should drain after the OPEN pair");
        assert!(actor.pending_open.is_none());
        assert!(actor.pending_critical_controls.is_empty());

        let mut queued_messages = Vec::new();
        while let Ok(item) = control_receiver.try_recv() {
            let Message::Text(text) = &item.message else {
                continue;
            };
            queued_messages
                .push(decode_control(text.as_bytes()).expect("queued control should decode"));
        }
        assert!(matches!(
            queued_messages.get(queued_messages.len().saturating_sub(3)),
            Some(ControlMessage::Opened(opened)) if opened.stream_id == 9
        ));
        assert!(matches!(
            queued_messages.get(queued_messages.len().saturating_sub(2)),
            Some(ControlMessage::AuthorizationChallenge(challenge)) if challenge.stream_id == 9
        ));
        assert!(matches!(
            queued_messages.last(),
            Some(ControlMessage::Pong(pong)) if pong.reply_to == "ping-spill"
        ));
    }

    #[test]
    fn critical_control_spill_accepts_one_maximum_protocol_frame() {
        let (mut actor, _active_key, _carrier_receiver, _control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        let deadline = actor
            .critical_control_deadline()
            .expect("critical deadline should be representable");
        let frame = Message::Text("x".repeat(MAX_CONTROL_MESSAGE_BYTES).into());
        actor
            .defer_critical_control(frame.clone(), deadline)
            .expect("a maximum-size protocol control frame must fit the spill");
        assert_eq!(
            actor.pending_critical_control_bytes,
            MAX_CONTROL_MESSAGE_BYTES
        );
        assert_eq!(actor.pending_critical_controls.len(), 1);
        assert!(matches!(
            actor.defer_critical_control(frame, deadline),
            Err(ClientError::QueueLimit)
        ));
    }

    #[tokio::test]
    async fn critical_control_expiry_is_observed_while_open_pair_waits() {
        let (mut actor, _active_key, _carrier_receiver, _control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        fill_control_queue_before_open(&mut actor)
            .await
            .expect("initial OPEN burst should be admitted");
        actor
            .handle_control(ControlMessage::Open(test_open(9)))
            .await
            .expect("OPEN should wait for its atomic pair");
        actor
            .handle_control(ControlMessage::Ping(Ping::new(
                "ping-expired",
                "session",
                1,
                1,
            )))
            .await
            .expect("PONG should enter bounded spill");
        let expired_started = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("test instant should support a bounded subtraction");
        let expired_wall = SystemTime::now()
            .checked_sub(Duration::from_secs(1))
            .expect("test wall clock should support a bounded subtraction");
        actor
            .pending_critical_controls
            .front_mut()
            .expect("PONG should remain in spill")
            .deadline = DualDeadline::new(expired_started, expired_wall, Duration::from_millis(1))
            .expect("expired test deadline should be representable");

        assert!(matches!(
            actor.flush_pending_critical_controls(),
            Err(ClientError::Transport {
                scope: "control response",
                ..
            })
        ));
        assert!(actor.pending_open.is_some());
        assert!(actor.pending_critical_controls.is_empty());
        assert_eq!(actor.pending_critical_control_bytes, 0);
    }

    #[tokio::test]
    async fn multiple_pending_opens_preserve_head_deadline_and_fifo_order() {
        let (mut actor, _active_key, _carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        fill_control_queue_before_open(&mut actor)
            .await
            .expect("initial OPEN burst should be admitted");
        actor
            .handle_control(ControlMessage::Open(test_open(9)))
            .await
            .expect("first OPEN should be retained under queue pressure");

        let (first_message_id, first_operation_deadline, first_auth_deadline) = {
            let pending = actor
                .pending_open
                .as_ref()
                .expect("first OPEN should be the pending head");
            (
                pending.open.message_id.clone(),
                pending.operation_deadline.monotonic,
                pending
                    .authorization
                    .as_ref()
                    .expect("deferred OPEN should retain its authorization deadline")
                    .auth_deadline
                    .monotonic,
            )
        };

        tokio::task::yield_now().await;
        actor
            .handle_control(ControlMessage::Open(test_open(10)))
            .await
            .expect("second OPEN should join the bounded pending FIFO");
        tokio::task::yield_now().await;
        actor
            .handle_control(ControlMessage::Open(test_open(11)))
            .await
            .expect("third OPEN should join the bounded pending FIFO");

        let head = actor
            .pending_open
            .as_ref()
            .expect("later OPENs must not replace the pending head");
        assert_eq!(head.open.message_id, first_message_id);
        assert_eq!(head.operation_deadline.monotonic, first_operation_deadline);
        assert_eq!(
            head.authorization
                .as_ref()
                .expect("pending head authorization must be retained")
                .auth_deadline
                .monotonic,
            first_auth_deadline
        );
        assert_eq!(actor.pending_open_queue.len(), 2);
        assert_eq!(actor.pending_open_queue[0].open.stream_id, 10);
        assert_eq!(actor.pending_open_queue[1].open.stream_id, 11);
        assert!(
            actor.pending_open_queue[0].operation_deadline.monotonic
                <= actor.pending_open_queue[1].operation_deadline.monotonic,
            "queued OPEN deadlines must retain receive order"
        );
        assert_eq!(actor.streams.len(), 8);

        control_receiver
            .try_recv()
            .expect("first queued response should drain");
        control_receiver
            .try_recv()
            .expect("second queued response should drain");
        actor
            .flush_pending_open()
            .expect("the retained head should admit after its pair has room");
        assert!(actor.pending_open.is_none());
        assert_eq!(actor.pending_open_queue.len(), 2);
        assert!(actor.streams.contains_key(&9));
    }

    #[tokio::test]
    async fn expired_pending_open_does_not_block_spilled_critical_response() {
        let (mut actor, _active_key, _carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        fill_control_queue_before_open(&mut actor)
            .await
            .expect("initial OPEN burst should be admitted");
        actor
            .handle_control(ControlMessage::Open(test_open(9)))
            .await
            .expect("queue pressure should retain the OPEN");
        actor
            .handle_control(ControlMessage::Ping(Ping::new(
                "expired-ping",
                "session",
                1,
                1,
            )))
            .await
            .expect("critical PING should spill behind the pending OPEN");

        let expired_started = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("test instant should support bounded subtraction");
        let expired_wall = SystemTime::now()
            .checked_sub(Duration::from_secs(1))
            .expect("test wall clock should support bounded subtraction");
        let expired = DualDeadline::new(expired_started, expired_wall, Duration::from_millis(1))
            .expect("expired test deadline should be representable");
        let pending = actor
            .pending_open
            .as_mut()
            .expect("queue pressure should retain the OPEN");
        pending.operation_deadline = expired;
        pending
            .authorization
            .as_mut()
            .expect("deferred OPEN should retain authorization state")
            .auth_deadline = expired;

        control_receiver
            .try_recv()
            .expect("first queued response should drain");
        control_receiver
            .try_recv()
            .expect("second queued response should drain");
        actor
            .flush_pending_open()
            .expect("expired OPEN should produce a bounded refusal");
        actor
            .flush_pending_critical_controls()
            .expect("the spilled critical response should still make progress");
        assert!(actor.pending_open.is_none());
        assert!(actor.pending_critical_controls.is_empty());

        let mut queued = Vec::new();
        while let Ok(item) = control_receiver.try_recv() {
            let Message::Text(text) = &item.message else {
                continue;
            };
            queued.push(decode_control(text.as_bytes()).expect("queued control should decode"));
        }
        let pong_index = queued.iter().position(|message| {
            matches!(message, ControlMessage::Pong(pong) if pong.reply_to == "expired-ping")
        });
        let rejection_index = queued.iter().position(|message| {
            matches!(
                message,
                ControlMessage::Rejected(rejected)
                    if rejected.stream_id == 9 && rejected.code == "AUTHORIZATION_EXPIRED"
            )
        });
        assert!(
            pong_index.is_some(),
            "spilled critical PING should be delivered"
        );
        assert!(
            rejection_index.is_some(),
            "expired pending OPEN should receive a typed refusal"
        );
        assert!(
            pong_index.expect("spilled PING should have an index")
                < rejection_index.expect("expired OPEN should have an index"),
            "critical responses must retain their receive order"
        );
    }

    #[tokio::test]
    async fn raw_websocket_ping_spills_at_full_control_capacity() {
        let (mut actor, _active_key, _carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        fill_control_queue_before_open(&mut actor)
            .await
            .expect("initial OPEN burst should be admitted");
        actor
            .handle_control(ControlMessage::Ping(Ping::new(
                "fill-control-queue",
                "session",
                1,
                1,
            )))
            .await
            .expect("last control slot should accept the logical PING");
        actor
            .handle_control(ControlMessage::Open(test_open(9)))
            .await
            .expect("OPEN should be retained once its pair cannot fit");

        actor
            .handle_control_message(Message::Ping(b"ws-ping".to_vec().into()))
            .await
            .expect("raw WebSocket PING must use the bounded critical spill");
        assert_eq!(control_receiver.len(), 16);
        assert_eq!(actor.pending_critical_controls.len(), 1);
        assert!(matches!(
            actor
                .pending_critical_controls
                .front()
                .map(|pending| &pending.message),
            Some(Message::Pong(payload)) if payload.as_ref() == b"ws-ping"
        ));

        control_receiver
            .try_recv()
            .expect("first queued response should drain");
        control_receiver
            .try_recv()
            .expect("second queued response should drain");
        actor
            .flush_pending_open()
            .expect("drained queue should admit the pending OPEN");
        control_receiver
            .try_recv()
            .expect("first OPEN response should drain");
        control_receiver
            .try_recv()
            .expect("second OPEN response should drain");
        actor
            .flush_pending_critical_controls()
            .expect("raw WebSocket PONG should drain after the OPEN pair");
        assert!(actor.pending_critical_controls.is_empty());

        let mut saw_pong = false;
        while let Ok(item) = control_receiver.try_recv() {
            if let Message::Pong(payload) = &item.message
                && payload.as_ref() == b"ws-ping"
            {
                saw_pong = true;
            }
        }
        assert!(saw_pong, "raw WebSocket PING should receive a bounded PONG");
    }

    #[tokio::test]
    async fn cancel_removes_pending_open_head_and_queued_entry() {
        let (mut actor, _active_key, _carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        fill_control_queue_before_open(&mut actor)
            .await
            .expect("initial OPEN burst should be admitted");
        let head_open = test_open(9);
        let queued_open = test_open(10);
        actor
            .handle_control(ControlMessage::Open(head_open.clone()))
            .await
            .expect("first OPEN should be retained under queue pressure");
        actor
            .handle_control(ControlMessage::Open(queued_open.clone()))
            .await
            .expect("second OPEN should enter the bounded pending FIFO");
        let retained_before_cancel = actor.pending_open_budget.current();
        assert!(
            retained_before_cancel > 0,
            "the pending head and FIFO entry must hold parsed OPEN budget"
        );
        assert_eq!(
            actor
                .pending_open
                .as_ref()
                .expect("first OPEN should remain the pending head")
                .open
                .stream_id,
            head_open.stream_id
        );
        assert_eq!(actor.pending_open_queue.len(), 1);

        actor
            .handle_control(ControlMessage::Cancel(Cancel::new(
                "cancel-queued-open-wrong-operation",
                "session",
                1,
                queued_open.stream_id,
                "different-operation",
            )))
            .await
            .expect("mismatched CANCEL should remain best effort");
        assert_eq!(actor.pending_open_queue.len(), 1);

        actor
            .handle_control(ControlMessage::Cancel(Cancel::new(
                "cancel-queued-open",
                "session",
                1,
                queued_open.stream_id,
                queued_open.operation_id.clone(),
            )))
            .await
            .expect("CANCEL for a queued OPEN should be handled");
        assert!(
            actor
                .pending_open_queue
                .iter()
                .all(|pending| pending.open.stream_id != queued_open.stream_id),
            "CANCEL must remove a queued pending OPEN"
        );
        assert!(
            actor.pending_open_budget.current() < retained_before_cancel,
            "removing one queued OPEN must release only its parsed reservation"
        );
        assert!(actor.pending_open.is_some());

        actor
            .handle_control(ControlMessage::Cancel(Cancel::new(
                "cancel-head-open",
                "session",
                1,
                head_open.stream_id,
                head_open.operation_id,
            )))
            .await
            .expect("CANCEL for the pending head should be handled");
        assert!(
            actor.pending_open.is_none(),
            "CANCEL must remove the deferred OPEN head"
        );
        assert!(actor.pending_open_queue.is_empty());
        assert_eq!(
            actor.pending_open_budget.current(),
            0,
            "removing the pending head must release the final parsed reservation"
        );

        actor
            .flush_pending_open()
            .expect("canceled OPENs must not fail or become admitted on retry");
        assert_eq!(actor.streams.len(), 8);
        assert!(!actor.streams.contains_key(&head_open.stream_id));
        assert!(!actor.streams.contains_key(&queued_open.stream_id));
        while let Ok(item) = control_receiver.try_recv() {
            let Message::Text(text) = &item.message else {
                continue;
            };
            let message = decode_control(text.as_bytes()).expect("queued control should decode");
            assert!(!matches!(
                &message,
                ControlMessage::Opened(opened)
                    if opened.stream_id == head_open.stream_id
                        || opened.stream_id == queued_open.stream_id
            ));
            assert!(!matches!(
                &message,
                ControlMessage::AuthorizationChallenge(challenge)
                    if challenge.stream_id == head_open.stream_id
                        || challenge.stream_id == queued_open.stream_id
            ));
        }
    }

    #[tokio::test]
    async fn duplicate_open_replays_original_responses_without_refreshing_admission() {
        let (mut actor, _active_key, _carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        let open = test_open(1);
        actor
            .handle_control(ControlMessage::Open(open.clone()))
            .await
            .expect("initial OPEN should be admitted");
        let initial = drain_control_messages(&mut control_receiver);
        assert_eq!(
            initial.len(),
            2,
            "OPEN admission must emit OPENED plus challenge"
        );
        assert!(matches!(
            initial.first(),
            Some(ControlMessage::Opened(opened))
                if opened.reply_to == open.message_id && opened.stream_id == open.stream_id
        ));
        assert!(matches!(
            initial.get(1),
            Some(ControlMessage::AuthorizationChallenge(challenge))
                if challenge.stream_id == open.stream_id
        ));
        let before = {
            let stream = actor
                .streams
                .get(&open.stream_id)
                .expect("initial OPEN should create one stream");
            (
                stream.auth.challenge_id.clone(),
                stream.auth.nonce.clone(),
                stream.auth.deadline.monotonic,
                stream.auth.deadline.wall,
                stream.auth.operation_deadline.monotonic,
                stream.auth.operation_deadline.wall,
            )
        };

        actor
            .handle_control(ControlMessage::Open(open.clone()))
            .await
            .expect("an identical OPEN retry should replay its bounded responses");
        let replay = drain_control_messages(&mut control_receiver);
        assert_eq!(
            replay,
            vec![initial[0].clone()],
            "identical OPEN must replay only the immutable OPENED response"
        );
        assert_eq!(
            actor.streams.len(),
            1,
            "a retry must not admit a second stream"
        );
        let after = {
            let stream = actor
                .streams
                .get(&open.stream_id)
                .expect("the original stream must remain admitted");
            (
                stream.auth.challenge_id.clone(),
                stream.auth.nonce.clone(),
                stream.auth.deadline.monotonic,
                stream.auth.deadline.wall,
                stream.auth.operation_deadline.monotonic,
                stream.auth.operation_deadline.wall,
            )
        };
        assert_eq!(
            after, before,
            "replay must not refresh challenge or operation deadlines"
        );
    }

    #[tokio::test]
    async fn confirmed_open_retry_does_not_replay_authorization_refresh() {
        let (mut actor, _active_key, _carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        // Use a short, valid grant window so the test observes the real
        // initial-confirmation -> refresh-confirmation transition without a
        // multi-second sleep.
        actor.config.limits.grant_timeout_ms = 250;
        let open = test_open(1);
        actor
            .handle_control(ControlMessage::Open(open.clone()))
            .await
            .expect("initial OPEN should be admitted");
        let initial = drain_control_messages(&mut control_receiver);
        assert_eq!(initial.len(), 2);
        let initial_challenge = match initial.get(1) {
            Some(ControlMessage::AuthorizationChallenge(challenge)) => challenge.clone(),
            other => panic!("initial OPEN should emit its challenge, got {other:?}"),
        };
        let initial_challenge_deadline = actor
            .streams
            .get(&open.stream_id)
            .expect("initial OPEN should create one stream")
            .auth
            .deadline;
        actor
            .handle_authorization_confirmed(AuthorizationConfirmed::new(
                "initial-confirmation",
                initial_challenge.message_id.clone(),
                "session",
                1,
                open.stream_id,
                initial_challenge.challenge_id.clone(),
                initial_challenge.nonce.clone(),
                initial_challenge.permission_digest.clone(),
                initial_challenge.grant_revision,
                250,
            ))
            .await
            .expect("the initial challenge should confirm");

        tokio::time::sleep(Duration::from_millis(20)).await;
        // Keep the original 250 ms challenge deadline as the historical
        // boundary, but give the actual refreshed grant a full five seconds
        // so scheduler load cannot make this assertion race its expiry.
        actor.config.limits.grant_timeout_ms = 5_000;
        actor
            .refresh_authorizations()
            .await
            .expect("the confirmed stream should receive a real refresh challenge");
        let refresh_messages = drain_control_messages(&mut control_receiver);
        let refresh_challenge = refresh_messages.iter().find_map(|message| match message {
            ControlMessage::AuthorizationChallenge(challenge) => Some(challenge.clone()),
            _ => None,
        });
        let refresh_challenge = refresh_challenge.expect("refresh should emit one challenge");
        actor
            .handle_authorization_confirmed(AuthorizationConfirmed::new(
                "refresh-confirmation",
                refresh_challenge.message_id.clone(),
                "session",
                1,
                open.stream_id,
                refresh_challenge.challenge_id.clone(),
                refresh_challenge.nonce.clone(),
                refresh_challenge.permission_digest.clone(),
                refresh_challenge.grant_revision,
                5_000,
            ))
            .await
            .expect("the refresh challenge should confirm");

        // Let the original challenge window expire while retaining the newer
        // confirmed grant. This is the state in which replaying the old
        // challenge would incorrectly refresh authorization.
        let wait = initial_challenge_deadline
            .monotonic
            .saturating_duration_since(Instant::now())
            + Duration::from_millis(2);
        tokio::time::sleep(wait).await;
        assert!(initial_challenge_deadline.expired());
        assert!(
            !actor
                .streams
                .get(&open.stream_id)
                .expect("the refreshed stream should remain active")
                .auth
                .deadline
                .expired()
        );
        let before = {
            let stream = actor
                .streams
                .get(&open.stream_id)
                .expect("the refreshed stream should remain active");
            (
                stream.auth.challenge_id.clone(),
                stream.auth.nonce.clone(),
                stream.auth.permission_digest.clone(),
                stream.auth.grant_revision,
                stream.auth.deadline.monotonic,
                stream.auth.deadline.wall,
                stream.auth.operation_deadline.monotonic,
                stream.auth.operation_deadline.wall,
            )
        };

        actor
            .handle_control(ControlMessage::Open(open))
            .await
            .expect("a confirmed OPEN retry should replay OPENED");
        let replay = drain_control_messages(&mut control_receiver);
        assert_eq!(
            replay,
            vec![initial[0].clone()],
            "a confirmed retry must not replay the independent auth challenge"
        );
        assert!(
            !replay
                .iter()
                .any(|message| matches!(message, ControlMessage::AuthorizationChallenge(_)))
        );
        let after = {
            let stream = actor
                .streams
                .get(&1)
                .expect("the refreshed stream should remain active");
            (
                stream.auth.challenge_id.clone(),
                stream.auth.nonce.clone(),
                stream.auth.permission_digest.clone(),
                stream.auth.grant_revision,
                stream.auth.deadline.monotonic,
                stream.auth.deadline.wall,
                stream.auth.operation_deadline.monotonic,
                stream.auth.operation_deadline.wall,
            )
        };
        assert_eq!(after, before, "a retry must not refresh any auth state");
    }

    #[tokio::test]
    async fn duplicate_pending_open_coalesces_without_refreshing_deadlines() {
        let (mut actor, _active_key, _carrier_receiver, control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        fill_control_queue_before_open(&mut actor)
            .await
            .expect("initial OPEN burst should fill the bounded response queue");
        let open = test_open(9);
        actor
            .handle_control(ControlMessage::Open(open.clone()))
            .await
            .expect("the first OPEN should wait for its atomic response pair");
        let retained_bytes = pending_open_retained_bytes(&open).expect("bounded OPEN estimate");
        assert_eq!(
            actor.pending_open_budget.current(),
            retained_bytes,
            "a deferred OPEN must reserve its parsed representation"
        );
        let before = {
            let pending = actor
                .pending_open
                .as_ref()
                .expect("the first OPEN should be the pending head");
            (
                pending.open.message_id.clone(),
                pending.operation_deadline.monotonic,
                pending.operation_deadline.wall,
                pending
                    .authorization
                    .as_ref()
                    .expect("the pending OPEN should retain its challenge")
                    .challenge_id
                    .clone(),
                pending
                    .authorization
                    .as_ref()
                    .expect("the pending OPEN should retain its challenge")
                    .nonce
                    .clone(),
                pending
                    .authorization
                    .as_ref()
                    .expect("the pending OPEN should retain its challenge")
                    .auth_deadline
                    .monotonic,
                pending
                    .authorization
                    .as_ref()
                    .expect("the pending OPEN should retain its challenge")
                    .auth_deadline
                    .wall,
            )
        };
        assert!(actor.pending_open_queue.is_empty());
        assert_eq!(control_receiver.len(), 15);

        actor
            .handle_control(ControlMessage::Open(open))
            .await
            .expect("an identical pending OPEN should be coalesced");
        assert_eq!(
            actor.pending_open_budget.current(),
            retained_bytes,
            "an idempotent pending retry must not double-charge parsed state"
        );
        assert!(
            actor.pending_open_queue.is_empty(),
            "a duplicate pending OPEN must not consume another FIFO slot"
        );
        let after = {
            let pending = actor
                .pending_open
                .as_ref()
                .expect("the original pending OPEN must remain the head");
            (
                pending.open.message_id.clone(),
                pending.operation_deadline.monotonic,
                pending.operation_deadline.wall,
                pending
                    .authorization
                    .as_ref()
                    .expect("the pending OPEN should retain its challenge")
                    .challenge_id
                    .clone(),
                pending
                    .authorization
                    .as_ref()
                    .expect("the pending OPEN should retain its challenge")
                    .nonce
                    .clone(),
                pending
                    .authorization
                    .as_ref()
                    .expect("the pending OPEN should retain its challenge")
                    .auth_deadline
                    .monotonic,
                pending
                    .authorization
                    .as_ref()
                    .expect("the pending OPEN should retain its challenge")
                    .auth_deadline
                    .wall,
            )
        };
        assert_eq!(
            after, before,
            "coalescing must preserve all original deadlines and IDs"
        );
        assert_eq!(
            control_receiver.len(),
            15,
            "coalescing must not emit a duplicate response"
        );
    }

    #[tokio::test]
    async fn pending_open_budget_releases_after_deferred_pair_admission() {
        let (mut actor, _active_key, _carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        fill_control_queue_before_open(&mut actor)
            .await
            .expect("initial OPEN burst should fill the bounded response queue");
        let open = test_open(9);
        actor
            .handle_control(ControlMessage::Open(open))
            .await
            .expect("the OPEN should be retained until both response slots fit");
        assert!(actor.pending_open_budget.current() > 0);

        for _ in 0..15 {
            control_receiver
                .try_recv()
                .expect("the existing bounded responses should drain");
        }
        actor
            .flush_pending_open()
            .expect("the deferred atomic pair should admit after the drain");
        assert!(actor.pending_open.is_none());
        assert!(actor.pending_open_queue.is_empty());
        assert_eq!(
            actor.pending_open_budget.current(),
            0,
            "admission must release the parsed OPEN reservation exactly once"
        );
    }

    #[tokio::test]
    async fn pending_open_budget_exhaustion_is_a_typed_rejection() {
        let (mut actor, _active_key, _carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        fill_control_queue_before_open(&mut actor)
            .await
            .expect("initial OPEN burst should fill the bounded response queue");
        let open = test_open(9);
        let estimate = pending_open_retained_bytes(&open).expect("bounded OPEN estimate");
        Arc::get_mut(&mut actor.pending_open_budget)
            .expect("test actor should own the parsed OPEN budget")
            .maximum = estimate.saturating_sub(1);

        actor
            .handle_control(ControlMessage::Open(open.clone()))
            .await
            .expect("parsed-OPEN exhaustion should return a bounded refusal");
        let response = drain_control_messages(&mut control_receiver);
        assert!(matches!(
            response.last(),
            Some(ControlMessage::Rejected(rejected))
                if rejected.reply_to == open.message_id
                    && rejected.code == "RESOURCE_EXHAUSTED"
                    && rejected.reason.contains("parsed OPEN retention")
        ));
        assert!(actor.pending_open.is_none());
        assert!(actor.pending_open_queue.is_empty());
        assert_eq!(
            actor.pending_open_budget.current(),
            0,
            "a typed parsed-OPEN refusal must not leave a reservation behind"
        );
    }

    #[tokio::test]
    async fn changed_open_body_with_reused_message_id_is_a_protocol_error() {
        let (mut actor, _active_key, _carrier_receiver, _control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        let first = test_open(1);
        actor
            .handle_control(ControlMessage::Open(first.clone()))
            .await
            .expect("initial OPEN should be admitted");
        let mut changed = test_open(2);
        changed.message_id = first.message_id;
        let error = actor
            .handle_control(ControlMessage::Open(changed))
            .await
            .expect_err("reusing an OPEN message ID with a changed body must fail closed");
        assert!(
            matches!(error, ClientError::Protocol(_)),
            "conflicting OPEN IDs must be typed as protocol errors: {error:?}"
        );
        assert_eq!(
            actor.streams.len(),
            1,
            "conflicting content must not admit another stream"
        );
        assert!(!actor.streams.contains_key(&2));
    }

    #[tokio::test]
    async fn new_open_message_id_reusing_stream_id_is_typed_stream_exists() {
        let (mut actor, _active_key, _carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        let first = test_open(1);
        actor
            .handle_control(ControlMessage::Open(first))
            .await
            .expect("initial OPEN should be admitted");
        let mut duplicate_stream = test_open(2);
        duplicate_stream.message_id = "open-message-new-stream-id-conflict".to_owned();
        duplicate_stream.operation_id = "operation-new-stream-id-conflict".to_owned();
        duplicate_stream.stream_id = 1;
        actor
            .handle_control(ControlMessage::Open(duplicate_stream.clone()))
            .await
            .expect("a new message ID may receive a typed stream conflict");
        let messages = drain_control_messages(&mut control_receiver);
        assert!(matches!(
            messages.last(),
            Some(ControlMessage::Rejected(rejected))
                if rejected.reply_to == duplicate_stream.message_id
                    && rejected.stream_id == duplicate_stream.stream_id
                    && rejected.code == "STREAM_EXISTS"
        ));
        assert_eq!(
            actor.streams.len(),
            1,
            "STREAM_EXISTS must not replace the original stream"
        );
    }

    #[tokio::test]
    async fn stream_forget_purges_matching_pending_open_before_journal_compaction() {
        let (mut actor, active_key, mut carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);

        // Leave one response slot available: the first OPEN needs an atomic
        // two-message pair and therefore becomes the pending head. A second
        // message ID for the same stream/operation is retained behind it.
        for nonce in 0..15 {
            actor
                .handle_control(ControlMessage::Ping(Ping::new(
                    format!("pending-forget-ping-{nonce}"),
                    "session",
                    1,
                    nonce,
                )))
                .await
                .expect("bounded PONG burst should fit the control queue");
        }
        assert_eq!(control_receiver.len(), 15);

        let first = test_open(1);
        actor
            .handle_control(ControlMessage::Open(first.clone()))
            .await
            .expect("the first OPEN should wait for its atomic pair");
        assert!(actor.pending_open.is_some());

        let mut queued = first.clone();
        queued.message_id = "pending-forget-queued".to_owned();
        actor
            .handle_control(ControlMessage::Open(queued))
            .await
            .expect("the correlated second OPEN should retain FIFO order");
        let other = test_open(2);
        actor
            .handle_control(ControlMessage::Open(other.clone()))
            .await
            .expect("an independent OPEN should remain after the correlated one");
        let tail = test_open(3);
        actor
            .handle_control(ControlMessage::Open(tail.clone()))
            .await
            .expect("a later independent OPEN should retain its FIFO position");
        assert_eq!(actor.pending_open_queue.len(), 3);

        let other_deadline = actor.pending_open_queue[1].operation_deadline;
        for _ in 0..15 {
            control_receiver
                .try_recv()
                .expect("the queued PONG burst should drain");
        }
        actor
            .flush_pending_open()
            .expect("the first OPEN should admit after the writer drains");
        assert!(actor.streams.contains_key(&first.stream_id));
        assert_eq!(actor.pending_open_queue.len(), 3);

        let (sequence, final_state) = test_owner_forget_sequence(first.stream_id);
        {
            let stream = actor
                .streams
                .get_mut(&first.stream_id)
                .expect("the first OPEN should own the stream");
            stream.sequence = sequence;
            stream.input_fin = true;
            stream.output_fin = true;
        }
        actor
            .handle_stream_forget(tunnel_protocol::rotation_control::StreamForget {
                message_id: "pending-forget".to_owned(),
                reply_to: String::new(),
                session_id: "session".to_owned(),
                epoch: 1,
                stream_id: first.stream_id,
                operation_id: first.operation_id.clone(),
                direction: Direction::RelayToConnector,
                final_state,
            })
            .expect("correlated FORGET should queue its carrier barrier");
        assert!(matches!(
            carrier_receiver
                .try_recv()
                .expect("FORGET should queue a carrier barrier"),
            CarrierCommand::Barrier
        ));
        actor
            .handle_barrier_complete(&active_key)
            .expect("the carrier barrier should complete FORGET");
        assert!(!actor.streams.contains_key(&first.stream_id));

        assert_eq!(actor.pending_open_queue.len(), 2);
        assert_eq!(
            actor.pending_open_queue[0].open.message_id,
            other.message_id
        );
        assert_eq!(actor.pending_open_queue[1].open.message_id, tail.message_id);
        assert_eq!(
            actor.pending_open_queue[0].operation_deadline.monotonic, other_deadline.monotonic,
            "purging the matching OPEN must not extend the next operation deadline"
        );

        actor
            .flush_pending_open()
            .expect("the next independent OPEN should retain FIFO order");
        assert!(actor.streams.contains_key(&other.stream_id));
        assert!(actor.pending_open.is_none());
        assert_eq!(actor.pending_open_queue.len(), 1);
        assert_eq!(actor.pending_open_queue[0].open.message_id, tail.message_id);
    }

    #[tokio::test]
    async fn stream_forget_releases_pending_open_budget_once() {
        let (mut actor, active_key, mut carrier_receiver, _control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        for nonce in 0..15 {
            actor
                .handle_control(ControlMessage::Ping(Ping::new(
                    format!("pending-budget-forget-ping-{nonce}"),
                    "session",
                    1,
                    nonce,
                )))
                .await
                .expect("bounded PONG burst should fit the control queue");
        }
        let open = test_open(1);
        actor
            .handle_control(ControlMessage::Open(open.clone()))
            .await
            .expect("the OPEN should retain its parsed state while its pair waits");
        assert!(actor.pending_open_budget.current() > 0);

        let forget = tunnel_protocol::rotation_control::StreamForget {
            message_id: "pending-budget-forget".to_owned(),
            reply_to: String::new(),
            session_id: "session".to_owned(),
            epoch: 1,
            stream_id: open.stream_id,
            operation_id: open.operation_id,
            direction: Direction::RelayToConnector,
            final_state: no_stream_forget_state(open.stream_id),
        };
        actor
            .handle_stream_forget(forget.clone())
            .expect("FORGET should authenticate the retained pending OPEN");
        assert!(matches!(
            carrier_receiver
                .try_recv()
                .expect("FORGET should queue a carrier barrier"),
            CarrierCommand::Barrier
        ));
        actor
            .handle_barrier_complete(&active_key)
            .expect("the carrier barrier should complete pending cleanup");
        assert!(actor.pending_open.is_none());
        assert!(actor.pending_open_queue.is_empty());
        assert_eq!(
            actor.pending_open_budget.current(),
            0,
            "pending-only FORGET must release the parsed reservation"
        );

        actor
            .handle_stream_forget(forget)
            .expect("repeated FORGET should remain idempotent");
        assert_eq!(
            actor.pending_open_budget.current(),
            0,
            "repeated FORGET must not release parsed budget twice"
        );
    }

    #[tokio::test]
    async fn rejected_open_reserves_stream_id_for_new_message_ids() {
        let (mut actor, _active_key, _carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        let mut rejected_open = test_open(1);
        rejected_open.service_id = "not-exported".to_owned();
        actor
            .handle_control(ControlMessage::Open(rejected_open.clone()))
            .await
            .expect("the first OPEN should receive a typed rejection");
        let first_response = drain_control_messages(&mut control_receiver);
        assert!(matches!(
            first_response.last(),
            Some(ControlMessage::Rejected(rejected))
                if rejected.code == "EXPORT_DENIED"
                    && rejected.stream_id == rejected_open.stream_id
        ));
        assert!(actor.streams.is_empty());
        assert_eq!(
            actor.pending_open_budget.current(),
            0,
            "an immediate OPEN rejection must release parsed admission state"
        );

        let mut reused = test_open(2);
        reused.stream_id = rejected_open.stream_id;
        reused.message_id = "reused-rejected-stream".to_owned();
        actor
            .handle_control(ControlMessage::Open(reused.clone()))
            .await
            .expect("a reused stream ID should receive a typed conflict");
        let second_response = drain_control_messages(&mut control_receiver);
        assert!(matches!(
            second_response.last(),
            Some(ControlMessage::Rejected(rejected))
                if rejected.code == "STREAM_EXISTS"
                    && rejected.stream_id == reused.stream_id
                    && rejected.reply_to == reused.message_id
        ));
        assert!(
            !actor.streams.contains_key(&reused.stream_id),
            "a rejected OPEN must reserve its stream ID for the session"
        );
    }

    #[tokio::test]
    async fn stream_reservation_uses_first_receive_order_for_pending_opens() {
        let (mut actor, _active_key, _carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        fill_control_queue_before_open(&mut actor)
            .await
            .expect("the control queue should be full before the OPEN pair");
        let first = test_open(9);
        actor
            .handle_control(ControlMessage::Open(first.clone()))
            .await
            .expect("the first OPEN should retain the pending head");
        let mut second = first.clone();
        second.message_id = "later-same-stream".to_owned();
        actor
            .handle_control(ControlMessage::Open(second.clone()))
            .await
            .expect("the later same-stream OPEN should retain FIFO order");
        assert_eq!(actor.pending_open_queue.len(), 1);

        for _ in 0..15 {
            control_receiver
                .try_recv()
                .expect("the existing control responses should drain");
        }
        actor
            .flush_pending_open()
            .expect("the first received OPEN must be admitted");
        assert!(actor.streams.contains_key(&first.stream_id));

        actor
            .flush_pending_open()
            .expect("the later same-stream OPEN should receive a conflict");
        assert!(actor.streams.contains_key(&first.stream_id));
        let responses = drain_control_messages(&mut control_receiver);
        assert!(matches!(
            responses.last(),
            Some(ControlMessage::Rejected(rejected))
                if rejected.code == "STREAM_EXISTS"
                    && rejected.reply_to == second.message_id
        ));
    }

    #[tokio::test]
    async fn cancelled_pending_open_reserves_stream_id_for_new_message_ids() {
        let (mut actor, _active_key, _carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        fill_control_queue_before_open(&mut actor)
            .await
            .expect("the control queue should be full before the OPEN pair");
        let cancelled = test_open(9);
        actor
            .handle_control(ControlMessage::Open(cancelled.clone()))
            .await
            .expect("the OPEN should retain a pending journal entry");
        actor
            .handle_control(ControlMessage::Cancel(Cancel::new(
                "cancel-stream-reservation",
                "session",
                1,
                cancelled.stream_id,
                cancelled.operation_id.clone(),
            )))
            .await
            .expect("CANCEL should compact the pending OPEN");
        assert!(actor.pending_open.is_none());

        let mut reused = test_open(10);
        reused.stream_id = cancelled.stream_id;
        reused.message_id = "reused-cancelled-stream".to_owned();
        actor
            .handle_control(ControlMessage::Open(reused.clone()))
            .await
            .expect("the reused stream should retain a bounded pending response");
        for _ in 0..15 {
            control_receiver
                .try_recv()
                .expect("the existing control responses should drain");
        }
        actor
            .flush_pending_open()
            .expect("the cancelled reservation should produce a typed conflict");
        assert!(!actor.streams.contains_key(&reused.stream_id));
        let responses = drain_control_messages(&mut control_receiver);
        assert!(matches!(
            responses.last(),
            Some(ControlMessage::Rejected(rejected))
                if rejected.code == "STREAM_EXISTS"
                    && rejected.reply_to == reused.message_id
        ));
    }

    #[tokio::test]
    async fn stream_forget_prioritizes_active_operation_over_rejected_entries() {
        let (mut actor, active_key, mut carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        let first = test_open(1);
        actor
            .handle_control(ControlMessage::Open(first.clone()))
            .await
            .expect("initial OPEN should be admitted");
        let mut rejected = test_open(2);
        rejected.message_id = "open-message-0-rejected".to_owned();
        rejected.operation_id = "operation-rejected".to_owned();
        rejected.stream_id = first.stream_id;
        actor
            .handle_control(ControlMessage::Open(rejected.clone()))
            .await
            .expect("a reused stream ID should receive a journaled rejection");
        let responses = drain_control_messages(&mut control_receiver);
        assert!(responses.iter().any(|message| matches!(
            message,
            ControlMessage::Rejected(rejected_response)
                if rejected_response.reply_to == rejected.message_id
                    && rejected_response.code == "STREAM_EXISTS"
        )));
        let used_before_forget = actor.open_journal.used_bytes();

        let (sequence, final_state) = test_owner_forget_sequence(first.stream_id);
        {
            let stream = actor
                .streams
                .get_mut(&first.stream_id)
                .expect("the original stream should remain active");
            stream.sequence = sequence;
            stream.input_fin = true;
            stream.output_fin = true;
        }
        let original_forget = tunnel_protocol::rotation_control::StreamForget {
            message_id: "forget-original-operation".to_owned(),
            reply_to: String::new(),
            session_id: "session".to_owned(),
            epoch: 1,
            stream_id: first.stream_id,
            operation_id: first.operation_id.clone(),
            direction: Direction::RelayToConnector,
            final_state,
        };
        actor
            .handle_stream_forget(original_forget)
            .expect("the active stream operation must win over an earlier rejection");
        assert!(matches!(
            carrier_receiver
                .try_recv()
                .expect("active FORGET barrier should queue"),
            CarrierCommand::Barrier
        ));
        actor
            .handle_barrier_complete(&active_key)
            .expect("active stream FORGET barrier should complete");
        let used_after_original = actor.open_journal.used_bytes();
        assert!(used_after_original < used_before_forget);
        assert!(actor.streams.is_empty());

        // The rejected entry has no M2Stream, but its exact operation remains
        // independently forgettable even after the stream-ID watermark moves.
        let rejected_forget = tunnel_protocol::rotation_control::StreamForget {
            message_id: "forget-rejected-operation".to_owned(),
            reply_to: String::new(),
            session_id: "session".to_owned(),
            epoch: 1,
            stream_id: rejected.stream_id,
            operation_id: rejected.operation_id,
            direction: Direction::RelayToConnector,
            final_state: no_stream_forget_state(rejected.stream_id),
        };
        actor
            .handle_stream_forget(rejected_forget)
            .expect("the rejected operation should retain its own cleanup identity");
        assert!(matches!(
            carrier_receiver
                .try_recv()
                .expect("rejected FORGET barrier should queue after watermark"),
            CarrierCommand::Barrier
        ));
        actor
            .handle_barrier_complete(&active_key)
            .expect("rejected FORGET barrier should compact its own journal entry");
        assert!(
            actor.open_journal.used_bytes() < used_after_original,
            "compacting the rejected entry must release only its own response charge"
        );
        assert!(
            actor
                .open_journal
                .retained_operation_matches(first.stream_id, "operation-rejected")
                .is_none()
        );
    }

    /// Drive one admitted stream through its owner-ordered reclamation and
    /// return the responses the connector queued for it.
    async fn open_forget_cycle(
        actor: &mut M2Actor,
        active_key: &CarrierKey,
        carrier_receiver: &mut mpsc::Receiver<CarrierCommand>,
        control_receiver: &mut mpsc::Receiver<crate::QueuedMessage>,
        stream_id: u64,
    ) -> (Vec<ControlMessage>, usize) {
        let open = test_open(stream_id);
        actor
            .handle_control(ControlMessage::Open(open.clone()))
            .await
            .expect("a sequential OPEN should be handled");
        let responses = drain_control_messages(control_receiver);
        let entries_while_live = actor.open_journal.entry_count();
        if !actor.streams.contains_key(&stream_id) {
            return (responses, entries_while_live);
        }
        let (sequence, final_state) = test_owner_forget_sequence(stream_id);
        {
            let stream = actor
                .streams
                .get_mut(&stream_id)
                .expect("admitted OPEN should have a stream");
            stream.sequence = sequence;
            stream.input_fin = true;
            stream.output_fin = true;
        }
        actor
            .handle_stream_forget(tunnel_protocol::rotation_control::StreamForget {
                message_id: format!("forget-{stream_id}"),
                reply_to: String::new(),
                session_id: "session".to_owned(),
                epoch: 1,
                stream_id,
                operation_id: open.operation_id.clone(),
                direction: Direction::RelayToConnector,
                final_state,
            })
            .expect("authenticated FORGET should queue its carrier barrier");
        while carrier_receiver.try_recv().is_ok() {}
        actor
            .handle_barrier_complete(active_key)
            .expect("carrier barrier should complete FORGET");
        (responses, entries_while_live)
    }

    /// The relay's unary echo window: `wire::MAX_ECHO_WINDOW_BYTES`, the
    /// 64 KiB body bound plus the 256-byte canary.  Restated because the
    /// relay crate is not a dependency of the connector.
    const UNARY_ECHO_WINDOW: u64 = 64 * 1024 + 256;

    /// The owner evidence the relay (task row M7-C92) derives for a completed
    /// unary echo: its fixed DATA(1)+FIN(2) exchange, fully acknowledged.
    fn unary_echo_owner_forget_state(stream_id: u64, body_len: u64) -> ResumeDirectionState {
        let snapshot = DirectionSnapshot {
            last_emitted: 2,
            peer_acked: 2,
            recv_contiguous: 0,
            delivered_contiguous: 0,
            send_credit: UNARY_ECHO_WINDOW,
            sent_bytes: body_len,
            receive_credit: UNARY_ECHO_WINDOW,
            received_bytes: 0,
            send_terminal: Some(tunnel_protocol::sequence::Terminal::Fin),
            send_terminal_sequence: Some(2),
            receive_terminal: None,
            receive_terminal_sequence: None,
            replay_floor: None,
            replay_bytes: 0,
            reorder_frames: 0,
            reorder_bytes: 0,
        };
        ResumeDirectionState::from_sequence_snapshot(stream_id, &snapshot)
            .expect("unary echo owner evidence is a valid resume state")
    }

    /// Frames the connector queued on its carrier since the last drain.
    fn drain_carrier_frames(receiver: &mut mpsc::Receiver<CarrierCommand>) -> Vec<Frame> {
        let mut frames = Vec::new();
        while let Ok(command) = receiver.try_recv() {
            if let CarrierCommand::Frame(frame) = command {
                frames.push(Frame::decode(&frame.bytes).expect("carrier frame decodes"));
            }
        }
        frames
    }

    /// M7-C92: the owner's STREAM_FORGET for a completed unary echo is what
    /// releases its OPEN journal entry, and the idempotency guarantee the
    /// journal exists for still holds on both sides of it.  Before the
    /// FORGET a replayed OPEN is deduplicated without a second dispatch;
    /// after it the replay is past the OPEN retry horizon and is refused
    /// `STREAM_EXISTS`, again without a second dispatch, whatever carrier or
    /// rotation it arrives after.  The FORGET carries exactly the evidence
    /// the relay derives, so this also proves the connector accepts it.
    #[tokio::test]
    async fn forgotten_unary_echo_open_replay_is_refused_without_second_dispatch() {
        let (mut actor, active_key, mut carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        let stream_id = 1;
        let body = b"unary-echo-body".to_vec();
        let open = Open::new(
            "unary-open-message",
            "session",
            1,
            stream_id,
            "unary-operation",
            "echo",
            "echo",
            UNARY_ECHO_WINDOW,
            UNARY_ECHO_WINDOW,
        );
        actor
            .handle_control(ControlMessage::Open(open.clone()))
            .await
            .expect("the unary echo OPEN is admitted");
        let challenge = drain_control_messages(&mut control_receiver)
            .into_iter()
            .find_map(|message| match message {
                ControlMessage::AuthorizationChallenge(challenge) => Some(challenge),
                _ => None,
            })
            .expect("the OPEN is challenged");
        actor
            .handle_authorization_confirmed(AuthorizationConfirmed::new(
                "unary-confirmation",
                challenge.message_id.clone(),
                "session",
                1,
                stream_id,
                challenge.challenge_id.clone(),
                challenge.nonce.clone(),
                challenge.permission_digest.clone(),
                challenge.grant_revision,
                5_000,
            ))
            .await
            .expect("the challenge confirms");
        actor
            .handle_frame(
                active_key.clone(),
                Frame::data(1, 1, stream_id, 1, 0, body.clone()),
            )
            .await
            .expect("the relay's DATA is accepted");
        actor
            .handle_frame(active_key.clone(), Frame::fin(1, 1, stream_id, 2, 0))
            .await
            .expect("the relay's FIN is accepted");
        actor
            .flush_pending_outputs()
            .await
            .expect("the echo response flushes");
        actor
            .flush_pending_carrier_controls()
            .expect("the ACK feedback flushes");
        let frames = drain_carrier_frames(&mut carrier_receiver);
        let dispatches = |frames: &[Frame]| {
            frames
                .iter()
                .filter(|frame| frame.kind == FrameKind::Data && frame.stream_id == stream_id)
                .count()
        };
        assert!(dispatches(&frames) > 0, "the echo is dispatched once");
        let response_fin = frames
            .iter()
            .find(|frame| frame.kind == FrameKind::Fin && frame.stream_id == stream_id)
            .map(|frame| frame.sequence)
            .expect("the connector finishes its response");
        assert!(
            frames
                .iter()
                .filter(|frame| frame.stream_id == stream_id)
                .any(|frame| frame.ack == 2),
            "the connector acknowledges the relay's FIN, which the owner's proof requires"
        );
        actor
            .handle_frame(
                active_key.clone(),
                Frame::ack(1, 1, stream_id, response_fin),
            )
            .await
            .expect("the relay acknowledges the connector's FIN");

        // Inside the retention window a replay is deduplicated: the retained
        // OPENED is replayed and nothing is dispatched again.
        drain_control_messages(&mut control_receiver);
        actor
            .handle_control(ControlMessage::Open(open.clone()))
            .await
            .expect("a retained replay is answered from the journal");
        let replayed = drain_control_messages(&mut control_receiver);
        assert!(
            replayed.iter().any(|message| matches!(
                message,
                ControlMessage::Opened(opened) if opened.reply_to == open.message_id
            )),
            "the retained reply is replayed: {replayed:?}"
        );
        assert_eq!(dispatches(&drain_carrier_frames(&mut carrier_receiver)), 0);

        actor
            .handle_stream_forget(tunnel_protocol::rotation_control::StreamForget {
                message_id: "unary-forget".to_owned(),
                reply_to: String::new(),
                session_id: "session".to_owned(),
                epoch: 1,
                stream_id,
                operation_id: open.operation_id.clone(),
                direction: Direction::RelayToConnector,
                final_state: unary_echo_owner_forget_state(stream_id, body.len() as u64),
            })
            .expect("the connector accepts the relay's unary evidence");
        while carrier_receiver.try_recv().is_ok() {}
        actor
            .handle_barrier_complete(&active_key)
            .expect("the FORGET barrier completes");
        assert!(!actor.streams.contains_key(&stream_id));
        assert_eq!(
            actor.open_journal.entry_count(),
            0,
            "the FORGET releases the unary echo's journal entry"
        );

        // Past the horizon the same OPEN is refused, not dispatched again.
        actor
            .handle_control(ControlMessage::Open(open.clone()))
            .await
            .expect("a post-horizon replay is a typed refusal");
        assert!(matches!(
            drain_control_messages(&mut control_receiver).last(),
            Some(ControlMessage::Rejected(rejected))
                if rejected.code == "STREAM_EXISTS" && rejected.reply_to == open.message_id
        ));
        assert!(!actor.streams.contains_key(&stream_id));
        assert_eq!(dispatches(&drain_carrier_frames(&mut carrier_receiver)), 0);
        assert_eq!(
            actor.open_journal.entry_count(),
            0,
            "the refusal is not journaled"
        );
    }

    /// M7-C82: a long-lived session serves an unbounded number of sequential
    /// streams.  Before the OPEN retry horizon this died at the 128th stream:
    /// the journal refused admission and the owner's next STREAM_FORGET for
    /// that unjournaled stream failed the session.
    #[tokio::test]
    async fn sequential_open_forget_cycles_keep_the_open_journal_bounded() {
        let (mut actor, active_key, mut carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        let cycles = 4 * M2_OPEN_JOURNAL_MAX_ENTRIES as u64;
        let mut peak_entries = 0;
        for stream_id in 1..=cycles {
            let (responses, entries_while_live) = open_forget_cycle(
                &mut actor,
                &active_key,
                &mut carrier_receiver,
                &mut control_receiver,
                stream_id,
            )
            .await;
            assert!(
                responses.iter().all(|message| !matches!(
                    message,
                    ControlMessage::Rejected(rejected) if rejected.stream_id == stream_id
                )),
                "stream {stream_id} must be admitted, not refused"
            );
            peak_entries = peak_entries.max(entries_while_live);
            assert!(actor.streams.is_empty());
        }
        assert_eq!(
            peak_entries, 1,
            "a sequential session retains one entry at a time"
        );
        assert_eq!(actor.open_journal.entry_count(), 0);
        assert_eq!(actor.open_journal.used_bytes(), 0);
        assert_eq!(actor.retired_streams.retired_count(), cycles);
        assert_eq!(
            actor.retired_streams.len(),
            1,
            "contiguous reclamation coalesces into one retained range"
        );
        assert_eq!(actor.retired_streams.coalesced_gaps, 0);
    }

    /// The refusal path keeps its meaning for genuinely concurrent work, and
    /// the owner's later STREAM_FORGET for a stream refused before it could
    /// be journaled is benign rather than session-fatal.
    #[tokio::test]
    async fn concurrent_live_entries_still_exhaust_and_their_forget_is_benign() {
        let (mut actor, _active_key, _carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        for stream_id in 1..=(M2_OPEN_JOURNAL_MAX_ENTRIES as u64) {
            let open = test_open(stream_id);
            let canonical = encode_control(&ControlMessage::Open(open.clone()))
                .expect("test OPEN should encode");
            assert!(matches!(
                actor.open_journal.observe(
                    &open.message_id,
                    &canonical,
                    open.stream_id,
                    &open.operation_id,
                ),
                Ok(OpenJournalObservation::New)
            ));
        }
        let refused = test_open(M2_OPEN_JOURNAL_MAX_ENTRIES as u64 + 1);
        actor
            .handle_control(ControlMessage::Open(refused.clone()))
            .await
            .expect("real exhaustion is a typed refusal, not a session failure");
        assert!(matches!(
            drain_control_messages(&mut control_receiver).last(),
            Some(ControlMessage::Rejected(rejected))
                if rejected.code == "RESOURCE_EXHAUSTED"
                    && rejected.stream_id == refused.stream_id
        ));
        assert!(!actor.streams.contains_key(&refused.stream_id));

        actor
            .handle_stream_forget(tunnel_protocol::rotation_control::StreamForget {
                message_id: "forget-refused".to_owned(),
                reply_to: String::new(),
                session_id: "session".to_owned(),
                epoch: 1,
                stream_id: refused.stream_id,
                operation_id: refused.operation_id.clone(),
                direction: Direction::RelayToConnector,
                final_state: no_stream_forget_state(refused.stream_id),
            })
            .expect("forgetting a stream refused before journaling must be benign");
        assert!(actor.pending_forgets.is_empty());
    }

    #[test]
    fn retired_stream_ids_track_membership_exactly_and_stay_bounded() {
        let mut retired = RetiredStreamIds::default();
        let mut reference = BTreeSet::new();
        // Reclamation order follows completion, not allocation, so IDs arrive
        // out of order inside a bounded window of concurrently live streams.
        // Insert a deterministic permutation of each 64-ID window, repeating
        // some IDs, and check exact membership throughout.
        let mut state = 0x2545_F491_4F6C_DD1D_u64;
        let mut ids = Vec::new();
        for window in 0..64_u64 {
            let mut block = (1..=64_u64).map(|id| window * 64 + id).collect::<Vec<_>>();
            for index in (1..block.len()).rev() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                block.swap(index, (state % (index as u64 + 1)) as usize);
            }
            ids.extend(block.iter().copied());
            ids.extend(block.iter().take(3).copied());
        }
        for id in ids {
            retired.insert(id);
            reference.insert(id);
            assert!(retired.contains(id));
            assert!(retired.len() <= M2_RETIRED_STREAM_RANGES);
        }
        assert_eq!(retired.coalesced_gaps, 0);
        assert_eq!(retired.retired_count(), reference.len() as u64);
        for candidate in 1..9_000_u64 {
            assert_eq!(
                retired.contains(candidate),
                reference.contains(&candidate),
                "retired membership must be exact for {candidate}"
            );
        }
    }

    #[test]
    fn retired_stream_ids_coalesce_the_lowest_gap_instead_of_growing() {
        let mut retired = RetiredStreamIds::default();
        for index in 0..=(M2_RETIRED_STREAM_RANGES as u64) {
            // Every other ID, so each insert opens a fresh range.
            retired.insert(index * 2 + 1);
        }
        assert_eq!(retired.len(), M2_RETIRED_STREAM_RANGES);
        assert_eq!(retired.coalesced_gaps, 1);
        // Coalescing can only make the record more permissive about an ID it
        // never saw; it never admits one.
        assert!(retired.contains(2));
        assert!(retired.contains(1));
        assert!(retired.contains(3));
        assert!(!retired.contains(M2_RETIRED_STREAM_RANGES as u64 * 2 + 4));
    }

    #[tokio::test]
    async fn stream_forget_releases_open_journal_and_refuses_retries_past_the_horizon() {
        let (mut actor, active_key, mut carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        let open = test_open(1);
        actor
            .handle_control(ControlMessage::Open(open.clone()))
            .await
            .expect("initial OPEN should be admitted");
        let initial = drain_control_messages(&mut control_receiver);
        // Before the horizon a retry is still deduplicated: the retained
        // reply is replayed exactly and no second stream is admitted.
        actor
            .handle_control(ControlMessage::Open(open.clone()))
            .await
            .expect("a retry for a live entry should replay its retained reply");
        let replayed = drain_control_messages(&mut control_receiver);
        assert_eq!(replayed.len(), 1);
        assert!(matches!(
            (initial.first(), replayed.first()),
            (Some(ControlMessage::Opened(first)), Some(ControlMessage::Opened(replay)))
                if first == replay
        ));
        assert_eq!(actor.streams.len(), 1);
        let used_before_forget = actor.open_journal.used_bytes();
        let (sequence, final_state) = test_owner_forget_sequence(open.stream_id);
        {
            let stream = actor
                .streams
                .get_mut(&open.stream_id)
                .expect("admitted OPEN should have a stream");
            stream.sequence = sequence;
            stream.input_fin = true;
            stream.output_fin = true;
        }
        let forget = tunnel_protocol::rotation_control::StreamForget {
            message_id: "open-journal-forget".to_owned(),
            reply_to: String::new(),
            session_id: "session".to_owned(),
            epoch: 1,
            stream_id: open.stream_id,
            operation_id: open.operation_id.clone(),
            direction: Direction::RelayToConnector,
            final_state,
        };
        actor
            .handle_stream_forget(forget)
            .expect("authenticated FORGET should queue its carrier barrier");
        assert!(actor.streams.contains_key(&open.stream_id));
        assert!(matches!(
            carrier_receiver
                .try_recv()
                .expect("FORGET should queue a barrier"),
            CarrierCommand::Barrier
        ));
        actor
            .handle_barrier_complete(&active_key)
            .expect("carrier barrier should complete FORGET");
        assert!(!actor.streams.contains_key(&open.stream_id));
        // Past the OPEN retry horizon the whole entry is released, not just
        // its cached response, so a long-lived session's journal is bounded
        // by what it still holds.
        assert_eq!(actor.open_journal.used_bytes(), 0);
        assert!(used_before_forget > 0);
        assert_eq!(actor.open_journal.entry_count(), 0);
        assert!(actor.retired_streams.contains(open.stream_id));

        // The owner can never legitimately retry this message ID again. The
        // retired stream ID, not the released entry, refuses it, so the retry
        // is never dispatched a second time and no result is fabricated.
        actor
            .handle_control(ControlMessage::Open(open.clone()))
            .await
            .expect("a retry past the horizon should receive a typed refusal");
        let stale = drain_control_messages(&mut control_receiver);
        assert!(matches!(
            stale.last(),
            Some(ControlMessage::Rejected(rejected))
                if rejected.code == "STREAM_EXISTS"
                    && rejected.reply_to == open.message_id
        ));
        assert!(actor.streams.is_empty());
        // The refusal is not journaled.  Journaling it would retain a fresh
        // entry for a stream the owner has already forgotten and will never
        // forget again, so a rule-violating owner could leak one entry per
        // refusal until the session wedged at RESOURCE_EXHAUSTED.
        assert_eq!(actor.open_journal.entry_count(), 0);
        assert_eq!(actor.open_journal.used_bytes(), 0);

        // The connector can no longer tell that retry apart from a reused
        // message ID carrying different contents.  Both are refused before
        // admission rather than dispatched; the owner must not reuse a
        // message ID within a session.
        let mut changed = open.clone();
        changed.message_id = "open-journal-reused-id".to_owned();
        changed.operation_id = "open-journal-changed".to_owned();
        actor
            .handle_control(ControlMessage::Open(changed.clone()))
            .await
            .expect("a forgotten stream ID must be refused, never resurrected");
        let resurrected = drain_control_messages(&mut control_receiver);
        assert!(matches!(
            resurrected.last(),
            Some(ControlMessage::Rejected(rejected))
                if rejected.code == "STREAM_EXISTS"
                    && rejected.reply_to == changed.message_id
        ));
        assert!(actor.streams.is_empty());
        assert_eq!(actor.open_journal.entry_count(), 0);
        assert_eq!(actor.open_journal.used_bytes(), 0);
    }

    /// A refusal past the horizon must not be able to fill the journal, even
    /// from an owner that breaks the rule and retries forever.
    #[tokio::test]
    async fn repeated_post_horizon_retries_cannot_fill_the_open_journal() {
        let (mut actor, active_key, mut carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        let (_responses, _entries) = open_forget_cycle(
            &mut actor,
            &active_key,
            &mut carrier_receiver,
            &mut control_receiver,
            1,
        )
        .await;
        for index in 0..(4 * M2_OPEN_JOURNAL_MAX_ENTRIES) {
            let mut retry = test_open(1);
            retry.message_id = format!("post-horizon-{index}");
            actor
                .handle_control(ControlMessage::Open(retry.clone()))
                .await
                .expect("a post-horizon retry is refused, never a session failure");
            assert!(matches!(
                drain_control_messages(&mut control_receiver).last(),
                Some(ControlMessage::Rejected(rejected))
                    if rejected.code == "STREAM_EXISTS" && rejected.reply_to == retry.message_id
            ));
            assert_eq!(actor.open_journal.entry_count(), 0);
        }
        assert_eq!(actor.open_journal.used_bytes(), 0);
        // A fresh stream ID is still admitted afterwards.
        let (responses, _entries) = open_forget_cycle(
            &mut actor,
            &active_key,
            &mut carrier_receiver,
            &mut control_receiver,
            2,
        )
        .await;
        assert!(responses.iter().all(|message| !matches!(
            message,
            ControlMessage::Rejected(rejected) if rejected.stream_id == 2
        )));
    }

    #[test]
    fn stream_forget_for_a_retired_stream_still_authenticates_its_context() {
        let (mut actor, _key, mut carrier_receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        actor.forgotten_stream_through = 4;
        actor.retired_streams.insert(4);
        let benign = tunnel_protocol::rotation_control::StreamForget {
            message_id: "retired-forget".to_owned(),
            reply_to: String::new(),
            session_id: "session".to_owned(),
            epoch: 1,
            stream_id: 4,
            operation_id: "operation-4".to_owned(),
            direction: Direction::RelayToConnector,
            final_state: no_stream_forget_state(4),
        };
        actor
            .handle_stream_forget(benign.clone())
            .expect("a retired stream ID in this session is benign");
        // An ID the owner allocated but never named in an OPEN sits below the
        // watermark and is benign for the same reason.
        let mut never_seen = benign.clone();
        never_seen.stream_id = 3;
        never_seen.final_state = no_stream_forget_state(3);
        actor
            .handle_stream_forget(never_seen)
            .expect("an ID below the watermark was allocated by this owner");
        // Benignity is decided only after the message authenticates.
        let mut stale_epoch = benign.clone();
        stale_epoch.epoch = 2;
        assert!(matches!(
            actor
                .handle_stream_forget(stale_epoch)
                .expect_err("a stale epoch must not be accepted for a retired ID"),
            ClientError::Protocol(message) if message == "STREAM_FORGET context mismatch"
        ));
        let mut other_session = benign;
        other_session.session_id = "other-session".to_owned();
        assert!(matches!(
            actor
                .handle_stream_forget(other_session)
                .expect_err("another session's message must not be accepted"),
            ClientError::Protocol(message) if message == "STREAM_FORGET context mismatch"
        ));
        assert!(carrier_receiver.try_recv().is_err());
    }

    #[test]
    fn stream_forget_unknown_future_id_is_rejected_without_watermark_advance() {
        let (mut actor, _key, mut carrier_receiver, _control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        let error = actor
            .handle_stream_forget(tunnel_protocol::rotation_control::StreamForget {
                message_id: "unknown-future-forget".to_owned(),
                reply_to: String::new(),
                session_id: "session".to_owned(),
                epoch: 1,
                stream_id: 1,
                operation_id: "unknown-operation".to_owned(),
                direction: Direction::RelayToConnector,
                final_state: no_stream_forget_state(1),
            })
            .expect_err("unknown future stream IDs must not create tombstones");
        assert!(matches!(error, ClientError::Protocol(_)));
        assert!(actor.pending_forgets.is_empty());
        assert_eq!(actor.forgotten_stream_through, 0);
        assert!(carrier_receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn rejected_open_stream_forget_releases_journal_response_once() {
        let (mut actor, active_key, mut carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        let mut rejected_open = test_open(1);
        rejected_open.service_id = "not-exported".to_owned();
        actor
            .handle_control(ControlMessage::Open(rejected_open.clone()))
            .await
            .expect("a locally denied OPEN should emit a typed rejection");
        // Exercise the stale stream-ID fence as well: a retained REJECTED
        // entry still needs its authenticated FORGET to reach reclamation
        // even when the watermark and the retired-stream record would
        // otherwise make a message for this ID benign.
        actor.forgotten_stream_through = rejected_open.stream_id;
        actor.retired_streams.insert(rejected_open.stream_id);
        let rejection = drain_control_messages(&mut control_receiver);
        assert!(matches!(
            rejection.last(),
            Some(ControlMessage::Rejected(rejected))
                if rejected.code == "EXPORT_DENIED"
                    && rejected.stream_id == rejected_open.stream_id
                    && rejected.operation_id == rejected_open.operation_id
        ));
        assert!(actor.streams.is_empty());
        let used_before_forget = actor.open_journal.used_bytes();
        assert!(used_before_forget > 0);

        let forget = tunnel_protocol::rotation_control::StreamForget {
            message_id: "rejected-open-forget".to_owned(),
            reply_to: String::new(),
            session_id: "session".to_owned(),
            epoch: 1,
            stream_id: rejected_open.stream_id,
            operation_id: rejected_open.operation_id.clone(),
            direction: Direction::RelayToConnector,
            final_state: no_stream_forget_state(rejected_open.stream_id),
        };
        let mut wrong_forget = forget.clone();
        wrong_forget.operation_id = "wrong-rejected-operation".to_owned();
        let error = actor
            .handle_stream_forget(wrong_forget)
            .expect_err("wrong operation identity must not release a rejected OPEN");
        assert!(matches!(error, ClientError::Protocol(_)));
        assert!(carrier_receiver.try_recv().is_err());
        assert_eq!(actor.open_journal.used_bytes(), used_before_forget);

        actor
            .handle_stream_forget(forget.clone())
            .expect("STREAM_FORGET should authenticate the retained rejection");
        assert!(matches!(
            carrier_receiver
                .try_recv()
                .expect("forget barrier should be queued"),
            CarrierCommand::Barrier
        ));
        actor
            .handle_barrier_complete(&active_key)
            .expect("forget barrier should compact the rejected journal entry");
        assert!(actor.streams.is_empty());
        let used_after_forget = actor.open_journal.used_bytes();
        assert!(
            used_after_forget < used_before_forget,
            "STREAM_FORGET must release a rejected OPEN response even without an M2Stream"
        );

        actor
            .handle_stream_forget(forget)
            .expect("repeated STREAM_FORGET should be idempotent");
        assert_eq!(
            actor.open_journal.used_bytes(),
            used_after_forget,
            "repeated cleanup must not release the retained journal charge twice"
        );
    }

    #[tokio::test]
    async fn open_journal_response_capacity_is_terminal_not_pending() {
        let (mut actor, _active_key, _carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        let open = test_open(1);
        let canonical =
            encode_control(&ControlMessage::Open(open.clone())).expect("test OPEN should encode");
        let entry_bytes = M2_OPEN_JOURNAL_ENTRY_OVERHEAD
            + open.message_id.len()
            + canonical.len()
            + open.operation_id.len();
        // Let the request fingerprint fit, but leave less than one immutable
        // OPENED response. This must be a typed terminal retention result,
        // rather than an endlessly retried pending OPEN.
        actor.open_journal.max_bytes = entry_bytes + 1;
        let error = actor
            .handle_control(ControlMessage::Open(open))
            .await
            .expect_err("permanent OPEN retention exhaustion must fail closed");
        assert!(matches!(error, ClientError::OpenRetentionFull));
        assert!(actor.pending_open.is_none());
        assert!(actor.pending_open_queue.is_empty());
        assert!(actor.streams.is_empty());
        assert_eq!(actor.open_journal.active_entries, 0);
        assert_eq!(actor.open_journal.tombstones, 1);
        assert!(control_receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn full_open_tombstone_budget_rejects_new_ids_but_replays_known_open() {
        let (mut actor, _active_key, _carrier_receiver, mut control_receiver) =
            test_actor_with_control_capacity(M2_CARRIER_QUEUE_FRAMES, 16);
        let known = test_open(1);
        actor
            .handle_control(ControlMessage::Open(known.clone()))
            .await
            .expect("known OPEN should be admitted");
        let original = drain_control_messages(&mut control_receiver);
        assert_eq!(original.len(), 2);
        for index in 0..(M2_OPEN_JOURNAL_MAX_ENTRIES - 1) {
            let message_id = format!("open-tombstone-{index}");
            let canonical = format!("canonical-{index}");
            assert!(matches!(
                actor.open_journal.observe(
                    &message_id,
                    canonical.as_bytes(),
                    index as u64 + 1,
                    &format!("operation-old-{index}"),
                ),
                Ok(OpenJournalObservation::New)
            ));
            actor
                .open_journal
                .compact(&message_id)
                .expect("bounded tombstone slot should compact");
        }
        let mut unknown = test_open(2);
        unknown.message_id = "open-after-tombstone-cap".to_owned();
        actor
            .handle_control(ControlMessage::Open(unknown))
            .await
            .expect("new IDs should receive bounded RESOURCE_EXHAUSTED refusal");
        let refusal = drain_control_messages(&mut control_receiver);
        assert!(matches!(
            refusal.last(),
            Some(ControlMessage::Rejected(rejected))
                if rejected.code == "RESOURCE_EXHAUSTED"
                    && rejected.reason.contains("fresh session")
        ));

        actor
            .handle_control(ControlMessage::Open(known))
            .await
            .expect("known retry must remain available when new IDs are refused");
        let replay = drain_control_messages(&mut control_receiver);
        assert_eq!(
            replay,
            vec![original[0].clone()],
            "known OPEN must replay its immutable OPENED response without refreshing auth"
        );
        assert_eq!(actor.streams.len(), 1);
    }

    #[test]
    fn open_journal_reserves_slots_for_active_forget_tombstones() {
        let mut journal = OpenJournal::new(16, MAX_JOURNAL_BYTES);
        for index in 0..(M2_OPEN_JOURNAL_MAX_ENTRIES - 16) {
            let message_id = format!("open-old-tombstone-{index}");
            let canonical = format!("old-canonical-{index}");
            assert!(matches!(
                journal.observe(
                    &message_id,
                    canonical.as_bytes(),
                    index as u64 + 1,
                    &format!("operation-old-{index}"),
                ),
                Ok(OpenJournalObservation::New)
            ));
            journal
                .compact(&message_id)
                .expect("reserved tombstone slot should compact");
        }

        let response = ControlMessage::Ping(Ping::new("open-journal-response", "session", 1, 1));
        let response =
            M2Actor::encode_control_message(&response).expect("test response should encode");
        let response_bytes = crate::message_size(&response) + M2_OPEN_JOURNAL_RESPONSE_OVERHEAD;
        let mut active_ids = Vec::new();
        for index in 0..16 {
            let message_id = format!("open-active-{index}");
            let canonical = format!("active-canonical-{index}");
            assert!(matches!(
                journal.observe(
                    &message_id,
                    canonical.as_bytes(),
                    index as u64 + 1,
                    &format!("operation-active-{index}"),
                ),
                Ok(OpenJournalObservation::New)
            ));
            journal
                .complete(
                    &message_id,
                    vec![response.clone()],
                    vec![None],
                    response_bytes,
                )
                .expect("active response should fit its reserved slot");
            active_ids.push(message_id);
        }
        assert_eq!(journal.entries.len(), M2_OPEN_JOURNAL_MAX_ENTRIES);
        assert_eq!(journal.active_entries, 16);
        let before_forget = journal.used_bytes();
        for message_id in &active_ids {
            journal
                .compact(message_id)
                .expect("every active stream must retain a forget tombstone slot");
        }
        let after_forget = journal.used_bytes();
        assert!(after_forget < before_forget);
        assert_eq!(journal.active_entries, 0);
        assert_eq!(journal.tombstones, M2_OPEN_JOURNAL_MAX_ENTRIES);
        for message_id in &active_ids {
            journal
                .compact(message_id)
                .expect("duplicate cleanup must be idempotent");
        }
        assert_eq!(journal.used_bytes(), after_forget);
    }

    const TEST_SETUP_TIMEOUT: Duration = Duration::from_secs(2);
    const TEST_ASSERT_TIMEOUT: Duration = Duration::from_millis(750);
    const TEST_ACTOR_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

    async fn test_websocket_pair() -> Result<(ClientWebSocket, WebSocketStream<TcpStream>), String>
    {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|error| format!("test websocket listener should bind: {error}"))?;
        let address = listener
            .local_addr()
            .map_err(|error| format!("test websocket listener should have an address: {error}"))?;
        let result = timeout(TEST_SETUP_TIMEOUT, async {
            let client = async {
                connect_async(format!("ws://{address}"))
                    .await
                    .map_err(|error| format!("test websocket client handshake failed: {error}"))
            };
            let server = async {
                let (socket, _) = listener
                    .accept()
                    .await
                    .map_err(|error| format!("test websocket listener accept failed: {error}"))?;
                accept_async(socket)
                    .await
                    .map_err(|error| format!("test websocket server handshake failed: {error}"))
            };
            tokio::try_join!(client, server)
        })
        .await
        .map_err(|_| "test websocket setup exceeded its bounded deadline".to_owned())??;
        Ok((result.0.0, result.1))
    }

    fn runtime_welcome() -> tunnel_protocol::Welcome {
        let mut welcome = tunnel_protocol::Welcome::new(
            "welcome",
            "hello",
            "session",
            1,
            1,
            "connection",
            "ticket",
            "reconnect",
        );
        welcome.supported_features = vec![M2_FEATURE.to_owned()];
        welcome
    }

    fn websocket_control(message: &ControlMessage) -> Message {
        Message::Text(
            String::from_utf8(encode_control(message).expect("test control should encode"))
                .expect("test control should be UTF-8")
                .into(),
        )
    }

    struct ControlWriterGateGuard(Arc<test_hooks::ControlWriterGate>);

    impl Drop for ControlWriterGateGuard {
        fn drop(&mut self) {
            self.0.release.notify_waiters();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pending_open_does_not_starve_cancel_on_real_session_control_loop() -> Result<(), String>
    {
        let gate = Arc::new(test_hooks::ControlWriterGate {
            block_once: AtomicBool::new(true),
            entered: Notify::new(),
            release: Notify::new(),
        });
        let _gate_guard = ControlWriterGateGuard(gate.clone());

        let (control_client, mut control_peer) = test_websocket_pair().await?;
        let (data_client, mut data_peer) = test_websocket_pair().await?;
        let (control_sink, control_stream) = control_client.split();
        let (data_sink, data_stream) = data_client.split();
        let cancellation = CancellationToken::new();
        let (readiness, _readiness_receiver) = watch::channel(Readiness::Connecting);
        let (status, _status_receiver) = watch::channel(ConnectionStatus::default());
        let session = SessionInfo {
            session_id: "session".to_owned(),
            epoch: 1,
            generation: 1,
        };
        let mut actor = tokio::spawn(run_m2_session(
            RuntimeConfig::default(),
            session,
            runtime_welcome(),
            "owner".to_owned(),
            None,
            RotationConfig::default(),
            control_sink,
            control_stream,
            data_sink,
            data_stream,
            cancellation.clone(),
            readiness,
            status,
            None,
            None,
            Some(gate.clone()),
            HttpHandlers::default(),
        ));

        // The test-only writer gate holds the first control item after the
        // real writer receives it. The actor can therefore admit seven more
        // OPEN pairs, leaving one slot free, while the ninth pair requires
        // two permits and becomes the pending head; the tenth is queued in
        // the bounded OPEN FIFO.
        let proof = async {
            let entered = gate.entered.notified();
            control_peer
                .send(websocket_control(&ControlMessage::Open(test_open(1))))
                .await
                .map_err(|error| format!("first OPEN should reach the actor: {error}"))?;
            timeout(TEST_SETUP_TIMEOUT, entered)
                .await
                .map_err(|_| "control writer did not enter the deterministic hold".to_owned())?;
            for stream_id in 2..=10 {
                control_peer
                    .send(websocket_control(&ControlMessage::Open(test_open(
                        stream_id,
                    ))))
                    .await
                    .map_err(|error| format!("OPEN burst should reach the actor: {error}"))?;
            }

            // This CANCEL is ordered after the ninth and tenth OPENs on the
            // real control socket. The ninth pair is pending and the tenth
            // OPEN must enter the bounded FIFO rather than closing the
            // session. A responsive control path must still cancel stream 1
            // and emit its RESET on the independent data carrier without
            // waiting for the control writer to drain.
            control_peer
                .send(websocket_control(&ControlMessage::Cancel(Cancel::new(
                    "cancel-1",
                    "session",
                    1,
                    1,
                    "operation-1",
                ))))
                .await
                .map_err(|error| format!("CANCEL should reach the actor: {error}"))?;

            let reset_seen = timeout(TEST_ASSERT_TIMEOUT, async {
                while let Some(message) = data_peer.next().await {
                    let Ok(Message::Binary(bytes)) = message else {
                        continue;
                    };
                    let Ok(frame) = Frame::decode(bytes.as_ref()) else {
                        continue;
                    };
                    if frame.kind == FrameKind::Reset && frame.stream_id == 1 {
                        return true;
                    }
                }
                false
            })
            .await
            .map_err(|_| "CANCEL did not produce RESET before the bounded deadline".to_owned())?;
            Ok::<bool, String>(reset_seen)
        }
        .await;

        // Always release the injected hold before joining the actor, including
        // on the current red implementation where the proof above fails.
        gate.release.notify_waiters();
        cancellation.cancel();
        let actor_result = match timeout(TEST_ACTOR_CLEANUP_TIMEOUT, &mut actor).await {
            Ok(joined) => joined,
            Err(_) => {
                actor.abort();
                (&mut actor).await
            }
        };
        assert!(
            matches!(&actor_result, Ok(Ok(()))),
            "session actor must be joined cleanly after cancellation: {actor_result:?}"
        );
        assert!(
            matches!(&proof, Ok(true)),
            "CANCEL must be handled while one OPEN waits for a bounded control pair; result={proof:?}"
        );
        Ok(())
    }

    /// Drive one connector actor to `Retiring` with its old carrier still
    /// owned, exactly as `ROTATE_COMMIT` leaves it.  The returned flag is set
    /// by the old carrier's own task when it observes the close command, so a
    /// forced closure is proven on the carrier channel rather than inferred.
    async fn retiring_connector_actor() -> (
        M2Actor,
        RotationAttemptIdentity,
        CarrierKey,
        Arc<AtomicBool>,
        tokio::task::JoinHandle<()>,
        mpsc::Receiver<CarrierCommand>,
        mpsc::Receiver<crate::QueuedMessage>,
    ) {
        let (mut actor, old_key, old_receiver, control_receiver) =
            test_actor_with_carrier(M2_CARRIER_QUEUE_FRAMES);
        actor.streams.insert(1, test_stream());

        let old_closed = Arc::new(AtomicBool::new(false));
        let observer = old_closed.clone();
        let old_carrier_task = tokio::spawn(async move {
            let mut receiver = old_receiver;
            while let Some(command) = receiver.recv().await {
                if let CarrierCommand::Close(reply) = command {
                    observer.store(true, Ordering::SeqCst);
                    let _ = reply.send(());
                    break;
                }
            }
        });

        let candidate_key = CarrierKey::new(2, "candidate");
        let (candidate_tx, candidate_receiver) = mpsc::channel(M2_CARRIER_QUEUE_FRAMES);
        actor.candidate = Some(Carrier {
            key: candidate_key.clone(),
            local_addr: None,
            tx: candidate_tx,
            pending_controls: BTreeMap::new(),
            reader_cancel: CancellationToken::new(),
            reader: None,
            writer: None,
        });

        let attempt = RotationAttemptIdentity::new(
            "session",
            1,
            "owner",
            "rotation",
            old_key.generation,
            candidate_key.generation,
            old_key.connection_id.clone(),
            candidate_key.connection_id.clone(),
        );
        let now = actor.now_ms();
        actor
            .rotation
            .prepare(attempt.clone(), now)
            .expect("rotation prepares");
        actor
            .rotation
            .candidate_ready(&attempt, now)
            .expect("candidate is ready");
        actor
            .rotation
            .quiesce(
                &attempt,
                tunnel_protocol::rotation_control::StreamRoster::new("snapshot", vec![1]),
                now,
            )
            .expect("rotation quiesces");
        let local_fence = FenceSnapshot::new(
            "snapshot",
            vec![tunnel_protocol::rotation_control::StreamFence::new(
                1,
                Direction::ConnectorToRelay,
                0,
            )],
        );
        let peer_fence = FenceSnapshot::new(
            "snapshot",
            vec![tunnel_protocol::rotation_control::StreamFence::new(
                1,
                Direction::RelayToConnector,
                0,
            )],
        );
        actor
            .rotation
            .frozen(
                &attempt,
                local_fence.clone(),
                Direction::ConnectorToRelay,
                now,
            )
            .expect("local fence is accepted");
        actor
            .rotation
            .frozen(
                &attempt,
                peer_fence.clone(),
                Direction::RelayToConnector,
                now,
            )
            .expect("peer fence is accepted");
        actor
            .rotation
            .drained(
                &attempt,
                tunnel_protocol::rotation_control::DrainProof::new(
                    "snapshot",
                    peer_fence.digest().expect("peer fence digest"),
                    Direction::RelayToConnector,
                    vec![tunnel_protocol::rotation_control::StreamAck::new(1, 0)],
                ),
                now,
            )
            .expect("peer drain proof is accepted");
        actor
            .rotation
            .drained(
                &attempt,
                tunnel_protocol::rotation_control::DrainProof::new(
                    "snapshot",
                    local_fence.digest().expect("local fence digest"),
                    Direction::ConnectorToRelay,
                    vec![tunnel_protocol::rotation_control::StreamAck::new(1, 0)],
                ),
                now,
            )
            .expect("local drain proof is accepted");
        actor.local_fence = Some(local_fence.clone());
        actor.local_drained_message_id = Some("drained".to_owned());

        let commit = RotateCommit {
            message_id: "commit".to_owned(),
            reply_to: "drained".to_owned(),
            attempt: attempt.clone(),
            snapshot_id: "snapshot".to_owned(),
            drain_proofs: vec![
                tunnel_protocol::rotation_control::DrainProofRef {
                    snapshot_id: "snapshot".to_owned(),
                    fence_digest: local_fence.digest().expect("local fence digest"),
                    direction: Direction::ConnectorToRelay,
                },
                tunnel_protocol::rotation_control::DrainProofRef {
                    snapshot_id: "snapshot".to_owned(),
                    fence_digest: peer_fence.digest().expect("peer fence digest"),
                    direction: Direction::RelayToConnector,
                },
            ],
        };
        let scope = actor
            .rotation_journal_scope(&ControlMessage::RotateCommit(commit.clone()))
            .expect("commit belongs to the active rotation");
        actor
            .observe_rotation_message(&ControlMessage::RotateCommit(commit.clone()), scope)
            .expect("commit is journaled");
        actor
            .handle_rotate_commit(commit)
            .await
            .expect("candidate is committed");
        assert_eq!(actor.rotation.phase(), RotationPhase::Retiring);
        assert_eq!(actor.active.key, candidate_key);
        assert_eq!(
            actor
                .retiring
                .as_ref()
                .expect("old carrier is still owned after commit")
                .key,
            old_key
        );
        // The stall this row is about: the connector never answered
        // `ROTATE_RETIRE`, so it holds no local retired message identifier to
        // correlate a completion against.
        assert!(actor.local_retired_message_id.is_none());
        (
            actor,
            attempt,
            candidate_key,
            old_closed,
            old_carrier_task,
            candidate_receiver,
            control_receiver,
        )
    }

    /// Move the actor clock past the absolute overlap deadline and the owner's
    /// one bounded post-deadline grace without sleeping.  `now_ms` is measured
    /// from `rotation_started`, so moving that start into the past advances the
    /// clock monotonically.
    fn cross_overlap_deadline_and_grace(actor: &mut M2Actor) {
        let elapsed = tunnel_protocol::rotation::DEFAULT_OVERLAP_TIMEOUT_MS
            + tunnel_protocol::rotation::DEFAULT_HANDSHAKE_TIMEOUT_MS
            + 1_000;
        actor.rotation_started = Instant::now() - Duration::from_millis(elapsed);
    }

    /// Task row M7-C97: an OPEN the owner admits after ROTATE_COMMITTED and
    /// before ROTATE_COMPLETE is admitted, not refused `GOAWAY` "connector is
    /// draining".  The owner resumes admission at COMMITTED; before M7-C97
    /// the connector resumed it only at COMPLETE, and the shipped-binary echo
    /// gate failed about one run in seven with `503 DEVICE_REJECTED` when a
    /// request landed in that window.
    #[tokio::test]
    async fn an_open_admitted_by_the_owner_while_retiring_is_not_refused_as_draining() {
        let (
            mut actor,
            _attempt,
            _candidate_key,
            _old_closed,
            _old_carrier_task,
            _candidate_receiver,
            mut control_receiver,
        ) = retiring_connector_actor().await;
        assert_eq!(actor.rotation.phase(), RotationPhase::Retiring);
        drain_control_messages(&mut control_receiver);
        let open = test_open(2);
        actor
            .handle_control(ControlMessage::Open(open.clone()))
            .await
            .expect("an OPEN while retiring is handled");
        let responses = drain_control_messages(&mut control_receiver);
        assert!(
            responses.iter().all(|message| !matches!(
                message,
                ControlMessage::Rejected(rejected) if rejected.reply_to == open.message_id
            )),
            "an OPEN the owner admitted after COMMITTED must not be refused: {responses:?}"
        );
        assert!(
            responses.iter().any(|message| matches!(
                message,
                ControlMessage::Opened(opened) if opened.reply_to == open.message_id
            )),
            "the OPEN is admitted on the activated carrier: {responses:?}"
        );
        assert!(actor.streams.contains_key(&open.stream_id));
        // Admission resumed; the writer did not (M7-C98): the old carrier
        // receives nothing sequenced, and output stays held while frozen.
        assert!(actor.writes_frozen);
        let old_frames = actor
            .retiring
            .as_ref()
            .map(|carrier| carrier.tx.max_capacity() - carrier.tx.capacity())
            .unwrap_or(0);
        assert_eq!(old_frames, 0, "nothing is queued on the retiring carrier");
    }

    /// Review S2 of M7-C97: once the active (new) carrier is lost while
    /// `Retiring`, it is replaced by a placeholder, so an OPEN must be refused
    /// as draining rather than admitted onto a carrier that cannot serve it.
    #[tokio::test]
    async fn an_open_after_the_active_carrier_dies_while_retiring_is_refused_as_draining() {
        let (
            mut actor,
            _attempt,
            candidate_key,
            _old_closed,
            _old_carrier_task,
            _candidate_receiver,
            mut control_receiver,
        ) = retiring_connector_actor().await;
        assert!(actor.accepting);
        actor
            .mark_carrier_closed(&candidate_key, true, true)
            .await
            .expect("the active carrier's loss is recorded");
        drain_control_messages(&mut control_receiver);
        let open = test_open(2);
        actor
            .handle_control(ControlMessage::Open(open.clone()))
            .await
            .expect("an OPEN after carrier loss is handled");
        let responses = drain_control_messages(&mut control_receiver);
        assert!(
            responses.iter().any(|message| matches!(
                message,
                ControlMessage::Rejected(rejected)
                    if rejected.reply_to == open.message_id && rejected.code == "GOAWAY"
            )),
            "an OPEN after the active carrier died must be refused: {responses:?}"
        );
        assert!(!actor.streams.contains_key(&open.stream_id));
    }

    /// protocol.md, reply-target table: "Owner COMPLETE | Connector RETIRED;
    /// empty only for a forced completion whose connector RETIRED never
    /// arrived".  A connector that stalled through the overlap deadline must
    /// absorb that completion and release its own half of the old transport
    /// instead of failing the session on reply correlation.
    #[tokio::test]
    async fn forced_complete_with_no_reply_target_is_absorbed_and_force_closes_the_old_carrier() {
        let (
            mut actor,
            attempt,
            candidate_key,
            old_closed,
            old_carrier_task,
            _candidate_receiver,
            _control_receiver,
        ) = retiring_connector_actor().await;
        cross_overlap_deadline_and_grace(&mut actor);

        let complete = RotateComplete {
            message_id: "complete".to_owned(),
            reply_to: String::new(),
            attempt: attempt.clone(),
            snapshot_id: "snapshot".to_owned(),
            forced: true,
            reason: Some("connector_retirement_missing".to_owned()),
        };
        actor
            .handle_rotate_complete(complete)
            .await
            .expect("a forced ROTATE_COMPLETE with an empty reply target is absorbed");

        assert!(
            old_closed.load(Ordering::SeqCst),
            "the connector must force-close its own half of the old transport"
        );
        assert!(actor.retiring.is_none());
        assert_eq!(actor.rotation.phase(), RotationPhase::Active);
        assert_eq!(actor.active.key, candidate_key);
        assert_eq!(actor.rotations_completed, 1);
        assert!(
            actor.rotation.status().deadline_forced_retirement,
            "the forced retirement stays visible in diagnostics"
        );
        assert!(actor.accepting);
        assert!(!actor.writes_frozen);
        old_carrier_task
            .await
            .expect("old carrier task joins after the forced closure");
    }

    /// The same wire message with a reply target that is neither empty nor this
    /// connector's own `ROTATE_RETIRED` is still refused: relaxing correlation
    /// for the forced shape must not become a way to address one connector's
    /// attempt with another's reply header.
    #[tokio::test]
    async fn forced_complete_with_a_foreign_reply_target_is_refused() {
        let (
            mut actor,
            attempt,
            _candidate_key,
            old_closed,
            old_carrier_task,
            _candidate_receiver,
            _control_receiver,
        ) = retiring_connector_actor().await;
        cross_overlap_deadline_and_grace(&mut actor);

        let complete = RotateComplete {
            message_id: "complete".to_owned(),
            reply_to: "someone-elses-retired".to_owned(),
            attempt,
            snapshot_id: "snapshot".to_owned(),
            forced: true,
            reason: Some("connector_retirement_missing".to_owned()),
        };
        let error = actor
            .handle_rotate_complete(complete)
            .await
            .expect_err("a forced COMPLETE naming a foreign reply target is refused");
        assert!(
            matches!(&error, ClientError::Protocol(detail)
                if detail == "ROTATE_COMPLETE forced reply correlation mismatch"),
            "unexpected error: {error:?}"
        );
        assert!(
            !old_closed.load(Ordering::SeqCst),
            "a refused completion must not release the old transport"
        );
        assert!(actor.retiring.is_some());
        assert_eq!(actor.rotation.phase(), RotationPhase::Retiring);
        drop(actor);
        old_carrier_task
            .await
            .expect("old carrier task joins after the actor is dropped");
    }

    /// protocol.md, absolute overlap deadline: "after commit, forcibly close
    /// any old transport still lingering", and Retire: "a connector that still
    /// holds its half is required by its own deadline to force-close it before
    /// the next attempt".  The deadline alone must do this, with no
    /// `ROTATE_COMPLETE` from the owner at all.
    #[tokio::test]
    async fn overlap_deadline_alone_force_closes_the_connector_old_carrier() {
        let (
            mut actor,
            _attempt,
            candidate_key,
            old_closed,
            old_carrier_task,
            _candidate_receiver,
            _control_receiver,
        ) = retiring_connector_actor().await;
        cross_overlap_deadline_and_grace(&mut actor);

        actor
            .handle_rotation_deadline()
            .await
            .expect("the overlap deadline retires the old carrier in place");

        assert!(
            old_closed.load(Ordering::SeqCst),
            "the connector must force-close its own old carrier at its own deadline"
        );
        assert!(actor.retiring.is_none());
        assert!(
            actor.rotation.status().deadline_forced_retirement,
            "the machine latches the forced retirement at the deadline"
        );
        // The connector's own closure is only one side's evidence: the attempt
        // still waits for the owner's completion, and the candidate is already
        // the active carrier.
        assert_eq!(actor.rotation.phase(), RotationPhase::Retiring);
        assert_eq!(actor.active.key, candidate_key);
        // The arm is idempotent: a second deadline tick releases nothing more.
        actor
            .handle_rotation_deadline()
            .await
            .expect("a repeated deadline tick is a no-op");
        assert!(actor.retiring.is_none());
        old_carrier_task
            .await
            .expect("old carrier task joins after the forced closure");
    }
}
