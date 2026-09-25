//! Connector library with explicit M1 and M2 transport profiles.
//!
//! Both profiles establish one mutually authenticated control WSS and one
//! mutually authenticated data WSS for a session. M1 is the baseline profile:
//! transport loss closes the pair and requires a fresh session. M2 adds
//! ordered data-carrier rotation and bounded retained replay, while preserving
//! logical stream identity across physical connections. Neither profile
//! resubmits application operations after an ambiguous transport outcome.

#![forbid(unsafe_code)]

mod config;
pub mod credentials;
/// The device half of the filesystem endpoint (M4 gate 4).
pub mod fs_export;
pub mod http_forward;
mod m2_runtime;
/// Local, read-only supervisor status IPC (M6-06).
pub mod supervisor_ipc;

pub use config::FsExportSettings;
use config::{ExportConfig, ExportKind, RuntimeConfig};
use credentials::{CredentialError, load_client_config};
use futures_util::{SinkExt, StreamExt};
use std::{
    collections::{BTreeMap, VecDeque},
    error::Error,
    fmt,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    sync::{Mutex, mpsc, watch},
    task::JoinHandle,
};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
    tungstenite::{
        Message,
        client::IntoClientRequest,
        http::HeaderValue,
        protocol::frame::{CloseFrame, coding::CloseCode},
    },
};
use tokio_util::sync::CancellationToken;
use tunnel_protocol::{
    AuthorizationChallenge, AuthorizationConfirmed, AuthorizationInvalidated,
    CONTROL_IDENTITY_REJECTED_CLOSE_CODE, CONTROL_IDENTITY_REJECTED_CLOSE_REASON,
    CONTROL_OWNER_BUSY_CLOSE_CODE, CONTROL_OWNER_BUSY_CLOSE_REASON,
    CONTROL_PROTOCOL_UNSUPPORTED_CLOSE_CODE, CONTROL_PROTOCOL_UNSUPPORTED_CLOSE_REASON, Cancel,
    ControlMessage, DataReady, Frame, FrameKind, Hello, MAX_CONTROL_MESSAGE_BYTES, MAX_FRAME_LEN,
    MAX_PAYLOAD_LEN, Open, Opened, Ping, Pong, Rejected, ServiceAdvertisement, Welcome,
    decode_control, encode_control,
};
use url::Url;
use uuid::Uuid;

pub use config::{
    CredentialConfig, DEFAULT_SUPERVISOR_SOCKET_NAME, ExportConfig as LocalExport,
    ExportKind as LocalExportKind, LimitsConfig, ReconnectConfig, RuntimeConfig as ConnectConfig,
    RuntimeConfigError, SupervisorConfig,
};
pub use credentials::{CsrOutput, ImportedCredential};
pub use tokio_util::sync::CancellationToken as ConnectCancellation;

/// Every process exit status `tunnel-client` can produce to report a
/// failure, as a closed set. Success (`0`) is deliberately absent: it is not
/// a diagnostic, and a caller that treats it as one cannot tell a completed
/// run from one that never started.
///
/// **This lives here, in the library, because it had been copied.** The
/// production-cluster chaos gate classifies a connector's pre-readiness exit
/// against this vocabulary, and it held its own `[1, 2, 3, 4, 5, 6]` literal
/// with a comment pointing at `CliError::exit_code` — a cross-crate
/// invariant that nothing checked. When task row M0-03 gave `OWNER_BUSY` and
/// `RESOURCE_EXHAUSTED` exit `7` and `CANCELLED` exit `130`, that literal
/// silently began classifying two real interruptions as `Unclassified`,
/// which blocks release. One copy, imported by both, is what stops the next
/// one.
///
/// `6` is listed and is not currently reachable; see the exit-code table in
/// `docs/runtime.md`. Listing it is safe in the direction that matters: this
/// is the set a classifier may *accept*, so an unreachable member costs
/// nothing, while a missing member misclassifies a real exit.
///
/// `8` is `status` finding no supervisor for the profile (`SUPERVISOR_ABSENT`,
/// M6-06); `connect` never produces it.
pub const CLI_DIAGNOSTIC_EXIT_CODES: [u8; 9] = [1, 2, 3, 4, 5, 6, 7, 8, 130];

/// The M1 failure policy. A later caller can explicitly create a fresh
/// session; the library never reconnects or replays an operation itself.
pub const M1_TRANSPORT_FAILURE_POLICY: &str =
    "close control and data and require a fresh session; no retained replay or automatic reconnect";

/// The connector transport profile.  M1 is retained for the deterministic
/// baseline harness; the foreground CLI and library constructor default to
/// M2 so new sessions negotiate ordered rotation when the relay supports it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TransportProfile {
    /// One control and one data socket; any transport failure ends the epoch.
    M1,
    /// Ordered stream state with scheduled data-carrier rotation and bounded
    /// retained recovery.
    #[default]
    M2,
}

const PROTOCOL_MAJOR: u16 = 1;
const PROTOCOL_MINOR: u16 = 0;
const DATA_CLOSE_AUTH_EXPIRED: u16 = 4_001;
const DATA_CLOSE_PROTOCOL: u16 = 4_002;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const WRITER_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const WRITER_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
const CONTROL_QUEUE_BYTES: usize = 64 * 1024;
const DATA_QUEUE_BYTES: usize = 8 * 1024 * 1024;
const CONTROL_SUBPROTOCOL: &str = "agent-tunnel.control.v1";
const DATA_SUBPROTOCOL: &str = "agent-tunnel.data.v1";

#[cfg(test)]
pub(crate) mod test_hooks {
    use std::sync::atomic::AtomicBool;
    use tokio::sync::Notify;

    pub(crate) struct ControlWriterGate {
        pub(crate) block_once: AtomicBool,
        pub(crate) entered: Notify,
        pub(crate) release: Notify,
    }
}

#[cfg(test)]
pub(crate) type WriterTestGate = std::sync::Arc<test_hooks::ControlWriterGate>;
#[cfg(not(test))]
pub(crate) type WriterTestGate = ();

type ClientWebSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
type ClientStream = futures_util::stream::SplitStream<ClientWebSocket>;
type ClientSink = futures_util::stream::SplitSink<ClientWebSocket, Message>;
type SupervisorJoin = JoinHandle<Result<(), ClientError>>;

fn socket_local_addr(socket: &ClientWebSocket) -> Option<SocketAddr> {
    socket.get_ref().get_ref().local_addr().ok()
}

struct ConnectionLifecycle {
    cancellation: CancellationToken,
    join: Mutex<Option<SupervisorJoin>>,
}

/// Options for establishing one M1 connector session.
#[derive(Clone, Debug)]
pub struct ConnectOptions {
    /// Validated runtime configuration.
    pub config: RuntimeConfig,
    /// Cancellation owned by the caller. Cancelling before or during
    /// admission closes both sockets and joins all connector tasks.
    pub cancellation: CancellationToken,
    /// Explicit transport profile.  `M2` is the default for callers using
    /// [`ConnectOptions::new`]; M1 callers must opt into the baseline policy.
    pub profile: TransportProfile,
}

impl ConnectOptions {
    #[must_use]
    pub fn new(config: RuntimeConfig) -> Self {
        Self {
            config,
            cancellation: CancellationToken::new(),
            profile: TransportProfile::M2,
        }
    }
}

/// How many retained OPEN journal stream IDs a status snapshot reports.
pub const OPEN_JOURNAL_STREAM_IDS_REPORTED: usize = 8;

/// A bounded, payload-free status snapshot owned by the connector actor.
/// Identifiers are useful for diagnosing a handover; credentials and frame
/// bodies are deliberately absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionStatus {
    pub phase: String,
    pub session_id: Option<String>,
    pub epoch: Option<u64>,
    pub active_generation: Option<u64>,
    pub active_connection_id: Option<String>,
    pub candidate_generation: Option<u64>,
    pub candidate_connection_id: Option<String>,
    pub rotation_id: Option<String>,
    pub streams: usize,
    /// Retained OPEN journal entries: pending, completed and tombstoned
    /// requests the session has not yet reclaimed.  It is bounded by the
    /// tracked-entry cap and does not grow with the number of streams the
    /// session has served, because an entry is released at the OPEN retry
    /// horizon in docs/protocol.md.
    pub open_journal_entries: usize,
    /// The stream IDs of those entries, lowest first, at most
    /// [`OPEN_JOURNAL_STREAM_IDS_REPORTED`] of them.  Identifiers only: which
    /// streams a session still retains is what separates a slow reclamation
    /// from a leak (M3-31).
    pub open_journal_stream_ids: Vec<u64>,
    /// Stream IDs whose OPEN state has been reclaimed at that horizon, or
    /// refused before it could be journaled.  Monotonic for the session.
    pub open_streams_retired: u64,
    /// How often the bounded retired-stream record coalesced its lowest gap
    /// to stay within its range limit.  A gap can be a stream ID the owner
    /// allocated and never named in an OPEN or a STREAM_FORGET, so this can
    /// increment legitimately under sustained control-queue pressure; it is
    /// an observability signal about that pressure, not a safety condition.
    /// Every absorbed ID lies below the reclamation watermark and is already
    /// benign, and coalescing never makes an ID admissible.
    pub open_retired_ranges_coalesced: u64,
    pub emitted_sequences: u64,
    pub received_sequences: u64,
    pub drain_fences: usize,
    pub drain_acks: usize,
    pub replay_frames: usize,
    pub replay_bytes: usize,
    pub queue_frames: usize,
    pub queue_bytes: usize,
    pub rotations_completed: u64,
    /// Current retained-recovery attempt number, or the last completed
    /// attempt carried with a verified successor reset.  This is bounded by
    /// the protocol's maximum recovery attempts and never contains payloads.
    pub recovery_attempt: Option<u64>,
    /// Monotonic actor-clock start of the current or most recently completed
    /// retained-recovery attempt, copied from the rotation state machine's
    /// authenticated attempt.
    pub recovery_attempt_started_at_ms: Option<u64>,
    /// Monotonic actor-clock deadline of the current or most recently
    /// completed retained-recovery attempt. It is the current attempt's
    /// overlap deadline and is never later than the immutable episode cap.
    pub recovery_attempt_deadline_ms: Option<u64>,
    /// Immutable actor-clock deadline shared by every attempt in the current
    /// or most recently completed recovery episode. This is distinct from
    /// the per-attempt overlap deadline above.
    pub recovery_episode_deadline_ms: Option<u64>,
    /// The sorted physical carrier IDs released by the current recovery
    /// attempt. The list is bounded by the protocol closure-record limit and
    /// contains identity metadata only; prior authenticated IDs remain local
    /// fences rather than being repeated on later retry records.
    pub recovery_closed_connection_ids: Vec<String>,
    /// Closed reason for the last successful retained-recovery reset.
    pub recovery_reset_reason: Option<&'static str>,
    /// Exact old/new carrier identities for the active recovery attempt or
    /// the last verified fenced successor.
    pub recovery_old_generation: Option<u64>,
    pub recovery_old_connection_id: Option<String>,
    pub recovery_successor_generation: Option<u64>,
    pub recovery_successor_connection_id: Option<String>,
    pub control_local_addr: Option<SocketAddr>,
    pub active_local_addr: Option<SocketAddr>,
    pub candidate_local_addr: Option<SocketAddr>,
    /// The filesystem mutation ledger, summed over every filesystem exchange
    /// this session has completed.
    ///
    /// **Counters, and counters only.** Every field is an event count, so no
    /// path, name, byte of content or credential is representable here — the
    /// same construction rule `tunnel_fs_provider::ProviderStats` is built to,
    /// and the reason it can be republished unfiltered.
    ///
    /// It is here because a ledger nothing exposes is a ledger no operator can
    /// read: `AGENTS.md` requires diagnostics to expose counters, and how far a
    /// mutation got — dispatched, applied, `failed`, `partial` or `unknown` —
    /// is the counter a filesystem export has that nothing else does. Zero for
    /// a session that served no filesystem stream.
    pub fs: FsCounters,
    /// Per-stream operation authorization, summed over live streams.
    /// Counters only, like `fs`.
    pub stream_auth: StreamAuthCounters,
}

/// The connector's view of stream operation authorization.
///
/// A stream's input is buffered, not dispatched, while its authorization is
/// unconfirmed, and an authorization that lapses ends the stream with a RESET
/// and discards what was buffered. These are the counters that tell those
/// states apart when a request is lost (task row M6-C84).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StreamAuthCounters {
    /// Live streams whose authorization is not currently confirmed.
    pub unconfirmed_streams: usize,
    /// Live streams with an authorization refresh challenge in flight.
    pub refreshes_in_flight: usize,
    /// Inbound records buffered across live streams, awaiting authorization.
    pub buffered_inputs: usize,
    /// Streams this session ended because their authorization lapsed.
    pub expired_streams: u64,
}

/// The filesystem mutation ledger as a session total.
///
/// A distinct type rather than `ProviderStats` itself, because this is a **sum
/// over exchanges** where the provider's own counters are per session;
/// republishing that type directly would let a reader take `mutations_applied`
/// here for the number one 9P session applied.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FsCounters {
    /// Filesystem exchanges that ran to completion on this device session.
    pub exchanges: u64,
    /// Mutating requests refused before the host was touched. `not_started`.
    pub mutations_refused: u64,
    /// Mutating requests handed to the host.
    pub mutations_dispatched: u64,
    /// Dispatched mutations the host applied, whole or in part.
    pub mutations_applied: u64,
    /// Applied mutations whose reply reached the carrier.
    pub mutations_acknowledged: u64,
    /// Dispatched mutations the host reported changed nothing. `failed`.
    pub mutation_failed: u64,
    /// Mutations that applied part of what they were asked for. `partial`.
    pub mutation_partial: u64,
    /// Applied mutations whose outcome the consumer cannot learn. `unknown`.
    pub mutation_unknown: u64,
    /// Bytes the host acknowledged writing.
    pub bytes_written: u64,
}

impl FsCounters {
    /// Fold one completed exchange's provider counters into this total.
    pub fn absorb(&mut self, stats: &tunnel_fs_provider::ProviderStats) {
        self.exchanges += 1;
        self.mutations_refused += stats.mutations_refused;
        self.mutations_dispatched += stats.mutations_dispatched;
        self.mutations_applied += stats.mutations_applied;
        self.mutations_acknowledged += stats.mutations_acknowledged;
        self.mutation_failed += stats.mutation_failed;
        self.mutation_partial += stats.mutation_partial;
        self.mutation_unknown += stats.mutation_unknown;
        self.bytes_written += stats.bytes_written;
    }
}

impl Default for ConnectionStatus {
    fn default() -> Self {
        Self {
            phase: "connecting".to_owned(),
            session_id: None,
            epoch: None,
            active_generation: None,
            active_connection_id: None,
            candidate_generation: None,
            candidate_connection_id: None,
            rotation_id: None,
            streams: 0,
            open_journal_entries: 0,
            open_journal_stream_ids: Vec::new(),
            open_streams_retired: 0,
            open_retired_ranges_coalesced: 0,
            emitted_sequences: 0,
            received_sequences: 0,
            drain_fences: 0,
            drain_acks: 0,
            replay_frames: 0,
            replay_bytes: 0,
            queue_frames: 0,
            queue_bytes: 0,
            rotations_completed: 0,
            recovery_attempt: None,
            recovery_attempt_started_at_ms: None,
            recovery_attempt_deadline_ms: None,
            recovery_episode_deadline_ms: None,
            recovery_closed_connection_ids: Vec::new(),
            recovery_reset_reason: None,
            recovery_old_generation: None,
            recovery_old_connection_id: None,
            recovery_successor_generation: None,
            recovery_successor_connection_id: None,
            control_local_addr: None,
            active_local_addr: None,
            candidate_local_addr: None,
            fs: FsCounters::default(),
            stream_auth: StreamAuthCounters::default(),
        }
    }
}

/// Stable identifiers and negotiated values visible after DataReady.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionInfo {
    pub session_id: String,
    pub epoch: u64,
    pub generation: u64,
}

/// Observable connector lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Readiness {
    Connecting,
    ControlOpen,
    DataOpening,
    Ready(SessionInfo),
    Stopping,
    Closed { reason: String },
}

impl Readiness {
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }
}

/// Handle for observing and stopping the foreground connector supervisor.
#[derive(Clone)]
pub struct ConnectionHandle {
    readiness: watch::Receiver<Readiness>,
    status: watch::Receiver<ConnectionStatus>,
    lifecycle: Arc<ConnectionLifecycle>,
}

impl fmt::Debug for ConnectionHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionHandle")
            .field("readiness", &*self.readiness.borrow())
            .field("status", &*self.status.borrow())
            .finish_non_exhaustive()
    }
}

impl ConnectionHandle {
    /// Subscribe to lifecycle changes without exposing payloads or secrets.
    #[must_use]
    pub fn readiness(&self) -> watch::Receiver<Readiness> {
        self.readiness.clone()
    }

    /// Subscribe to the actor-owned bounded status snapshot.
    #[must_use]
    pub fn status(&self) -> watch::Receiver<ConnectionStatus> {
        self.status.clone()
    }

    /// Return the most recent redacted status snapshot.
    #[must_use]
    pub fn status_snapshot(&self) -> ConnectionStatus {
        self.status.borrow().clone()
    }

    /// Wait for Ready or a terminal closed state.
    pub async fn wait_ready(&mut self) -> Result<SessionInfo, ClientError> {
        loop {
            let state = self.readiness.borrow().clone();
            match state {
                Readiness::Ready(info) => return Ok(info),
                Readiness::Closed { reason } => {
                    return Err(ClientError::Transport {
                        scope: "session",
                        detail: reason,
                    });
                }
                _ => {
                    self.readiness
                        .changed()
                        .await
                        .map_err(|_| ClientError::Cancelled)?;
                }
            }
        }
    }

    /// Stop both sockets and join the supervisor and writer tasks.
    pub async fn stop(&self) -> Result<(), ClientError> {
        self.lifecycle.cancellation.cancel();
        // Keep the lifecycle mutex held until the one supervisor join has
        // completed. A second concurrent stop therefore waits for the first
        // caller instead of observing `None` and returning early.
        let mut lifecycle_join = self.lifecycle.join.lock().await;
        let result = match lifecycle_join.as_mut() {
            // Await through the option while holding the mutex. The handle is
            // only removed after completion, so cancellation of this stop
            // future leaves it available for a later caller to join.
            Some(join) => match join.await {
                Ok(result) => result.map(|_| ()),
                Err(_) => Err(ClientError::SupervisorPanicked),
            },
            None => Ok(()),
        };
        let _ = lifecycle_join.take();
        drop(lifecycle_join);
        result
    }

    /// Alias used by callers that model supervisor lifecycle as shutdown.
    pub async fn shutdown(&self) -> Result<(), ClientError> {
        self.stop().await
    }
}

impl Drop for ConnectionHandle {
    fn drop(&mut self) {
        if Arc::strong_count(&self.lifecycle) == 1 {
            self.lifecycle.cancellation.cancel();
        }
    }
}

/// Connect the M2 control/data pair with in-process `http-forward/1`
/// handlers registered for the configured `http-forward` exports.  The M1
/// profile has no HTTP exports and is rejected.
pub async fn connect_with_http_handlers(
    options: ConnectOptions,
    handlers: http_forward::HttpHandlers,
) -> Result<ConnectionHandle, ClientError> {
    if options.profile != TransportProfile::M2 {
        return Err(ClientError::Invalid(
            "http-forward exports require the M2 transport profile",
        ));
    }
    m2_runtime::connect_m2(options, handlers).await
}

/// Connect the control/data pair, perform HELLO/WELCOME and DATA_READY, then
/// return a handle for the running session actor.
pub async fn connect(options: ConnectOptions) -> Result<ConnectionHandle, ClientError> {
    if options.profile == TransportProfile::M2 {
        return m2_runtime::connect_m2(options, http_forward::HttpHandlers::default()).await;
    }
    options.config.validate()?;
    if options.cancellation.is_cancelled() {
        return Err(ClientError::Cancelled);
    }
    let tls = load_client_config(&options.config.credentials).map_err(ClientError::Credential)?;
    let control_url = Url::parse(&options.config.relay_url)
        .map_err(|_| ClientError::Invalid("relay_url is not a valid URL"))?;
    let (readiness_tx, readiness_rx) = watch::channel(Readiness::Connecting);
    let (_, status_rx) = watch::channel(ConnectionStatus::default());

    let mut control = open_socket(
        &control_url,
        tls.clone(),
        None,
        CONTROL_SUBPROTOCOL,
        MAX_CONTROL_MESSAGE_BYTES,
        &options.cancellation,
    )
    .await?;
    readiness_tx
        .send(Readiness::ControlOpen)
        .map_err(|_| ClientError::Cancelled)?;
    let hello = ControlMessage::Hello(Hello {
        message_id: message_id(),
        connector_id: options.config.device_id.clone(),
        protocol_major: PROTOCOL_MAJOR,
        protocol_minor: PROTOCOL_MINOR,
        features: vec![
            "m1-control-data".to_owned(),
            "authorization-challenge".to_owned(),
            "echo".to_owned(),
        ],
        services: configured_services(&options.config),
        rotation_policy: None,
    });
    tokio::select! {
        _ = options.cancellation.cancelled() => return Err(ClientError::Cancelled),
        result = send_control_direct(&mut control, &hello) => result?,
    }
    let welcome = receive_welcome(&mut control, hello.message_id(), &options.cancellation).await?;
    if welcome.protocol_major != PROTOCOL_MAJOR {
        return Err(ClientError::Protocol(format!(
            "relay selected unsupported protocol major {}",
            welcome.protocol_major
        )));
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
        tls,
        Some(&welcome.attachment_ticket),
        DATA_SUBPROTOCOL,
        MAX_FRAME_LEN,
        &options.cancellation,
    )
    .await?;

    // Data attachment is authenticated by mTLS and the one-use ticket. No
    // application bytes are sent on the data socket before DATA_READY.
    let data_ready = receive_data_ready(&mut control, &options.cancellation).await?;
    validate_data_ready(&data_ready, &session, &welcome)?;

    let (control_sink, control_stream) = control.split();
    let (data_sink, data_stream) = data.split();
    let cancellation = options.cancellation.clone();
    let actor_config = options.config.clone();
    let actor_readiness = readiness_tx.clone();
    let actor_cancel = cancellation.clone();
    let ready_info = SessionInfo {
        session_id: data_ready.session_id,
        epoch: data_ready.epoch,
        generation: data_ready.generation,
    };
    let join = tokio::spawn(async move {
        run_session(
            actor_config,
            session,
            welcome,
            control_sink,
            control_stream,
            data_sink,
            data_stream,
            actor_cancel,
            actor_readiness,
        )
        .await
    });
    readiness_tx
        .send(Readiness::Ready(ready_info))
        .map_err(|_| ClientError::Cancelled)?;
    let lifecycle = Arc::new(ConnectionLifecycle {
        cancellation,
        join: Mutex::new(Some(join)),
    });
    Ok(ConnectionHandle {
        readiness: readiness_rx,
        status: status_rx,
        lifecycle,
    })
}

fn configured_services(config: &RuntimeConfig) -> Vec<ServiceAdvertisement> {
    config
        .exports
        .iter()
        .map(|(name, export)| {
            ServiceAdvertisement::new(
                name.clone(),
                match export.kind {
                    ExportKind::Echo => "echo",
                    ExportKind::HttpForward => "http-forward",
                    ExportKind::Fs => "fs",
                },
                "1",
                ["echo", "data", "fin", "ack"],
            )
        })
        .collect()
}

async fn open_socket(
    url: &Url,
    tls: Arc<rustls::ClientConfig>,
    ticket: Option<&str>,
    subprotocol: &'static str,
    max_message_size: usize,
    cancellation: &CancellationToken,
) -> Result<ClientWebSocket, ClientError> {
    let mut request =
        url.as_str()
            .into_client_request()
            .map_err(|error| ClientError::Transport {
                scope: "websocket request",
                detail: sanitize_error(&error.to_string()),
            })?;
    if let Some(ticket) = ticket {
        let value = format!("Bearer {ticket}");
        let header = HeaderValue::from_str(&value).map_err(|_| {
            ClientError::Protocol("attachment ticket is not a valid header value".to_owned())
        })?;
        request.headers_mut().insert("authorization", header);
    }
    let subprotocol_header = HeaderValue::from_static(subprotocol);
    request
        .headers_mut()
        .insert("sec-websocket-protocol", subprotocol_header);
    let connector = Connector::Rustls(tls);
    let mut config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
    config.read_buffer_size = 4 * 1024;
    config.write_buffer_size = 0;
    config.max_write_buffer_size = max_message_size.saturating_mul(2).max(64 * 1024);
    config.max_message_size = Some(max_message_size);
    config.max_frame_size = Some(max_message_size + 16);
    config.accept_unmasked_frames = false;
    let handshake = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        connect_async_tls_with_config(request, Some(config), true, Some(connector)),
    );
    tokio::pin!(handshake);
    let (socket, response) = tokio::select! {
        _ = cancellation.cancelled() => return Err(ClientError::Cancelled),
        result = &mut handshake => result
            .map_err(|_| ClientError::HandshakeTimeout)?
            .map_err(|error| match tls_refusal(&error) {
                // Classified before `sanitize_error` erases it: a certificate
                // verification refusal is terminal, a certificate that is
                // only not current on someone's clock is retryable with its
                // reason, and anything else is an opaque retryable failure.
                Some(TlsFailure::Refused(reason)) => ClientError::TlsRefused(reason),
                Some(TlsFailure::NotCurrent { scope, detail }) => ClientError::Transport {
                    scope,
                    detail: detail.to_owned(),
                },
                None => ClientError::Transport {
                    scope: "websocket handshake",
                    detail: sanitize_error(&error.to_string()),
                },
            })?,
    };
    let selected_protocol = response
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok());
    if selected_protocol != Some(subprotocol) {
        return Err(ClientError::Protocol(format!(
            "relay did not select required WebSocket subprotocol {subprotocol}"
        )));
    }
    Ok(socket)
}

async fn send_control_direct(
    socket: &mut ClientWebSocket,
    message: &ControlMessage,
) -> Result<(), ClientError> {
    let bytes =
        encode_control(message).map_err(|error| ClientError::Protocol(error.to_string()))?;
    let text = String::from_utf8(bytes)
        .map_err(|_| ClientError::Protocol("control codec produced non-UTF-8 JSON".to_owned()))?;
    socket
        .send(Message::Text(text.into()))
        .await
        .map_err(|error| ClientError::Transport {
            scope: "control write",
            detail: sanitize_error(&error.to_string()),
        })
}

async fn receive_welcome(
    socket: &mut ClientWebSocket,
    hello_message_id: &str,
    cancellation: &CancellationToken,
) -> Result<Welcome, ClientError> {
    let deadline = tokio::time::sleep(HANDSHAKE_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        let next = tokio::select! {
            _ = &mut deadline => return Err(ClientError::HandshakeTimeout),
            _ = cancellation.cancelled() => return Err(ClientError::Cancelled),
            item = socket.next() => item,
        };
        match next {
            Some(Ok(Message::Text(text))) => {
                let message = decode_control(text.as_bytes())
                    .map_err(|error| ClientError::Protocol(error.to_string()))?;
                match message {
                    ControlMessage::Welcome(welcome) => {
                        if welcome.reply_to != hello_message_id {
                            return Err(ClientError::Protocol(
                                "WELCOME reply_to does not match HELLO".to_owned(),
                            ));
                        }
                        return Ok(welcome);
                    }
                    ControlMessage::Ping(ping) => {
                        let pong = ControlMessage::Pong(Pong::new(
                            message_id(),
                            ping.message_id,
                            ping.session_id,
                            ping.epoch,
                            ping.nonce,
                        ));
                        send_control_direct(socket, &pong).await?;
                    }
                    other => {
                        return Err(ClientError::Protocol(format!(
                            "expected WELCOME, received {}",
                            other.kind_name()
                        )));
                    }
                }
            }
            Some(Ok(Message::Ping(payload))) => {
                socket.send(Message::Pong(payload)).await.map_err(|error| {
                    ClientError::Transport {
                        scope: "control pong",
                        detail: sanitize_error(&error.to_string()),
                    }
                })?;
            }
            Some(Ok(Message::Close(Some(frame)))) => {
                if let Some(error) = classify_initial_control_close(&frame) {
                    return Err(error);
                }
                return Err(ClientError::Transport {
                    scope: "control handshake",
                    detail: "relay closed the control socket".to_owned(),
                });
            }
            Some(Ok(Message::Close(_))) | None => {
                return Err(ClientError::Transport {
                    scope: "control handshake",
                    detail: "relay closed the control socket".to_owned(),
                });
            }
            Some(Ok(Message::Binary(_))) => {
                return Err(ClientError::Protocol(
                    "binary message on control socket".to_owned(),
                ));
            }
            Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
            Some(Err(error)) => {
                return Err(ClientError::Transport {
                    scope: "control read",
                    detail: sanitize_error(&error.to_string()),
                });
            }
        }
    }
}

fn classify_initial_control_close(frame: &CloseFrame) -> Option<ClientError> {
    if frame.code == CloseCode::from(CONTROL_OWNER_BUSY_CLOSE_CODE)
        && &*frame.reason == CONTROL_OWNER_BUSY_CLOSE_REASON
    {
        return Some(ClientError::OwnerBusy);
    }
    // M6-C38: the relay does not speak this client's protocol major.  A
    // protocol error, so `PROTOCOL_ERROR`, terminal for the reconnect loop:
    // only upgrading one side can fix it.
    if frame.code == CloseCode::from(CONTROL_PROTOCOL_UNSUPPORTED_CLOSE_CODE)
        && &*frame.reason == CONTROL_PROTOCOL_UNSUPPORTED_CLOSE_REASON
    {
        return Some(ClientError::Protocol(format!(
            "the relay refused this client's protocol major {PROTOCOL_MAJOR} \
             ({CONTROL_PROTOCOL_UNSUPPORTED_CLOSE_REASON}); upgrade tunnel-client or the \
             relay so they share a protocol major; retrying will not help"
        )));
    }
    // M6-C32: the relay refused this device's identity.  A credential
    // error, so `CREDENTIAL_ERROR`, exit 3, and not retryable.
    (frame.code == CloseCode::from(CONTROL_IDENTITY_REJECTED_CLOSE_CODE)
        && &*frame.reason == CONTROL_IDENTITY_REJECTED_CLOSE_REASON)
        .then_some(ClientError::Credential(
            CredentialError::RelayRefusedIdentity,
        ))
}

async fn receive_data_ready(
    socket: &mut ClientWebSocket,
    cancellation: &CancellationToken,
) -> Result<DataReady, ClientError> {
    let deadline = tokio::time::sleep(HANDSHAKE_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        let next = tokio::select! {
            _ = &mut deadline => return Err(ClientError::HandshakeTimeout),
            _ = cancellation.cancelled() => return Err(ClientError::Cancelled),
            item = socket.next() => item,
        };
        match next {
            Some(Ok(Message::Text(text))) => {
                let message = decode_control(text.as_bytes())
                    .map_err(|error| ClientError::Protocol(error.to_string()))?;
                match message {
                    ControlMessage::DataReady(ready) => return Ok(ready),
                    ControlMessage::Ping(ping) => {
                        let pong = ControlMessage::Pong(Pong::new(
                            message_id(),
                            ping.message_id,
                            ping.session_id,
                            ping.epoch,
                            ping.nonce,
                        ));
                        send_control_direct(socket, &pong).await?;
                    }
                    other => {
                        return Err(ClientError::Protocol(format!(
                            "expected DATA_READY, received {}",
                            other.kind_name()
                        )));
                    }
                }
            }
            Some(Ok(Message::Ping(payload))) => {
                socket.send(Message::Pong(payload)).await.map_err(|error| {
                    ClientError::Transport {
                        scope: "control pong",
                        detail: sanitize_error(&error.to_string()),
                    }
                })?;
            }
            Some(Ok(Message::Close(_))) | None => {
                return Err(ClientError::Transport {
                    scope: "data attachment",
                    detail: "relay closed the control socket before DATA_READY".to_owned(),
                });
            }
            Some(Ok(Message::Binary(_))) => {
                return Err(ClientError::Protocol(
                    "binary message on control socket".to_owned(),
                ));
            }
            Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
            Some(Err(error)) => {
                return Err(ClientError::Transport {
                    scope: "control read",
                    detail: sanitize_error(&error.to_string()),
                });
            }
        }
    }
}

fn validate_data_ready(
    ready: &DataReady,
    session: &SessionInfo,
    welcome: &Welcome,
) -> Result<(), ClientError> {
    if ready.session_id != session.session_id
        || ready.epoch != session.epoch
        || ready.generation != welcome.generation
        || ready.connection_id != welcome.connection_id
        || ready.reply_to != welcome.message_id
    {
        return Err(ClientError::Protocol(
            "DATA_READY context does not match WELCOME".to_owned(),
        ));
    }
    Ok(())
}

fn data_url_for(control: &Url) -> Url {
    let mut url = control.clone();
    let path = control.path();
    let replacement = if let Some(prefix) = path.strip_suffix("/control") {
        format!("{prefix}/data")
    } else if path.ends_with('/') {
        format!("{path}data")
    } else {
        format!("{path}/data")
    };
    url.set_path(&replacement);
    url.set_query(None);
    url.set_fragment(None);
    url
}

struct QueueBudget {
    bytes: AtomicUsize,
    maximum: usize,
}

impl QueueBudget {
    fn current(&self) -> usize {
        self.bytes.load(Ordering::Acquire)
    }

    fn reserve(self: &Arc<Self>, bytes: usize) -> Result<(), ClientError> {
        if bytes > self.maximum {
            return Err(ClientError::QueueLimit);
        }
        let mut current = self.bytes.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(bytes) else {
                return Err(ClientError::QueueLimit);
            };
            if next > self.maximum {
                return Err(ClientError::QueueLimit);
            }
            match self.bytes.compare_exchange_weak(
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

    fn release(&self, bytes: usize) {
        self.bytes.fetch_sub(bytes, Ordering::AcqRel);
    }
}

struct QueuedMessage {
    message: Message,
    bytes: usize,
    budget: Arc<QueueBudget>,
    deadline: Option<DualDeadline>,
}

impl Drop for QueuedMessage {
    fn drop(&mut self) {
        self.budget.release(self.bytes);
    }
}

#[derive(Clone)]
struct OutboundQueue {
    sender: mpsc::Sender<QueuedMessage>,
    budget: Arc<QueueBudget>,
    cancellation: CancellationToken,
}

impl OutboundQueue {
    fn new(
        max_frames: usize,
        maximum_bytes: usize,
        cancellation: CancellationToken,
    ) -> (Self, mpsc::Receiver<QueuedMessage>) {
        let (sender, receiver) = mpsc::channel(max_frames.max(1));
        (
            Self {
                sender,
                budget: Arc::new(QueueBudget {
                    bytes: AtomicUsize::new(0),
                    maximum: maximum_bytes,
                }),
                cancellation,
            },
            receiver,
        )
    }

    async fn send(
        &self,
        message: Message,
        deadline: Option<DualDeadline>,
    ) -> Result<(), ClientError> {
        let bytes = message_size(&message);
        self.budget.reserve(bytes)?;
        let item = QueuedMessage {
            message,
            bytes,
            budget: self.budget.clone(),
            deadline,
        };
        if let Some(deadline) = deadline {
            tokio::select! {
                result = self.sender.send(item) => result.map_err(|_| ClientError::Transport { scope: "writer", detail: "writer stopped".to_owned() }),
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline.monotonic)) => Err(ClientError::AuthorizationExpired),
                _ = self.cancellation.cancelled() => Err(ClientError::Cancelled),
            }
        } else {
            tokio::select! {
                result = self.sender.send(item) => result.map_err(|_| ClientError::Transport { scope: "writer", detail: "writer stopped".to_owned() }),
                _ = self.cancellation.cancelled() => Err(ClientError::Cancelled),
            }
        }
    }

    #[cfg(test)]
    fn try_send(&self, message: Message) -> Result<(), ClientError> {
        self.try_send_with_deadline(message, None)
    }

    /// Free frame slots in the writer queue right now.  Best-effort traffic
    /// uses it to avoid taking a slot that an atomic OPEN pair still needs.
    fn capacity(&self) -> usize {
        self.sender.capacity()
    }

    /// Enqueue without waiting for capacity, while retaining the writer-side
    /// deadline used by authorization-bearing control messages. M1 continues
    /// to use [`Self::send`] and its cancellation/deadline-aware backpressure;
    /// M2 actors use this bounded path so a full writer queue cannot stall the
    /// actor.
    fn try_send_with_deadline(
        &self,
        message: Message,
        deadline: Option<DualDeadline>,
    ) -> Result<(), ClientError> {
        let bytes = message_size(&message);
        self.budget.reserve(bytes)?;
        let item = QueuedMessage {
            message,
            bytes,
            budget: self.budget.clone(),
            deadline,
        };
        self.sender.try_send(item).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => ClientError::QueueLimit,
            mpsc::error::TrySendError::Closed(_) => ClientError::Transport {
                scope: "writer",
                detail: "writer stopped".to_owned(),
            },
        })
    }

    /// Reserve and enqueue the two control responses for one OPEN as one
    /// bounded admission.  The actor must not publish stream state after only
    /// the OPENED response has entered the queue: a full queue at the
    /// authorization challenge would otherwise make the whole session fail
    /// while leaving a half-admitted stream behind.
    fn try_send_pair(
        &self,
        first: Message,
        first_deadline: Option<DualDeadline>,
        second: Message,
        second_deadline: Option<DualDeadline>,
    ) -> Result<(), ClientError> {
        let first_bytes = message_size(&first);
        let second_bytes = message_size(&second);
        let total_bytes = first_bytes
            .checked_add(second_bytes)
            .ok_or(ClientError::QueueLimit)?;
        self.budget.reserve(total_bytes)?;
        let mut permits = match self.sender.try_reserve_many(2) {
            Ok(permits) => permits,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.budget.release(total_bytes);
                return Err(ClientError::QueueLimit);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.budget.release(total_bytes);
                return Err(ClientError::Transport {
                    scope: "writer",
                    detail: "writer stopped".to_owned(),
                });
            }
        };
        let first_permit = permits.next().ok_or_else(|| {
            self.budget.release(total_bytes);
            ClientError::QueueLimit
        })?;
        let second_permit = permits.next().ok_or_else(|| {
            self.budget.release(total_bytes);
            ClientError::QueueLimit
        })?;
        first_permit.send(QueuedMessage {
            message: first,
            bytes: first_bytes,
            budget: self.budget.clone(),
            deadline: first_deadline,
        });
        second_permit.send(QueuedMessage {
            message: second,
            bytes: second_bytes,
            budget: self.budget.clone(),
            deadline: second_deadline,
        });
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum WriterKind {
    Control,
    Data,
}

#[derive(Clone, Copy)]
struct WriterFailure(WriterKind);

async fn writer_loop(
    kind: WriterKind,
    mut sink: ClientSink,
    mut receiver: mpsc::Receiver<QueuedMessage>,
    failure: mpsc::Sender<WriterFailure>,
    cancellation: CancellationToken,
    _test_gate: Option<WriterTestGate>,
) -> Result<(), ClientError> {
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                close_writer_sink(sink).await;
                return Ok(());
            }
            item = receiver.recv() => {
                let Some(item) = item else {
                    close_writer_sink(sink).await;
                    return Ok(());
                };
                #[cfg(test)]
                if matches!(kind, WriterKind::Control)
                    && let Some(gate) = _test_gate.as_ref()
                    && gate
                        .block_once
                        .swap(false, std::sync::atomic::Ordering::AcqRel)
                {
                    gate.entered.notify_one();
                    let cancelled = tokio::select! {
                        biased;
                        _ = gate.release.notified() => false,
                        _ = cancellation.cancelled() => true,
                    };
                    if cancelled {
                        // Dropping this test-held sink is immediate and keeps
                        // cancellation from waiting on a close handshake.
                        return Ok(());
                    }
                }
                if item.deadline.is_some_and(DualDeadline::expired) {
                    let _ = failure.send(WriterFailure(kind)).await;
                    return Err(ClientError::AuthorizationExpired);
                }
                if let Err(error) = send_writer_message(&mut sink, item.message.clone(), &cancellation).await {
                    if !matches!(&error, &ClientError::Cancelled) {
                        let _ = failure.send(WriterFailure(kind)).await;
                    }
                    return Err(error);
                }
            }
        }
    }
}

async fn send_writer_message(
    sink: &mut ClientSink,
    message: Message,
    cancellation: &CancellationToken,
) -> Result<(), ClientError> {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(ClientError::Cancelled),
        result = tokio::time::timeout(WRITER_WRITE_TIMEOUT, sink.send(message)) => {
            match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(ClientError::Transport {
                    scope: "writer",
                    detail: sanitize_error(&error.to_string()),
                }),
                Err(_) => Err(ClientError::Transport {
                    scope: "writer",
                    detail: "writer send deadline exceeded".to_owned(),
                }),
            }
        }
    }
}

async fn close_writer_sink(mut sink: ClientSink) {
    let _ = tokio::time::timeout(WRITER_CLOSE_TIMEOUT, sink.close()).await;
}

/// A fail-closed deadline held against both clocks available to a desktop
/// process. `Instant` can stop advancing during system suspend; the wall
/// deadline catches that case. A wall clock observed before the challenge
/// anchor is treated as a reversal and therefore expired.
#[derive(Clone, Copy, Debug)]
struct DualDeadline {
    started: Instant,
    started_wall: SystemTime,
    monotonic: Instant,
    wall: SystemTime,
}

impl DualDeadline {
    fn new(started: Instant, started_wall: SystemTime, duration: Duration) -> Option<Self> {
        Some(Self {
            started,
            started_wall,
            monotonic: started.checked_add(duration)?,
            wall: started_wall.checked_add(duration)?,
        })
    }

    fn shorten(self, duration: Duration) -> Option<Self> {
        Some(Self {
            started: self.started,
            started_wall: self.started_wall,
            monotonic: self.monotonic.min(self.started.checked_add(duration)?),
            wall: self.wall.min(self.started_wall.checked_add(duration)?),
        })
    }

    fn min(self, other: Self) -> Self {
        Self {
            started: self.started,
            started_wall: self.started_wall,
            monotonic: self.monotonic.min(other.monotonic),
            wall: self.wall.min(other.wall),
        }
    }

    fn expired_at(self, monotonic_now: Instant, wall_now: SystemTime) -> bool {
        monotonic_now >= self.monotonic
            || wall_now.duration_since(self.started_wall).is_err()
            || wall_now >= self.wall
    }

    fn expired(self) -> bool {
        self.expired_at(Instant::now(), SystemTime::now())
    }

    fn remaining(self, monotonic_now: Instant) -> Duration {
        self.monotonic.saturating_duration_since(monotonic_now)
    }
}

#[derive(Clone, Debug)]
struct AuthContext {
    challenge_id: String,
    nonce: String,
    permission_digest: String,
    grant_revision: u64,
    deadline: DualDeadline,
    operation_deadline: DualDeadline,
    confirmed: bool,
    /// A fresh challenge is awaiting confirmation.  M2 sets this again for
    /// each long-lived stream authorization refresh; the operation deadline
    /// remains independent and is never extended by a confirmation.
    refresh_in_flight: bool,
    invalidated: bool,
}

#[derive(Debug)]
enum BufferedInput {
    Data(Vec<u8>),
    Fin,
}

#[derive(Debug)]
struct StreamContext {
    export: ExportConfig,
    auth: AuthContext,
    inbound_sequence: u64,
    outbound_sequence: u64,
    inbound_fin: bool,
    outbound_fin: bool,
    pending: VecDeque<BufferedInput>,
    pending_bytes: usize,
}

struct SessionActor {
    config: RuntimeConfig,
    session: SessionInfo,
    control_queue: OutboundQueue,
    data_queue: OutboundQueue,
    streams: BTreeMap<u64, StreamContext>,
    queued_bytes: usize,
    accepting: bool,
}

#[allow(clippy::too_many_arguments)]
async fn run_session(
    config: RuntimeConfig,
    session: SessionInfo,
    _welcome: Welcome,
    control_sink: ClientSink,
    mut control_stream: ClientStream,
    data_sink: ClientSink,
    mut data_stream: ClientStream,
    cancellation: CancellationToken,
    readiness: watch::Sender<Readiness>,
) -> Result<(), ClientError> {
    let (control_queue, control_receiver) = OutboundQueue::new(
        config.limits.max_queue_frames.min(16),
        CONTROL_QUEUE_BYTES.min(config.limits.max_queue_bytes),
        cancellation.clone(),
    );
    let (data_queue, data_receiver) = OutboundQueue::new(
        config.limits.max_queue_frames,
        DATA_QUEUE_BYTES.min(config.limits.max_queue_bytes),
        cancellation.clone(),
    );
    let (writer_failure_tx, mut writer_failure_rx) = mpsc::channel(2);
    let control_writer = tokio::spawn(writer_loop(
        WriterKind::Control,
        control_sink,
        control_receiver,
        writer_failure_tx.clone(),
        cancellation.clone(),
        None,
    ));
    let data_writer = tokio::spawn(writer_loop(
        WriterKind::Data,
        data_sink,
        data_receiver,
        writer_failure_tx,
        cancellation.clone(),
        None,
    ));
    let mut actor = SessionActor {
        config,
        session,
        control_queue,
        data_queue,
        streams: BTreeMap::new(),
        queued_bytes: 0,
        accepting: true,
    };
    let result = loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break Ok(()),
            failure = writer_failure_rx.recv() => {
                break writer_failure_result(
                    cancellation.is_cancelled(),
                    failure.map(|failure| failure.0),
                );
            }
            control = control_stream.next() => {
                match control {
                    Some(Ok(message)) => {
                        if let Err(error) = actor.handle_control_message(message).await {
                            break session_failure_result(cancellation.is_cancelled(), error);
                        }
                    }
                    Some(Err(error)) => break session_failure_result(
                        cancellation.is_cancelled(),
                        ClientError::Transport { scope: "control read", detail: sanitize_error(&error.to_string()) },
                    ),
                    None => break session_failure_result(
                        cancellation.is_cancelled(),
                        ClientError::Transport { scope: "control read", detail: "control socket closed".to_owned() },
                    ),
                }
            }
            data = data_stream.next() => {
                match data {
                    Some(Ok(message)) => {
                        if let Err(error) = actor.handle_data_message(message).await {
                            break session_failure_result(cancellation.is_cancelled(), error);
                        }
                    }
                    Some(Err(error)) => break session_failure_result(
                        cancellation.is_cancelled(),
                        ClientError::Transport { scope: "data read", detail: sanitize_error(&error.to_string()) },
                    ),
                    None => break session_failure_result(
                        cancellation.is_cancelled(),
                        ClientError::Transport { scope: "data read", detail: "data socket closed".to_owned() },
                    ),
                }
            }
        }
    };
    readiness.send(Readiness::Stopping).ok();
    cancellation.cancel();
    let _ = control_writer.await;
    let _ = data_writer.await;
    let closed_reason = match &result {
        Ok(()) => "stopped".to_owned(),
        Err(ClientError::Cancelled) => "cancelled".to_owned(),
        Err(error) => error.safe_message(),
    };
    readiness
        .send(Readiness::Closed {
            reason: closed_reason,
        })
        .ok();
    result
}

fn session_failure_result(
    cancellation_requested: bool,
    error: ClientError,
) -> Result<(), ClientError> {
    if cancellation_requested {
        Ok(())
    } else {
        Err(error)
    }
}

fn writer_failure_result(
    cancellation_requested: bool,
    kind: Option<WriterKind>,
) -> Result<(), ClientError> {
    if cancellation_requested {
        return Ok(());
    }
    let scope = match kind {
        Some(WriterKind::Control) => "control writer",
        Some(WriterKind::Data) => "data writer",
        None => "writer",
    };
    session_failure_result(
        cancellation_requested,
        ClientError::Transport {
            scope,
            detail: "writer stopped".to_owned(),
        },
    )
}

impl SessionActor {
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
            Message::Ping(payload) => self.control_queue.send(Message::Pong(payload), None).await,
            Message::Pong(_) | Message::Frame(_) => Ok(()),
            Message::Close(_) => Err(ClientError::Transport {
                scope: "control read",
                detail: "control socket closed".to_owned(),
            }),
        }
    }

    async fn handle_control(&mut self, message: ControlMessage) -> Result<(), ClientError> {
        match message {
            ControlMessage::Open(open) => self.handle_open(open).await,
            ControlMessage::AuthorizationConfirmed(confirmed) => {
                self.handle_authorization_confirmed(confirmed).await
            }
            ControlMessage::AuthorizationInvalidated(invalidated) => {
                self.handle_authorization_invalidated(invalidated).await
            }
            ControlMessage::Cancel(cancel) => self.handle_cancel(cancel).await,
            ControlMessage::Ping(ping) => self.handle_ping(ping).await,
            ControlMessage::GoAway(goaway) => {
                if goaway.session_id == self.session.session_id
                    && goaway.epoch == self.session.epoch
                {
                    self.accepting = false;
                }
                Ok(())
            }
            ControlMessage::Welcome(_)
            | ControlMessage::DataReady(_)
            | ControlMessage::Opened(_)
            | ControlMessage::Rejected(_)
            | ControlMessage::Hello(_)
            | ControlMessage::Pong(_)
            | ControlMessage::AuthorizationChallenge(_) => Ok(()),
            ControlMessage::ResultStatus(_)
            | ControlMessage::RotateRequest(_)
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
            | ControlMessage::StreamForget(_)
            | ControlMessage::Resume(_)
            | ControlMessage::RecoveryBegin(_)
            | ControlMessage::RecoveryClosed(_)
            | ControlMessage::OwnerFence(_)
            | ControlMessage::OwnerFenced(_)
            | ControlMessage::Resumed(_) => Err(ClientError::Protocol(
                "M2 control message received while using the explicit M1 profile".to_owned(),
            )),
        }
    }

    async fn handle_open(&mut self, open: Open) -> Result<(), ClientError> {
        if open.session_id != self.session.session_id || open.epoch != self.session.epoch {
            return Err(ClientError::Protocol(
                "OPEN context does not match the authenticated session".to_owned(),
            ));
        }
        let export = self.config.exports.get(&open.service_id).cloned();
        if !self.accepting {
            return self
                .send_rejected(&open, "GOAWAY", "connector is draining")
                .await;
        }
        if self.streams.len() >= self.config.limits.max_streams {
            return self
                .send_rejected(&open, "RESOURCE_EXHAUSTED", "stream limit reached")
                .await;
        }
        let Some(export) = export else {
            return self
                .send_rejected(&open, "EXPORT_DENIED", "service is not locally allowlisted")
                .await;
        };
        if export.kind != ExportKind::Echo || open.operation != "echo" {
            return self
                .send_rejected(
                    &open,
                    "OPERATION_DENIED",
                    "only the local echo operation is enabled",
                )
                .await;
        }
        if self.streams.contains_key(&open.stream_id) {
            return self
                .send_rejected(&open, "STREAM_EXISTS", "stream ID is already active")
                .await;
        }
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
        self.send_control(opened, None).await?;

        // The monotonic deadline starts before the challenge can wait behind a
        // bounded control queue. The wall-clock anchor is captured alongside
        // it so system suspend cannot make a stale grant usable.
        let started = Instant::now();
        let started_wall = SystemTime::now();
        let challenge_id = message_id();
        let nonce = message_id();
        let permission_digest = open
            .metadata
            .get("permission_digest")
            .cloned()
            .unwrap_or_else(|| "m1-echo".to_owned());
        let grant_revision = open
            .metadata
            .get("grant_revision")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
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
        let deadline = DualDeadline::new(
            started,
            started_wall,
            Duration::from_millis(self.config.limits.grant_timeout_ms),
        )
        .ok_or_else(|| ClientError::Protocol("authorization deadline overflow".to_owned()))?;
        let operation_deadline = DualDeadline::new(
            started,
            started_wall,
            Duration::from_millis(self.config.limits.operation_timeout_ms),
        )
        .ok_or_else(|| ClientError::Protocol("operation deadline overflow".to_owned()))?;
        let stream_id = open.stream_id;
        let context = StreamContext {
            export,
            auth: AuthContext {
                challenge_id,
                nonce,
                permission_digest,
                grant_revision,
                deadline,
                operation_deadline,
                confirmed: false,
                refresh_in_flight: true,
                invalidated: false,
            },
            inbound_sequence: 0,
            outbound_sequence: 0,
            inbound_fin: false,
            outbound_fin: false,
            pending: VecDeque::new(),
            pending_bytes: 0,
        };
        self.streams.insert(stream_id, context);
        self.send_control(challenge, None).await
    }

    async fn send_rejected(
        &self,
        open: &Open,
        code: &str,
        reason: &str,
    ) -> Result<(), ClientError> {
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
        .await
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
        let decision: (bool, VecDeque<BufferedInput>, usize) = {
            let Some(context) = self.streams.get_mut(&stream_id) else {
                return Ok(());
            };
            let now = Instant::now();
            let wall_now = SystemTime::now();
            if context.auth.confirmed {
                // A confirmation is one-shot. Ignore a replay rather than
                // allowing the same nonce to move the deadline again.
                return Ok(());
            }
            let valid = context.auth.challenge_id == confirmed.challenge_id
                && context.auth.nonce == confirmed.nonce
                && context.auth.permission_digest == confirmed.permission_digest
                && context.auth.grant_revision == confirmed.grant_revision
                && !context.auth.invalidated
                && (1..=5_000).contains(&confirmed.remaining_ms)
                && !context.auth.deadline.expired_at(now, wall_now)
                && !context.auth.operation_deadline.expired_at(now, wall_now);
            if !valid {
                (false, VecDeque::new(), 0)
            } else {
                // The relay's remaining lifetime is anchored to the
                // device-created challenge. It can shorten this local
                // deadline but never extend it.
                let Some(anchored_deadline) = context.auth.deadline.shorten(Duration::from_millis(
                    confirmed
                        .remaining_ms
                        .min(self.config.limits.grant_timeout_ms),
                )) else {
                    return self.expire_stream(stream_id).await;
                };
                context.auth.deadline = anchored_deadline;
                if context.auth.deadline.expired_at(now, wall_now)
                    || context.auth.operation_deadline.expired_at(now, wall_now)
                {
                    (false, VecDeque::new(), 0)
                } else {
                    context.auth.confirmed = true;
                    context.auth.nonce.clear();
                    let pending = std::mem::take(&mut context.pending);
                    let pending_bytes = context.pending_bytes;
                    context.pending_bytes = 0;
                    (true, pending, pending_bytes)
                }
            }
        };
        if !decision.0 {
            return self.expire_stream(stream_id).await;
        }
        let (_, pending, pending_bytes) = decision;
        self.queued_bytes = self.queued_bytes.saturating_sub(pending_bytes);
        for item in pending {
            match item {
                BufferedInput::Data(payload) => self.dispatch_payload(stream_id, payload).await?,
                BufferedInput::Fin => self.dispatch_fin(stream_id).await?,
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
            .is_some_and(|context| context.auth.challenge_id == invalidated.challenge_id)
        {
            self.expire_stream(invalidated.stream_id).await?;
        }
        Ok(())
    }

    async fn handle_cancel(&mut self, cancel: Cancel) -> Result<(), ClientError> {
        if cancel.session_id != self.session.session_id || cancel.epoch != self.session.epoch {
            return Err(ClientError::Protocol("CANCEL context mismatch".to_owned()));
        }
        if let Some(context) = self.streams.remove(&cancel.stream_id) {
            self.queued_bytes = self.queued_bytes.saturating_sub(context.pending_bytes);
            self.send_control(
                ControlMessage::Rejected(Rejected::new(
                    message_id(),
                    cancel.message_id,
                    self.session.session_id.clone(),
                    self.session.epoch,
                    cancel.stream_id,
                    cancel.operation_id,
                    "CANCELLED",
                    "local echo cancelled",
                )),
                None,
            )
            .await?;
        }
        Ok(())
    }

    async fn handle_ping(&self, ping: Ping) -> Result<(), ClientError> {
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
        .await
    }

    async fn handle_data_message(&mut self, message: Message) -> Result<(), ClientError> {
        match message {
            Message::Binary(bytes) => {
                let frame = Frame::decode(&bytes)
                    .map_err(|error| ClientError::Protocol(error.to_string()))?;
                if frame.epoch != self.session.epoch {
                    return Err(ClientError::Protocol(
                        "data frame epoch does not match session".to_owned(),
                    ));
                }
                self.handle_frame(frame).await
            }
            Message::Text(_) => Err(ClientError::Protocol(
                "text message on data socket".to_owned(),
            )),
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => Ok(()),
            Message::Close(_) => Err(ClientError::Transport {
                scope: "data read",
                detail: "data socket closed".to_owned(),
            }),
        }
    }

    async fn handle_frame(&mut self, frame: Frame) -> Result<(), ClientError> {
        let stream_id = frame.stream_id;
        if frame.generation != self.session.generation {
            return Err(ClientError::Protocol(
                "data frame generation does not match active socket".to_owned(),
            ));
        }
        if matches!(
            frame.kind,
            FrameKind::Data | FrameKind::Fin | FrameKind::Reset
        ) && self
            .streams
            .get(&stream_id)
            .is_some_and(|context| frame.ack > context.outbound_sequence)
        {
            return Err(ClientError::Protocol(
                "piggybacked data ACK exceeds emitted sequence".to_owned(),
            ));
        }
        if self
            .streams
            .get(&stream_id)
            .is_some_and(|context| context.auth.operation_deadline.expired())
        {
            return self.expire_stream(stream_id).await;
        }
        match frame.kind {
            FrameKind::Data => {
                let payload_len = frame.payload.len();
                let queued_bytes = self.queued_bytes;
                let decision = {
                    let Some(context) = self.streams.get_mut(&stream_id) else {
                        return self.send_reset(stream_id, DATA_CLOSE_PROTOCOL).await;
                    };
                    if context.inbound_fin || frame.sequence <= context.inbound_sequence {
                        return Err(ClientError::Protocol(
                            "duplicate or post-FIN DATA frame".to_owned(),
                        ));
                    } else if context.inbound_sequence.checked_add(1) != Some(frame.sequence) {
                        Err(())
                    } else {
                        context.inbound_sequence = frame.sequence;
                        let confirmed = context.auth.confirmed;
                        let exceeds = !confirmed
                            && (context.pending_bytes.saturating_add(payload_len)
                                > self.config.limits.max_queue_bytes
                                || queued_bytes.saturating_add(payload_len)
                                    > self.config.limits.max_queue_bytes);
                        if !confirmed && !exceeds {
                            context.pending_bytes += payload_len;
                            context
                                .pending
                                .push_back(BufferedInput::Data(frame.payload.clone()));
                        }
                        Ok((frame.sequence, confirmed, exceeds))
                    }
                };
                let Ok((acknowledged, confirmed, exceeds)) = decision else {
                    return self.send_reset(stream_id, DATA_CLOSE_PROTOCOL).await;
                };
                self.send_ack(stream_id, acknowledged).await?;
                if exceeds {
                    return self.expire_stream(stream_id).await;
                }
                if confirmed {
                    self.dispatch_payload(stream_id, frame.payload).await
                } else {
                    self.queued_bytes = self.queued_bytes.saturating_add(payload_len);
                    Ok(())
                }
            }
            FrameKind::Fin => {
                let decision = {
                    let Some(context) = self.streams.get_mut(&stream_id) else {
                        return self.send_reset(stream_id, DATA_CLOSE_PROTOCOL).await;
                    };
                    if context.inbound_fin || frame.sequence <= context.inbound_sequence {
                        return Err(ClientError::Protocol(
                            "duplicate or repeated FIN frame".to_owned(),
                        ));
                    } else if context.inbound_sequence.checked_add(1) != Some(frame.sequence) {
                        Err(())
                    } else {
                        context.inbound_sequence = frame.sequence;
                        context.inbound_fin = true;
                        let confirmed = context.auth.confirmed;
                        if !confirmed {
                            context.pending.push_back(BufferedInput::Fin);
                        }
                        Ok((frame.sequence, confirmed))
                    }
                };
                let Ok((acknowledged, confirmed)) = decision else {
                    return self.send_reset(stream_id, DATA_CLOSE_PROTOCOL).await;
                };
                self.send_ack(stream_id, acknowledged).await?;
                if confirmed {
                    self.dispatch_fin(stream_id).await
                } else {
                    Ok(())
                }
            }
            FrameKind::Ack => {
                let terminal = {
                    let Some(context) = self.streams.get(&stream_id) else {
                        // A terminal ACK may arrive again after the stream was
                        // retired.  Ignore unknown ACKs in M1 rather than
                        // creating a RESET ping-pong loop.
                        return Ok(());
                    };
                    if frame.ack > context.outbound_sequence {
                        return Err(ClientError::Protocol(
                            "data ACK exceeds emitted sequence".to_owned(),
                        ));
                    }
                    context.inbound_fin
                        && context.outbound_fin
                        && frame.ack == context.outbound_sequence
                };
                if terminal && let Some(context) = self.streams.remove(&stream_id) {
                    self.queued_bytes = self.queued_bytes.saturating_sub(context.pending_bytes);
                }
                Ok(())
            }
            FrameKind::WindowUpdate => Ok(()),
            FrameKind::Reset => {
                let valid_terminal = {
                    let Some(context) = self.streams.get_mut(&stream_id) else {
                        return self.send_reset(stream_id, DATA_CLOSE_PROTOCOL).await;
                    };
                    if !terminal_sequence_valid(
                        context.inbound_sequence,
                        frame.sequence,
                        context.inbound_fin,
                    ) {
                        false
                    } else {
                        context.inbound_sequence = frame.sequence;
                        true
                    }
                };
                if !valid_terminal {
                    return Err(ClientError::Protocol(
                        "RESET sequence is stale, gapped, or follows FIN".to_owned(),
                    ));
                }
                if let Some(context) = self.streams.remove(&stream_id) {
                    self.queued_bytes = self.queued_bytes.saturating_sub(context.pending_bytes);
                }
                Ok(())
            }
        }
    }

    async fn dispatch_payload(
        &mut self,
        stream_id: u64,
        payload: Vec<u8>,
    ) -> Result<(), ClientError> {
        let (deadline, canary, ack, current_sequence) = {
            let Some(context) = self.streams.get(&stream_id) else {
                return Ok(());
            };
            if !context.auth.confirmed || context.auth.invalidated {
                return Ok(());
            }
            if context.outbound_fin {
                return Err(ClientError::Protocol(
                    "DATA received after local FIN".to_owned(),
                ));
            }
            (
                context.auth.deadline.min(context.auth.operation_deadline),
                context.export.device_canary.clone(),
                context.inbound_sequence,
                context.outbound_sequence,
            )
        };
        if deadline.expired() {
            return self.expire_stream(stream_id).await;
        }
        let canary_len = canary.as_ref().map_or(0, String::len);
        let output_len = checked_echo_output_len(canary_len, payload.len())
            .ok_or_else(|| ClientError::Protocol("echo output length overflow".to_owned()))?;
        let mut output = Vec::with_capacity(output_len);
        if let Some(canary) = canary {
            output.extend_from_slice(canary.as_bytes());
        }
        output.extend_from_slice(&payload);
        let chunk_count = output.len().div_ceil(MAX_PAYLOAD_LEN);
        let (next_sequence, _last_sequence) =
            reserve_outbound_sequences(current_sequence, chunk_count)
                .ok_or_else(|| ClientError::Protocol("outbound sequence exhausted".to_owned()))?;

        for (offset, chunk) in output.chunks(MAX_PAYLOAD_LEN).enumerate() {
            if deadline.expired() {
                return self.expire_stream(stream_id).await;
            }
            let offset = u64::try_from(offset).map_err(|_| {
                ClientError::Protocol("echo output frame index overflow".to_owned())
            })?;
            let sequence = next_sequence + offset;
            let frame = Frame::data(
                self.session.epoch,
                self.session.generation,
                stream_id,
                sequence,
                ack,
                chunk.to_vec(),
            );
            let encoded = frame
                .encode()
                .map_err(|error| ClientError::Protocol(error.to_string()))?;
            self.data_queue
                .send(Message::Binary(encoded.into()), Some(deadline))
                .await?;
            if let Some(context) = self.streams.get_mut(&stream_id) {
                context.outbound_sequence = sequence;
            }
            if deadline.expired() {
                // The frame is already admitted to the writer queue. Do not
                // enqueue a RESET with a reused sequence; fail the session so
                // the uncertain queued side effect cannot be replayed.
                return Err(ClientError::AuthorizationExpired);
            }
        }
        Ok(())
    }

    async fn dispatch_fin(&mut self, stream_id: u64) -> Result<(), ClientError> {
        let (deadline, ack, next_sequence) = {
            let Some(context) = self.streams.get(&stream_id) else {
                return Ok(());
            };
            if !context.auth.confirmed || context.auth.invalidated || context.outbound_fin {
                return Ok(());
            }
            (
                context.auth.deadline.min(context.auth.operation_deadline),
                context.inbound_sequence,
                reserve_outbound_sequences(context.outbound_sequence, 1)
                    .map(|(first, _)| first)
                    .ok_or_else(|| {
                        ClientError::Protocol("outbound sequence exhausted".to_owned())
                    })?,
            )
        };
        if deadline.expired() {
            return self.expire_stream(stream_id).await;
        }
        let frame = Frame::fin(
            self.session.epoch,
            self.session.generation,
            stream_id,
            next_sequence,
            ack,
        );
        let encoded = frame
            .encode()
            .map_err(|error| ClientError::Protocol(error.to_string()))?;
        self.data_queue
            .send(Message::Binary(encoded.into()), Some(deadline))
            .await?;
        if let Some(context) = self.streams.get_mut(&stream_id) {
            context.outbound_sequence = next_sequence;
            context.outbound_fin = true;
        }
        if deadline.expired() {
            return Err(ClientError::AuthorizationExpired);
        }
        Ok(())
    }

    async fn send_ack(&self, stream_id: u64, acknowledged: u64) -> Result<(), ClientError> {
        let frame = Frame::ack(
            self.session.epoch,
            self.session.generation,
            stream_id,
            acknowledged,
        );
        let encoded = frame
            .encode()
            .map_err(|error| ClientError::Protocol(error.to_string()))?;
        self.data_queue
            .send(Message::Binary(encoded.into()), None)
            .await
    }

    async fn send_reset(&mut self, stream_id: u64, reason: u16) -> Result<(), ClientError> {
        let sequence = self.streams.get(&stream_id).map_or(1, |context| {
            context.outbound_sequence.checked_add(1).unwrap_or(1)
        });
        let frame = Frame::reset(
            self.session.epoch,
            self.session.generation,
            stream_id.max(1),
            sequence,
            self.streams
                .get(&stream_id)
                .map_or(0, |context| context.inbound_sequence),
            reason,
        );
        let encoded = frame
            .encode()
            .map_err(|error| ClientError::Protocol(error.to_string()))?;
        self.data_queue
            .send(Message::Binary(encoded.into()), None)
            .await?;
        if let Some(context) = self.streams.remove(&stream_id) {
            self.queued_bytes = self.queued_bytes.saturating_sub(context.pending_bytes);
        }
        Ok(())
    }

    async fn expire_stream(&mut self, stream_id: u64) -> Result<(), ClientError> {
        self.send_reset(stream_id, DATA_CLOSE_AUTH_EXPIRED).await
    }

    async fn send_control(
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
            .send(Message::Text(text.into()), deadline)
            .await
    }
}

fn message_size(message: &Message) -> usize {
    match message {
        Message::Text(text) => text.len(),
        Message::Binary(bytes) => bytes.len(),
        Message::Ping(bytes) | Message::Pong(bytes) => bytes.len(),
        Message::Close(Some(frame)) => frame.reason.len() + 2,
        Message::Close(None) | Message::Frame(_) => 0,
    }
}

fn message_id() -> String {
    Uuid::new_v4().to_string()
}

fn terminal_sequence_valid(current: u64, incoming: u64, fin_seen: bool) -> bool {
    !fin_seen && current.checked_add(1) == Some(incoming)
}

fn reserve_outbound_sequences(current: u64, frame_count: usize) -> Option<(u64, u64)> {
    if frame_count == 0 {
        return Some((current, current));
    }
    let first = current.checked_add(1)?;
    let last_offset = u64::try_from(frame_count - 1).ok()?;
    Some((first, first.checked_add(last_offset)?))
}

fn checked_echo_output_len(canary_len: usize, payload_len: usize) -> Option<usize> {
    canary_len.checked_add(payload_len)
}

/// `Transport` scope of a handshake the relay refused with a
/// `certificate_expired` TLS alert. rustls sends that one alert for **both**
/// an expired and a not-yet-valid client certificate (`impl
/// From<CertificateError> for AlertDescription`), judged on the **relay's**
/// clock, so the alert alone cannot say whether the certificate is expired or
/// the two clocks disagree. It is therefore reported retryable here, and
/// `tunnel-client connect` decides with the one thing it has that the relay
/// does not: this device's certificate, read against this host's clock
/// (task row M6-C23).
pub const DEVICE_CERTIFICATE_NOT_CURRENT_SCOPE: &str = "device certificate validity";

/// `Transport` scope of a `STREAM_FORGET` whose terminal proof was still
/// waiting for the relay's final data-channel ACK when its bounded
/// revalidation window ended (task row M6-C105). Everything but that ACK
/// validated; only evidence is missing, and a missing ACK is what a stalled
/// process (`Instant` keeps running through SIGSTOP) or a lost data path
/// produces, including a host suspended past the relay's idle eviction -- so
/// the session fails retryable and `connect` reconnects. Evidence that
/// contradicts the proof, or an owner snapshot invalid in itself, stays
/// `ClientError::Protocol`.
pub const STREAM_FORGET_PROOF_SCOPE: &str = "stream forget proof";

/// The one detail written under `STREAM_FORGET_PROOF_SCOPE`.
pub const STREAM_FORGET_PROOF_EXPIRED: &str =
    "STREAM_FORGET terminal proof did not converge before its deadline";

/// `Transport` scope of a relay certificate this client found expired or not
/// yet valid on **its own** clock. Retryable: either this host's clock is
/// wrong or the relay's certificate is due for renewal, and both are fixed
/// without touching the device.
pub const RELAY_CERTIFICATE_NOT_CURRENT_SCOPE: &str = "relay certificate validity";

/// Safe message of `ClientError::AuthorizationExpired` (`AUTHORIZATION_STALE`,
/// exit `4`). Published so a harness that buckets CLI messages matches the
/// text by name rather than by a copy that can drift (task row M6-C39).
pub const AUTHORIZATION_EXPIRED_MESSAGE: &str = "a stream's authorization window lapsed before \
its frame was written, so the session was restarted; this is usually a stalled or congested \
data path";

/// How a TLS handshake failure is classified before sanitization.
enum TlsFailure {
    /// A refusal no retry can fix; the reason is fixed text.
    Refused(&'static str),
    /// A certificate valid except for the time; retryable, with a fixed
    /// reason under a scope `safe_message` reveals.
    NotCurrent {
        scope: &'static str,
        detail: &'static str,
    },
}

/// The certificate-verification failures of a handshake, classified **by
/// rustls variant and never by message text** (task row M6-C23, reconnect).
///
/// Every handshake failure is otherwise one opaque `websocket handshake
/// failed`, so a reconnecting `connect` could not tell a wrong `server_ca`
/// from a relay that is still restarting. Three outcomes:
///
/// * **Terminal** (`TlsFailure::Refused`): this client refused the relay's
///   certificate as from an unknown issuer (the wrong `server_ca`), badly
///   signed, revoked, not valid for the relay's name, or not for server
///   authentication; or the relay refused this device's certificate with an
///   unknown-CA, bad, unsupported, revoked, unknown or required-but-absent
///   certificate alert. These are properties of the identities, not of time
///   or the network.
/// * **Retryable with its reason** (`TlsFailure::NotCurrent`): a certificate
///   that is expired or not yet valid **on somebody's clock** -- the relay's
///   certificate on ours, or ours on the relay's (the `certificate_expired`
///   alert). Clock skew between a CA, a relay and a device is ordinary, and a
///   relay certificate can be renewed; `connect` settles the device side
///   against its own certificate (see `DEVICE_CERTIFICATE_NOT_CURRENT_SCOPE`).
/// * **Opaque and retryable** (`None`): a reset, an EOF, an I/O error, a
///   timeout, a middlebox dropping the connection, an unclassified alert such
///   as `handshake_failure`, `decrypt_error` or `access_denied`, and
///   certificate errors outside the lists (`BadEncoding`, `Other`, variants a
///   later rustls adds). Those are what a laptop waking from sleep or a flaky
///   network produce.
///
/// Every reason is a string written here; nothing from the peer or its
/// certificate is carried.
fn tls_refusal(error: &tokio_tungstenite::tungstenite::Error) -> Option<TlsFailure> {
    use tokio_tungstenite::tungstenite::{Error as WsError, error::TlsError};
    let rustls_error: &rustls::Error = match error {
        WsError::Tls(TlsError::Rustls(error)) => error,
        // tokio-rustls reports handshake and record errors as an I/O error
        // whose inner error is the `rustls::Error`.
        WsError::Io(error) => error.get_ref()?.downcast_ref::<rustls::Error>()?,
        _ => return None,
    };
    classify_rustls_refusal(rustls_error)
}

fn classify_rustls_refusal(error: &rustls::Error) -> Option<TlsFailure> {
    use rustls::{AlertDescription as Alert, CertificateError as Cert};
    let refused = |reason| Some(TlsFailure::Refused(reason));
    let relay_not_current = |detail| {
        Some(TlsFailure::NotCurrent {
            scope: RELAY_CERTIFICATE_NOT_CURRENT_SCOPE,
            detail,
        })
    };
    match error {
        rustls::Error::InvalidCertificate(reason) => match reason {
            Cert::UnknownIssuer => refused(
                "the relay's certificate was refused: unknown issuer (check credentials.server_ca)",
            ),
            Cert::BadSignature => refused("the relay's certificate was refused: bad signature"),
            Cert::Revoked => refused("the relay's certificate was refused: revoked"),
            Cert::NotValidForName | Cert::NotValidForNameContext { .. } => {
                refused("the relay's certificate was refused: not valid for the relay_url host")
            }
            Cert::InvalidPurpose | Cert::InvalidPurposeContext { .. } => {
                refused("the relay's certificate was refused: not valid for server authentication")
            }
            Cert::Expired | Cert::ExpiredContext { .. } => relay_not_current(
                "the relay's certificate is expired on this host's clock: the relay's certificate needs renewing, or this host's clock is ahead; retrying",
            ),
            Cert::NotValidYet | Cert::NotValidYetContext { .. } => relay_not_current(
                "the relay's certificate is not yet valid on this host's clock: this host's clock is likely behind; retrying",
            ),
            _ => None,
        },
        rustls::Error::AlertReceived(alert) => match alert {
            Alert::UnknownCA => refused(
                "the relay refused this device's certificate: unknown CA (the relay does not trust its issuer)",
            ),
            Alert::BadCertificate => {
                refused("the relay refused this device's certificate: bad certificate")
            }
            Alert::UnsupportedCertificate => {
                refused("the relay refused this device's certificate: unsupported certificate")
            }
            Alert::CertificateRevoked => {
                refused("the relay refused this device's certificate: revoked")
            }
            Alert::CertificateUnknown => {
                refused("the relay refused this device's certificate: certificate unknown")
            }
            Alert::CertificateRequired => {
                refused("the relay refused the connection: a device certificate is required")
            }
            Alert::CertificateExpired => Some(TlsFailure::NotCurrent {
                scope: DEVICE_CERTIFICATE_NOT_CURRENT_SCOPE,
                detail: "the relay refused this device's certificate as expired or not yet valid on the relay's clock",
            }),
            _ => None,
        },
        _ => None,
    }
}

fn sanitize_error(error: &str) -> String {
    // Transport diagnostics are intentionally generic. In particular, do not
    // echo a request URL, Authorization header, certificate, or payload.
    let _ = error;
    "transport failure".to_owned()
}

/// Map a forget-barrier failure detail onto a bounded label.
///
/// Every detail this crate attaches to that scope is a fixed string written
/// here, so the allowlist is exhaustive by construction; anything else stays
/// opaque, exactly as transport details do elsewhere.
fn safe_barrier_detail(detail: &str) -> &'static str {
    match detail {
        "carrier disappeared before barrier completion" => {
            "carrier disappeared before barrier completion"
        }
        "data writer stopped before barrier completion" => {
            "data writer stopped before barrier completion"
        }
        _ => "bounded barrier state failure",
    }
}

fn safe_rotation_detail(detail: &str) -> String {
    // Only expose a closed set of state diagnostics.  Rotation details are
    // otherwise intentionally opaque because transport errors can originate
    // below the protocol boundary.
    let (base, metadata) = detail
        .split_once("; recovery_trigger=")
        .map_or((detail, None), |(base, metadata)| (base, Some(metadata)));
    let safe_base = match base {
        "candidate abort owner decision not received before overlap deadline" => {
            "owner abort decision deadline expired".to_owned()
        }
        "rotation deadline requires retained recovery" => "retained recovery required".to_owned(),
        "rotation state closed" => "rotation reached terminal state".to_owned(),
        "recovery episode deadline expired" => "recovery episode deadline expired".to_owned(),
        "recovery candidate phase deadline expired" => {
            "recovery candidate phase deadline expired".to_owned()
        }
        "control socket closed during retained recovery" => {
            "control socket closed during retained recovery".to_owned()
        }
        _ => "bounded rotation state failure".to_owned(),
    };
    let Some(metadata) = metadata else {
        return safe_base;
    };
    let Some((trigger, metadata)) = metadata.split_once("; recovery_role=") else {
        return safe_base;
    };
    let Some((role, generation)) = metadata.split_once("; recovery_generation=") else {
        return safe_base;
    };
    // An optional bounded attempt number follows the generation when the
    // episode itself was ended by the coordinator.
    let (generation, attempt) = generation
        .split_once("; recovery_attempt=")
        .map_or((generation, None), |(generation, attempt)| {
            (generation, Some(attempt))
        });
    let attempt = match attempt {
        None => None,
        Some(attempt) => match attempt.parse::<u64>() {
            Ok(attempt) if (1..=3).contains(&attempt) => Some(attempt),
            _ => return safe_base,
        },
    };
    let trigger = match trigger {
        "data_writer_failed" | "data_reader_closed" | "data_writer_closed" => trigger,
        _ => return safe_base,
    };
    let role = match role {
        "active"
        | "candidate"
        | "retiring"
        | "pending_candidate"
        | "pending_candidate_close"
        | "recovery_closed"
        | "unknown" => role,
        _ => return safe_base,
    };
    let Ok(generation) = generation.parse::<u64>() else {
        return safe_base;
    };
    let mut message = format!(
        "{safe_base}; recovery_trigger={trigger}; recovery_role={role}; recovery_generation={generation}"
    );
    if let Some(attempt) = attempt {
        message.push_str(&format!("; recovery_attempt={attempt}"));
    }
    message
}

/// Errors returned by the connector API. Display text is safe for CLI JSON;
/// it does not include credentials, payloads, or endpoint query strings.
#[derive(Debug)]
pub enum ClientError {
    Config(RuntimeConfigError),
    Credential(CredentialError),
    Invalid(&'static str),
    Protocol(String),
    Transport {
        scope: &'static str,
        detail: String,
    },
    /// The authenticated relay rejected this session because the exact
    /// tenant/device owner slot is already held.  Callers must stop the
    /// existing owner before starting another session; this is terminal and
    /// never eligible for an automatic reconnect or takeover.
    OwnerBusy,
    /// TLS certificate verification refused, on either side, for a reason no
    /// retry can fix (see `tls_refusal`).  The string is a fixed reason
    /// written by this crate, never peer or certificate content.  Terminal:
    /// `CREDENTIAL_ERROR`, not retryable, and `connect` does not reconnect
    /// after it.
    TlsRefused(&'static str),
    HandshakeTimeout,
    AuthorizationExpired,
    QueueLimit,
    /// The authenticated session cannot retain another OPEN response. This
    /// is terminal for the current session; callers must establish a fresh
    /// session instead of retrying the same request indefinitely.
    OpenRetentionFull,
    Cancelled,
    SupervisorPanicked,
}

impl ClientError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Config(_) => "INVALID_CONFIG",
            Self::Credential(_) => "CREDENTIAL_ERROR",
            Self::Invalid(_) => "INVALID_INVOCATION",
            Self::Protocol(_) => "PROTOCOL_ERROR",
            Self::Transport { .. } => "TRANSPORT_ERROR",
            Self::OwnerBusy => "OWNER_BUSY",
            Self::TlsRefused(_) => "CREDENTIAL_ERROR",
            Self::HandshakeTimeout => "DEADLINE_EXCEEDED",
            Self::AuthorizationExpired => "AUTHORIZATION_STALE",
            Self::QueueLimit | Self::OpenRetentionFull => "RESOURCE_EXHAUSTED",
            Self::Cancelled => "CANCELLED",
            Self::SupervisorPanicked => "SUPERVISOR_FAILED",
        }
    }

    #[must_use]
    pub fn retryable(&self) -> bool {
        matches!(self, Self::Transport { .. } | Self::HandshakeTimeout)
    }

    fn safe_message(&self) -> String {
        match self {
            Self::Config(error) => error.to_string(),
            Self::Credential(error) => error.to_string(),
            Self::Invalid(message) => (*message).to_owned(),
            Self::Protocol(message) => message.clone(),
            Self::Transport { scope, detail }
                if *scope == "data rotation" || *scope == "retained recovery" =>
            {
                format!("{scope} failed: {}", safe_rotation_detail(detail))
            }
            // The forget barrier's details are a closed set this crate writes
            // itself, naming which half of the carrier went away, so they can
            // be surfaced under the same allowlist discipline as rotation
            // details.  Without this the failure reads only as "stream forget
            // barrier failed", which is what made two survey failures in
            // different gates unexplainable.
            Self::Transport { scope, detail } if *scope == "stream forget barrier" => {
                format!("{scope} failed: {}", safe_barrier_detail(detail))
            }
            // Fixed reasons written by `classify_rustls_refusal`, and the one
            // fixed detail of an expired STREAM_FORGET proof.
            Self::Transport { scope, detail }
                if *scope == DEVICE_CERTIFICATE_NOT_CURRENT_SCOPE
                    || *scope == RELAY_CERTIFICATE_NOT_CURRENT_SCOPE
                    || *scope == STREAM_FORGET_PROOF_SCOPE =>
            {
                detail.clone()
            }
            Self::Transport { scope, .. } => format!("{scope} failed"),
            Self::OwnerBusy => {
                "device already has an active owner; stop it before starting another session"
                    .to_owned()
            }
            Self::TlsRefused(reason) => (*reason).to_owned(),
            Self::HandshakeTimeout => "TLS/WebSocket handshake deadline exceeded".to_owned(),
            Self::AuthorizationExpired => AUTHORIZATION_EXPIRED_MESSAGE.to_owned(),
            Self::QueueLimit => "bounded connector queue limit reached".to_owned(),
            Self::OpenRetentionFull => {
                "OPEN idempotency retention is full; start a fresh session".to_owned()
            }
            Self::Cancelled => "connector cancelled".to_owned(),
            Self::SupervisorPanicked => "connector supervisor failed".to_owned(),
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.safe_message())
    }
}

impl Error for ClientError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::Credential(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RuntimeConfigError> for ClientError {
    fn from(error: RuntimeConfigError) -> Self {
        Self::Config(error)
    }
}

#[cfg(test)]
mod barrier_detail_tests {
    use super::{ClientError, safe_barrier_detail};

    #[test]
    fn forget_barrier_failures_name_which_half_went_away() {
        // The two details this crate writes reach the operator intact, so a
        // barrier failure says which half of the carrier went away instead of
        // only that the barrier failed.
        for detail in [
            "carrier disappeared before barrier completion",
            "data writer stopped before barrier completion",
        ] {
            let error = ClientError::Transport {
                scope: "stream forget barrier",
                detail: detail.to_owned(),
            };
            let message = error.safe_message();
            assert!(
                message.contains(detail),
                "barrier failure must name its bounded detail, got {message}"
            );
        }
    }

    #[test]
    fn an_unrecognised_barrier_detail_stays_opaque() {
        // The allowlist is exhaustive for what this crate writes; anything
        // else must not reach the operator, because a transport detail can
        // originate below the protocol boundary.
        assert_eq!(
            safe_barrier_detail("connection refused by 203.0.113.7:4433"),
            "bounded barrier state failure"
        );
        let error = ClientError::Transport {
            scope: "stream forget barrier",
            detail: "connection refused by 203.0.113.7:4433".to_owned(),
        };
        let message = error.safe_message();
        assert!(!message.contains("203.0.113.7"), "detail leaked: {message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_endpoint_replaces_control_path_without_ticket_leak() {
        let control = Url::parse("wss://relay.test/v1/device/control?ignored=1").expect("url");
        assert_eq!(
            data_url_for(&control).as_str(),
            "wss://relay.test/v1/device/data"
        );
    }

    #[test]
    fn configured_echo_advertisement_is_bounded_and_named() {
        let config = RuntimeConfig::default();
        let services = configured_services(&config);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].service_id, "echo");
        assert_eq!(services[0].service_type, "echo");
    }

    #[test]
    fn queue_budget_rejects_over_limit_without_wrapping() {
        let budget = Arc::new(QueueBudget {
            bytes: AtomicUsize::new(0),
            maximum: 4,
        });
        assert!(budget.reserve(5).is_err());
        assert_eq!(budget.bytes.load(Ordering::Acquire), 0);
        budget.reserve(4).expect("exact limit");
        assert!(budget.reserve(1).is_err());
        budget.release(4);
    }

    #[tokio::test]
    async fn try_send_with_deadline_is_bounded_and_preserves_deadline() {
        let cancellation = CancellationToken::new();
        let (queue, mut receiver) = OutboundQueue::new(1, 64, cancellation);
        let deadline = DualDeadline::new(Instant::now(), SystemTime::now(), Duration::from_secs(1))
            .expect("valid deadline");

        queue
            .try_send_with_deadline(Message::Text("first".to_owned().into()), Some(deadline))
            .expect("first bounded enqueue");
        assert!(matches!(
            queue.try_send(Message::Text("second".to_owned().into())),
            Err(ClientError::QueueLimit)
        ));

        let queued = receiver.recv().await.expect("queued message");
        assert!(queued.deadline.is_some());
        drop(queued);
        queue
            .try_send(Message::Text("second".to_owned().into()))
            .expect("budget released after dequeue");
    }

    #[tokio::test]
    async fn concurrent_stop_waits_for_existing_supervisor_join() {
        let cancellation = CancellationToken::new();
        let (readiness_tx, readiness_rx) = watch::channel(Readiness::Connecting);
        let (status_tx, status_rx) = watch::channel(ConnectionStatus::default());
        drop(readiness_tx);
        drop(status_tx);

        let release = Arc::new(tokio::sync::Notify::new());
        let supervisor_release = release.clone();
        let join = tokio::spawn(async move {
            supervisor_release.notified().await;
            Ok(())
        });
        let lifecycle = Arc::new(ConnectionLifecycle {
            cancellation,
            join: Mutex::new(Some(join)),
        });
        let handle = ConnectionHandle {
            readiness: readiness_rx,
            status: status_rx,
            lifecycle: lifecycle.clone(),
        };

        let first_handle = handle.clone();
        let first = tokio::spawn(async move { first_handle.stop().await });
        let mut first_holds_join_lock = false;
        for _ in 0..1_000 {
            if lifecycle.join.try_lock().is_err() {
                first_holds_join_lock = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(first_holds_join_lock, "first stop did not begin joining");

        let second_handle = handle.clone();
        let mut second = tokio::spawn(async move { second_handle.stop().await });
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut second)
                .await
                .is_err(),
            "concurrent stop returned before the supervisor completed"
        );

        release.notify_one();
        assert!(first.await.expect("first stop task").is_ok());
        assert!(second.await.expect("second stop task").is_ok());
    }

    #[tokio::test]
    async fn cancelled_stop_keeps_supervisor_join_for_next_caller() {
        let cancellation = CancellationToken::new();
        let (readiness_tx, readiness_rx) = watch::channel(Readiness::Connecting);
        let (status_tx, status_rx) = watch::channel(ConnectionStatus::default());
        drop(readiness_tx);
        drop(status_tx);

        let release = Arc::new(tokio::sync::Notify::new());
        let supervisor_release = release.clone();
        let join = tokio::spawn(async move {
            supervisor_release.notified().await;
            Ok(())
        });
        let lifecycle = Arc::new(ConnectionLifecycle {
            cancellation,
            join: Mutex::new(Some(join)),
        });
        let handle = ConnectionHandle {
            readiness: readiness_rx,
            status: status_rx,
            lifecycle: lifecycle.clone(),
        };

        let first_handle = handle.clone();
        let first = tokio::spawn(async move { first_handle.stop().await });
        let mut first_holds_join_lock = false;
        for _ in 0..1_000 {
            if lifecycle.join.try_lock().is_err() {
                first_holds_join_lock = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(first_holds_join_lock, "first stop did not begin joining");

        first.abort();
        let first_error = first.await.expect_err("first stop should be cancelled");
        assert!(first_error.is_cancelled());

        let second_handle = handle.clone();
        let mut second = tokio::spawn(async move { second_handle.stop().await });
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut second)
                .await
                .is_err(),
            "replacement stop returned before the supervisor completed"
        );

        release.notify_one();
        assert!(second.await.expect("replacement stop task").is_ok());
    }

    #[test]
    fn authorization_replay_cannot_extend_first_short_deadline() {
        let started = Instant::now();
        let started_wall = SystemTime::now();
        let first = DualDeadline::new(started, started_wall, Duration::from_millis(5_000))
            .expect("valid first grant")
            .shorten(Duration::from_millis(100))
            .expect("valid short grant");
        let replay = first
            .shorten(Duration::from_millis(5_000))
            .expect("valid replay lifetime");
        assert_eq!(replay.monotonic, first.monotonic);
        assert_eq!(replay.wall, first.wall);
    }

    #[test]
    fn authorization_wall_clock_expiry_fails_closed_when_monotonic_is_unchanged() {
        let started = Instant::now();
        let started_wall = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let deadline = DualDeadline::new(started, started_wall, Duration::from_secs(5))
            .expect("valid deadline");
        assert!(deadline.expired_at(started, started_wall + Duration::from_secs(6)));
    }

    #[test]
    fn authorization_wall_clock_reversal_fails_closed() {
        let started = Instant::now();
        let started_wall = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let deadline = DualDeadline::new(started, started_wall, Duration::from_secs(5))
            .expect("valid deadline");
        assert!(deadline.expired_at(started, started_wall - Duration::from_secs(1)));
    }

    #[test]
    fn reset_requires_the_next_receive_sequence_and_single_terminal_event() {
        assert!(terminal_sequence_valid(4, 5, false));
        assert!(!terminal_sequence_valid(4, 4, false));
        assert!(!terminal_sequence_valid(4, 6, false));
        assert!(!terminal_sequence_valid(4, 5, true));
    }

    #[test]
    fn outbound_sequence_reservation_happens_before_queue_deadline_race() {
        assert_eq!(reserve_outbound_sequences(4, 2), Some((5, 6)));
        assert_eq!(reserve_outbound_sequences(u64::MAX, 1), None);
        assert_eq!(reserve_outbound_sequences(9, 0), Some((9, 9)));
    }

    #[test]
    fn owner_busy_is_typed_actionable_and_non_retryable() {
        let error = ClientError::OwnerBusy;
        assert_eq!(error.code(), "OWNER_BUSY");
        assert!(!error.retryable());
        assert_eq!(
            error.to_string(),
            "device already has an active owner; stop it before starting another session"
        );
        assert!(!error.to_string().contains("token"));
        assert!(!error.to_string().contains("redis"));
    }

    #[test]
    fn only_the_authenticated_owner_busy_close_is_classified() {
        let owner_busy = CloseFrame {
            code: CloseCode::from(CONTROL_OWNER_BUSY_CLOSE_CODE),
            reason: CONTROL_OWNER_BUSY_CLOSE_REASON.into(),
        };
        assert!(matches!(
            classify_initial_control_close(&owner_busy),
            Some(ClientError::OwnerBusy)
        ));

        let wrong_reason = CloseFrame {
            code: owner_busy.code,
            reason: "backend owner still live".into(),
        };
        assert!(classify_initial_control_close(&wrong_reason).is_none());

        let wrong_code = CloseFrame {
            code: CloseCode::Error,
            reason: CONTROL_OWNER_BUSY_CLOSE_REASON.into(),
        };
        assert!(classify_initial_control_close(&wrong_code).is_none());
    }

    /// M6-C32: the relay's identity refusal is terminal and a credential
    /// fault, never a retryable transport loss.
    #[test]
    fn an_identity_rejected_close_is_a_non_retryable_credential_error() {
        let rejected = CloseFrame {
            code: CloseCode::from(CONTROL_IDENTITY_REJECTED_CLOSE_CODE),
            reason: CONTROL_IDENTITY_REJECTED_CLOSE_REASON.into(),
        };
        let error = classify_initial_control_close(&rejected).expect("classified");
        assert!(matches!(
            error,
            ClientError::Credential(CredentialError::RelayRefusedIdentity)
        ));
        assert_eq!(error.code(), "CREDENTIAL_ERROR");
        assert!(!error.retryable());
        assert!(error.to_string().contains("device_id"));

        let wrong_reason = CloseFrame {
            code: rejected.code,
            reason: "catalog lookup failed".into(),
        };
        assert!(classify_initial_control_close(&wrong_reason).is_none());
    }

    /// M6-C38: the relay's protocol-major refusal is a terminal protocol
    /// error naming the cause, never a retryable transport loss; a close
    /// with the right code and another reason is not classified.
    #[test]
    fn a_protocol_unsupported_close_is_a_non_retryable_protocol_error() {
        let refused = CloseFrame {
            code: CloseCode::from(CONTROL_PROTOCOL_UNSUPPORTED_CLOSE_CODE),
            reason: CONTROL_PROTOCOL_UNSUPPORTED_CLOSE_REASON.into(),
        };
        let error = classify_initial_control_close(&refused).expect("classified");
        assert!(matches!(error, ClientError::Protocol(_)), "{error:?}");
        assert_eq!(error.code(), "PROTOCOL_ERROR");
        assert!(!error.retryable());
        let message = error.to_string();
        assert!(message.contains("protocol major 1"), "{message}");
        assert!(message.contains("PROTOCOL_UNSUPPORTED"), "{message}");

        let wrong_reason = CloseFrame {
            code: refused.code,
            reason: "protocol error".into(),
        };
        assert!(classify_initial_control_close(&wrong_reason).is_none());
    }

    #[test]
    fn echo_canary_output_splits_a_64kib_input_into_bounded_frames() {
        let input_len = 65_536;
        let canary_len = 256;
        let output_len = checked_echo_output_len(canary_len, input_len).expect("bounded length");
        assert_eq!(output_len, input_len + canary_len);
        assert!(output_len > MAX_PAYLOAD_LEN);
        assert_eq!(output_len.div_ceil(MAX_PAYLOAD_LEN), 2);
        assert!(checked_echo_output_len(usize::MAX, 1).is_none());
    }

    #[tokio::test]
    async fn cancellation_wins_when_writer_failure_is_already_ready() {
        let cancellation = CancellationToken::new();
        let (failure_tx, mut failure_rx) = mpsc::channel(1);
        cancellation.cancel();
        failure_tx
            .send(WriterFailure(WriterKind::Data))
            .await
            .expect("failure receiver remains available");

        let result = tokio::select! {
            biased;
            _ = cancellation.cancelled() => Ok(()),
            failure = failure_rx.recv() => writer_failure_result(
                cancellation.is_cancelled(),
                failure.map(|failure| failure.0),
            ),
        };

        assert!(result.is_ok());
        assert_eq!(
            writer_failure_result(false, Some(WriterKind::Data))
                .unwrap_err()
                .code(),
            "TRANSPORT_ERROR"
        );
    }
}
