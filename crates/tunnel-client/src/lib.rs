//! M1 connector library.
//!
//! A connector establishes exactly one mutually authenticated control WSS and
//! one mutually authenticated data WSS for a session. M1 deliberately has no
//! scheduled data rotation, resume/replay, or reconnect loop: any transport
//! failure closes the pair and the caller must start a fresh session. This
//! keeps application side effects from being replayed while the retained
//! stream state needed by M2 is still being designed.

#![forbid(unsafe_code)]

mod config;
pub mod credentials;

use config::{ExportConfig, ExportKind, RuntimeConfig};
use credentials::{CredentialError, load_client_config};
use futures_util::{SinkExt, StreamExt};
use std::{
    collections::{BTreeMap, VecDeque},
    error::Error,
    fmt,
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
    tungstenite::{Message, client::IntoClientRequest, http::HeaderValue},
};
use tokio_util::sync::CancellationToken;
use tunnel_protocol::{
    AuthorizationChallenge, AuthorizationConfirmed, AuthorizationInvalidated, Cancel,
    ControlMessage, DataReady, Frame, FrameKind, Hello, MAX_CONTROL_MESSAGE_BYTES, MAX_FRAME_LEN,
    MAX_PAYLOAD_LEN, Open, Opened, Ping, Pong, Rejected, ServiceAdvertisement, Welcome,
    decode_control, encode_control,
};
use url::Url;
use uuid::Uuid;

pub use config::{
    CredentialConfig, ExportConfig as LocalExport, ExportKind as LocalExportKind, LimitsConfig,
    RuntimeConfig as ConnectConfig, RuntimeConfigError,
};
pub use credentials::{CsrOutput, ImportedCredential};
pub use tokio_util::sync::CancellationToken as ConnectCancellation;

/// The M1 failure policy. A later caller can explicitly create a fresh
/// session; the library never reconnects or replays an operation itself.
pub const M1_TRANSPORT_FAILURE_POLICY: &str =
    "close control and data and require a fresh session; no retained replay or automatic reconnect";

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

type ClientWebSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
type ClientStream = futures_util::stream::SplitStream<ClientWebSocket>;
type ClientSink = futures_util::stream::SplitSink<ClientWebSocket, Message>;
type SupervisorJoin = JoinHandle<Result<(), ClientError>>;

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
}

impl ConnectOptions {
    #[must_use]
    pub fn new(config: RuntimeConfig) -> Self {
        Self {
            config,
            cancellation: CancellationToken::new(),
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
    lifecycle: Arc<ConnectionLifecycle>,
}

impl fmt::Debug for ConnectionHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionHandle")
            .field("readiness", &*self.readiness.borrow())
            .finish_non_exhaustive()
    }
}

impl ConnectionHandle {
    /// Subscribe to lifecycle changes without exposing payloads or secrets.
    #[must_use]
    pub fn readiness(&self) -> watch::Receiver<Readiness> {
        self.readiness.clone()
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
        let join = self.lifecycle.join.lock().await.take();
        match join {
            Some(join) => join
                .await
                .map_err(|_| ClientError::SupervisorPanicked)?
                .map(|_| ()),
            None => Ok(()),
        }
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

/// Connect the control/data pair, perform HELLO/WELCOME and DATA_READY, then
/// return a handle for the running session actor.
pub async fn connect(options: ConnectOptions) -> Result<ConnectionHandle, ClientError> {
    options.config.validate()?;
    if options.cancellation.is_cancelled() {
        return Err(ClientError::Cancelled);
    }
    let tls = load_client_config(&options.config.credentials).map_err(ClientError::Credential)?;
    let control_url = Url::parse(&options.config.relay_url)
        .map_err(|_| ClientError::Invalid("relay_url is not a valid URL"))?;
    let (readiness_tx, readiness_rx) = watch::channel(Readiness::Connecting);

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
            .map_err(|error| ClientError::Transport {
                scope: "websocket handshake",
                detail: sanitize_error(&error.to_string()),
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
    ));
    let data_writer = tokio::spawn(writer_loop(
        WriterKind::Data,
        data_sink,
        data_receiver,
        writer_failure_tx,
        cancellation.clone(),
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

fn sanitize_error(error: &str) -> String {
    // Transport diagnostics are intentionally generic. In particular, do not
    // echo a request URL, Authorization header, certificate, or payload.
    let _ = error;
    "transport failure".to_owned()
}

/// Errors returned by the connector API. Display text is safe for CLI JSON;
/// it does not include credentials, payloads, or endpoint query strings.
#[derive(Debug)]
pub enum ClientError {
    Config(RuntimeConfigError),
    Credential(CredentialError),
    Invalid(&'static str),
    Protocol(String),
    Transport { scope: &'static str, detail: String },
    HandshakeTimeout,
    AuthorizationExpired,
    QueueLimit,
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
            Self::HandshakeTimeout => "DEADLINE_EXCEEDED",
            Self::AuthorizationExpired => "AUTHORIZATION_STALE",
            Self::QueueLimit => "RESOURCE_EXHAUSTED",
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
            Self::Transport { scope, .. } => format!("{scope} failed"),
            Self::HandshakeTimeout => "TLS/WebSocket handshake deadline exceeded".to_owned(),
            Self::AuthorizationExpired => "authorization confirmation deadline expired".to_owned(),
            Self::QueueLimit => "bounded connector queue limit reached".to_owned(),
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
