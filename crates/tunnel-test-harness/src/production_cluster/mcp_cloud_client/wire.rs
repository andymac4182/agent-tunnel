//! Consumer and device-host plumbing for the M3-03 gate.
//!
//! * [`Sidecar`]: a local Unix-socket front for the official rmcp Streamable
//!   HTTP client.  rmcp 3.4.0 ships a Unix-socket HTTP client (for sidecar
//!   proxies) but no TLS client without reqwest, which the workspace does not
//!   pin.  The sidecar only adds TLS: it copies each accepted connection's
//!   bytes, unchanged and in both directions, to one fresh TLS connection to
//!   the ingress relay, and closes both sides when either ends.  It never
//!   parses HTTP, so every header, body byte and disconnect the relay sees is
//!   rmcp's own.
//! * [`CountingHttpClient`]: rmcp's [`UnixSocketHttpClient`] decorated with
//!   a payload-free [`WireLedger`].  Every call is delegated unchanged; the
//!   ledger only counts POSTs by JSON-RPC method, responses by call, legacy
//!   session headers, standalone streams and where log notifications
//!   arrived.
//! * [`HttpBackend`]: the synthetic rmcp Streamable HTTP server as its own
//!   process on a fixed loopback port, so a `crash` tool ends that process
//!   and nothing else.
//!
//! All data is synthetic.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use futures_util::stream::BoxStream;
use http::{HeaderName, HeaderValue};
use rmcp::model::{ClientJsonRpcMessage, ProgressNotificationParam, ProtocolVersion};
use rmcp::service::NotificationContext;
use rmcp::transport::UnixSocketHttpClient;
use rmcp::transport::streamable_http_client::{
    SseError, StreamableHttpClient, StreamableHttpError, StreamableHttpPostResponse,
};
use rmcp::{ClientHandler, RoleClient};
use rustls::pki_types::{CertificateDer, ServerName};
use sse_stream::Sse;
use tokio::sync::Notify;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use crate::{HarnessError, Result};

/// The smallest retry hint the relay sends with a retryable refusal
/// (`OWNER_NOT_READY_RETRY_AFTER_MS`), and so the shortest wait between two
/// resends of one request.
pub(super) const MIN_RETRY_HINT_MS: u64 = 250;
/// Margin over the derived cap: a drain can be slower than its budget on a
/// loaded machine, and a refusal may land just before the freeze starts.
pub(super) const RETRY_MARGIN: u64 = 4;
/// How many times one POST or standalone GET is sent again after a
/// retryable `not_dispatched` refusal that coincided with a rotation
/// freeze.
///
/// A freeze ends when the attempt commits or its handshake budget expires,
/// so the cap covers that budget at the smallest hint, plus the margin.
/// Deriving it from the gate's own rotation policy keeps a slow-but-legal
/// drain from failing a call; the evidence validator bounds it again with
/// the same expression.
pub(super) const NOT_DISPATCHED_RETRIES: u64 =
    (super::MCP_GATE_ROTATION.handshake_timeout_seconds * 1_000).div_ceil(MIN_RETRY_HINT_MS)
        + RETRY_MARGIN;
/// The longest retry hint honoured.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(1);
/// How long after the last observed frozen owner sample a refusal still
/// counts as coinciding with that freeze.
const FREEZE_COINCIDENCE: Duration = Duration::from_millis(750);

/// Whether the owner session is, or has just been, in a rotation freeze.
///
/// The relay answers every owner-not-ready condition with the same
/// retryable `503 PEER_UNAVAILABLE` `not_dispatched` body (`http.rs`
/// `retryable_peer_failure_response`), so the body alone cannot say whether
/// the refusal came from the documented quiesce-admission pause or from a
/// fault state.  The gate samples the owner's session phase instead and
/// resends only while that says a rotation is frozen.
#[derive(Debug, Default)]
pub(super) struct FreezeWatch {
    frozen: AtomicBool,
    /// Whether any frozen sample was ever recorded.
    seen_frozen: AtomicBool,
    /// Milliseconds since the watch started, at the last frozen sample.
    last_frozen_ms: AtomicU64,
    started: Mutex<Option<Instant>>,
    /// The connector's last observed rotation phase and completed rotation
    /// count, for a refusal that did not coincide with a freeze.
    phase: Mutex<String>,
    rotations_completed: AtomicU64,
}

impl FreezeWatch {
    /// Record one connector status sample: its rotation phase and completed
    /// rotation count.
    pub fn record(&self, phase: &str, rotations_completed: u64) {
        let frozen = FROZEN_PHASES.contains(&phase);
        let mut started = self
            .started
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let started = *started.get_or_insert_with(Instant::now);
        self.frozen.store(frozen, Ordering::SeqCst);
        self.rotations_completed
            .store(rotations_completed, Ordering::SeqCst);
        phase.clone_into(
            &mut self
                .phase
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        if frozen {
            self.seen_frozen.store(true, Ordering::SeqCst);
            self.last_frozen_ms.store(
                u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                Ordering::SeqCst,
            );
        }
    }

    /// Why a refusal was not attributed to a freeze: the connector state at
    /// the moment it was observed.  The owner freezes before the connector
    /// sees `ROTATE_QUIESCE`, so a refusal can land in that head gap.
    fn unexplained(&self) -> String {
        let phase = self
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let since_frozen = {
            let started = self
                .started
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            started.map(|started| {
                u64::try_from(started.elapsed().as_millis())
                    .unwrap_or(u64::MAX)
                    .saturating_sub(self.last_frozen_ms.load(Ordering::SeqCst))
            })
        };
        let since_frozen = if self.seen_frozen.load(Ordering::SeqCst) {
            since_frozen
        } else {
            None
        };
        format!(
            "not_dispatched refusal outside a rotation freeze: connector phase={phase:?} rotations_completed={} ms_since_last_freeze={since_frozen:?}",
            self.rotations_completed.load(Ordering::SeqCst),
        )
    }

    /// Whether a refusal observed now coincides with a rotation freeze.
    fn coincides(&self) -> bool {
        if self.frozen.load(Ordering::SeqCst) {
            return true;
        }
        let started = {
            let started = self
                .started
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *started
        };
        let Some(started) = started else {
            return false;
        };
        if !self.seen_frozen.load(Ordering::SeqCst) {
            return false;
        }
        let last = self.last_frozen_ms.load(Ordering::SeqCst);
        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
            <= last + FREEZE_COINCIDENCE.as_millis() as u64
    }
}

/// The retry hint of a retryable `not_dispatched` 503 relay refusal, or
/// `None` for any other failure.  Only such a refusal may be resent: the
/// relay states nothing was dispatched.
fn not_dispatched_retry_after(
    error: &StreamableHttpError<rmcp::transport::common::unix_socket::UnixSocketError>,
) -> Option<Duration> {
    let StreamableHttpError::UnexpectedServerResponse(text) = error else {
        return None;
    };
    let body = text.strip_prefix("HTTP 503 Service Unavailable: ")?;
    let value = serde_json::from_str::<serde_json::Value>(body).ok()?;
    (value["execution"] == "not_dispatched" && value["retryable"] == true).then(|| {
        Duration::from_millis(value["retry_after_ms"].as_u64().unwrap_or(250)).min(MAX_RETRY_AFTER)
    })
}

/// The connector rotation phases in which the owner pauses new stream
/// admission (docs/protocol.md, "Quiesce admission").
pub(super) const FROZEN_PHASES: [&str; 3] = ["quiescing", "draining", "committing"];

/// rmcp's default SSE event bound, restated because its constant is private.
const MAX_SSE_EVENT_BYTES: usize = 16 * 1024 * 1024;
const POLL: Duration = Duration::from_millis(20);

// ---------------------------------------------------------------------------
// Sidecar.

/// The TLS sidecar in front of the ingress relay.
pub(super) struct Sidecar {
    pub socket: PathBuf,
    connections: Arc<AtomicU64>,
    shutdown: CancellationToken,
    _directory: tempfile::TempDir,
}

impl Drop for Sidecar {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl Sidecar {
    /// Listen on a fresh Unix socket and forward every connection to
    /// `target` over TLS trusting only `ca_der`.
    pub fn start(target: SocketAddr, ca_der: &[u8]) -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca_der.to_vec()))
            .map_err(|error| HarnessError::Http(format!("sidecar CA: {error}")))?;
        let config = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| HarnessError::Http(format!("sidecar TLS: {error}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let directory = tempfile::Builder::new()
            .prefix("m3mcp")
            .tempdir()
            .map_err(HarnessError::Io)?;
        let socket = directory.path().join("s.sock");
        let listener = tokio::net::UnixListener::bind(&socket).map_err(HarnessError::Io)?;
        let shutdown = CancellationToken::new();
        let connections = Arc::new(AtomicU64::new(0));
        let stop = shutdown.clone();
        let counter = Arc::clone(&connections);
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    () = stop.cancelled() => return,
                    accepted = listener.accept() => accepted,
                };
                let Ok((local, _)) = accepted else { return };
                counter.fetch_add(1, Ordering::SeqCst);
                let connector = connector.clone();
                let stop = stop.clone();
                tokio::spawn(async move {
                    let Ok(tcp) = tokio::net::TcpStream::connect(target).await else {
                        return;
                    };
                    let Ok(name) = ServerName::try_from("localhost".to_owned()) else {
                        return;
                    };
                    let Ok(remote) = connector.connect(name, tcp).await else {
                        return;
                    };
                    let (mut local_read, mut local_write) = tokio::io::split(local);
                    let (mut remote_read, mut remote_write) = tokio::io::split(remote);
                    // Whichever side ends first ends the connection: a client
                    // that drops its response is a disconnect at the relay.
                    tokio::select! {
                        _ = tokio::io::copy(&mut local_read, &mut remote_write) => {}
                        _ = tokio::io::copy(&mut remote_read, &mut local_write) => {}
                        () = stop.cancelled() => {}
                    }
                });
            }
        });
        Ok(Self {
            socket,
            connections,
            shutdown,
            _directory: directory,
        })
    }

    pub fn connections(&self) -> u64 {
        self.connections.load(Ordering::SeqCst)
    }
}

/// Lowercase hex of a digest.
pub(super) fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A bounded SSE reconnection policy: three attempts 250 ms apart.
#[derive(Debug)]
pub(super) struct BoundedRetry;

impl rmcp::transport::common::client_side_sse::SseRetryPolicy for BoundedRetry {
    fn retry(&self, current_times: usize) -> Option<Duration> {
        (current_times < 3).then_some(Duration::from_millis(250))
    }
}

// ---------------------------------------------------------------------------
// Wire ledger.

/// Payload-free counts of one client's HTTP traffic.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WireCounts {
    /// POSTed JSON-RPC requests and notifications by method (`tools/call`
    /// as `tools/call:<tool>`); client responses as `response`.
    pub posts: BTreeMap<String, u64>,
    /// JSON-RPC results received, by the call they answer.
    pub results: BTreeMap<String, u64>,
    /// JSON-RPC errors received, by the call they answer.
    pub errors: BTreeMap<String, u64>,
    /// POSTs that failed at the transport (other than an expired session).
    pub post_failures: u64,
    /// POSTs the relay refused with a retryable `503 PEER_UNAVAILABLE`
    /// `not_dispatched` answer.
    pub not_dispatched_refusals: u64,
    /// Those refusals that coincided with an observed owner rotation freeze
    /// and were therefore sent again after the hint.  A refusal outside a
    /// freeze is never resent, so it fails its call.
    pub not_dispatched_retries: u64,
    /// The connector state at the first refusal that did not coincide with
    /// a freeze, so a failure names its cause.
    pub unexplained_refusal: Option<String>,
    /// Standalone GETs refused with 503 and sent again.
    pub standalone_retries: u64,
    /// POSTs answered 404 for an attached legacy session.
    pub session_expired: u64,
    /// POST responses carrying `Mcp-Session-Id`.
    pub session_headers: u64,
    /// Standalone GET streams opened for a legacy session.
    pub standalone_opened: u64,
    /// Standalone GET attempts refused for any reason.
    pub standalone_refused: u64,
    /// Standalone GET attempts the relay refused with 503.
    pub standalone_not_dispatched_refusals: u64,
    /// GET attempts without a session (stateless response resumption).
    pub resume_attempts: u64,
    /// The `seq` field of each `notifications/message` log in wire arrival
    /// order, across every stream of the client.
    pub log_seqs: Vec<u64>,
    /// `notifications/message` events on POST response streams.
    pub logs_on_request_streams: u64,
    /// `notifications/message` events on standalone GET streams.
    pub logs_on_standalone_streams: u64,
    /// Legacy session DELETEs.
    pub deletes: u64,
    /// Progress notification values in wire arrival order, across every
    /// stream of the client.
    pub progress_values: Vec<u64>,
    /// SHA-256 over each progress message and a newline, in wire arrival
    /// order (hex).  A digest, never the messages.
    pub progress_digest: String,
    /// The first transport failure's status line and sanitized gateway
    /// code, truncated (diagnostics only).
    pub first_failure: Option<String>,
}

impl WireCounts {
    pub fn post(&self, key: &str) -> u64 {
        self.posts.get(key).copied().unwrap_or(0)
    }

    pub fn result(&self, key: &str) -> u64 {
        self.results.get(key).copied().unwrap_or(0)
    }

    pub fn error(&self, key: &str) -> u64 {
        self.errors.get(key).copied().unwrap_or(0)
    }
}

#[derive(Default)]
struct LedgerInner {
    counts: WireCounts,
    digest: sha2::Sha256,
    /// JSON-RPC request ID → call key.  IDs never leave this process.
    outstanding: HashMap<String, String>,
}

/// The shared ledger of one client.
#[derive(Default)]
pub struct WireLedger {
    inner: Mutex<LedgerInner>,
}

impl std::fmt::Debug for WireLedger {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("WireLedger").finish_non_exhaustive()
    }
}

fn call_key(value: &serde_json::Value) -> Option<String> {
    let method = value.get("method")?.as_str()?;
    if method == "tools/call" {
        let tool = value
            .get("params")
            .and_then(|params| params.get("name"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("?");
        Some(format!("tools/call:{tool}"))
    } else {
        Some(method.to_owned())
    }
}

impl WireLedger {
    fn with<T>(&self, update: impl FnOnce(&mut LedgerInner) -> T) -> T {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        update(&mut inner)
    }

    pub fn counts(&self) -> WireCounts {
        use sha2::Digest;
        self.with(|inner| {
            let mut counts = inner.counts.clone();
            counts.progress_digest = hex_digest(&inner.digest.clone().finalize());
            counts
        })
    }

    fn note_post(&self, message: &ClientJsonRpcMessage) {
        let Ok(value) = serde_json::to_value(message) else {
            return;
        };
        self.with(|inner| {
            let key = call_key(&value).unwrap_or_else(|| "response".to_owned());
            *inner.counts.posts.entry(key.clone()).or_default() += 1;
            if let Some(id) = value.get("id")
                && value.get("method").is_some()
            {
                inner.outstanding.insert(id.to_string(), key);
            }
        });
    }

    fn observe(&self, data: &str, standalone: bool) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(data) else {
            return;
        };
        self.with(|inner| {
            if let Some(method) = value.get("method").and_then(serde_json::Value::as_str) {
                if method == "notifications/progress" {
                    use sha2::Digest;
                    let params = &value["params"];
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    inner
                        .counts
                        .progress_values
                        .push(params["progress"].as_f64().unwrap_or(-1.0) as u64);
                    if let Some(message) = params["message"].as_str() {
                        inner.digest.update(message.as_bytes());
                        inner.digest.update(b"\n");
                    }
                }
                if value.get("id").is_none() && method == "notifications/message" {
                    if let Some(seq) = value["params"]["data"]["seq"].as_u64() {
                        inner.counts.log_seqs.push(seq);
                    }
                    if standalone {
                        inner.counts.logs_on_standalone_streams += 1;
                    } else {
                        inner.counts.logs_on_request_streams += 1;
                    }
                }
                return;
            }
            let Some(id) = value.get("id") else { return };
            let key = inner
                .outstanding
                .remove(&id.to_string())
                .unwrap_or_else(|| "unknown".to_owned());
            if value.get("error").is_some() {
                *inner.counts.errors.entry(key).or_default() += 1;
            } else if value.get("result").is_some() {
                *inner.counts.results.entry(key).or_default() += 1;
            }
        });
    }

    fn wrap(
        self: &Arc<Self>,
        stream: BoxStream<'static, std::result::Result<Sse, SseError>>,
        standalone: bool,
    ) -> BoxStream<'static, std::result::Result<Sse, SseError>> {
        let ledger = Arc::clone(self);
        stream
            .inspect(move |item| {
                if let Ok(event) = item
                    && let Some(data) = &event.data
                {
                    ledger.observe(data, standalone);
                }
            })
            .boxed()
    }
}

/// rmcp's Unix-socket client with a payload-free ledger.
#[derive(Clone)]
pub(super) struct CountingHttpClient {
    inner: UnixSocketHttpClient,
    ledger: Arc<WireLedger>,
    freeze: Arc<FreezeWatch>,
}

impl CountingHttpClient {
    pub fn new(
        inner: UnixSocketHttpClient,
        ledger: Arc<WireLedger>,
        freeze: Arc<FreezeWatch>,
    ) -> Self {
        Self {
            inner,
            ledger,
            freeze,
        }
    }

    fn observe_post(
        &self,
        result: std::result::Result<
            StreamableHttpPostResponse,
            StreamableHttpError<rmcp::transport::common::unix_socket::UnixSocketError>,
        >,
    ) -> std::result::Result<
        StreamableHttpPostResponse,
        StreamableHttpError<rmcp::transport::common::unix_socket::UnixSocketError>,
    > {
        match result {
            Ok(StreamableHttpPostResponse::Json(message, session)) => {
                if session.is_some() {
                    self.ledger.with(|inner| inner.counts.session_headers += 1);
                }
                if let Ok(text) = serde_json::to_string(&message) {
                    self.ledger.observe(&text, false);
                }
                Ok(StreamableHttpPostResponse::Json(message, session))
            }
            Ok(StreamableHttpPostResponse::Sse(stream, session)) => {
                if session.is_some() {
                    self.ledger.with(|inner| inner.counts.session_headers += 1);
                }
                Ok(StreamableHttpPostResponse::Sse(
                    self.ledger.wrap(stream, false),
                    session,
                ))
            }
            Ok(other) => Ok(other),
            Err(StreamableHttpError::SessionExpired) => {
                self.ledger.with(|inner| inner.counts.session_expired += 1);
                Err(StreamableHttpError::SessionExpired)
            }
            Err(error) => {
                let summary = error.to_string().chars().take(200).collect::<String>();
                self.ledger.with(|inner| {
                    inner.counts.post_failures += 1;
                    inner.counts.first_failure.get_or_insert(summary);
                });
                Err(error)
            }
        }
    }
}

impl StreamableHttpClient for CountingHttpClient {
    type Error = rmcp::transport::common::unix_socket::UnixSocketError;

    async fn post_message(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> std::result::Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        self.post_message_with_max_sse_event_size(
            uri,
            message,
            session_id,
            auth_header,
            custom_headers,
            MAX_SSE_EVENT_BYTES,
        )
        .await
    }

    async fn post_message_with_max_sse_event_size(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
        max_sse_event_size: usize,
    ) -> std::result::Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        self.ledger.note_post(&message);
        let mut retries = 0;
        loop {
            let result = self
                .inner
                .post_message_with_max_sse_event_size(
                    Arc::clone(&uri),
                    message.clone(),
                    session_id.clone(),
                    auth_header.clone(),
                    custom_headers.clone(),
                    max_sse_event_size,
                )
                .await;
            if let Err(error) = &result
                && let Some(delay) = not_dispatched_retry_after(error)
            {
                let coincides = self.freeze.coincides();
                let cause = (!coincides).then(|| self.freeze.unexplained());
                self.ledger.with(|inner| {
                    inner.counts.not_dispatched_refusals += 1;
                    if coincides {
                        inner.counts.not_dispatched_retries += 1;
                    } else if let Some(cause) = cause {
                        inner.counts.unexplained_refusal.get_or_insert(cause);
                    }
                });
                if coincides && retries < NOT_DISPATCHED_RETRIES {
                    retries += 1;
                    sleep(delay).await;
                    continue;
                }
            }
            return self.observe_post(result);
        }
    }

    async fn delete_session(
        &self,
        uri: Arc<str>,
        session_id: Arc<str>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> std::result::Result<(), StreamableHttpError<Self::Error>> {
        self.ledger.with(|inner| inner.counts.deletes += 1);
        self.inner
            .delete_session(uri, session_id, auth_header, custom_headers)
            .await
    }

    async fn get_stream(
        &self,
        uri: Arc<str>,
        session_id: Option<Arc<str>>,
        last_event_id: Option<String>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> std::result::Result<
        BoxStream<'static, std::result::Result<Sse, SseError>>,
        StreamableHttpError<Self::Error>,
    > {
        self.get_stream_with_max_sse_event_size(
            uri,
            session_id,
            last_event_id,
            auth_header,
            custom_headers,
            MAX_SSE_EVENT_BYTES,
        )
        .await
    }

    async fn get_stream_with_max_sse_event_size(
        &self,
        uri: Arc<str>,
        session_id: Option<Arc<str>>,
        last_event_id: Option<String>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
        max_sse_event_size: usize,
    ) -> std::result::Result<
        BoxStream<'static, std::result::Result<Sse, SseError>>,
        StreamableHttpError<Self::Error>,
    > {
        let standalone = session_id.is_some();
        if !standalone {
            self.ledger.with(|inner| inner.counts.resume_attempts += 1);
        }
        let mut retries = 0;
        let result = loop {
            let result = self
                .inner
                .get_stream_with_max_sse_event_size(
                    Arc::clone(&uri),
                    session_id.clone(),
                    last_event_id.clone(),
                    auth_header.clone(),
                    custom_headers.clone(),
                    max_sse_event_size,
                )
                .await;
            // A GET refusal carries no body to inspect; a standalone stream
            // dispatches nothing, so a 503 is resent within the same bound
            // while the owner is frozen.
            let refused = standalone
                && matches!(
                    &result,
                    Err(StreamableHttpError::UnexpectedServerResponse(text))
                        if text.as_ref() == "get_stream returned 503 Service Unavailable"
                );
            if refused {
                let coincides = self.freeze.coincides();
                let cause = (!coincides).then(|| self.freeze.unexplained());
                self.ledger.with(|inner| {
                    inner.counts.standalone_not_dispatched_refusals += 1;
                    if coincides {
                        inner.counts.standalone_retries += 1;
                    } else if let Some(cause) = cause {
                        inner.counts.unexplained_refusal.get_or_insert(cause);
                    }
                });
                if coincides && retries < NOT_DISPATCHED_RETRIES {
                    retries += 1;
                    sleep(Duration::from_millis(MIN_RETRY_HINT_MS)).await;
                    continue;
                }
            }
            break result;
        };
        match result {
            Ok(stream) => {
                if standalone {
                    self.ledger
                        .with(|inner| inner.counts.standalone_opened += 1);
                }
                Ok(self.ledger.wrap(stream, standalone))
            }
            Err(error) => {
                if standalone {
                    self.ledger
                        .with(|inner| inner.counts.standalone_refused += 1);
                }
                Err(error)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Client handler.

#[derive(Default)]
struct HandlerState {
    progress: Mutex<Vec<(f64, Option<String>)>>,
    logs: Mutex<Vec<serde_json::Value>>,
    changed: Notify,
}

/// The gate's rmcp client handler: records progress and log notifications.
#[derive(Clone, Default)]
pub(super) struct GateClient {
    state: Arc<HandlerState>,
    protocol: Option<ProtocolVersion>,
}

impl std::fmt::Debug for GateClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("GateClient").finish_non_exhaustive()
    }
}

impl GateClient {
    pub fn legacy() -> Self {
        Self {
            protocol: Some(ProtocolVersion::V_2025_11_25),
            ..Self::default()
        }
    }

    pub fn progress(&self) -> Vec<(f64, Option<String>)> {
        self.state
            .progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn logs(&self) -> Vec<serde_json::Value> {
        self.state
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Wait, bounded, until `ready` holds for the recorded notifications.
    pub async fn wait_for(&self, bound: Duration, ready: impl Fn(&Self) -> bool) -> bool {
        timeout(bound, async {
            loop {
                let changed = self.state.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if ready(self) {
                    return;
                }
                changed.await;
            }
        })
        .await
        .is_ok()
    }
}

impl ClientHandler for GateClient {
    fn get_info(&self) -> rmcp::model::ClientConfig {
        let mut info = rmcp::model::ClientConfig::default();
        if let Some(protocol) = &self.protocol {
            info = info.with_protocol_version(protocol.clone());
        }
        info
    }

    async fn on_progress(
        &self,
        params: ProgressNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        self.state
            .progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((params.progress, params.message));
        self.state.changed.notify_waiters();
    }

    #[allow(deprecated)]
    async fn on_logging_message(
        &self,
        params: rmcp::model::LoggingMessageNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        self.state
            .logs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(params.data);
        self.state.changed.notify_waiters();
    }
}

// ---------------------------------------------------------------------------
// Fixture processes.

/// The built `tunnel-mcp-fixture` binary: `TUNNEL_MCP_FIXTURE_BIN`, or next
/// to this executable.
pub(super) fn fixture_binary_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("TUNNEL_MCP_FIXTURE_BIN") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        return Err(HarnessError::Process(
            "TUNNEL_MCP_FIXTURE_BIN does not point to a file".into(),
        ));
    }
    let mut candidates = Vec::new();
    if let Ok(current) = std::env::current_exe()
        && let Some(parent) = current.parent()
    {
        candidates.push(parent.join("tunnel-mcp-fixture"));
        if let Some(target_dir) = parent.parent() {
            candidates.push(target_dir.join("tunnel-mcp-fixture"));
        }
    }
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .and_then(|path| path.canonicalize().ok())
        .ok_or_else(|| {
            HarnessError::Process(
                "built tunnel-mcp-fixture binary is missing next to the harness executable; run `cargo build --locked -p tunnel-mcp-fixture`".into(),
            )
        })
}

/// Whether a process with `pid` still exists (a zombie counts).
pub(super) fn process_exists(pid: u32) -> bool {
    i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
        .is_some_and(|pid| rustix::process::test_kill_process(pid).is_ok())
}

/// Wait, bounded, until `pid` no longer exists.
pub(super) async fn wait_process_gone(pid: u32, bound: Duration) -> bool {
    let deadline = Instant::now() + bound;
    loop {
        if !process_exists(pid) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(POLL).await;
    }
}

/// Wait, bounded, for a file to exist.
pub(super) async fn wait_file(path: &Path, bound: Duration) -> bool {
    let deadline = Instant::now() + bound;
    loop {
        if path.exists() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(POLL).await;
    }
}

/// Wait, bounded, for a pid file and parse it.
pub(super) async fn wait_pid_file(path: &Path, bound: Duration) -> Option<u32> {
    if !wait_file(path, bound).await {
        return None;
    }
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Count lines equal to `needle`.
pub(super) fn count_lines(path: &Path, needle: &str) -> u64 {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| *line == needle)
        .count() as u64
}

/// The synthetic rmcp Streamable HTTP server process.
pub(super) struct HttpBackend {
    binary: PathBuf,
    pub marker_dir: PathBuf,
    legacy: bool,
    pub address: SocketAddr,
    child: Option<tokio::process::Child>,
    pub starts: u64,
    /// Every backend process ID this backend started.
    pub pids: Vec<u32>,
}

impl HttpBackend {
    pub async fn start(binary: &Path, marker_dir: &Path, legacy: bool) -> Result<Self> {
        let mut backend = Self {
            binary: binary.to_owned(),
            marker_dir: marker_dir.to_owned(),
            legacy,
            address: SocketAddr::from(([127, 0, 0, 1], 0)),
            child: None,
            starts: 0,
            pids: Vec::new(),
        };
        backend.spawn(0).await?;
        Ok(backend)
    }

    async fn spawn(&mut self, port: u16) -> Result<()> {
        let address_file = self.marker_dir.join("backend-address");
        let _ = std::fs::remove_file(&address_file);
        let child = tokio::process::Command::new(&self.binary)
            .arg("http")
            .arg(&self.marker_dir)
            .arg(port.to_string())
            .arg(if self.legacy { "legacy" } else { "stateless" })
            .arg(&address_file)
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(HarnessError::Io)?;
        if let Some(pid) = child.id() {
            self.pids.push(pid);
        }
        self.child = Some(child);
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(text) = std::fs::read_to_string(&address_file)
                && let Ok(address) = text.trim().parse::<SocketAddr>()
            {
                self.address = address;
                self.starts += 1;
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "the synthetic MCP HTTP backend did not publish its address".into(),
                ));
            }
            sleep(POLL).await;
        }
    }

    /// Wait, bounded, for the backend process to exit.
    pub async fn wait_exit(&mut self, bound: Duration) -> bool {
        let Some(child) = self.child.as_mut() else {
            return true;
        };
        timeout(bound, child.wait()).await.is_ok()
    }

    /// Start a fresh backend process on the same port.
    pub async fn restart(&mut self) -> Result<()> {
        self.stop().await;
        self.spawn(self.address.port()).await
    }

    pub async fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            let _ = timeout(Duration::from_secs(10), child.wait()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_coincides_only_with_a_recent_or_current_freeze() {
        let watch = FreezeWatch::default();
        // Nothing observed yet: a refusal cannot be attributed to a freeze.
        assert!(!watch.coincides());
        watch.record("active", 3);
        assert!(!watch.coincides());
        for phase in FROZEN_PHASES {
            let watch = FreezeWatch::default();
            watch.record(phase, 3);
            assert!(watch.coincides(), "{phase}");
        }
        let watch = FreezeWatch::default();
        watch.record("quiescing", 3);
        assert!(watch.coincides());
        // Still inside the coincidence window after the freeze ends.
        watch.record("active", 4);
        assert!(watch.coincides());
    }

    #[test]
    fn an_unexplained_refusal_names_the_connector_state() {
        let watch = FreezeWatch::default();
        watch.record("active", 7);
        let unexplained = watch.unexplained();
        assert!(unexplained.contains("phase=\"active\""), "{unexplained}");
        assert!(
            unexplained.contains("rotations_completed=7"),
            "{unexplained}"
        );
        // No freeze has been seen at all, so there is no age to report.
        assert!(
            unexplained.contains("ms_since_last_freeze=None"),
            "{unexplained}"
        );
    }

    #[test]
    fn the_resend_cap_covers_the_rotation_handshake_budget() {
        let handshake_ms = super::super::MCP_GATE_ROTATION.handshake_timeout_seconds * 1_000;
        assert_eq!(
            NOT_DISPATCHED_RETRIES,
            handshake_ms.div_ceil(MIN_RETRY_HINT_MS) + RETRY_MARGIN
        );
        // Every resend waits at least the smallest hint, so the cap spans
        // the whole handshake budget with the margin to spare.
        assert!(NOT_DISPATCHED_RETRIES * MIN_RETRY_HINT_MS > handshake_ms);
        assert_eq!(NOT_DISPATCHED_RETRIES, 12);
    }

    #[test]
    fn only_a_retryable_not_dispatched_503_carries_a_retry_hint() {
        let refusal = |body: &str| {
            StreamableHttpError::UnexpectedServerResponse(std::borrow::Cow::Owned(format!(
                "HTTP 503 Service Unavailable: {body}"
            )))
        };
        let frozen = refusal(
            r#"{"code":"PEER_UNAVAILABLE","execution":"not_dispatched","retryable":true,"retry_after_ms":250}"#,
        );
        assert_eq!(
            not_dispatched_retry_after(&frozen),
            Some(Duration::from_millis(250))
        );
        // An unknown outcome, a non-retryable refusal and another status are
        // never resent: only the relay's "nothing was dispatched" answer is.
        for body in [
            r#"{"code":"PEER_UNAVAILABLE","execution":"unknown","retryable":true,"retry_after_ms":250}"#,
            r#"{"code":"PEER_UNAVAILABLE","execution":"not_dispatched","retryable":false}"#,
        ] {
            assert_eq!(not_dispatched_retry_after(&refusal(body)), None);
        }
        assert_eq!(
            not_dispatched_retry_after(&StreamableHttpError::UnexpectedServerResponse(
                std::borrow::Cow::Borrowed("HTTP 502 Bad Gateway: {}")
            )),
            None
        );
        // A hint longer than the ceiling is clamped.
        assert_eq!(
            not_dispatched_retry_after(&refusal(
                r#"{"execution":"not_dispatched","retryable":true,"retry_after_ms":60000}"#
            )),
            Some(MAX_RETRY_AFTER)
        );
    }
}
