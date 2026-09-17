//! The in-process ACP HTTP/SSE handler (M8 chunk 3, the bridge half of
//! M8-02).
//!
//! [`AcpExport::handle`] is an [`HttpHandler`][h] the connector registers
//! through `HttpHandlers::with_export`: it takes the gate-2 bridge's typed
//! request and returns a response whose body streams.  **There is no address,
//! no listener and no socket anywhere in this file**; `tunnel_http_bridge::serve`
//! calls the handler directly, and `tests/no_listener.rs` reads the process's
//! own socket table to say so rather than asserting the absence of a call.
//!
//! [h]: https://docs.rs/tunnel-client
//!
//! # The 202 rule
//!
//! `docs/acp.md`: "HTTP 202 means accepted by the bridge, not that an agent
//! finished or committed an action."  Every POST but `initialize` answers 202
//! and the JSON-RPC result arrives later on a **different exchange** — the
//! connection GET for `session/new`, the session GET for `session/prompt`.
//! Nothing in this file infers completion from a status, and no test of it may
//! terminate on one.
//!
//! # Wire order
//!
//! Agent→host messages reach this bridge on one channel from the supervisor's
//! one stdout reader ([`OutboundMessage`]), and each SSE stream has one
//! bounded queue and one draining task.  Wire order is therefore the order the
//! agent wrote, with nothing downstream reordering it.  A bridge-composed
//! result — a `session/new` or `session/prompt` answer — is enqueued by the
//! task that awaited it, which cannot run until the supervisor's reader has
//! already forwarded everything that preceded the result on the child's
//! stdout.
//!
//! # Subscribers
//!
//! One subscriber per connection and one per session, enforced by *taking* the
//! queue's receiving half: a second GET finds nothing to take and is refused
//! **409**.  A pre-subscription message is charged to the same bounded queue,
//! as `docs/acp.md` requires, rather than dropped or buffered without limit.
//!
//! # What this file does not do
//!
//! There is **no principal in this chunk**.  `docs/acp.md` derives the
//! principal at the relay ingress, and the in-process gate-2 bridge has no
//! ingress in front of it, exactly as `tunnel_mcp_export` records for M3-01 and
//! M3-02: every request here carries `tunnel-principal-binding: None`, which
//! binds a connection to "no principal" and still refuses any other value.
//! Binding to a real authenticated principal, the cluster, rotation and
//! cross-tenant isolation are chunks 4 and 5.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tunnel_acp::lifecycle::{LifecycleRule, PermissionOutcome, RequestId};
use tunnel_acp::message::{
    AcpMessage, AcpRejection, AcpRule, MessageKind, validate_delete, validate_get, validate_post,
};
use tunnel_acp::{AcpLimits, AcpProfile};
use tunnel_http_bridge::{ChannelBody, Profile};

use crate::config::{AcpConfigError, AcpExportConfig, ValidatedAcp};
use crate::sse::{
    self, ChannelResponseBody, ExportBody, StreamFailure, StreamSender, json_response, no_body,
    rejection, sse_event, sse_head,
};
use crate::supervisor::{
    ConnectionScope, OutboundMessage, Supervisor, SupervisorConfig, SupervisorError,
};

/// Messages queued for one not-yet-subscribed or slow SSE stream.
///
/// `docs/acp.md`: "Charge pre-subscription messages to the same bounded
/// queues."  This is that bound, and it is finite.
pub const STREAM_BACKLOG: usize = 32;

/// How often a connection's watchdog reads its clock.
const WATCHDOG_TICK: Duration = Duration::from_millis(20);

/// An exchange the export interrupts instead of answering.  It carries no
/// message: the peer learns only the bridge's sanitized code.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExportError;

impl std::fmt::Display for ExportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("acp export interrupted the exchange")
    }
}

impl std::error::Error for ExportError {}

/// Payload-free counters of one ACP export.
#[derive(Debug, Default)]
struct Counters {
    connections_opened: AtomicU64,
    connections_closed: AtomicU64,
    connection_subscribe_expired: AtomicU64,
    session_subscribe_expired: AtomicU64,
    subscribers_refused: AtomicU64,
    sessions_opened: AtomicU64,
    prompts_accepted: AtomicU64,
    prompts_refused_not_ready: AtomicU64,
    permissions_answered: AtomicU64,
    batches_refused: AtomicU64,
    rejected: AtomicU64,
    sse_events: AtomicU64,
    sse_bytes: AtomicU64,
    /// The last measured **microseconds** a subscription deadline actually ran
    /// before the watchdog expired it, with the bound it exceeded.  Strictly
    /// greater than the bound.
    ///
    /// Microseconds rather than milliseconds because the bound is a whole
    /// number of milliseconds: a watchdog that fires at 300.4 ms reports 300
    /// once truncated, and "strictly greater" then reads as equal. The
    /// resolution has to be finer than the bound for the measurement to say
    /// anything.
    last_expiry_elapsed_us: AtomicU64,
    last_expiry_bound_us: AtomicU64,
    /// SSE streams whose subscriber went away while messages were still being
    /// routed to them.
    streams_lost: AtomicU64,
    /// Messages dropped because their stream was already over.
    messages_dropped_on_closed_stream: AtomicU64,
    /// Connections ended because their child did.
    connections_ended_by_child: AtomicU64,
    /// The child's own refused-batch and refused-line counts, folded in when a
    /// connection ends, so they survive the connection they belonged to.
    child_batch_output: AtomicU64,
    child_invalid_output: AtomicU64,
}

/// A snapshot of an export's counters.  Identifiers, phases and counters
/// only; never a payload or a credential.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AcpDiagnostics {
    pub connections_opened: u64,
    pub connections_closed: u64,
    pub connection_subscribe_expired: u64,
    pub session_subscribe_expired: u64,
    pub subscribers_refused: u64,
    pub sessions_opened: u64,
    pub prompts_accepted: u64,
    pub prompts_refused_not_ready: u64,
    pub permissions_answered: u64,
    pub batches_refused: u64,
    pub rejected: u64,
    pub sse_events: u64,
    pub sse_bytes: u64,
    pub last_expiry_elapsed_us: u64,
    pub last_expiry_bound_us: u64,
    pub streams_lost: u64,
    pub messages_dropped_on_closed_stream: u64,
    pub connections_ended_by_child: u64,
    pub child_batch_output: u64,
    pub child_invalid_output: u64,
    pub live_connections: u64,
}

/// One SSE destination: a bounded queue whose receiving half the single
/// subscriber takes.
#[derive(Debug)]
struct Target {
    tx: mpsc::Sender<Bytes>,
    /// `None` once a subscriber has taken it.  Taking is what makes "one
    /// subscriber" a structural property rather than a flag someone has to
    /// remember to check.
    rx: Mutex<Option<mpsc::Receiver<Bytes>>>,
    created: Instant,
    subscribed: Mutex<bool>,
    /// This stream is over: its subscriber went away, or its window expired.
    ///
    /// **It is per target, and that is the whole point.** A dropped SSE body
    /// is an ordinary event — a client closing one session's stream, or this
    /// bridge expiring a session whose GET never arrived — and before review
    /// found it, the first such failure returned the connection's one
    /// dispatcher task, which dropped the supervisor's forward channel, which
    /// ended the supervisor's reader, which meant **every other session and
    /// the connection stream itself stopped receiving and every outstanding
    /// prompt hung until DELETE**. Marking one target closed and carrying on is
    /// what stops one lost subscriber from silently disabling a connection.
    closed: Mutex<bool>,
}

impl Target {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel(STREAM_BACKLOG);
        Self {
            tx,
            rx: Mutex::new(Some(rx)),
            created: Instant::now(),
            subscribed: Mutex::new(false),
            closed: Mutex::new(false),
        }
    }

    fn close(&self) {
        *self.closed.lock().unwrap_or_else(PoisonError::into_inner) = true;
        // Nothing may subscribe to a stream that is over, so the receiving
        // half is taken away as well: a later GET is refused 409 by the same
        // mechanism that refuses a second subscriber.
        let _ = self
            .rx
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    fn is_closed(&self) -> bool {
        *self.closed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn take(&self) -> Option<mpsc::Receiver<Bytes>> {
        if self.is_closed() {
            return None;
        }
        let taken = self
            .rx
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if taken.is_some() {
            *self
                .subscribed
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = true;
        }
        taken
    }

    fn is_subscribed(&self) -> bool {
        *self
            .subscribed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

struct ConnectionState {
    connection: Arc<Target>,
    sessions: BTreeMap<String, Arc<Target>>,
    closed: bool,
}

/// One live ACP transport connection: its child, its streams and its
/// deadlines.
struct Connection {
    id: String,
    supervisor: Supervisor,
    /// The opaque per-principal binding the ingress derived, or `None`.  In
    /// this chunk it is always `None`: there is no ingress in front of the
    /// in-process bridge.
    principal: Option<String>,
    workspace: String,
    limits: AcpLimits,
    subscribe_deadline: Duration,
    state: Mutex<ConnectionState>,
    counters: Arc<Counters>,
    shutdown: CancellationToken,
}

impl Connection {
    fn with<R>(&self, apply: impl FnOnce(&mut ConnectionState) -> R) -> R {
        let mut guard = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        apply(&mut guard)
    }

    /// The session's queue, created on first mention.
    ///
    /// Both the dispatcher and the POST that created the session reach for it,
    /// and which of them arrives first is a race the agent decides: an update
    /// can be on the wire before `session/new`'s own result has been read.
    /// Creating on demand is what keeps that from being delivered to the wrong
    /// stream.
    fn session_target(&self, session: &str) -> Option<Arc<Target>> {
        self.with(|state| {
            if state.closed {
                return None;
            }
            // A closed session stays closed: the entry is kept so a target
            // that was expired or lost cannot be resurrected by the next
            // message that mentions its identifier.
            Some(Arc::clone(
                state
                    .sessions
                    .entry(session.to_owned())
                    .or_insert_with(|| Arc::new(Target::new())),
            ))
        })
    }
}

/// One configured ACP export.
#[derive(Clone)]
pub struct AcpExport {
    inner: Arc<Inner>,
}

struct Inner {
    validated: ValidatedAcp,
    connections: Mutex<BTreeMap<String, Arc<Connection>>>,
    counters: Arc<Counters>,
    next: AtomicU64,
    epoch: u64,
}

impl std::fmt::Debug for AcpExport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcpExport")
            .field("profile", &self.inner.validated.profile)
            .finish_non_exhaustive()
    }
}

impl AcpExport {
    /// Build an export from validated operator configuration.
    ///
    /// # Errors
    /// The first configuration rule violated.
    pub fn from_config(config: &AcpExportConfig) -> Result<Self, AcpConfigError> {
        let validated = config.validate()?;
        Ok(Self {
            inner: Arc::new(Inner {
                validated,
                connections: Mutex::new(BTreeMap::new()),
                counters: Arc::new(Counters::default()),
                next: AtomicU64::new(0),
                epoch: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |since| since.as_nanos() as u64),
            }),
        })
    }

    #[must_use]
    pub fn profile(&self) -> AcpProfile {
        self.inner.validated.profile
    }

    /// The selected profile's `http-forward/1` policies with this export's
    /// limits, so the device validates heads against exactly the allowlist the
    /// relay enforces.
    ///
    /// # Errors
    /// Only if the pinned profile tables are inconsistent.
    pub fn profile_policies(&self) -> Result<Profile, tunnel_http_forward::PolicyError> {
        self.inner
            .validated
            .profile
            .policies(self.inner.validated.limits)
    }

    /// Payload-free counters.
    #[must_use]
    pub fn diagnostics(&self) -> AcpDiagnostics {
        let counters = &self.inner.counters;
        let load = |value: &AtomicU64| value.load(Ordering::Relaxed);
        AcpDiagnostics {
            connections_opened: load(&counters.connections_opened),
            connections_closed: load(&counters.connections_closed),
            // **Acquire, and read before the measurement below.** The watchdog
            // publishes `last_expiry_*` and then releases these counters, so a
            // reader that saw the count with a relaxed load could still read a
            // stale elapsed and compare 0 against 0 — which passes, and proves
            // nothing. This pairing is what makes the measurement readable at
            // all.
            connection_subscribe_expired: counters
                .connection_subscribe_expired
                .load(Ordering::Acquire),
            session_subscribe_expired: counters.session_subscribe_expired.load(Ordering::Acquire),
            subscribers_refused: load(&counters.subscribers_refused),
            sessions_opened: load(&counters.sessions_opened),
            prompts_accepted: load(&counters.prompts_accepted),
            prompts_refused_not_ready: load(&counters.prompts_refused_not_ready),
            permissions_answered: load(&counters.permissions_answered),
            batches_refused: load(&counters.batches_refused),
            rejected: load(&counters.rejected),
            sse_events: load(&counters.sse_events),
            sse_bytes: load(&counters.sse_bytes),
            last_expiry_elapsed_us: load(&counters.last_expiry_elapsed_us),
            last_expiry_bound_us: load(&counters.last_expiry_bound_us),
            streams_lost: load(&counters.streams_lost),
            messages_dropped_on_closed_stream: load(&counters.messages_dropped_on_closed_stream),
            connections_ended_by_child: counters.connections_ended_by_child.load(Ordering::Acquire),
            child_batch_output: load(&counters.child_batch_output),
            child_invalid_output: load(&counters.child_invalid_output),
            live_connections: self
                .inner
                .connections
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .len() as u64,
        }
    }

    /// The child's process id for each live connection, so a test can read the
    /// process table rather than a counter.
    #[must_use]
    pub fn child_pids(&self) -> Vec<u32> {
        self.inner
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .filter_map(|connection| connection.supervisor.pid())
            .collect()
    }

    /// End every connection this export holds, draining each child and
    /// signalling its process group.
    ///
    /// Dropping the export's last handle does the same through the
    /// supervisor's own `Drop`; this is the explicit form, for a connector
    /// that stops its handlers before dropping them.  Idempotent.
    pub fn shutdown(&self) {
        let connections: Vec<Arc<Connection>> = self
            .inner
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect();
        self.inner
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        for connection in connections {
            connection.with(|state| state.closed = true);
            connection.shutdown.cancel();
            connection.supervisor.kill();
            self.inner
                .counters
                .connections_closed
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn connection(&self, id: &str) -> Option<Arc<Connection>> {
        self.inner
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .cloned()
    }

    fn remove(&self, id: &str) -> Option<Arc<Connection>> {
        let removed = self
            .inner
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
        if removed.is_some() {
            self.inner
                .counters
                .connections_closed
                .fetch_add(1, Ordering::Relaxed);
        }
        removed
    }

    /// Serve one exchange in process.
    ///
    /// # Errors
    /// [`ExportError`] when the exchange must be interrupted rather than
    /// answered.
    pub async fn handle(
        &self,
        request: Request<ChannelBody>,
    ) -> Result<Response<ExportBody>, ExportError> {
        let (parts, body) = request.into_parts();
        match parts.method {
            http::Method::POST => self.post(&parts.headers, body).await,
            http::Method::GET => Ok(self.get(&parts.headers)),
            http::Method::DELETE => Ok(self.delete(&parts.headers).await),
            // The codec routes only these three; anything else never reaches
            // the handler.  Answering rather than panicking keeps a future
            // routing mistake a 405 instead of a killed exchange.
            _ => Ok(no_body(StatusCode::METHOD_NOT_ALLOWED)),
        }
    }

    fn refuse(&self, rejection_value: &AcpRejection) -> Response<ExportBody> {
        self.inner.counters.rejected.fetch_add(1, Ordering::Relaxed);
        if rejection_value.rule == AcpRule::BatchNotSupported {
            self.inner
                .counters
                .batches_refused
                .fetch_add(1, Ordering::Relaxed);
        }
        rejection(rejection_value)
    }

    async fn post(
        &self,
        headers: &http::HeaderMap,
        body: ChannelBody,
    ) -> Result<Response<ExportBody>, ExportError> {
        let limit = self.inner.validated.limits.request_body();
        let Ok(bytes) = collect_limited(body, limit).await else {
            return Ok(json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                Bytes::from_static(b"{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"request body exceeds the configured limit\"},\"id\":null}"),
            ));
        };
        // Buffered and fully validated before anything is dispatched to a
        // child: a batch is refused here, by its own rule and its own 501.
        let message = match validate_post(headers, &bytes) {
            Ok(message) => message,
            Err(rejected) => return Ok(self.refuse(&rejected)),
        };
        if message.is_initialize() {
            return self.initialize(headers, message).await;
        }
        let Some(id) = header(headers, tunnel_acp::headers::ACP_CONNECTION_ID) else {
            // `validate_post` already required it; this is the unreachable
            // half of the same rule, answered rather than unwrapped.
            return Ok(self.refuse(&AcpRejection::new(
                AcpRule::ConnectionHeaderRequired,
                "Acp-Connection-Id is required",
            )));
        };
        let Some(connection) = self.connection(&id) else {
            return Ok(not_found());
        };
        if connection.principal != principal_binding(headers) {
            // The binding is compared, never interpreted and never derived
            // here.  In this chunk both sides are `None`.
            return Ok(not_found());
        }
        self.dispatch(&connection, headers, message).await
    }

    async fn initialize(
        &self,
        headers: &http::HeaderMap,
        message: AcpMessage,
    ) -> Result<Response<ExportBody>, ExportError> {
        let validated = &self.inner.validated;
        let sequence = self.inner.next.fetch_add(1, Ordering::Relaxed);
        let id = format!("acp-{:016x}-{sequence:x}", self.inner.epoch);
        let scope = ConnectionScope {
            // There is no tenant, principal or device identity in the
            // in-process bridge.  These are the *scope* of a JSON-RPC id, not
            // an authorization claim, and they are fixed synthetic values here
            // so that two connections still scope their ids apart by the one
            // identifier this chunk actually has.
            tenant: "in-process".to_owned(),
            principal: principal_binding(headers).unwrap_or_else(|| "none".to_owned()),
            device: "in-process".to_owned(),
            service: "acp".to_owned(),
            connection: id.clone(),
        };
        let mut supervisor_config = SupervisorConfig::new(validated.child.clone(), scope);
        supervisor_config.permission_timeout = validated.permission_timeout;
        supervisor_config.session_limit = validated.session_limit;

        let (forward_tx, forward_rx) = mpsc::channel(STREAM_BACKLOG);
        let Ok((supervisor, mut events)) =
            Supervisor::start_forwarding(supervisor_config, Some(forward_tx))
        else {
            return Ok(json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                Bytes::from_static(b"{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"the configured agent could not be started\"},\"id\":null}"),
            ));
        };
        // The diagnostic channel must be drained or the reader blocks; the
        // bridge has no use for it beyond that, and it carries no payload.
        tokio::spawn(async move { while events.recv().await.is_some() {} });

        let params = message
            .value
            .get("params")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let result = match supervisor.initialize_with(params).await {
            Ok(result) => result,
            Err(_) => {
                supervisor.drain().await;
                return Ok(json_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    Bytes::from_static(b"{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"the agent did not complete initialization\"},\"id\":null}"),
                ));
            }
        };
        // The agent's own negotiated version, refused by the pinned profile's
        // rule if it is not 1 — in the **result** as well as the request.
        if let Err(rejected) = check_result_version(&result) {
            supervisor.drain().await;
            return Ok(self.refuse(&rejected));
        }

        let connection = Arc::new(Connection {
            id: id.clone(),
            supervisor,
            principal: principal_binding(headers),
            workspace: validated.workspace.to_string_lossy().into_owned(),
            limits: validated.limits,
            subscribe_deadline: validated.subscribe_deadline,
            state: Mutex::new(ConnectionState {
                connection: Arc::new(Target::new()),
                sessions: BTreeMap::new(),
                closed: false,
            }),
            counters: Arc::clone(&self.inner.counters),
            shutdown: CancellationToken::new(),
        });
        self.inner
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id.clone(), Arc::clone(&connection));
        self.inner
            .counters
            .connections_opened
            .fetch_add(1, Ordering::Relaxed);

        tokio::spawn(dispatch_outbound(Arc::clone(&connection), forward_rx));
        tokio::spawn(watch_deadlines(self.clone(), Arc::clone(&connection)));

        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": message.id.clone().unwrap_or(Value::Null),
            "result": result,
        }))
        .unwrap_or_default();
        let mut response = json_response(StatusCode::OK, Bytes::from(body));
        if let Ok(value) = http::HeaderValue::from_str(&id) {
            response.headers_mut().insert(
                http::HeaderName::from_static(tunnel_acp::headers::ACP_CONNECTION_ID),
                value,
            );
        }
        Ok(response)
    }

    async fn dispatch(
        &self,
        connection: &Arc<Connection>,
        headers: &http::HeaderMap,
        message: AcpMessage,
    ) -> Result<Response<ExportBody>, ExportError> {
        let params = message
            .value
            .get("params")
            .cloned()
            .unwrap_or_else(|| json!({}));
        match message.kind {
            MessageKind::Response => self.answer_permission(connection, &message).await,
            MessageKind::Notification | MessageKind::Request => {
                match message.method.as_deref() {
                    Some("session/new") => {
                        Ok(self.new_session(connection, &message, params).await)
                    }
                    Some("session/prompt") => {
                        Ok(self.prompt(connection, &message, headers, params).await)
                    }
                    Some("session/cancel") => {
                        let session = header(headers, tunnel_acp::headers::ACP_SESSION_ID)
                            .or_else(|| message.session_id().map(ToOwned::to_owned));
                        if let Some(session) = session {
                            let _ = connection.supervisor.cancel_session(&session, params).await;
                        }
                        Ok(no_body(StatusCode::ACCEPTED))
                    }
                    // `session/load` is an accepted method of the profile but
                    // has no policy yet: `docs/acp.md` requires an authorized
                    // stored session/workspace mapping and a negotiated
                    // capability before cross-connection loading. Refusing is
                    // the honest answer; forwarding it would be a claim.
                    Some(_) | None => Ok(json_response(
                        StatusCode::NOT_IMPLEMENTED,
                        Bytes::from_static(b"{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"this method is not carried by this export\"},\"id\":null}"),
                    )),
                }
            }
        }
    }

    async fn new_session(
        &self,
        connection: &Arc<Connection>,
        message: &AcpMessage,
        params: Value,
    ) -> Response<ExportBody> {
        // The host cannot select a working directory: `docs/acp.md` requires
        // `cwd` to be the configured workspace, and a mismatch is refused
        // before anything reaches the agent.  Empty `mcpServers` only.
        if params.get("cwd").and_then(Value::as_str) != Some(connection.workspace.as_str())
            || !params
                .get("mcpServers")
                .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty))
        {
            return json_response(
                StatusCode::BAD_REQUEST,
                Bytes::from_static(b"{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"cwd must be the configured workspace and mcpServers must be empty\"},\"id\":null}"),
            );
        }
        let host_id = message.id.clone().unwrap_or(Value::Null);
        let connection = Arc::clone(connection);
        let counters = Arc::clone(&self.inner.counters);
        // 202 now; the result travels on the connection GET.
        tokio::spawn(async move {
            let Ok(session) = connection.supervisor.new_session_with(params).await else {
                return;
            };
            counters.sessions_opened.fetch_add(1, Ordering::Relaxed);
            // Create the queue before publishing the identifier, so a host
            // that opens the session GET the instant it reads the result finds
            // a stream, and so anything the agent already said is in it.
            let _ = connection.session_target(&session);
            let target = connection.with(|state| Arc::clone(&state.connection));
            let body = serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": host_id,
                "result": {"sessionId": session},
            }))
            .unwrap_or_default();
            let _ = target.tx.send(Bytes::from(body)).await;
        });
        no_body(StatusCode::ACCEPTED)
    }

    async fn prompt(
        &self,
        connection: &Arc<Connection>,
        message: &AcpMessage,
        headers: &http::HeaderMap,
        params: Value,
    ) -> Response<ExportBody> {
        let Some(session) = header(headers, tunnel_acp::headers::ACP_SESSION_ID) else {
            return self.refuse(&AcpRejection::new(
                AcpRule::SessionHeaderRequired,
                "this method is session-scoped and requires Acp-Session-Id",
            ));
        };
        if !connection.supervisor.has_session(&session) {
            return not_found();
        }
        let ticket = match connection.supervisor.prompt_with(&session, params) {
            Ok(ticket) => ticket,
            Err(error) => {
                if error.rule() == Some(LifecycleRule::SessionNotReady) {
                    self.inner
                        .counters
                        .prompts_refused_not_ready
                        .fetch_add(1, Ordering::Relaxed);
                }
                return supervisor_refusal(&error);
            }
        };
        self.inner
            .counters
            .prompts_accepted
            .fetch_add(1, Ordering::Relaxed);
        let host_id = message.id.clone().unwrap_or(Value::Null);
        let connection = Arc::clone(connection);
        tokio::spawn(async move {
            let Some(target) = connection.session_target(&session) else {
                return;
            };
            // `stop_reason` runs the pinned crate's own v1 turn-completion
            // reader: a v2 acknowledgement with no `stopReason` is refused by
            // its own rule rather than delivered as a finished turn.
            let body = match ticket.stop_reason().await {
                Ok(stop) => serde_json::to_vec(&json!({
                    "jsonrpc": "2.0",
                    "id": host_id,
                    "result": {"stopReason": stop},
                })),
                Err(error) => serde_json::to_vec(&json!({
                    "jsonrpc": "2.0",
                    "id": host_id,
                    "error": {"code": -32603, "message": error.to_string()},
                })),
            }
            .unwrap_or_default();
            let _ = target.tx.send(Bytes::from(body)).await;
        });
        no_body(StatusCode::ACCEPTED)
    }

    async fn answer_permission(
        &self,
        connection: &Arc<Connection>,
        message: &AcpMessage,
    ) -> Result<Response<ExportBody>, ExportError> {
        let Some(id) = message.id.as_ref().and_then(request_id) else {
            return Ok(self.refuse(&AcpRejection::new(
                AcpRule::RequestId,
                "a response must carry the id of the request it answers",
            )));
        };
        let Some(outcome) = permission_outcome(&message.value) else {
            return Ok(self.refuse(&AcpRejection::new(
                AcpRule::NotJsonRpcMessage,
                "a permission response must carry result.outcome",
            )));
        };
        match connection.supervisor.answer_permission(&id, outcome).await {
            Ok(()) => {
                self.inner
                    .counters
                    .permissions_answered
                    .fetch_add(1, Ordering::Relaxed);
                Ok(no_body(StatusCode::ACCEPTED))
            }
            Err(error) => Ok(supervisor_refusal(&error)),
        }
    }

    fn get(&self, headers: &http::HeaderMap) -> Response<ExportBody> {
        if let Err(rejected) = validate_get(headers) {
            return self.refuse(&rejected);
        }
        let Some(id) = header(headers, tunnel_acp::headers::ACP_CONNECTION_ID) else {
            return not_found();
        };
        let Some(connection) = self.connection(&id) else {
            return not_found();
        };
        if connection.principal != principal_binding(headers) {
            return not_found();
        }
        let session = header(headers, tunnel_acp::headers::ACP_SESSION_ID);
        let target = match &session {
            Some(session) => {
                if !connection.supervisor.has_session(session) {
                    return not_found();
                }
                match connection.session_target(session) {
                    Some(target) => target,
                    None => return not_found(),
                }
            }
            None => connection.with(|state| Arc::clone(&state.connection)),
        };
        let Some(queue) = target.take() else {
            // The one-subscriber rule, and it is structural: there is nothing
            // left to take.
            self.inner
                .counters
                .subscribers_refused
                .fetch_add(1, Ordering::Relaxed);
            return no_body(StatusCode::CONFLICT);
        };
        if let Some(session) = &session {
            // A session admits its prompt only once its subscriber is ready,
            // and this is the moment it becomes so.
            let _ = connection.supervisor.subscriber_ready(session);
        }
        let bytes = Arc::new(AtomicU64::new(0));
        let (sender, body) =
            ChannelResponseBody::channel(connection.limits.sse_response_body(), bytes);
        tokio::spawn(pump_stream(
            queue,
            sender,
            Arc::clone(&self.inner.counters),
            connection.shutdown.clone(),
        ));
        let mut response = Response::new(sse::stream_body(body));
        *response.status_mut() = StatusCode::OK;
        sse_head(&mut response, &connection.id);
        response
    }

    async fn delete(&self, headers: &http::HeaderMap) -> Response<ExportBody> {
        if let Err(rejected) = validate_delete(headers) {
            return self.refuse(&rejected);
        }
        let Some(id) = header(headers, tunnel_acp::headers::ACP_CONNECTION_ID) else {
            return not_found();
        };
        let Some(connection) = self.connection(&id) else {
            return not_found();
        };
        if connection.principal != principal_binding(headers) {
            return not_found();
        }
        self.remove(&id);
        // 202: accepted by the bridge.  Teardown — cancelling outstanding
        // permissions, killing the child's process group, reaping it — is not
        // finished when this status is written, which is exactly what
        // `docs/acp.md` says 202 means.
        close_connection(&connection).await;
        no_body(StatusCode::ACCEPTED)
    }
}

/// Route one agent→host message to the stream it belongs on, in the order the
/// agent wrote it.
///
/// **One lost subscriber closes one stream, and nothing else.** This task is
/// the connection's only reader of the supervisor's forward channel, so
/// returning from it stops every stream on the connection at once and hangs
/// every outstanding prompt — which is what it used to do on the first failed
/// send. A target whose body has gone away is marked closed and its messages
/// are dropped; the loop carries on.
///
/// **What this is not.** `docs/acp.md` says an established required SSE stream
/// breaking should terminate the whole ACP transport in v0. That is *subscriber
/// loss*, it is M8-03's open half, and it is not implemented: this bridge keeps
/// the connection and its other sessions running. The change here is narrower
/// and only removes a silent, destructive failure — it is not the documented
/// policy.
async fn dispatch_outbound(
    connection: Arc<Connection>,
    mut inbox: mpsc::Receiver<OutboundMessage>,
) {
    while let Some(message) = inbox.recv().await {
        let target = match message.session.as_deref() {
            Some(session) => connection.session_target(session),
            None => Some(connection.with(|state| Arc::clone(&state.connection))),
        };
        // `None` means the connection itself is closed; there is nothing left
        // to route to and the child is on its way out.
        let Some(target) = target else { return };
        if target.is_closed() {
            connection
                .counters
                .messages_dropped_on_closed_stream
                .fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if target.tx.send(Bytes::from(message.compact)).await.is_err() {
            target.close();
            connection
                .counters
                .streams_lost
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Drain one stream's queue into its SSE body, framing each message.
async fn pump_stream(
    mut queue: mpsc::Receiver<Bytes>,
    sender: StreamSender,
    counters: Arc<Counters>,
    shutdown: CancellationToken,
) {
    loop {
        let compact = tokio::select! {
            () = shutdown.cancelled() => {
                // A connection that ended while a stream was open fails the
                // body rather than ending it cleanly: `docs/acp.md` refuses to
                // let a broken ACP stream look like an orderly one.
                sender.fail(StreamFailure::Interrupted).await;
                return;
            }
            message = queue.recv() => message,
        };
        let Some(compact) = compact else {
            // The queue ended.  **Which ending that is depends on why**, and
            // the two must not be confused: a connection that was closed ends
            // its targets and then drops them, so the queue running dry *after*
            // the shutdown signal is a broken stream, not an orderly one. A
            // `select!` that happened to pick this branch first would otherwise
            // deliver a clean end of stream for a transport that failed.
            if shutdown.is_cancelled() {
                sender.fail(StreamFailure::Interrupted).await;
            }
            return;
        };
        let event = sse_event(&compact);
        counters.sse_events.fetch_add(1, Ordering::Relaxed);
        counters
            .sse_bytes
            .fetch_add(event.len() as u64, Ordering::Relaxed);
        if sender.send(event).await.is_err() {
            return;
        }
    }
}

/// Read the clock and expire a subscription that never arrived.
///
/// The deadline is **measured**, not assumed: the elapsed time it actually ran
/// is recorded with the bound it exceeded, so a test reads what happened
/// rather than the constant it was configured with.
async fn watch_deadlines(export: AcpExport, connection: Arc<Connection>) {
    let bound = connection.subscribe_deadline;
    let bound_us = u64::try_from(bound.as_micros()).unwrap_or(u64::MAX);
    let mut ticker = tokio::time::interval(WATCHDOG_TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = connection.shutdown.cancelled() => return,
            // **A child that is gone ends its transport.** `docs/acp.md`: "A
            // child crash closes the transport and invalidates live sessions."
            // This task used to simply return here, which left the connection
            // in the export's map with a dead child behind it until someone
            // sent a DELETE, and left every open stream hanging without an
            // ending. A child can end for reasons that are the profile's own —
            // a batch, a malformed line, an oversized line, each of which kills
            // it by its own `AcpRule` — so this is the path those refusals
            // reach the host on.
            () = connection.supervisor.wait_exited() => {
                end_with_child(&export, &connection).await;
                return;
            }
            _ = ticker.tick() => {}
        }
        let target = connection.with(|state| Arc::clone(&state.connection));
        if !target.is_subscribed() && target.created.elapsed() > bound {
            let elapsed = u64::try_from(target.created.elapsed().as_micros()).unwrap_or(u64::MAX);
            // The measurement is published **before** the counter that makes it
            // findable. A reader that sees the count and then reads a stale
            // elapsed would compare 0 against 0 and pass; that is not the
            // observation this is for.
            connection
                .counters
                .last_expiry_elapsed_us
                .store(elapsed, Ordering::Relaxed);
            connection
                .counters
                .last_expiry_bound_us
                .store(bound_us, Ordering::Relaxed);
            connection
                .counters
                .connection_subscribe_expired
                .fetch_add(1, Ordering::Release);
            export.remove(&connection.id);
            close_connection(&connection).await;
            return;
        }
        let expired: Vec<Arc<Target>> = connection.with(|state| {
            state
                .sessions
                .values()
                .filter(|target| !target.is_subscribed() && target.created.elapsed() > bound)
                .cloned()
                .collect()
        });
        for target in expired {
            let elapsed = u64::try_from(target.created.elapsed().as_micros()).unwrap_or(u64::MAX);
            // Published before the counter, for the reason above.
            connection
                .counters
                .last_expiry_elapsed_us
                .store(elapsed, Ordering::Relaxed);
            connection
                .counters
                .last_expiry_bound_us
                .store(bound_us, Ordering::Relaxed);
            connection
                .counters
                .session_subscribe_expired
                .fetch_add(1, Ordering::Release);
            // Closing the target is what stops a later GET from subscribing to
            // a session whose window has closed: the same mechanism as the
            // one-subscriber rule, so an expired session answers 409 and never
            // silently reopens.
            target.close();
        }
    }
}

/// End a connection because its child did, folding the child's own refusal
/// counters in first so they outlive the connection that carried them.
async fn end_with_child(export: &AcpExport, connection: &Arc<Connection>) {
    let child = connection.supervisor.diagnostics();
    connection
        .counters
        .child_batch_output
        .fetch_add(child.batch_output, Ordering::Relaxed);
    connection
        .counters
        .child_invalid_output
        .fetch_add(child.invalid_output, Ordering::Relaxed);
    // Published before the counter a reader waits on, for the same reason the
    // deadline measurements are.
    connection
        .counters
        .connections_ended_by_child
        .fetch_add(1, Ordering::Release);
    export.remove(&connection.id);
    close_connection(connection).await;
}

async fn close_connection(connection: &Arc<Connection>) {
    connection.with(|state| {
        state.closed = true;
        state.connection.close();
        for target in state.sessions.values() {
            target.close();
        }
    });
    // Every open body is failed rather than ended cleanly: `docs/acp.md`
    // refuses to let a broken ACP stream look like an orderly one, so a
    // consumer sees an error and not an end of stream.
    connection.shutdown.cancel();
    connection.supervisor.drain().await;
}

fn not_found() -> Response<ExportBody> {
    json_response(
        StatusCode::NOT_FOUND,
        Bytes::from_static(b"{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32001,\"message\":\"no such connection or session\"},\"id\":null}"),
    )
}

/// The HTTP answer for a lifecycle refusal.
///
/// A refusal is a *bridge* outcome and may terminate on a status: nothing was
/// dispatched to an agent, so there is no later message for it to anchor to.
/// The claims that must not terminate on a status are the ones about a prompt,
/// a session or a permission having happened.
fn supervisor_refusal(error: &SupervisorError) -> Response<ExportBody> {
    let (status, code) = match error.rule() {
        Some(LifecycleRule::UnknownRequestId | LifecycleRule::UnknownSession) => {
            (StatusCode::NOT_FOUND, -32001)
        }
        Some(LifecycleRule::SessionLimit | LifecycleRule::PendingLimit) => {
            (StatusCode::TOO_MANY_REQUESTS, -32002)
        }
        Some(_) => (StatusCode::CONFLICT, -32003),
        None => (StatusCode::SERVICE_UNAVAILABLE, -32603),
    };
    let body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": Value::Null,
        "error": {"code": code, "message": error.to_string()},
    }))
    .unwrap_or_default();
    json_response(status, Bytes::from(body))
}

fn header(headers: &http::HeaderMap, name: &str) -> Option<String> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    first
        .to_str()
        .ok()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// The opaque per-principal binding the relay ingress derived, or `None`.
///
/// The device never interprets the value and never derives one: it compares it
/// for equality with the value the connection was opened with.  A deployment
/// with no relay ingress in front of the export — every test in this chunk —
/// has no authenticated principal at all, so every request carries `None`,
/// which binds a connection to "no principal" and still refuses any other
/// value.  This is the same sentence `tunnel_mcp_export` records for M3-04,
/// and it is deliberately not a claim of principal binding.
fn principal_binding(headers: &http::HeaderMap) -> Option<String> {
    header(headers, tunnel_acp::headers::TUNNEL_PRINCIPAL_BINDING)
}

fn request_id(value: &Value) -> Option<RequestId> {
    match value {
        Value::String(text) => Some(RequestId::Text(text.clone())),
        Value::Number(number) => number.as_i64().map(RequestId::Number),
        _ => None,
    }
}

fn permission_outcome(message: &Value) -> Option<PermissionOutcome> {
    let outcome = message.pointer("/result/outcome")?;
    match outcome.get("outcome").and_then(Value::as_str)? {
        "selected" => outcome
            .get("optionId")
            .and_then(Value::as_str)
            .map(|option| PermissionOutcome::Selected(option.to_owned())),
        "cancelled" => Some(PermissionOutcome::Cancelled),
        _ => None,
    }
}

/// The agent's `initialize` result must negotiate version 1.
fn check_result_version(result: &Value) -> Result<(), AcpRejection> {
    let Some(version) = result.get("protocolVersion") else {
        return Err(AcpRejection::new(
            AcpRule::ProtocolVersionShape,
            "protocolVersion is required",
        ));
    };
    tunnel_acp::message::negotiate_protocol_version(version).map(|_| ())
}

async fn collect_limited(body: ChannelBody, limit: u64) -> Result<Bytes, ()> {
    use http_body_util::BodyExt;
    let mut body = std::pin::pin!(body);
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| ())?;
        if let Ok(data) = frame.into_data() {
            if (out.len() as u64).saturating_add(data.len() as u64) > limit {
                return Err(());
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(Bytes::from(out))
}
