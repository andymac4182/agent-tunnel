//! The stdio export: an in-process Streamable HTTP handler bridging to a
//! supervised MCP child process.
//!
//! The bridge forwards raw JSON-RPC messages.  A request's compact bytes are
//! written to the child exactly (IDs, `_meta` and unknown fields intact), and
//! each child stdout line is forwarded as one SSE `data` event or as the
//! complete `application/json` body, never re-serialized.
//!
//! **2026-07-28** (no protocol sessions).  Every POSTed JSON-RPC request gets
//! its own child process, so request IDs, notifications and progress of
//! different requests or consumers can never cross.  If the child's first
//! message is the final response it is returned as `application/json`;
//! otherwise the response is an SSE stream of the child's notifications
//! followed by the final response.  A child request on that stream, a
//! response for another ID, a crash, invalid output or an oversized message
//! interrupts the exchange (never a fabricated JSON-RPC result, never a
//! replay).  Closing the response stream is cancellation: the bridge writes
//! `notifications/cancelled` with the request ID to the child, allows
//! [`CANCEL_GRACE`] and kills it.  Client notifications and responses have
//! no per-request child to reach and are refused with 400.
//!
//! **2025-11-25** (sessions).  `initialize` without `Mcp-Session-Id` starts
//! one child and one session, identified by a random 128-bit ID returned in
//! `Mcp-Session-Id`.  Requests are routed back to their POST by ID;
//! notifications carrying the request's `progressToken` follow it; every
//! other server message (logging, list changes, server requests) goes to the
//! single standalone GET stream, or waits in a bounded backlog until one
//! opens.  A disconnect is not cancellation in this revision: the client
//! POSTs `notifications/cancelled`, which is forwarded unchanged.  DELETE
//! kills the child.  A child crash ends the session: open streams are
//! interrupted and later requests get 404.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;
use tunnel_http_bridge::{ChannelBody, HandlerCancellation};
use tunnel_mcp::message::{
    McpMessage, McpRejection, MessageKind, codes, validate_delete, validate_get, validate_post,
};
use tunnel_mcp::{McpLimits, McpProfile, headers};

use crate::body::{
    ChannelResponseBody, CollectError, ExportBody, StreamFailure, collect_limited, json_response,
    local_error, no_body, rejection, sse_event, sse_head,
};
use crate::child::{self, ChildCounters, ChildEvent, ChildHandle};
use crate::config::StdioBackend;
use crate::{ExportCounters, ExportError};

/// How long a cancelled 2026 child may keep running after
/// `notifications/cancelled` before it is killed.
pub const CANCEL_GRACE: Duration = Duration::from_secs(1);
/// Server messages kept for a legacy session without a GET stream.
pub const MAX_BACKLOG_MESSAGES: usize = 64;

/// What a request's response stream receives.
#[derive(Debug)]
enum Routed {
    Interim(Bytes),
    Final(Bytes),
    Ended,
}

fn id_key(id: &Value) -> String {
    serde_json::to_string(id).unwrap_or_default()
}

fn cancelled_notification(id: &Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": { "requestId": id, "reason": "the consumer closed the response stream" }
    }))
    .unwrap_or_default()
}

/// Runs its action exactly once: `true` when the request completed (or the
/// child already ended), `false` when it was abandoned.
struct RequestGuard {
    action: Option<Box<dyn FnOnce(bool) + Send>>,
}

impl RequestGuard {
    fn new(action: impl FnOnce(bool) + Send + 'static) -> Self {
        Self {
            action: Some(Box::new(action)),
        }
    }

    fn complete(&mut self) {
        if let Some(action) = self.action.take() {
            action(true);
        }
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if let Some(action) = self.action.take() {
            action(false);
        }
    }
}

/// A validated stdio export.
pub struct StdioExport {
    profile: McpProfile,
    limits: McpLimits,
    backend: StdioBackend,
    counters: Arc<ExportCounters>,
    slots: Arc<Semaphore>,
    sessions: Arc<Mutex<HashMap<String, Arc<Session>>>>,
}

impl std::fmt::Debug for StdioExport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StdioExport")
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

fn cancellation(request: &Request<ChannelBody>) -> CancellationToken {
    request
        .extensions()
        .get::<HandlerCancellation>()
        .map(|cancel| cancel.0.clone())
        .unwrap_or_default()
}

impl StdioExport {
    pub(crate) fn new(
        profile: McpProfile,
        limits: McpLimits,
        backend: StdioBackend,
        counters: Arc<ExportCounters>,
    ) -> Self {
        let slots = Arc::new(Semaphore::new(backend.max_children));
        Self {
            profile,
            limits,
            backend,
            counters,
            slots,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn child_counters(&self) -> &Arc<ChildCounters> {
        &self.counters.children
    }

    fn reject(&self, rejection_value: &McpRejection) -> Response<ExportBody> {
        self.counters.rejected.fetch_add(1, Ordering::Relaxed);
        rejection(rejection_value)
    }

    /// Serve one exchange.
    ///
    /// # Errors
    /// [`ExportError`] when the exchange must be interrupted rather than
    /// answered (a child that ended after the request was written, a request
    /// body failure).
    pub async fn handle(
        self: Arc<Self>,
        request: Request<ChannelBody>,
    ) -> Result<Response<ExportBody>, ExportError> {
        let cancel = cancellation(&request);
        let (parts, body) = request.into_parts();
        match parts.method {
            Method::POST => {
                let body = match collect_limited(body, self.limits.request_body()).await {
                    Ok(body) => body,
                    Err(CollectError::TooLarge) => {
                        return Ok(self.reject(&McpRejection {
                            status: 413,
                            code: codes::INVALID_REQUEST,
                            message: "the request body exceeds the export limit",
                            id: None,
                            supported: None,
                        }));
                    }
                    Err(CollectError::Interrupted) => return Err(ExportError),
                };
                let message = match validate_post(self.profile, &parts.headers, &body) {
                    Ok(message) => message,
                    Err(error) => return Ok(self.reject(&error)),
                };
                match self.profile {
                    McpProfile::V2026_07_28 => self.post_current(message, cancel).await,
                    McpProfile::V2025_11_25 => {
                        self.post_legacy(&parts.headers, message, cancel).await
                    }
                }
            }
            Method::GET | Method::DELETE => {
                let checked = if parts.method == Method::GET {
                    validate_get(self.profile, &parts.headers)
                } else {
                    validate_delete(self.profile, &parts.headers)
                };
                if let Err(error) = checked {
                    return Ok(self.reject(&error));
                }
                match collect_limited(body, 0).await {
                    Ok(_) => {}
                    Err(CollectError::TooLarge) => {
                        return Ok(self.reject(&McpRejection {
                            status: 400,
                            code: codes::INVALID_REQUEST,
                            message: "GET and DELETE carry no body",
                            id: None,
                            supported: None,
                        }));
                    }
                    Err(CollectError::Interrupted) => return Err(ExportError),
                }
                if parts.method == Method::GET {
                    self.get_legacy(&parts.headers, cancel)
                } else {
                    Ok(self.delete_legacy(&parts.headers))
                }
            }
            _ => Ok(self.reject(&McpRejection {
                status: 405,
                code: codes::INVALID_REQUEST,
                message: "method not allowed",
                id: None,
                supported: None,
            })),
        }
    }

    // ---- 2026-07-28 ---------------------------------------------------------

    async fn post_current(
        self: &Arc<Self>,
        message: McpMessage,
        cancel: CancellationToken,
    ) -> Result<Response<ExportBody>, ExportError> {
        let (MessageKind::Request, Some(id)) = (message.kind, message.id.clone()) else {
            return Ok(self.reject(&McpRejection {
                status: 400,
                code: codes::INVALID_REQUEST,
                message: "this stdio export accepts JSON-RPC requests only",
                id: None,
                supported: None,
            }));
        };
        let Ok(permit) = Arc::clone(&self.slots).try_acquire_owned() else {
            return Ok(local_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "the export is at its child process limit",
                Some(id),
            ));
        };
        let Ok((child, events)) = child::spawn(
            &self.backend,
            self.limits.json_response_body(),
            self.child_counters(),
        ) else {
            // Nothing was started, so nothing can have run.
            return Ok(local_error(
                StatusCode::BAD_GATEWAY,
                "the MCP server process could not be started",
                Some(id),
            ));
        };
        if child.send(&message.compact).await.is_err() {
            return Err(ExportError);
        }
        let (routed_tx, routed_rx) = mpsc::channel(crate::body::STREAM_QUEUE);
        tokio::spawn(route_single(
            events,
            id_key(&id),
            routed_tx,
            child.kill_token(),
        ));
        let counters = Arc::clone(&self.counters);
        let guard = RequestGuard::new(move |completed| {
            finish_current_child(child, permit, id, completed, counters);
        });
        self.respond(routed_rx, cancel, guard, None).await
    }

    // ---- shared response streaming -------------------------------------------

    async fn respond(
        &self,
        mut routed: mpsc::Receiver<Routed>,
        cancel: CancellationToken,
        guard: RequestGuard,
        session: Option<HeaderValue>,
    ) -> Result<Response<ExportBody>, ExportError> {
        let first = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(ExportError),
            first = routed.recv() => first,
        };
        self.respond_with_first(first, routed, cancel, guard, session)
    }

    fn respond_with_first(
        &self,
        first: Option<Routed>,
        mut routed: mpsc::Receiver<Routed>,
        cancel: CancellationToken,
        mut guard: RequestGuard,
        session: Option<HeaderValue>,
    ) -> Result<Response<ExportBody>, ExportError> {
        let with_session = |mut response: Response<ExportBody>| {
            if let Some(session) = &session {
                response
                    .headers_mut()
                    .insert(headers::MCP_SESSION_ID, session.clone());
            }
            response
        };
        match first {
            None | Some(Routed::Ended) => {
                guard.complete();
                self.counters.interrupted.fetch_add(1, Ordering::Relaxed);
                Err(ExportError)
            }
            Some(Routed::Final(bytes)) => {
                guard.complete();
                self.counters.json_responses.fetch_add(1, Ordering::Relaxed);
                Ok(with_session(json_response(StatusCode::OK, bytes)))
            }
            Some(Routed::Interim(bytes)) => {
                let (sender, body) = ChannelResponseBody::channel(
                    self.limits.sse_response_body(),
                    Arc::clone(&self.counters.streamed_bytes),
                );
                let mut response = Response::new(body.boxed());
                sse_head(&mut response);
                self.counters.sse_responses.fetch_add(1, Ordering::Relaxed);
                let counters = Arc::clone(&self.counters);
                tokio::spawn(async move {
                    let mut guard = guard;
                    if sender.send(sse_event(&bytes)).await.is_err() {
                        return;
                    }
                    loop {
                        tokio::select! {
                            biased;
                            () = sender.closed() => return,
                            () = cancel.cancelled() => return,
                            next = routed.recv() => match next {
                                Some(Routed::Interim(bytes)) => {
                                    if sender.send(sse_event(&bytes)).await.is_err() {
                                        return;
                                    }
                                }
                                Some(Routed::Final(bytes)) => {
                                    if sender.send(sse_event(&bytes)).await.is_ok() {
                                        guard.complete();
                                    }
                                    return;
                                }
                                None | Some(Routed::Ended) => {
                                    guard.complete();
                                    counters.interrupted.fetch_add(1, Ordering::Relaxed);
                                    sender.fail(StreamFailure::Interrupted).await;
                                    return;
                                }
                            },
                        }
                    }
                });
                Ok(with_session(response))
            }
        }
    }

    // ---- 2025-11-25 ---------------------------------------------------------

    async fn post_legacy(
        self: &Arc<Self>,
        headers_map: &HeaderMap,
        message: McpMessage,
        cancel: CancellationToken,
    ) -> Result<Response<ExportBody>, ExportError> {
        let session_header = headers_map
            .get(headers::MCP_SESSION_ID)
            .and_then(|value| value.to_str().ok());
        if message.is_initialize() {
            if session_header.is_some() {
                return Ok(self.reject(&McpRejection {
                    status: 400,
                    code: codes::INVALID_REQUEST,
                    message: "initialize must not carry Mcp-Session-Id",
                    id: message.id.clone(),
                    supported: None,
                }));
            }
            return self.initialize_legacy(message, cancel).await;
        }
        let Some(session_id) = session_header else {
            return Ok(self.reject(&McpRejection {
                status: 400,
                code: codes::INVALID_REQUEST,
                message: "Mcp-Session-Id is required",
                id: message.id.clone(),
                supported: None,
            }));
        };
        let Some(session) = self.session(session_id) else {
            return Ok(self.reject(&McpRejection {
                status: 404,
                code: codes::INVALID_REQUEST,
                message: "session not found",
                id: message.id.clone(),
                supported: None,
            }));
        };
        match (message.kind, message.id.clone()) {
            (MessageKind::Request, Some(id)) => {
                let Some(routed) = session.register(&id, message.progress_token()) else {
                    return Ok(self.reject(&McpRejection {
                        status: 400,
                        code: codes::INVALID_REQUEST,
                        message: "a request with this id is already in flight",
                        id: Some(id),
                        supported: None,
                    }));
                };
                if session.child.send(&message.compact).await.is_err() {
                    session.unregister(&id_key(&id));
                    return Err(ExportError);
                }
                let key = id_key(&id);
                let guard_session = Arc::clone(&session);
                let guard = RequestGuard::new(move |_| guard_session.unregister(&key));
                let header = HeaderValue::from_str(&session.id).ok();
                self.respond(routed, cancel, guard, header).await
            }
            _ => {
                if session.child.send(&message.compact).await.is_err() {
                    return Err(ExportError);
                }
                Ok(no_body(StatusCode::ACCEPTED))
            }
        }
    }

    async fn initialize_legacy(
        self: &Arc<Self>,
        message: McpMessage,
        cancel: CancellationToken,
    ) -> Result<Response<ExportBody>, ExportError> {
        let id = message.id.clone().unwrap_or(Value::Null);
        let Ok(permit) = Arc::clone(&self.slots).try_acquire_owned() else {
            return Ok(local_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "the export is at its session limit",
                Some(id),
            ));
        };
        let Ok((child, events)) = child::spawn(
            &self.backend,
            self.limits.json_response_body(),
            self.child_counters(),
        ) else {
            return Ok(local_error(
                StatusCode::BAD_GATEWAY,
                "the MCP server process could not be started",
                Some(id),
            ));
        };
        let session_id = uuid::Uuid::new_v4().simple().to_string();
        let session = Arc::new(Session {
            id: session_id.clone(),
            child,
            router: Mutex::new(Router::default()),
            _slot: permit,
            backlog_limit: usize::try_from(self.limits.json_response_body()).unwrap_or(usize::MAX),
        });
        let Some(routed) = session.register(&id, message.progress_token()) else {
            return Err(ExportError);
        };
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(session_id.clone(), Arc::clone(&session));
        self.counters
            .sessions_opened
            .fetch_add(1, Ordering::Relaxed);
        tokio::spawn(run_session(
            Arc::clone(&session),
            events,
            Arc::clone(&self.sessions),
            Arc::clone(&self.counters),
        ));
        if session.child.send(&message.compact).await.is_err() {
            self.remove_session(&session_id);
            return Err(ExportError);
        }
        let key = id_key(&id);
        let guard_session = Arc::clone(&session);
        let guard = RequestGuard::new(move |_| guard_session.unregister(&key));
        let mut routed = routed;
        let first = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                self.remove_session(&session_id);
                return Err(ExportError);
            }
            first = routed.recv() => first,
        };
        // A failed initialize creates no session: its error is returned
        // without Mcp-Session-Id and the child is killed.
        let failed = match &first {
            Some(Routed::Final(bytes)) => serde_json::from_slice::<Value>(bytes)
                .map_or(true, |value| value.get("result").is_none()),
            None | Some(Routed::Ended) => true,
            Some(Routed::Interim(_)) => false,
        };
        let header = if failed {
            self.remove_session(&session_id);
            None
        } else {
            HeaderValue::from_str(&session_id).ok()
        };
        self.respond_with_first(first, routed, cancel, guard, header)
    }

    fn get_legacy(
        &self,
        headers_map: &HeaderMap,
        cancel: CancellationToken,
    ) -> Result<Response<ExportBody>, ExportError> {
        let Some(session) = headers_map
            .get(headers::MCP_SESSION_ID)
            .and_then(|value| value.to_str().ok())
            .and_then(|id| self.session(id))
        else {
            return Ok(self.reject(&McpRejection {
                status: 404,
                code: codes::INVALID_REQUEST,
                message: "session not found",
                id: None,
                supported: None,
            }));
        };
        let (stream_tx, mut stream_rx) = mpsc::channel(MAX_BACKLOG_MESSAGES + 1);
        if !session.open_standalone(&stream_tx) {
            return Ok(self.reject(&McpRejection {
                status: 409,
                code: codes::INVALID_REQUEST,
                message: "a standalone stream is already open for this session",
                id: None,
                supported: None,
            }));
        }
        let (sender, body) = ChannelResponseBody::channel(
            self.limits.sse_response_body(),
            Arc::clone(&self.counters.streamed_bytes),
        );
        let mut response = Response::new(body.boxed());
        sse_head(&mut response);
        if let Ok(value) = HeaderValue::from_str(&session.id) {
            response
                .headers_mut()
                .insert(headers::MCP_SESSION_ID, value);
        }
        drop(stream_tx);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    () = sender.closed() => break,
                    () = cancel.cancelled() => break,
                    next = stream_rx.recv() => match next {
                        Some(Routed::Interim(bytes) | Routed::Final(bytes)) => {
                            if sender.send(sse_event(&bytes)).await.is_err() {
                                break;
                            }
                        }
                        None | Some(Routed::Ended) => {
                            sender.fail(StreamFailure::Interrupted).await;
                            break;
                        }
                    },
                }
            }
            session.close_standalone();
        });
        Ok(response)
    }

    fn delete_legacy(&self, headers_map: &HeaderMap) -> Response<ExportBody> {
        let removed = headers_map
            .get(headers::MCP_SESSION_ID)
            .and_then(|value| value.to_str().ok())
            .and_then(|id| self.remove_session(id));
        match removed {
            Some(session) => {
                session.child.kill();
                no_body(StatusCode::NO_CONTENT)
            }
            None => self.reject(&McpRejection {
                status: 404,
                code: codes::INVALID_REQUEST,
                message: "session not found",
                id: None,
                supported: None,
            }),
        }
    }

    fn session(&self, id: &str) -> Option<Arc<Session>> {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(id)
            .cloned()
    }

    fn remove_session(&self, id: &str) -> Option<Arc<Session>> {
        let removed = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(id);
        if let Some(session) = &removed {
            session.child.kill();
        }
        removed
    }

    /// Open legacy sessions.
    #[must_use]
    pub fn open_sessions(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

fn finish_current_child(
    child: ChildHandle,
    permit: OwnedSemaphorePermit,
    id: Value,
    completed: bool,
    counters: Arc<ExportCounters>,
) {
    if completed {
        drop(child);
        drop(permit);
        return;
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    runtime.spawn(async move {
        if child.send(&cancelled_notification(&id)).await.is_ok() {
            counters
                .cancel_notifications_sent
                .fetch_add(1, Ordering::Relaxed);
        }
        let _ = tokio::time::timeout(CANCEL_GRACE, child.wait_exited()).await;
        drop(child);
        drop(permit);
    });
}

/// Classify one 2026 child's messages relative to its single request.
async fn route_single(
    mut events: mpsc::Receiver<ChildEvent>,
    key: String,
    routed: mpsc::Sender<Routed>,
    kill: CancellationToken,
) {
    while let Some(event) = events.recv().await {
        let next = match event {
            ChildEvent::Ended(_) => Routed::Ended,
            ChildEvent::Message(message) => {
                let has_method = message.value.get("method").is_some();
                let response_id = message.value.get("id");
                match (has_method, response_id) {
                    (true, None) => Routed::Interim(message.compact),
                    (false, Some(id)) if id_key(id) == key => Routed::Final(message.compact),
                    // A server request or a response for another ID is not
                    // allowed on a 2026 request stream.
                    _ => {
                        kill.cancel();
                        Routed::Ended
                    }
                }
            }
        };
        let last = !matches!(next, Routed::Interim(_));
        if routed.send(next).await.is_err() || last {
            return;
        }
    }
    let _ = routed.send(Routed::Ended).await;
}

// ---- legacy sessions -------------------------------------------------------

#[derive(Default)]
struct Router {
    pending: HashMap<String, mpsc::Sender<Routed>>,
    progress: HashMap<String, String>,
    standalone: Option<mpsc::Sender<Routed>>,
    backlog: VecDeque<Bytes>,
    backlog_bytes: usize,
    ended: bool,
}

struct Session {
    id: String,
    child: ChildHandle,
    router: Mutex<Router>,
    _slot: OwnedSemaphorePermit,
    backlog_limit: usize,
}

impl Session {
    fn router(&self) -> std::sync::MutexGuard<'_, Router> {
        self.router
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn register(&self, id: &Value, progress: Option<&Value>) -> Option<mpsc::Receiver<Routed>> {
        let key = id_key(id);
        let mut router = self.router();
        if router.ended || router.pending.contains_key(&key) {
            return None;
        }
        let (tx, rx) = mpsc::channel(crate::body::STREAM_QUEUE);
        router.pending.insert(key.clone(), tx);
        if let Some(token) = progress {
            router.progress.insert(id_key(token), key);
        }
        Some(rx)
    }

    fn unregister(&self, key: &str) {
        let mut router = self.router();
        router.pending.remove(key);
        router.progress.retain(|_, request| request != key);
    }

    fn open_standalone(&self, stream: &mpsc::Sender<Routed>) -> bool {
        let mut router = self.router();
        if router.ended
            || router
                .standalone
                .as_ref()
                .is_some_and(|open| !open.is_closed())
        {
            return false;
        }
        while let Some(bytes) = router.backlog.pop_front() {
            if stream.try_send(Routed::Interim(bytes)).is_err() {
                break;
            }
        }
        router.backlog_bytes = 0;
        router.standalone = Some(stream.clone());
        true
    }

    fn close_standalone(&self) {
        let mut router = self.router();
        if router
            .standalone
            .as_ref()
            .is_some_and(mpsc::Sender::is_closed)
        {
            router.standalone = None;
        }
    }
}

enum Destination {
    Request(mpsc::Sender<Routed>, bool),
    Standalone(mpsc::Sender<Routed>),
    Backlogged,
    Overflow,
    Dropped,
}

async fn run_session(
    session: Arc<Session>,
    mut events: mpsc::Receiver<ChildEvent>,
    sessions: Arc<Mutex<HashMap<String, Arc<Session>>>>,
    counters: Arc<ExportCounters>,
) {
    while let Some(event) = events.recv().await {
        let ChildEvent::Message(message) = event else {
            break;
        };
        let destination = {
            let mut router = session.router();
            let has_method = message.value.get("method").is_some();
            let id = message.value.get("id");
            if let (false, Some(id)) = (has_method, id) {
                let key = id_key(id);
                router.progress.retain(|_, request| *request != key);
                match router.pending.remove(&key) {
                    Some(sender) => Destination::Request(sender, true),
                    None => Destination::Dropped,
                }
            } else {
                let token = message
                    .value
                    .get("params")
                    .and_then(|params| params.get("progressToken"))
                    .map(id_key);
                let request = token
                    .as_ref()
                    .filter(|_| id.is_none())
                    .and_then(|token| router.progress.get(token))
                    .and_then(|key| router.pending.get(key))
                    .cloned();
                if let Some(sender) = request {
                    Destination::Request(sender, false)
                } else if let Some(standalone) =
                    router.standalone.clone().filter(|open| !open.is_closed())
                {
                    Destination::Standalone(standalone)
                } else if router.backlog.len() < MAX_BACKLOG_MESSAGES
                    && router.backlog_bytes.saturating_add(message.compact.len())
                        <= session.backlog_limit
                {
                    router.backlog_bytes += message.compact.len();
                    router.backlog.push_back(message.compact.clone());
                    Destination::Backlogged
                } else {
                    Destination::Overflow
                }
            }
        };
        match destination {
            Destination::Request(sender, is_final) => {
                let routed = if is_final {
                    Routed::Final(message.compact)
                } else {
                    Routed::Interim(message.compact)
                };
                if sender.send(routed).await.is_err() {
                    counters.undeliverable.fetch_add(1, Ordering::Relaxed);
                }
            }
            Destination::Standalone(sender) => {
                if sender.send(Routed::Interim(message.compact)).await.is_err() {
                    counters.undeliverable.fetch_add(1, Ordering::Relaxed);
                }
            }
            Destination::Backlogged => {}
            Destination::Dropped => {
                counters.undeliverable.fetch_add(1, Ordering::Relaxed);
            }
            Destination::Overflow => {
                counters.undeliverable.fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
    }
    // The child ended (or overflowed): interrupt every stream, end the
    // session and kill the process.
    let (pending, standalone) = {
        let mut router = session.router();
        router.ended = true;
        router.progress.clear();
        (
            router
                .pending
                .drain()
                .map(|(_, sender)| sender)
                .collect::<Vec<_>>(),
            router.standalone.take(),
        )
    };
    for sender in pending.into_iter().chain(standalone) {
        let _ = sender.send(Routed::Ended).await;
    }
    sessions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&session.id);
    session.child.kill();
    counters.sessions_ended.fetch_add(1, Ordering::Relaxed);
}
