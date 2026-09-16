//! The Streamable HTTP export: transparent forwarding to one fixed,
//! operator-configured loopback MCP server.
//!
//! * The target address, `Host`, path and backend credential come only from
//!   configuration.  The consumer's request contributes a method that its
//!   profile routes allow, the validated profile headers and the validated
//!   body; nothing in it can select a host, port, proxy or path.
//! * The complete bounded body is validated ([`tunnel_mcp::message`]) before
//!   the backend is dialled.
//! * `Accept-Encoding: identity` is always sent and any other response
//!   `Content-Encoding` is refused, so byte limits count real bytes.
//! * Redirects are never followed: a 3xx is a local 502.  A backend 401, 403
//!   or 407 is a local 502 as well, so a private `WWW-Authenticate`
//!   challenge never reaches the consumer as if it were relay login.
//! * Response headers are reduced to the profile's response allowlist; the
//!   body streams with the JSON or SSE cumulative limit by content type.
//! * Dropping the response body closes the backend connection, which is the
//!   2026-07-28 cancellation signal; for 2025-11-25 it is a plain disconnect,
//!   exactly what the consumer did.
//! * A failure before the request is written is a sanitized 502 JSON-RPC
//!   error (the backend was not invoked); a failure after it was written is
//!   an interruption with no fabricated JSON-RPC result.
//! * M3-04: the backend owns `mcp-2025-11-25` session identifiers, but the
//!   device owns who may use one.  This export remembers the opaque
//!   `tunnel-principal-binding` each session was issued to and refuses any
//!   other principal — and any session it did not see issued — as an unknown
//!   session, before the backend is dialled.  The binding itself is
//!   relay-to-device metadata and is never forwarded upstream.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tunnel_http_bridge::ChannelBody;
use tunnel_mcp::message::{McpRejection, codes, validate_delete, validate_get, validate_post};
use tunnel_mcp::{McpLimits, McpProfile};

use crate::body::{
    BoxError, CollectError, ExportBody, StreamFailure, collect_limited, local_error, rejection,
};
use crate::config::{HttpBackend, McpConfigError};
use crate::{ExportCounters, ExportError};

/// Bound on dialling the fixed backend.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// The longest accepted bearer token file.
pub const MAX_TOKEN_BYTES: usize = 8192;
/// Backend-issued `mcp-2025-11-25` sessions whose principal binding this
/// export tracks at once.
pub const MAX_TRACKED_SESSIONS: usize = 256;
/// Sessions one principal may hold at once.  One principal therefore cannot
/// fill the table, and a new `initialize` is refused before the backend is
/// dialled instead of evicting somebody else's live session.
pub const MAX_SESSIONS_PER_BINDING: usize = MAX_TRACKED_SESSIONS / 8;

/// Principal bindings for the sessions a Streamable HTTP backend issued
/// through this export (M3-04).  The backend owns the session identifiers;
/// the device owns which principal may use them.
///
/// Nothing here ever evicts another principal's entry.  An earlier revision
/// dropped the oldest binding when the table filled, which let any authorized
/// principal evict every other principal's live session — a cross-principal
/// denial channel — by opening 257 sessions.  Capacity is now refused at the
/// door, and entries leave only when their own session does: a successful
/// DELETE, or a backend that answers 404 for it.
#[derive(Debug, Default)]
struct SessionBindings {
    bindings: std::collections::HashMap<String, Option<String>>,
}

impl SessionBindings {
    /// Whether `binding` may use `session`.  An unknown session is refused.
    fn permits(&self, session: &str, binding: Option<&String>) -> bool {
        self.bindings
            .get(session)
            .is_some_and(|known| known.as_ref() == binding)
    }

    fn held_by(&self, binding: Option<&String>) -> usize {
        self.bindings
            .values()
            .filter(|known| known.as_ref() == binding)
            .count()
    }

    /// Whether one more session may be opened for `binding`.
    fn has_room_for(&self, binding: Option<&String>) -> bool {
        self.bindings.len() < MAX_TRACKED_SESSIONS
            && self.held_by(binding) < MAX_SESSIONS_PER_BINDING
    }

    /// Record a session the backend issued.  Refuses silently when the table
    /// or the principal's share is full, which fails closed: the session is
    /// unusable through this export and the client re-initializes.
    fn remember(&mut self, session: String, binding: Option<String>) {
        if self.bindings.contains_key(&session) || !self.has_room_for(binding.as_ref()) {
            return;
        }
        self.bindings.insert(session, binding);
    }

    fn forget(&mut self, session: &str) {
        self.bindings.remove(session);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.bindings.len()
    }
}

/// A validated Streamable HTTP export.
pub struct HttpBackendExport {
    profile: McpProfile,
    limits: McpLimits,
    backend: HttpBackend,
    authorization: Option<HeaderValue>,
    counters: Arc<ExportCounters>,
    sessions: std::sync::Mutex<SessionBindings>,
}

impl std::fmt::Debug for HttpBackendExport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpBackendExport")
            .field("profile", &self.profile)
            .field("credential", &self.authorization.is_some())
            .finish_non_exhaustive()
    }
}

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The backend response body: counted, limited, and owning the connection.
struct BackendBody {
    inner: Incoming,
    limit: u64,
    sent: u64,
    failed: bool,
    counter: Arc<AtomicU64>,
    _connection: AbortOnDrop,
}

impl Body for BackendBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.failed {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(_))) => {
                self.failed = true;
                Poll::Ready(Some(Err(Box::new(StreamFailure::Interrupted))))
            }
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    let sent = self.sent.saturating_add(data.len() as u64);
                    if sent > self.limit {
                        self.failed = true;
                        return Poll::Ready(Some(Err(Box::new(StreamFailure::Limit))));
                    }
                    self.sent = sent;
                    self.counter.fetch_add(data.len() as u64, Ordering::Relaxed);
                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
                Err(frame) => {
                    // Non-empty trailers are refused by the bridge; pass the
                    // frame on so it decides.
                    Poll::Ready(Some(Ok(frame)))
                }
            },
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

impl HttpBackendExport {
    pub(crate) fn new(
        profile: McpProfile,
        limits: McpLimits,
        backend: HttpBackend,
        counters: Arc<ExportCounters>,
    ) -> Result<Self, McpConfigError> {
        const TOKEN_RULE: &str =
            "mcp.backend.bearer_token_file must hold one visible-ASCII token of at most 8192 bytes";
        let authorization = match &backend.bearer_token_file {
            None => None,
            Some(path) => {
                let text = std::fs::read(path).map_err(|_| McpConfigError(TOKEN_RULE))?;
                let token = std::str::from_utf8(&text)
                    .map_err(|_| McpConfigError(TOKEN_RULE))?
                    .trim_end_matches(['\n', '\r']);
                if token.is_empty()
                    || token.len() > MAX_TOKEN_BYTES
                    || !token.bytes().all(|byte| byte.is_ascii_graphic())
                {
                    return Err(McpConfigError(TOKEN_RULE));
                }
                let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
                    .map_err(|_| McpConfigError(TOKEN_RULE))?;
                value.set_sensitive(true);
                Some(value)
            }
        };
        Ok(Self {
            profile,
            limits,
            backend,
            authorization,
            counters,
            sessions: std::sync::Mutex::new(SessionBindings::default()),
        })
    }

    fn sessions(&self) -> std::sync::MutexGuard<'_, SessionBindings> {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn reject(&self, value: &McpRejection) -> Response<ExportBody> {
        self.counters.rejected.fetch_add(1, Ordering::Relaxed);
        rejection(value)
    }

    fn backend_error(&self, status: StatusCode, message: &'static str) -> Response<ExportBody> {
        self.counters.backend_errors.fetch_add(1, Ordering::Relaxed);
        local_error(status, message, None)
    }

    /// Serve one exchange.
    ///
    /// # Errors
    /// [`ExportError`] when the backend may have received the request but no
    /// response head was obtained, or the request body failed.
    pub async fn handle(
        self: Arc<Self>,
        request: Request<ChannelBody>,
    ) -> Result<Response<ExportBody>, ExportError> {
        let (parts, body) = request.into_parts();
        let limit = if parts.method == Method::POST {
            self.limits.request_body()
        } else {
            0
        };
        let checked = match parts.method {
            Method::POST => Ok(()),
            Method::GET => validate_get(self.profile, &parts.headers),
            Method::DELETE => validate_delete(self.profile, &parts.headers),
            _ => Err(McpRejection {
                status: 405,
                code: codes::INVALID_REQUEST,
                message: "method not allowed",
                id: None,
                supported: None,
            }),
        };
        if let Err(error) = checked {
            return Ok(self.reject(&error));
        }
        let body = match collect_limited(body, limit).await {
            Ok(body) => body,
            Err(CollectError::TooLarge) => {
                return Ok(self.reject(&McpRejection {
                    status: if limit == 0 { 400 } else { 413 },
                    code: codes::INVALID_REQUEST,
                    message: "the request body exceeds the export limit",
                    id: None,
                    supported: None,
                }));
            }
            Err(CollectError::Interrupted) => return Err(ExportError),
        };
        if parts.method == Method::POST
            && let Err(error) = validate_post(self.profile, &parts.headers, &body)
        {
            return Ok(self.reject(&error));
        }

        // M3-04.  This revision's sessions belong to the backend, but which
        // principal may use one is the device's decision: a request naming a
        // session this export did not see opened for exactly this principal
        // binding is answered as an unknown session, before the backend is
        // dialled, so nothing is dispatched and nothing distinguishes a
        // foreign session from a nonexistent one.
        let binding = crate::request_principal_binding(&parts.headers);
        let named_session = parts
            .headers
            .get(tunnel_mcp::headers::MCP_SESSION_ID)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        if self.profile.is_legacy() {
            match &named_session {
                Some(session) if !self.sessions().permits(session, binding.as_ref()) => {
                    return Ok(self.reject(&McpRejection {
                        status: 404,
                        code: codes::INVALID_REQUEST,
                        message: "session not found",
                        id: None,
                        supported: None,
                    }));
                }
                // A POST naming no session opens one.  Capacity is decided
                // here, before the backend is dialled, so a full table
                // refuses the newcomer instead of evicting somebody else's
                // live session, and so the backend never creates a session
                // this export could not track.
                None if parts.method == Method::POST
                    && !self.sessions().has_room_for(binding.as_ref()) =>
                {
                    return Ok(local_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "the export is at its session limit",
                        None,
                    ));
                }
                _ => {}
            }
        }

        let mut upstream = Request::builder()
            .method(parts.method.clone())
            .uri(self.backend.path.as_str());
        for (name, value) in &parts.headers {
            // The codec already reduced the head to the profile allowlist;
            // copy exactly those fields and nothing the export sets itself.
            // The principal binding is relay-to-device metadata and is never
            // forwarded: the backend authenticates nobody.
            if name.as_str() == tunnel_mcp::headers::TUNNEL_PRINCIPAL_BINDING
                || name == http::header::HOST
                || name == http::header::ACCEPT_ENCODING
                || name == http::header::AUTHORIZATION
                || name == http::header::CONTENT_LENGTH
            {
                continue;
            }
            upstream = upstream.header(name, value);
        }
        upstream = upstream
            .header(http::header::HOST, self.backend.authority.as_str())
            .header(http::header::ACCEPT_ENCODING, "identity");
        if let Some(authorization) = &self.authorization {
            upstream = upstream.header(http::header::AUTHORIZATION, authorization.clone());
        }
        let Ok(upstream) = upstream.body(http_body_util::Full::new(body)) else {
            return Ok(self.backend_error(
                StatusCode::BAD_GATEWAY,
                "the MCP backend request could not be built",
            ));
        };

        let Ok(Ok(stream)) =
            tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(self.backend.address)).await
        else {
            return Ok(
                self.backend_error(StatusCode::BAD_GATEWAY, "the MCP backend is unavailable")
            );
        };
        let Ok((mut sender, connection)) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await
        else {
            return Ok(
                self.backend_error(StatusCode::BAD_GATEWAY, "the MCP backend is unavailable")
            );
        };
        let connection = AbortOnDrop(tokio::spawn(async move {
            let _ = connection.await;
        }));
        self.counters.dispatched.fetch_add(1, Ordering::Relaxed);
        let Ok(response) = sender.send_request(upstream).await else {
            self.counters.interrupted.fetch_add(1, Ordering::Relaxed);
            return Err(ExportError);
        };
        let status = response.status();
        if status.is_redirection() {
            return Ok(self.backend_error(
                StatusCode::BAD_GATEWAY,
                "the MCP backend redirected; redirects are not followed",
            ));
        }
        if matches!(
            status,
            StatusCode::UNAUTHORIZED
                | StatusCode::FORBIDDEN
                | StatusCode::PROXY_AUTHENTICATION_REQUIRED
        ) {
            return Ok(self.backend_error(
                StatusCode::BAD_GATEWAY,
                "the MCP backend refused the device credential",
            ));
        }
        if status.is_informational() || status == StatusCode::SWITCHING_PROTOCOLS {
            return Ok(self.backend_error(
                StatusCode::BAD_GATEWAY,
                "the MCP backend switched protocols",
            ));
        }
        let upstream_headers = response.headers();
        if upstream_headers
            .get_all(http::header::CONTENT_ENCODING)
            .iter()
            .any(|value| !value.as_bytes().eq_ignore_ascii_case(b"identity"))
        {
            return Ok(self.backend_error(
                StatusCode::BAD_GATEWAY,
                "the MCP backend used an unsupported content encoding",
            ));
        }
        let is_sse = upstream_headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("text/event-stream"))
            });
        let body_limit = if is_sse {
            self.limits.sse_response_body()
        } else {
            self.limits.json_response_body()
        };
        let declared = upstream_headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if declared.is_some_and(|length| length > body_limit) {
            return Ok(self.backend_error(
                StatusCode::BAD_GATEWAY,
                "the MCP backend response exceeds the export limit",
            ));
        }
        if self.profile.is_legacy() {
            // A session the backend issues on a successful exchange belongs
            // to the principal that opened it, and a successful DELETE ends
            // it.  Nothing is recorded for a failed exchange.
            let issued = upstream_headers
                .get(tunnel_mcp::headers::MCP_SESSION_ID)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            match (&named_session, status) {
                // Only the exchange that opened a session binds it.  A
                // backend that echoes some other identifier on a later
                // request cannot bind it to this caller.
                (None, status) if status.is_success() => {
                    if let Some(session) = issued {
                        self.sessions().remember(session, binding.clone());
                    }
                }
                // The session this request named is gone: a successful
                // DELETE ended it, and a 404 says the backend expired it.
                // Forgetting it is what keeps the table from filling with
                // sessions no one can use.
                (Some(session), status)
                    if (status.is_success() && parts.method == Method::DELETE)
                        || status == StatusCode::NOT_FOUND =>
                {
                    self.sessions().forget(session);
                }
                _ => {}
            }
        }
        let mut out = Response::builder().status(status);
        for (name, _) in self.profile.response_headers() {
            let mut values = upstream_headers.get_all(*name).iter();
            if let Some(value) = values.next() {
                if values.next().is_some() {
                    return Ok(self.backend_error(
                        StatusCode::BAD_GATEWAY,
                        "the MCP backend repeated a singleton response header",
                    ));
                }
                if !value
                    .as_bytes()
                    .iter()
                    .all(|byte| *byte == b'\t' || (0x20..0x7f).contains(byte))
                {
                    return Ok(self.backend_error(
                        StatusCode::BAD_GATEWAY,
                        "the MCP backend sent an invalid response header",
                    ));
                }
                out = out.header(*name, value.clone());
            }
        }
        let zero_body = matches!(
            status,
            StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::NOT_MODIFIED
        );
        let body: ExportBody = if zero_body {
            drop(response);
            drop(connection);
            crate::body::empty()
        } else {
            BackendBody {
                inner: response.into_body(),
                limit: body_limit,
                sent: 0,
                failed: false,
                counter: Arc::clone(&self.counters.streamed_bytes),
                _connection: connection,
            }
            .boxed()
        };
        out.body(body).map_err(|_| ExportError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(label: &str) -> Option<String> {
        Some(label.to_owned())
    }

    /// M3-04 review: opening sessions must never cost another principal its
    /// own.  An earlier revision evicted the oldest entry when the table
    /// filled, so any authorized principal could drop every other
    /// principal's live session by opening `MAX_TRACKED_SESSIONS + 1`.
    #[test]
    fn one_principal_cannot_evict_another_by_opening_sessions() {
        let mut sessions = SessionBindings::default();
        let victim = binding("victim");
        sessions.remember("victim-session".into(), victim.clone());
        assert!(sessions.permits("victim-session", victim.as_ref()));

        // The attacker exhausts its own share, then the whole table.
        let attacker = binding("attacker");
        for index in 0..MAX_TRACKED_SESSIONS * 2 {
            sessions.remember(format!("attacker-{index}"), attacker.clone());
        }
        assert_eq!(
            sessions.held_by(attacker.as_ref()),
            MAX_SESSIONS_PER_BINDING
        );
        assert!(!sessions.has_room_for(attacker.as_ref()));
        // The victim's session is untouched, and the victim can still open
        // one: a principal's own share is not consumed by anybody else.
        assert!(sessions.permits("victim-session", victim.as_ref()));
        assert!(sessions.has_room_for(victim.as_ref()));
        assert!(sessions.len() <= MAX_TRACKED_SESSIONS);
    }

    /// The table is bounded, and a full table refuses the newcomer.
    #[test]
    fn a_full_table_refuses_instead_of_evicting() {
        let mut sessions = SessionBindings::default();
        let principals = MAX_TRACKED_SESSIONS / MAX_SESSIONS_PER_BINDING;
        for principal in 0..principals {
            let holder = binding(&format!("principal-{principal}"));
            for index in 0..MAX_SESSIONS_PER_BINDING {
                sessions.remember(format!("s-{principal}-{index}"), holder.clone());
            }
        }
        assert_eq!(sessions.len(), MAX_TRACKED_SESSIONS);
        let newcomer = binding("newcomer");
        assert!(!sessions.has_room_for(newcomer.as_ref()));
        sessions.remember("newcomer-session".into(), newcomer.clone());
        assert!(!sessions.permits("newcomer-session", newcomer.as_ref()));
        assert_eq!(sessions.len(), MAX_TRACKED_SESSIONS);
        // The first principal's sessions all survived.
        let first = binding("principal-0");
        assert_eq!(sessions.held_by(first.as_ref()), MAX_SESSIONS_PER_BINDING);
        // Ending one frees exactly one slot, for its own holder.
        sessions.forget("s-0-0");
        assert!(sessions.has_room_for(first.as_ref()));
        assert!(sessions.has_room_for(newcomer.as_ref()));
    }

    /// A binding is compared exactly: no principal inherits another's
    /// session, and "no principal" is its own holder.
    #[test]
    fn a_session_permits_only_its_own_binding() {
        let mut sessions = SessionBindings::default();
        sessions.remember("bound".into(), binding("alice"));
        sessions.remember("unbound".into(), None);
        assert!(sessions.permits("bound", binding("alice").as_ref()));
        assert!(!sessions.permits("bound", binding("bob").as_ref()));
        assert!(!sessions.permits("bound", None));
        assert!(sessions.permits("unbound", None));
        assert!(!sessions.permits("unbound", binding("alice").as_ref()));
        assert!(!sessions.permits("never-issued", binding("alice").as_ref()));
    }
}
