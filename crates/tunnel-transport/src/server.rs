//! Bounded TLS acceptor and Axum connection supervisor.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{Extension, Router};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto,
    service::TowerToHyperService,
};
use socket2::SockRef;
use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tokio_util::sync::CancellationToken;

use crate::tls::{TlsIdentity, TlsIdentityError, parse_leaf_identity};

/// Maximum number of TLS handshakes and HTTP connections supervised at once.
///
/// The public API intentionally takes a fixed `ServerConfig`; this hard cap
/// prevents an unauthenticated peer from creating an unbounded number of
/// handshake tasks before the relay's admission layer runs.
pub const DEFAULT_MAX_CONCURRENT_HANDSHAKES: usize = 64;

/// Maximum HTTP/2 streams advertised for one accepted connection.
///
/// A connection permit is held until the HTTP connection future completes;
/// this second bound prevents one long-lived HTTP/2 connection from creating
/// an unbounded number of concurrent request streams.  Device WebSocket
/// quotas remain an application-level concern because Hyper hands an HTTP/1
/// upgrade to the route's `on_upgrade` task before its connection future
/// completes.
pub const DEFAULT_MAX_HTTP2_STREAMS: u32 = 100;

/// Maximum HTTP header-list bytes accepted by HTTP/2.
pub const DEFAULT_MAX_HTTP2_HEADER_LIST_BYTES: u32 = 32 * 1024;

/// Maximum HTTP/1 header count accepted by Hyper.
pub const DEFAULT_MAX_HTTP1_HEADERS: usize = 100;

/// Deadline for a TCP connection to complete its TLS handshake.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Deadline for an accepted connection to dispatch its first complete HTTP
/// request after its TLS handshake completes.
///
/// A connection permit is held for the whole HTTP connection, so the
/// pre-request phase needs its own bound.  Hyper cannot supply one: the
/// `hyper_util` protocol sniffer waits for up to the 24-byte HTTP/2 preface
/// with no deadline of its own, and HTTP/2 has no header-read timeout at all.
/// A peer that completes the TLS handshake and then sends nothing — or just a
/// prefix of the preface — would otherwise hold its permit until it closed the
/// socket, so [`DEFAULT_MAX_CONCURRENT_HANDSHAKES`] silent connections would
/// block every further accept.
///
/// This bound covers the entire pre-request phase: version sniffing, the
/// HTTP/2 preamble, and the first request head.  It is disarmed permanently as
/// soon as any request is dispatched to the router, so an established device
/// WebSocket upgrade or a long-lived consumer request is never closed by it.
pub const DEFAULT_PRE_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Deadline for Hyper to read one complete HTTP/1 request head.
///
/// Hyper arms this bound for every head read, so it also bounds an idle
/// HTTP/1 keep-alive connection between requests.  It is not armed while a
/// request is in flight, while a response body is streaming, or after an
/// upgrade, so legitimately long-lived connections are unaffected.  Hyper
/// discards the setting (logging a warning) unless a timer is installed on the
/// builder, which [`serve`] now does.
pub const DEFAULT_HTTP1_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

const MIN_ACCEPTED_SEND_BUFFER_BYTES: u32 = 1024;
const MAX_ACCEPTED_SEND_BUFFER_BYTES: u32 = 1024 * 1024;

/// Smallest accepted listener deadline.  Shorter values are indistinguishable
/// from scheduling noise on a loaded host and would close healthy connections.
const MIN_LISTENER_TIMEOUT: Duration = Duration::from_millis(100);
/// Largest accepted listener deadline, matching the documented 300-second
/// ceiling used by the other configured handshake and overlap bounds.
const MAX_LISTENER_TIMEOUT: Duration = Duration::from_secs(300);
const LISTENER_TIMEOUT_RANGE: &str = "must be 100ms..=300s";

/// Bounded deadlines applied to every accepted listener connection.
///
/// Each value is a configuration value with a documented default rather than a
/// literal in the accept path.  `validate` enforces the same kind of range and
/// cross-field rules as the relay's configured limits, and is called before the
/// listener accepts its first socket so an invalid deployment fails closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenerTimeouts {
    /// Deadline for a TCP connection to complete its TLS handshake.
    ///
    /// Default [`DEFAULT_HANDSHAKE_TIMEOUT`]; accepts 100ms..=300s.
    pub handshake_timeout: Duration,
    /// Deadline for a handshaken connection to dispatch its first complete
    /// HTTP request.
    ///
    /// Default [`DEFAULT_PRE_REQUEST_TIMEOUT`]; accepts 100ms..=300s.  The
    /// bound applies only to the pre-request phase; it is disarmed once the
    /// connection dispatches a request.
    pub pre_request_timeout: Duration,
    /// Deadline for Hyper to read one complete HTTP/1 request head, including
    /// an idle keep-alive gap between requests.
    ///
    /// Default [`DEFAULT_HTTP1_HEADER_READ_TIMEOUT`]; accepts 100ms..=300s and
    /// must not exceed `pre_request_timeout`.
    pub http1_header_read_timeout: Duration,
}

impl Default for ListenerTimeouts {
    fn default() -> Self {
        Self {
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            pre_request_timeout: DEFAULT_PRE_REQUEST_TIMEOUT,
            http1_header_read_timeout: DEFAULT_HTTP1_HEADER_READ_TIMEOUT,
        }
    }
}

impl ListenerTimeouts {
    /// Validate every configured listener deadline and their cross-field rule.
    ///
    /// The pre-request bound encloses the first HTTP/1 head read, so an
    /// HTTP/1 header deadline larger than the pre-request deadline would be
    /// unreachable configuration on a first request and a weaker bound than
    /// the operator asked for on an idle keep-alive connection.
    pub fn validate(&self) -> Result<(), TransportError> {
        for (field, value) in [
            ("handshake_timeout", self.handshake_timeout),
            ("pre_request_timeout", self.pre_request_timeout),
            ("http1_header_read_timeout", self.http1_header_read_timeout),
        ] {
            if !(MIN_LISTENER_TIMEOUT..=MAX_LISTENER_TIMEOUT).contains(&value) {
                return Err(TransportError::InvalidListenerTimeouts {
                    field,
                    reason: LISTENER_TIMEOUT_RANGE,
                });
            }
        }
        if self.http1_header_read_timeout > self.pre_request_timeout {
            return Err(TransportError::InvalidListenerTimeouts {
                field: "http1_header_read_timeout",
                reason: "must not exceed pre_request_timeout",
            });
        }
        Ok(())
    }
}

/// Bounded diagnostics for the most recently accepted TCP socket configured by
/// [`AcceptedSocketOptions`].  The value is deliberately a single atomic
/// sample: it cannot retain connection identifiers, addresses, or payloads.
#[derive(Clone, Debug, Default)]
pub struct AcceptedSocketDiagnostics {
    last_send_buffer_bytes: Arc<AtomicUsize>,
    /// Accepted sockets whose `TCP_NODELAY` read back as set (M6-C124).
    nodelay_set: Arc<AtomicUsize>,
    /// Accepted sockets whose `TCP_NODELAY` read back as clear or unreadable.
    nodelay_unset: Arc<AtomicUsize>,
}

impl AcceptedSocketDiagnostics {
    /// Create an empty diagnostic sample.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the most recently observed accepted-socket send buffer size.
    ///
    /// `None` means that no accepted socket has yet been observed.
    pub fn last_send_buffer_bytes(&self) -> Option<usize> {
        match self.last_send_buffer_bytes.load(Ordering::Acquire) {
            0 => None,
            value => Some(value),
        }
    }

    fn record_send_buffer_bytes(&self, bytes: usize) {
        self.last_send_buffer_bytes.store(bytes, Ordering::Release);
    }

    /// Accepted sockets observed with `TCP_NODELAY` set, and observed with it
    /// clear (or unreadable), in that order.  Task row M6-C124: every
    /// accepted socket is expected in the first count.
    pub fn nodelay_counts(&self) -> (usize, usize) {
        (
            self.nodelay_set.load(Ordering::Acquire),
            self.nodelay_unset.load(Ordering::Acquire),
        )
    }

    fn record_nodelay(&self, set: bool) {
        let counter = if set {
            &self.nodelay_set
        } else {
            &self.nodelay_unset
        };
        counter.fetch_add(1, Ordering::AcqRel);
    }
}

/// Optional configuration for accepted public TCP sockets.
///
/// The default is empty and preserves the platform's normal socket defaults.
/// A requested send buffer is applied only after `accept`, so it does not rely
/// on listener-option inheritance, which differs across supported platforms.
#[derive(Clone, Debug, Default)]
pub struct AcceptedSocketOptions {
    /// Requested accepted-socket send buffer size in bytes.
    pub send_buffer_bytes: Option<u32>,
    /// Optional bounded sample of the actual accepted-socket buffer size.
    pub diagnostics: Option<AcceptedSocketDiagnostics>,
    /// A fixed name for this listener (`consumer`, `device`) carried by its
    /// TLS refusal log lines (M6-C52); `None` logs `unnamed`.
    pub listener: Option<&'static str>,
}

/// Errors returned by the listener supervisor itself.  A malformed or
/// unauthorized client handshake is a connection-local event and is closed;
/// it does not terminate the listener.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The listener failed to accept a TCP connection.
    #[error("TCP accept failed: {0}")]
    Accept(#[source] std::io::Error),
    /// A supervised connection task panicked or was cancelled unexpectedly.
    #[error("transport connection task failed: {0}")]
    Task(#[source] tokio::task::JoinError),
    /// A connection task encountered an HTTP serving error.
    #[error("HTTP connection failed: {0}")]
    Http(String),
    /// The accepted socket could not be configured as requested.
    #[error("accepted TCP socket configuration failed for {requested_bytes} bytes: {source}")]
    SocketConfiguration {
        /// Requested send buffer size.
        requested_bytes: u32,
        /// Platform error returned by the socket option.
        #[source]
        source: std::io::Error,
    },
    /// The accepted-socket option was outside the bounded test/deployment
    /// range.
    #[error(
        "accepted TCP socket send buffer request {requested_bytes} is outside the 1024..=1048576 byte range"
    )]
    InvalidSocketConfiguration {
        /// Requested send buffer size that failed validation.
        requested_bytes: u32,
    },
    /// A configured listener deadline was outside its documented range or
    /// violated the cross-field rule.
    #[error("listener timeout {field} is invalid: {reason}")]
    InvalidListenerTimeouts {
        /// Name of the offending [`ListenerTimeouts`] field.
        field: &'static str,
        /// Bounded explanation; it never contains connection data.
        reason: &'static str,
    },
}

/// Serve an Axum router over TLS 1.3 on a TCP listener.
///
/// The supplied [`rustls::ServerConfig`] must be constructed by
/// [`crate::load_server_config_from_pem`] or an equivalent TLS-1.3-only
/// configuration.  The helper enables HTTP/1.1 and HTTP/2 through ALPN and
/// verifies device/peer client certificates when a client CA is configured.
///
/// Every successful TLS handshake extracts the peer certificate chain from
/// the rustls connection itself.  A [`TlsIdentity`] is placed in request
/// extensions for mTLS listeners; no request header can create or replace it.
/// Consumer configs without client authentication receive no identity
/// extension and remain responsible for HTTP-layer authentication.
///
/// Handshake work is bounded by [`DEFAULT_MAX_CONCURRENT_HANDSHAKES`], and
/// cancellation stops accepting sockets then asks active HTTP/1.1 and HTTP/2
/// connections to drain before their task groups are joined.
///
/// Every connection permit is additionally bounded in time by the default
/// [`ListenerTimeouts`], so a peer that completes the TLS handshake and never
/// sends a complete request is closed and releases its permit.
pub async fn serve(
    listener: TcpListener,
    router: Router,
    config: Arc<rustls::ServerConfig>,
    cancel: CancellationToken,
) -> Result<(), TransportError> {
    serve_with_socket_options(
        listener,
        router,
        config,
        cancel,
        AcceptedSocketOptions::default(),
    )
    .await
}

/// Serve an Axum router while applying bounded options to each accepted TCP
/// socket before its TLS task starts.
///
/// The ordinary [`serve`] entry point leaves platform socket defaults
/// unchanged.  This optioned entry point exists for narrowly scoped transport
/// fixtures and deployments that explicitly need a deterministic accepted
/// socket setting; it never changes the listener's handshake or HTTP limits.
pub async fn serve_with_socket_options(
    listener: TcpListener,
    router: Router,
    config: Arc<rustls::ServerConfig>,
    cancel: CancellationToken,
    socket_options: AcceptedSocketOptions,
) -> Result<(), TransportError> {
    serve_with_listener_options(
        listener,
        router,
        config,
        cancel,
        socket_options,
        ListenerTimeouts::default(),
    )
    .await
}

/// Serve an Axum router with explicit accepted-socket options and explicit
/// bounded listener deadlines.
///
/// Deployments and fixtures that need a tighter or looser pre-request bound use
/// this entry point; [`serve`] and [`serve_with_socket_options`] apply the
/// documented [`ListenerTimeouts`] defaults.  The deadlines are validated
/// before the listener accepts a socket, so an invalid value returns an error
/// and releases the listener instead of serving with an unbounded permit.
pub async fn serve_with_listener_options(
    listener: TcpListener,
    router: Router,
    config: Arc<rustls::ServerConfig>,
    cancel: CancellationToken,
    socket_options: AcceptedSocketOptions,
    timeouts: ListenerTimeouts,
) -> Result<(), TransportError> {
    validate_socket_options(&socket_options)?;
    timeouts.validate()?;
    let acceptor = TlsAcceptor::from(config);
    let permits = Arc::new(tokio::sync::Semaphore::new(
        DEFAULT_MAX_CONCURRENT_HANDSHAKES,
    ));
    let mut tasks = JoinSet::new();
    let child_cancel = cancel.child_token();
    let mut first_error = None;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            result = listener.accept() => {
                let (stream, remote_addr) = match result {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        first_error = Some(TransportError::Accept(error));
                        break;
                    }
                };
                let permit = match permits.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        // The socket has not completed TLS authentication.  Drop it
                        // immediately when the bounded handshake budget is full.
                        tracing::debug!(%remote_addr, "dropping TLS connection at handshake capacity");
                        continue;
                    }
                };
                if let Err(error) = configure_accepted_socket(&stream, &socket_options, remote_addr) {
                    first_error = Some(error);
                    break;
                }
                let acceptor = acceptor.clone();
                let router = router.clone();
                let connection_cancel = child_cancel.child_token();
                let listener_name = socket_options.listener.unwrap_or("unnamed");
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = serve_connection(stream, acceptor, router, connection_cancel, timeouts, listener_name).await {
                        tracing::debug!(%remote_addr, ?error, "TLS/HTTP connection closed");
                    }
                    Ok::<(), TransportError>(())
                });
            }
            Some(result) = tasks.join_next() => {
                let result = match result {
                    Ok(result) => result,
                    Err(error) => Err(TransportError::Task(error)),
                };
                if let Err(error) = result {
                    first_error = Some(error);
                    break;
                }
            }
        }
    }

    if first_error.is_some() {
        cancel.cancel();
    }
    child_cancel.cancel();
    while let Some(result) = tasks.join_next().await {
        let result = match result {
            Ok(result) => result,
            Err(error) => Err(TransportError::Task(error)),
        };
        if let Err(error) = result {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn validate_socket_options(options: &AcceptedSocketOptions) -> Result<(), TransportError> {
    if let Some(requested_bytes) = options.send_buffer_bytes
        && !(MIN_ACCEPTED_SEND_BUFFER_BYTES..=MAX_ACCEPTED_SEND_BUFFER_BYTES)
            .contains(&requested_bytes)
    {
        return Err(TransportError::InvalidSocketConfiguration { requested_bytes });
    }
    Ok(())
}

/// Disable Nagle's algorithm on an accepted socket (task row M6-C124).
///
/// Both listeners carry request/reply traffic in small TLS records: a
/// WebSocket frame to a device and the device's reply, or an HTTP response
/// head and body to a consumer.  With Nagle on, a small write that follows an
/// unacknowledged one waits for the peer's delayed ACK (40 ms on Linux).
/// Bulk transfers are unaffected in kind: they fill whole segments, which
/// Nagle never held back.  Listener-option inheritance differs across
/// platforms, so the option is set on each accepted socket.  A failure is
/// connection-local (a peer that already reset makes some platforms refuse
/// the option) and the connection is still served; the diagnostics count it.
fn set_accepted_nodelay(
    stream: &TcpStream,
    diagnostics: Option<&AcceptedSocketDiagnostics>,
    remote_addr: std::net::SocketAddr,
) {
    if let Err(error) = stream.set_nodelay(true) {
        tracing::debug!(%remote_addr, %error, "TCP_NODELAY could not be set on an accepted socket");
    }
    if let Some(diagnostics) = diagnostics {
        diagnostics.record_nodelay(stream.nodelay().unwrap_or(false));
    }
}

fn configure_accepted_socket(
    stream: &TcpStream,
    options: &AcceptedSocketOptions,
    remote_addr: std::net::SocketAddr,
) -> Result<(), TransportError> {
    set_accepted_nodelay(stream, options.diagnostics.as_ref(), remote_addr);
    if options.send_buffer_bytes.is_none() && options.diagnostics.is_none() {
        return Ok(());
    }

    let socket = SockRef::from(stream);
    if let Some(requested_bytes) = options.send_buffer_bytes {
        socket
            .set_send_buffer_size(requested_bytes as usize)
            .map_err(|source| TransportError::SocketConfiguration {
                requested_bytes,
                source,
            })?;
    }
    let actual_bytes =
        socket
            .send_buffer_size()
            .map_err(|source| TransportError::SocketConfiguration {
                requested_bytes: options.send_buffer_bytes.unwrap_or_default(),
                source,
            })?;
    if let Some(diagnostics) = &options.diagnostics {
        diagnostics.record_send_buffer_bytes(actual_bytes);
    }
    tracing::debug!(
        %remote_addr,
        requested_send_buffer_bytes = options.send_buffer_bytes,
        accepted_send_buffer_bytes = actual_bytes,
        "configured accepted TCP socket"
    );
    Ok(())
}

/// Hyper service wrapper that records the first dispatched request.
///
/// Hyper calls the service only after it has parsed a complete request head, so
/// the first call is the exact boundary between the bounded pre-request phase
/// and an established connection.  The wrapper adds no per-request state and
/// retains no request data.
#[derive(Clone)]
struct ObserveFirstRequest<S> {
    inner: S,
    first_request: CancellationToken,
}

impl<S, R> hyper::service::Service<R> for ObserveFirstRequest<S>
where
    S: hyper::service::Service<R>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn call(&self, request: R) -> Self::Future {
        self.first_request.cancel();
        self.inner.call(request)
    }
}

async fn serve_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    router: Router,
    cancel: CancellationToken,
    timeouts: ListenerTimeouts,
    listener: &'static str,
) -> Result<(), TransportError> {
    let handshake = timeout(timeouts.handshake_timeout, acceptor.accept(stream));
    let tls_stream = match tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        result = handshake => result,
    } {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            // Certificate failures, protocol mismatches, and missing client
            // certificates are expected per-connection authentication failures.
            // Task row M6-C52: a certificate refusal is the answer to "why is
            // my device refused", so it is logged at the default level with a
            // fixed label; anything else (a scanner, a health check's bare
            // TCP close) stays at debug.
            // Any peer that can reach the listener can trigger it, so the
            // line is rate limited per label (review of M6-C52).
            match tls_refusal_label(&error) {
                Some(refusal) => {
                    log_tls_refusal(&TLS_REFUSAL_LOG, listener, refusal);
                }
                None => tracing::debug!(?error, "TLS handshake rejected"),
            }
            return Ok(());
        }
        Err(_) => {
            tracing::debug!("TLS handshake timed out");
            return Ok(());
        }
    };

    let identity = verified_identity(&tls_stream)?;
    let io = TokioIo::new(tls_stream);
    let router = match identity {
        Some(identity) => router.layer(Extension(identity)),
        None => router,
    };
    let first_request = CancellationToken::new();
    let service = ObserveFirstRequest {
        inner: TowerToHyperService::new(router.into_service()),
        first_request: first_request.clone(),
    };
    let mut builder = auto::Builder::new(TokioExecutor::new());
    // Hyper discards its header-read deadline and logs a warning when no timer
    // is installed, so install one before configuring that deadline.
    builder
        .http1()
        .timer(TokioTimer::new())
        .max_headers(DEFAULT_MAX_HTTP1_HEADERS)
        .header_read_timeout(Some(timeouts.http1_header_read_timeout));
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(DEFAULT_MAX_HTTP2_STREAMS)
        .max_header_list_size(DEFAULT_MAX_HTTP2_HEADER_LIST_BYTES);
    let mut connection = Box::pin(builder.serve_connection_with_upgrades(io, service));

    // The pre-request deadline is armed from the completed handshake and
    // disarmed for good by the first dispatched request.  Returning on the
    // deadline drops the connection future and its TLS stream, which closes the
    // socket and releases this task's listener permit.
    let pre_request_deadline = tokio::time::sleep(timeouts.pre_request_timeout);
    tokio::pin!(pre_request_deadline);
    let mut pre_request_phase = true;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                connection.as_mut().graceful_shutdown();
                return connection.await.map_err(|error| TransportError::Http(error.to_string()));
            }
            result = &mut connection => {
                return result.map_err(|error| TransportError::Http(error.to_string()));
            }
            _ = first_request.cancelled(), if pre_request_phase => {
                pre_request_phase = false;
            }
            _ = &mut pre_request_deadline, if pre_request_phase => {
                tracing::debug!(
                    pre_request_timeout_ms = timeouts.pre_request_timeout.as_millis(),
                    "closing connection that dispatched no request before the pre-request deadline"
                );
                return Ok(());
            }
        }
    }
}

/// The process-wide limit on `TLS handshake refused` lines.
static TLS_REFUSAL_LOG: std::sync::LazyLock<crate::log_limit::RefusalLogLimiter> =
    std::sync::LazyLock::new(crate::log_limit::RefusalLogLimiter::with_defaults);

/// Write one `TLS handshake refused` line for `refusal` on `listener` unless
/// `limiter` suppresses it; returns whether it was written.  An admitted line
/// carries `suppressed`, the number of lines for this label the limiter
/// dropped since the previous one.
pub fn log_tls_refusal(
    limiter: &crate::log_limit::RefusalLogLimiter,
    listener: &'static str,
    refusal: &'static str,
) -> bool {
    match limiter.admit(refusal) {
        Some(suppressed) => {
            tracing::info!(
                phase = "tls_refused",
                listener,
                refusal,
                suppressed,
                "TLS handshake refused"
            );
            true
        }
        None => false,
    }
}

/// A fixed, payload-free label for a TLS handshake that failed over a
/// certificate, on either side (task row M6-C52), or `None` for any other
/// handshake failure.  The labels name the rustls error class only: no
/// certificate content, subject, address or alert detail beyond its fixed
/// name reaches the log.
pub(crate) fn tls_refusal_label(error: &std::io::Error) -> Option<&'static str> {
    use rustls::{AlertDescription, CertificateError, Error};
    let error = error.get_ref()?.downcast_ref::<Error>()?;
    Some(match error {
        Error::NoCertificatesPresented => "client_certificate_missing",
        Error::InvalidCertificate(certificate) => match certificate {
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                "client_certificate_expired"
            }
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                "client_certificate_not_yet_valid"
            }
            CertificateError::UnknownIssuer => "client_certificate_unknown_issuer",
            CertificateError::BadSignature => "client_certificate_bad_signature",
            CertificateError::Revoked => "client_certificate_revoked",
            CertificateError::InvalidPurpose | CertificateError::InvalidPurposeContext { .. } => {
                "client_certificate_wrong_purpose"
            }
            _ => "client_certificate_invalid",
        },
        // The peer refused this listener's own certificate.
        Error::AlertReceived(alert) => match alert {
            AlertDescription::UnknownCA => "peer_refused_server_certificate_unknown_ca",
            AlertDescription::CertificateExpired => "peer_refused_server_certificate_expired",
            AlertDescription::BadCertificate
            | AlertDescription::UnsupportedCertificate
            | AlertDescription::CertificateUnknown
            | AlertDescription::CertificateRevoked
            | AlertDescription::BadCertificateStatusResponse => "peer_refused_server_certificate",
            _ => return None,
        },
        _ => return None,
    })
}

fn verified_identity<S>(stream: &TlsStream<S>) -> Result<Option<TlsIdentity>, TransportError> {
    let certificates = stream.get_ref().1.peer_certificates();
    certificates
        .map(parse_leaf_identity)
        .transpose()
        .map_err(|error: TlsIdentityError| TransportError::Http(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEND_BUFFER_BYTES: u32 = 16 * 1024;

    fn test_server_config() -> Arc<rustls::ServerConfig> {
        let builder = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is supported by the test provider")
        .with_no_client_auth();
        Arc::new(
            builder.with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new())),
        )
    }

    /// M6-C52: certificate refusals on either side get a fixed label that is
    /// logged at the default level; every other handshake failure -- a
    /// scanner, a load balancer's bare TCP close -- gets none and stays at
    /// debug.  The labels are the only thing logged, so no certificate
    /// content can reach the line.
    /// Review of M6-C52: a peer that presents no client certificate, as fast
    /// as it likes, gets at most the limiter's burst of lines per window.
    #[test]
    fn tls_refusal_lines_are_rate_limited() {
        let limiter = crate::log_limit::RefusalLogLimiter::new(5, Duration::from_secs(60));
        let written = (0..500)
            .filter(|_| log_tls_refusal(&limiter, "device", "client_certificate_missing"))
            .count();
        assert_eq!(written, 5);
    }

    #[test]
    fn only_certificate_refusals_are_labelled_for_the_default_log() {
        use rustls::{AlertDescription, CertificateError, Error};
        let io = |error: Error| std::io::Error::new(std::io::ErrorKind::InvalidData, error);
        for (error, label) in [
            (Error::NoCertificatesPresented, "client_certificate_missing"),
            (
                Error::InvalidCertificate(CertificateError::Expired),
                "client_certificate_expired",
            ),
            (
                Error::InvalidCertificate(CertificateError::NotValidYet),
                "client_certificate_not_yet_valid",
            ),
            (
                Error::InvalidCertificate(CertificateError::UnknownIssuer),
                "client_certificate_unknown_issuer",
            ),
            (
                Error::AlertReceived(AlertDescription::UnknownCA),
                "peer_refused_server_certificate_unknown_ca",
            ),
            (
                Error::AlertReceived(AlertDescription::BadCertificate),
                "peer_refused_server_certificate",
            ),
        ] {
            assert_eq!(tls_refusal_label(&io(error)), Some(label), "{label}");
        }
        for unlabelled in [
            io(Error::AlertReceived(AlertDescription::ProtocolVersion)),
            io(Error::DecryptError),
            std::io::Error::from(std::io::ErrorKind::UnexpectedEof),
            std::io::Error::other("not a rustls error"),
        ] {
            assert_eq!(tls_refusal_label(&unlabelled), None, "{unlabelled:?}");
        }
    }

    #[test]
    fn capacity_and_handshake_deadline_are_bounded() {
        assert_eq!(DEFAULT_MAX_CONCURRENT_HANDSHAKES, 64);
        assert_eq!(DEFAULT_HANDSHAKE_TIMEOUT, Duration::from_secs(10));
    }

    fn invalid_field(timeouts: ListenerTimeouts) -> &'static str {
        match timeouts.validate() {
            Err(TransportError::InvalidListenerTimeouts { field, .. }) => field,
            other => panic!("expected an invalid listener timeout, got {other:?}"),
        }
    }

    #[test]
    fn listener_timeout_defaults_are_documented_and_valid() {
        let timeouts = ListenerTimeouts::default();
        assert_eq!(timeouts.handshake_timeout, Duration::from_secs(10));
        assert_eq!(timeouts.pre_request_timeout, Duration::from_secs(15));
        assert_eq!(timeouts.http1_header_read_timeout, Duration::from_secs(10));
        assert!(
            timeouts.http1_header_read_timeout <= timeouts.pre_request_timeout,
            "the default values must satisfy the cross-field rule"
        );
        assert!(timeouts.validate().is_ok());
        // A silent connection holds a permit for at most the handshake budget
        // plus the pre-request budget.
        assert_eq!(
            timeouts.handshake_timeout + timeouts.pre_request_timeout,
            Duration::from_secs(25)
        );
    }

    #[test]
    fn listener_timeout_boundaries_are_inclusive() {
        let minimum = ListenerTimeouts {
            handshake_timeout: MIN_LISTENER_TIMEOUT,
            pre_request_timeout: MIN_LISTENER_TIMEOUT,
            http1_header_read_timeout: MIN_LISTENER_TIMEOUT,
        };
        assert!(minimum.validate().is_ok(), "100ms must be accepted");
        let maximum = ListenerTimeouts {
            handshake_timeout: MAX_LISTENER_TIMEOUT,
            pre_request_timeout: MAX_LISTENER_TIMEOUT,
            http1_header_read_timeout: MAX_LISTENER_TIMEOUT,
        };
        assert!(maximum.validate().is_ok(), "300s must be accepted");
    }

    #[test]
    fn listener_timeouts_below_the_minimum_are_rejected_per_field() {
        let below = MIN_LISTENER_TIMEOUT - Duration::from_millis(1);
        assert_eq!(
            invalid_field(ListenerTimeouts {
                handshake_timeout: below,
                ..ListenerTimeouts::default()
            }),
            "handshake_timeout"
        );
        assert_eq!(
            invalid_field(ListenerTimeouts {
                pre_request_timeout: below,
                http1_header_read_timeout: below,
                ..ListenerTimeouts::default()
            }),
            "pre_request_timeout"
        );
        assert_eq!(
            invalid_field(ListenerTimeouts {
                http1_header_read_timeout: below,
                ..ListenerTimeouts::default()
            }),
            "http1_header_read_timeout"
        );
        assert_eq!(
            invalid_field(ListenerTimeouts {
                handshake_timeout: Duration::ZERO,
                pre_request_timeout: Duration::ZERO,
                http1_header_read_timeout: Duration::ZERO,
            }),
            "handshake_timeout",
            "a zero deadline must never disable a bound"
        );
    }

    #[test]
    fn listener_timeouts_above_the_maximum_are_rejected_per_field() {
        let above = MAX_LISTENER_TIMEOUT + Duration::from_millis(1);
        assert_eq!(
            invalid_field(ListenerTimeouts {
                handshake_timeout: above,
                ..ListenerTimeouts::default()
            }),
            "handshake_timeout"
        );
        assert_eq!(
            invalid_field(ListenerTimeouts {
                pre_request_timeout: above,
                ..ListenerTimeouts::default()
            }),
            "pre_request_timeout"
        );
        assert_eq!(
            invalid_field(ListenerTimeouts {
                pre_request_timeout: MAX_LISTENER_TIMEOUT,
                http1_header_read_timeout: above,
                ..ListenerTimeouts::default()
            }),
            "http1_header_read_timeout"
        );
    }

    #[test]
    fn header_read_deadline_may_not_exceed_the_pre_request_deadline() {
        let equal = ListenerTimeouts {
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            pre_request_timeout: Duration::from_secs(5),
            http1_header_read_timeout: Duration::from_secs(5),
        };
        assert!(
            equal.validate().is_ok(),
            "an equal header-read deadline is the accepted boundary"
        );
        let above = ListenerTimeouts {
            http1_header_read_timeout: Duration::from_secs(5) + Duration::from_millis(1),
            ..equal
        };
        let error = above
            .validate()
            .expect_err("a header-read deadline above the pre-request deadline must be rejected");
        assert!(matches!(
            error,
            TransportError::InvalidListenerTimeouts {
                field: "http1_header_read_timeout",
                reason: "must not exceed pre_request_timeout",
            }
        ));
    }

    #[tokio::test]
    async fn invalid_listener_timeouts_return_and_release_listener() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind invalid-timeout test listener");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(serve_with_listener_options(
            listener,
            Router::new(),
            test_server_config(),
            CancellationToken::new(),
            AcceptedSocketOptions::default(),
            ListenerTimeouts {
                pre_request_timeout: Duration::ZERO,
                ..ListenerTimeouts::default()
            },
        ));

        let error = timeout(Duration::from_secs(1), server)
            .await
            .expect("invalid timeout did not fail before the deadline")
            .expect("invalid-timeout supervisor task panicked")
            .expect_err("invalid timeout unexpectedly started the listener");
        assert!(matches!(
            error,
            TransportError::InvalidListenerTimeouts {
                field: "pre_request_timeout",
                ..
            }
        ));

        // Five seconds, not one: Windows answers a connect to a closed
        // loopback port only after retrying the refused SYN (about two
        // seconds), where Unix refuses at once. The assertion below is what
        // can fail; this bound only keeps the check from hanging.
        let connection = timeout(Duration::from_secs(5), TcpStream::connect(address))
            .await
            .expect("released listener connection check timed out");
        assert!(
            connection.is_err(),
            "listener remained reachable after timeout validation failure"
        );
    }

    #[tokio::test]
    async fn accepted_socket_send_buffer_option_is_observed_after_accept() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind transport test listener");
        let address = listener.local_addr().expect("listener address");
        let cancel = CancellationToken::new();
        let diagnostics = AcceptedSocketDiagnostics::new();
        let server = tokio::spawn(serve_with_socket_options(
            listener,
            Router::new(),
            test_server_config(),
            cancel.clone(),
            AcceptedSocketOptions {
                send_buffer_bytes: Some(TEST_SEND_BUFFER_BYTES),
                diagnostics: Some(diagnostics.clone()),
                listener: None,
            },
        ));

        let client = TcpStream::connect(address)
            .await
            .expect("connect accepted-socket test client");
        let effective = timeout(Duration::from_secs(1), async {
            loop {
                if let Some(bytes) = diagnostics.last_send_buffer_bytes() {
                    break bytes;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("accepted socket was not configured before the deadline");
        assert!(
            effective > 0,
            "platform returned an empty effective send-buffer sample"
        );

        cancel.cancel();
        drop(client);
        let result = timeout(Duration::from_secs(1), server)
            .await
            .expect("transport supervisor did not join after cancellation")
            .expect("transport supervisor task panicked");
        assert!(result.is_ok(), "cancellation returned an error: {result:?}");
    }

    /// Task row M6-C124: every accepted socket has `TCP_NODELAY` set, with no
    /// socket option requested — the listener default, which is what the
    /// relay's consumer and device listeners use.
    #[tokio::test]
    async fn accepted_sockets_have_nodelay_set_by_default() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind nodelay test listener");
        let address = listener.local_addr().expect("listener address");
        let cancel = CancellationToken::new();
        let diagnostics = AcceptedSocketDiagnostics::new();
        let server = tokio::spawn(serve_with_socket_options(
            listener,
            Router::new(),
            test_server_config(),
            cancel.clone(),
            AcceptedSocketOptions {
                send_buffer_bytes: None,
                diagnostics: Some(diagnostics.clone()),
                listener: None,
            },
        ));

        let mut clients = Vec::new();
        for _ in 0..3 {
            clients.push(
                TcpStream::connect(address)
                    .await
                    .expect("connect nodelay test client"),
            );
        }
        let counts = timeout(Duration::from_secs(5), async {
            loop {
                let (set, unset) = diagnostics.nodelay_counts();
                if set + unset >= 3 {
                    break (set, unset);
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("accepted sockets were not observed before the deadline");
        assert_eq!(
            counts,
            (3, 0),
            "every accepted socket must have TCP_NODELAY set (set, unset)"
        );

        cancel.cancel();
        drop(clients);
        let result = timeout(Duration::from_secs(1), server)
            .await
            .expect("transport supervisor did not join after cancellation")
            .expect("transport supervisor task panicked");
        assert!(result.is_ok(), "cancellation returned an error: {result:?}");
    }

    #[tokio::test]
    async fn invalid_accepted_socket_option_returns_and_releases_listener() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind invalid-option test listener");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(serve_with_socket_options(
            listener,
            Router::new(),
            test_server_config(),
            CancellationToken::new(),
            AcceptedSocketOptions {
                send_buffer_bytes: Some(0),
                diagnostics: None,
                listener: None,
            },
        ));

        let error = timeout(Duration::from_secs(1), server)
            .await
            .expect("invalid option did not fail before the deadline")
            .expect("invalid-option supervisor task panicked")
            .expect_err("invalid option unexpectedly started the listener");
        assert!(matches!(
            error,
            TransportError::InvalidSocketConfiguration { requested_bytes: 0 }
        ));

        // Five seconds, not one: Windows answers a connect to a closed
        // loopback port only after retrying the refused SYN (about two
        // seconds), where Unix refuses at once. The assertion below is what
        // can fail; this bound only keeps the check from hanging.
        let connection = timeout(Duration::from_secs(5), TcpStream::connect(address))
            .await
            .expect("released listener connection check timed out");
        assert!(
            connection.is_err(),
            "listener remained reachable after configuration failure"
        );
    }
}
