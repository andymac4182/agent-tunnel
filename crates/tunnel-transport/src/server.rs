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
    rt::{TokioExecutor, TokioIo},
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

const MIN_ACCEPTED_SEND_BUFFER_BYTES: u32 = 1024;
const MAX_ACCEPTED_SEND_BUFFER_BYTES: u32 = 1024 * 1024;

/// Bounded diagnostics for the most recently accepted TCP socket configured by
/// [`AcceptedSocketOptions`].  The value is deliberately a single atomic
/// sample: it cannot retain connection identifiers, addresses, or payloads.
#[derive(Clone, Debug, Default)]
pub struct AcceptedSocketDiagnostics {
    last_send_buffer_bytes: Arc<AtomicUsize>,
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
    validate_socket_options(&socket_options)?;
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
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = serve_connection(stream, acceptor, router, connection_cancel).await {
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

fn configure_accepted_socket(
    stream: &TcpStream,
    options: &AcceptedSocketOptions,
    remote_addr: std::net::SocketAddr,
) -> Result<(), TransportError> {
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

async fn serve_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    router: Router,
    cancel: CancellationToken,
) -> Result<(), TransportError> {
    let handshake = timeout(DEFAULT_HANDSHAKE_TIMEOUT, acceptor.accept(stream));
    let tls_stream = match tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        result = handshake => result,
    } {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            // Certificate failures, protocol mismatches, and missing client
            // certificates are expected per-connection authentication failures.
            tracing::debug!(?error, "TLS handshake rejected");
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
    let service = TowerToHyperService::new(router.into_service());
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder.http1().max_headers(DEFAULT_MAX_HTTP1_HEADERS);
    builder
        .http2()
        .max_concurrent_streams(DEFAULT_MAX_HTTP2_STREAMS)
        .max_header_list_size(DEFAULT_MAX_HTTP2_HEADER_LIST_BYTES);
    let mut connection = Box::pin(builder.serve_connection_with_upgrades(io, service));

    tokio::select! {
        result = &mut connection => result.map_err(|error| TransportError::Http(error.to_string())),
        _ = cancel.cancelled() => {
            connection.as_mut().graceful_shutdown();
            connection.await.map_err(|error| TransportError::Http(error.to_string()))
        }
    }
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

    #[test]
    fn capacity_and_handshake_deadline_are_bounded() {
        assert_eq!(DEFAULT_MAX_CONCURRENT_HANDSHAKES, 64);
        assert_eq!(DEFAULT_HANDSHAKE_TIMEOUT, Duration::from_secs(10));
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

        let connection = timeout(Duration::from_secs(1), TcpStream::connect(address))
            .await
            .expect("released listener connection check timed out");
        assert!(
            connection.is_err(),
            "listener remained reachable after configuration failure"
        );
    }
}
