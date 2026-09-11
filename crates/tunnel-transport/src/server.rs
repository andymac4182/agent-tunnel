//! Bounded TLS acceptor and Axum connection supervisor.

use std::{sync::Arc, time::Duration};

use axum::{Extension, Router};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
    service::TowerToHyperService,
};
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
    let acceptor = TlsAcceptor::from(config);
    let permits = Arc::new(tokio::sync::Semaphore::new(
        DEFAULT_MAX_CONCURRENT_HANDSHAKES,
    ));
    let mut tasks = JoinSet::new();
    let child_cancel = cancel.child_token();

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            result = listener.accept() => {
                let (stream, remote_addr) = result.map_err(TransportError::Accept)?;
                let permit = match permits.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        // The socket has not completed TLS authentication.  Drop it
                        // immediately when the bounded handshake budget is full.
                        tracing::debug!(%remote_addr, "dropping TLS connection at handshake capacity");
                        continue;
                    }
                };
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
                result.map_err(TransportError::Task)??;
            }
        }
    }

    child_cancel.cancel();
    while let Some(result) = tasks.join_next().await {
        result.map_err(TransportError::Task)??;
    }
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

    #[test]
    fn capacity_and_handshake_deadline_are_bounded() {
        assert_eq!(DEFAULT_MAX_CONCURRENT_HANDSHAKES, 64);
        assert_eq!(DEFAULT_HANDSHAKE_TIMEOUT, Duration::from_secs(10));
    }
}
