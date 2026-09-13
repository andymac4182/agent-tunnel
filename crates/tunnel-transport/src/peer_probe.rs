//! Bounded, authenticated HTTP/3 peer body probe.
//!
//! This module deliberately does not implement relay ownership, forwarding,
//! routing, or stream recovery.  It proves only that a private QUIC/H3 pair
//! can authenticate both relay certificates and exchange one bounded body in
//! each direction.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::{Buf, Bytes};
use http::{Request, Response, StatusCode};
use rustls::pki_types::CertificateDer;
use thiserror::Error;
use tokio::{task::JoinSet, time::timeout};
use tokio_util::sync::CancellationToken;

use crate::tls::{CertificateRole, SpkiSha256, TlsIdentity, TlsIdentityError, parse_leaf_identity};

/// The default maximum request or response body accepted by the probe.
pub const DEFAULT_PEER_PROBE_BODY_BYTES: usize = 64 * 1024;

/// The default number of concurrently handshaking/served probe connections.
pub const DEFAULT_PEER_PROBE_CONNECTIONS: usize = 16;

/// The default deadline for one QUIC handshake and body exchange.
pub const DEFAULT_PEER_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Limits applied to every peer probe connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerProbeLimits {
    /// Maximum request and response body size in bytes.
    pub max_body_bytes: usize,
    /// Overall deadline for a handshake and one body exchange.
    pub timeout: Duration,
    /// Maximum number of active incoming connections served by the proof
    /// listener.
    pub max_connections: usize,
}

impl Default for PeerProbeLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: DEFAULT_PEER_PROBE_BODY_BYTES,
            timeout: DEFAULT_PEER_PROBE_TIMEOUT,
            max_connections: DEFAULT_PEER_PROBE_CONNECTIONS,
        }
    }
}

impl PeerProbeLimits {
    /// Construct limits and reject zero values that would make the probe
    /// unusable or remove its memory bound.
    pub fn new(
        max_body_bytes: usize,
        timeout: Duration,
        max_connections: usize,
    ) -> Result<Self, PeerProbeError> {
        if max_body_bytes == 0 || timeout.is_zero() || max_connections == 0 {
            return Err(PeerProbeError::InvalidLimits);
        }
        Ok(Self {
            max_body_bytes,
            timeout,
            max_connections,
        })
    }
}

/// Independently managed relay peer public-key pins.
///
/// The set is intentionally separate from the server CA trust bundle.  A CA
/// authorizes certificate issuance; this set constrains which currently
/// approved relay keys may use the private peer route.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ApprovedPeerPins {
    pins: Arc<[SpkiSha256]>,
}

impl ApprovedPeerPins {
    /// Build a non-empty pin set.  An empty set would silently disable the
    /// identity check, so it is rejected.
    pub fn new<I>(pins: I) -> Result<Self, PeerProbeError>
    where
        I: IntoIterator<Item = SpkiSha256>,
    {
        let mut pins: Vec<_> = pins.into_iter().collect();
        pins.sort_unstable();
        pins.dedup();
        if pins.is_empty() {
            return Err(PeerProbeError::EmptyPeerPins);
        }
        Ok(Self { pins: pins.into() })
    }

    /// Return whether a public-key pin is currently approved.
    #[must_use]
    pub fn contains(&self, pin: SpkiSha256) -> bool {
        self.pins.binary_search(&pin).is_ok()
    }

    /// Return the number of approved pins.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pins.len()
    }

    /// Return whether no pins are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }
}

/// Result returned by a successful body probe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerProbeResponse {
    /// HTTP status returned by the peer.
    pub status: StatusCode,
    /// Bounded response body bytes.
    pub body: Bytes,
    /// Verified peer TLS identity from the QUIC connection.
    pub peer_identity: TlsIdentity,
}

/// Errors returned by the bounded HTTP/3 proof.
#[derive(Debug, Error)]
pub enum PeerProbeError {
    /// Invalid zero-valued limits.
    #[error("peer probe limits must be non-zero")]
    InvalidLimits,
    /// No public-key pin was configured.
    #[error("peer probe requires at least one approved peer SPKI pin")]
    EmptyPeerPins,
    /// The body would exceed the configured bound.
    #[error("peer probe body exceeds bound: observed {observed} bytes, maximum {maximum} bytes")]
    BodyTooLarge {
        /// Bytes observed after the newest chunk.
        observed: usize,
        /// Configured maximum body size.
        maximum: usize,
    },
    /// The QUIC peer did not expose a rustls certificate chain.
    #[error("peer QUIC connection did not expose a rustls certificate chain")]
    MissingPeerCertificate,
    /// The dynamic peer identity was not the rustls certificate vector used by
    /// Quinn's rustls backend.
    #[error("peer QUIC identity used an unsupported certificate representation")]
    UnsupportedPeerIdentity,
    /// The peer certificate did not carry a relay peer role marker.
    #[error("peer certificate is not a relay peer identity")]
    WrongPeerRole,
    /// The peer certificate key was not approved by the explicit pin set.
    #[error("peer SPKI pin is not approved: {0}")]
    UnapprovedPeer(SpkiSha256),
    /// Quinn rejected a connection operation.
    #[error("QUIC peer operation failed: {0}")]
    Quic(String),
    /// H3 rejected a request or response.
    #[error("HTTP/3 peer operation failed: {0}")]
    H3(String),
    /// A handshake or body exchange exceeded its deadline.
    #[error("HTTP/3 peer probe timed out")]
    Timeout,
    /// A supervised connection task failed to join.
    #[error("HTTP/3 peer task failed: {0}")]
    Task(#[source] tokio::task::JoinError),
    /// TLS certificate metadata could not be parsed after the QUIC verifier
    /// completed.
    #[error("verified peer certificate metadata failed: {0}")]
    Identity(#[source] TlsIdentityError),
}

/// Serve the bounded authenticated HTTP/3 body probe on an already configured
/// Quinn endpoint.
///
/// The endpoint must be created with a TLS 1.3 `quinn::ServerConfig` from
/// [`crate::load_peer_server_config_from_pem`].  Every connection requires a
/// verified peer certificate, the `peer` URI SAN role, and a matching
/// [`ApprovedPeerPins`] entry before H3 request handling begins.
pub async fn serve_peer_probe(
    endpoint: quinn::Endpoint,
    approved_pins: ApprovedPeerPins,
    limits: PeerProbeLimits,
    cancel: CancellationToken,
) -> Result<(), PeerProbeError> {
    let permits = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let permit = match permits.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        // Dropping Incoming refuses the connection before an
                        // H3 stream can allocate request buffers.
                        continue;
                    }
                };
                let approved_pins = approved_pins.clone();
                let limits = limits.clone();
                let connection_cancel = cancel.child_token();
                tasks.spawn(async move {
                    let _permit = permit;
                    timeout(limits.timeout, async {
                        let connection = incoming.await.map_err(|error| PeerProbeError::Quic(error.to_string()))?;
                        serve_incoming_connection(connection, &approved_pins, &limits, connection_cancel).await
                    }).await.map_err(|_| PeerProbeError::Timeout)?
                });
            }
            Some(result) = tasks.join_next() => {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => tracing::debug!(?error, "HTTP/3 peer probe connection closed"),
                    Err(error) => return Err(PeerProbeError::Task(error)),
                }
            }
        }
    }

    endpoint.close(quinn::VarInt::from_u32(0), b"peer probe shutdown");
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) if cancel.is_cancelled() => {
                tracing::debug!(
                    ?error,
                    "HTTP/3 peer probe connection stopped during shutdown"
                );
            }
            Ok(Err(error)) => return Err(error),
            Err(error) => return Err(PeerProbeError::Task(error)),
        }
    }
    Ok(())
}

async fn serve_incoming_connection(
    connection: quinn::Connection,
    approved_pins: &ApprovedPeerPins,
    limits: &PeerProbeLimits,
    cancel: CancellationToken,
) -> Result<(), PeerProbeError> {
    let identity = verified_peer_identity(&connection)?;
    verify_peer(&identity, approved_pins)?;

    let quic = h3_quinn::Connection::new(connection);
    let mut builder = h3::server::builder();
    builder.max_field_section_size(16 * 1024);
    let mut h3_connection = builder
        .build::<_, Bytes>(quic)
        .await
        .map_err(|error| PeerProbeError::H3(error.to_string()))?;

    loop {
        let resolver = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            result = h3_connection.accept() => result.map_err(|error| PeerProbeError::H3(error.to_string()))?,
        };
        let Some(resolver) = resolver else {
            return Ok(());
        };
        handle_request(resolver, limits).await?;
    }
}

async fn handle_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    limits: &PeerProbeLimits,
) -> Result<(), PeerProbeError> {
    let (_request, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(|error| PeerProbeError::H3(error.to_string()))?;
    let body = receive_body(&mut stream, limits.max_body_bytes).await?;
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .map_err(|error| PeerProbeError::H3(error.to_string()))?;
    stream
        .send_response(response)
        .await
        .map_err(|error| PeerProbeError::H3(error.to_string()))?;
    stream
        .send_data(body)
        .await
        .map_err(|error| PeerProbeError::H3(error.to_string()))?;
    stream
        .finish()
        .await
        .map_err(|error| PeerProbeError::H3(error.to_string()))?;
    Ok(())
}

async fn receive_body<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    maximum: usize,
) -> Result<Bytes, PeerProbeError>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let mut body = Vec::new();
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .map_err(|error| PeerProbeError::H3(error.to_string()))?
    {
        let observed = body.len().saturating_add(chunk.remaining());
        if observed > maximum {
            stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
            return Err(PeerProbeError::BodyTooLarge { observed, maximum });
        }
        body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
    }
    Ok(Bytes::from(body))
}

/// Send one bounded HTTP/3 request body and receive the peer's echoed body.
///
/// The endpoint must use [`crate::load_peer_client_config_from_pem`].  The
/// client performs an explicit SPKI pin check in addition to normal rustls
/// CA/name/usage validation and never calls Quinn's 0-RTT APIs.
pub async fn peer_probe(
    endpoint: &quinn::Endpoint,
    address: SocketAddr,
    server_name: &str,
    request_body: Bytes,
    limits: PeerProbeLimits,
    approved_pins: &ApprovedPeerPins,
) -> Result<PeerProbeResponse, PeerProbeError> {
    if request_body.len() > limits.max_body_bytes {
        return Err(PeerProbeError::BodyTooLarge {
            observed: request_body.len(),
            maximum: limits.max_body_bytes,
        });
    }

    let connecting = endpoint
        .connect(address, server_name)
        .map_err(|error| PeerProbeError::Quic(error.to_string()))?;
    let connection = timeout(limits.timeout, connecting)
        .await
        .map_err(|_| PeerProbeError::Timeout)?
        .map_err(|error| PeerProbeError::Quic(error.to_string()))?;
    let identity = verified_peer_identity(&connection)?;
    verify_peer(&identity, approved_pins)?;

    let quic = h3_quinn::Connection::new(connection);
    let mut builder = h3::client::builder();
    builder.max_field_section_size(16 * 1024);
    let (mut driver, mut sender) = timeout(limits.timeout, builder.build::<_, _, Bytes>(quic))
        .await
        .map_err(|_| PeerProbeError::Timeout)?
        .map_err(|error| PeerProbeError::H3(error.to_string()))?;
    let driver_task = tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    let result = timeout(limits.timeout, async {
        let request = Request::builder()
            .method("POST")
            .uri("https://agent-tunnel.peer/probe")
            .body(())
            .map_err(|error| PeerProbeError::H3(error.to_string()))?;
        let mut stream = sender
            .send_request(request)
            .await
            .map_err(|error| PeerProbeError::H3(error.to_string()))?;
        stream
            .send_data(request_body)
            .await
            .map_err(|error| PeerProbeError::H3(error.to_string()))?;
        stream
            .finish()
            .await
            .map_err(|error| PeerProbeError::H3(error.to_string()))?;
        let response = stream
            .recv_response()
            .await
            .map_err(|error| PeerProbeError::H3(error.to_string()))?;
        let body = receive_client_body(&mut stream, limits.max_body_bytes).await?;
        Ok::<_, PeerProbeError>(PeerProbeResponse {
            status: response.status(),
            body,
            peer_identity: identity,
        })
    })
    .await
    .map_err(|_| PeerProbeError::Timeout)?;
    driver_task.abort();
    result
}

async fn receive_client_body<S>(
    stream: &mut h3::client::RequestStream<S, Bytes>,
    maximum: usize,
) -> Result<Bytes, PeerProbeError>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let mut body = Vec::new();
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .map_err(|error| PeerProbeError::H3(error.to_string()))?
    {
        let observed = body.len().saturating_add(chunk.remaining());
        if observed > maximum {
            stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
            return Err(PeerProbeError::BodyTooLarge { observed, maximum });
        }
        body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
    }
    Ok(Bytes::from(body))
}

pub(crate) fn verified_peer_identity(
    connection: &quinn::Connection,
) -> Result<TlsIdentity, PeerProbeError> {
    let identity = connection
        .peer_identity()
        .ok_or(PeerProbeError::MissingPeerCertificate)?;
    let certificates = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| PeerProbeError::UnsupportedPeerIdentity)?;
    parse_leaf_identity(&certificates).map_err(PeerProbeError::Identity)
}

pub(crate) fn verify_peer(
    identity: &TlsIdentity,
    approved_pins: &ApprovedPeerPins,
) -> Result<(), PeerProbeError> {
    if !matches!(identity.role(), CertificateRole::Peer { .. }) {
        return Err(PeerProbeError::WrongPeerRole);
    }
    if !approved_pins.contains(identity.spki_sha256()) {
        return Err(PeerProbeError::UnapprovedPeer(identity.spki_sha256()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_reject_unbounded_zero_values() {
        assert!(matches!(
            PeerProbeLimits::new(0, Duration::from_secs(1), 1),
            Err(PeerProbeError::InvalidLimits)
        ));
        assert!(matches!(
            PeerProbeLimits::new(1, Duration::ZERO, 1),
            Err(PeerProbeError::InvalidLimits)
        ));
        assert!(matches!(
            PeerProbeLimits::new(1, Duration::from_secs(1), 0),
            Err(PeerProbeError::InvalidLimits)
        ));
    }

    #[test]
    fn pins_are_non_empty_sorted_and_deduplicated() {
        let first = SpkiSha256::from_bytes([1; 32]);
        let second = SpkiSha256::from_bytes([2; 32]);
        let pins = ApprovedPeerPins::new([second, first, second]).unwrap();
        assert_eq!(pins.len(), 2);
        assert!(pins.contains(first));
        assert!(pins.contains(second));
        assert!(matches!(
            ApprovedPeerPins::new(std::iter::empty()),
            Err(PeerProbeError::EmptyPeerPins)
        ));
    }
}
