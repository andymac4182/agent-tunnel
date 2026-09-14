//! Reusable, bounded HTTP/3 transport for authenticated relay peers.
//!
//! This module owns the QUIC/HTTP/3 connection lifecycle and body chunk
//! accounting.  It deliberately does not know about relay ownership,
//! tenants, Redis, or application routing.  A caller supplies a policy which
//! is evaluated after the peer certificate has been verified and before a
//! request body is admitted.

use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex, OnceLock,
        atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::{Buf, Bytes};
use http::{Request, Response};
use thiserror::Error;
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, watch},
    task::{JoinHandle, JoinSet},
    time::{Instant, sleep_until, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

use crate::{
    peer_probe::{ApprovedPeerPins, PeerProbeError, verified_peer_identity},
    tls::TlsIdentity,
};

/// The default maximum size of one body chunk exposed by this transport.
pub const DEFAULT_PEER_BODY_CHUNK_BYTES: usize = 64 * 1024;

/// The default maximum body bytes counted for one request direction.
pub const DEFAULT_PEER_STREAM_BODY_BYTES: usize = 256 * 1024;

/// The default maximum body bytes counted across one HTTP/3 connection.
pub const DEFAULT_PEER_CONNECTION_BODY_BYTES: usize = 8 * 1024 * 1024;

/// The default number of simultaneously admitted peer connections.
pub const DEFAULT_PEER_CONNECTIONS: usize = 16;

/// The default number of simultaneously admitted request streams per peer
/// connection.
pub const DEFAULT_PEER_STREAMS_PER_CONNECTION: usize = 128;

/// The default number of distinct destinations retained by a client pool.
pub const DEFAULT_PEER_DESTINATIONS: usize = 32;

/// The default HTTP/3 header section bound.
pub const DEFAULT_PEER_HEADER_BYTES: usize = 16 * 1024;

/// The default deadline for a QUIC/TLS handshake and HTTP/3 setup.
pub const DEFAULT_PEER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a connection checkout waits for a permit that is about to be
/// released before it reports typed capacity exhaustion.
///
/// Replacing an unusable pooled connection releases its permit when the last
/// handle drops, which is ordinarily immediate; this grace covers that handoff
/// without letting a caller sit on an exhausted pool. It is far below any
/// probe or request budget, so exhaustion stays observable as capacity rather
/// than surfacing as that caller's own timeout.
const CAPACITY_RELEASE_GRACE: Duration = Duration::from_millis(250);

/// The default absolute checkout/setup deadline for one request stream.
pub const DEFAULT_PEER_STREAM_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// The default QUIC and per-operation peer inactivity timeout.
pub const DEFAULT_PEER_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// The default bounded budget for a peer connection drain and joined shutdown.
pub const DEFAULT_PEER_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of relay peer SPKI keys retained by a dynamic pin
/// snapshot.  A membership coordinator may keep current and next keys for a
/// bounded relay roster; larger snapshots are rejected before allocation.
pub const MAX_DYNAMIC_PEER_PINS: usize = 64;

/// Bounds applied independently to peer connections, streams, and body
/// chunks.
///
/// `max_stream_body_bytes` and `max_connection_body_bytes` bound bytes that
/// are currently in flight through the transport in either direction.  A
/// returned receive chunk carries its reservation until the caller drops it;
/// a send reservation lasts until the write completes, is cancelled, or
/// fails.  An application forwarding queue must apply its own charged
/// reservation before retaining a copy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerTransportLimits {
    /// Maximum body chunk accepted or returned by one API call.
    pub max_chunk_bytes: usize,
    /// Maximum in-flight body bytes across one request stream's directions.
    pub max_stream_body_bytes: usize,
    /// Maximum in-flight body bytes across one connection.
    pub max_connection_body_bytes: usize,
    /// Maximum active connections supervised by one server or client pool.
    pub max_connections: usize,
    /// Maximum active request streams on one connection.
    pub max_streams_per_connection: usize,
    /// Maximum distinct destinations retained by one client pool.
    pub max_destinations: usize,
    /// Maximum encoded HTTP/3 header section accepted from a peer.
    pub max_header_bytes: usize,
    /// Deadline for QUIC/TLS connection establishment and HTTP/3 setup.
    pub handshake_timeout: Duration,
    /// Absolute checkout/setup deadline for each admitted request stream.
    ///
    /// This is deliberately not a total lifetime for an admitted request.
    /// Long-lived streams are governed by [`Self::idle_timeout`] between
    /// transport operations.
    pub stream_timeout: Duration,
    /// Maximum allowed inactivity between HTTP/3 operations on a stream and
    /// the QUIC connection idle timeout advertised to the peer.
    pub idle_timeout: Duration,
    /// Absolute budget used while closing a peer connection and joining its
    /// child tasks.
    pub drain_timeout: Duration,
}

impl Default for PeerTransportLimits {
    fn default() -> Self {
        Self {
            max_chunk_bytes: DEFAULT_PEER_BODY_CHUNK_BYTES,
            max_stream_body_bytes: DEFAULT_PEER_STREAM_BODY_BYTES,
            max_connection_body_bytes: DEFAULT_PEER_CONNECTION_BODY_BYTES,
            max_connections: DEFAULT_PEER_CONNECTIONS,
            max_streams_per_connection: DEFAULT_PEER_STREAMS_PER_CONNECTION,
            max_destinations: DEFAULT_PEER_DESTINATIONS,
            max_header_bytes: DEFAULT_PEER_HEADER_BYTES,
            handshake_timeout: DEFAULT_PEER_HANDSHAKE_TIMEOUT,
            stream_timeout: DEFAULT_PEER_STREAM_TIMEOUT,
            idle_timeout: DEFAULT_PEER_IDLE_TIMEOUT,
            drain_timeout: DEFAULT_PEER_DRAIN_TIMEOUT,
        }
    }
}

impl PeerTransportLimits {
    /// Validate all configured bounds before creating a supervisor or pool.
    pub fn validate(&self) -> Result<(), PeerTransportError> {
        if self.max_chunk_bytes == 0
            || self.max_stream_body_bytes == 0
            || self.max_connection_body_bytes == 0
            || self.max_connections == 0
            || self.max_streams_per_connection == 0
            || self.max_destinations == 0
            || self.max_header_bytes == 0
            || self.handshake_timeout.is_zero()
            || self.stream_timeout.is_zero()
            || self.idle_timeout.is_zero()
            || self.drain_timeout.is_zero()
            || self.max_chunk_bytes > self.max_stream_body_bytes
            || self.max_stream_body_bytes > self.max_connection_body_bytes
        {
            return Err(PeerTransportError::InvalidLimits);
        }
        Ok(())
    }

    /// Construct and validate transport limits.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        max_chunk_bytes: usize,
        max_stream_body_bytes: usize,
        max_connection_body_bytes: usize,
        max_connections: usize,
        max_streams_per_connection: usize,
        max_destinations: usize,
        max_header_bytes: usize,
        handshake_timeout: Duration,
        stream_timeout: Duration,
    ) -> Result<Self, PeerTransportError> {
        let limits = Self {
            max_chunk_bytes,
            max_stream_body_bytes,
            max_connection_body_bytes,
            max_connections,
            max_streams_per_connection,
            max_destinations,
            max_header_bytes,
            handshake_timeout,
            stream_timeout,
            idle_timeout: DEFAULT_PEER_IDLE_TIMEOUT,
            drain_timeout: DEFAULT_PEER_DRAIN_TIMEOUT,
        };
        limits.validate()?;
        Ok(limits)
    }

    /// Construct and validate transport limits with explicit idle and drain
    /// policy values.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_timeouts(
        max_chunk_bytes: usize,
        max_stream_body_bytes: usize,
        max_connection_body_bytes: usize,
        max_connections: usize,
        max_streams_per_connection: usize,
        max_destinations: usize,
        max_header_bytes: usize,
        handshake_timeout: Duration,
        stream_timeout: Duration,
        idle_timeout: Duration,
        drain_timeout: Duration,
    ) -> Result<Self, PeerTransportError> {
        Self::new(
            max_chunk_bytes,
            max_stream_body_bytes,
            max_connection_body_bytes,
            max_connections,
            max_streams_per_connection,
            max_destinations,
            max_header_bytes,
            handshake_timeout,
            stream_timeout,
        )?
        .with_timeouts(idle_timeout, drain_timeout)
    }

    /// Return these limits with the deployment's peer idle and drain policy.
    ///
    /// The idle timeout is refreshed by each successful transport operation,
    /// so an active stream is not killed merely because it has been open for a
    /// long time.
    pub fn with_timeouts(
        mut self,
        idle_timeout: Duration,
        drain_timeout: Duration,
    ) -> Result<Self, PeerTransportError> {
        self.idle_timeout = idle_timeout;
        self.drain_timeout = drain_timeout;
        self.validate()?;
        Ok(self)
    }

    /// Apply this peer policy to a QUIC server configuration before creating
    /// its endpoint. QUIC idle timeout and stream ceilings are negotiated
    /// during the handshake and cannot be added after a connection is
    /// established.
    pub fn apply_to_server_config(
        &self,
        config: &mut quinn::ServerConfig,
    ) -> Result<(), PeerTransportError> {
        config.transport_config(self.quic_transport_config()?);
        Ok(())
    }

    /// Apply this peer policy to a QUIC client configuration before it is
    /// installed on an endpoint.
    pub fn apply_to_client_config(
        &self,
        config: &mut quinn::ClientConfig,
    ) -> Result<(), PeerTransportError> {
        config.transport_config(self.quic_transport_config()?);
        Ok(())
    }

    fn quic_transport_config(&self) -> Result<Arc<quinn::TransportConfig>, PeerTransportError> {
        self.validate()?;
        let idle_timeout = quinn::IdleTimeout::try_from(self.idle_timeout)
            .map_err(|_| PeerTransportError::InvalidLimits)?;
        let streams = quinn::VarInt::from_u64(self.max_streams_per_connection as u64)
            .map_err(|_| PeerTransportError::InvalidLimits)?;
        // `configure_quic_connection` already uses 16 for H3 control/QPACK
        // unidirectional streams.  Advertise that same bounded value during
        // the handshake instead of briefly exposing Quinn's default of 100.
        let uni_streams = quinn::VarInt::from_u32(16);
        let mut transport = quinn::TransportConfig::default();
        transport
            .max_idle_timeout(Some(idle_timeout))
            .max_concurrent_bidi_streams(streams)
            .max_concurrent_uni_streams(uni_streams);
        Ok(Arc::new(transport))
    }
}

/// A bounded body chunk returned by or supplied to the peer transport.
///
/// Chunks returned by a receive operation retain their in-flight transport
/// reservation for as long as any clone of the chunk is retained.  Consuming
/// a chunk with [`Self::into_bytes`] transfers ownership to the caller and
/// releases that transport reservation; caller-owned copies are governed by
/// the caller's own budget.  Zero-length chunks carry no reservation metadata.
pub struct PeerBodyChunk {
    bytes: Bytes,
    _charge: Option<Arc<BodyCharge>>,
}

impl Clone for PeerBodyChunk {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            _charge: self._charge.clone(),
        }
    }
}

impl std::fmt::Debug for PeerBodyChunk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PeerBodyChunk")
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl PartialEq for PeerBodyChunk {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for PeerBodyChunk {}

impl PeerBodyChunk {
    /// Construct a chunk using the default 64 KiB chunk bound.
    pub fn new(bytes: Bytes) -> Result<Self, PeerTransportError> {
        Self::with_limit(bytes, DEFAULT_PEER_BODY_CHUNK_BYTES)
    }

    /// Construct a chunk with an explicit caller-selected bound.
    pub fn with_limit(bytes: Bytes, maximum: usize) -> Result<Self, PeerTransportError> {
        if bytes.len() > maximum {
            return Err(PeerTransportError::ChunkTooLarge {
                observed: bytes.len(),
                maximum,
            });
        }
        Ok(Self {
            bytes,
            _charge: None,
        })
    }

    /// Return the chunk length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return whether the chunk is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Borrow the chunk bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// Consume the wrapper and return the owned bytes.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }

    fn from_received(bytes: Bytes, charge: BodyCharge) -> Self {
        let _charge = (charge.length != 0).then(|| Arc::new(charge));
        Self { bytes, _charge }
    }
}

/// A peer destination selected by the caller's membership snapshot.
///
/// The transport never resolves or chooses a destination.  The `server_name`
/// is used only for TLS certificate-name verification; the address must come
/// from an already-authorized membership record.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PeerDestination {
    /// Private QUIC endpoint address.
    pub address: SocketAddr,
    /// TLS server name expected for the peer certificate.
    pub server_name: String,
}

impl PeerDestination {
    /// Construct a destination from an approved address and TLS name.
    #[must_use]
    pub fn new(address: SocketAddr, server_name: impl Into<String>) -> Self {
        Self {
            address,
            server_name: server_name.into(),
        }
    }
}

/// A redacted snapshot of one pooled peer connection's admission state.
///
/// This is intentionally observational: it does not expose certificates,
/// payloads, or endpoint names, and it cannot alter pool admission.  The
/// capacity fixtures use it to distinguish a full stream semaphore from a
/// closed pooled connection whose connection permit is still retained by a
/// long-lived stream handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerPoolConnectionStats {
    /// Number of stream permits currently available on this connection.
    pub available_stream_permits: usize,
    /// Configured stream permit ceiling for this connection.
    pub max_stream_permits: usize,
    /// Whether QUIC has reported a terminal close reason.
    pub closed: bool,
}

/// A bounded, redacted snapshot of the client pool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerPoolStats {
    /// Number of connection permits not currently owned by a connection.
    pub available_connection_permits: usize,
    /// Configured connection permit ceiling.
    pub max_connection_permits: usize,
    /// Connections currently retained in the destination map.
    pub pooled_connections: Vec<PeerPoolConnectionStats>,
}

/// The transport stage currently executing for one request-stream open.
///
/// This observer is optional and read-only.  It exists for bounded fixtures
/// that need to distinguish stream-permit checkout, sender-mutex wait, and
/// HTTP/3 dispatch when their outer deadline cancels an open attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PeerTransportOpenStage {
    /// Waiting for the configured per-connection stream permit.
    StreamPermitCheckout = 0,
    /// Waiting for the shared HTTP/3 sender mutex.
    SenderLock = 1,
    /// Dispatching the HTTP/3 request, including QUIC bidi-stream checkout.
    H3Dispatch = 2,
    /// The request stream was returned to the caller.
    Complete = 3,
}

/// A bounded stage observer for one transport request-stream attempt.
#[derive(Clone, Debug)]
pub struct PeerOpenProgress {
    stage: Arc<AtomicU8>,
}

impl PeerOpenProgress {
    /// Create an observer whose initial stage is stream-permit checkout.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stage: Arc::new(AtomicU8::new(
                PeerTransportOpenStage::StreamPermitCheckout as u8,
            )),
        }
    }

    /// Return the last stage recorded by this request attempt.
    #[must_use]
    pub fn stage(&self) -> PeerTransportOpenStage {
        match self.stage.load(Ordering::Acquire) {
            1 => PeerTransportOpenStage::SenderLock,
            2 => PeerTransportOpenStage::H3Dispatch,
            3 => PeerTransportOpenStage::Complete,
            _ => PeerTransportOpenStage::StreamPermitCheckout,
        }
    }

    fn set_stage(&self, stage: PeerTransportOpenStage) {
        self.stage.store(stage as u8, Ordering::Release);
    }
}

impl Default for PeerOpenProgress {
    fn default() -> Self {
        Self::new()
    }
}

/// A bounded, immutable view of the relay SPKI pins currently approved by a
/// caller-owned membership coordinator.
///
/// An empty snapshot is fail-closed: it rejects every peer and causes active
/// connections whose pin is absent to close.  Transport does not mint or
/// validate membership records; callers must update [`SharedPeerPins`] only
/// from an already verified membership snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerPinSnapshot {
    pins: Option<ApprovedPeerPins>,
    revision: u64,
}

impl PeerPinSnapshot {
    fn new(pins: Option<ApprovedPeerPins>, revision: u64) -> Self {
        Self { pins, revision }
    }

    /// Return whether this snapshot approves the supplied SPKI pin.
    #[must_use]
    pub fn contains(&self, pin: crate::SpkiSha256) -> bool {
        self.pins.as_ref().is_some_and(|pins| pins.contains(pin))
    }

    /// Return the number of approved SPKI pins in this snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pins.as_ref().map_or(0, ApprovedPeerPins::len)
    }

    /// Return whether this snapshot is fail-closed and approves no peers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pins.is_none()
    }

    /// Return the monotonically increasing update revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    fn verify(&self, identity: &TlsIdentity) -> Result<(), PeerProbeError> {
        if !identity.role().is_peer() {
            return Err(PeerProbeError::WrongPeerRole);
        }
        if !self.contains(identity.spki_sha256()) {
            return Err(PeerProbeError::UnapprovedPeer(identity.spki_sha256()));
        }
        Ok(())
    }
}

/// Shared dynamic relay pin state for peer clients and servers.
///
/// Updates publish a bounded watch revision.  Existing connections observe
/// revocation and close themselves; callers can invoke
/// [`PeerClient::refresh_pins`] or [`PeerClient::close_peer`] when they need a
/// joined cleanup point.  Replacing with an empty iterator is supported and
/// deliberately fails closed.  Certificate expiry is also a caller concern:
/// the membership coordinator must remove expired keys (or publish an empty
/// snapshot) so the watcher can close the corresponding connection.
#[derive(Clone, Debug)]
pub struct SharedPeerPins {
    updates: watch::Sender<PeerPinSnapshot>,
}

impl SharedPeerPins {
    /// Create dynamic pin state from the non-empty static pin set.
    pub fn new(pins: ApprovedPeerPins) -> Result<Self, PeerTransportError> {
        if pins.len() > MAX_DYNAMIC_PEER_PINS {
            return Err(PeerTransportError::TooManyPeerPins {
                observed: pins.len(),
                maximum: MAX_DYNAMIC_PEER_PINS,
            });
        }
        let (updates, _receiver) = watch::channel(PeerPinSnapshot::new(Some(pins), 0));
        Ok(Self { updates })
    }

    /// Create fail-closed dynamic pin state with no approved keys.
    #[must_use]
    pub fn empty() -> Self {
        let (updates, _receiver) = watch::channel(PeerPinSnapshot::new(None, 0));
        Self { updates }
    }

    /// Return the current immutable pin snapshot.
    #[must_use]
    pub fn snapshot(&self) -> PeerPinSnapshot {
        self.updates.borrow().clone()
    }

    /// Replace the approved key set from a bounded caller-owned membership
    /// snapshot.  Empty input revokes every key and fails closed.
    pub fn replace<I>(&self, pins: I) -> Result<(), PeerTransportError>
    where
        I: IntoIterator<Item = crate::SpkiSha256>,
    {
        let mut values = Vec::with_capacity(MAX_DYNAMIC_PEER_PINS.min(8));
        for pin in pins {
            values.push(pin);
            if values.len() > MAX_DYNAMIC_PEER_PINS {
                return Err(PeerTransportError::TooManyPeerPins {
                    observed: values.len(),
                    maximum: MAX_DYNAMIC_PEER_PINS,
                });
            }
        }
        values.sort_unstable();
        values.dedup();
        let pins = if values.is_empty() {
            None
        } else {
            Some(
                ApprovedPeerPins::new(values)
                    .map_err(|error| PeerTransportError::Authentication(error.to_string()))?,
            )
        };
        self.replace_snapshot(pins);
        Ok(())
    }

    /// Replace the approved key set using an existing static pin set.
    ///
    /// This is useful when a membership coordinator already validated and
    /// deduplicated its keys.  An empty set cannot be represented by
    /// [`ApprovedPeerPins`]; use [`SharedPeerPins::empty`] or
    /// [`SharedPeerPins::replace`] to revoke all keys.
    pub fn replace_approved(&self, pins: ApprovedPeerPins) -> Result<(), PeerTransportError> {
        if pins.len() > MAX_DYNAMIC_PEER_PINS {
            return Err(PeerTransportError::TooManyPeerPins {
                observed: pins.len(),
                maximum: MAX_DYNAMIC_PEER_PINS,
            });
        }
        self.replace_snapshot(Some(pins));
        Ok(())
    }

    fn replace_snapshot(&self, pins: Option<ApprovedPeerPins>) {
        let revision = self.updates.borrow().revision.saturating_add(1);
        self.updates
            .send_replace(PeerPinSnapshot::new(pins, revision));
    }

    fn subscribe(&self) -> watch::Receiver<PeerPinSnapshot> {
        self.updates.subscribe()
    }
}

/// Policy callback error returned when a caller rejects a request.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
#[error("peer request rejected by caller policy")]
pub struct PeerPolicyRejected;

/// Routing/membership policy consulted after TLS peer authentication and
/// before request body admission.
pub trait PeerRequestPolicy: Send + Sync + 'static {
    /// Return `true` only when this authenticated peer and request are
    /// allowed by the caller's current membership snapshot.
    fn authorize(&self, identity: &TlsIdentity, request: &Request<()>) -> bool;
}

impl<F> PeerRequestPolicy for F
where
    F: Fn(&TlsIdentity, &Request<()>) -> bool + Send + Sync + 'static,
{
    fn authorize(&self, identity: &TlsIdentity, request: &Request<()>) -> bool {
        self(identity, request)
    }
}

/// A boxed asynchronous server request handler.
pub type PeerHandlerFuture = Pin<Box<dyn Future<Output = Result<(), PeerTransportError>> + Send>>;

/// Application callback for admitted peer requests.
pub trait PeerRequestHandler: Send + Sync + 'static {
    /// Handle one request after its headers and authenticated peer identity
    /// have been admitted.
    fn handle(
        &self,
        identity: TlsIdentity,
        request: Request<()>,
        stream: PeerServerStream,
    ) -> PeerHandlerFuture;
}

impl<F, Fut> PeerRequestHandler for F
where
    F: Fn(TlsIdentity, Request<()>, PeerServerStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), PeerTransportError>> + Send + 'static,
{
    fn handle(
        &self,
        identity: TlsIdentity,
        request: Request<()>,
        stream: PeerServerStream,
    ) -> PeerHandlerFuture {
        Box::pin(self(identity, request, stream))
    }
}

/// Errors from peer transport setup, admission, body bounds, or supervision.
#[derive(Debug, Error)]
pub enum PeerTransportError {
    /// One or more limits were zero, inconsistent, or otherwise unusable.
    #[error("peer transport limits are invalid")]
    InvalidLimits,
    /// The connection or destination pool is at capacity.
    #[error("peer transport capacity is exhausted")]
    Capacity,
    /// A dynamic pin snapshot exceeded its configured key bound.
    #[error("peer pin snapshot exceeds bound: observed {observed} keys, maximum {maximum}")]
    TooManyPeerPins {
        /// Number of keys observed before rejecting the snapshot.
        observed: usize,
        /// Maximum number of keys retained by one dynamic snapshot.
        maximum: usize,
    },
    /// The authenticated peer failed the role or SPKI check.
    #[error("peer authentication failed: {0}")]
    Authentication(String),
    /// A request was rejected by the caller-supplied policy.
    #[error("peer request rejected by caller policy")]
    PolicyRejected,
    /// A body chunk exceeded the explicit per-call bound.
    #[error("peer body chunk exceeds bound: observed {observed} bytes, maximum {maximum} bytes")]
    ChunkTooLarge {
        /// Bytes in the rejected chunk.
        observed: usize,
        /// Maximum permitted chunk bytes.
        maximum: usize,
    },
    /// A stream or connection body budget would be exceeded.
    #[error("peer body exceeds bound: observed {observed} bytes, maximum {maximum} bytes")]
    BodyTooLarge {
        /// Bytes observed after the rejected chunk.
        observed: usize,
        /// Maximum permitted bytes.
        maximum: usize,
    },
    /// A QUIC operation failed.
    #[error("peer QUIC operation failed: {0}")]
    Quic(String),
    /// An HTTP/3 operation failed.
    #[error("peer HTTP/3 operation failed: {0}")]
    H3(String),
    /// The peer is gracefully closing and did not process this request.
    ///
    /// This is a pre-dispatch outcome: either the request never reached the
    /// peer's request-stream admission boundary (HTTP/3 GOAWAY observed before
    /// the stream was created), or a raced stream was refused with
    /// `H3_REQUEST_REJECTED`, which per RFC 9114 means the peer did not process
    /// it.  Both are safe to report as `not_dispatched`.  A stream the peer
    /// reset for any other reason after it may have been dispatched still
    /// reports [`Self::H3`] or [`Self::Quic`], preserving `unknown` certainty.
    #[error("peer HTTP/3 connection is gracefully closing")]
    GoAway,
    /// A bounded operation exceeded its deadline.
    #[error("peer transport operation timed out")]
    Timeout,
    /// The caller cancelled a transport operation.
    #[error("peer transport operation cancelled")]
    Cancelled,
    /// A supervised task could not be joined.
    #[error("peer transport task failed: {0}")]
    Task(#[source] tokio::task::JoinError),
}

type ClientSender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type ClientStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type ClientSendStream = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type ClientRecvStream = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;
type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type ServerSendStream = h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type ServerRecvStream = h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;

fn planned_idle_result(
    connection_result: h3::error::ConnectionError,
) -> Result<(), PeerTransportError> {
    if connection_result.is_h3_no_error()
        || connection_result.is_remote_no_error_application_close()
    {
        Ok(())
    } else {
        Err(PeerTransportError::H3(connection_result.to_string()))
    }
}

/// Classify an HTTP/3 client stream error raised after a request stream was
/// created.  A peer that is gracefully closing refuses or resets the stream
/// with `RemoteClosing` or a `H3_REQUEST_REJECTED` terminate code; per
/// [RFC 9114 §8.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-8.1)
/// `H3_REQUEST_REJECTED` means the owner did not process the request, so both
/// map to the typed pre-dispatch [`PeerTransportError::GoAway`]
/// (`not_dispatched`).  An already admitted stream that the owner reset for any
/// other reason keeps its generic HTTP/3 classification, preserving the
/// `unknown`-certainty contract for work that may have been dispatched.
fn classify_client_stream_error(error: h3::error::StreamError) -> PeerTransportError {
    match &error {
        h3::error::StreamError::RemoteClosing { .. } => PeerTransportError::GoAway,
        h3::error::StreamError::RemoteTerminate { code, .. }
            if *code == h3::error::Code::H3_REQUEST_REJECTED =>
        {
            PeerTransportError::GoAway
        }
        _ => PeerTransportError::H3(error.to_string()),
    }
}

struct StreamLease {
    _permit: OwnedSemaphorePermit,
}

struct BodyBudget {
    stream_bytes: Arc<AtomicUsize>,
    connection_bytes: Arc<AtomicUsize>,
    max_stream_bytes: usize,
    max_connection_bytes: usize,
    max_chunk_bytes: usize,
}

impl BodyBudget {
    fn reserve(&self, length: usize) -> Result<BodyCharge, PeerTransportError> {
        if length > self.max_chunk_bytes {
            return Err(PeerTransportError::ChunkTooLarge {
                observed: length,
                maximum: self.max_chunk_bytes,
            });
        }

        reserve_counter(&self.stream_bytes, length, self.max_stream_bytes).map_err(|observed| {
            PeerTransportError::BodyTooLarge {
                observed,
                maximum: self.max_stream_bytes,
            }
        })?;

        if let Err(observed) = reserve_counter(
            self.connection_bytes.as_ref(),
            length,
            self.max_connection_bytes,
        ) {
            self.stream_bytes.fetch_sub(length, Ordering::AcqRel);
            return Err(PeerTransportError::BodyTooLarge {
                observed,
                maximum: self.max_connection_bytes,
            });
        }
        Ok(BodyCharge {
            stream: self.stream_bytes.clone(),
            connection: self.connection_bytes.clone(),
            length,
        })
    }
}

/// An in-flight body reservation owned by one send operation or returned
/// receive chunk.  Dropping it releases both stream and connection bytes.
#[derive(Debug)]
struct BodyCharge {
    stream: Arc<AtomicUsize>,
    connection: Arc<AtomicUsize>,
    length: usize,
}

impl Drop for BodyCharge {
    fn drop(&mut self) {
        self.stream.fetch_sub(self.length, Ordering::AcqRel);
        self.connection.fetch_sub(self.length, Ordering::AcqRel);
    }
}

fn reserve_counter(counter: &AtomicUsize, length: usize, maximum: usize) -> Result<(), usize> {
    loop {
        let current = counter.load(Ordering::Acquire);
        let observed = current.saturating_add(length);
        if observed > maximum {
            return Err(observed);
        }
        if counter
            .compare_exchange(current, observed, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Ok(());
        }
    }
}

fn body_budget(
    limits: &PeerTransportLimits,
    connection_bytes: Arc<AtomicUsize>,
) -> Arc<BodyBudget> {
    Arc::new(BodyBudget {
        stream_bytes: Arc::new(AtomicUsize::new(0)),
        connection_bytes,
        max_stream_bytes: limits.max_stream_body_bytes,
        max_connection_bytes: limits.max_connection_body_bytes,
        max_chunk_bytes: limits.max_chunk_bytes,
    })
}

fn map_probe_error(error: PeerProbeError) -> PeerTransportError {
    PeerTransportError::Authentication(error.to_string())
}

/// Await one checkout step without resetting the caller's absolute deadline.
/// Pool lock, capacity, handshake, and H3 setup waits all use the same
/// deadline so a slow or cancelled creator cannot strand later waiters behind
/// a sequence of fresh per-phase timers.
async fn with_checkout_deadline<F, T>(
    cancel: &CancellationToken,
    deadline: Instant,
    future: F,
) -> Result<T, PeerTransportError>
where
    F: Future<Output = T>,
{
    tokio::select! {
        _ = cancel.cancelled() => Err(PeerTransportError::Cancelled),
        result = timeout_at(deadline, future) => {
            result.map_err(|_| PeerTransportError::Timeout)
        }
    }
}

/// Wait for one request-stream permit without confusing a bounded capacity
/// wait with a later HTTP/3 setup timeout.
///
/// A closed semaphore and an exhausted checkout deadline both mean that this
/// connection cannot admit another request stream.  Cancellation remains a
/// distinct result so shutdown and pin revocation still interrupt waiters.
async fn acquire_stream_permit_until(
    cancel: &CancellationToken,
    deadline: Instant,
    permits: Arc<Semaphore>,
) -> Result<OwnedSemaphorePermit, PeerTransportError> {
    tokio::select! {
        _ = cancel.cancelled() => Err(PeerTransportError::Cancelled),
        result = timeout_at(deadline, permits.acquire_owned()) => match result {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) | Err(_) => Err(PeerTransportError::Capacity),
        },
    }
}

fn spawn_pin_watcher(
    identity: &TlsIdentity,
    pins: &SharedPeerPins,
    connection: &quinn::Connection,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    let pin = identity.spki_sha256();
    let mut updates = pins.subscribe();
    let connection = connection.clone();
    tokio::spawn(async move {
        loop {
            if !updates.borrow().contains(pin) {
                cancel.cancel();
                connection.close(quinn::VarInt::from_u32(0), b"peer pin revoked");
                break;
            }
            tokio::select! {
                _ = cancel.cancelled() => break,
                changed = updates.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
            }
        }
    })
}

fn configure_quic_connection(
    connection: &quinn::Connection,
    limits: &PeerTransportLimits,
) -> Result<(), PeerTransportError> {
    let window = quinn::VarInt::from_u64(limits.max_connection_body_bytes as u64)
        .map_err(|_| PeerTransportError::InvalidLimits)?;
    let streams = quinn::VarInt::from_u64(limits.max_streams_per_connection as u64)
        .map_err(|_| PeerTransportError::InvalidLimits)?;
    let uni_streams = quinn::VarInt::from_u64(16).map_err(|_| PeerTransportError::InvalidLimits)?;
    // These connection-local settings cap QUIC's receive and stream windows
    // independently of application frame budgets.  The HTTP/3 implementation
    // may retain a small amount of control/QPACK state outside this accounting.
    connection.set_receive_window(window);
    connection.set_send_window(limits.max_connection_body_bytes as u64);
    connection.set_max_concurrent_bi_streams(streams);
    connection.set_max_concurrent_uni_streams(uni_streams);
    Ok(())
}

/// Server-side stream with a request body and response body on the same
/// long-lived HTTP/3 request stream.
pub struct PeerServerStream {
    inner: Option<ServerStream>,
    budget: Arc<BodyBudget>,
    lease: Arc<StreamLease>,
    idle_timeout: Duration,
}

impl PeerServerStream {
    fn new(
        inner: ServerStream,
        budget: Arc<BodyBudget>,
        lease: Arc<StreamLease>,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            inner: Some(inner),
            budget,
            lease,
            idle_timeout,
        }
    }

    /// Split request receive and response send directions so they can make
    /// progress concurrently.  This is required for response headers/body to
    /// be sent before the request body reaches request-end.
    pub fn split(mut self) -> (PeerServerSend, PeerServerRecv) {
        let inner = self.inner.take().expect("peer server stream is present");
        let (send, recv) = inner.split();
        (
            PeerServerSend {
                inner: send,
                budget: self.budget.clone(),
                _lease: self.lease.clone(),
                idle_timeout: self.idle_timeout,
            },
            PeerServerRecv {
                inner: recv,
                budget: self.budget,
                _lease: self.lease,
                idle_timeout: self.idle_timeout,
            },
        )
    }

    /// Send response headers before reading or finishing the request body.
    pub async fn send_response(
        &mut self,
        response: Response<()>,
    ) -> Result<(), PeerTransportError> {
        let inner = self.inner.as_mut().expect("peer server stream is present");
        match timeout(self.idle_timeout, inner.send_response(response)).await {
            Ok(result) => result.map_err(|error| PeerTransportError::H3(error.to_string())),
            Err(_) => {
                inner.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                Err(PeerTransportError::Timeout)
            }
        }
    }

    /// Send one bounded response body chunk.
    pub async fn send_chunk(&mut self, chunk: Bytes) -> Result<(), PeerTransportError> {
        send_server_chunk(
            self.inner.as_mut().expect("peer server stream is present"),
            &self.budget,
            self.idle_timeout,
            chunk,
        )
        .await
    }

    /// Send one logical body as bounded HTTP/3 body chunks.
    ///
    /// This preserves the supplied byte sequence as one application payload
    /// while allowing the transport to fragment it at its configured body
    /// chunk limit.  The peer record decoder reassembles records across these
    /// arbitrary HTTP/3 chunk boundaries.
    pub async fn send_chunked(&mut self, bytes: &[u8]) -> Result<(), PeerTransportError> {
        send_server_chunks(
            self.inner.as_mut().expect("peer server stream is present"),
            &self.budget,
            self.idle_timeout,
            bytes,
        )
        .await
    }

    /// Send one already bounded response body chunk.
    pub async fn send_body_chunk(
        &mut self,
        chunk: PeerBodyChunk,
    ) -> Result<(), PeerTransportError> {
        self.send_chunk(chunk.into_bytes()).await
    }

    /// Finish the response body.
    pub async fn finish(&mut self) -> Result<(), PeerTransportError> {
        let inner = self.inner.as_mut().expect("peer server stream is present");
        match timeout(self.idle_timeout, inner.finish()).await {
            Ok(result) => result.map_err(|error| PeerTransportError::H3(error.to_string())),
            Err(_) => {
                inner.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                Err(PeerTransportError::Timeout)
            }
        }
    }

    /// Receive one bounded request body chunk.
    pub async fn recv_chunk(&mut self) -> Result<Option<PeerBodyChunk>, PeerTransportError> {
        recv_server_chunk(
            self.inner.as_mut().expect("peer server stream is present"),
            &self.budget,
            self.idle_timeout,
        )
        .await
    }

    /// Cancel both directions of this stream.
    pub fn cancel(&mut self) {
        if let Some(inner) = self.inner.as_mut() {
            inner.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
            inner.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        }
    }
}

/// Server-side response sender returned by [`PeerServerStream::split`].
pub struct PeerServerSend {
    inner: ServerSendStream,
    budget: Arc<BodyBudget>,
    _lease: Arc<StreamLease>,
    idle_timeout: Duration,
}

impl PeerServerSend {
    /// Send response headers before request-end.
    pub async fn send_response(
        &mut self,
        response: Response<()>,
    ) -> Result<(), PeerTransportError> {
        match timeout(self.idle_timeout, self.inner.send_response(response)).await {
            Ok(result) => result.map_err(|error| PeerTransportError::H3(error.to_string())),
            Err(_) => {
                self.inner
                    .stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                Err(PeerTransportError::Timeout)
            }
        }
    }

    /// Send one bounded response body chunk.
    pub async fn send_chunk(&mut self, chunk: Bytes) -> Result<(), PeerTransportError> {
        send_server_chunk(&mut self.inner, &self.budget, self.idle_timeout, chunk).await
    }

    /// Send one logical body as bounded HTTP/3 body chunks.
    ///
    /// The bytes remain one application payload; only the HTTP/3 body
    /// representation is fragmented at the configured transport limit.
    pub async fn send_chunked(&mut self, bytes: &[u8]) -> Result<(), PeerTransportError> {
        self.send_chunked_until(bytes, Instant::now() + self.idle_timeout)
            .await
    }

    /// Send one logical response body under an absolute deadline supplied by
    /// the caller's operation.  See
    /// [`PeerClientSend::send_chunked_until`] for the shared contract.
    pub async fn send_chunked_until(
        &mut self,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), PeerTransportError> {
        send_server_chunks_until(&mut self.inner, &self.budget, deadline, bytes).await
    }

    /// Send one already bounded response body chunk.
    pub async fn send_body_chunk(
        &mut self,
        chunk: PeerBodyChunk,
    ) -> Result<(), PeerTransportError> {
        self.send_chunk(chunk.into_bytes()).await
    }

    /// Finish the response body.
    pub async fn finish(&mut self) -> Result<(), PeerTransportError> {
        match timeout(self.idle_timeout, self.inner.finish()).await {
            Ok(result) => result.map_err(|error| PeerTransportError::H3(error.to_string())),
            Err(_) => {
                self.inner
                    .stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                Err(PeerTransportError::Timeout)
            }
        }
    }

    /// Cancel the response direction.
    pub fn cancel(&mut self) {
        self.inner
            .stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
    }
}

/// Server-side request body receiver returned by [`PeerServerStream::split`].
pub struct PeerServerRecv {
    inner: ServerRecvStream,
    budget: Arc<BodyBudget>,
    _lease: Arc<StreamLease>,
    idle_timeout: Duration,
}

impl PeerServerRecv {
    /// Receive one bounded request body chunk.
    pub async fn recv_chunk(&mut self) -> Result<Option<PeerBodyChunk>, PeerTransportError> {
        recv_server_chunk(&mut self.inner, &self.budget, self.idle_timeout).await
    }

    /// Receive one bounded request body chunk under an absolute deadline
    /// supplied by the caller's operation instead of the idle timeout.
    ///
    /// A peer that is legitimately silent because it waits on this side's
    /// parked response is not idle-faulted; the caller's own bound (the
    /// consumer's absolute authorization deadline) applies.  Resets, request
    /// end and malformed chunks are still surfaced immediately.
    pub async fn recv_chunk_until(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<PeerBodyChunk>, PeerTransportError> {
        recv_server_chunk_until(&mut self.inner, &self.budget, deadline).await
    }

    /// Ask the peer to stop sending the request body.
    pub fn cancel(&mut self) {
        self.inner
            .stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
    }
}

async fn send_server_chunk<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    idle_timeout: Duration,
    chunk: Bytes,
) -> Result<(), PeerTransportError>
where
    S: h3::quic::SendStream<Bytes>,
{
    send_server_chunk_until(stream, budget, Instant::now() + idle_timeout, chunk).await
}

/// Write one bounded body chunk against an already-created absolute deadline.
///
/// The deadline belongs to the caller's operation.  It is never recomputed
/// here, so a multi-chunk body cannot renew its own bound one physical write
/// at a time.  An elapsed deadline cancels the stream before returning.
async fn send_server_chunk_until<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    deadline: Instant,
    chunk: Bytes,
) -> Result<(), PeerTransportError>
where
    S: h3::quic::SendStream<Bytes>,
{
    if chunk.len() > budget.max_chunk_bytes {
        stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        return Err(PeerTransportError::ChunkTooLarge {
            observed: chunk.len(),
            maximum: budget.max_chunk_bytes,
        });
    }
    let charge = budget.reserve(chunk.len())?;
    let result = match timeout_at(deadline, stream.send_data(chunk)).await {
        Ok(result) => result.map_err(|error| PeerTransportError::H3(error.to_string())),
        Err(_) => {
            stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
            Err(PeerTransportError::Timeout)
        }
    };
    drop(charge);
    result
}

async fn send_server_chunks<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    idle_timeout: Duration,
    bytes: &[u8],
) -> Result<(), PeerTransportError>
where
    S: h3::quic::SendStream<Bytes>,
{
    send_server_chunks_until(stream, budget, Instant::now() + idle_timeout, bytes).await
}

/// Write one logical body as bounded chunks that all share one absolute
/// deadline.  The deadline is created once by the caller, so the total wall
/// clock cost of the body cannot grow with its chunk count.
async fn send_server_chunks_until<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    deadline: Instant,
    bytes: &[u8],
) -> Result<(), PeerTransportError>
where
    S: h3::quic::SendStream<Bytes>,
{
    for chunk in bounded_body_chunks(bytes, budget.max_chunk_bytes) {
        send_server_chunk_until(stream, budget, deadline, Bytes::copy_from_slice(chunk)).await?;
    }
    Ok(())
}

async fn recv_server_chunk<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    idle_timeout: Duration,
) -> Result<Option<PeerBodyChunk>, PeerTransportError>
where
    S: h3::quic::RecvStream,
{
    recv_server_chunk_until(stream, budget, Instant::now() + idle_timeout).await
}

/// Read one bounded request body chunk against an absolute deadline.
async fn recv_server_chunk_until<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    deadline: Instant,
) -> Result<Option<PeerBodyChunk>, PeerTransportError>
where
    S: h3::quic::RecvStream,
{
    let chunk = match timeout_at(deadline, stream.recv_data()).await {
        Ok(result) => result.map_err(|error| PeerTransportError::H3(error.to_string()))?,
        Err(_) => {
            stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
            return Err(PeerTransportError::Timeout);
        }
    };
    let Some(mut chunk) = chunk else {
        return Ok(None);
    };
    let length = chunk.remaining();
    if length > budget.max_chunk_bytes {
        stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
        return Err(PeerTransportError::ChunkTooLarge {
            observed: length,
            maximum: budget.max_chunk_bytes,
        });
    }
    let charge = budget.reserve(length)?;
    Ok(Some(PeerBodyChunk::from_received(
        chunk.copy_to_bytes(length),
        charge,
    )))
}

/// Client-side request/response stream before splitting its directions.
pub struct PeerClientStream {
    inner: Option<ClientStream>,
    budget: Arc<BodyBudget>,
    lease: Arc<StreamLease>,
    _connection: Arc<ClientConnection>,
    idle_timeout: Duration,
}

impl PeerClientStream {
    /// Split request sending and response receiving so both directions can
    /// make progress concurrently.
    pub fn split(mut self) -> (PeerClientSend, PeerClientRecv) {
        let inner = self.inner.take().expect("peer client stream is present");
        let (send, recv) = inner.split();
        (
            PeerClientSend {
                inner: send,
                budget: self.budget.clone(),
                _lease: self.lease.clone(),
                _connection: self._connection.clone(),
                idle_timeout: self.idle_timeout,
            },
            PeerClientRecv {
                inner: recv,
                budget: self.budget,
                _lease: self.lease,
                _connection: self._connection,
                idle_timeout: self.idle_timeout,
            },
        )
    }

    /// Send one bounded request body chunk.
    pub async fn send_chunk(&mut self, chunk: Bytes) -> Result<(), PeerTransportError> {
        let result = send_client_chunk(
            self.inner.as_mut().expect("peer client stream is present"),
            &self.budget,
            self.idle_timeout,
            chunk,
        )
        .await;
        self._connection.observe_stream_result(result)
    }

    /// Send one logical body as bounded HTTP/3 body chunks.
    ///
    /// This preserves the supplied byte sequence as one application payload
    /// while allowing the transport to fragment it at its configured body
    /// chunk limit.  The peer record decoder reassembles records across these
    /// arbitrary HTTP/3 chunk boundaries.
    pub async fn send_chunked(&mut self, bytes: &[u8]) -> Result<(), PeerTransportError> {
        let result = send_client_chunks(
            self.inner.as_mut().expect("peer client stream is present"),
            &self.budget,
            self.idle_timeout,
            bytes,
        )
        .await;
        self._connection.observe_stream_result(result)
    }

    /// Send one already bounded request body chunk.
    pub async fn send_body_chunk(
        &mut self,
        chunk: PeerBodyChunk,
    ) -> Result<(), PeerTransportError> {
        self.send_chunk(chunk.into_bytes()).await
    }

    /// Finish the request body.
    pub async fn finish(&mut self) -> Result<(), PeerTransportError> {
        let inner = self.inner.as_mut().expect("peer client stream is present");
        let result = match timeout(self.idle_timeout, inner.finish()).await {
            Ok(result) => result.map_err(classify_client_stream_error),
            Err(_) => {
                inner.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                Err(PeerTransportError::Timeout)
            }
        };
        self._connection.observe_stream_result(result)
    }

    /// Receive response headers.  This may complete before the request body
    /// has been finished.
    pub async fn recv_response(&mut self) -> Result<Response<()>, PeerTransportError> {
        let inner = self.inner.as_mut().expect("peer client stream is present");
        let result = match timeout(self.idle_timeout, inner.recv_response()).await {
            Ok(result) => result.map_err(classify_client_stream_error),
            Err(_) => {
                inner.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                Err(PeerTransportError::Timeout)
            }
        };
        self._connection.observe_stream_result(result)
    }

    /// Receive one bounded response body chunk.
    pub async fn recv_chunk(&mut self) -> Result<Option<PeerBodyChunk>, PeerTransportError> {
        let result = recv_client_chunk(
            self.inner.as_mut().expect("peer client stream is present"),
            &self.budget,
            self.idle_timeout,
        )
        .await;
        self._connection.observe_stream_result(result)
    }

    /// Cancel both directions of this stream.
    pub fn cancel(&mut self) {
        if let Some(inner) = self.inner.as_mut() {
            inner.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        }
    }
}

/// Client-side request sender returned by [`PeerClientStream::split`].
pub struct PeerClientSend {
    inner: ClientSendStream,
    budget: Arc<BodyBudget>,
    _lease: Arc<StreamLease>,
    _connection: Arc<ClientConnection>,
    idle_timeout: Duration,
}

impl PeerClientSend {
    /// Send one bounded request body chunk.
    pub async fn send_chunk(&mut self, chunk: Bytes) -> Result<(), PeerTransportError> {
        let result =
            send_client_chunk(&mut self.inner, &self.budget, self.idle_timeout, chunk).await;
        self._connection.observe_stream_result(result)
    }

    /// Send one logical body as bounded HTTP/3 body chunks.
    ///
    /// The bytes remain one application payload; only the HTTP/3 body
    /// representation is fragmented at the configured transport limit.
    pub async fn send_chunked(&mut self, bytes: &[u8]) -> Result<(), PeerTransportError> {
        self.send_chunked_until(bytes, Instant::now() + self.idle_timeout)
            .await
    }

    /// Send one logical body under an absolute deadline supplied by the
    /// caller's operation.
    ///
    /// Every physical write of this body is bounded by the same instant, so a
    /// blackholed peer cannot hold the writer past the operation's budget by
    /// accepting one chunk at a time.  An elapsed deadline cancels the send
    /// stream and returns [`PeerTransportError::Timeout`].
    pub async fn send_chunked_until(
        &mut self,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), PeerTransportError> {
        let result = send_client_chunks_until(&mut self.inner, &self.budget, deadline, bytes).await;
        self._connection.observe_stream_result(result)
    }

    /// Send one already bounded request body chunk.
    pub async fn send_body_chunk(
        &mut self,
        chunk: PeerBodyChunk,
    ) -> Result<(), PeerTransportError> {
        self.send_chunk(chunk.into_bytes()).await
    }

    /// Finish the request body.
    pub async fn finish(&mut self) -> Result<(), PeerTransportError> {
        let result = match timeout(self.idle_timeout, self.inner.finish()).await {
            Ok(result) => result.map_err(classify_client_stream_error),
            Err(_) => {
                self.inner
                    .stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                Err(PeerTransportError::Timeout)
            }
        };
        self._connection.observe_stream_result(result)
    }

    /// Cancel the request direction.
    pub fn cancel(&mut self) {
        self.inner
            .stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
    }
}

/// Client-side response receiver returned by [`PeerClientStream::split`].
pub struct PeerClientRecv {
    inner: ClientRecvStream,
    budget: Arc<BodyBudget>,
    _lease: Arc<StreamLease>,
    _connection: Arc<ClientConnection>,
    idle_timeout: Duration,
}

impl PeerClientRecv {
    /// Receive response headers before request-end.
    pub async fn recv_response(&mut self) -> Result<Response<()>, PeerTransportError> {
        let result = match timeout(self.idle_timeout, self.inner.recv_response()).await {
            Ok(result) => result.map_err(classify_client_stream_error),
            Err(_) => {
                self.inner
                    .stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
                Err(PeerTransportError::Timeout)
            }
        };
        self._connection.observe_stream_result(result)
    }

    /// Receive one bounded response body chunk.
    pub async fn recv_chunk(&mut self) -> Result<Option<PeerBodyChunk>, PeerTransportError> {
        let result = recv_client_chunk(&mut self.inner, &self.budget, self.idle_timeout).await;
        self._connection.observe_stream_result(result)
    }

    /// Receive one bounded response body chunk under an absolute deadline
    /// supplied by the caller's operation instead of the idle timeout.
    ///
    /// The mirror of [`PeerServerRecv::recv_chunk_until`] on the ingress
    /// side.  A saturated-but-healthy owner is legitimately silent while it
    /// queues this response, so it is not idle-faulted; the caller's own
    /// bound (the consumer's absolute authorization deadline) applies.
    /// Resets, response end and malformed chunks are still surfaced
    /// immediately, and the QUIC connection idle timeout remains the
    /// transport-level liveness check for a peer that has actually gone
    /// away.
    pub async fn recv_chunk_until(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<PeerBodyChunk>, PeerTransportError> {
        let result = recv_client_chunk_until(&mut self.inner, &self.budget, deadline).await;
        self._connection.observe_stream_result(result)
    }

    /// Ask the peer to stop sending the response body.
    pub fn cancel(&mut self) {
        self.inner
            .stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
    }
}

async fn send_client_chunk<S>(
    stream: &mut h3::client::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    idle_timeout: Duration,
    chunk: Bytes,
) -> Result<(), PeerTransportError>
where
    S: h3::quic::SendStream<Bytes>,
{
    send_client_chunk_until(stream, budget, Instant::now() + idle_timeout, chunk).await
}

/// Write one bounded request body chunk against an already-created absolute
/// deadline.  See [`send_server_chunk_until`] for the shared contract.
async fn send_client_chunk_until<S>(
    stream: &mut h3::client::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    deadline: Instant,
    chunk: Bytes,
) -> Result<(), PeerTransportError>
where
    S: h3::quic::SendStream<Bytes>,
{
    if chunk.len() > budget.max_chunk_bytes {
        stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        return Err(PeerTransportError::ChunkTooLarge {
            observed: chunk.len(),
            maximum: budget.max_chunk_bytes,
        });
    }
    let charge = budget.reserve(chunk.len())?;
    let result = match timeout_at(deadline, stream.send_data(chunk)).await {
        Ok(result) => result.map_err(classify_client_stream_error),
        Err(_) => {
            stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
            Err(PeerTransportError::Timeout)
        }
    };
    drop(charge);
    result
}

async fn send_client_chunks<S>(
    stream: &mut h3::client::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    idle_timeout: Duration,
    bytes: &[u8],
) -> Result<(), PeerTransportError>
where
    S: h3::quic::SendStream<Bytes>,
{
    send_client_chunks_until(stream, budget, Instant::now() + idle_timeout, bytes).await
}

/// Write one logical request body as bounded chunks that all share one
/// absolute deadline created by the caller.
async fn send_client_chunks_until<S>(
    stream: &mut h3::client::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    deadline: Instant,
    bytes: &[u8],
) -> Result<(), PeerTransportError>
where
    S: h3::quic::SendStream<Bytes>,
{
    for chunk in bounded_body_chunks(bytes, budget.max_chunk_bytes) {
        send_client_chunk_until(stream, budget, deadline, Bytes::copy_from_slice(chunk)).await?;
    }
    Ok(())
}

fn bounded_body_chunks(bytes: &[u8], max_chunk_bytes: usize) -> impl Iterator<Item = &[u8]> {
    bytes.chunks(max_chunk_bytes)
}

async fn recv_client_chunk<S>(
    stream: &mut h3::client::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    idle_timeout: Duration,
) -> Result<Option<PeerBodyChunk>, PeerTransportError>
where
    S: h3::quic::RecvStream,
{
    recv_client_chunk_until(stream, budget, Instant::now() + idle_timeout).await
}

/// Read one bounded response body chunk against an absolute deadline.
async fn recv_client_chunk_until<S>(
    stream: &mut h3::client::RequestStream<S, Bytes>,
    budget: &BodyBudget,
    deadline: Instant,
) -> Result<Option<PeerBodyChunk>, PeerTransportError>
where
    S: h3::quic::RecvStream,
{
    let chunk = match timeout_at(deadline, stream.recv_data()).await {
        Ok(result) => result.map_err(classify_client_stream_error)?,
        Err(_) => {
            stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
            return Err(PeerTransportError::Timeout);
        }
    };
    let Some(mut chunk) = chunk else {
        return Ok(None);
    };
    let length = chunk.remaining();
    if length > budget.max_chunk_bytes {
        stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
        return Err(PeerTransportError::ChunkTooLarge {
            observed: length,
            maximum: budget.max_chunk_bytes,
        });
    }
    let charge = budget.reserve(length)?;
    Ok(Some(PeerBodyChunk::from_received(
        chunk.copy_to_bytes(length),
        charge,
    )))
}

struct ClientConnection {
    destination: PeerDestination,
    identity: TlsIdentity,
    pin_provider: SharedPeerPins,
    connection: quinn::Connection,
    sender: Mutex<ClientSender>,
    stream_permits: Arc<Semaphore>,
    connection_bytes: Arc<AtomicUsize>,
    limits: PeerTransportLimits,
    cancel: CancellationToken,
    /// A peer-observed H3 GOAWAY asks the client driver to acknowledge it
    /// after every existing stream lease has been returned.  This is kept
    /// separate from `cancel`, which is reserved for emergency/local close.
    planned_remote_closing: CancellationToken,
    driver: Mutex<Option<JoinHandle<Result<(), PeerTransportError>>>>,
    pin_watcher: Mutex<Option<JoinHandle<()>>>,
    _connection_permit: OwnedSemaphorePermit,
}

impl ClientConnection {
    /// Record a stream-level outcome on its pooled connection.
    ///
    /// A typed [`PeerTransportError::GoAway`] observed on an already opened
    /// stream means the peer is closing this connection, so later opens are
    /// gated pre-dispatch here exactly as they are after a GOAWAY observed at
    /// request open; the existing driver still owns the bounded
    /// acknowledgement and lease drain.  Every other result passes through.
    fn observe_stream_result<T>(
        &self,
        result: Result<T, PeerTransportError>,
    ) -> Result<T, PeerTransportError> {
        if matches!(result, Err(PeerTransportError::GoAway)) {
            self.planned_remote_closing.cancel();
        }
        result
    }

    async fn open(
        self: &Arc<Self>,
        request: Request<()>,
    ) -> Result<PeerClientStream, PeerTransportError> {
        self.open_until(request, Instant::now() + self.limits.stream_timeout)
            .await
    }

    /// Open a request stream before an absolute caller-owned deadline.
    ///
    /// The permit wait has its own configured stream checkout bound, clipped
    /// to the caller deadline, and is the only setup step classified as
    /// [`PeerTransportError::Capacity`] on expiry.  The sender lock and H3
    /// request dispatch retain the ordinary [`PeerTransportError::Timeout`]
    /// classification when their shared deadline expires.
    async fn open_until(
        self: &Arc<Self>,
        request: Request<()>,
        deadline: Instant,
    ) -> Result<PeerClientStream, PeerTransportError> {
        self.open_until_with_progress(request, deadline, None).await
    }

    async fn open_until_with_progress(
        self: &Arc<Self>,
        request: Request<()>,
        deadline: Instant,
        progress: Option<&PeerOpenProgress>,
    ) -> Result<PeerClientStream, PeerTransportError> {
        self.pin_provider
            .snapshot()
            .verify(&self.identity)
            .map_err(map_probe_error)?;
        if self.connection.close_reason().is_some() {
            return Err(PeerTransportError::Quic(
                "peer connection is closed".to_owned(),
            ));
        }
        if self.planned_remote_closing.is_cancelled() {
            // Once a peer GOAWAY has been observed, do not acquire a permit
            // or touch the sender again.  The existing driver owns the
            // bounded acknowledgement and stream-lease drain.
            return Err(PeerTransportError::GoAway);
        }
        let permit_deadline = std::cmp::min(deadline, Instant::now() + self.limits.stream_timeout);
        if let Some(progress) = progress {
            progress.set_stage(PeerTransportOpenStage::StreamPermitCheckout);
        }
        let permit =
            acquire_stream_permit_until(&self.cancel, permit_deadline, self.stream_permits.clone())
                .await?;
        if let Some(progress) = progress {
            progress.set_stage(PeerTransportOpenStage::SenderLock);
        }
        let mut sender = with_checkout_deadline(&self.cancel, deadline, self.sender.lock()).await?;
        if let Some(progress) = progress {
            progress.set_stage(PeerTransportOpenStage::H3Dispatch);
        }
        let stream = with_checkout_deadline(&self.cancel, deadline, sender.send_request(request))
            .await?
            .map_err(|error| {
                let classified = classify_client_stream_error(error);
                if matches!(classified, PeerTransportError::GoAway) {
                    // Do not reuse the emergency token: a peer that is closing
                    // has not dispatched this request (`RemoteClosing`, or an
                    // `H3_REQUEST_REJECTED` reset of a raced stream), while
                    // existing streams must remain alive until their leases are
                    // returned.
                    self.planned_remote_closing.cancel();
                }
                classified
            })?;
        drop(sender);

        let budget = body_budget(&self.limits, self.connection_bytes.clone());
        if let Some(progress) = progress {
            progress.set_stage(PeerTransportOpenStage::Complete);
        }
        Ok(PeerClientStream {
            inner: Some(stream),
            budget,
            lease: Arc::new(StreamLease { _permit: permit }),
            _connection: self.clone(),
            idle_timeout: self.limits.idle_timeout,
        })
    }

    async fn shutdown_until(&self, deadline: Instant) -> Result<(), PeerTransportError> {
        self.cancel.cancel();
        self.connection
            .close(quinn::VarInt::from_u32(0), b"shutdown");
        let driver = self.driver.lock().await.take();
        let watcher = self.pin_watcher.lock().await.take();
        let mut first_error = None;
        if let Some(driver) = driver {
            match join_handle_until(driver, deadline).await {
                Some(Err(error)) => first_error = Some(PeerTransportError::Task(error)),
                Some(Ok(Err(error))) => first_error = Some(error),
                None => {
                    first_error.get_or_insert(PeerTransportError::Timeout);
                    tracing::warn!("peer HTTP/3 driver exceeded drain timeout");
                }
                Some(Ok(Ok(()))) => {}
            }
        }
        if let Some(watcher) = watcher {
            match join_handle_until(watcher, deadline).await {
                Some(Err(error)) => {
                    first_error.get_or_insert(PeerTransportError::Task(error));
                }
                None => {
                    first_error.get_or_insert(PeerTransportError::Timeout);
                    tracing::warn!("peer pin watcher exceeded drain timeout");
                }
                Some(Ok(())) => {}
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), PeerTransportError> {
        self.shutdown_until(Instant::now() + self.limits.drain_timeout)
            .await
    }
}

async fn join_handle_until<T>(
    mut handle: JoinHandle<T>,
    deadline: Instant,
) -> Option<Result<T, tokio::task::JoinError>> {
    match timeout_at(deadline, &mut handle).await {
        Ok(result) => Some(result),
        Err(_) => {
            handle.abort();
            let _ = handle.await;
            None
        }
    }
}

async fn join_handle_until_bounded<T>(
    mut handle: JoinHandle<T>,
    deadline: Instant,
) -> Option<Result<T, tokio::task::JoinError>> {
    match timeout_at(deadline, &mut handle).await {
        Ok(result) => Some(result),
        Err(_) => {
            handle.abort();
            // Do not await an aborted planned-drain task beyond the shared
            // deadline.  A task that does not join in this final bounded
            // window is reported as incomplete by the caller; dropping the
            // handle here cannot extend the transport drain budget.
            let _ = timeout_at(deadline, &mut handle).await;
            None
        }
    }
}

const FORCED_JOIN_GRACE: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DrainOutcome {
    forced: bool,
    incomplete: bool,
}

async fn drain_peer_tasks(
    tasks: &mut JoinSet<Result<(), PeerTransportError>>,
    deadline: Instant,
    cancellation_requested: bool,
    first_error: &mut Option<PeerTransportError>,
    label: &'static str,
) -> DrainOutcome {
    drain_peer_tasks_with_grace(
        tasks,
        deadline,
        cancellation_requested,
        first_error,
        label,
        true,
        true,
    )
    .await
}

/// Drain a task group without recording an individual task's own error as the
/// group's failure.  Used for forwarded-stream groups, where a stream ending
/// with an error is a stream-local lifecycle event (exactly as in normal
/// serving) and only a forced-deadline abort or a task panic fails the drain.
async fn drain_peer_tasks_without_recording_task_errors(
    tasks: &mut JoinSet<Result<(), PeerTransportError>>,
    deadline: Instant,
    cancellation_requested: bool,
    first_error: &mut Option<PeerTransportError>,
    label: &'static str,
) -> DrainOutcome {
    drain_peer_tasks_with_grace(
        tasks,
        deadline,
        cancellation_requested,
        first_error,
        label,
        true,
        false,
    )
    .await
}

async fn drain_peer_tasks_with_grace(
    tasks: &mut JoinSet<Result<(), PeerTransportError>>,
    deadline: Instant,
    cancellation_requested: bool,
    first_error: &mut Option<PeerTransportError>,
    label: &'static str,
    reserve_grace: bool,
    record_task_errors: bool,
) -> DrainOutcome {
    let wait_deadline = if cancellation_requested || !reserve_grace {
        deadline
    } else {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining > FORCED_JOIN_GRACE {
            deadline - FORCED_JOIN_GRACE
        } else {
            deadline
        }
    };
    let mut outcome = DrainOutcome::default();
    loop {
        match timeout_at(wait_deadline, tasks.join_next()).await {
            Ok(Some(Ok(Ok(())))) => {}
            Ok(Some(Ok(Err(error)))) if cancellation_requested || !record_task_errors => {
                tracing::debug!(
                    ?error,
                    task_group = label,
                    "peer task stopped during shutdown"
                );
            }
            Ok(Some(Ok(Err(error)))) => {
                first_error.get_or_insert(error);
            }
            Ok(Some(Err(error))) => {
                first_error.get_or_insert(PeerTransportError::Task(error));
            }
            Ok(None) => break,
            Err(_) => {
                tracing::warn!(
                    task_group = label,
                    "peer drain deadline exceeded; aborting tasks"
                );
                outcome.forced = true;
                // A forced abort is a terminal timeout outcome even when all
                // cancelled tasks subsequently join. Never report a forced
                // drain as a clean success. Emergency cancellation preserves
                // the existing full join; planned drains reserve the final
                // grace window and report incomplete cleanup explicitly.
                if !cancellation_requested {
                    first_error.get_or_insert(PeerTransportError::Timeout);
                }
                tasks.abort_all();
                if cancellation_requested {
                    while tasks.join_next().await.is_some() {}
                    break;
                }
                loop {
                    match timeout_at(deadline, tasks.join_next()).await {
                        Ok(Some(_)) => {}
                        Ok(None) => break,
                        Err(_) => {
                            outcome.incomplete = true;
                            first_error.get_or_insert(PeerTransportError::Timeout);
                            tasks.abort_all();
                            break;
                        }
                    }
                }
                break;
            }
        }
    }
    outcome
}

impl Drop for ClientConnection {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.connection
            .close(quinn::VarInt::from_u32(0), b"connection dropped");
        if let Some(driver) = self.driver.get_mut().take() {
            driver.abort();
        }
        if let Some(watcher) = self.pin_watcher.get_mut().take() {
            watcher.abort();
        }
    }
}

/// A reusable handle to one authenticated, pooled peer connection.
#[derive(Clone)]
pub struct PeerConnectionHandle {
    inner: Arc<ClientConnection>,
}

impl PeerConnectionHandle {
    /// Return the destination selected by the caller's membership snapshot.
    #[must_use]
    pub fn destination(&self) -> &PeerDestination {
        &self.inner.destination
    }

    /// Return the verified peer identity obtained from the TLS connection.
    #[must_use]
    pub fn peer_identity(&self) -> &TlsIdentity {
        &self.inner.identity
    }

    /// Open one request stream on this reusable connection.
    pub async fn open(&self, request: Request<()>) -> Result<PeerClientStream, PeerTransportError> {
        self.inner.open(request).await
    }

    /// Open one request stream before an absolute transport deadline.
    ///
    /// This is used by bounded health probes so stream-permit exhaustion can
    /// be reported as capacity even when the probe deadline is shorter than
    /// the connection's normal stream checkout timeout.  Sender locking and
    /// HTTP/3 dispatch retain their normal timeout classification.
    pub async fn open_until(
        &self,
        request: Request<()>,
        deadline: Instant,
    ) -> Result<PeerClientStream, PeerTransportError> {
        self.inner.open_until(request, deadline).await
    }

    /// Open one request stream while recording the bounded transport stage.
    ///
    /// The observer is scoped to this attempt and does not alter admission,
    /// deadlines, or transport error classification.
    pub async fn open_with_progress(
        &self,
        request: Request<()>,
        progress: &PeerOpenProgress,
    ) -> Result<PeerClientStream, PeerTransportError> {
        self.inner
            .open_until_with_progress(
                request,
                Instant::now() + self.inner.limits.stream_timeout,
                Some(progress),
            )
            .await
    }

    /// Authorize and open a request using a caller-owned membership snapshot.
    ///
    /// This check is local to the caller and is deliberately repeated by a
    /// receiving [`PeerServer`] before it admits the request body.
    pub async fn open_with_policy<P>(
        &self,
        request: Request<()>,
        policy: &P,
    ) -> Result<PeerClientStream, PeerTransportError>
    where
        P: PeerRequestPolicy,
    {
        if !policy.authorize(&self.inner.identity, &request) {
            return Err(PeerTransportError::PolicyRejected);
        }
        self.inner.open(request).await
    }

    /// Cancel and join the connection's HTTP/3 driver task.
    pub async fn shutdown(&self) -> Result<(), PeerTransportError> {
        self.inner.shutdown().await
    }
}

struct PeerPoolState {
    connections: Mutex<HashMap<PeerDestination, Arc<ClientConnection>>>,
    dial_locks: Mutex<HashMap<PeerDestination, Arc<DialEntry>>>,
}

struct DialEntry {
    lock: Mutex<()>,
    users: AtomicUsize,
    retired: std::sync::atomic::AtomicBool,
}

impl DialEntry {
    fn new() -> Self {
        Self {
            lock: Mutex::new(()),
            users: AtomicUsize::new(0),
            retired: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

fn acquire_dial_entry(
    locks: &mut HashMap<PeerDestination, Arc<DialEntry>>,
    destination: &PeerDestination,
    max_destinations: usize,
) -> Result<Arc<DialEntry>, PeerTransportError> {
    if let Some(entry) = locks.get(destination).cloned() {
        if !entry.retired.load(Ordering::Acquire) {
            return Ok(entry);
        }
        // A creator can be cancelled after releasing its users count but
        // before it can await the pool map.  Remove only that retired marker;
        // other destinations remain accounted against the pool bound.
        locks.remove(destination);
    }
    if locks.len() >= max_destinations {
        return Err(PeerTransportError::Capacity);
    }
    let entry = Arc::new(DialEntry::new());
    locks.insert(destination.clone(), entry.clone());
    Ok(entry)
}

struct DialLease {
    state: Arc<PeerPoolState>,
    destination: PeerDestination,
    entry: Arc<DialEntry>,
    released: bool,
}

impl DialLease {
    async fn release(mut self, retain: bool) {
        let last_user = self.entry.users.fetch_sub(1, Ordering::AcqRel) == 1;
        self.released = true;
        if !last_user || retain {
            return;
        }
        // Mark before awaiting the map lock.  If cancellation drops this
        // release future while the lock is contended, the next creator can
        // still retire this exact marker instead of inheriting a zero-user
        // entry forever.
        self.entry.retired.store(true, Ordering::Release);
        let mut locks = self.state.dial_locks.lock().await;
        if locks
            .get(&self.destination)
            .is_some_and(|entry| Arc::ptr_eq(entry, &self.entry))
        {
            locks.remove(&self.destination);
        }
    }
}

impl Drop for DialLease {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        if self.entry.users.fetch_sub(1, Ordering::AcqRel) == 1 {
            // Drop cannot await the pool map.  Mark the exact entry retired so
            // the next creator removes it before checking destination
            // capacity; waiters that already hold a lease continue to share
            // the old marker safely.
            self.entry.retired.store(true, Ordering::Release);
        }
    }
}

/// An on-demand authenticated peer client with one pooled connection and one
/// in-flight dial per destination.
#[derive(Clone)]
pub struct PeerClient {
    endpoint: quinn::Endpoint,
    pin_provider: SharedPeerPins,
    limits: PeerTransportLimits,
    connections: Arc<Semaphore>,
    state: Arc<PeerPoolState>,
    cancel: CancellationToken,
}

impl PeerClient {
    /// Construct a client from a Quinn endpoint configured with the mandatory
    /// TLS 1.3 peer client configuration.
    pub fn new(
        endpoint: quinn::Endpoint,
        approved_pins: ApprovedPeerPins,
        limits: PeerTransportLimits,
    ) -> Result<Self, PeerTransportError> {
        let pin_provider = SharedPeerPins::new(approved_pins)?;
        Self::new_with_pin_provider(endpoint, pin_provider, limits)
    }

    /// Construct a client backed by a caller-updated dynamic peer pin
    /// snapshot.  The initial snapshot may be empty, which fails closed until
    /// the caller publishes approved keys.
    pub fn new_with_pin_provider(
        endpoint: quinn::Endpoint,
        pin_provider: SharedPeerPins,
        limits: PeerTransportLimits,
    ) -> Result<Self, PeerTransportError> {
        limits.validate()?;
        Ok(Self {
            endpoint,
            pin_provider,
            connections: Arc::new(Semaphore::new(limits.max_connections)),
            state: Arc::new(PeerPoolState {
                connections: Mutex::new(HashMap::new()),
                dial_locks: Mutex::new(HashMap::new()),
            }),
            cancel: CancellationToken::new(),
            limits,
        })
    }

    /// Return a pooled connection, dialing at most once concurrently for this
    /// destination.
    pub async fn connect(
        &self,
        destination: PeerDestination,
    ) -> Result<PeerConnectionHandle, PeerTransportError> {
        if self.cancel.is_cancelled() {
            return Err(PeerTransportError::Cancelled);
        }
        let current_pins = self.pin_provider.snapshot();
        if current_pins.is_empty() {
            return Err(PeerTransportError::Authentication(
                "no approved peer SPKI pins".to_owned(),
            ));
        }
        let deadline = Instant::now() + self.limits.handshake_timeout;
        let entry = {
            let mut locks =
                with_checkout_deadline(&self.cancel, deadline, self.state.dial_locks.lock())
                    .await?;
            acquire_dial_entry(&mut locks, &destination, self.limits.max_destinations)?
        };
        entry.users.fetch_add(1, Ordering::AcqRel);
        let lease = DialLease {
            state: self.state.clone(),
            destination: destination.clone(),
            entry: entry.clone(),
            released: false,
        };
        let dial_guard =
            match with_checkout_deadline(&self.cancel, deadline, entry.lock.lock()).await {
                Ok(guard) => guard,
                Err(error) => {
                    lease.release(false).await;
                    return Err(error);
                }
            };

        let result: Result<PeerConnectionHandle, PeerTransportError> = async {
            if let Some(connection) =
                with_checkout_deadline(&self.cancel, deadline, self.state.connections.lock())
                    .await?
                    .get(&destination)
                    .filter(|connection| {
                        connection.connection.close_reason().is_none()
                            && !connection.cancel.is_cancelled()
                            && current_pins.verify(&connection.identity).is_ok()
                    })
                    .cloned()
            {
                return Ok(PeerConnectionHandle { inner: connection });
            }

            let previous =
                with_checkout_deadline(&self.cancel, deadline, self.state.connections.lock())
                    .await?
                    .remove(&destination);
            if let Some(previous) = previous {
                previous.shutdown_until(deadline).await?;
            }

            // Connection-pool exhaustion is a typed capacity condition and must
            // be reported as one, promptly.  Waiting on the semaphore under the
            // handshake deadline reported `Timeout` instead: it is
            // `with_checkout_deadline` that maps deadline expiry to `Timeout`,
            // and the `?` propagated that before the `map_err` intended to
            // produce `Capacity`, which only ever saw the semaphore's own closed
            // error.  So a caller learned nothing about capacity, and learned it
            // only after the whole handshake budget: the readiness probe
            // recorded the route `Unreachable` rather than `CapacityExhausted`,
            // collapsing the distinction that model is built on.
            //
            // A permit can also be moments from release: the branch above
            // removes and shuts down an unusable pooled connection for this
            // destination, and its permit lands when the last handle to it
            // drops.  Refusing instantly turns that ordinary replacement into a
            // spurious capacity error (measured: the peer-capacity gate went
            // from roughly one failure in six to five in fourteen).  So take a
            // free permit immediately, otherwise wait a short bounded grace
            // that stays well inside a probe's budget, and report exhaustion as
            // typed capacity either way.
            let connection_permit = match self.connections.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    let grace = deadline.min(Instant::now() + CAPACITY_RELEASE_GRACE);
                    match timeout_at(grace, self.connections.clone().acquire_owned()).await {
                        Ok(Ok(permit)) => permit,
                        Ok(Err(_)) | Err(_) => return Err(PeerTransportError::Capacity),
                    }
                }
            };
            let connecting = self
                .endpoint
                .connect(destination.address, &destination.server_name)
                .map_err(|error| PeerTransportError::Quic(error.to_string()))?;
            let connection = with_checkout_deadline(&self.cancel, deadline, connecting)
                .await?
                .map_err(|error| PeerTransportError::Quic(error.to_string()))?;
            configure_quic_connection(&connection, &self.limits)?;
            let identity = verified_peer_identity(&connection).map_err(map_probe_error)?;
            self.pin_provider
                .snapshot()
                .verify(&identity)
                .map_err(map_probe_error)?;

            let quic = h3_quinn::Connection::new(connection.clone());
            let mut builder = h3::client::builder();
            builder.max_field_section_size(self.limits.max_header_bytes as u64);
            let (driver, sender) =
                with_checkout_deadline(&self.cancel, deadline, builder.build::<_, _, Bytes>(quic))
                    .await?
                    .map_err(|error| PeerTransportError::H3(error.to_string()))?;
            let connection_cancel = self.cancel.child_token();
            let driver_cancel = connection_cancel.clone();
            let planned_remote_closing = CancellationToken::new();
            let driver_planned_remote_closing = planned_remote_closing.clone();
            let driver_stream_permits =
                Arc::new(Semaphore::new(self.limits.max_streams_per_connection));
            let driver_wait_permits = driver_stream_permits.clone();
            let driver_max_streams = self.limits.max_streams_per_connection;
            let driver_drain_timeout = self.limits.drain_timeout;
            let driver_connection = connection.clone();
            let driver_task = tokio::spawn(async move {
                let mut driver = driver;
                loop {
                    tokio::select! {
                        biased;
                        _ = driver_cancel.cancelled() => {
                            let _ = driver.shutdown(0).await;
                            break Ok(());
                        }
                        _ = driver_planned_remote_closing.cancelled() => {
                        let permit_count = match u32::try_from(driver_max_streams) {
                            Ok(count) => count,
                            Err(_) => {
                                driver_connection.close(
                                    quinn::VarInt::from_u32(0),
                                    b"invalid peer stream permit bound",
                                );
                                return Err(PeerTransportError::InvalidLimits);
                            }
                        };
                        let deadline = Instant::now() + driver_drain_timeout;
                        // Keep polling the HTTP/3 driver while existing stream
                        // leases drain.  Waiting only on the semaphore can
                        // starve control/QPACK progress for an admitted stream.
                        let mut idle = Box::pin(driver.wait_idle());
                        let all_streams = tokio::select! {
                            biased;
                            _ = driver_cancel.cancelled() => {
                                driver_connection.close(
                                    quinn::VarInt::from_u32(0),
                                    b"peer emergency during GOAWAY acknowledgement",
                                );
                                return Ok(());
                            }
                            connection_result = &mut idle => {
                                // The connection went idle before the stream
                                // leases drained.  That is only a failure if
                                // the close itself was one: a peer that
                                // finished its own planned close first ends
                                // the connection with no error, and the wait
                                // below classifies exactly that case with
                                // `planned_idle_result`.  Classifying it the
                                // same way here is what keeps a benign close
                                // from being reported as a transport failure
                                // depending on which branch of this race wins.
                                let result = planned_idle_result(connection_result);
                                driver_connection.close(
                                    quinn::VarInt::from_u32(0),
                                    if result.is_ok() {
                                        b"peer connection closed cleanly during GOAWAY drain"
                                            as &[u8]
                                    } else {
                                        b"peer HTTP/3 driver stopped during GOAWAY drain" as &[u8]
                                    },
                                );
                                return result;
                            }
                            result = timeout_at(
                                deadline,
                                driver_wait_permits.acquire_many_owned(permit_count),
                            ) => result,
                        };
                        drop(idle);
                        let Ok(Ok(_all_streams)) = all_streams else {
                            driver_connection.close(
                                quinn::VarInt::from_u32(0),
                                b"peer GOAWAY stream drain deadline",
                            );
                            return Err(PeerTransportError::Timeout);
                        };
                        let shutdown = tokio::select! {
                            biased;
                            _ = driver_cancel.cancelled() => {
                                driver_connection.close(
                                    quinn::VarInt::from_u32(0),
                                    b"peer emergency during GOAWAY acknowledgement",
                                );
                                return Ok(());
                            }
                            result = timeout_at(deadline, driver.shutdown(0)) => result,
                        };
                        match shutdown {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => {
                                driver_connection.close(
                                    quinn::VarInt::from_u32(0),
                                    b"peer GOAWAY acknowledgement failed",
                                );
                                return Err(PeerTransportError::H3(error.to_string()));
                            }
                            Err(_) => {
                                driver_connection.close(
                                    quinn::VarInt::from_u32(0),
                                    b"peer GOAWAY acknowledgement deadline",
                                );
                                return Err(PeerTransportError::Timeout);
                            }
                        }
                        let idle = tokio::select! {
                            biased;
                            _ = driver_cancel.cancelled() => {
                                driver_connection.close(
                                    quinn::VarInt::from_u32(0),
                                    b"peer emergency during GOAWAY wait",
                                );
                                return Ok(());
                            }
                            result = timeout_at(deadline, driver.wait_idle()) => result,
                        };
                        let idle_result = match idle {
                            Err(_) => {
                                driver_connection.close(
                                    quinn::VarInt::from_u32(0),
                                    b"peer GOAWAY idle deadline",
                                );
                                Err(PeerTransportError::Timeout)
                            }
                            Ok(connection_result) => {
                                let result = planned_idle_result(connection_result);
                                if result.is_err() {
                                    driver_connection.close(
                                        quinn::VarInt::from_u32(0),
                                        b"peer GOAWAY idle failure",
                                    );
                                }
                                result
                            }
                        };
                        break idle_result;
                        }
                        result = driver.wait_for_remote_goaway() => {
                            if result.is_ok() {
                                // Reuse the same bounded acknowledgement path
                                // as an attempted post-GOAWAY open. The typed
                                // gate remains in `open_until`; this passive
                                // event only removes the need for a failed
                                // probe to wake the driver.
                                driver_planned_remote_closing.cancel();
                            } else {
                                // A normal close or protocol error before
                                // GOAWAY preserves the existing terminal
                                // driver behavior and is never promoted to a
                                // planned drain.
                                break Ok(());
                            }
                        }
                    }
                }
            });
            let pin_watcher = spawn_pin_watcher(
                &identity,
                &self.pin_provider,
                &connection,
                connection_cancel.clone(),
            );

            let pooled = Arc::new(ClientConnection {
                destination: destination.clone(),
                identity,
                pin_provider: self.pin_provider.clone(),
                connection,
                sender: Mutex::new(sender),
                stream_permits: driver_stream_permits,
                connection_bytes: Arc::new(AtomicUsize::new(0)),
                limits: self.limits.clone(),
                cancel: connection_cancel,
                planned_remote_closing,
                driver: Mutex::new(Some(driver_task)),
                pin_watcher: Mutex::new(Some(pin_watcher)),
                _connection_permit: connection_permit,
            });
            with_checkout_deadline(&self.cancel, deadline, self.state.connections.lock())
                .await?
                .insert(destination, pooled.clone());
            Ok(PeerConnectionHandle { inner: pooled })
        }
        .await;
        drop(dial_guard);
        let retain = result.is_ok();
        lease.release(retain).await;
        result
    }

    /// Return the current dynamic peer pin snapshot used for admission.
    #[must_use]
    pub fn pin_snapshot(&self) -> PeerPinSnapshot {
        self.pin_provider.snapshot()
    }

    /// Return bounded, redacted pool admission counters for diagnostics.
    ///
    /// The snapshot deliberately reports only semaphore counts and terminal
    /// state.  It is read-only and does not keep any pooled connection alive.
    pub async fn pool_stats(&self) -> PeerPoolStats {
        let connections = self.state.connections.lock().await;
        let pooled_connections = connections
            .values()
            .map(|connection| PeerPoolConnectionStats {
                available_stream_permits: connection.stream_permits.available_permits(),
                max_stream_permits: self.limits.max_streams_per_connection,
                closed: connection.connection.close_reason().is_some()
                    || connection.cancel.is_cancelled(),
            })
            .collect();
        PeerPoolStats {
            available_connection_permits: self.connections.available_permits(),
            max_connection_permits: self.limits.max_connections,
            pooled_connections,
        }
    }

    /// Return one bounded, redacted admission snapshot for a selected route.
    ///
    /// This diagnostic view correlates a caller's route with its pooled
    /// connection without exposing the destination address or TLS name.
    pub async fn pool_stats_for(
        &self,
        destination: &PeerDestination,
    ) -> Option<PeerPoolConnectionStats> {
        let connections = self.state.connections.lock().await;
        connections
            .get(destination)
            .map(|connection| PeerPoolConnectionStats {
                available_stream_permits: connection.stream_permits.available_permits(),
                max_stream_permits: self.limits.max_streams_per_connection,
                closed: connection.connection.close_reason().is_some()
                    || connection.cancel.is_cancelled(),
            })
    }

    /// Close and join one pooled peer connection, if present.
    pub async fn close_peer(
        &self,
        destination: &PeerDestination,
    ) -> Result<(), PeerTransportError> {
        let connection = self.state.connections.lock().await.remove(destination);
        if let Some(connection) = connection {
            connection
                .shutdown_until(Instant::now() + self.limits.drain_timeout)
                .await?;
        }
        Ok(())
    }

    /// Close and join every pooled connection whose SPKI pin is absent from
    /// the current dynamic snapshot.
    ///
    /// Pin watchers close revoked connections immediately; this method gives
    /// callers an explicit joined cleanup point after publishing a snapshot.
    pub async fn refresh_pins(&self) -> Result<usize, PeerTransportError> {
        let snapshot = self.pin_provider.snapshot();
        let stale = {
            let mut connections = self.state.connections.lock().await;
            let destinations = connections
                .iter()
                .filter(|(_, connection)| !snapshot.contains(connection.identity.spki_sha256()))
                .map(|(destination, _)| destination.clone())
                .collect::<Vec<_>>();
            destinations
                .into_iter()
                .filter_map(|destination| connections.remove(&destination))
                .collect::<Vec<_>>()
        };
        let count = stale.len();
        let deadline = Instant::now() + self.limits.drain_timeout;
        let mut first_error = None;
        for connection in stale {
            if let Err(error) = connection.shutdown_until(deadline).await {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(count)
    }

    /// Open a request using a pooled connection selected from the destination.
    pub async fn open(
        &self,
        destination: PeerDestination,
        request: Request<()>,
    ) -> Result<PeerClientStream, PeerTransportError> {
        self.connect(destination).await?.open(request).await
    }

    /// Authorize and open a request using a caller-owned membership snapshot.
    pub async fn open_with_policy<P>(
        &self,
        destination: PeerDestination,
        request: Request<()>,
        policy: &P,
    ) -> Result<PeerClientStream, PeerTransportError>
    where
        P: PeerRequestPolicy,
    {
        self.connect(destination)
            .await?
            .open_with_policy(request, policy)
            .await
    }

    /// Cancel and join every pooled connection driver task.
    pub async fn shutdown(&self) -> Result<(), PeerTransportError> {
        self.cancel.cancel();
        let connections = self
            .state
            .connections
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let deadline = Instant::now() + self.limits.drain_timeout;
        let mut first_error = None;
        for connection in connections {
            if let Err(error) = connection.shutdown_until(deadline).await {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        self.state.connections.lock().await.clear();
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerShutdownMode {
    Emergency,
    PlannedDrain,
}

/// Shared signal for one planned server drain.
///
/// The deadline is written before the token is cancelled so every connection
/// task uses the same absolute budget.  Emergency server shutdown never
/// cancels this token.
#[derive(Clone)]
struct PlannedDrainSignal {
    token: CancellationToken,
    deadline: Arc<OnceLock<Instant>>,
    admission_closed: Arc<AtomicBool>,
}

impl PlannedDrainSignal {
    fn new() -> Self {
        Self {
            token: CancellationToken::new(),
            deadline: Arc::new(OnceLock::new()),
            admission_closed: Arc::new(AtomicBool::new(false)),
        }
    }

    fn set_deadline(&self, deadline: Instant) {
        let _ = self.deadline.set(deadline);
    }

    fn deadline(&self) -> Option<Instant> {
        self.deadline.get().copied()
    }

    fn close_admission(&self) {
        self.admission_closed.store(true, Ordering::Release);
    }

    fn begin_admission(&self) -> bool {
        // This final check is the admission linearization point.  A stream
        // that passes it before close_admission is already admitted and may
        // finish after GOAWAY; a resolver/policy path that reaches it after
        // the boundary is rejected before handler dispatch.
        !self.admission_closed.load(Ordering::Acquire)
    }
}

/// A server supervisor for authenticated, long-lived HTTP/3 peer requests.
pub struct PeerServer<P, H>
where
    P: PeerRequestPolicy,
    H: PeerRequestHandler,
{
    endpoint: quinn::Endpoint,
    pin_provider: SharedPeerPins,
    limits: PeerTransportLimits,
    policy: Arc<P>,
    handler: Arc<H>,
    diagnostics: Arc<PeerServerDiagnostics>,
}

/// A bounded snapshot of one authenticated incoming peer connection.
///
/// The counters describe the target-side H3 stream lifecycle.  The QUIC
/// frame counters are cumulative for the connection and intentionally expose
/// only stream-credit/control categories; they contain no request payload or
/// header values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerServerConnectionStats {
    /// Verified peer role identity.
    pub peer_node_id: String,
    /// The TLS server name the calling peer presented when it opened this
    /// connection, when the handshake carried one.
    ///
    /// This is the caller's SNI as the listener observed it, not a value this
    /// side chose.  It is a bounded identifier with no payload or credential
    /// content, and it lets an observer check that a dialling relay used the
    /// server name from its verified membership record.
    pub observed_server_name: Option<String>,
    /// Listener-local diagnostic identifier for this connection lifetime.
    ///
    /// Identifiers are allocated from a monotonic counter starting at one, so
    /// zero always means "no connection" to callers and an identifier is never
    /// reused by a later connection on the same listener, unlike the QUIC
    /// stack's slab-indexed stable id.
    pub connection_id: usize,
    /// H3 requests accepted by the target connection.
    pub accepted_streams: u64,
    /// Accepted requests currently resolving headers/policy.
    pub resolving_streams: u64,
    /// Requests currently owned by the application handler.
    pub active_streams: u64,
    /// Requests whose handler completed without an error.
    pub completed_streams: u64,
    /// Requests cancelled before normal completion, including requests
    /// rejected because the target stream permit ceiling was reached.
    pub cancelled_streams: u64,
    /// Requests that ended with a transport, authentication, or policy error.
    pub error_streams: u64,
    /// Server-side H3 stream permits available at the snapshot instant.
    pub available_stream_permits: usize,
    /// Configured server-side H3 stream permit ceiling.
    pub max_stream_permits: usize,
    /// Number of MAX_STREAMS (bidirectional) frames sent by the target.
    pub frame_tx_max_streams_bidi: u64,
    /// Number of MAX_STREAMS (bidirectional) frames received by the target.
    pub frame_rx_max_streams_bidi: u64,
    /// Number of STREAMS_BLOCKED (bidirectional) frames sent by the target.
    pub frame_tx_streams_blocked_bidi: u64,
    /// Number of STREAMS_BLOCKED (bidirectional) frames received by the target.
    pub frame_rx_streams_blocked_bidi: u64,
    /// Number of RESET_STREAM frames sent by the target.
    pub frame_tx_reset_stream: u64,
    /// Number of RESET_STREAM frames received by the target.
    pub frame_rx_reset_stream: u64,
    /// Number of STOP_SENDING frames sent by the target.
    pub frame_tx_stop_sending: u64,
    /// Number of STOP_SENDING frames received by the target.
    pub frame_rx_stop_sending: u64,
    /// Whether this connection successfully wrote its planned H3 GOAWAY.
    pub planned_goaway_sent: bool,
    /// Whether the planned drain had to cancel an admitted stream at its
    /// shared deadline.
    pub forced_stream_cancellation: bool,
    /// Whether the planned drain had to close QUIC at its shared deadline.
    pub forced_connection_close: bool,
    /// Whether a bounded cleanup join could not complete before the deadline.
    pub drain_join_incomplete: bool,
}

/// A bounded target-side snapshot of currently supervised peer connections.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PeerServerStats {
    /// One entry per currently supervised authenticated QUIC connection.
    pub connections: Vec<PeerServerConnectionStats>,
}

struct PeerServerConnectionDiagnostics {
    peer_node_id: String,
    observed_server_name: Option<String>,
    connection_id: usize,
    connection: quinn::Connection,
    stream_permits: Arc<Semaphore>,
    max_stream_permits: usize,
    accepted_streams: AtomicU64,
    resolving_streams: AtomicU64,
    active_streams: AtomicU64,
    completed_streams: AtomicU64,
    cancelled_streams: AtomicU64,
    error_streams: AtomicU64,
    planned_goaway_sent: AtomicBool,
    forced_stream_cancellation: AtomicBool,
    forced_connection_close: AtomicBool,
    drain_join_incomplete: AtomicBool,
}

/// In-process, bounded target-side peer diagnostics.
///
/// This is intentionally a library-owned observation point instead of an
/// unauthenticated endpoint.  At most `max_connections` entries are retained;
/// completed connection entries are removed when a replacement is registered.
pub struct PeerServerDiagnostics {
    max_connections: usize,
    next_connection_id: AtomicUsize,
    connections: StdMutex<HashMap<usize, Arc<PeerServerConnectionDiagnostics>>>,
}

impl PeerServerDiagnostics {
    fn new(max_connections: usize) -> Arc<Self> {
        Arc::new(Self {
            max_connections,
            next_connection_id: AtomicUsize::new(1),
            connections: StdMutex::new(HashMap::new()),
        })
    }

    /// Return a bounded snapshot without exposing request payloads.
    pub fn snapshot(&self) -> PeerServerStats {
        let connections = match self.connections.lock() {
            Ok(connections) => connections,
            Err(_) => return PeerServerStats::default(),
        };
        let connections = connections
            .values()
            .map(|connection| {
                let stats = connection.connection.stats();
                PeerServerConnectionStats {
                    peer_node_id: connection.peer_node_id.clone(),
                    observed_server_name: connection.observed_server_name.clone(),
                    connection_id: connection.connection_id,
                    accepted_streams: connection.accepted_streams.load(Ordering::Acquire),
                    resolving_streams: connection.resolving_streams.load(Ordering::Acquire),
                    active_streams: connection.active_streams.load(Ordering::Acquire),
                    completed_streams: connection.completed_streams.load(Ordering::Acquire),
                    cancelled_streams: connection.cancelled_streams.load(Ordering::Acquire),
                    error_streams: connection.error_streams.load(Ordering::Acquire),
                    available_stream_permits: connection.stream_permits.available_permits(),
                    max_stream_permits: connection.max_stream_permits,
                    frame_tx_max_streams_bidi: stats.frame_tx.max_streams_bidi,
                    frame_rx_max_streams_bidi: stats.frame_rx.max_streams_bidi,
                    frame_tx_streams_blocked_bidi: stats.frame_tx.streams_blocked_bidi,
                    frame_rx_streams_blocked_bidi: stats.frame_rx.streams_blocked_bidi,
                    frame_tx_reset_stream: stats.frame_tx.reset_stream,
                    frame_rx_reset_stream: stats.frame_rx.reset_stream,
                    frame_tx_stop_sending: stats.frame_tx.stop_sending,
                    frame_rx_stop_sending: stats.frame_rx.stop_sending,
                    planned_goaway_sent: connection.planned_goaway_sent.load(Ordering::Acquire),
                    forced_stream_cancellation: connection
                        .forced_stream_cancellation
                        .load(Ordering::Acquire),
                    forced_connection_close: connection
                        .forced_connection_close
                        .load(Ordering::Acquire),
                    drain_join_incomplete: connection.drain_join_incomplete.load(Ordering::Acquire),
                }
            })
            .collect();
        PeerServerStats { connections }
    }

    fn register(
        &self,
        peer_node_id: &str,
        connection: &quinn::Connection,
        stream_permits: Arc<Semaphore>,
        max_stream_permits: usize,
    ) -> Option<Arc<PeerServerConnectionDiagnostics>> {
        let mut connections = self.connections.lock().ok()?;
        connections.retain(|_, connection| connection.connection.close_reason().is_none());
        if connections.len() >= self.max_connections {
            return None;
        }
        let observation = Arc::new(PeerServerConnectionDiagnostics {
            peer_node_id: peer_node_id.to_owned(),
            observed_server_name: observed_server_name(connection),
            // Monotonic and non-zero: zero is the callers' "no connection"
            // sentinel, and a slab-indexed QUIC stable id could be reused by a
            // later connection while an earlier entry is still being drained.
            connection_id: self.next_connection_id.fetch_add(1, Ordering::AcqRel),
            connection: connection.clone(),
            stream_permits,
            max_stream_permits,
            accepted_streams: AtomicU64::new(0),
            resolving_streams: AtomicU64::new(0),
            active_streams: AtomicU64::new(0),
            completed_streams: AtomicU64::new(0),
            cancelled_streams: AtomicU64::new(0),
            error_streams: AtomicU64::new(0),
            planned_goaway_sent: AtomicBool::new(false),
            forced_stream_cancellation: AtomicBool::new(false),
            forced_connection_close: AtomicBool::new(false),
            drain_join_incomplete: AtomicBool::new(false),
        });
        connections.insert(observation.connection_id, observation.clone());
        Some(observation)
    }

    fn unregister(&self, connection_id: usize) {
        if let Ok(mut connections) = self.connections.lock() {
            connections.remove(&connection_id);
        }
    }
}

/// Read the TLS server name the calling peer presented on this connection.
///
/// The value comes from the completed handshake, so it is what the caller
/// actually sent rather than anything this side derived. Returning `None`
/// when the handshake carried no server name keeps the observation honest
/// instead of substituting a local default.
fn observed_server_name(connection: &quinn::Connection) -> Option<String> {
    connection
        .handshake_data()?
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()?
        .server_name
}

struct PeerServerDiagnosticsGuard {
    diagnostics: Arc<PeerServerDiagnostics>,
    connection_id: usize,
}

impl Drop for PeerServerDiagnosticsGuard {
    fn drop(&mut self) {
        self.diagnostics.unregister(self.connection_id);
    }
}

#[derive(Clone, Copy)]
enum PeerServerRequestStage {
    Resolving,
    Active,
}

#[derive(Clone, Copy)]
enum PeerServerRequestOutcome {
    Pending,
    Completed,
    Cancelled,
    Error,
}

struct PeerServerRequestDiagnosticsGuard {
    diagnostics: Option<Arc<PeerServerConnectionDiagnostics>>,
    stage: PeerServerRequestStage,
    outcome: PeerServerRequestOutcome,
}

impl PeerServerRequestDiagnosticsGuard {
    fn new(diagnostics: Option<Arc<PeerServerConnectionDiagnostics>>) -> Self {
        if let Some(diagnostics) = &diagnostics {
            diagnostics.resolving_streams.fetch_add(1, Ordering::AcqRel);
        }
        Self {
            diagnostics,
            stage: PeerServerRequestStage::Resolving,
            outcome: PeerServerRequestOutcome::Pending,
        }
    }

    fn mark_active(&mut self) {
        if !matches!(self.stage, PeerServerRequestStage::Resolving) {
            return;
        }
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.resolving_streams.fetch_sub(1, Ordering::AcqRel);
            diagnostics.active_streams.fetch_add(1, Ordering::AcqRel);
        }
        self.stage = PeerServerRequestStage::Active;
    }

    fn finish(&mut self, cancelled: bool, result: &Result<(), PeerTransportError>) {
        self.outcome = if cancelled || matches!(result, Err(PeerTransportError::Cancelled)) {
            PeerServerRequestOutcome::Cancelled
        } else if result.is_ok() {
            PeerServerRequestOutcome::Completed
        } else {
            PeerServerRequestOutcome::Error
        };
    }
}

impl Drop for PeerServerRequestDiagnosticsGuard {
    fn drop(&mut self) {
        let Some(diagnostics) = &self.diagnostics else {
            return;
        };
        match self.stage {
            PeerServerRequestStage::Resolving => {
                diagnostics.resolving_streams.fetch_sub(1, Ordering::AcqRel);
            }
            PeerServerRequestStage::Active => {
                diagnostics.active_streams.fetch_sub(1, Ordering::AcqRel);
            }
        }
        match self.outcome {
            PeerServerRequestOutcome::Pending | PeerServerRequestOutcome::Cancelled => {
                diagnostics.cancelled_streams.fetch_add(1, Ordering::AcqRel);
            }
            PeerServerRequestOutcome::Completed => {
                diagnostics.completed_streams.fetch_add(1, Ordering::AcqRel);
            }
            PeerServerRequestOutcome::Error => {
                diagnostics.error_streams.fetch_add(1, Ordering::AcqRel);
            }
        }
    }
}

impl<P, H> PeerServer<P, H>
where
    P: PeerRequestPolicy,
    H: PeerRequestHandler,
{
    /// Construct a server over a Quinn endpoint configured with mandatory
    /// TLS 1.3 relay peer authentication.
    pub fn new(
        endpoint: quinn::Endpoint,
        approved_pins: ApprovedPeerPins,
        limits: PeerTransportLimits,
        policy: P,
        handler: H,
    ) -> Result<Self, PeerTransportError> {
        let pin_provider = SharedPeerPins::new(approved_pins)?;
        Self::new_with_pin_provider(endpoint, pin_provider, limits, policy, handler)
    }

    /// Construct a server backed by caller-updated dynamic peer pin state.
    /// The initial snapshot may be empty, which rejects every peer until the
    /// caller publishes approved keys.
    pub fn new_with_pin_provider(
        endpoint: quinn::Endpoint,
        pin_provider: SharedPeerPins,
        limits: PeerTransportLimits,
        policy: P,
        handler: H,
    ) -> Result<Self, PeerTransportError> {
        limits.validate()?;
        let max_connections = limits.max_connections;
        Ok(Self {
            endpoint,
            pin_provider,
            limits,
            policy: Arc::new(policy),
            handler: Arc::new(handler),
            diagnostics: PeerServerDiagnostics::new(max_connections),
        })
    }

    /// Return the bounded in-process target-side diagnostics view.
    pub fn diagnostics(&self) -> Arc<PeerServerDiagnostics> {
        self.diagnostics.clone()
    }

    /// Run until cancellation, then close the endpoint and join all
    /// connection and request tasks immediately.
    pub async fn serve(self, cancel: CancellationToken) -> Result<(), PeerTransportError> {
        self.serve_with_mode(cancel, PeerShutdownMode::Emergency)
            .await
    }

    /// Run until cancellation, then send HTTP/3 GOAWAY to established
    /// connections and join admitted streams under the transport drain
    /// deadline.  Pin revocation and connection-local cancellation remain
    /// emergency closes; this mode only applies to the caller's planned
    /// listener shutdown signal.
    pub async fn serve_planned(self, cancel: CancellationToken) -> Result<(), PeerTransportError> {
        self.serve_with_mode(cancel, PeerShutdownMode::PlannedDrain)
            .await
    }

    /// Run with independent emergency and planned listener signals.
    ///
    /// An ordinary process/identity/pin cancellation remains emergency and
    /// closes immediately.  The separate planned token is the only signal
    /// allowed to enter the bounded HTTP/3 GOAWAY drain.  This seam is used by
    /// the in-process three-relay acceptance fixture; it does not change the
    /// default [`Self::serve`] behavior.
    pub async fn serve_with_planned_shutdown(
        self,
        emergency: CancellationToken,
        planned: CancellationToken,
    ) -> Result<(), PeerTransportError> {
        serve_peer_inner(
            self.endpoint,
            self.pin_provider,
            self.limits,
            self.policy,
            self.handler,
            self.diagnostics,
            emergency,
            PeerShutdownMode::PlannedDrain,
            Some(planned),
        )
        .await
    }

    async fn serve_with_mode(
        self,
        cancel: CancellationToken,
        mode: PeerShutdownMode,
    ) -> Result<(), PeerTransportError> {
        serve_peer_inner(
            self.endpoint,
            self.pin_provider,
            self.limits,
            self.policy,
            self.handler,
            self.diagnostics,
            cancel,
            mode,
            None,
        )
        .await
    }
}

/// Serve authenticated peer HTTP/3 requests until cancellation.
pub async fn serve_peer<P, H>(
    endpoint: quinn::Endpoint,
    approved_pins: ApprovedPeerPins,
    limits: PeerTransportLimits,
    policy: P,
    handler: H,
    cancel: CancellationToken,
) -> Result<(), PeerTransportError>
where
    P: PeerRequestPolicy,
    H: PeerRequestHandler,
{
    PeerServer::new(endpoint, approved_pins, limits, policy, handler)?
        .serve(cancel)
        .await
}

#[allow(clippy::too_many_arguments)]
async fn serve_peer_inner<P, H>(
    endpoint: quinn::Endpoint,
    pin_provider: SharedPeerPins,
    limits: PeerTransportLimits,
    policy: Arc<P>,
    handler: Arc<H>,
    diagnostics: Arc<PeerServerDiagnostics>,
    cancel: CancellationToken,
    mode: PeerShutdownMode,
    planned_cancel: Option<CancellationToken>,
) -> Result<(), PeerTransportError>
where
    P: PeerRequestPolicy,
    H: PeerRequestHandler,
{
    let permits = Arc::new(Semaphore::new(limits.max_connections));
    let mut tasks = JoinSet::new();
    let child_cancel = cancel.child_token();
    let planned = PlannedDrainSignal::new();
    let planned_cancel_enabled = planned_cancel.is_some();
    let mut requested_mode = mode;
    let mut supervisor_error = None;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                // With the dual-signal API this is the emergency path. The
                // legacy PlannedDrain API has no second token, so its caller
                // cancellation remains the planned signal.
                requested_mode = if planned_cancel_enabled {
                    PeerShutdownMode::Emergency
                } else {
                    mode
                };
                break;
            }
            _ = async {
                if let Some(token) = &planned_cancel {
                    token.cancelled().await;
                } else {
                    std::future::pending::<()>().await;
                }
            }, if planned_cancel_enabled => {
                requested_mode = PeerShutdownMode::PlannedDrain;
                break;
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let permit = match permits.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => continue,
                };
                let pin_provider = pin_provider.clone();
                let limits = limits.clone();
                let policy = policy.clone();
                let handler = handler.clone();
                let diagnostics = diagnostics.clone();
                // In planned mode the caller cancellation is the drain
                // request itself.  Keep established connection/stream
                // cancellation independent so admitted handlers survive
                // long enough to observe GOAWAY and finish under the shared
                // deadline.  Emergency mode retains the existing child
                // token propagation.
                // A dual-signal server gives established connection tasks an
                // emergency child token while the planned signal is carried by
                // `planned`. The legacy PlannedDrain form already has a
                // cancelled parent token, so it keeps its independent token.
                let connection_cancel = if planned_cancel_enabled {
                    child_cancel.child_token()
                } else {
                    match mode {
                        PeerShutdownMode::Emergency => child_cancel.child_token(),
                        PeerShutdownMode::PlannedDrain => CancellationToken::new(),
                    }
                };
                let planned = planned.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let handshake_cancel = connection_cancel.clone();
                    let handshake_planned = planned.clone();
                    let connection = tokio::select! {
                        biased;
                        _ = handshake_cancel.cancelled() => {
                            return Ok(())
                        }
                        _ = handshake_planned.token.cancelled(), if mode == PeerShutdownMode::PlannedDrain => {
                            return Ok(())
                        }
                        result = timeout(limits.handshake_timeout, incoming) => {
                            result
                                .map_err(|_| PeerTransportError::Timeout)?
                                .map_err(|error| PeerTransportError::Quic(error.to_string()))?
                        }
                    };
                    serve_incoming_connection(
                        connection,
                        &pin_provider,
                        &limits,
                        policy,
                        handler,
                        diagnostics,
                        connection_cancel,
                        mode,
                        planned,
                    )
                    .await
                });
            }
            Some(result) = tasks.join_next() => {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => tracing::debug!(?error, "HTTP/3 peer connection closed"),
                    Err(error) => {
                        supervisor_error = Some(PeerTransportError::Task(error));
                        break;
                    }
                }
            }
        }
    }

    let deadline = Instant::now() + limits.drain_timeout;
    match requested_mode {
        PeerShutdownMode::Emergency => {
            child_cancel.cancel();
            endpoint.close(quinn::VarInt::from_u32(0), b"peer shutdown");
            let _ = drain_peer_tasks(
                &mut tasks,
                deadline,
                cancel.is_cancelled(),
                &mut supervisor_error,
                "peer-connections",
            )
            .await;
        }
        PeerShutdownMode::PlannedDrain => {
            // Quinn Endpoint::close() also closes established connections.
            // Remove the server configuration first so existing H3
            // connections can send GOAWAY and drain independently.
            endpoint.set_server_config(None);
            planned.close_admission();
            planned.set_deadline(deadline);
            planned.token.cancel();
            let _ = drain_peer_tasks_with_grace(
                &mut tasks,
                deadline,
                false,
                &mut supervisor_error,
                "peer-connections",
                false,
                true,
            )
            .await;
            // All connection tasks have either drained or been joined/aborted
            // at the shared deadline before the endpoint is closed.
            endpoint.close(quinn::VarInt::from_u32(0), b"peer planned drain");
            child_cancel.cancel();
        }
    }
    if let Some(error) = supervisor_error {
        return Err(error);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn serve_incoming_connection<P, H>(
    connection: quinn::Connection,
    pin_provider: &SharedPeerPins,
    limits: &PeerTransportLimits,
    policy: Arc<P>,
    handler: Arc<H>,
    diagnostics: Arc<PeerServerDiagnostics>,
    cancel: CancellationToken,
    mode: PeerShutdownMode,
    planned: PlannedDrainSignal,
) -> Result<(), PeerTransportError>
where
    P: PeerRequestPolicy,
    H: PeerRequestHandler,
{
    configure_quic_connection(&connection, limits)?;
    let identity = verified_peer_identity(&connection).map_err(map_probe_error)?;
    pin_provider
        .snapshot()
        .verify(&identity)
        .map_err(map_probe_error)?;

    let quic = h3_quinn::Connection::new(connection.clone());
    let mut builder = h3::server::builder();
    builder.max_field_section_size(limits.max_header_bytes as u64);
    let mut h3_connection = timeout(limits.handshake_timeout, builder.build::<_, Bytes>(quic))
        .await
        .map_err(|_| PeerTransportError::Timeout)?
        .map_err(|error| PeerTransportError::H3(error.to_string()))?;
    let pin_watcher = spawn_pin_watcher(&identity, pin_provider, &connection, cancel.clone());
    let stream_permits = Arc::new(Semaphore::new(limits.max_streams_per_connection));
    let connection_diagnostics = diagnostics.register(
        identity.role_id(),
        &connection,
        stream_permits.clone(),
        limits.max_streams_per_connection,
    );
    let _diagnostics_guard =
        connection_diagnostics
            .as_ref()
            .map(|observation| PeerServerDiagnosticsGuard {
                diagnostics: diagnostics.clone(),
                connection_id: observation.connection_id,
            });
    let connection_bytes = Arc::new(AtomicUsize::new(0));
    let mut stream_tasks = JoinSet::new();
    let stream_cancel = cancel.child_token();
    let mut connection_error = None;
    let mut planned_requested = false;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                // A pin revocation or connection-local emergency wins if it
                // races the listener's planned signal.  If the planned
                // signal was already published, the deadline selection below
                // retains its absolute budget while preserving the emergency
                // close path.
                break;
            }
            _ = planned.token.cancelled(), if mode == PeerShutdownMode::PlannedDrain => {
                planned_requested = true;
                break;
            }
            result = h3_connection.accept() => {
                let resolver = match result {
                    Ok(Some(resolver)) => resolver,
                    Ok(None) => break,
                    Err(error) => {
                        connection_error = Some(PeerTransportError::H3(error.to_string()));
                        break;
                    }
                };
                if let Some(connection_diagnostics) = &connection_diagnostics {
                    connection_diagnostics
                        .accepted_streams
                        .fetch_add(1, Ordering::AcqRel);
                }
                let permit = match stream_permits.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        if let Some(connection_diagnostics) = &connection_diagnostics {
                            connection_diagnostics
                                .cancelled_streams
                                .fetch_add(1, Ordering::AcqRel);
                        }
                        continue;
                    }
                };
                let identity = identity.clone();
                let policy = policy.clone();
                let handler = handler.clone();
                let limits = limits.clone();
                let pin_provider = pin_provider.clone();
                let stream_cancel = stream_cancel.child_token();
                let connection_bytes = connection_bytes.clone();
                let connection_diagnostics = connection_diagnostics.clone();
                let planned = planned.clone();
                stream_tasks.spawn(async move {
                    handle_incoming_stream(
                        resolver,
                        identity,
                        pin_provider,
                        policy,
                        handler,
                        limits,
                        connection_bytes,
                        permit,
                        connection_diagnostics,
                        stream_cancel,
                        planned,
                    )
                    .await
                });
            }
            Some(result) = stream_tasks.join_next() => {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => tracing::debug!(?error, "HTTP/3 peer stream closed"),
                    Err(error) => {
                        connection_error = Some(PeerTransportError::Task(error));
                        break;
                    }
                }
            }
        }
    }

    let planned_deadline_published =
        mode == PeerShutdownMode::PlannedDrain && planned.token.is_cancelled();
    let deadline = if planned_requested || planned_deadline_published {
        planned.deadline().ok_or(PeerTransportError::Timeout)?
    } else {
        Instant::now() + limits.drain_timeout
    };
    if planned_requested {
        let mut forced_stream_cancellation = false;
        let mut forced_connection_close = false;
        let mut drain_join_incomplete = false;
        let mut connection_closed = false;
        let drain_wait_deadline = {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining > FORCED_JOIN_GRACE {
                deadline - FORCED_JOIN_GRACE
            } else {
                deadline
            }
        };
        // Send GOAWAY while QUIC is still open.  The accepted stream tasks
        // remain live while the H3 connection is driven to its post-GOAWAY
        // completion boundary.
        let goaway_sent = match timeout_at(drain_wait_deadline, h3_connection.shutdown(0)).await {
            Ok(Ok(())) => true,
            Ok(Err(error)) => {
                connection_error = Some(PeerTransportError::H3(error.to_string()));
                false
            }
            Err(_) => {
                connection_error = Some(PeerTransportError::Timeout);
                forced_connection_close = true;
                false
            }
        };
        if goaway_sent {
            if let Some(connection_diagnostics) = &connection_diagnostics {
                connection_diagnostics
                    .planned_goaway_sent
                    .store(true, Ordering::Release);
            }
        } else {
            connection.close(quinn::VarInt::from_u32(0), b"peer planned drain failure");
            connection_closed = true;
        }
        if goaway_sent {
            let mut h3_complete = false;
            while !h3_complete {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {
                        // A pin revocation or connection-local emergency
                        // cancellation wins over a planned drain already in
                        // progress. The watcher has already closed QUIC;
                        // leave the planned loop immediately and join below.
                        connection_error.get_or_insert(PeerTransportError::Cancelled);
                        connection.close(quinn::VarInt::from_u32(0), b"peer emergency during drain");
                        connection_closed = true;
                        break;
                    }
                    _ = sleep_until(drain_wait_deadline) => {
                        connection_error.get_or_insert(PeerTransportError::Timeout);
                        forced_connection_close = true;
                        forced_stream_cancellation = !stream_tasks.is_empty();
                        connection.close(quinn::VarInt::from_u32(0), b"peer planned drain deadline");
                        connection_closed = true;
                        break;
                    }
                    result = h3_connection.accept() => match result {
                        Ok(Some(resolver)) => {
                            // h3 rejects streams above the GOAWAY boundary
                            // before returning a resolver. If a resolver does
                            // surface here, consume and reset it with
                            // H3_REQUEST_REJECTED ("not processed") without
                            // dispatching; it is a bounded late-admission
                            // observation, not an application success.
                            if let Ok(Ok((_request, mut stream))) =
                                timeout_at(drain_wait_deadline, resolver.resolve_request()).await
                            {
                                stream.stop_sending(h3::error::Code::H3_REQUEST_REJECTED);
                                stream.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
                            }
                        }
                        Ok(None) => h3_complete = true,
                        Err(error) => {
                            connection_error = Some(PeerTransportError::H3(error.to_string()));
                            connection.close(quinn::VarInt::from_u32(0), b"peer planned H3 error");
                            connection_closed = true;
                            break;
                        }
                    },
                    Some(result) = stream_tasks.join_next() => match result {
                        Ok(Ok(())) => {}
                        // A forwarded stream ending with an error is a
                        // stream-local lifecycle event, exactly as in normal
                        // serving.  Peers tearing down around GOAWAY reset
                        // their streams (H3_REQUEST_CANCELLED/REJECTED); that
                        // is the expected drain outcome, not a listener
                        // failure.  Only a task panic or the forced-deadline
                        // path above fails the drain.
                        Ok(Err(error)) => {
                            tracing::debug!(
                                ?error,
                                "peer stream closed during planned drain"
                            );
                        }
                        Err(error) => {
                            connection_error = Some(PeerTransportError::Task(error));
                        }
                    },
                }
            }
        }
        if goaway_sent && !connection_closed && !forced_connection_close {
            while !stream_tasks.is_empty() {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {
                        connection_error.get_or_insert(PeerTransportError::Cancelled);
                        connection.close(quinn::VarInt::from_u32(0), b"peer emergency during drain");
                        forced_connection_close = true;
                        forced_stream_cancellation = true;
                        connection_closed = true;
                        break;
                    }
                    _ = sleep_until(drain_wait_deadline) => {
                        connection_error.get_or_insert(PeerTransportError::Timeout);
                        forced_connection_close = true;
                        forced_stream_cancellation = true;
                        connection.close(quinn::VarInt::from_u32(0), b"peer planned drain deadline");
                        connection_closed = true;
                        break;
                    }
                    Some(result) = stream_tasks.join_next() => match result {
                        Ok(Ok(())) => {}
                        // A forwarded stream's own error is stream-local, as in
                        // normal serving; the drain joins it rather than
                        // treating an expected GOAWAY-induced reset as a
                        // listener failure.
                        Ok(Err(error)) => {
                            tracing::debug!(
                                ?error,
                                "peer stream closed during planned drain"
                            );
                        }
                        Err(error) => {
                            connection_error = Some(PeerTransportError::Task(error));
                        }
                    },
                }
            }
        }
        if forced_connection_close && !connection_closed {
            connection.close(quinn::VarInt::from_u32(0), b"peer planned drain deadline");
            connection_closed = true;
        }
        stream_cancel.cancel();
        // Join any stragglers.  Stream-handler errors here are stream-local and
        // must not fail the listener (matching normal serving); only a forced
        // abort at the shared deadline is reported as incomplete cleanup.
        let stream_drain = drain_peer_tasks_without_recording_task_errors(
            &mut stream_tasks,
            deadline,
            false,
            &mut connection_error,
            "peer-streams",
        )
        .await;
        forced_stream_cancellation |= stream_drain.forced;
        drain_join_incomplete |= stream_drain.incomplete;
        forced_connection_close |= stream_drain.forced || stream_drain.incomplete;
        if let Some(connection_diagnostics) = &connection_diagnostics {
            connection_diagnostics
                .forced_stream_cancellation
                .store(forced_stream_cancellation, Ordering::Release);
            connection_diagnostics
                .forced_connection_close
                .store(forced_connection_close, Ordering::Release);
            connection_diagnostics
                .drain_join_incomplete
                .store(drain_join_incomplete, Ordering::Release);
        }
        // This is the terminal action after GOAWAY/accepted-stream draining,
        // or the explicit forced-close action at the shared deadline.
        if !connection_closed {
            connection.close(
                quinn::VarInt::from_u64(h3::error::Code::H3_NO_ERROR.value())
                    .expect("H3_NO_ERROR fits a QUIC application close code"),
                b"peer planned drain",
            );
        }
    } else {
        // Preserve the existing emergency ordering for process cancellation,
        // pin revocation, and connection-local failures.
        stream_cancel.cancel();
        connection.close(quinn::VarInt::from_u32(0), b"peer drain");
        if timeout_at(deadline, h3_connection.shutdown(0))
            .await
            .is_err()
        {
            tracing::warn!("HTTP/3 peer connection drain deadline exceeded");
        }
        // A forwarded stream's own terminal error is stream-local; the
        // emergency close already cancelled it, and an expected reset must not
        // be promoted to a listener failure.  Only a forced-deadline abort is
        // reported as incomplete cleanup below.
        let stream_drain = drain_peer_tasks_without_recording_task_errors(
            &mut stream_tasks,
            deadline,
            cancel.is_cancelled() && !planned_deadline_published,
            &mut connection_error,
            "peer-streams",
        )
        .await;
        if planned_deadline_published && let Some(connection_diagnostics) = &connection_diagnostics
        {
            connection_diagnostics
                .forced_stream_cancellation
                .store(stream_drain.forced, Ordering::Release);
            connection_diagnostics.forced_connection_close.store(
                stream_drain.forced || stream_drain.incomplete,
                Ordering::Release,
            );
            connection_diagnostics
                .drain_join_incomplete
                .store(stream_drain.incomplete, Ordering::Release);
        }
    }
    cancel.cancel();
    let pin_watcher_result = if planned_requested || planned_deadline_published {
        join_handle_until_bounded(pin_watcher, deadline).await
    } else {
        join_handle_until(pin_watcher, deadline).await
    };
    match pin_watcher_result {
        Some(Err(error)) => {
            connection_error.get_or_insert(PeerTransportError::Task(error));
        }
        None => {
            tracing::warn!("peer pin watcher exceeded drain timeout");
            connection_error.get_or_insert(PeerTransportError::Timeout);
            if (planned_requested || planned_deadline_published)
                && let Some(connection_diagnostics) = &connection_diagnostics
            {
                connection_diagnostics
                    .drain_join_incomplete
                    .store(true, Ordering::Release);
            }
        }
        Some(Ok(())) => {}
    }
    if let Some(error) = connection_error {
        return Err(error);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_incoming_stream<P, H>(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    identity: TlsIdentity,
    pin_provider: SharedPeerPins,
    policy: Arc<P>,
    handler: Arc<H>,
    limits: PeerTransportLimits,
    connection_bytes: Arc<AtomicUsize>,
    permit: OwnedSemaphorePermit,
    diagnostics: Option<Arc<PeerServerConnectionDiagnostics>>,
    cancel: CancellationToken,
    planned: PlannedDrainSignal,
) -> Result<(), PeerTransportError>
where
    P: PeerRequestPolicy,
    H: PeerRequestHandler,
{
    let mut diagnostics = PeerServerRequestDiagnosticsGuard::new(diagnostics);
    let planned_token = planned.token.clone();
    let result = async {
        if !pin_provider.snapshot().contains(identity.spki_sha256()) {
            cancel.cancel();
            return Err(PeerTransportError::Authentication(
                "peer SPKI pin was revoked".to_owned(),
            ));
        }
        let (request, stream) = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            _ = planned.token.cancelled() => return Ok(()),
            result = timeout(limits.idle_timeout, resolver.resolve_request()) => {
                result
                    .map_err(|_| PeerTransportError::Timeout)?
                    .map_err(|error| PeerTransportError::H3(error.to_string()))?
            }
        };
        if planned.admission_closed.load(Ordering::Acquire) {
            // A planned drain closed admission before this stream was
            // dispatched.  Reset with H3_REQUEST_REJECTED ("not processed")
            // so the caller classifies it as a pre-dispatch GoAway rather than
            // an ambiguous cancellation.
            let mut stream = stream;
            stream.stop_sending(h3::error::Code::H3_REQUEST_REJECTED);
            stream.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
            return Ok(());
        }
        diagnostics.mark_active();
        if !policy.authorize(&identity, &request) {
            let mut stream = stream;
            stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
            stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
            return Err(PeerTransportError::PolicyRejected);
        }
        if !planned.begin_admission() {
            // The planned-drain admission boundary closed while this stream was
            // resolving; it was never dispatched, so signal not-processed.
            let mut stream = stream;
            stream.stop_sending(h3::error::Code::H3_REQUEST_REJECTED);
            stream.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
            return Ok(());
        }
        let budget = body_budget(&limits, connection_bytes);
        let stream = PeerServerStream::new(
            stream,
            budget,
            Arc::new(StreamLease { _permit: permit }),
            limits.idle_timeout,
        );
        let handler_future = handler.handle(identity, request, stream);
        tokio::select! {
            biased;
            // The handler owns the request stream after admission.  On
            // cancellation its future is dropped, then the enclosing
            // connection performs the bounded QUIC close/join at the shared
            // deadline; do not move the stream into two select branches.
            _ = cancel.cancelled() => Ok(()),
            result = handler_future => result,
        }
    }
    .await;
    diagnostics.finish(
        cancel.is_cancelled() || planned_token.is_cancelled(),
        &result,
    );
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_explicit_and_bounded() {
        let defaults = PeerTransportLimits::default();
        assert!(defaults.validate().is_ok());
        assert_eq!(defaults.idle_timeout, DEFAULT_PEER_IDLE_TIMEOUT);
        assert_eq!(defaults.drain_timeout, DEFAULT_PEER_DRAIN_TIMEOUT);
        assert_eq!(
            defaults
                .clone()
                .with_timeouts(Duration::from_secs(7), Duration::from_secs(3))
                .unwrap()
                .idle_timeout,
            Duration::from_secs(7)
        );
        assert!(matches!(
            defaults.with_timeouts(Duration::ZERO, Duration::from_secs(3)),
            Err(PeerTransportError::InvalidLimits)
        ));
        assert!(matches!(
            PeerTransportLimits::new(
                0,
                1,
                1,
                1,
                1,
                1,
                1,
                Duration::from_secs(1),
                Duration::from_secs(1)
            ),
            Err(PeerTransportError::InvalidLimits)
        ));
        assert!(matches!(
            PeerBodyChunk::new(Bytes::from(vec![0; DEFAULT_PEER_BODY_CHUNK_BYTES + 1])),
            Err(PeerTransportError::ChunkTooLarge { .. })
        ));
    }

    #[test]
    fn body_budget_rejects_stream_and_connection_limits() {
        let budget = BodyBudget {
            stream_bytes: Arc::new(AtomicUsize::new(0)),
            connection_bytes: Arc::new(AtomicUsize::new(0)),
            max_stream_bytes: 4,
            max_connection_bytes: 8,
            max_chunk_bytes: 4,
        };
        let held = budget.reserve(4).unwrap();
        assert!(matches!(
            budget.reserve(1),
            Err(PeerTransportError::BodyTooLarge { maximum: 4, .. })
        ));
        drop(held);
        assert_eq!(budget.stream_bytes.load(Ordering::Acquire), 0);
        assert_eq!(budget.connection_bytes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn body_budget_retained_chunks_saturate_and_connection_failure_rolls_back() {
        let connection_bytes = Arc::new(AtomicUsize::new(0));
        let budget = BodyBudget {
            stream_bytes: Arc::new(AtomicUsize::new(0)),
            connection_bytes: connection_bytes.clone(),
            max_stream_bytes: 8,
            max_connection_bytes: 8,
            max_chunk_bytes: 8,
        };
        let first = budget.reserve(4).unwrap();
        let retained = PeerBodyChunk::from_received(Bytes::from_static(b"1234"), first);
        let retained_clone = retained.clone();
        assert_eq!(budget.stream_bytes.load(Ordering::Acquire), 4);
        assert_eq!(connection_bytes.load(Ordering::Acquire), 4);
        assert!(matches!(
            budget.reserve(5),
            Err(PeerTransportError::BodyTooLarge { maximum: 8, .. })
        ));
        drop(retained);
        assert_eq!(budget.stream_bytes.load(Ordering::Acquire), 4);
        drop(retained_clone);
        assert_eq!(budget.stream_bytes.load(Ordering::Acquire), 0);
        assert_eq!(connection_bytes.load(Ordering::Acquire), 0);

        let budget = BodyBudget {
            stream_bytes: Arc::new(AtomicUsize::new(0)),
            connection_bytes: Arc::new(AtomicUsize::new(0)),
            max_stream_bytes: 8,
            max_connection_bytes: 4,
            max_chunk_bytes: 8,
        };
        let held = budget.reserve(4).unwrap();
        assert!(matches!(
            budget.reserve(4),
            Err(PeerTransportError::BodyTooLarge { maximum: 4, .. })
        ));
        assert_eq!(budget.stream_bytes.load(Ordering::Acquire), 4);
        assert_eq!(budget.connection_bytes.load(Ordering::Acquire), 4);
        drop(held);
        assert_eq!(budget.stream_bytes.load(Ordering::Acquire), 0);
        assert_eq!(budget.connection_bytes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn body_budget_allows_repeated_transfers_after_each_write_releases() {
        let budget = BodyBudget {
            stream_bytes: Arc::new(AtomicUsize::new(0)),
            connection_bytes: Arc::new(AtomicUsize::new(0)),
            max_stream_bytes: 4,
            max_connection_bytes: 4,
            max_chunk_bytes: 4,
        };
        // The byte ceilings are in-flight bounds, not a lifetime transfer
        // quota: completed writes release their charge and a long-lived H3
        // stream can keep transferring bounded chunks.
        for _ in 0..256 {
            let charge = budget.reserve(4).unwrap();
            drop(charge);
        }
        assert_eq!(budget.stream_bytes.load(Ordering::Acquire), 0);
        assert_eq!(budget.connection_bytes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn bounded_body_chunks_preserve_order_and_configured_boundaries() {
        let maximum = DEFAULT_PEER_BODY_CHUNK_BYTES;
        let mut body = Vec::with_capacity(maximum + 72);
        body.extend((0..maximum + 72).map(|index| (index % 251) as u8));

        let chunks: Vec<&[u8]> = bounded_body_chunks(&body, maximum).collect();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), maximum);
        assert_eq!(chunks[1].len(), 72);
        assert!(chunks.iter().all(|chunk| chunk.len() <= maximum));

        let reconstructed: Vec<u8> = chunks
            .iter()
            .flat_map(|chunk| chunk.iter().copied())
            .collect();
        assert_eq!(reconstructed, body);

        let smaller: Vec<&[u8]> = bounded_body_chunks(&body[..23], 7).collect();
        assert_eq!(
            smaller.iter().map(|chunk| chunk.len()).collect::<Vec<_>>(),
            [7, 7, 7, 2]
        );
        assert_eq!(smaller.concat(), &body[..23]);
    }

    #[test]
    fn bounded_body_chunks_exact_limit_has_no_empty_tail() {
        let body = vec![0x5a; DEFAULT_PEER_BODY_CHUNK_BYTES];
        let chunks: Vec<&[u8]> =
            bounded_body_chunks(&body, DEFAULT_PEER_BODY_CHUNK_BYTES).collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], body.as_slice());
        assert!(
            bounded_body_chunks(&[], DEFAULT_PEER_BODY_CHUNK_BYTES)
                .next()
                .is_none()
        );
    }

    #[test]
    fn zero_length_receive_chunks_do_not_retain_budget_metadata() {
        let budget = BodyBudget {
            stream_bytes: Arc::new(AtomicUsize::new(0)),
            connection_bytes: Arc::new(AtomicUsize::new(0)),
            max_stream_bytes: 4,
            max_connection_bytes: 4,
            max_chunk_bytes: 4,
        };
        let zero = PeerBodyChunk::from_received(Bytes::new(), budget.reserve(0).unwrap());
        assert!(zero._charge.is_none());
        assert_eq!(budget.stream_bytes.load(Ordering::Acquire), 0);
        assert_eq!(budget.connection_bytes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn dynamic_pin_snapshots_are_bounded_and_fail_closed() {
        let first = crate::SpkiSha256::from_bytes([1; 32]);
        let second = crate::SpkiSha256::from_bytes([2; 32]);
        let approved = ApprovedPeerPins::new([first, second]).unwrap();
        let shared = SharedPeerPins::new(approved).unwrap();
        let initial = shared.snapshot();
        assert_eq!(initial.len(), 2);
        assert!(initial.contains(first));
        assert_eq!(initial.revision(), 0);

        shared.replace(std::iter::empty()).unwrap();
        let revoked = shared.snapshot();
        assert!(revoked.is_empty());
        assert!(!revoked.contains(first));
        assert_eq!(revoked.revision(), 1);

        let too_many = (0..=MAX_DYNAMIC_PEER_PINS)
            .map(|value| crate::SpkiSha256::from_bytes([value as u8; 32]));
        assert!(matches!(
            shared.replace(too_many),
            Err(PeerTransportError::TooManyPeerPins { .. })
        ));
        assert!(shared.snapshot().is_empty());
    }

    #[test]
    fn dial_pool_retires_stale_markers_before_enforcing_saturation() {
        let destination = PeerDestination::new("127.0.0.1:1".parse().unwrap(), "peer.test");
        let other = PeerDestination::new("127.0.0.1:2".parse().unwrap(), "peer.test");
        let mut locks = HashMap::new();
        let retired = acquire_dial_entry(&mut locks, &destination, 1).unwrap();
        retired.retired.store(true, Ordering::Release);

        let replacement = acquire_dial_entry(&mut locks, &destination, 1).unwrap();
        assert!(!Arc::ptr_eq(&retired, &replacement));
        assert!(matches!(
            acquire_dial_entry(&mut locks, &other, 1),
            Err(PeerTransportError::Capacity)
        ));
    }

    #[tokio::test]
    async fn checkout_deadline_is_absolute_and_cancellation_wakes_waiters() {
        let cancel = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_millis(35);
        with_checkout_deadline(
            &cancel,
            deadline,
            tokio::time::sleep(Duration::from_millis(10)),
        )
        .await
        .unwrap();
        assert!(matches!(
            with_checkout_deadline(
                &cancel,
                deadline,
                tokio::time::sleep(Duration::from_millis(50)),
            )
            .await,
            Err(PeerTransportError::Timeout)
        ));

        cancel.cancel();
        assert!(matches!(
            with_checkout_deadline(
                &cancel,
                Instant::now() + Duration::from_secs(1),
                tokio::time::sleep(Duration::from_secs(1)),
            )
            .await,
            Err(PeerTransportError::Cancelled)
        ));
    }

    #[tokio::test]
    async fn cancelled_dial_creator_releases_its_pool_marker() {
        let state = Arc::new(PeerPoolState {
            connections: Mutex::new(HashMap::new()),
            dial_locks: Mutex::new(HashMap::new()),
        });
        let destination = PeerDestination::new("127.0.0.1:1".parse().unwrap(), "peer.test");
        let entry = Arc::new(DialEntry::new());
        entry.users.fetch_add(1, Ordering::AcqRel);
        state
            .dial_locks
            .lock()
            .await
            .insert(destination.clone(), entry.clone());
        DialLease {
            state: state.clone(),
            destination: destination.clone(),
            entry,
            released: false,
        }
        .release(false)
        .await;
        assert!(state.dial_locks.lock().await.is_empty());

        let dropped_destination = PeerDestination::new("127.0.0.1:2".parse().unwrap(), "peer.test");
        let dropped_entry = Arc::new(DialEntry::new());
        dropped_entry.users.fetch_add(1, Ordering::AcqRel);
        state
            .dial_locks
            .lock()
            .await
            .insert(dropped_destination.clone(), dropped_entry.clone());
        drop(DialLease {
            state,
            destination: dropped_destination,
            entry: dropped_entry.clone(),
            released: false,
        });
        assert!(dropped_entry.retired.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn peer_shutdown_uses_one_shared_drain_deadline() {
        let mut tasks = JoinSet::new();
        tasks.spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok(())
        });
        let started = Instant::now();
        let mut first_error = None;
        let _ = drain_peer_tasks(
            &mut tasks,
            started + Duration::from_millis(25),
            true,
            &mut first_error,
            "test-drain",
        )
        .await;
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(tasks.is_empty());
        assert!(first_error.is_none());
    }

    #[test]
    fn planned_admission_gate_preserves_preboundary_and_rejects_postboundary() {
        let planned = PlannedDrainSignal::new();
        let preadmitted = planned.begin_admission();
        planned.close_admission();

        assert!(preadmitted);
        assert!(!planned.begin_admission());
    }
}
