//! Relay-side HTTP/3 peer forwarding.
//!
//! This module is the narrow adapter between the public/device Axum routers
//! and the authenticated, bounded peer transport.  It deliberately does not
//! decide ownership or membership itself: [`OwnerRouter`] reads the
//! authoritative catalog and a caller-owned [`PeerBindingProvider`] supplies
//! the signed membership evidence needed before a peer dial.  The owner
//! token, source identity, and one-hop budget are carried in the first
//! charged peer record of every stream.

use std::{
    collections::{HashMap, VecDeque},
    error::Error,
    fmt,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

#[path = "peer_readiness.rs"]
pub mod peer_readiness;

#[cfg(test)]
#[path = "peer_runtime_probe_tests.rs"]
mod peer_runtime_probe_tests;

use axum::http::{Request, Response, StatusCode};
use chrono::{DateTime, TimeZone, Utc};
use futures_util::stream::{self, StreamExt};
use tokio::{
    sync::Mutex,
    time::{Instant as TokioInstant, timeout_at},
};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{Catalog, OwnerToken};
use tunnel_cluster::{
    envelope::{
        Destination, DeviceAuthenticationContext, ForwardedConsumerBearer, IngressRequestBinding,
        InternalRoute, PeerIdentity, RequestEnvelope, VerifiedDeviceCertificate, decode_envelope,
    },
    membership::VerifiedPeerBinding,
    peer_frame::{
        ConnectionBudget, PeerFrameError, PeerRecord, PeerRecordDecoder, PeerRecordKind,
        StreamBudget,
    },
};
use tunnel_transport::{
    PeerClient, PeerClientRecv, PeerClientSend, PeerClientStream, PeerDestination,
    PeerHandlerFuture, PeerOpenProgress, PeerRequestHandler, PeerRequestPolicy, PeerServerRecv,
    PeerServerSend, PeerServerStream, PeerTransportError, PeerTransportOpenStage, TlsIdentity,
};
use uuid::Uuid;

use self::peer_readiness::{
    MAX_CONCURRENT_PEER_PROBES, PEER_PROBE_TIMEOUT, PeerListenerState, PeerProbeState,
    PeerReadiness, PeerReadinessError, PeerRouteTarget,
};
use crate::{
    http::{PeerAdmissionBarrier, PeerAdmissionScope},
    membership_runtime::PeerAdmissionCancellation,
    routing::{OwnerRoute, OwnerRouter, OwnerRoutingError, OwnerScope},
};

impl PeerBindingProvider for crate::MembershipRuntime {
    fn binding<'a>(
        &'a self,
        node_id: &'a str,
        boot_id: &'a str,
        now: DateTime<Utc>,
    ) -> PeerBindingFuture<'a> {
        Box::pin(async move {
            let membership = self
                .snapshot()
                .memberships
                .into_iter()
                .find(|membership| membership.node_id == node_id)
                .ok_or_else(|| PeerRuntimeError::Membership("peer is not trusted".to_owned()))?;
            for spki in membership.spki_sha256 {
                let identity = crate::membership_runtime::PeerIdentity::new(node_id, boot_id, spki);
                if let Ok(binding) = self.verified_peer_binding(&identity)
                    && binding.valid_until() > now
                {
                    return Ok(binding);
                }
            }
            Err(PeerRuntimeError::Membership(
                "peer is not trusted".to_owned(),
            ))
        })
    }

    fn is_ready(&self) -> bool {
        matches!(self.readiness(), crate::MembershipReadiness::Ready)
    }

    fn binding_for_certificate<'a>(
        &'a self,
        node_id: &'a str,
        boot_id: &'a str,
        spki_sha256: &'a str,
        _now: DateTime<Utc>,
    ) -> PeerBindingFuture<'a> {
        Box::pin(async move {
            let identity =
                crate::membership_runtime::PeerIdentity::new(node_id, boot_id, spki_sha256);
            self.verified_peer_binding(&identity)
                .map_err(|_| PeerRuntimeError::Membership("peer is not trusted".to_owned()))
        })
    }

    fn admission_cancellation<'a>(
        &'a self,
        node_id: &'a str,
        boot_id: &'a str,
        spki_sha256: &'a str,
        _now: DateTime<Utc>,
    ) -> PeerAdmissionCancellationFuture<'a> {
        Box::pin(async move {
            let identity =
                crate::membership_runtime::PeerIdentity::new(node_id, boot_id, spki_sha256);
            self.admit_peer(identity)
                .map(|admission| Some(admission.cancellation()))
                .map_err(|error| PeerRuntimeError::Membership(error.to_string()))
        })
    }
}

const DEVICE_CONTROL_PATH: &str = "/internal/v1/device/control";
const DEVICE_DATA_PATH: &str = "/internal/v1/device/data";
const CONSUMER_STREAMS_PATH: &str = "/internal/v1/streams";
const OPERATION_STATUS_PATH: &str = "/internal/v1/operations/status";
const HEALTH_PATH: &str = "/internal/v1/health";
const PEER_METHOD: &str = "POST";
const PEER_ADMISSION_HEADER: &str = "x-agent-tunnel-admission";
const PEER_ADMISSION_OWNER_NOT_READY: &str = "owner_not_ready";
const PEER_ADMISSION_CAPACITY: &str = "capacity";
const PEER_ERROR_EXECUTION_HEADER: &str = "x-agent-tunnel-execution";
const PEER_ERROR_CODE_HEADER: &str = "x-agent-tunnel-error-code";
const PEER_RETRYABLE_HEADER: &str = "x-agent-tunnel-retryable";
const PEER_RETRY_AFTER_MS_HEADER: &str = "x-agent-tunnel-retry-after-ms";
pub(crate) const OWNER_NOT_READY_RETRY_AFTER_MS: u64 = 250;
pub(crate) const STREAM_LIMIT_RETRY_AFTER_MS: u64 = 250;
const MAX_OWNER_NOT_READY_RETRY_AFTER_MS: u64 = 5_000;
const MAX_STREAM_LIMIT_RETRY_AFTER_MS: u64 = 5_000;
const CONSUMER_RECORD_PREFIX_LEN: usize = 4;
const MAX_ECHO_CANARY_BYTES: usize = 256;
const MAX_CONSUMER_UNARY_BODY: usize = crate::wire::MAX_BODY_BYTES;
const MAX_CONSUMER_RESPONSE_BODY: usize = crate::wire::MAX_BODY_BYTES + MAX_ECHO_CANARY_BYTES;
const MAX_CONSUMER_RESPONSE_RECORD: usize = CONSUMER_RECORD_PREFIX_LEN + MAX_CONSUMER_RESPONSE_BODY;

/// The maximum body record used for the initial envelope.
const MAX_ENVELOPE_RECORD: usize = 8 * 1024;

/// An asynchronous membership lookup used by peer routing.
pub type PeerBindingFuture<'a> =
    Pin<Box<dyn Future<Output = Result<VerifiedPeerBinding, PeerRuntimeError>> + Send + 'a>>;

/// An optional cancellation edge for one verified peer admission.
///
/// Membership-backed providers retain this cancellation edge across pooled
/// streams. Standalone providers may return `None` and rely on their configured
/// transport and operation bounds.
pub type PeerAdmissionCancellationFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<Option<PeerAdmissionCancellation>, PeerRuntimeError>>
            + Send
            + 'a,
    >,
>;

/// Supplies verified membership evidence for one exact node/boot pair.
///
/// Implementations normally wrap the relay's membership runtime.  The
/// provider must never construct a binding from request headers or from a
/// Redis key alone; it must intersect the signed record/checkpoint with the
/// completed peer mTLS identity.
pub trait PeerBindingProvider: Send + Sync + 'static {
    /// Return a currently valid binding for the exact destination identity.
    fn binding<'a>(
        &'a self,
        node_id: &'a str,
        boot_id: &'a str,
        now: DateTime<Utc>,
    ) -> PeerBindingFuture<'a>;

    /// Return current signed membership evidence for one exact node, boot, and
    /// authenticated certificate SPKI.  The default preserves the original
    /// provider contract while making the observed certificate pin an
    /// explicit fail-closed check for standalone fixtures.
    fn binding_for_certificate<'a>(
        &'a self,
        node_id: &'a str,
        boot_id: &'a str,
        spki_sha256: &'a str,
        now: DateTime<Utc>,
    ) -> PeerBindingFuture<'a> {
        Box::pin(async move {
            let binding = self.binding(node_id, boot_id, now).await?;
            if binding.spki_sha256() != spki_sha256 {
                return Err(PeerRuntimeError::PeerIdentityMismatch);
            }
            Ok(binding)
        })
    }

    /// Return whether new cluster dispatches may be admitted.
    ///
    /// The default keeps standalone peer-runtime fixtures and the local M1/M2
    /// profile ready. Membership-backed providers override this with their
    /// current signed-checkpoint/catalog readiness.
    fn is_ready(&self) -> bool {
        true
    }

    /// Return the cancellation edge for an active membership admission.
    ///
    /// Providers with process-local membership state can override this after
    /// the exact binding and authenticated certificate have been checked.
    /// The API-only default intentionally preserves the old forwarding
    /// behavior and returns no cancellation edge.
    fn admission_cancellation<'a>(
        &'a self,
        _node_id: &'a str,
        _boot_id: &'a str,
        _spki_sha256: &'a str,
        _now: DateTime<Utc>,
    ) -> PeerAdmissionCancellationFuture<'a> {
        Box::pin(async { Ok(None) })
    }
}

impl<F, Fut> PeerBindingProvider for F
where
    F: Fn(&str, &str, DateTime<Utc>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<VerifiedPeerBinding, PeerRuntimeError>> + Send + 'static,
{
    fn binding<'a>(
        &'a self,
        node_id: &'a str,
        boot_id: &'a str,
        now: DateTime<Utc>,
    ) -> PeerBindingFuture<'a> {
        Box::pin((self)(node_id, boot_id, now))
    }
}

/// An owner-side callback invoked after the private transport and membership
/// checks have accepted one peer request.
pub type PeerIngressHandlerFuture =
    Pin<Box<dyn Future<Output = Result<(), PeerRuntimeError>> + Send>>;

/// Dispatch one authenticated, one-hop request to the owner actor.
pub trait PeerIngressHandler: Send + Sync + 'static {
    /// Handle the request.  The callback must independently validate the
    /// decoded envelope against the current catalog and, for consumers, run
    /// JWT validation before allocating actor state.
    fn handle(&self, request: InboundPeerRequest) -> PeerIngressHandlerFuture;
}

impl<F, Fut> PeerIngressHandler for F
where
    F: Fn(InboundPeerRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), PeerRuntimeError>> + Send + 'static,
{
    fn handle(&self, request: InboundPeerRequest) -> PeerIngressHandlerFuture {
        Box::pin((self)(request))
    }
}

/// Adapter implementing the transport crate's server callback.
///
/// [`PeerRuntimeHandler`] is the startup seam: pass
/// `runtime.server_handler(owner_callback)` to
/// `PeerServer::new_with_pin_provider`.  The transport policy runs first,
/// then this adapter performs the asynchronous signed membership and source
/// binding checks before invoking the owner callback.
pub struct PeerRuntimeHandler<H> {
    runtime: Arc<PeerRuntime>,
    handler: Arc<H>,
}

impl<H> PeerRequestHandler for PeerRuntimeHandler<H>
where
    H: PeerIngressHandler,
{
    fn handle(
        &self,
        identity: TlsIdentity,
        request: Request<()>,
        stream: PeerServerStream,
    ) -> PeerHandlerFuture {
        let runtime = Arc::clone(&self.runtime);
        let handler = Arc::clone(&self.handler);
        Box::pin(async move {
            if request.method() == axum::http::Method::GET && request.uri().path() == HEALTH_PATH {
                runtime
                    .accept_probe(identity, request, stream)
                    .await
                    .map_err(peer_transport_error)?;
                return Ok(());
            }
            let inbound = runtime
                .accept_inbound(identity, request, stream)
                .await
                .map_err(peer_transport_error)?;
            let admission_cancellation = inbound.admission_cancellation_context();
            if let Some(admission_cancellation) = admission_cancellation {
                let handler_future = handler.handle(inbound);
                tokio::pin!(handler_future);
                tokio::select! {
                    biased;
                    _ = admission_cancellation.cancelled() => {
                        // Cancellation is the fail-closed boundary for an
                        // arbitrary owner callback. Drop a callback that is
                        // paused before body receipt immediately; its
                        // request-scoped guards enqueue exact-key cleanup in
                        // Drop, while waiting here would retain admission
                        // after membership invalidation.
                        Err(peer_transport_error(admission_cancellation_error(
                            Some(&admission_cancellation),
                        )))
                    },
                    result = &mut handler_future => result.map_err(peer_transport_error),
                }
            } else {
                handler.handle(inbound).await.map_err(peer_transport_error)
            }
        })
    }
}

/// Errors raised while routing or bridging one peer request.
#[derive(Debug)]
pub enum PeerRuntimeError {
    /// The owner catalog could not be read or the owner claim was invalid.
    Routing(OwnerRoutingError),
    /// Membership or checkpoint evidence did not authorize the peer.
    Membership(String),
    /// The signed endpoint is not a concrete address accepted by the current
    /// transport adapter.
    InvalidEndpoint(String),
    /// The authenticated peer certificate did not match the signed binding.
    PeerIdentityMismatch,
    /// A private peer transport operation failed.
    Transport(PeerTransportError),
    /// The bounded envelope codec rejected the request.
    Envelope(tunnel_cluster::envelope::EnvelopeError),
    /// The bounded peer-record codec rejected a message.
    Frame(PeerFrameError),
    /// The owner rejected the HTTP/3 admission with a bounded status code.
    RemoteStatus(StatusCode),
    /// An internal route has no corresponding private endpoint.
    InvalidRoute(InternalRoute),
    /// The initial peer record was not the required envelope control record.
    UnexpectedRecord(PeerRecordKind),
    /// The selected owner has a committed session but its authenticated data
    /// carrier or owner-fence acknowledgement is not ready yet.  This is a
    /// pre-admission condition and is safe to retry after the bounded hint.
    OwnerNotReady { retry_after_ms: u64 },
    /// The authenticated owner refused a consumer stream before any
    /// application record was dispatched because its bounded stream limit is
    /// full.
    Capacity { retry_after_ms: u64 },
    /// The authenticated peer membership admission expired.
    MembershipExpired,
    /// The peer stream was already completed or cancelled.
    Closed,
}

impl fmt::Display for PeerRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Routing(_) => formatter.write_str("owner routing failed"),
            Self::Membership(_) => formatter.write_str("peer membership is not trusted"),
            Self::InvalidEndpoint(_) => formatter.write_str("peer endpoint is invalid"),
            Self::PeerIdentityMismatch => {
                formatter.write_str("peer identity does not match membership")
            }
            Self::Transport(_) => formatter.write_str("peer transport failed"),
            Self::Envelope(_) => formatter.write_str("peer envelope is invalid"),
            Self::Frame(_) => formatter.write_str("peer record is invalid"),
            Self::RemoteStatus(status) => {
                write!(formatter, "owner rejected peer request: {status}")
            }
            Self::InvalidRoute(_) => formatter.write_str("internal route is not supported"),
            Self::UnexpectedRecord(_) => {
                formatter.write_str("peer stream has an invalid first record")
            }
            Self::OwnerNotReady { .. } => formatter.write_str("peer owner is not ready"),
            Self::Capacity { .. } => formatter.write_str("peer owner stream capacity is exhausted"),
            Self::MembershipExpired => formatter.write_str("peer membership trust expired"),
            Self::Closed => formatter.write_str("peer stream is closed"),
        }
    }
}

impl Error for PeerRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Routing(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::Envelope(error) => Some(error),
            Self::Frame(error) => Some(error),
            _ => None,
        }
    }
}

impl From<OwnerRoutingError> for PeerRuntimeError {
    fn from(value: OwnerRoutingError) -> Self {
        Self::Routing(value)
    }
}

impl From<PeerTransportError> for PeerRuntimeError {
    fn from(value: PeerTransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<tunnel_cluster::envelope::EnvelopeError> for PeerRuntimeError {
    fn from(value: tunnel_cluster::envelope::EnvelopeError) -> Self {
        Self::Envelope(value)
    }
}

impl From<PeerFrameError> for PeerRuntimeError {
    fn from(value: PeerFrameError) -> Self {
        Self::Frame(value)
    }
}

fn admission_cancellation_error(
    cancellation: Option<&PeerAdmissionCancellation>,
) -> PeerRuntimeError {
    if cancellation.is_some_and(PeerAdmissionCancellation::trust_expired) {
        PeerRuntimeError::MembershipExpired
    } else {
        PeerRuntimeError::Closed
    }
}

/// Attribute a peer reset or close observed after this admission's signed
/// trust deadline to membership expiry.
///
/// Both relays on a pooled HTTP/3 stream enforce the same signed deadline,
/// and the remote side may cancel first.  Without this, the local observer
/// would record a generic transport close a few milliseconds before its own
/// invalidation dispatcher runs, and the exact stream's first terminal cause
/// would be lost.  Only the peer-reset family is reclassified: `GoAway`,
/// timeouts, limit and authentication failures keep their own typed
/// classification, and no error is reclassified before the deadline.
fn attribute_admission_failure<T>(
    result: Result<T, PeerRuntimeError>,
    cancellation: &PeerAdmissionCancellation,
) -> Result<T, PeerRuntimeError> {
    match result {
        Err(
            PeerRuntimeError::Transport(
                PeerTransportError::H3(_)
                | PeerTransportError::Quic(_)
                | PeerTransportError::Cancelled,
            )
            | PeerRuntimeError::Closed,
        ) if cancellation.trust_expired() => Err(PeerRuntimeError::MembershipExpired),
        other => other,
    }
}

/// Convert the richer relay admission error into the transport error surface
/// without forwarding credentials, envelopes, or catalog details to a peer.
fn peer_transport_error(error: PeerRuntimeError) -> PeerTransportError {
    match error {
        PeerRuntimeError::Transport(error) => error,
        PeerRuntimeError::Closed | PeerRuntimeError::MembershipExpired => {
            PeerTransportError::Cancelled
        }
        PeerRuntimeError::PeerIdentityMismatch
        | PeerRuntimeError::Membership(_)
        | PeerRuntimeError::Routing(_) => {
            PeerTransportError::Authentication("peer admission rejected".to_owned())
        }
        PeerRuntimeError::Envelope(_)
        | PeerRuntimeError::Frame(_)
        | PeerRuntimeError::InvalidEndpoint(_)
        | PeerRuntimeError::InvalidRoute(_)
        | PeerRuntimeError::RemoteStatus(_)
        | PeerRuntimeError::UnexpectedRecord(_)
        | PeerRuntimeError::OwnerNotReady { .. }
        | PeerRuntimeError::Capacity { .. } => {
            PeerTransportError::H3("peer ingress rejected".to_owned())
        }
    }
}

fn peer_readiness_error(error: PeerReadinessError) -> PeerRuntimeError {
    PeerRuntimeError::Membership(match error {
        PeerReadinessError::InvalidCapacity => "peer readiness capacity is invalid".to_owned(),
        PeerReadinessError::InvalidProbeTtl => {
            "peer readiness probe freshness is invalid".to_owned()
        }
        PeerReadinessError::TooManyRoutes { .. } => {
            "peer readiness route set exceeds the bounded deployment limit".to_owned()
        }
        PeerReadinessError::UnknownRoute => "peer readiness route is not required".to_owned(),
    })
}

/// The bounded stage of one direct peer-open attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum PeerOpenDiagnosticStage {
    /// Validating readiness, route, and envelope identity locally.
    Validation = 0,
    /// Checking or creating the pooled QUIC/HTTP/3 connection.
    PoolConnect = 1,
    /// Waiting for the configured request-stream permit.
    StreamPermitCheckout = 2,
    /// Waiting for the shared HTTP/3 sender mutex.
    SenderLock = 3,
    /// Dispatching request headers or waiting for a remote QUIC bidi stream.
    H3Dispatch = 4,
    /// Encoding and sending the authenticated envelope record.
    EnvelopeSend = 5,
    /// Returning a fully initialized exchange to the caller.
    Complete = 6,
    /// Waiting for the owner's HTTP/3 response head after the envelope was
    /// sent.  An owner admission decision observed here is attributed to
    /// [`Self::Owner`] by the fault observer.
    Head = 7,
    /// Forwarding or receiving bounded consumer body records after the head
    /// was accepted.
    Body = 8,
    /// Re-reading the authoritative owner claim or its lease before the public
    /// stream is committed, or refusing a forwarded request whose owner lease
    /// has lapsed.
    Lease = 9,
    /// The selected owner's own admission decision: owner-side routing,
    /// scope, credential and stream-limit checks, or an owner status the
    /// ingress observed after transport completed.
    Owner = 10,
}

impl PeerOpenDiagnosticStage {
    /// Every stage in dispatch order, for bounded diagnostics tables.
    pub const ALL: [Self; 11] = [
        Self::Validation,
        Self::PoolConnect,
        Self::StreamPermitCheckout,
        Self::SenderLock,
        Self::H3Dispatch,
        Self::EnvelopeSend,
        Self::Complete,
        Self::Head,
        Self::Body,
        Self::Lease,
        Self::Owner,
    ];

    /// The stable redacted label used in snapshots and diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Validation => "validation",
            Self::PoolConnect => "pool_connect",
            Self::StreamPermitCheckout => "stream_permit_checkout",
            Self::SenderLock => "sender_lock",
            Self::H3Dispatch => "h3_dispatch",
            Self::EnvelopeSend => "envelope_send",
            Self::Complete => "complete",
            Self::Head => "head",
            Self::Body => "body",
            Self::Lease => "lease",
            Self::Owner => "owner",
        }
    }
}

impl fmt::Display for PeerOpenDiagnosticStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A per-attempt, read-only observer for bounded peer-open diagnostics.
///
/// The observer is not shared between attempts and has no effect on
/// admission, deadlines, cancellation, or transport error classification.
#[derive(Debug)]
pub struct PeerOpenDiagnostic {
    runtime_stage: AtomicU8,
    transport: PeerOpenProgress,
}

impl PeerOpenDiagnostic {
    /// Create a fresh observer for one direct peer-open attempt.
    #[must_use]
    pub fn new() -> Self {
        Self {
            runtime_stage: AtomicU8::new(PeerOpenDiagnosticStage::Validation as u8),
            transport: PeerOpenProgress::new(),
        }
    }

    /// Return the last stage reached by this attempt.
    #[must_use]
    pub fn stage(&self) -> PeerOpenDiagnosticStage {
        match self.runtime_stage.load(Ordering::Acquire) {
            1 => PeerOpenDiagnosticStage::PoolConnect,
            2 => match self.transport.stage() {
                PeerTransportOpenStage::StreamPermitCheckout => {
                    PeerOpenDiagnosticStage::StreamPermitCheckout
                }
                PeerTransportOpenStage::SenderLock => PeerOpenDiagnosticStage::SenderLock,
                PeerTransportOpenStage::H3Dispatch => PeerOpenDiagnosticStage::H3Dispatch,
                PeerTransportOpenStage::Complete => PeerOpenDiagnosticStage::EnvelopeSend,
            },
            5 => PeerOpenDiagnosticStage::EnvelopeSend,
            6 => PeerOpenDiagnosticStage::Complete,
            7 => PeerOpenDiagnosticStage::Head,
            8 => PeerOpenDiagnosticStage::Body,
            9 => PeerOpenDiagnosticStage::Lease,
            10 => PeerOpenDiagnosticStage::Owner,
            _ => PeerOpenDiagnosticStage::Validation,
        }
    }

    /// Mark a dispatch or owner stage outside the transport open path.
    ///
    /// The transport-owned checkout/lock/dispatch stages are set by
    /// `open_with_diagnostics`; callers use this for the head, body, lease
    /// and owner stages they reach themselves.
    pub fn mark(&self, stage: PeerOpenDiagnosticStage) {
        self.set_runtime_stage(stage);
    }

    fn set_runtime_stage(&self, stage: PeerOpenDiagnosticStage) {
        self.runtime_stage.store(stage as u8, Ordering::Release);
    }

    fn transport_progress(&self) -> &PeerOpenProgress {
        &self.transport
    }
}

impl Default for PeerOpenDiagnostic {
    fn default() -> Self {
        Self::new()
    }
}

/// The owner-router and transport context installed before public admission
/// is enabled.
#[derive(Clone)]
pub struct PeerRuntime {
    client: PeerClient,
    router: Arc<OwnerRouter<dyn Catalog>>,
    bindings: Arc<dyn PeerBindingProvider>,
    source: PeerIdentity,
    readiness: Option<Arc<PeerReadiness>>,
    /// Cluster-level record budgets are shared by all request streams on one
    /// direct destination.  The transport applies an independent connection
    /// budget to the encoded HTTP/3 body.
    budgets: Arc<Mutex<HashMap<PeerDestination, ConnectionBudget>>>,
}

fn frame_consumer_unary_body(body: &[u8]) -> Result<Vec<u8>, PeerRuntimeError> {
    if body.len() > MAX_CONSUMER_UNARY_BODY {
        return Err(PeerRuntimeError::Frame(PeerFrameError::BodyTooLarge {
            kind: PeerRecordKind::ConsumerChunk,
            length: body.len(),
            maximum: MAX_CONSUMER_UNARY_BODY,
        }));
    }
    let length = u32::try_from(body.len()).map_err(|_| {
        PeerRuntimeError::Frame(PeerFrameError::BodyTooLarge {
            kind: PeerRecordKind::ConsumerChunk,
            length: body.len(),
            maximum: MAX_CONSUMER_UNARY_BODY,
        })
    })?;
    let mut framed = Vec::with_capacity(CONSUMER_RECORD_PREFIX_LEN + body.len());
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(body);
    Ok(framed)
}

#[derive(Default)]
struct ConsumerUnaryResponse {
    encoded: Vec<u8>,
    expected_total: Option<usize>,
    saw_chunk: bool,
    complete: bool,
}

impl ConsumerUnaryResponse {
    fn push(&mut self, chunk: &[u8]) -> Result<(), PeerRuntimeError> {
        if self.complete {
            return Err(PeerRuntimeError::Frame(PeerFrameError::MultipleRecords {
                count: 2,
            }));
        }
        let next_len = self
            .encoded
            .len()
            .checked_add(chunk.len())
            .ok_or(PeerRuntimeError::Closed)?;
        if next_len > MAX_CONSUMER_RESPONSE_RECORD {
            return Err(PeerRuntimeError::Frame(PeerFrameError::MultipleRecords {
                count: 2,
            }));
        }
        self.saw_chunk = true;
        self.encoded.extend_from_slice(chunk);
        if self.expected_total.is_none() && self.encoded.len() >= CONSUMER_RECORD_PREFIX_LEN {
            let declared = u32::from_be_bytes([
                self.encoded[0],
                self.encoded[1],
                self.encoded[2],
                self.encoded[3],
            ]) as usize;
            if declared > MAX_CONSUMER_RESPONSE_BODY {
                return Err(PeerRuntimeError::Frame(PeerFrameError::BodyTooLarge {
                    kind: PeerRecordKind::ConsumerChunk,
                    length: declared,
                    maximum: MAX_CONSUMER_RESPONSE_BODY,
                }));
            }
            self.expected_total = Some(CONSUMER_RECORD_PREFIX_LEN + declared);
        }
        if let Some(expected_total) = self.expected_total {
            if self.encoded.len() > expected_total {
                return Err(PeerRuntimeError::Frame(PeerFrameError::MultipleRecords {
                    count: 2,
                }));
            }
            self.complete = self.encoded.len() == expected_total;
        }
        Ok(())
    }

    fn finish(self) -> Result<Vec<u8>, PeerRuntimeError> {
        if !self.saw_chunk || self.encoded.is_empty() {
            return Err(PeerRuntimeError::Frame(PeerFrameError::NoRecord));
        }
        let Some(expected_total) = self.expected_total else {
            return Err(PeerRuntimeError::Frame(PeerFrameError::Truncated {
                expected: CONSUMER_RECORD_PREFIX_LEN,
                received: self.encoded.len(),
            }));
        };
        if self.encoded.len() < expected_total {
            return Err(PeerRuntimeError::Frame(PeerFrameError::Truncated {
                expected: expected_total,
                received: self.encoded.len(),
            }));
        }
        Ok(self.encoded[CONSUMER_RECORD_PREFIX_LEN..expected_total].to_vec())
    }
}

fn owner_not_ready_retry_after(response: &Response<()>) -> Option<u64> {
    if response.status() != StatusCode::SERVICE_UNAVAILABLE
        || response
            .headers()
            .get(PEER_ADMISSION_HEADER)
            .and_then(|value| value.to_str().ok())
            != Some(PEER_ADMISSION_OWNER_NOT_READY)
        || response
            .headers()
            .get(PEER_ERROR_EXECUTION_HEADER)
            .and_then(|value| value.to_str().ok())
            != Some("not_dispatched")
        || response
            .headers()
            .get(PEER_RETRYABLE_HEADER)
            .and_then(|value| value.to_str().ok())
            != Some("true")
    {
        return None;
    }
    let retry_after_ms = response
        .headers()
        .get(PEER_RETRY_AFTER_MS_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())?;
    (retry_after_ms > 0 && retry_after_ms <= MAX_OWNER_NOT_READY_RETRY_AFTER_MS)
        .then_some(retry_after_ms)
}

fn stream_limit_retry_after(response: &Response<()>) -> Option<u64> {
    if response.status() != StatusCode::TOO_MANY_REQUESTS
        || response
            .headers()
            .get(PEER_ADMISSION_HEADER)
            .and_then(|value| value.to_str().ok())
            != Some(PEER_ADMISSION_CAPACITY)
        || response
            .headers()
            .get(PEER_ERROR_CODE_HEADER)
            .and_then(|value| value.to_str().ok())
            != Some("STREAM_LIMIT")
        || response
            .headers()
            .get(PEER_ERROR_EXECUTION_HEADER)
            .and_then(|value| value.to_str().ok())
            != Some("not_dispatched")
        || response
            .headers()
            .get(PEER_RETRYABLE_HEADER)
            .and_then(|value| value.to_str().ok())
            != Some("true")
    {
        return None;
    }
    let retry_after_ms = response
        .headers()
        .get(PEER_RETRY_AFTER_MS_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())?;
    (retry_after_ms > 0 && retry_after_ms <= MAX_STREAM_LIMIT_RETRY_AFTER_MS)
        .then_some(retry_after_ms)
}

impl PeerRuntime {
    /// Construct a peer runtime around an already configured HTTP/3 client.
    ///
    /// The client must use the relay peer mTLS configuration.  Membership is
    /// supplied separately so Redis cannot bootstrap trust by itself.
    pub fn new(
        client: PeerClient,
        router: Arc<OwnerRouter<dyn Catalog>>,
        bindings: Arc<dyn PeerBindingProvider>,
        source_node_id: impl Into<String>,
        source_boot_id: impl Into<String>,
    ) -> Self {
        Self::new_inner(
            client,
            router,
            bindings,
            source_node_id,
            source_boot_id,
            None,
        )
    }

    /// Construct a cluster peer runtime with explicit listener, route, and
    /// capacity readiness state.  The plain [`Self::new`] constructor remains
    /// available for the single-relay M1/M2 profile and focused fixtures.
    pub fn new_with_readiness(
        client: PeerClient,
        router: Arc<OwnerRouter<dyn Catalog>>,
        bindings: Arc<dyn PeerBindingProvider>,
        source_node_id: impl Into<String>,
        source_boot_id: impl Into<String>,
        readiness: Arc<PeerReadiness>,
    ) -> Self {
        Self::new_inner(
            client,
            router,
            bindings,
            source_node_id,
            source_boot_id,
            Some(readiness),
        )
    }

    fn new_inner(
        client: PeerClient,
        router: Arc<OwnerRouter<dyn Catalog>>,
        bindings: Arc<dyn PeerBindingProvider>,
        source_node_id: impl Into<String>,
        source_boot_id: impl Into<String>,
        readiness: Option<Arc<PeerReadiness>>,
    ) -> Self {
        Self {
            client,
            router,
            bindings,
            source: PeerIdentity::new(source_node_id, source_boot_id),
            readiness,
            budgets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Build the transport adapter for the owner-side private listener.
    ///
    /// The returned handler is suitable for
    /// `PeerServer::new_with_pin_provider`.  It retains the runtime and the
    /// owner callback in `Arc`s so every transport stream can be supervised
    /// and joined by the transport server.
    pub fn server_handler<H>(self: &Arc<Self>, handler: H) -> PeerRuntimeHandler<H>
    where
        H: PeerIngressHandler,
    {
        PeerRuntimeHandler {
            runtime: Arc::clone(self),
            handler: Arc::new(handler),
        }
    }

    /// Return the policy and handler pair required by
    /// `PeerServer::new_with_pin_provider`.
    ///
    /// Root startup owns the QUIC endpoint, dynamic approved-pin snapshot,
    /// transport limits, and shutdown token.  Keeping those inputs outside
    /// this crate avoids a second endpoint or trust-store owner while still
    /// making the application ingress adapter a single typed value.
    pub fn server_components<H>(
        self: &Arc<Self>,
        handler: H,
    ) -> (impl PeerRequestPolicy, PeerRuntimeHandler<H>)
    where
        H: PeerIngressHandler,
    {
        (Self::server_policy(), self.server_handler(handler))
    }

    /// Return the current bounded admission state supplied by the membership
    /// provider. This is deliberately a boolean so health output cannot leak
    /// backend errors, endpoints, membership records, or key pins.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.bindings.is_ready()
            && self
                .readiness
                .as_ref()
                .is_none_or(|readiness| readiness.is_ready())
    }

    /// Return the optional process-local peer readiness state.
    #[must_use]
    pub fn peer_readiness(&self) -> Option<Arc<PeerReadiness>> {
        self.readiness.clone()
    }

    /// Return bounded, redacted transport-pool counters for fixture
    /// diagnostics.  This is observational and cannot change admission.
    pub async fn peer_pool_stats(&self) -> tunnel_transport::PeerPoolStats {
        self.client.pool_stats().await
    }

    /// Reconcile the pooled transport against the current dynamic SPKI set.
    ///
    /// Pin watchers already close revoked certificates asynchronously; this
    /// joined pass gives membership refresh a bounded cleanup point for those
    /// connections. Same-pin membership record/deadline changes are handled by
    /// the per-admission cancellation edge carried by each exchange.
    pub async fn refresh_peer_pins(&self) -> Result<(), PeerRuntimeError> {
        self.client
            .refresh_pins()
            .await
            .map(|_| ())
            .map_err(Into::into)
    }

    /// Return the redacted pool counters for a selected remote owner route.
    ///
    /// This is fixture diagnostics only: it correlates the route under test
    /// with its pooled connection without exposing destination addresses or
    /// TLS names and cannot change admission.
    pub async fn route_pool_stats(
        &self,
        route: &OwnerRoute,
    ) -> Option<tunnel_transport::PeerPoolConnectionStats> {
        let OwnerRoute::Remote {
            peer: Some(binding),
            ..
        } = route
        else {
            return None;
        };
        let destination = peer_destination(binding).ok()?;
        self.client.pool_stats_for(&destination).await
    }

    /// Update the private listener state after the deployment boundary has
    /// successfully bound or begun draining the QUIC endpoint.
    pub fn set_peer_listener_state(&self, state: PeerListenerState) {
        if let Some(readiness) = &self.readiness {
            readiness.set_listener_state(state);
        }
    }

    /// Publish a bounded observation of available peer transport capacity.
    pub fn set_peer_capacity(&self, available: usize) {
        if let Some(readiness) = &self.readiness {
            readiness.set_available_capacity(available);
        }
    }

    /// Withdraw peer readiness because this relay's own cluster prerequisites
    /// are not currently satisfied.
    ///
    /// Reachability and capacity evidence is dropped and the route revision is
    /// fenced, so `/readyz` and public admission fail closed immediately. The
    /// verified route and pin set stays installed: it is this relay's signed
    /// evidence of which peer certificates are approved, and it is what lets
    /// an authenticated peer's bounded reachability probe still be answered
    /// while this relay is unready. Discarding it instead couples each
    /// relay's readiness to the other's, which cannot converge.
    pub fn withdraw_peer_readiness(&self) {
        if let Some(readiness) = &self.readiness {
            readiness.reset_route_probes();
        }
    }

    /// Withdraw peer readiness and the verified route set together, because no
    /// current signed peer key material could be published at all. Without
    /// approved pins there is no trust evidence to admit any peer, so probe
    /// admission must fail closed as well.
    pub fn withdraw_peer_trust(&self) {
        if let Some(readiness) = &self.readiness {
            readiness.clear_available_capacity();
            let _ = readiness.replace_required_routes(std::iter::empty::<PeerRouteTarget>());
        }
    }

    /// Replace the required route set from current verified membership and
    /// probe it with bounded authenticated mTLS connections.  A failure is
    /// retained in readiness even when this method returns the first typed
    /// error, so health and public admission fail closed together.
    pub async fn refresh_required_routes(
        &self,
        targets: Vec<PeerRouteTarget>,
    ) -> Result<(), PeerRuntimeError> {
        let Some(readiness) = self.readiness.clone() else {
            return Err(PeerRuntimeError::Membership(
                "peer readiness is not configured".to_owned(),
            ));
        };
        let revision = readiness
            .replace_required_routes_with_revision(targets.clone())
            .map_err(peer_readiness_error)?;

        let mut probes = stream::iter(targets.into_iter().map(|target| async move {
            let result = self.probe_route(&target).await;
            (target, result)
        }))
        .buffer_unordered(MAX_CONCURRENT_PEER_PROBES);
        let mut first_error = None;
        while let Some((target, result)) = probes.next().await {
            match result {
                Ok(()) => {
                    let _published = readiness
                        .record_probe_at(revision, &target, PeerProbeState::Reachable)
                        .map_err(peer_readiness_error)?;
                    // A successful health stream proves one slot for this
                    // route only; stale results are deliberately ignored.
                }
                Err(error) => {
                    let probe_state = if matches!(
                        &error,
                        PeerRuntimeError::Transport(PeerTransportError::Capacity)
                    ) {
                        PeerProbeState::CapacityExhausted
                    } else {
                        PeerProbeState::Unreachable
                    };
                    // Keep the publication fence: an older refresh must not
                    // overwrite a newer route revision.  Its transport
                    // outcome still belongs to this caller, though.  Dropping
                    // a stale Capacity error here turns an overlapping
                    // refresh into a false Ok(()) and hides the real probe
                    // failure from readiness reconciliation.
                    let _published = readiness
                        .record_probe_at(revision, &target, probe_state)
                        .map_err(peer_readiness_error)?;
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn probe_route(&self, target: &PeerRouteTarget) -> Result<(), PeerRuntimeError> {
        self.probe_route_with_deadline(target, PEER_PROBE_TIMEOUT)
            .await
    }

    async fn probe_route_with_deadline(
        &self,
        target: &PeerRouteTarget,
        deadline: Duration,
    ) -> Result<(), PeerRuntimeError> {
        let expires_at = TokioInstant::now() + deadline;
        // A failed health stream is reachability evidence, not authority to
        // cancel unrelated admitted requests on its pooled connection.
        // QUIC closure and explicit identity/pin invalidation still retire
        // unusable connections through their existing lifecycle paths.
        self.probe_route_until(target, expires_at).await
    }

    async fn probe_route_until(
        &self,
        target: &PeerRouteTarget,
        expires_at: TokioInstant,
    ) -> Result<(), PeerRuntimeError> {
        let address = target
            .peer_endpoint()
            .parse::<SocketAddr>()
            .map_err(|error| PeerRuntimeError::InvalidEndpoint(error.to_string()))?;
        let destination = PeerDestination::new(address, target.server_name());
        let connection = timeout_at(expires_at, self.client.connect(destination))
            .await
            .map_err(|_| PeerRuntimeError::Transport(PeerTransportError::Timeout))??;
        let identity = connection.peer_identity();
        let observed_spki = identity.spki_sha256().to_hex();
        if !identity.role().is_peer()
            || identity.role_id() != target.node_id()
            || !target
                .approved_spki_sha256()
                .iter()
                .any(|pin| pin == &observed_spki)
        {
            let _ = timeout_at(expires_at, connection.shutdown()).await;
            return Err(PeerRuntimeError::PeerIdentityMismatch);
        }
        // A cached QUIC connection is not itself a reachability proof.  Open
        // the reserved authenticated health route so HTTP/3 stream capacity,
        // request dispatch, and the response path are exercised as one
        // bounded round trip.  The probe carries no application payload.
        let request = Request::builder()
            .method(axum::http::Method::GET)
            .uri(format!("https://{}{HEALTH_PATH}", target.server_name()))
            .body(())
            .map_err(|_| PeerRuntimeError::Closed)?;
        let mut stream = connection.open_until(request, expires_at).await?;
        timeout_at(expires_at, stream.finish())
            .await
            .map_err(|_| PeerRuntimeError::Transport(PeerTransportError::Timeout))??;
        let response = timeout_at(expires_at, stream.recv_response())
            .await
            .map_err(|_| PeerRuntimeError::Transport(PeerTransportError::Timeout))??;
        if !response.status().is_success() {
            return Err(PeerRuntimeError::RemoteStatus(response.status()));
        }
        match timeout_at(expires_at, stream.recv_chunk())
            .await
            .map_err(|_| PeerRuntimeError::Transport(PeerTransportError::Timeout))??
        {
            None => Ok(()),
            Some(_) => {
                // A readiness probe has no application body.  Stop at the
                // first unexpected chunk rather than draining an unbounded or
                // periodically-fed response body.
                stream.cancel();
                Err(PeerRuntimeError::Closed)
            }
        }
    }

    async fn accept_probe(
        &self,
        identity: TlsIdentity,
        request: Request<()>,
        stream: PeerServerStream,
    ) -> Result<(), PeerRuntimeError> {
        tokio::time::timeout(
            PEER_PROBE_TIMEOUT,
            self.accept_probe_until(identity, request, stream),
        )
        .await
        .map_err(|_| PeerRuntimeError::Transport(PeerTransportError::Timeout))?
    }

    async fn accept_probe_until(
        &self,
        identity: TlsIdentity,
        request: Request<()>,
        stream: PeerServerStream,
    ) -> Result<(), PeerRuntimeError> {
        // Probe admission deliberately does not consult this relay's own
        // cluster readiness. `GET /internal/v1/health` is "Authenticated
        // version/readiness metadata, bounded response": a route whose purpose
        // is to report readiness cannot require the responder to already be
        // ready. Requiring it makes the two relays' readiness mutually
        // dependent, so a relay booting next to a flapping peer can never
        // converge, and it makes "peer starting" indistinguishable from "peer
        // unreachable" to the prober.
        //
        // Every fail-closed check still applies: the transport has already
        // completed mTLS against the approved pin set, and the caller must be
        // an authenticated relay-role certificate whose node identifier and
        // SPKI digest match one of the currently verified signed route
        // targets. The exchange allocates one bounded stream, carries no
        // application payload, and grants no owner, ticket, or dispatch state,
        // so it is not a way to bypass admission.
        if !identity.role().is_peer()
            || self.readiness.as_ref().is_none_or(|readiness| {
                !readiness.accepts_probe(identity.role_id(), &identity.spki_sha256().to_hex())
            })
        {
            return Err(PeerRuntimeError::Membership(
                "peer probe admission rejected".to_owned(),
            ));
        }
        if request.method() != axum::http::Method::GET
            || request.uri().path() != HEALTH_PATH
            || request.uri().query().is_some()
        {
            return Err(PeerRuntimeError::Closed);
        }
        let (mut send, mut recv) = stream.split();
        match recv.recv_chunk().await? {
            None => {}
            Some(_) => {
                recv.cancel();
                send.cancel();
                return Err(PeerRuntimeError::Closed);
            }
        }
        send.send_response(Response::new(())).await?;
        send.finish().await.map_err(Into::into)
    }

    /// Cancel and join all outbound HTTP/3 client connection drivers owned by
    /// this runtime.  The relay supervisor calls this after the inbound peer
    /// server and public listeners have stopped accepting work.
    pub async fn shutdown(&self) -> Result<(), PeerRuntimeError> {
        if let Some(readiness) = &self.readiness {
            readiness.set_listener_state(PeerListenerState::Draining);
            readiness.clear_available_capacity();
        }
        self.client.shutdown().await.map_err(Into::into)
    }

    /// Return the synchronous pre-body policy for the private listener.
    ///
    /// It checks the authenticated role, method, query shape, and fixed route
    /// set.  Exact node/boot/SPKI membership and deadline checks happen in
    /// [`Self::accept_inbound`] immediately after the first charged envelope
    /// record is decoded.
    pub fn server_policy() -> impl PeerRequestPolicy {
        |identity: &TlsIdentity, request: &Request<()>| {
            identity.role().is_peer()
                && request.uri().query().is_none()
                && ((request.method() == axum::http::Method::GET
                    && request.uri().path() == HEALTH_PATH)
                    || (request.method() == axum::http::Method::POST
                        && matches!(
                            request.uri().path(),
                            DEVICE_CONTROL_PATH
                                | DEVICE_DATA_PATH
                                | CONSUMER_STREAMS_PATH
                                | OPERATION_STATUS_PATH
                                | HEALTH_PATH
                        )))
        }
    }

    /// Return the source identity placed into internal envelopes.
    #[must_use]
    pub fn source(&self) -> &PeerIdentity {
        &self.source
    }

    /// Resolve a current owner and obtain a verified peer binding before any
    /// remote connection is attempted.
    pub async fn resolve(
        &self,
        scope: OwnerScope,
        now: DateTime<Utc>,
    ) -> Result<OwnerRoute, PeerRuntimeError> {
        let route = self.router.resolve(scope, now, None).await?;
        let OwnerRoute::Remote { owner, .. } = &route else {
            return Ok(route);
        };
        let binding = self
            .bindings
            .binding(&owner.token.node_id, &owner.token.boot_id, now)
            .await?;
        if binding.valid_until() <= now
            || binding.node_id() != owner.token.node_id
            || binding.boot_id() != owner.token.boot_id
        {
            return Err(PeerRuntimeError::PeerIdentityMismatch);
        }
        // Re-run the router with the binding.  This also prevents a cached
        // remote owner from being used without current signed trust evidence.
        self.router
            .resolve(scope, now, Some(&binding))
            .await
            .map_err(Into::into)
    }

    /// Open one direct, one-hop request to the selected remote owner.
    pub async fn open(
        &self,
        route: &OwnerRoute,
        envelope: RequestEnvelope,
    ) -> Result<PeerExchange, PeerRuntimeError> {
        self.open_inner(route, envelope, None, None).await
    }

    /// Open one request through the ordinary validation/readiness path while
    /// optionally holding immediately before pooled HTTP/3 admission. The
    /// barrier is a fixture-only seam; all runtime checks remain in
    /// `open_inner`.
    pub(crate) async fn open_with_admission_barrier(
        &self,
        route: &OwnerRoute,
        envelope: RequestEnvelope,
        barrier: &PeerAdmissionBarrier,
        scope: PeerAdmissionScope,
        budget: Duration,
        diagnostic: Option<&PeerOpenDiagnostic>,
    ) -> Result<PeerExchange, PeerRuntimeError> {
        self.open_inner(route, envelope, diagnostic, Some((barrier, scope, budget)))
            .await
    }

    /// Open one direct request while recording bounded per-attempt progress.
    ///
    /// The observer is scoped to this call and does not alter admission,
    /// deadlines, cancellation, or transport error classification.
    pub async fn open_with_diagnostics(
        &self,
        route: &OwnerRoute,
        envelope: RequestEnvelope,
        diagnostic: &PeerOpenDiagnostic,
    ) -> Result<PeerExchange, PeerRuntimeError> {
        self.open_inner(route, envelope, Some(diagnostic), None)
            .await
    }

    async fn open_inner(
        &self,
        route: &OwnerRoute,
        envelope: RequestEnvelope,
        diagnostic: Option<&PeerOpenDiagnostic>,
        admission_barrier: Option<(&PeerAdmissionBarrier, PeerAdmissionScope, Duration)>,
    ) -> Result<PeerExchange, PeerRuntimeError> {
        if let Some(diagnostic) = diagnostic {
            diagnostic.set_runtime_stage(PeerOpenDiagnosticStage::Validation);
        }
        if self.readiness.as_ref().is_some_and(|_| !self.is_ready()) {
            return Err(PeerRuntimeError::Membership(
                "peer route readiness is unavailable".to_owned(),
            ));
        }
        let OwnerRoute::Remote { owner, peer } = route else {
            return Err(PeerRuntimeError::InvalidRoute(envelope.route));
        };
        let binding = peer
            .as_ref()
            .ok_or(PeerRuntimeError::PeerIdentityMismatch)?;
        if binding.node_id() != owner.token.node_id
            || binding.boot_id() != owner.token.boot_id
            || binding.valid_until() <= Utc::now()
        {
            return Err(PeerRuntimeError::PeerIdentityMismatch);
        }
        if envelope.source != self.source
            || envelope.destination.owner_token != owner.token
            || envelope.hop_budget != tunnel_cluster::envelope::REQUIRED_HOP_BUDGET
        {
            return Err(PeerRuntimeError::PeerIdentityMismatch);
        }
        let destination = peer_destination(binding)?;
        if let Some((barrier, scope, budget)) = admission_barrier {
            barrier
                .wait_before_peer_admission(scope, budget)
                .await
                .map(|_| ())
                .map_err(|_| PeerRuntimeError::Closed)?;
        }
        let request = Request::builder()
            .method(PEER_METHOD)
            .uri(format!(
                "https://{}{route}",
                binding.server_name(),
                route = route_path(envelope.route)
            ))
            .header("content-type", "application/octet-stream")
            .body(())
            .map_err(|_| PeerRuntimeError::Closed)?;
        let readiness_target = PeerRouteTarget::from_verified_binding(binding);
        if let Some(diagnostic) = diagnostic {
            diagnostic.set_runtime_stage(PeerOpenDiagnosticStage::PoolConnect);
        }
        let connection = match self.client.connect(destination.clone()).await {
            Ok(connection) => connection,
            Err(error) => {
                if let Some(readiness) = &self.readiness {
                    readiness.mark_route_unreachable(&readiness_target);
                }
                return Err(error.into());
            }
        };
        let identity = connection.peer_identity();
        // `binding` was selected before the handshake only to obtain the
        // signed endpoint/server name and exact node/boot route.  A signed
        // membership may contain more than one currently valid SPKI during
        // certificate overlap, so the preselected pin is not an identity
        // assertion.  The completed mTLS SPKI is validated immediately below
        // by `binding_for_certificate`, which also rechecks the signed
        // endpoint and trust deadline.
        if !identity.role().is_peer() || identity.role_id() != binding.node_id() {
            let _ = connection.shutdown().await;
            if let Some(readiness) = &self.readiness {
                readiness.mark_route_unreachable(&readiness_target);
            }
            return Err(PeerRuntimeError::PeerIdentityMismatch);
        }
        let observed_spki = identity.spki_sha256().to_hex();
        let fresh_binding = match self
            .bindings
            .binding_for_certificate(
                binding.node_id(),
                binding.boot_id(),
                &observed_spki,
                Utc::now(),
            )
            .await
        {
            Ok(binding) => binding,
            Err(error) => {
                let _ = connection.shutdown().await;
                return Err(error);
            }
        };
        if fresh_binding.node_id() != binding.node_id()
            || fresh_binding.boot_id() != binding.boot_id()
            || fresh_binding.spki_sha256() != observed_spki
            || fresh_binding.peer_endpoint() != binding.peer_endpoint()
            || fresh_binding.server_name() != binding.server_name()
            || fresh_binding.valid_until() <= Utc::now()
        {
            let _ = connection.shutdown().await;
            if let Some(readiness) = &self.readiness {
                readiness.mark_route_unreachable(&readiness_target);
            }
            return Err(PeerRuntimeError::PeerIdentityMismatch);
        }
        // Keep the process-local membership admission attached to this
        // request.  The binding check above proves the current certificate;
        // this second edge is what lets a later signed revocation, key expiry,
        // or checkpoint expiry interrupt a stream opened on a pooled H3
        // connection.  Operation/owner/device deadlines remain independent.
        let admission_cancellation = match self
            .bindings
            .admission_cancellation(
                binding.node_id(),
                binding.boot_id(),
                &observed_spki,
                Utc::now(),
            )
            .await
        {
            Ok(cancellation) => cancellation,
            Err(error) => {
                // Do not leave a pooled connection alive when its current
                // membership admission cannot be attached to this stream.
                let _ = connection.shutdown().await;
                return Err(error);
            }
        };
        if let Some(diagnostic) = diagnostic {
            diagnostic.set_runtime_stage(PeerOpenDiagnosticStage::StreamPermitCheckout);
        }
        // Keep the already authenticated admission edge live through stream
        // checkout/setup.  A revocation racing a permit or H3 dispatch must
        // cancel this attempt before the request can be admitted; the
        // transport's own shared checkout deadline still bounds every wait.
        let stream_open = async {
            match diagnostic {
                Some(diagnostic) => {
                    connection
                        .open_with_progress(request, diagnostic.transport_progress())
                        .await
                }
                None => connection.open(request).await,
            }
        };
        let stream_result = match admission_cancellation.as_ref() {
            Some(admission_cancellation) => tokio::select! {
                biased;
                _ = admission_cancellation.cancelled() => {
                    Err(admission_cancellation_error(Some(admission_cancellation)))
                },
                result = stream_open => result.map_err(Into::into),
            },
            None => stream_open.await.map_err(Into::into),
        };
        let stream = match stream_result {
            Ok(stream) => stream,
            Err(error) => {
                if let Some(readiness) = &self.readiness {
                    readiness.mark_route_unreachable(&readiness_target);
                }
                return Err(error);
            }
        };
        if let Some(diagnostic) = diagnostic {
            diagnostic.set_runtime_stage(PeerOpenDiagnosticStage::EnvelopeSend);
        }
        let budget = {
            let mut budgets = self.budgets.lock().await;
            if budgets.len() >= tunnel_transport::DEFAULT_PEER_DESTINATIONS
                && !budgets.contains_key(&destination)
                && let Some(evicted) = budgets.keys().next().cloned()
            {
                budgets.remove(&evicted);
            }
            budgets
                .entry(destination)
                .or_insert_with(ConnectionBudget::new)
                .clone()
        };
        // A stream that raced the peer's GOAWAY may still be refused after it
        // was opened; the hook withdraws this route's readiness on that typed
        // outcome exactly as an open-time failure does above.
        let route_hook = self.readiness.as_ref().map(|readiness| {
            Arc::new(RouteUnreachableHook {
                readiness: Arc::clone(readiness),
                target: readiness_target.clone(),
            })
        });
        let exchange =
            PeerExchange::new(stream, envelope, budget, admission_cancellation, route_hook).await?;
        if let Some(diagnostic) = diagnostic {
            diagnostic.set_runtime_stage(PeerOpenDiagnosticStage::Complete);
        }
        Ok(exchange)
    }

    /// Forward one bounded consumer request and collect its bounded response.
    ///
    /// The owner independently validates the bearer in the envelope before
    /// dispatch.  This helper is intentionally limited to one request body;
    /// long-lived consumer WebSockets use [`PeerExchange`] directly so both
    /// directions remain concurrent.
    pub async fn forward_unary(
        &self,
        route: &OwnerRoute,
        envelope: RequestEnvelope,
        body: &[u8],
    ) -> Result<Vec<u8>, PeerRuntimeError> {
        self.forward_unary_inner(route, envelope, body, None).await
    }

    /// Forward one bounded consumer request while recording the head and
    /// body stages on the caller's observer in addition to the open stages.
    pub async fn forward_unary_with_diagnostics(
        &self,
        route: &OwnerRoute,
        envelope: RequestEnvelope,
        body: &[u8],
        diagnostic: &PeerOpenDiagnostic,
    ) -> Result<Vec<u8>, PeerRuntimeError> {
        self.forward_unary_inner(route, envelope, body, Some(diagnostic))
            .await
    }

    async fn forward_unary_inner(
        &self,
        route: &OwnerRoute,
        envelope: RequestEnvelope,
        body: &[u8],
        diagnostic: Option<&PeerOpenDiagnostic>,
    ) -> Result<Vec<u8>, PeerRuntimeError> {
        let framed_body = frame_consumer_unary_body(body)?;
        let exchange = self.open_inner(route, envelope, diagnostic, None).await?;
        let (mut send, mut recv) = exchange.split();
        if let Some(diagnostic) = diagnostic {
            diagnostic.mark(PeerOpenDiagnosticStage::Head);
        }
        // The owner sends response headers before it consumes the request
        // body.  Accept them first so a committed-but-not-ready owner can
        // return its bounded retry classification without receiving any
        // application bytes.
        recv.accept_response().await?;
        if let Some(diagnostic) = diagnostic {
            diagnostic.mark(PeerOpenDiagnosticStage::Body);
        }
        for chunk in framed_body.chunks(tunnel_cluster::peer_frame::MAX_CONSUMER_CHUNK_BODY) {
            send.send_message(PeerRecordKind::ConsumerChunk, chunk)
                .await?;
        }
        send.finish().await?;
        let mut response = ConsumerUnaryResponse::default();
        while let Some(record) = recv.recv_message().await? {
            if record.kind() != PeerRecordKind::ConsumerChunk {
                return Err(PeerRuntimeError::UnexpectedRecord(record.kind()));
            }
            response.push(record.body())?;
        }
        response.finish()
    }

    /// Parse and authenticate the first envelope on an incoming peer stream.
    ///
    /// The owner callback must still resolve the current owner and call
    /// [`RequestEnvelope::validate`] with an authoritative destination and,
    /// for consumers, a freshly validated JWT/catalog access token.
    pub async fn accept_inbound(
        &self,
        identity: TlsIdentity,
        request: Request<()>,
        stream: PeerServerStream,
    ) -> Result<InboundPeerRequest, PeerRuntimeError> {
        if request.method() != axum::http::Method::POST || request.uri().query().is_some() {
            return Err(PeerRuntimeError::Closed);
        }
        let expected_path = request.uri().path();
        let (mut send, mut recv) = stream.split();
        let connection_budget = ConnectionBudget::new();
        let stream_budget = connection_budget
            .open_stream()
            .map_err(PeerFrameError::from)?;
        let mut decoder = PeerRecordDecoder::new(stream_budget.clone());
        let mut pending = VecDeque::new();
        let envelope_record = loop {
            let Some(chunk) = recv.recv_chunk().await? else {
                return Err(PeerRuntimeError::Closed);
            };
            let records = decoder.push(chunk.as_bytes())?;
            if !records.is_empty() {
                pending.extend(records);
                break pending.pop_front().expect("non-empty record queue");
            }
        };
        if envelope_record.kind() != PeerRecordKind::CompleteControlText {
            return Err(PeerRuntimeError::UnexpectedRecord(envelope_record.kind()));
        }
        if envelope_record.body_len() > MAX_ENVELOPE_RECORD {
            return Err(PeerRuntimeError::Closed);
        }
        let envelope = decode_envelope(envelope_record.body())?;
        if route_path(envelope.route) != expected_path {
            return Err(PeerRuntimeError::InvalidRoute(envelope.route));
        }
        if !identity.role().is_peer() || identity.role_id() != envelope.source.node_id {
            return Err(PeerRuntimeError::PeerIdentityMismatch);
        }
        let observed_spki = identity.spki_sha256().to_hex();
        let binding = match self
            .bindings
            .binding_for_certificate(
                &envelope.source.node_id,
                &envelope.source.boot_id,
                &observed_spki,
                Utc::now(),
            )
            .await
        {
            Ok(binding) => binding,
            Err(error) => {
                send.cancel();
                recv.cancel();
                return Err(error);
            }
        };
        if binding.node_id() != identity.role_id()
            || binding.boot_id() != envelope.source.boot_id
            || binding.spki_sha256() != observed_spki
            || binding.valid_until() <= Utc::now()
        {
            return Err(PeerRuntimeError::PeerIdentityMismatch);
        }
        // Admission is deliberately acquired after the envelope and mTLS
        // identity have been matched.  It is a cancellation edge for this
        // forwarded stream, not a replacement for the independent owner,
        // authorization, or certificate-expiry checks in the handler.
        let admission_cancellation = match self
            .bindings
            .admission_cancellation(
                &envelope.source.node_id,
                &envelope.source.boot_id,
                &observed_spki,
                Utc::now(),
            )
            .await
        {
            Ok(cancellation) => cancellation,
            Err(error) => {
                send.cancel();
                recv.cancel();
                return Err(error);
            }
        };
        Ok(InboundPeerRequest {
            identity,
            request,
            envelope,
            binding,
            send,
            recv,
            decoder,
            pending,
            admission_cancellation,
            _connection_budget: connection_budget,
            _envelope_record: envelope_record,
        })
    }

    /// Return the private HTTP/3 path for a typed route.
    #[must_use]
    pub const fn path(route: InternalRoute) -> &'static str {
        route_path(route)
    }
}

/// Withdraws a selected route's readiness when a request on it observes the
/// peer's typed graceful-close outcome after the stream was already opened.
///
/// `open_inner` withdraws readiness for open-time failures itself; a stream
/// that raced the peer's GOAWAY can still be refused with `H3_REQUEST_REJECTED`
/// at the envelope-send or response boundary, and that peer is equally not a
/// viable route until it is re-probed.  The hook carries only the bounded route
/// target already validated for this request.
struct RouteUnreachableHook {
    readiness: Arc<PeerReadiness>,
    target: PeerRouteTarget,
}

impl RouteUnreachableHook {
    fn observe(&self, error: &PeerRuntimeError) {
        if matches!(
            error,
            PeerRuntimeError::Transport(PeerTransportError::GoAway)
        ) {
            self.readiness.mark_route_unreachable(&self.target);
        }
    }
}

fn observe_route_error(hook: Option<&Arc<RouteUnreachableHook>>, error: &PeerRuntimeError) {
    if let Some(hook) = hook {
        hook.observe(error);
    }
}

/// A live direct peer request after the initial envelope has been sent.
pub struct PeerExchange {
    send: PeerClientSend,
    recv: PeerClientRecv,
    budget: StreamBudget,
    admission_cancellation: Option<CancellationToken>,
    admission_context: Option<PeerAdmissionCancellation>,
    route_hook: Option<Arc<RouteUnreachableHook>>,
}

impl PeerExchange {
    async fn new(
        stream: PeerClientStream,
        envelope: RequestEnvelope,
        connection_budget: ConnectionBudget,
        admission_context: Option<PeerAdmissionCancellation>,
        route_hook: Option<Arc<RouteUnreachableHook>>,
    ) -> Result<Self, PeerRuntimeError> {
        let (mut send, recv) = stream.split();
        let budget = connection_budget
            .open_stream()
            .map_err(PeerFrameError::from)?;
        let admission_cancellation = admission_context
            .as_ref()
            .map(PeerAdmissionCancellation::token);
        let bytes = envelope.encode()?;
        if bytes.len() > MAX_ENVELOPE_RECORD {
            return Err(PeerRuntimeError::Envelope(
                tunnel_cluster::envelope::EnvelopeError::MessageTooLarge {
                    length: bytes.len(),
                    maximum: MAX_ENVELOPE_RECORD,
                },
            ));
        }
        let record = budget.record_from_slice(PeerRecordKind::CompleteControlText, &bytes)?;
        if let Err(error) =
            send_record(&mut send, &budget, record, admission_context.as_ref()).await
        {
            observe_route_error(route_hook.as_ref(), &error);
            return Err(error);
        }
        Ok(Self {
            send,
            recv,
            budget,
            admission_cancellation,
            admission_context,
            route_hook,
        })
    }

    /// Split request sending and response receiving for concurrent WebSocket
    /// pumps.  Both halves retain the same bounded stream budget.
    #[must_use]
    pub fn split(self) -> (PeerExchangeSend, PeerExchangeRecv) {
        let Self {
            send,
            recv,
            budget,
            admission_cancellation,
            admission_context,
            route_hook,
        } = self;
        (
            PeerExchangeSend {
                send,
                budget: budget.clone(),
                admission_context: admission_context.clone(),
                route_hook: route_hook.clone(),
            },
            PeerExchangeRecv {
                recv,
                decoder: PeerRecordDecoder::new(budget.clone()),
                pending: VecDeque::new(),
                response_seen: false,
                budget,
                admission_cancellation,
                admission_context,
                route_hook,
            },
        )
    }

    /// Cancel both directions of this request.
    pub fn cancel(&mut self) {
        self.send.cancel();
        self.recv.cancel();
    }
}

/// Request half of a live peer exchange.
pub struct PeerExchangeSend {
    send: PeerClientSend,
    budget: StreamBudget,
    admission_context: Option<PeerAdmissionCancellation>,
    route_hook: Option<Arc<RouteUnreachableHook>>,
}

impl PeerExchangeSend {
    /// Forward one complete WebSocket message while retaining its charge
    /// through the transport send.
    pub async fn send_message(
        &mut self,
        kind: PeerRecordKind,
        body: &[u8],
    ) -> Result<(), PeerRuntimeError> {
        let record = self.budget.record_from_slice(kind, body)?;
        let result = send_record(
            &mut self.send,
            &self.budget,
            record,
            self.admission_context.as_ref(),
        )
        .await;
        if let Err(error) = &result {
            observe_route_error(self.route_hook.as_ref(), error);
        }
        result
    }

    /// Finish the request direction.
    pub async fn finish(&mut self) -> Result<(), PeerRuntimeError> {
        let result = finish_client_send(&mut self.send, self.admission_context.as_ref()).await;
        if let Err(error) = &result {
            observe_route_error(self.route_hook.as_ref(), error);
        }
        result
    }

    /// Cancel the request direction.
    pub fn cancel(&mut self) {
        self.send.cancel();
    }
}

/// Response half of a live peer exchange.
pub struct PeerExchangeRecv {
    recv: PeerClientRecv,
    decoder: PeerRecordDecoder,
    pending: VecDeque<PeerRecord>,
    response_seen: bool,
    budget: StreamBudget,
    admission_cancellation: Option<CancellationToken>,
    admission_context: Option<PeerAdmissionCancellation>,
    route_hook: Option<Arc<RouteUnreachableHook>>,
}

impl PeerExchangeRecv {
    /// Accept the owner's response headers before reading records.
    pub async fn accept_response(&mut self) -> Result<Response<()>, PeerRuntimeError> {
        let response =
            match recv_client_response(&mut self.recv, self.admission_context.as_ref()).await {
                Ok(response) => response,
                Err(error) => {
                    observe_route_error(self.route_hook.as_ref(), &error);
                    return Err(error);
                }
            };
        if !response.status().is_success() {
            if let Some(retry_after_ms) = owner_not_ready_retry_after(&response) {
                return Err(PeerRuntimeError::OwnerNotReady { retry_after_ms });
            }
            if let Some(retry_after_ms) = stream_limit_retry_after(&response) {
                return Err(PeerRuntimeError::Capacity { retry_after_ms });
            }
            return Err(PeerRuntimeError::RemoteStatus(response.status()));
        }
        self.response_seen = true;
        Ok(response)
    }

    /// Receive one complete peer record, preserving WebSocket message
    /// boundaries across arbitrary HTTP/3 body chunking.
    pub async fn recv_message(&mut self) -> Result<Option<PeerRecord>, PeerRuntimeError> {
        if self
            .admission_cancellation
            .as_ref()
            .is_some_and(|token| token.is_cancelled())
        {
            self.recv.cancel();
            return Err(admission_cancellation_error(
                self.admission_context.as_ref(),
            ));
        }
        if !self.response_seen {
            self.accept_response().await?;
        }
        loop {
            if let Some(record) = self.pending.pop_front() {
                if self
                    .admission_cancellation
                    .as_ref()
                    .is_some_and(|token| token.is_cancelled())
                {
                    self.recv.cancel();
                    return Err(admission_cancellation_error(
                        self.admission_context.as_ref(),
                    ));
                }
                return Ok(Some(record));
            }
            let chunk =
                match recv_client_chunk(&mut self.recv, self.admission_context.as_ref()).await {
                    Ok(chunk) => chunk,
                    Err(error) => {
                        observe_route_error(self.route_hook.as_ref(), &error);
                        return Err(error);
                    }
                };
            let Some(chunk) = chunk else {
                self.decoder.finish()?;
                return Ok(None);
            };
            self.pending.extend(self.decoder.push(chunk.as_bytes())?);
        }
    }

    /// Cancel the response direction.
    pub fn cancel(&mut self) {
        self.recv.cancel();
    }

    /// Return bounded diagnostics for this exchange.
    #[must_use]
    pub fn reserved_bytes(&self) -> usize {
        self.budget.reserved_bytes()
    }
}

/// An incoming peer request after its source mTLS identity, signed binding,
/// route path, and first charged envelope record have been checked.
pub struct InboundPeerRequest {
    identity: TlsIdentity,
    request: Request<()>,
    envelope: RequestEnvelope,
    binding: VerifiedPeerBinding,
    send: PeerServerSend,
    recv: PeerServerRecv,
    decoder: PeerRecordDecoder,
    pending: VecDeque<PeerRecord>,
    admission_cancellation: Option<PeerAdmissionCancellation>,
    _connection_budget: ConnectionBudget,
    _envelope_record: PeerRecord,
}

impl InboundPeerRequest {
    pub(crate) fn admission_cancellation_context(&self) -> Option<PeerAdmissionCancellation> {
        self.admission_cancellation.clone()
    }

    /// Return the authenticated peer certificate metadata.
    #[must_use]
    pub fn identity(&self) -> &TlsIdentity {
        &self.identity
    }

    /// Return the verified signed membership binding.
    #[must_use]
    pub fn binding(&self) -> &VerifiedPeerBinding {
        &self.binding
    }

    /// Return the decoded request envelope.  The owner must still revalidate
    /// its destination, grant, and consumer JWT before dispatch.
    #[must_use]
    pub fn envelope(&self) -> &RequestEnvelope {
        &self.envelope
    }

    /// Return the request URI checked against the typed envelope route.
    #[must_use]
    pub fn request(&self) -> &Request<()> {
        &self.request
    }

    /// Reject a request whose authenticated owner is present but has not yet
    /// completed its data-carrier/owner-fence admission.  The request body is
    /// cancelled before response headers are sent, so the peer cannot submit
    /// application bytes before the owner becomes ready.  The response uses
    /// private authenticated headers rather than a body because the caller
    /// has not entered the owner stream yet.
    pub async fn reject_owner_not_ready(self) -> Result<(), PeerRuntimeError> {
        let (mut send, mut recv) = self.split();
        recv.cancel();
        let response = Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("content-type", "application/octet-stream")
            .header(PEER_ADMISSION_HEADER, PEER_ADMISSION_OWNER_NOT_READY)
            .header(PEER_ERROR_EXECUTION_HEADER, "not_dispatched")
            .header(PEER_RETRYABLE_HEADER, "true")
            .header(
                PEER_RETRY_AFTER_MS_HEADER,
                OWNER_NOT_READY_RETRY_AFTER_MS.to_string(),
            )
            .body(())
            .map_err(|_| PeerRuntimeError::Closed)?;
        send.respond_with_headers(response).await?;
        send.finish().await
    }

    /// Reject a consumer stream before body admission because the owner's
    /// bounded logical stream limit is full.  The exact authenticated marker
    /// lets the ingress return HTTP 429 without treating an arbitrary
    /// transport failure as a retryable capacity result.
    pub async fn reject_stream_limit(self) -> Result<(), PeerRuntimeError> {
        let (mut send, mut recv) = self.split();
        recv.cancel();
        let response = Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("content-type", "application/octet-stream")
            .header(PEER_ADMISSION_HEADER, PEER_ADMISSION_CAPACITY)
            .header(PEER_ERROR_CODE_HEADER, "STREAM_LIMIT")
            .header(PEER_ERROR_EXECUTION_HEADER, "not_dispatched")
            .header(PEER_RETRYABLE_HEADER, "true")
            .header(
                PEER_RETRY_AFTER_MS_HEADER,
                STREAM_LIMIT_RETRY_AFTER_MS.to_string(),
            )
            .body(())
            .map_err(|_| PeerRuntimeError::Closed)?;
        send.respond_with_headers(response).await?;
        send.finish().await
    }

    /// Split the incoming request into concurrent owner send/receive halves.
    #[must_use]
    pub fn split(self) -> (InboundPeerSend, InboundPeerRecv) {
        let Self {
            identity,
            request,
            envelope,
            binding,
            send,
            recv,
            decoder,
            pending,
            admission_cancellation,
            _connection_budget,
            _envelope_record,
        } = self;
        let admission_token = admission_cancellation
            .as_ref()
            .map(PeerAdmissionCancellation::token);
        let admission_context = admission_cancellation.clone();
        (
            InboundPeerSend {
                send,
                budget: decoder.stream_budget().clone(),
                admission_context: admission_context.clone(),
            },
            InboundPeerRecv {
                identity,
                request,
                envelope,
                binding,
                recv,
                decoder,
                pending,
                admission_cancellation: admission_token,
                admission_context,
                _connection_budget,
                _envelope_record,
            },
        )
    }
}

/// Owner response half for an incoming peer request.
pub struct InboundPeerSend {
    send: PeerServerSend,
    budget: StreamBudget,
    admission_context: Option<PeerAdmissionCancellation>,
}

impl InboundPeerSend {
    async fn respond_with_headers(
        &mut self,
        response: Response<()>,
    ) -> Result<(), PeerRuntimeError> {
        send_server_response(&mut self.send, response, self.admission_context.as_ref()).await
    }

    /// Send response headers exactly once.
    pub async fn respond(&mut self, status: StatusCode) -> Result<(), PeerRuntimeError> {
        let response = Response::builder()
            .status(status)
            .header("content-type", "application/octet-stream")
            .body(())
            .map_err(|_| PeerRuntimeError::Closed)?;
        self.respond_with_headers(response).await
    }

    /// Send one complete response WebSocket message.
    pub async fn send_message(
        &mut self,
        kind: PeerRecordKind,
        body: &[u8],
    ) -> Result<(), PeerRuntimeError> {
        let record = self.budget.record_from_slice(kind, body)?;
        send_server_record(
            &mut self.send,
            &self.budget,
            record,
            self.admission_context.as_ref(),
        )
        .await
    }

    /// Finish the response body.
    pub async fn finish(&mut self) -> Result<(), PeerRuntimeError> {
        finish_server_send(&mut self.send, self.admission_context.as_ref()).await
    }

    /// Cancel the response direction.
    pub fn cancel(&mut self) {
        self.send.cancel();
    }
}

/// Owner receive half for an incoming peer request.
pub struct InboundPeerRecv {
    identity: TlsIdentity,
    request: Request<()>,
    envelope: RequestEnvelope,
    binding: VerifiedPeerBinding,
    recv: PeerServerRecv,
    decoder: PeerRecordDecoder,
    pending: VecDeque<PeerRecord>,
    admission_cancellation: Option<CancellationToken>,
    admission_context: Option<PeerAdmissionCancellation>,
    _connection_budget: ConnectionBudget,
    _envelope_record: PeerRecord,
}

impl InboundPeerRecv {
    /// Return the peer identity for owner-side diagnostics.
    #[must_use]
    pub fn identity(&self) -> &TlsIdentity {
        &self.identity
    }

    /// Return the verified source membership binding.
    #[must_use]
    pub fn binding(&self) -> &VerifiedPeerBinding {
        &self.binding
    }

    /// Return the validated route envelope.
    #[must_use]
    pub fn envelope(&self) -> &RequestEnvelope {
        &self.envelope
    }

    /// Return the authenticated HTTP/3 request metadata.
    #[must_use]
    pub fn request(&self) -> &Request<()> {
        &self.request
    }

    /// Receive one complete peer record under the transport idle timeout.
    pub async fn recv_message(&mut self) -> Result<Option<PeerRecord>, PeerRuntimeError> {
        self.recv_message_with(None).await
    }

    /// Receive one complete peer record under the caller's absolute deadline
    /// instead of the transport idle timeout.
    ///
    /// Used while this side's response is parked: the peer is legitimately
    /// silent until it is answered, so only resets, cancellation, request end
    /// and malformed records end the read early, and the caller's own bound
    /// (the consumer's absolute authorization deadline) applies otherwise.
    pub async fn recv_message_until(
        &mut self,
        deadline: tokio::time::Instant,
    ) -> Result<Option<PeerRecord>, PeerRuntimeError> {
        self.recv_message_with(Some(deadline)).await
    }

    async fn recv_message_with(
        &mut self,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<Option<PeerRecord>, PeerRuntimeError> {
        if self
            .admission_cancellation
            .as_ref()
            .is_some_and(|token| token.is_cancelled())
        {
            self.recv.cancel();
            return Err(admission_cancellation_error(
                self.admission_context.as_ref(),
            ));
        }
        loop {
            if let Some(record) = self.pending.pop_front() {
                if self
                    .admission_cancellation
                    .as_ref()
                    .is_some_and(|token| token.is_cancelled())
                {
                    self.recv.cancel();
                    return Err(admission_cancellation_error(
                        self.admission_context.as_ref(),
                    ));
                }
                return Ok(Some(record));
            }
            let Some(chunk) =
                recv_server_chunk(&mut self.recv, self.admission_context.as_ref(), deadline)
                    .await?
            else {
                self.decoder.finish()?;
                return Ok(None);
            };
            self.pending.extend(self.decoder.push(chunk.as_bytes())?);
        }
    }

    /// Cancel the request direction.
    pub fn cancel(&mut self) {
        self.recv.cancel();
    }
}

/// Create the absolute deadline for one peer record send.
///
/// The deadline comes from the record's own stream budget and is created once,
/// before the first physical write, rather than as a fresh relative timer per
/// physical write.  When the admission carries its own signed trust boundary
/// the earlier instant wins, so a send can never outlive the authorization it
/// was admitted under.  EC-029 requires exactly this: every physical write of
/// a peer record is bounded by an instant fixed before the record started.
fn record_send_deadline(
    budget: &StreamBudget,
    admission_cancellation: Option<&PeerAdmissionCancellation>,
) -> TokioInstant {
    let deadline = TokioInstant::now() + budget.record_send_budget();
    match admission_cancellation.and_then(PeerAdmissionCancellation::expires_at) {
        Some(expires_at) => deadline.min(TokioInstant::from_std(expires_at)),
        None => deadline,
    }
}

/// Whether a send outcome must cancel the stream before it is reported.
///
/// A bounded send that elapsed leaves a peer that is not reading: the stream
/// is reset so the owning pump terminates and can be joined, instead of being
/// left half open for the connection idle timeout to collect.
fn send_failure_cancels_stream(result: &Result<(), PeerRuntimeError>) -> bool {
    matches!(
        result,
        Err(PeerRuntimeError::Closed
            | PeerRuntimeError::MembershipExpired
            | PeerRuntimeError::Transport(PeerTransportError::Timeout))
    )
}

async fn send_record(
    send: &mut PeerClientSend,
    budget: &StreamBudget,
    record: PeerRecord,
    admission_cancellation: Option<&PeerAdmissionCancellation>,
) -> Result<(), PeerRuntimeError> {
    let deadline = record_send_deadline(budget, admission_cancellation);
    let encoded = record
        .encode_charged(budget)
        .map_err(|error| PeerRuntimeError::Frame(PeerFrameError::from(error)))?;
    send_client_chunks(send, encoded.as_ref(), deadline, admission_cancellation).await
}

async fn send_server_record(
    send: &mut PeerServerSend,
    budget: &StreamBudget,
    record: PeerRecord,
    admission_cancellation: Option<&PeerAdmissionCancellation>,
) -> Result<(), PeerRuntimeError> {
    let deadline = record_send_deadline(budget, admission_cancellation);
    let encoded = record
        .encode_charged(budget)
        .map_err(|error| PeerRuntimeError::Frame(PeerFrameError::from(error)))?;
    send_server_chunks(send, encoded.as_ref(), deadline, admission_cancellation).await
}

async fn send_client_chunks(
    send: &mut PeerClientSend,
    bytes: &[u8],
    deadline: TokioInstant,
    admission_cancellation: Option<&PeerAdmissionCancellation>,
) -> Result<(), PeerRuntimeError> {
    let result = if let Some(admission_cancellation) = admission_cancellation {
        if admission_cancellation.is_cancelled() {
            send.cancel();
            return Err(admission_cancellation_error(Some(admission_cancellation)));
        }
        tokio::select! {
            biased;
            _ = admission_cancellation.cancelled() => {
                Err(admission_cancellation_error(Some(admission_cancellation)))
            },
            result = send.send_chunked_until(bytes, deadline) => {
                attribute_admission_failure(result.map_err(Into::into), admission_cancellation)
            }
        }
    } else {
        // The absolute deadline is the only bound on this branch, so it must
        // not be omitted: there is no admission token to cancel the write.
        send.send_chunked_until(bytes, deadline)
            .await
            .map_err(Into::into)
    };
    if send_failure_cancels_stream(&result) {
        send.cancel();
    }
    result
}

async fn send_server_chunks(
    send: &mut PeerServerSend,
    bytes: &[u8],
    deadline: TokioInstant,
    admission_cancellation: Option<&PeerAdmissionCancellation>,
) -> Result<(), PeerRuntimeError> {
    let result = if let Some(admission_cancellation) = admission_cancellation {
        if admission_cancellation.is_cancelled() {
            send.cancel();
            return Err(admission_cancellation_error(Some(admission_cancellation)));
        }
        tokio::select! {
            biased;
            _ = admission_cancellation.cancelled() => {
                Err(admission_cancellation_error(Some(admission_cancellation)))
            },
            result = send.send_chunked_until(bytes, deadline) => {
                attribute_admission_failure(result.map_err(Into::into), admission_cancellation)
            }
        }
    } else {
        // See `send_client_chunks`: the absolute deadline is the only bound
        // when no admission context exists for this stream.
        send.send_chunked_until(bytes, deadline)
            .await
            .map_err(Into::into)
    };
    if send_failure_cancels_stream(&result) {
        send.cancel();
    }
    result
}

async fn finish_client_send(
    send: &mut PeerClientSend,
    admission_cancellation: Option<&PeerAdmissionCancellation>,
) -> Result<(), PeerRuntimeError> {
    if let Some(admission_cancellation) = admission_cancellation {
        if admission_cancellation.is_cancelled() {
            send.cancel();
            return Err(admission_cancellation_error(Some(admission_cancellation)));
        }
        let result = tokio::select! {
            biased;
            _ = admission_cancellation.cancelled() => {
                Err(admission_cancellation_error(Some(admission_cancellation)))
            },
            result = send.finish() => {
                attribute_admission_failure(result.map_err(Into::into), admission_cancellation)
            }
        };
        if matches!(
            result,
            Err(PeerRuntimeError::Closed | PeerRuntimeError::MembershipExpired)
        ) {
            send.cancel();
        }
        result
    } else {
        send.finish().await.map_err(Into::into)
    }
}

async fn finish_server_send(
    send: &mut PeerServerSend,
    admission_cancellation: Option<&PeerAdmissionCancellation>,
) -> Result<(), PeerRuntimeError> {
    if let Some(admission_cancellation) = admission_cancellation {
        if admission_cancellation.is_cancelled() {
            send.cancel();
            return Err(admission_cancellation_error(Some(admission_cancellation)));
        }
        let result = tokio::select! {
            biased;
            _ = admission_cancellation.cancelled() => {
                Err(admission_cancellation_error(Some(admission_cancellation)))
            },
            result = send.finish() => {
                attribute_admission_failure(result.map_err(Into::into), admission_cancellation)
            }
        };
        if matches!(
            result,
            Err(PeerRuntimeError::Closed | PeerRuntimeError::MembershipExpired)
        ) {
            send.cancel();
        }
        result
    } else {
        send.finish().await.map_err(Into::into)
    }
}

async fn send_server_response(
    send: &mut PeerServerSend,
    response: Response<()>,
    admission_cancellation: Option<&PeerAdmissionCancellation>,
) -> Result<(), PeerRuntimeError> {
    if let Some(admission_cancellation) = admission_cancellation {
        if admission_cancellation.is_cancelled() {
            send.cancel();
            return Err(admission_cancellation_error(Some(admission_cancellation)));
        }
        let result = tokio::select! {
            biased;
            _ = admission_cancellation.cancelled() => {
                Err(admission_cancellation_error(Some(admission_cancellation)))
            },
            result = send.send_response(response) => {
                attribute_admission_failure(result.map_err(Into::into), admission_cancellation)
            }
        };
        if matches!(
            result,
            Err(PeerRuntimeError::Closed | PeerRuntimeError::MembershipExpired)
        ) {
            send.cancel();
        }
        result
    } else {
        send.send_response(response).await.map_err(Into::into)
    }
}

async fn recv_client_response(
    recv: &mut PeerClientRecv,
    admission_cancellation: Option<&PeerAdmissionCancellation>,
) -> Result<Response<()>, PeerRuntimeError> {
    if let Some(admission_cancellation) = admission_cancellation {
        if admission_cancellation.is_cancelled() {
            recv.cancel();
            return Err(admission_cancellation_error(Some(admission_cancellation)));
        }
        let result = tokio::select! {
            biased;
            _ = admission_cancellation.cancelled() => {
                Err(admission_cancellation_error(Some(admission_cancellation)))
            },
            result = recv.recv_response() => {
                attribute_admission_failure(result.map_err(Into::into), admission_cancellation)
            }
        };
        if matches!(
            result,
            Err(PeerRuntimeError::Closed | PeerRuntimeError::MembershipExpired)
        ) {
            recv.cancel();
        }
        result
    } else {
        recv.recv_response().await.map_err(Into::into)
    }
}

async fn recv_client_chunk(
    recv: &mut PeerClientRecv,
    admission_cancellation: Option<&PeerAdmissionCancellation>,
) -> Result<Option<tunnel_transport::PeerBodyChunk>, PeerRuntimeError> {
    if let Some(admission_cancellation) = admission_cancellation {
        if admission_cancellation.is_cancelled() {
            recv.cancel();
            return Err(admission_cancellation_error(Some(admission_cancellation)));
        }
        let result = tokio::select! {
            biased;
            _ = admission_cancellation.cancelled() => {
                Err(admission_cancellation_error(Some(admission_cancellation)))
            },
            result = recv.recv_chunk() => {
                attribute_admission_failure(result.map_err(Into::into), admission_cancellation)
            }
        };
        if matches!(
            result,
            Err(PeerRuntimeError::Closed | PeerRuntimeError::MembershipExpired)
        ) {
            recv.cancel();
        }
        result
    } else {
        recv.recv_chunk().await.map_err(Into::into)
    }
}

/// Receive one request body chunk.  `deadline` replaces the transport idle
/// timeout when the caller's own absolute bound applies (a parked response).
async fn recv_server_chunk(
    recv: &mut PeerServerRecv,
    admission_cancellation: Option<&PeerAdmissionCancellation>,
    deadline: Option<tokio::time::Instant>,
) -> Result<Option<tunnel_transport::PeerBodyChunk>, PeerRuntimeError> {
    let receive = async {
        match deadline {
            Some(deadline) => recv.recv_chunk_until(deadline).await,
            None => recv.recv_chunk().await,
        }
    };
    if let Some(admission_cancellation) = admission_cancellation {
        if admission_cancellation.is_cancelled() {
            drop(receive);
            recv.cancel();
            return Err(admission_cancellation_error(Some(admission_cancellation)));
        }
        let result = tokio::select! {
            biased;
            _ = admission_cancellation.cancelled() => {
                Err(admission_cancellation_error(Some(admission_cancellation)))
            },
            result = receive => {
                attribute_admission_failure(result.map_err(Into::into), admission_cancellation)
            }
        };
        if matches!(
            result,
            Err(PeerRuntimeError::Closed | PeerRuntimeError::MembershipExpired)
        ) {
            recv.cancel();
        }
        result
    } else {
        receive.await.map_err(Into::into)
    }
}

fn peer_destination(binding: &VerifiedPeerBinding) -> Result<PeerDestination, PeerRuntimeError> {
    let address = binding
        .peer_endpoint()
        .parse::<SocketAddr>()
        .map_err(|error| PeerRuntimeError::InvalidEndpoint(error.to_string()))?;
    Ok(PeerDestination::new(address, binding.server_name()))
}

const fn route_path(route: InternalRoute) -> &'static str {
    match route {
        InternalRoute::Health => HEALTH_PATH,
        InternalRoute::DeviceControl => DEVICE_CONTROL_PATH,
        InternalRoute::DeviceData => DEVICE_DATA_PATH,
        InternalRoute::ConsumerStreams => CONSUMER_STREAMS_PATH,
        InternalRoute::OperationStatus => OPERATION_STATUS_PATH,
    }
}

/// Build a device certificate context bound to the exact ingress request.
pub fn device_authentication_context(
    identity: &TlsIdentity,
    source: &PeerIdentity,
    destination: &Destination,
    request_id: &str,
    now: DateTime<Utc>,
) -> Result<DeviceAuthenticationContext, PeerRuntimeError> {
    let device_id = match identity.role() {
        tunnel_transport::CertificateRole::Device { id } => id
            .parse::<Uuid>()
            .map_err(|_| PeerRuntimeError::PeerIdentityMismatch)?,
        tunnel_transport::CertificateRole::Peer { .. } => {
            return Err(PeerRuntimeError::PeerIdentityMismatch);
        }
    };
    let to_utc = |seconds: i64| {
        Utc.timestamp_opt(seconds, 0)
            .single()
            .ok_or(PeerRuntimeError::PeerIdentityMismatch)
    };
    let not_before = to_utc(identity.certificate_not_before())?;
    let expires_at = to_utc(identity.certificate_expires_at())?;
    let ingress_expires_at = expires_at.min(now + chrono::Duration::seconds(20));
    let certificate = VerifiedDeviceCertificate {
        certificate_identity: identity.role_id().to_owned(),
        spki_fingerprint: identity.spki_sha256().to_hex(),
        serial: identity.certificate_serial().to_owned(),
        not_before,
        expires_at,
        tenant_id: destination.tenant_id,
        device_id,
    };
    let ingress = IngressRequestBinding {
        request_id: request_id.to_owned(),
        source: source.clone(),
        destination: destination.clone(),
        expires_at: ingress_expires_at,
    };
    Ok(DeviceAuthenticationContext {
        certificate,
        ingress,
    })
}

/// Construct the consumer bearer carried to the owner.  The owner must run
/// its own OIDC and catalog validation; this helper only binds the opaque
/// bearer to the exact owner token.
pub fn forwarded_consumer_bearer(
    bearer: &str,
    owner: OwnerToken,
) -> Result<ForwardedConsumerBearer, PeerRuntimeError> {
    ForwardedConsumerBearer::new(bearer, owner)
        .map_err(|error| PeerRuntimeError::Membership(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_cluster::peer_frame::{
        ConnectionBudget, MAX_CONSUMER_CHUNK_BODY, MAX_DEVICE_DATA_BODY, PREFIX_LEN,
        PeerRecordDecoder,
    };
    use tunnel_transport::DEFAULT_PEER_BODY_CHUNK_BYTES;

    #[test]
    fn peer_reset_after_admission_deadline_is_attributed_to_membership_expiry() {
        let expired = PeerAdmissionCancellation::from_token_with_deadline(
            tokio_util::sync::CancellationToken::new(),
            std::time::Instant::now() - std::time::Duration::from_millis(1),
        );
        let live = PeerAdmissionCancellation::from_token_with_deadline(
            tokio_util::sync::CancellationToken::new(),
            std::time::Instant::now() + std::time::Duration::from_secs(60),
        );
        let reset = || -> Result<(), PeerRuntimeError> {
            Err(PeerRuntimeError::Transport(PeerTransportError::H3(
                "H3_REQUEST_CANCELLED".to_owned(),
            )))
        };

        // After the signed deadline, the peer-reset family is the observable
        // effect of expiry on the other relay; it is attributed as such even
        // though this edge has not been cancelled by the local dispatcher.
        assert!(!expired.is_cancelled());
        assert!(matches!(
            attribute_admission_failure(reset(), &expired),
            Err(PeerRuntimeError::MembershipExpired)
        ));
        for error in [
            PeerRuntimeError::Transport(PeerTransportError::Quic("closed".to_owned())),
            PeerRuntimeError::Transport(PeerTransportError::Cancelled),
            PeerRuntimeError::Closed,
        ] {
            assert!(matches!(
                attribute_admission_failure(Err::<(), _>(error), &expired),
                Err(PeerRuntimeError::MembershipExpired)
            ));
        }

        // Nothing is reclassified before the deadline.
        assert!(matches!(
            attribute_admission_failure(reset(), &live),
            Err(PeerRuntimeError::Transport(PeerTransportError::H3(_)))
        ));

        // Typed non-reset outcomes keep their own classification after the
        // deadline, and success is untouched.
        assert!(matches!(
            attribute_admission_failure(
                Err::<(), _>(PeerRuntimeError::Transport(PeerTransportError::GoAway)),
                &expired
            ),
            Err(PeerRuntimeError::Transport(PeerTransportError::GoAway))
        ));
        assert!(matches!(
            attribute_admission_failure(
                Err::<(), _>(PeerRuntimeError::Transport(PeerTransportError::Timeout)),
                &expired
            ),
            Err(PeerRuntimeError::Transport(PeerTransportError::Timeout))
        ));
        assert!(matches!(
            attribute_admission_failure(
                Err::<(), _>(PeerRuntimeError::OwnerNotReady {
                    retry_after_ms: 250
                }),
                &expired
            ),
            Err(PeerRuntimeError::OwnerNotReady {
                retry_after_ms: 250
            })
        ));
        assert_eq!(
            attribute_admission_failure(Ok::<u8, PeerRuntimeError>(7), &expired).ok(),
            Some(7)
        );

        // The cancellation error follows the same evidence: a passed
        // deadline without a dispatched reason is expiry; a live edge, an
        // unclassified cancellation of it, or no edge is a generic close.
        assert!(matches!(
            admission_cancellation_error(Some(&expired)),
            PeerRuntimeError::MembershipExpired
        ));
        assert!(matches!(
            admission_cancellation_error(Some(&live)),
            PeerRuntimeError::Closed
        ));
        live.token().cancel();
        assert!(matches!(
            admission_cancellation_error(Some(&live)),
            PeerRuntimeError::Closed
        ));
        assert!(matches!(
            admission_cancellation_error(None),
            PeerRuntimeError::Closed
        ));
    }

    #[test]
    fn maximum_device_record_reassembles_across_transport_chunks() {
        let body: Vec<u8> = (0..MAX_DEVICE_DATA_BODY)
            .map(|index| (index % 251) as u8)
            .collect();
        let source_connection = ConnectionBudget::new();
        let source_stream = source_connection.open_stream().expect("source stream");
        let record = source_stream
            .record_from_slice(PeerRecordKind::CompleteDeviceData, &body)
            .expect("maximum device record");
        let encoded = record
            .encode_charged(&source_stream)
            .expect("charged encoded record");
        assert_eq!(encoded.len(), PREFIX_LEN + MAX_DEVICE_DATA_BODY);
        assert_eq!(encoded.charged_bytes(), encoded.len());
        assert_eq!(source_stream.reserved_bytes(), encoded.len() * 2);

        let receiver_connection = ConnectionBudget::new();
        let receiver_stream = receiver_connection.open_stream().expect("receiver stream");
        let mut decoder = PeerRecordDecoder::new(receiver_stream.clone());
        let mut records = Vec::new();
        for chunk in encoded.as_ref().chunks(DEFAULT_PEER_BODY_CHUNK_BYTES) {
            assert!(!chunk.is_empty());
            assert!(chunk.len() <= DEFAULT_PEER_BODY_CHUNK_BYTES);
            records.extend(decoder.push(chunk).expect("fragmented record"));
        }

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind(), PeerRecordKind::CompleteDeviceData);
        assert_eq!(records[0].body(), body.as_slice());
        drop(records);
        decoder.finish().expect("complete record");
        assert_eq!(receiver_connection.reserved_bytes(), 0);

        drop(encoded);
        assert_eq!(source_stream.reserved_bytes(), record.encoded_len());
        drop(record);
        assert_eq!(source_connection.reserved_bytes(), 0);
    }

    #[test]
    fn consumer_unary_request_frames_and_splits_at_consumer_chunk_bound() {
        let body = vec![0x5a; MAX_CONSUMER_UNARY_BODY];
        let framed = frame_consumer_unary_body(&body).expect("maximum unary body");
        assert_eq!(
            &framed[..CONSUMER_RECORD_PREFIX_LEN],
            &(MAX_CONSUMER_UNARY_BODY as u32).to_be_bytes()
        );
        assert_eq!(&framed[CONSUMER_RECORD_PREFIX_LEN..], body.as_slice());
        let chunks: Vec<&[u8]> = framed.chunks(MAX_CONSUMER_CHUNK_BODY).collect();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), MAX_CONSUMER_CHUNK_BODY);
        assert_eq!(chunks[1].len(), CONSUMER_RECORD_PREFIX_LEN);

        let empty = frame_consumer_unary_body(&[]).expect("empty unary body");
        assert_eq!(empty, 0_u32.to_be_bytes().to_vec());
        assert!(matches!(
            frame_consumer_unary_body(&vec![0; MAX_CONSUMER_UNARY_BODY + 1]),
            Err(PeerRuntimeError::Frame(PeerFrameError::BodyTooLarge {
                kind: PeerRecordKind::ConsumerChunk,
                length,
                maximum: MAX_CONSUMER_UNARY_BODY,
            })) if length == MAX_CONSUMER_UNARY_BODY + 1
        ));
    }

    #[test]
    fn consumer_unary_response_accepts_one_split_bounded_record() {
        let body = vec![0x4d; MAX_CONSUMER_RESPONSE_BODY];
        let mut encoded = (MAX_CONSUMER_RESPONSE_BODY as u32).to_be_bytes().to_vec();
        encoded.extend_from_slice(&body);
        let mut response = ConsumerUnaryResponse::default();
        for chunk in encoded.chunks(MAX_CONSUMER_CHUNK_BODY) {
            response.push(chunk).expect("bounded response chunk");
        }
        assert_eq!(response.finish().expect("complete response"), body);
    }

    #[test]
    fn consumer_unary_response_rejects_missing_truncated_extra_and_oversized_records() {
        assert!(matches!(
            ConsumerUnaryResponse::default().finish(),
            Err(PeerRuntimeError::Frame(PeerFrameError::NoRecord))
        ));

        let mut truncated = ConsumerUnaryResponse::default();
        truncated.push(&[0, 0, 0]).expect("partial prefix");
        assert!(matches!(
            truncated.finish(),
            Err(PeerRuntimeError::Frame(PeerFrameError::Truncated {
                expected: CONSUMER_RECORD_PREFIX_LEN,
                received: 3,
            }))
        ));

        let mut coalesced = ConsumerUnaryResponse::default();
        let mut coalesced_bytes = 1_u32.to_be_bytes().to_vec();
        coalesced_bytes.extend_from_slice(b"x");
        coalesced_bytes.extend_from_slice(&0_u32.to_be_bytes());
        assert!(matches!(
            coalesced.push(&coalesced_bytes),
            Err(PeerRuntimeError::Frame(PeerFrameError::MultipleRecords {
                count: 2,
            }))
        ));

        let mut extra_chunk = ConsumerUnaryResponse::default();
        extra_chunk
            .push(&1_u32.to_be_bytes())
            .expect("response prefix");
        extra_chunk.push(b"x").expect("response body");
        assert!(matches!(
            extra_chunk.push(&[]),
            Err(PeerRuntimeError::Frame(PeerFrameError::MultipleRecords {
                count: 2,
            }))
        ));

        let mut oversized = ConsumerUnaryResponse::default();
        let oversized_length = (MAX_CONSUMER_RESPONSE_BODY as u32 + 1).to_be_bytes();
        assert!(matches!(
            oversized.push(&oversized_length),
            Err(PeerRuntimeError::Frame(PeerFrameError::BodyTooLarge {
                kind: PeerRecordKind::ConsumerChunk,
                length,
                maximum: MAX_CONSUMER_RESPONSE_BODY,
            })) if length == MAX_CONSUMER_RESPONSE_BODY + 1
        ));
    }

    #[test]
    fn owner_not_ready_marker_requires_bounded_pre_admission_metadata() {
        let response = Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header(PEER_ADMISSION_HEADER, PEER_ADMISSION_OWNER_NOT_READY)
            .header(PEER_ERROR_EXECUTION_HEADER, "not_dispatched")
            .header(PEER_RETRYABLE_HEADER, "true")
            .header(PEER_RETRY_AFTER_MS_HEADER, "250")
            .body(())
            .expect("valid owner readiness response");
        assert_eq!(owner_not_ready_retry_after(&response), Some(250));

        for (status, admission, execution, retryable, retry_after) in [
            (
                StatusCode::OK,
                PEER_ADMISSION_OWNER_NOT_READY,
                "not_dispatched",
                "true",
                "250",
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "other",
                "not_dispatched",
                "true",
                "250",
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                PEER_ADMISSION_OWNER_NOT_READY,
                "unknown",
                "true",
                "250",
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                PEER_ADMISSION_OWNER_NOT_READY,
                "not_dispatched",
                "false",
                "250",
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                PEER_ADMISSION_OWNER_NOT_READY,
                "not_dispatched",
                "true",
                "0",
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                PEER_ADMISSION_OWNER_NOT_READY,
                "not_dispatched",
                "true",
                "5001",
            ),
        ] {
            let response = Response::builder()
                .status(status)
                .header(PEER_ADMISSION_HEADER, admission)
                .header(PEER_ERROR_EXECUTION_HEADER, execution)
                .header(PEER_RETRYABLE_HEADER, retryable)
                .header(PEER_RETRY_AFTER_MS_HEADER, retry_after)
                .body(())
                .expect("valid marker test response");
            assert_eq!(owner_not_ready_retry_after(&response), None);
        }
    }

    #[test]
    fn stream_limit_marker_rejects_untyped_or_post_dispatch_failures() {
        let response = Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header(PEER_ADMISSION_HEADER, PEER_ADMISSION_CAPACITY)
            .header(PEER_ERROR_CODE_HEADER, "STREAM_LIMIT")
            .header(PEER_ERROR_EXECUTION_HEADER, "not_dispatched")
            .header(PEER_RETRYABLE_HEADER, "true")
            .header(PEER_RETRY_AFTER_MS_HEADER, "250")
            .body(())
            .expect("valid stream-limit response");
        assert_eq!(stream_limit_retry_after(&response), Some(250));

        for (status, code, execution, retryable, retry_after) in [
            (
                StatusCode::TOO_MANY_REQUESTS,
                "OTHER",
                "not_dispatched",
                "true",
                "250",
            ),
            (
                StatusCode::TOO_MANY_REQUESTS,
                "STREAM_LIMIT",
                "unknown",
                "true",
                "250",
            ),
            (
                StatusCode::TOO_MANY_REQUESTS,
                "STREAM_LIMIT",
                "not_dispatched",
                "false",
                "250",
            ),
            (
                StatusCode::TOO_MANY_REQUESTS,
                "STREAM_LIMIT",
                "not_dispatched",
                "true",
                "5001",
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "STREAM_LIMIT",
                "not_dispatched",
                "true",
                "250",
            ),
        ] {
            let response = Response::builder()
                .status(status)
                .header(PEER_ADMISSION_HEADER, PEER_ADMISSION_CAPACITY)
                .header(PEER_ERROR_CODE_HEADER, code)
                .header(PEER_ERROR_EXECUTION_HEADER, execution)
                .header(PEER_RETRYABLE_HEADER, retryable)
                .header(PEER_RETRY_AFTER_MS_HEADER, retry_after)
                .body(())
                .expect("valid marker rejection response");
            assert_eq!(stream_limit_retry_after(&response), None);
        }
    }
}
