use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
    time::Duration,
};

use axum::{
    Extension, Json, Router,
    body::to_bytes,
    extract::{
        Path, Request, State,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    time::{timeout, timeout_at},
};
use tunnel_catalog::{DeviceListFilter, OidcVerifier, SharedCatalog};
use tunnel_protocol::{CONTROL_OWNER_BUSY_CLOSE_CODE, CONTROL_OWNER_BUSY_CLOSE_REASON};
use tunnel_transport::{PeerTransportError, TlsIdentity};
use uuid::Uuid;

const CONTROL_SUBPROTOCOL: &str = "agent-tunnel.control.v1";
const DATA_SUBPROTOCOL: &str = "agent-tunnel.data.v1";
const ECHO_STREAM_SUBPROTOCOL: &str = "agent-tunnel.echo.v1";
const MAX_ECHO_CANARY_BYTES: usize = 256;
/// Bounded retry hint for a consumer admission refusal.  It matches the
/// existing owner-not-ready and stream-limit hints: admission capacity is
/// released by an in-flight operation completing, not by a lease or a clock.
const ADMISSION_LIMIT_RETRY_AFTER_MS: u64 = 250;
const MAX_ADMISSION_LIMIT_RETRY_AFTER_MS: u64 = 5_000;
// A ConsumerChunk body may use the full protocol-defined 64 KiB bound. The
// transport fragments its encoded record (including the eight-byte prefix)
// across bounded HTTP/3 body chunks. The public framing can still require
// multiple ordered ConsumerChunk records when its length prefix is included.
const MAX_CONSUMER_PEER_BODY: usize = tunnel_cluster::peer_frame::MAX_CONSUMER_CHUNK_BODY;
/// The one bounded body-limit decision shared by the owner-local WebSocket
/// handler, the forwarding ingress and the owner side of the peer stream.
const STREAM_RECORD_LIMIT: ConsumerRecordLimit = ConsumerRecordLimit::new(MAX_BODY_BYTES);
// Includes the record prefix and the largest unmasked WebSocket frame header.
const MAX_ECHO_WRITE_BYTES: usize = MAX_BODY_BYTES + MAX_ECHO_CANARY_BYTES + 4 + 10;

/// One-shot fixture seam immediately after authenticated owner admission and
/// immediately before Axum constructs the public WebSocket upgrade response.
/// It is optional and disabled on every ordinary relay path.  The harness can
/// arm it, observe the exact server-side point, close the client connection,
/// and release the handler without relying on a timing sleep or on guessing
/// whether a 101 response was already written.
#[derive(Clone, Debug)]
pub struct ConsumerUpgradeBarrier {
    state: Arc<ConsumerUpgradeBarrierState>,
}

#[derive(Debug)]
struct ConsumerUpgradeBarrierState {
    /// One-shot state machine: idle -> armed -> held -> released.  A barrier
    /// is never reusable; rejecting a stale second arm must not reset the
    /// state of the first request that is already held at the upgrade point.
    phase: AtomicU8,
    hits: AtomicU64,
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

const BARRIER_IDLE: u8 = 0;
const BARRIER_ARMED: u8 = 1;
const BARRIER_HELD: u8 = 2;
const BARRIER_RELEASED: u8 = 3;

impl Default for ConsumerUpgradeBarrier {
    fn default() -> Self {
        Self {
            state: Arc::new(ConsumerUpgradeBarrierState {
                phase: AtomicU8::new(BARRIER_IDLE),
                hits: AtomicU64::new(0),
                reached: tokio::sync::Notify::new(),
                release: tokio::sync::Notify::new(),
            }),
        }
    }
}

impl ConsumerUpgradeBarrier {
    /// Arm exactly one public upgrade interception.  A second arm is rejected
    /// so stale notifications cannot be mistaken for the selected request.
    pub fn arm(&self) -> bool {
        self.state
            .phase
            .compare_exchange(
                BARRIER_IDLE,
                BARRIER_ARMED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Wait until the selected handler reaches the post-admission boundary.
    pub async fn wait_reached(&self) {
        loop {
            if self.state.hits.load(Ordering::Acquire) != 0 {
                return;
            }
            if self.state.phase.load(Ordering::Acquire) == BARRIER_RELEASED {
                return;
            }
            let notified = self.state.reached.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state.hits.load(Ordering::Acquire) != 0 {
                return;
            }
            notified.await;
        }
    }

    /// Release the handler after the client has disconnected.  The release is
    /// sticky, so a cancellation/reordering race cannot strand the handler.
    pub fn release(&self) {
        let mut phase = self.state.phase.load(Ordering::Acquire);
        loop {
            match phase {
                BARRIER_ARMED | BARRIER_HELD => {
                    match self.state.phase.compare_exchange(
                        phase,
                        BARRIER_RELEASED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            self.state.release.notify_waiters();
                            return;
                        }
                        Err(next) => phase = next,
                    }
                }
                BARRIER_IDLE | BARRIER_RELEASED => return,
                _ => return,
            }
        }
    }

    pub fn hit_count(&self) -> u64 {
        self.state.hits.load(Ordering::Acquire)
    }

    /// Report whether the one-shot fixture handler is still holding the
    /// pre-upgrade admission.  This is intentionally an observation seam for
    /// race tests; production admission still uses `wait_before_upgrade` and
    /// `release` as before.
    pub fn is_held(&self) -> bool {
        self.state.phase.load(Ordering::Acquire) == BARRIER_HELD
    }

    async fn wait_before_upgrade(&self, budget: Duration) {
        if self
            .state
            .phase
            .compare_exchange(
                BARRIER_ARMED,
                BARRIER_HELD,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }
        self.state.hits.fetch_add(1, Ordering::AcqRel);
        self.state.reached.notify_waiters();
        let notified = self.state.release.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.state.phase.load(Ordering::Acquire) != BARRIER_RELEASED
            && timeout(budget, notified.as_mut()).await.is_err()
        {
            // The harness normally releases after observing the client
            // disconnect.  A bounded fallback prevents a fixture bug or
            // shutdown race from holding an HTTP admission task forever.
            self.release();
        }
    }
}

/// Exact identity selected by the authenticated public request before the
/// remote H3 admission attempt. This is payload-free and includes the full
/// owner fencing token, so a fixture cannot release a different request or
/// route after a planned drain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerAdmissionScope {
    tenant_id: Uuid,
    device_id: Uuid,
    service_id: Uuid,
    deployment_incarnation: String,
    node_id: String,
    boot_id: String,
    session_id: String,
    epoch: u64,
}

impl PeerAdmissionScope {
    #[must_use]
    pub fn for_owner(owner: &tunnel_catalog::OwnerToken, service_id: Uuid) -> Self {
        Self {
            tenant_id: owner.tenant_id,
            device_id: owner.device_id,
            service_id,
            deployment_incarnation: owner.deployment_incarnation.clone(),
            node_id: owner.node_id.clone(),
            boot_id: owner.boot_id.clone(),
            session_id: owner.session_id.clone(),
            epoch: owner.epoch,
        }
    }

    #[must_use]
    pub fn from_route(route: &crate::routing::OwnerRoute, service_id: Uuid) -> Option<Self> {
        match route {
            crate::routing::OwnerRoute::Remote { owner, .. } => {
                Some(Self::for_owner(&owner.token, service_id))
            }
            crate::routing::OwnerRoute::Local { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PeerAdmissionBarrierError {
    ScopeMismatch,
    ReleasedBeforeHit,
    TimedOut,
}

/// One-shot fixture seam immediately after public authentication, readiness,
/// and owner-route resolution, but before the remote HTTP/3 admission call.
/// It is disabled unless explicitly armed by a harness fixture and carries no
/// request payload or credential material.
#[derive(Clone, Debug)]
pub struct PeerAdmissionBarrier {
    state: Arc<PeerAdmissionBarrierState>,
}

#[derive(Debug)]
struct PeerAdmissionBarrierState {
    phase: AtomicU8,
    hits: AtomicU64,
    expected: std::sync::Mutex<Option<PeerAdmissionScope>>,
    observed: std::sync::Mutex<Option<PeerAdmissionScope>>,
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

const PEER_ADMISSION_IDLE: u8 = 0;
const PEER_ADMISSION_ARMED: u8 = 1;
const PEER_ADMISSION_HELD: u8 = 2;
const PEER_ADMISSION_RELEASED: u8 = 3;

impl Default for PeerAdmissionBarrier {
    fn default() -> Self {
        Self {
            state: Arc::new(PeerAdmissionBarrierState {
                phase: AtomicU8::new(PEER_ADMISSION_IDLE),
                hits: AtomicU64::new(0),
                expected: std::sync::Mutex::new(None),
                observed: std::sync::Mutex::new(None),
                reached: tokio::sync::Notify::new(),
                release: tokio::sync::Notify::new(),
            }),
        }
    }
}

impl PeerAdmissionBarrier {
    /// Arm exactly one request with its full owner/service scope.
    pub fn arm(&self, scope: PeerAdmissionScope) -> bool {
        let mut expected = self
            .state
            .expected
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.state.phase.load(Ordering::Acquire) != PEER_ADMISSION_IDLE {
            return false;
        }
        let armed = self
            .state
            .phase
            .compare_exchange(
                PEER_ADMISSION_IDLE,
                PEER_ADMISSION_ARMED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
        if armed {
            *expected = Some(scope);
        }
        armed
    }

    /// Wait until the selected request reaches the pre-H3-admission seam.
    pub async fn wait_reached(&self) {
        loop {
            if self.state.hits.load(Ordering::Acquire) != 0
                || self.state.phase.load(Ordering::Acquire) == PEER_ADMISSION_RELEASED
            {
                return;
            }
            let notified = self.state.reached.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state.hits.load(Ordering::Acquire) != 0
                || self.state.phase.load(Ordering::Acquire) == PEER_ADMISSION_RELEASED
            {
                return;
            }
            notified.await;
        }
    }

    pub fn release(&self) {
        let mut phase = self.state.phase.load(Ordering::Acquire);
        loop {
            match phase {
                PEER_ADMISSION_ARMED | PEER_ADMISSION_HELD => {
                    match self.state.phase.compare_exchange(
                        phase,
                        PEER_ADMISSION_RELEASED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            self.state.reached.notify_waiters();
                            self.state.release.notify_waiters();
                            return;
                        }
                        Err(next) => phase = next,
                    }
                }
                PEER_ADMISSION_IDLE | PEER_ADMISSION_RELEASED => return,
                _ => return,
            }
        }
    }

    #[must_use]
    pub fn hit_count(&self) -> u64 {
        self.state.hits.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn observed_scope(&self) -> Option<PeerAdmissionScope> {
        self.state
            .observed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) async fn wait_before_peer_admission(
        &self,
        scope: PeerAdmissionScope,
        budget: Duration,
    ) -> Result<bool, PeerAdmissionBarrierError> {
        let phase = self.state.phase.compare_exchange(
            PEER_ADMISSION_ARMED,
            PEER_ADMISSION_HELD,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        if let Err(phase) = phase {
            return match phase {
                PEER_ADMISSION_IDLE => Ok(false),
                PEER_ADMISSION_RELEASED => Err(PeerAdmissionBarrierError::ReleasedBeforeHit),
                _ => Err(PeerAdmissionBarrierError::ReleasedBeforeHit),
            };
        }
        let expected = self
            .state
            .expected
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if expected.as_ref() != Some(&scope) {
            self.release();
            return Err(PeerAdmissionBarrierError::ScopeMismatch);
        }
        *self
            .state
            .observed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(scope);
        self.state.hits.fetch_add(1, Ordering::AcqRel);
        self.state.reached.notify_waiters();
        let notified = self.state.release.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.state.phase.load(Ordering::Acquire) != PEER_ADMISSION_RELEASED
            && timeout(budget, notified.as_mut()).await.is_err()
        {
            self.release();
            return Err(PeerAdmissionBarrierError::TimedOut);
        }
        Ok(true)
    }
}

use tunnel_cluster::{
    envelope::{
        Destination, InternalRequest, InternalRoute, RequestEnvelope, VerifiedPeerIdentity,
    },
    peer_frame::PeerRecordKind,
};

use crate::{
    actor::{
        ConsumerStreamRegistration, EchoOutcome, RelayError, RelayHandle, TerminalCleanupGuard,
    },
    config::RelayLimits,
    consumer_framing::{ConsumerRecordAssembler, ConsumerRecordCursor, ConsumerRecordLimit},
    consumer_write_diagnostics::{
        ConsumerIngressKind, ConsumerWriteOutcome, ConsumerWriteScope, send_until,
        send_until_or_expired,
    },
    health,
    peer_consumer_transport_diagnostics::{
        PeerConsumerDiagnosticContext, PeerConsumerDiagnosticH3Code, PeerConsumerDiagnosticRole,
        classify_h3_code,
    },
    peer_runtime::{
        InboundPeerRequest, OWNER_NOT_READY_RETRY_AFTER_MS, PeerExchangeRecv, PeerExchangeSend,
        PeerIngressHandler, PeerRuntime, PeerRuntimeError, STREAM_LIMIT_RETRY_AFTER_MS,
        device_authentication_context, forwarded_consumer_bearer,
    },
    peer_transport_diagnostics::{PeerTransportDiagnosticOutcome, PeerTransportDiagnosticRole},
    routing::{
        OwnerRoute, OwnerRoutingError, OwnerScope, ServiceResolutionError, ServiceTarget,
        resolve_echo_service,
    },
    runtime::StreamTerminalCause,
    wire::{self, MAX_BODY_BYTES, MAX_CONTROL_BYTES},
};

/// Per-owner-scope consumer admission permits.
///
/// The relay-global [`Semaphore`] bounds the process but not a tenant, so one
/// tenant's in-flight operations could refuse every other tenant's public
/// request for the whole operation round trip.  The scope chosen here is the
/// canonical `(tenant_id, device_id)` owner scope already used by owner
/// resolution, the durable catalog keys and the owner token in
/// docs/cluster.md: it is exactly the owner an admitted operation targets, its
/// cardinality is already bounded by `max_devices`, and a tenant cannot widen
/// its own allowance by minting additional principals.
///
/// A scope entry exists only while it holds at least one permit, so the map is
/// bounded by the relay-global permit count rather than by the catalog.
pub(crate) struct ScopedAdmission {
    permits: usize,
    scopes: Mutex<HashMap<OwnerScope, Arc<Semaphore>>>,
}

impl ScopedAdmission {
    /// Build a registry whose effective per-scope bound is
    /// `min(per_owner, global)`.  The relay-global permit is always reserved
    /// first, so a configured per-owner allowance above the process bound
    /// could never be granted; clamping keeps the refusal attributable to the
    /// bound that actually applies.
    pub(crate) fn new(per_owner: usize, global: usize) -> Arc<Self> {
        Arc::new(Self {
            permits: per_owner.min(global).max(1),
            scopes: Mutex::new(HashMap::new()),
        })
    }

    /// The effective per-scope bound after clamping.
    #[cfg(test)]
    pub(crate) fn permits(&self) -> usize {
        self.permits
    }

    /// Reserve one permit for `scope`, or return `None` when this scope already
    /// holds its full allowance.  The lookup, the entry creation and the
    /// acquisition all happen under one lock, so a concurrent release cannot
    /// reclaim an entry a caller is about to acquire from.
    pub(crate) fn try_acquire(
        self: &Arc<Self>,
        scope: OwnerScope,
    ) -> Option<ScopedAdmissionPermit> {
        let mut scopes = self.lock();
        let semaphore = Arc::clone(
            scopes
                .entry(scope)
                .or_insert_with(|| Arc::new(Semaphore::new(self.permits))),
        );
        match Arc::clone(&semaphore).try_acquire_owned() {
            Ok(permit) => Some(ScopedAdmissionPermit {
                registry: Arc::clone(self),
                scope,
                permit: Some(permit),
            }),
            Err(_) => {
                Self::reclaim(&mut scopes, scope, self.permits);
                None
            }
        }
    }

    /// Permits currently held for `scope`.
    #[cfg(test)]
    pub(crate) fn in_flight(&self, scope: OwnerScope) -> usize {
        self.lock().get(&scope).map_or(0, |semaphore| {
            self.permits.saturating_sub(semaphore.available_permits())
        })
    }

    /// Scope entries currently tracked.  An entry without a held permit is a
    /// leak, so this is the bound the release path must keep.
    #[cfg(test)]
    pub(crate) fn tracked_scopes(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<OwnerScope, Arc<Semaphore>>> {
        // A permit bound must not be lost to a poisoned lock: the map holds no
        // invariant beyond "an entry exists while it has holders", and every
        // path below rebuilds that from the semaphore itself.
        self.scopes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Drop an idle entry.  `strong_count == 1` means only the map still
    /// references the semaphore, so no outstanding permit can be released into
    /// an entry that has already been removed.
    fn reclaim(
        scopes: &mut HashMap<OwnerScope, Arc<Semaphore>>,
        scope: OwnerScope,
        permits: usize,
    ) {
        if scopes.get(&scope).is_some_and(|semaphore| {
            Arc::strong_count(semaphore) == 1 && semaphore.available_permits() >= permits
        }) {
            scopes.remove(&scope);
        }
    }
}

/// One reserved per-scope admission permit.  It is released exactly once, on
/// drop, which covers every handler exit path including cancellation: an
/// abandoned request drops the handler future, and an abandoned upgrade drops
/// the guard the upgrade closure captured.
pub(crate) struct ScopedAdmissionPermit {
    registry: Arc<ScopedAdmission>,
    scope: OwnerScope,
    permit: Option<OwnedSemaphorePermit>,
}

impl Drop for ScopedAdmissionPermit {
    fn drop(&mut self) {
        // `take` makes the release idempotent in the type: the owned permit
        // returns its capacity when this statement's temporary is dropped, and
        // only then is the now-idle entry reclaimed.
        if self.permit.take().is_none() {
            return;
        }
        let permits = self.registry.permits;
        let mut scopes = self.registry.lock();
        ScopedAdmission::reclaim(&mut scopes, self.scope, permits);
    }
}

#[derive(Clone)]
pub(crate) struct HttpState {
    pub(crate) handle: RelayHandle,
    pub(crate) catalog: Option<SharedCatalog>,
    pub(crate) oidc: Option<Arc<OidcVerifier>>,
    pub(crate) limits: RelayLimits,
    /// Reserved before reading a request body; bounds aggregate materialization.
    /// This is the relay-global process bound and is deliberately not
    /// tenant-scoped, so it is always paired with `scoped_admission` below.
    pub(crate) admission: Arc<Semaphore>,
    /// Per-`(tenant_id, device_id)` consumer admission bound, reserved after
    /// the authenticated catalog identity is known and layered under
    /// `admission`.  Without it, one tenant's in-flight operations hold every
    /// relay-global permit for their whole round trip and every other tenant's
    /// public request receives the typed admission-limit refusal, which
    /// contradicts the multi-user isolation requirement in AGENTS.md and the
    /// tenant-scoped invariants in docs/cluster.md.
    pub(crate) scoped_admission: Arc<ScopedAdmission>,
    /// Optional cluster forwarding context.  `None` preserves the local M1/M2
    /// listener behavior for single-relay deployments and existing tests.
    pub(crate) peer: Option<Arc<PeerRuntime>>,
    /// Fixture-only one-shot gate after owner admission and before public
    /// WebSocket upgrade response construction.
    pub(crate) consumer_upgrade_barrier: Option<Arc<ConsumerUpgradeBarrier>>,
    /// Fixture-only one-shot gate after public readiness and exact owner-route
    /// resolution but before the remote H3 admission attempt.
    pub(crate) peer_admission_barrier: Option<Arc<PeerAdmissionBarrier>>,
}

/// Build both public consumer and device WebSocket routes. Run this router
/// through `tunnel_transport::serve` so identities come from verified TLS.
pub fn router(
    handle: RelayHandle,
    catalog: SharedCatalog,
    oidc: Arc<OidcVerifier>,
    limits: RelayLimits,
) -> Router {
    router_with_peer(handle, catalog, oidc, limits, None)
}

/// Build public and device routes with an optional direct owner-forwarding
/// runtime.  The runtime must be initialized before the listener is marked
/// ready; handlers never construct a peer client lazily.
pub fn router_with_peer(
    handle: RelayHandle,
    catalog: SharedCatalog,
    oidc: Arc<OidcVerifier>,
    limits: RelayLimits,
    peer: Option<Arc<PeerRuntime>>,
) -> Router {
    Router::new()
        .merge(consumer_router_with_peer(
            handle.clone(),
            catalog.clone(),
            oidc,
            limits.clone(),
            peer.clone(),
        ))
        .merge(device_router_with_peer(handle, Some(catalog), limits, peer))
}

pub fn consumer_router(
    handle: RelayHandle,
    catalog: SharedCatalog,
    oidc: Arc<OidcVerifier>,
    limits: RelayLimits,
) -> Router {
    consumer_router_with_peer(handle, catalog, oidc, limits, None)
}

/// Build consumer routes with optional direct owner forwarding.
pub fn consumer_router_with_peer(
    handle: RelayHandle,
    catalog: SharedCatalog,
    oidc: Arc<OidcVerifier>,
    limits: RelayLimits,
    peer: Option<Arc<PeerRuntime>>,
) -> Router {
    consumer_router_with_peer_and_barrier(handle, catalog, oidc, limits, peer, None)
}

/// Build consumer routes with an optional fixture-only post-admission barrier.
/// The barrier is intentionally separate from the normal public API path so
/// production callers retain the existing no-gate behavior.
pub fn consumer_router_with_peer_and_barrier(
    handle: RelayHandle,
    catalog: SharedCatalog,
    oidc: Arc<OidcVerifier>,
    limits: RelayLimits,
    peer: Option<Arc<PeerRuntime>>,
    consumer_upgrade_barrier: Option<Arc<ConsumerUpgradeBarrier>>,
) -> Router {
    consumer_router_with_peer_and_barriers(
        handle,
        catalog,
        oidc,
        limits,
        peer,
        consumer_upgrade_barrier,
        None,
    )
}

/// Build consumer routes with the two independent fixture-only seams. The
/// pre-H3 admission barrier is deliberately separate from the older post-
/// admission upgrade barrier; ordinary production callers pass `None` for
/// both and retain the existing route.
pub(crate) fn consumer_router_with_peer_and_barriers(
    handle: RelayHandle,
    catalog: SharedCatalog,
    oidc: Arc<OidcVerifier>,
    limits: RelayLimits,
    peer: Option<Arc<PeerRuntime>>,
    consumer_upgrade_barrier: Option<Arc<ConsumerUpgradeBarrier>>,
    peer_admission_barrier: Option<Arc<PeerAdmissionBarrier>>,
) -> Router {
    let state = HttpState {
        handle,
        catalog: Some(catalog),
        oidc: Some(oidc),
        admission: Arc::new(Semaphore::new(limits.max_pending_operations)),
        scoped_admission: ScopedAdmission::new(
            limits.max_pending_operations_per_owner,
            limits.max_pending_operations,
        ),
        limits: limits.clone(),
        peer,
        consumer_upgrade_barrier,
        peer_admission_barrier,
    };
    Router::new()
        .merge(health::router::<HttpState>(state.peer.clone()))
        .route("/v1/devices", get(list_devices))
        .route("/v1/devices/{device}/services", get(list_services))
        .route("/v1/devices/{device}/services/{service}/echo", post(echo))
        .route(
            "/v1/devices/{device}/services/{service}/stream",
            get(echo_stream),
        )
        // A known path with an unserved method is a typed not-dispatched
        // rejection, so a GET/HEAD/OPTIONS shape at the POST-only echo route
        // is proven never to select, reselect or dispatch to an owner.
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state)
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
}

pub fn device_router(handle: RelayHandle, limits: RelayLimits) -> Router {
    device_router_with_peer(handle, None, limits, None)
}

/// Build device routes with optional direct owner forwarding.  A catalog is
/// required only when a device ingress must discover a remote owner; local
/// M1/M2 registration remains available without one.
pub fn device_router_with_peer(
    handle: RelayHandle,
    catalog: Option<SharedCatalog>,
    limits: RelayLimits,
    peer: Option<Arc<PeerRuntime>>,
) -> Router {
    let state = HttpState {
        handle,
        catalog,
        oidc: None,
        admission: Arc::new(Semaphore::new(limits.max_devices.saturating_mul(2))),
        // Device sockets authenticate with their own mTLS identity and are
        // already bounded per device by the actor; the consumer-side per-owner
        // bound is carried here only so both routers share one state type.
        scoped_admission: ScopedAdmission::new(
            limits.max_pending_operations_per_owner,
            limits.max_pending_operations,
        ),
        limits,
        peer,
        consumer_upgrade_barrier: None,
        peer_admission_barrier: None,
    };
    Router::new()
        .route("/v1/tunnel/control", get(control))
        .route("/v1/tunnel/data", get(data))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            cluster_readiness_gate,
        ))
        .with_state(state)
}

async fn list_devices(State(state): State<HttpState>, headers: HeaderMap) -> Response {
    let Ok(_permit) = state.admission.clone().try_acquire_owned() else {
        return admission_limit_response(ADMISSION_LIMIT_RETRY_AFTER_MS);
    };
    let principal = match authenticate(&state, &headers, None).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let Some(catalog) = state.catalog.as_ref() else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTHORIZATION_UNAVAILABLE",
            "catalog unavailable",
            "not_dispatched",
        );
    };
    match catalog
        .list_devices_filtered(&principal, &DeviceListFilter::default(), Utc::now())
        .await
    {
        Ok(devices) => Json(devices).into_response(),
        Err(error) => catalog_error(error),
    }
}

async fn list_services(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(device): Path<String>,
) -> Response {
    let Ok(_permit) = state.admission.clone().try_acquire_owned() else {
        return admission_limit_response(ADMISSION_LIMIT_RETRY_AFTER_MS);
    };
    let principal = match authenticate(&state, &headers, None).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let device_id = match parse_uuid(&device) {
        Ok(value) => value,
        Err(()) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "not found",
                "not_dispatched",
            );
        }
    };
    let filter = DeviceListFilter {
        service_id: None,
        owner_user_id: None,
        include_inactive: false,
    };
    let Some(catalog) = state.catalog.as_ref() else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTHORIZATION_UNAVAILABLE",
            "catalog unavailable",
            "not_dispatched",
        );
    };
    match catalog
        .list_devices_filtered(&principal, &filter, Utc::now())
        .await
    {
        Ok(devices) => devices
            .into_iter()
            .find(|summary| summary.device_id == device_id)
            .map(|summary| Json(summary.services).into_response())
            .unwrap_or_else(|| {
                error_response(
                    StatusCode::NOT_FOUND,
                    "DEVICE_NOT_FOUND",
                    "not found",
                    "not_dispatched",
                )
            }),
        Err(error) => catalog_error(error),
    }
}

async fn echo(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((device, service)): Path<(String, String)>,
    request: Request,
) -> Response {
    if let Some(response) = cluster_unready_response(&state) {
        return response;
    }
    let Ok(_permit) = state.admission.clone().try_acquire_owned() else {
        return admission_limit_response(ADMISSION_LIMIT_RETRY_AFTER_MS);
    };
    let (Some(catalog), Some(oidc)) = (state.catalog.as_ref(), state.oidc.as_ref()) else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTHORIZATION_UNAVAILABLE",
            "catalog unavailable",
            "not_dispatched",
        );
    };
    let validated = match oidc
        .authenticate_for_scope(&**catalog, bearer(&headers), None, crate::ECHO_OPERATION)
        .await
    {
        Ok(value) => value,
        Err(_) => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "consumer authentication failed",
                "not_dispatched",
            );
        }
    };
    let device_id = match parse_uuid(&device) {
        Ok(value) => value,
        Err(()) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "not found",
                "not_dispatched",
            );
        }
    };
    let (service_id, mut grant) =
        match service_and_grant(&state, &validated.consumer, device_id, &service).await {
            Ok(value) => value,
            Err(response) => return response,
        };
    if grant.valid_until <= Utc::now() || !grant.permissions.allows(crate::ECHO_OPERATION) {
        return error_response(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "echo is not authorized",
            "not_dispatched",
        );
    }
    // The relay-global permit above is already held; this second, tenant-scoped
    // reservation is what stops one owner scope from holding every permit for
    // the whole round trip.  It is taken only once the authenticated catalog
    // identity fixes the scope, and it is released on drop, so an abandoned or
    // cancelled request cannot leak it.
    let Some(_scope_permit) = state
        .scoped_admission
        .try_acquire(OwnerScope::new(grant.tenant_id, device_id))
    else {
        return admission_limit_response(ADMISSION_LIMIT_RETRY_AFTER_MS);
    };
    let body = match timeout(
        Duration::from_secs(10),
        to_bytes(
            request.into_body(),
            state.limits.max_body_bytes.min(MAX_BODY_BYTES),
        ),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => {
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "BODY_LIMIT",
                "request body exceeds the echo limit or is incomplete",
                "not_dispatched",
            );
        }
        Err(_) => {
            return error_response(
                StatusCode::REQUEST_TIMEOUT,
                "BODY_TIMEOUT",
                "request body deadline exceeded",
                "not_dispatched",
            );
        }
    };
    if validated.expires_at <= Utc::now() {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "consumer token expired before dispatch",
            "not_dispatched",
        );
    }
    if let Some(response) = cluster_unready_response(&state) {
        return response;
    }
    grant.valid_until = grant.valid_until.min(validated.expires_at);
    let bearer_token = forwarded_bearer_token(&headers).to_owned();
    if let Some(peer) = state.peer.clone() {
        let scope = OwnerScope::new(grant.tenant_id, device_id);
        match peer.resolve(scope, Utc::now()).await {
            Ok(route @ OwnerRoute::Remote { .. }) => {
                let request_id = Uuid::new_v4().to_string();
                let destination = Destination::new(route.owner_token().clone(), service_id);
                let forwarded =
                    match forwarded_consumer_bearer(&bearer_token, route.owner_token().clone()) {
                        Ok(value) => value,
                        Err(_) => {
                            return error_response(
                                StatusCode::UNAUTHORIZED,
                                "UNAUTHORIZED",
                                "consumer authentication failed",
                                "not_dispatched",
                            );
                        }
                    };
                let envelope = RequestEnvelope::new(
                    InternalRoute::ConsumerStreams,
                    request_id.clone(),
                    peer.source().clone(),
                    destination,
                    20_000,
                    None,
                    InternalRequest::ConsumerStreams(
                        tunnel_cluster::envelope::ConsumerStreamsRequest {
                            stream_id: request_id,
                            required_scope: crate::ECHO_OPERATION.to_owned(),
                            bearer: forwarded,
                            bytes: Vec::new(),
                        },
                    ),
                );
                match peer.forward_unary(&route, envelope, &body).await {
                    Ok(bytes) => {
                        return (
                            StatusCode::OK,
                            [(header::CONTENT_TYPE, "application/octet-stream")],
                            bytes,
                        )
                            .into_response();
                    }
                    Err(error) => return peer_failure_response(error),
                }
            }
            Ok(OwnerRoute::Local { .. }) => {}
            Err(error) => return peer_failure_response(error),
        }
    }
    let result = timeout(
        state.limits.operation_timeout,
        state.handle.dispatch_echo(
            validated.consumer,
            device_id,
            service_id,
            grant,
            body.to_vec(),
            validated.expires_at,
        ),
    )
    .await;
    match result {
        Ok(Ok(EchoOutcome::Success(bytes))) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            bytes,
        )
            .into_response(),
        Ok(Ok(EchoOutcome::Failure { code, execution })) => failure_outcome(code, execution),
        Ok(Err(_)) => failure_outcome("REVERSE_CHANNEL_UNAVAILABLE", "not_dispatched"),
        Err(_) => failure_outcome("REVERSE_CHANNEL_INTERRUPTED", "unknown"),
    }
}

struct RemoteConsumerAdmission {
    request_id: String,
    send: Option<PeerExchangeSend>,
    recv: Option<PeerExchangeRecv>,
}

impl RemoteConsumerAdmission {
    fn new(request_id: String, send: PeerExchangeSend, recv: PeerExchangeRecv) -> Self {
        Self {
            request_id,
            send: Some(send),
            recv: Some(recv),
        }
    }

    fn into_parts(mut self) -> (String, PeerExchangeSend, PeerExchangeRecv) {
        (
            std::mem::take(&mut self.request_id),
            self.send.take().expect("peer admission send half present"),
            self.recv.take().expect("peer admission recv half present"),
        )
    }

    async fn accept_response(&mut self) -> Result<(), PeerRuntimeError> {
        self.recv
            .as_mut()
            .expect("peer admission response half present")
            .accept_response()
            .await
            .map(|_| ())
    }
}

impl Drop for RemoteConsumerAdmission {
    fn drop(&mut self) {
        if let Some(send) = self.send.as_mut() {
            send.cancel();
        }
        if let Some(recv) = self.recv.as_mut() {
            recv.cancel();
        }
    }
}

async fn open_remote_consumer_admission(
    peer: &PeerRuntime,
    route: &OwnerRoute,
    service_id: Uuid,
    bearer_token: &str,
    request_id: String,
    peer_admission_barrier: Option<(&PeerAdmissionBarrier, PeerAdmissionScope)>,
    peer_admission_budget: Duration,
) -> Result<RemoteConsumerAdmission, PeerRuntimeError> {
    let destination = Destination::new(route.owner_token().clone(), service_id);
    let bearer = forwarded_consumer_bearer(bearer_token, route.owner_token().clone())?;
    let envelope = RequestEnvelope::new(
        InternalRoute::ConsumerStreams,
        request_id.clone(),
        peer.source().clone(),
        destination,
        20_000,
        None,
        InternalRequest::ConsumerStreams(tunnel_cluster::envelope::ConsumerStreamsRequest {
            stream_id: request_id.clone(),
            required_scope: crate::ECHO_OPERATION.to_owned(),
            bearer,
            bytes: Vec::new(),
        }),
    );
    let exchange = if let Some((barrier, scope)) = peer_admission_barrier {
        peer.open_with_admission_barrier(route, envelope, barrier, scope, peer_admission_budget)
            .await?
    } else {
        peer.open(route, envelope).await?
    };
    let (send, recv) = exchange.split();
    let mut admission = RemoteConsumerAdmission::new(request_id, send, recv);
    admission.accept_response().await?;
    Ok(admission)
}

async fn admit_local_consumer_stream(
    handle: &RelayHandle,
    consumer: tunnel_catalog::AuthenticatedConsumer,
    device_id: Uuid,
    service_id: Uuid,
    grant: tunnel_catalog::GrantSnapshot,
    consumer_expires_at: chrono::DateTime<Utc>,
) -> Result<(ConsumerStreamRegistration, TerminalCleanupGuard), Response> {
    let registration = handle
        .open_echo_stream(consumer, device_id, service_id, grant, consumer_expires_at)
        .await
        .map_err(local_consumer_admission_response)?;
    let cleanup = handle.echo_cleanup_guard(
        registration.key.clone(),
        registration.stream_id,
        registration.operation_id.clone(),
        None,
    );
    Ok((registration, cleanup))
}

/// Re-read the authoritative complete owner token after admission has
/// succeeded and immediately before the public WebSocket 101 response is
/// constructed.  Route observations are intentionally not sufficient here:
/// a replacement session may have committed while the authenticated peer
/// admission was waiting at the upgrade barrier.  A changed, missing, or
/// unreadable claim fails closed as a bounded pre-admission retry result.
async fn revalidate_owner_before_upgrade(
    catalog: &SharedCatalog,
    route: &OwnerRoute,
    budget: Duration,
) -> Result<(), PeerRuntimeError> {
    let owner = timeout(
        budget,
        catalog.current_owner(
            route.owner_token().tenant_id,
            route.owner_token().device_id,
            Utc::now(),
        ),
    )
    .await
    .map_err(|_| PeerRuntimeError::OwnerNotReady {
        retry_after_ms: OWNER_NOT_READY_RETRY_AFTER_MS,
    })?
    .map_err(|_| PeerRuntimeError::OwnerNotReady {
        retry_after_ms: OWNER_NOT_READY_RETRY_AFTER_MS,
    })?;
    if owner
        .as_ref()
        .is_none_or(|claim| claim.token != *route.owner_token())
    {
        return Err(PeerRuntimeError::OwnerNotReady {
            retry_after_ms: OWNER_NOT_READY_RETRY_AFTER_MS,
        });
    }
    Ok(())
}

async fn echo_stream(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path((device, service)): Path<(String, String)>,
    upgrade: WebSocketUpgrade,
) -> Response {
    if let Some(response) = cluster_unready_response(&state) {
        return response;
    }
    if !subprotocol_offered(&headers, ECHO_STREAM_SUBPROTOCOL) {
        return error_response(
            StatusCode::UPGRADE_REQUIRED,
            "SUBPROTOCOL_REQUIRED",
            "consumer stream subprotocol is required",
            "not_dispatched",
        );
    }
    let Ok(permit) = state.admission.clone().try_acquire_owned() else {
        return admission_limit_response(ADMISSION_LIMIT_RETRY_AFTER_MS);
    };
    let (Some(catalog), Some(oidc)) = (state.catalog.as_ref(), state.oidc.as_ref()) else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTHORIZATION_UNAVAILABLE",
            "catalog unavailable",
            "not_dispatched",
        );
    };
    let validated = match oidc
        .authenticate_for_scope(&**catalog, bearer(&headers), None, crate::ECHO_OPERATION)
        .await
    {
        Ok(value) => value,
        Err(_) => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "consumer authentication failed",
                "not_dispatched",
            );
        }
    };
    let device_id = match parse_uuid(&device) {
        Ok(value) => value,
        Err(()) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "not found",
                "not_dispatched",
            );
        }
    };
    let (service_id, mut grant) =
        match service_and_grant(&state, &validated.consumer, device_id, &service).await {
            Ok(value) => value,
            Err(response) => return response,
        };
    if !grant.permissions.allows(crate::ECHO_OPERATION)
        || grant.valid_until <= Utc::now()
        || validated.expires_at <= Utc::now()
    {
        return error_response(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "echo stream is not authorized",
            "not_dispatched",
        );
    }
    grant.valid_until = grant.valid_until.min(validated.expires_at);
    // Layered under the relay-global permit taken above: the public stream is
    // long-lived, so without a tenant-scoped bound one owner scope's streams
    // refuse every other tenant's public request.  The guard travels into the
    // upgrade closure below and is released on drop, so an abandoned upgrade,
    // a failed peer admission and a normal close all release it exactly once.
    let Some(scope_permit) = state
        .scoped_admission
        .try_acquire(OwnerScope::new(grant.tenant_id, device_id))
    else {
        return admission_limit_response(ADMISSION_LIMIT_RETRY_AFTER_MS);
    };
    if let Some(response) = cluster_unready_response(&state) {
        return response;
    }
    let handle = state.handle.clone();
    let consumer = validated.consumer;
    let consumer_expires_at = validated.expires_at;
    let bearer_token = forwarded_bearer_token(&headers).to_owned();
    let dispatch_peer = state.peer.clone();
    let mut selected_route = None;
    let mut remote = None;
    if let Some(peer) = state.peer.clone() {
        match peer
            .resolve(OwnerScope::new(grant.tenant_id, device_id), Utc::now())
            .await
        {
            Ok(route @ OwnerRoute::Remote { .. }) => {
                let peer_admission_barrier = if let Some(barrier) =
                    state.peer_admission_barrier.as_ref()
                {
                    let scope = match PeerAdmissionScope::from_route(&route, service_id) {
                        Some(scope) => scope,
                        None => {
                            return peer_failure_response(PeerRuntimeError::PeerIdentityMismatch);
                        }
                    };
                    Some((barrier.as_ref(), scope))
                } else {
                    None
                };
                // The public WebSocket is not upgraded until this authenticated
                // peer admission completes.  Retain the same request identity
                // on a typed planned-drain failure so the bounded diagnostic
                // survives this pre-upgrade boundary; no payload or transport
                // text crosses the snapshot boundary.
                let request_id = Uuid::new_v4().to_string();
                let admission = match timeout(
                    state.limits.operation_timeout,
                    open_remote_consumer_admission(
                        &peer,
                        &route,
                        service_id,
                        &bearer_token,
                        request_id.clone(),
                        peer_admission_barrier,
                        state.limits.operation_timeout,
                    ),
                )
                .await
                {
                    Ok(result) => match result {
                        Ok(admission) => admission,
                        Err(error) => {
                            if matches!(
                                &error,
                                PeerRuntimeError::Transport(PeerTransportError::GoAway)
                            ) {
                                let owner = route.owner_token();
                                handle.record_peer_consumer_diagnostic(
                                    &PeerConsumerDiagnosticContext {
                                        tenant_id: owner.tenant_id,
                                        device_id: owner.device_id,
                                        session_id: owner.session_id.clone(),
                                        epoch: owner.epoch,
                                        service_id,
                                        request_id: request_id.clone(),
                                    },
                                    PeerConsumerDiagnosticRole::IngressSend,
                                    PeerTransportDiagnosticOutcome::GoAway,
                                    None,
                                );
                            }
                            return peer_failure_response(error);
                        }
                    },
                    Err(_) => return peer_failure_response(PeerRuntimeError::Closed),
                };
                selected_route = Some(route.clone());
                remote = Some((route, admission));
            }
            Ok(route @ OwnerRoute::Local { .. }) => {
                selected_route = Some(route);
            }
            Err(error) => return peer_failure_response(error),
        }
    }
    let local = if remote.is_none() {
        Some(
            match timeout(
                state.limits.operation_timeout,
                admit_local_consumer_stream(
                    &handle,
                    consumer,
                    device_id,
                    service_id,
                    grant,
                    consumer_expires_at,
                ),
            )
            .await
            {
                Ok(result) => match result {
                    Ok(admission) => admission,
                    Err(response) => return response,
                },
                Err(_) => {
                    return error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "REVERSE_CHANNEL_INTERRUPTED",
                        "reverse channel admission timed out",
                        "unknown",
                    );
                }
            },
        )
    } else {
        None
    };
    if let Some(barrier) = state.consumer_upgrade_barrier.as_ref() {
        barrier
            .wait_before_upgrade(state.limits.operation_timeout)
            .await;
    }
    if let Some(route) = selected_route.as_ref()
        && let Some(catalog) = state.catalog.as_ref()
        && let Err(error) =
            revalidate_owner_before_upgrade(catalog, route, state.limits.operation_timeout).await
    {
        return peer_failure_response(error);
    }
    upgrade
        .protocols([ECHO_STREAM_SUBPROTOCOL])
        .max_message_size(MAX_BODY_BYTES.saturating_add(4))
        .max_frame_size(MAX_BODY_BYTES.saturating_add(4))
        .write_buffer_size(0)
        .max_write_buffer_size(MAX_ECHO_WRITE_BYTES)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            let _scope_permit = scope_permit;
            if dispatch_peer.as_ref().is_some_and(|peer| !peer.is_ready()) {
                let mut socket = socket;
                let _ = send_socket(&mut socket, Message::Close(None)).await;
                return;
            }
            if let Some((route, admission)) = remote {
                handle_remote_consumer_stream(
                    socket,
                    handle,
                    route,
                    service_id,
                    consumer_expires_at,
                    admission,
                )
                .await;
            } else if let Some((registration, cleanup)) = local {
                registration.claim_admission();
                handle_consumer_stream(
                    socket,
                    handle,
                    registration,
                    cleanup,
                    device_id,
                    service_id,
                    consumer_expires_at,
                )
                .await;
            }
        })
        .into_response()
}

async fn handle_consumer_stream(
    mut socket: WebSocket,
    handle: RelayHandle,
    registration: ConsumerStreamRegistration,
    mut cleanup: TerminalCleanupGuard,
    device_id: Uuid,
    service_id: Uuid,
    consumer_expires_at: chrono::DateTime<Utc>,
) {
    let key = registration.key.clone();
    let stream_id = registration.stream_id;
    let operation_id = registration.operation_id.clone();
    let mut assembler = ConsumerRecordAssembler::new(STREAM_RECORD_LIMIT);
    let expires_in = (consumer_expires_at - Utc::now())
        .to_std()
        .unwrap_or_default();
    let expires = tokio::time::sleep(expires_in);
    tokio::pin!(expires);
    'connection: loop {
        let message = tokio::select! {
            biased;
            _ = registration.closed.cancelled() => break,
            _ = &mut expires => break,
            message = socket.next() => message,
        };
        let Some(message) = message else {
            break;
        };
        let message = match message {
            Ok(message) => message,
            Err(_) => break,
        };
        match message {
            Message::Binary(bytes) => {
                // The shared bounded decision: the input window is checked
                // before any copy and an over-limit prefix is rejected as soon
                // as it is complete, even without a body.
                if let Err(rejection) = assembler.push(&bytes) {
                    tracing::debug!(
                        rejection = ?rejection,
                        phase = rejection.phase(),
                        ingress = "local",
                        "consumer record rejected"
                    );
                    break 'connection;
                }
                loop {
                    let body = match assembler.next_body() {
                        Ok(Some(body)) => body,
                        Ok(None) => break,
                        Err(rejection) => {
                            tracing::debug!(
                                rejection = ?rejection,
                                phase = rejection.phase(),
                                ingress = "local",
                                "consumer record rejected"
                            );
                            break 'connection;
                        }
                    };
                    // The write stays inside the same closure/deadline scope
                    // as the read loop: a parked record cannot hold this
                    // stream past its absolute authorization deadline or past
                    // the owner closing it.
                    let result = match write_until_closed_or_expired(
                        handle.write_echo_stream(
                            key.clone(),
                            stream_id,
                            operation_id.clone(),
                            body,
                        ),
                        &registration.closed,
                        &mut expires,
                    )
                    .await
                    {
                        BoundedStreamWrite::Completed(result) => result,
                        BoundedStreamWrite::StreamClosed | BoundedStreamWrite::Expired => {
                            break 'connection;
                        }
                    };
                    let Ok(response) = result else {
                        break 'connection;
                    };
                    if response.len() < 4 {
                        break 'connection;
                    }
                    let response_len =
                        u32::from_be_bytes([response[0], response[1], response[2], response[3]])
                            as usize;
                    if response_len > MAX_BODY_BYTES.saturating_add(MAX_ECHO_CANARY_BYTES)
                        || response_len.saturating_add(4) != response.len()
                    {
                        break 'connection;
                    }
                    let outcome =
                        send_socket_outcome(&mut socket, Message::Binary(response.into())).await;
                    if outcome.is_timed_out() {
                        let _ = handle
                            .record_consumer_response_timeout(ConsumerWriteScope::new(
                                device_id,
                                service_id,
                                ConsumerIngressKind::Local,
                            ))
                            .await;
                    }
                    if !outcome.is_sent() {
                        break 'connection;
                    }
                }
            }
            Message::Ping(payload) => {
                if !send_socket(&mut socket, Message::Pong(payload)).await {
                    break;
                }
            }
            Message::Close(_) => {
                // Tungstenite queues the peer's close reply while reading.
                // Flush it before dropping the upgraded TLS connection.
                let _ = timeout(Duration::from_secs(5), socket.flush()).await;
                break;
            }
            Message::Pong(_) => {}
            Message::Text(_) => break,
        }
    }
    let _ = send_socket(&mut socket, Message::Close(None)).await;
    if matches!(
        timeout(
            Duration::from_secs(5),
            handle.close_echo_stream(key, stream_id, operation_id),
        )
        .await,
        Ok(true)
    ) {
        cleanup.disarm();
    }
}

async fn handle_remote_consumer_stream(
    mut socket: WebSocket,
    handle: RelayHandle,
    route: OwnerRoute,
    service_id: Uuid,
    consumer_expires_at: chrono::DateTime<Utc>,
    admission: RemoteConsumerAdmission,
) {
    let (request_id, mut send, mut recv) = admission.into_parts();
    let owner = route.owner_token();
    let diagnostic_context = PeerConsumerDiagnosticContext {
        tenant_id: owner.tenant_id,
        device_id: owner.device_id,
        session_id: owner.session_id.clone(),
        epoch: owner.epoch,
        service_id,
        request_id,
    };
    let expires_in = (consumer_expires_at - Utc::now())
        .to_std()
        .unwrap_or_default();
    let consumer_deadline = tokio::time::Instant::now() + expires_in;
    let expires = tokio::time::sleep_until(consumer_deadline);
    tokio::pin!(expires);

    // Keep peer request writes in a dedicated bounded pump.  The old
    // single-task loop awaited `send_message` while it was also responsible
    // for reading the owner response.  Once HTTP/3 request credit filled,
    // that await could hold the loop until the transport idle timeout while
    // the owner response remained unread. The bounded pump retains at most
    // three complete public frames across its in-flight, queued, and pending
    // slots, emits their records in order, and retains the transport's
    // existing per-record/byte limits.
    let (forward_tx, mut forward_rx) = mpsc::channel::<Vec<u8>>(1);
    let (stop_forward_tx, mut stop_forward_rx) = oneshot::channel();
    let mut forwarder = Box::pin(async move {
        while let Some(bytes) = tokio::select! {
            biased;
            _ = &mut stop_forward_rx => {
                // Stop is terminal for this exchange. Cancelling an
                // in-flight record is safe because the stream is cancelled
                // below and the frame is never retried on another carrier.
                send.cancel();
                return Ok::<_, (PeerRuntimeError, usize, usize)>(());
            }
            bytes = forward_rx.recv() => bytes,
        } {
            for chunk in bytes.chunks(MAX_CONSUMER_PEER_BODY) {
                let chunk_len = chunk.len();
                let result = tokio::select! {
                    biased;
                    _ = &mut stop_forward_rx => {
                        // The handler is tearing down this exchange, so do
                        // not resume a partially written record.
                        send.cancel();
                        return Ok(());
                    }
                    result = send.send_message(PeerRecordKind::ConsumerChunk, chunk) => result,
                };
                if let Err(error) = result {
                    send.cancel();
                    return Err((error, bytes.len(), chunk_len));
                }
            }
        }
        send.cancel();
        Ok(())
    });
    let mut forwarder_finished = false;
    let mut prefer_remote = true;
    // Same bounded decision as the owner-local handler, taken on the ingress
    // before any byte is queued for the peer: an over-limit prefix closes the
    // public stream here and is never forwarded.
    let mut cursor = ConsumerRecordCursor::new(STREAM_RECORD_LIMIT);

    enum RemoteConsumerEvent<Inbound, Remote> {
        Expired,
        Inbound(Inbound),
        Remote(Remote),
        ForwardReady,
        ForwardClosed,
        ForwardDone(Result<(), (PeerRuntimeError, usize, usize)>),
    }

    // At most three complete public frames are retained: one in the pump,
    // one in the channel, and one outside the channel. Keeping the last one
    // outside makes reserve() cancellation-safe: if a response wins the
    // select, that frame remains available for the next iteration rather
    // than being dropped with a cancelled send future. The WebSocket reader
    // is intentionally paused while all three slots are occupied; the pump's
    // existing transport idle deadline and this exchange's absolute expiry
    // bound how long Ping/Close can wait without consuming another Binary
    // frame into an unaccounted queue.
    let mut pending_forward = None;
    loop {
        let event = if pending_forward.is_some() {
            if prefer_remote {
                tokio::select! {
                    biased;
                    _ = &mut expires => RemoteConsumerEvent::Expired,
                    forward_done = &mut forwarder => RemoteConsumerEvent::ForwardDone(forward_done),
                    remote = recv.recv_message() => RemoteConsumerEvent::Remote(remote),
                    slot = forward_tx.reserve() => {
                        match slot {
                            Ok(slot) => {
                                slot.send(pending_forward.take().expect("pending frame"));
                                RemoteConsumerEvent::ForwardReady
                            }
                            Err(_) => RemoteConsumerEvent::ForwardClosed,
                        }
                    }
                }
            } else {
                tokio::select! {
                    biased;
                    _ = &mut expires => RemoteConsumerEvent::Expired,
                    forward_done = &mut forwarder => RemoteConsumerEvent::ForwardDone(forward_done),
                    slot = forward_tx.reserve() => {
                        match slot {
                            Ok(slot) => {
                                slot.send(pending_forward.take().expect("pending frame"));
                                RemoteConsumerEvent::ForwardReady
                            }
                            Err(_) => RemoteConsumerEvent::ForwardClosed,
                        }
                    }
                    remote = recv.recv_message() => RemoteConsumerEvent::Remote(remote),
                }
            }
        } else if prefer_remote {
            tokio::select! {
                biased;
                _ = &mut expires => RemoteConsumerEvent::Expired,
                forward_done = &mut forwarder => RemoteConsumerEvent::ForwardDone(forward_done),
                remote = recv.recv_message() => RemoteConsumerEvent::Remote(remote),
                inbound = socket.next() => RemoteConsumerEvent::Inbound(inbound),
            }
        } else {
            tokio::select! {
                biased;
                _ = &mut expires => RemoteConsumerEvent::Expired,
                forward_done = &mut forwarder => RemoteConsumerEvent::ForwardDone(forward_done),
                inbound = socket.next() => RemoteConsumerEvent::Inbound(inbound),
                remote = recv.recv_message() => RemoteConsumerEvent::Remote(remote),
            }
        };
        prefer_remote = !prefer_remote;

        match event {
            RemoteConsumerEvent::Expired | RemoteConsumerEvent::ForwardClosed => break,
            RemoteConsumerEvent::ForwardReady => {}
            RemoteConsumerEvent::ForwardDone(result) => {
                forwarder_finished = true;
                match result {
                    Ok(()) => {}
                    Err((error, body_len, chunk_len)) => {
                        let (outcome, h3_code) = peer_consumer_diagnostic_outcome(&error);
                        handle.record_peer_consumer_diagnostic(
                            &diagnostic_context,
                            PeerConsumerDiagnosticRole::IngressSend,
                            outcome,
                            h3_code,
                        );
                        tracing::debug!(
                            error = ?error,
                            body_len,
                            chunk_len,
                            phase = "consumer_peer_forward",
                            "consumer peer request forwarding failed"
                        );
                    }
                }
                break;
            }
            RemoteConsumerEvent::Inbound(inbound) => {
                let Some(inbound) = inbound else {
                    break;
                };
                let Ok(message) = inbound else {
                    break;
                };
                match message {
                    Message::Binary(bytes) => match cursor.forward(&bytes) {
                        Ok(forwardable) => {
                            if !forwardable.is_empty() {
                                pending_forward = Some(forwardable);
                            }
                        }
                        Err(rejection) => {
                            tracing::debug!(
                                rejection = ?rejection,
                                phase = rejection.phase(),
                                ingress = "forwarded",
                                "consumer record rejected"
                            );
                            break;
                        }
                    },
                    Message::Ping(payload) => {
                        if !send_socket_until(
                            &mut socket,
                            Message::Pong(payload),
                            consumer_deadline,
                        )
                        .await
                        {
                            break;
                        }
                    }
                    Message::Close(_) => break,
                    Message::Pong(_) => {}
                    Message::Text(_) => break,
                }
            }
            RemoteConsumerEvent::Remote(remote) => {
                let record = match remote {
                    Ok(Some(record)) => record,
                    Ok(None) => {
                        handle.record_peer_consumer_diagnostic(
                            &diagnostic_context,
                            PeerConsumerDiagnosticRole::IngressReceive,
                            PeerTransportDiagnosticOutcome::Closed,
                            None,
                        );
                        tracing::debug!(
                            phase = "consumer_peer_stream_end",
                            "consumer peer stream ended"
                        );
                        break;
                    }
                    Err(error) => {
                        let (outcome, h3_code) = peer_consumer_diagnostic_outcome(&error);
                        handle.record_peer_consumer_diagnostic(
                            &diagnostic_context,
                            PeerConsumerDiagnosticRole::IngressReceive,
                            outcome,
                            h3_code,
                        );
                        tracing::debug!(error = %error, phase = "consumer_peer_receive", "remote consumer receive failed");
                        break;
                    }
                };
                match record.kind() {
                    PeerRecordKind::ConsumerChunk => {
                        let outcome = send_socket_outcome_until(
                            &mut socket,
                            Message::Binary(record.body().to_vec().into()),
                            consumer_deadline,
                        )
                        .await;
                        if outcome.is_timed_out() {
                            let _ = timeout_at(
                                consumer_deadline,
                                handle.record_consumer_response_timeout(ConsumerWriteScope::new(
                                    route.owner_token().device_id,
                                    service_id,
                                    ConsumerIngressKind::Forwarded,
                                )),
                            )
                            .await;
                        }
                        if !outcome.is_sent() {
                            tracing::debug!(
                                body_len = record.body_len(),
                                phase = "consumer_public_response_send",
                                "consumer response forwarding failed"
                            );
                            break;
                        }
                    }
                    PeerRecordKind::Close => break,
                    _ => break,
                }
            }
        }
    }
    drop(forward_tx);
    let _ = stop_forward_tx.send(());
    if !forwarder_finished {
        let _ = forwarder.await;
    }
    recv.cancel();
    let _ = send_socket_until(&mut socket, Message::Close(None), consumer_deadline).await;
}

async fn service_and_grant(
    state: &HttpState,
    consumer: &tunnel_catalog::AuthenticatedConsumer,
    device_id: Uuid,
    service: &str,
) -> Result<(Uuid, tunnel_catalog::GrantSnapshot), Response> {
    let filter = DeviceListFilter::default();
    let Some(catalog) = state.catalog.as_ref() else {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTHORIZATION_UNAVAILABLE",
            "catalog unavailable",
            "not_dispatched",
        ));
    };
    let devices = catalog
        .list_devices_filtered(consumer, &filter, Utc::now())
        .await
        .map_err(catalog_error)?;
    let device = devices
        .into_iter()
        .find(|summary| summary.device_id == device_id)
        .ok_or_else(|| {
            error_response(
                StatusCode::NOT_FOUND,
                "DEVICE_NOT_FOUND",
                "not found",
                "not_dispatched",
            )
        })?;
    // The shared resolver decides identifier-versus-label, existence and
    // ambiguity for every path; this route only maps its typed outcome onto
    // the public response and never selects a first match itself.
    let service_id = resolve_echo_service(&device.services, ServiceTarget::parse(service))
        .map_err(service_resolution_response)?;
    let read_started = Utc::now();
    let grant = catalog
        .authorize(consumer, device_id, service_id, read_started, Utc::now())
        .await
        .map_err(catalog_error)?
        .ok_or_else(|| {
            error_response(
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                "service is not authorized",
                "not_dispatched",
            )
        })?;
    Ok((service_id, grant))
}

async fn authenticate(
    state: &HttpState,
    headers: &HeaderMap,
    scope: Option<&str>,
) -> Result<tunnel_catalog::AuthenticatedConsumer, Response> {
    let authorization = bearer(headers);
    let (Some(catalog), Some(oidc)) = (state.catalog.as_ref(), state.oidc.as_ref()) else {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTHORIZATION_UNAVAILABLE",
            "catalog unavailable",
            "not_dispatched",
        ));
    };
    match scope {
        Some(scope) => oidc
            .authenticate_for_scope(&**catalog, authorization, None, scope)
            .await
            .map(|value| value.consumer),
        None => oidc.authenticate(&**catalog, authorization, None).await,
    }
    .map_err(|_| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "consumer authentication failed",
            "not_dispatched",
        )
    })
}

fn bearer(headers: &HeaderMap) -> &str {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
}

// Called after OIDC validation; peer envelopes carry the raw token and the
// owner reconstructs the Authorization header for independent validation.
fn forwarded_bearer_token(headers: &HeaderMap) -> &str {
    let authorization = bearer(headers);
    authorization
        .strip_prefix("Bearer ")
        .or_else(|| authorization.strip_prefix("bearer "))
        .unwrap_or("")
}

fn parse_uuid(value: &str) -> Result<Uuid, ()> {
    Uuid::parse_str(value).map_err(|_| ())
}

async fn control(
    State(state): State<HttpState>,
    identity: Option<Extension<TlsIdentity>>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    if let Some(response) = cluster_unready_response(&state) {
        return response;
    }
    if !subprotocol_offered(&headers, CONTROL_SUBPROTOCOL) {
        return error_response(
            StatusCode::UPGRADE_REQUIRED,
            "SUBPROTOCOL_REQUIRED",
            "control WebSocket subprotocol required",
            "not_dispatched",
        );
    }
    let Some(Extension(identity)) = identity else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "DEVICE_MTLS_REQUIRED",
            "device certificate required",
            "not_dispatched",
        );
    };
    let Ok(permit) = state.admission.clone().try_acquire_owned() else {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "SOCKET_LIMIT",
            "device socket capacity exhausted",
            "not_dispatched",
        );
    };
    upgrade
        .protocols([CONTROL_SUBPROTOCOL])
        .max_message_size(state.limits.max_control_bytes)
        .max_frame_size(state.limits.max_control_bytes)
        .write_buffer_size(0)
        .max_write_buffer_size(MAX_CONTROL_BYTES * 2)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            handle_control_ingress(socket, identity, state).await;
        })
        .into_response()
}

async fn data(
    State(state): State<HttpState>,
    identity: Option<Extension<TlsIdentity>>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    if let Some(response) = cluster_unready_response(&state) {
        return response;
    }
    if !subprotocol_offered(&headers, DATA_SUBPROTOCOL) {
        return error_response(
            StatusCode::UPGRADE_REQUIRED,
            "SUBPROTOCOL_REQUIRED",
            "data WebSocket subprotocol required",
            "not_dispatched",
        );
    }
    let Some(Extension(identity)) = identity else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "DEVICE_MTLS_REQUIRED",
            "device certificate required",
            "not_dispatched",
        );
    };
    let ticket = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .unwrap_or("")
        .to_owned();
    if ticket.is_empty() || ticket.len() > MAX_CONTROL_BYTES.saturating_sub(7) {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "DATA_TICKET_REQUIRED",
            "attachment ticket required",
            "not_dispatched",
        );
    }
    let Ok(permit) = state.admission.clone().try_acquire_owned() else {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "SOCKET_LIMIT",
            "device socket capacity exhausted",
            "not_dispatched",
        );
    };
    upgrade
        .protocols([DATA_SUBPROTOCOL])
        .max_message_size(tunnel_protocol::MAX_FRAME_LEN)
        .max_frame_size(tunnel_protocol::MAX_FRAME_LEN)
        .write_buffer_size(0)
        .max_write_buffer_size(tunnel_protocol::MAX_FRAME_LEN * 2)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            handle_data_ingress(socket, identity, ticket, state).await;
        })
        .into_response()
}

fn subprotocol_offered(headers: &HeaderMap, required: &str) -> bool {
    headers
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|candidate| candidate == required)
        })
}

async fn remote_device_route(
    state: &HttpState,
    identity: &TlsIdentity,
    allow_fresh_control: bool,
) -> Result<Option<(Arc<PeerRuntime>, OwnerRoute)>, PeerRuntimeError> {
    if state.peer.as_ref().is_some_and(|peer| !peer.is_ready()) {
        return Err(PeerRuntimeError::Membership(
            "cluster readiness unavailable".to_owned(),
        ));
    }
    let Some(peer) = state.peer.clone() else {
        return Ok(None);
    };
    let Some(catalog) = state.catalog.as_ref() else {
        return Err(PeerRuntimeError::Membership(
            "device owner catalog unavailable".to_owned(),
        ));
    };
    let device = catalog
        .resolve_device(&identity.spki_sha256().to_hex(), Utc::now())
        .await
        .map_err(|error| {
            PeerRuntimeError::Routing(crate::routing::OwnerRoutingError::Catalog(error))
        })?
        .ok_or_else(|| {
            PeerRuntimeError::Membership("device credential is not active".to_owned())
        })?;
    let route = match peer
        .resolve(
            OwnerScope::new(device.tenant_id, device.device_id),
            Utc::now(),
        )
        .await
    {
        Ok(route) => route,
        Err(error) if allow_fresh_control && is_no_live_owner(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    match route {
        OwnerRoute::Remote { .. } => Ok(Some((peer, route))),
        OwnerRoute::Local { .. } => Ok(None),
    }
}

fn cluster_unready_response(state: &HttpState) -> Option<Response> {
    (!cluster_is_ready(state)).then(|| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "CLUSTER_UNREADY",
            "cluster readiness unavailable",
            "not_dispatched",
        )
    })
}

fn cluster_is_ready(state: &HttpState) -> bool {
    state.peer.as_ref().is_none_or(|peer| peer.is_ready())
}

async fn cluster_readiness_gate(
    State(state): State<HttpState>,
    request: Request,
    next: Next,
) -> Response {
    match cluster_unready_response(&state) {
        None => next.run(request).await,
        Some(response) => response,
    }
}

async fn handle_control_ingress(socket: WebSocket, identity: TlsIdentity, state: HttpState) {
    match remote_device_route(&state, &identity, true).await {
        Ok(Some((peer, route))) => {
            if let Err(error) = handle_remote_device_control(socket, identity, peer, route).await {
                tracing::debug!(?error, "remote device control forwarding stopped");
            }
        }
        Ok(None) => {
            if !cluster_is_ready(&state) {
                let mut socket = socket;
                let _ = send_socket(&mut socket, Message::Close(None)).await;
                return;
            }
            handle_control(socket, identity, state.handle).await;
        }
        Err(error) => {
            tracing::debug!(?error, "device control owner lookup failed");
            let mut socket = socket;
            let _ = send_socket(&mut socket, Message::Close(None)).await;
        }
    }
}

async fn handle_data_ingress(
    socket: WebSocket,
    identity: TlsIdentity,
    ticket: String,
    state: HttpState,
) {
    match remote_device_route(&state, &identity, false).await {
        Ok(Some((peer, route))) => {
            if let Err(error) =
                handle_remote_device_data(socket, identity, ticket, peer, route).await
            {
                tracing::debug!(?error, "remote device data forwarding stopped");
            }
        }
        Ok(None) => {
            if !cluster_is_ready(&state) {
                let mut socket = socket;
                let _ = send_socket(&mut socket, Message::Close(None)).await;
                return;
            }
            handle_data(socket, identity, ticket, state.handle).await;
        }
        Err(error) => {
            tracing::debug!(?error, "device data owner lookup failed");
            let mut socket = socket;
            let _ = send_socket(&mut socket, Message::Close(None)).await;
        }
    }
}

fn is_no_live_owner(error: &PeerRuntimeError) -> bool {
    matches!(
        error,
        PeerRuntimeError::Routing(OwnerRoutingError::NoLiveOwner(_))
    )
}

async fn handle_remote_device_control(
    mut socket: WebSocket,
    identity: TlsIdentity,
    peer: Arc<PeerRuntime>,
    route: OwnerRoute,
) -> Result<(), PeerRuntimeError> {
    let request_id = Uuid::new_v4().to_string();
    let destination = Destination::new(route.owner_token().clone(), Uuid::nil());
    let authentication = device_authentication_context(
        &identity,
        peer.source(),
        &destination,
        &request_id,
        Utc::now(),
    )?;
    let envelope = RequestEnvelope::new(
        InternalRoute::DeviceControl,
        request_id.clone(),
        peer.source().clone(),
        destination,
        20_000,
        None,
        InternalRequest::DeviceControl(tunnel_cluster::envelope::DeviceControlRequest {
            stream_id: request_id,
            authentication,
        }),
    );
    let exchange = peer.open(&route, envelope).await?;
    let (mut send, mut recv) = exchange.split();
    loop {
        tokio::select! {
            inbound = socket.next() => {
                let Some(inbound) = inbound else { break; };
                let message = inbound.map_err(|_| PeerRuntimeError::Closed)?;
                match message {
                    Message::Text(text) if text.len() <= MAX_CONTROL_BYTES => {
                        send.send_message(PeerRecordKind::CompleteControlText, text.as_bytes()).await?;
                    }
                    Message::Ping(payload) => {
                        if !send_socket(&mut socket, Message::Pong(payload)).await { break; }
                    }
                    Message::Close(_) => break,
                    Message::Pong(_) => {}
                    _ => break,
                }
            }
            remote = recv.recv_message() => {
                let Some(record) = remote? else { break; };
                match record.kind() {
                    PeerRecordKind::CompleteControlText => {
                        let text = record.as_text().map_err(PeerRuntimeError::Frame)?;
                        if !send_socket(&mut socket, Message::Text(text.to_owned().into())).await { break; }
                    }
                    PeerRecordKind::Close => break,
                    _ => break,
                }
            }
        }
    }
    send.cancel();
    recv.cancel();
    let _ = send_socket(&mut socket, Message::Close(None)).await;
    Ok(())
}

async fn handle_remote_device_data(
    mut socket: WebSocket,
    identity: TlsIdentity,
    ticket: String,
    peer: Arc<PeerRuntime>,
    route: OwnerRoute,
) -> Result<(), PeerRuntimeError> {
    let request_id = Uuid::new_v4().to_string();
    let destination = Destination::new(route.owner_token().clone(), Uuid::nil());
    let authentication = device_authentication_context(
        &identity,
        peer.source(),
        &destination,
        &request_id,
        Utc::now(),
    )?;
    let envelope = RequestEnvelope::new(
        InternalRoute::DeviceData,
        request_id.clone(),
        peer.source().clone(),
        destination,
        20_000,
        None,
        InternalRequest::DeviceData(tunnel_cluster::envelope::DeviceDataRequest {
            stream_id: request_id,
            sequence: 1,
            authentication,
            bytes: Vec::new(),
        }),
    );
    let exchange = peer.open(&route, envelope).await?;
    let (mut send, mut recv) = exchange.split();
    // The ticket is private device-authentication material.  It is carried
    // only inside the mTLS peer stream before any data frame and is consumed
    // atomically by the owner actor; it is never copied into HTTP headers.
    let ticket_record = format!("Bearer {ticket}");
    send.send_message(
        PeerRecordKind::CompleteControlText,
        ticket_record.as_bytes(),
    )
    .await?;
    loop {
        tokio::select! {
            inbound = socket.next() => {
                let Some(inbound) = inbound else { break; };
                let message = inbound.map_err(|_| PeerRuntimeError::Closed)?;
                match message {
                    Message::Binary(bytes) if bytes.len() <= tunnel_protocol::frame::MAX_FRAME_LEN => {
                        send.send_message(PeerRecordKind::CompleteDeviceData, &bytes).await?;
                    }
                    Message::Ping(payload) => {
                        if !send_socket(&mut socket, Message::Pong(payload)).await { break; }
                    }
                    Message::Close(_) => break,
                    Message::Pong(_) => {}
                    _ => break,
                }
            }
            remote = recv.recv_message() => {
                let Some(record) = remote? else { break; };
                match record.kind() {
                    PeerRecordKind::CompleteDeviceData => {
                        if !send_socket(&mut socket, Message::Binary(record.body().to_vec().into())).await { break; }
                    }
                    PeerRecordKind::Close => break,
                    _ => break,
                }
            }
        }
    }
    send.cancel();
    recv.cancel();
    let _ = send_socket(&mut socket, Message::Close(None)).await;
    Ok(())
}

/// Build the owner-side callback installed on the private HTTP/3 listener.
///
/// The callback is deliberately after transport admission: the peer runtime
/// has already checked the peer certificate, signed membership binding, route
/// path, and first bounded envelope record.  This layer rechecks the current
/// Redis owner, envelope scope, device credential or consumer bearer, then
/// enters the same relay actor used by local device sockets.
pub fn peer_ingress_handler(
    handle: RelayHandle,
    catalog: SharedCatalog,
    oidc: Arc<OidcVerifier>,
    local_node_id: String,
    local_boot_id: String,
) -> impl PeerIngressHandler {
    move |request: InboundPeerRequest| {
        let handle = handle.clone();
        let catalog = catalog.clone();
        let oidc = oidc.clone();
        let local_node_id = local_node_id.clone();
        let local_boot_id = local_boot_id.clone();
        async move {
            handle_peer_ingress(
                request,
                handle,
                catalog,
                oidc,
                &local_node_id,
                &local_boot_id,
            )
            .await
        }
    }
}

async fn handle_peer_ingress(
    request: InboundPeerRequest,
    handle: RelayHandle,
    catalog: SharedCatalog,
    oidc: Arc<OidcVerifier>,
    local_node_id: &str,
    local_boot_id: &str,
) -> Result<(), PeerRuntimeError> {
    let envelope = request.envelope().clone();
    let destination = envelope.destination.clone();
    let now = Utc::now();
    let owner = catalog
        .current_owner(destination.tenant_id, destination.device_id, now)
        .await
        .map_err(|_| PeerRuntimeError::Membership("owner catalog unavailable".to_owned()))?
        .ok_or_else(|| PeerRuntimeError::Membership("owner is unavailable".to_owned()))?;
    if owner.token != destination.owner_token
        || owner.token.node_id != local_node_id
        || owner.token.boot_id != local_boot_id
        || owner.lease_expires_at <= now
    {
        return Err(PeerRuntimeError::Membership(
            "peer request is not for this owner".to_owned(),
        ));
    }
    let verified_peer = VerifiedPeerIdentity::from_verified_peer_binding(request.binding())
        .map_err(|_| PeerRuntimeError::Membership("peer envelope rejected".to_owned()))?;
    let owner_access = match &envelope.request {
        InternalRequest::ConsumerStreams(stream) => {
            let authorization = format!("Bearer {}", stream.bearer.token());
            Some(
                oidc.authenticate_for_scope(
                    &*catalog,
                    &authorization,
                    Some(destination.tenant_id),
                    &stream.required_scope,
                )
                .await
                .map_err(|_| {
                    PeerRuntimeError::Membership("consumer authentication failed".to_owned())
                })?,
            )
        }
        _ => None,
    };
    envelope
        .validate(now, &verified_peer, &destination, owner_access.as_ref())
        .map_err(|_| PeerRuntimeError::Membership("peer envelope rejected".to_owned()))?;

    match envelope.request.clone() {
        InternalRequest::DeviceControl(request_body) => {
            let device = resolve_peer_device(&catalog, &request_body.authentication, now).await?;
            handle_peer_device_control(request, handle, device).await
        }
        InternalRequest::DeviceData(request_body) => {
            let device = resolve_peer_device(&catalog, &request_body.authentication, now).await?;
            handle_peer_device_data(request, handle, device).await
        }
        InternalRequest::ConsumerStreams(request_body) => {
            let access = owner_access.ok_or_else(|| {
                PeerRuntimeError::Membership("consumer authentication failed".to_owned())
            })?;
            let grant = owner_stream_grant(
                &catalog,
                &access.consumer,
                destination.device_id,
                destination.service_id,
                access.expires_at,
            )
            .await?;
            handle_peer_consumer_stream(
                request,
                handle,
                access.consumer,
                destination.device_id,
                destination.service_id,
                grant,
                access.expires_at,
                request_body.stream_id,
            )
            .await
        }
        InternalRequest::Health(_) | InternalRequest::OperationStatus(_) => {
            let (mut send, _recv) = request.split();
            send.respond(StatusCode::OK).await?;
            send.finish().await
        }
    }
}

async fn resolve_peer_device(
    catalog: &SharedCatalog,
    authentication: &tunnel_cluster::envelope::DeviceAuthenticationContext,
    now: chrono::DateTime<Utc>,
) -> Result<tunnel_catalog::DeviceIdentity, PeerRuntimeError> {
    let certificate = &authentication.certificate;
    let device = catalog
        .resolve_device(&certificate.spki_fingerprint, now)
        .await
        .map_err(|_| PeerRuntimeError::Membership("device catalog unavailable".to_owned()))?
        .ok_or_else(|| {
            PeerRuntimeError::Membership("device credential is not active".to_owned())
        })?;
    if device.tenant_id != certificate.tenant_id
        || device.device_id != certificate.device_id
        || device.spki_fingerprint != certificate.spki_fingerprint
        || !device.device_active
        || !device.credential_active
        || device.credential_revoked_at.is_some()
        || device.expires_at <= now
    {
        return Err(PeerRuntimeError::Membership(
            "device credential is not active".to_owned(),
        ));
    }
    Ok(device)
}

async fn owner_stream_grant(
    catalog: &SharedCatalog,
    consumer: &tunnel_catalog::AuthenticatedConsumer,
    device_id: Uuid,
    service_id: Uuid,
    expires_at: chrono::DateTime<Utc>,
) -> Result<tunnel_catalog::GrantSnapshot, PeerRuntimeError> {
    let devices = catalog
        .list_devices_filtered(consumer, &DeviceListFilter::default(), Utc::now())
        .await
        .map_err(|_| PeerRuntimeError::Membership("device catalog unavailable".to_owned()))?;
    let Some(device) = devices
        .into_iter()
        .find(|device| device.device_id == device_id)
    else {
        return Err(PeerRuntimeError::Membership(
            "service is not available".to_owned(),
        ));
    };
    // The owner repeats the ingress decision through the same resolver.  The
    // envelope carries an identifier, never a label, so a duplicate label
    // cannot reach dispatch here either: an ambiguous or missing target is
    // refused before any stream is opened.
    let service_id = resolve_echo_service(&device.services, ServiceTarget::Id(service_id))
        .map_err(|error| PeerRuntimeError::Membership(error.to_string()))?;
    let grant = catalog
        .authorize(consumer, device_id, service_id, Utc::now(), Utc::now())
        .await
        .map_err(|_| PeerRuntimeError::Membership("authorization unavailable".to_owned()))?
        .ok_or_else(|| PeerRuntimeError::Membership("service is not authorized".to_owned()))?;
    if !grant.permissions.allows(crate::ECHO_OPERATION) {
        return Err(PeerRuntimeError::Membership(
            "service is not authorized".to_owned(),
        ));
    }
    let mut grant = grant;
    grant.valid_until = grant.valid_until.min(expires_at);
    Ok(grant)
}

async fn handle_peer_device_control(
    request: InboundPeerRequest,
    handle: RelayHandle,
    device: tunnel_catalog::DeviceIdentity,
) -> Result<(), PeerRuntimeError> {
    let spki = device.spki_fingerprint.clone();
    let (mut send, mut recv) = request.split();
    let first = recv.recv_message().await?.ok_or(PeerRuntimeError::Closed)?;
    if first.kind() != PeerRecordKind::CompleteControlText {
        return Err(PeerRuntimeError::UnexpectedRecord(first.kind()));
    }
    let message = wire::parse_control(first.body()).map_err(|_| PeerRuntimeError::Closed)?;
    let hello = match message {
        tunnel_protocol::ControlMessage::Hello(hello) => hello,
        _ => return Err(PeerRuntimeError::UnexpectedRecord(first.kind())),
    };
    let registration = handle
        .register_forwarded_control(device, spki, hello)
        .await
        .map_err(|_| PeerRuntimeError::Closed)?;
    let key = registration.key.clone();
    let welcome = registration.welcome;
    let mut outbound = registration.rx;
    let mut cleanup = handle.control_cleanup_guard(key.clone());
    let result: Result<(), PeerRuntimeError> = async {
        send.respond(StatusCode::OK).await?;
        send.send_message(PeerRecordKind::CompleteControlText, welcome.as_bytes())
            .await?;
        loop {
            tokio::select! {
                inbound = recv.recv_message() => {
                    let Some(record) = inbound? else { break; };
                    if record.kind() != PeerRecordKind::CompleteControlText {
                        break;
                    }
                    let message = wire::parse_control(record.body()).map_err(|_| PeerRuntimeError::Closed)?;
                    handle.inbound_control(key.clone(), message).await.map_err(|_| PeerRuntimeError::Closed)?;
                }
                item = outbound.recv() => {
                    match item {
                        Some(crate::actor::ControlOutbound::Text(mut text)) => {
                            let sent = send.send_message(PeerRecordKind::CompleteControlText, text.as_bytes()).await;
                            text.release();
                            sent?;
                        }
                        Some(crate::actor::ControlOutbound::Close) | None => break,
                    }
                }
            }
        }
        Ok(())
    }
    .await;
    outbound.close();
    while outbound.try_recv().is_ok() {}
    if result.is_err() {
        send.cancel();
        recv.cancel();
    }
    if matches!(
        timeout(Duration::from_secs(5), handle.disconnect_control(key)).await,
        Ok(true)
    ) {
        cleanup.disarm();
    }
    match result {
        Ok(()) => send.finish().await,
        Err(error) => Err(error),
    }
}

async fn handle_peer_device_data(
    request: InboundPeerRequest,
    handle: RelayHandle,
    device: tunnel_catalog::DeviceIdentity,
) -> Result<(), PeerRuntimeError> {
    let device_id = device.device_id;
    let spki = device.spki_fingerprint.clone();
    let (mut send, mut recv) = request.split();
    let ticket_record = recv.recv_message().await?.ok_or(PeerRuntimeError::Closed)?;
    if ticket_record.kind() != PeerRecordKind::CompleteControlText {
        return Err(PeerRuntimeError::UnexpectedRecord(ticket_record.kind()));
    }
    let ticket = ticket_record
        .as_text()
        .map_err(PeerRuntimeError::Frame)?
        .strip_prefix("Bearer ")
        .or_else(|| ticket_record.as_text().ok()?.strip_prefix("bearer "))
        .ok_or(PeerRuntimeError::Closed)?
        .to_owned();
    let registration = handle
        .attach_forwarded_data(device, spki, ticket)
        .await
        .map_err(|_| PeerRuntimeError::Closed)?;
    let carrier = registration.carrier.clone();
    let mut outbound = registration.rx;
    let mut cleanup = handle.data_cleanup_guard(carrier.clone());
    let result: Result<(), PeerRuntimeError> = async {
        if let Err(error) = send.respond(StatusCode::OK).await {
            handle.record_peer_transport_diagnostic(
                device_id,
                &carrier,
                PeerTransportDiagnosticRole::OwnerSend,
                peer_transport_diagnostic_outcome(&error),
            );
            return Err(error);
        }
        loop {
            tokio::select! {
                inbound = recv.recv_message() => {
                    let record = match inbound {
                        Ok(Some(record)) => record,
                        Ok(None) => {
                            handle.record_peer_transport_diagnostic(
                                device_id,
                                &carrier,
                                PeerTransportDiagnosticRole::IngressReceive,
                                PeerTransportDiagnosticOutcome::Closed,
                            );
                            break;
                        }
                        Err(error) => {
                            handle.record_peer_transport_diagnostic(
                                device_id,
                                &carrier,
                                PeerTransportDiagnosticRole::IngressReceive,
                                peer_transport_diagnostic_outcome(&error),
                            );
                            Err(error)?
                        }
                    };
                    if record.kind() == PeerRecordKind::Close {
                        handle.record_peer_transport_diagnostic(
                            device_id,
                            &carrier,
                            PeerTransportDiagnosticRole::IngressReceive,
                            PeerTransportDiagnosticOutcome::Closed,
                        );
                        break;
                    }
                    if record.kind() != PeerRecordKind::CompleteDeviceData {
                        handle.record_peer_transport_diagnostic(
                            device_id,
                            &carrier,
                            PeerTransportDiagnosticRole::IngressReceive,
                            PeerTransportDiagnosticOutcome::ProtocolError,
                        );
                        break;
                    }
                    handle.inbound_data(carrier.clone(), record.body().to_vec()).await.map_err(|_| PeerRuntimeError::Closed)?;
                }
                item = outbound.recv() => {
                    match item {
                        Some(crate::actor::DataOutbound::Binary(mut bytes)) => {
                            let sent = send.send_message(PeerRecordKind::CompleteDeviceData, bytes.as_slice()).await;
                            if let Err(error) = &sent {
                                handle.record_peer_transport_diagnostic(
                                    device_id,
                                    &carrier,
                                    PeerTransportDiagnosticRole::OwnerSend,
                                    peer_transport_diagnostic_outcome(error),
                                );
                            }
                            bytes.release();
                            sent?;
                        }
                        Some(crate::actor::DataOutbound::Barrier(done)) => { let _ = done.send(()); }
                        Some(crate::actor::DataOutbound::Close) | None => break,
                    }
                }
            }
        }
        Ok(())
    }
    .await;
    outbound.close();
    while outbound.try_recv().is_ok() {}
    if result.is_err() {
        send.cancel();
        recv.cancel();
    }
    if matches!(
        timeout(Duration::from_secs(5), handle.disconnect_data(carrier)).await,
        Ok(true)
    ) {
        cleanup.disarm();
    }
    match result {
        Ok(()) => match send.finish().await {
            Ok(()) => Ok(()),
            Err(error) => {
                handle.record_peer_transport_diagnostic(
                    device_id,
                    &registration.carrier,
                    PeerTransportDiagnosticRole::OwnerSend,
                    peer_transport_diagnostic_outcome(&error),
                );
                Err(error)
            }
        },
        Err(error) => Err(error),
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_peer_consumer_stream(
    request: InboundPeerRequest,
    handle: RelayHandle,
    consumer: tunnel_catalog::AuthenticatedConsumer,
    device_id: Uuid,
    service_id: Uuid,
    grant: tunnel_catalog::GrantSnapshot,
    consumer_expires_at: chrono::DateTime<Utc>,
    _stream_id: String,
) -> Result<(), PeerRuntimeError> {
    let request_id = request.envelope().request_id.clone();
    // Keep the shared admission reason alive through request splitting. The
    // membership invalidation may happen while this logical stream is in
    // flight; sampling before the split would turn that typed expiry into a
    // generic close.
    let admission_context = request.admission_cancellation_context();
    let admission_context_for_wait = admission_context.clone();
    let admission_cancelled = async move {
        if let Some(admission) = admission_context_for_wait {
            admission.cancelled().await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    tokio::pin!(admission_cancelled);
    let registration = match handle
        .open_forwarded_echo_stream(
            consumer,
            device_id,
            service_id,
            grant,
            consumer_expires_at,
            request_id.clone(),
        )
        .await
    {
        Ok(registration) => registration,
        Err(RelayError::OwnerNotReady) => {
            // The actor raises this only after identity/scope/profile checks,
            // while the authenticated owner carrier or fence is still
            // incomplete.  Return a bounded H3 admission response before the
            // peer request is split or any ConsumerChunk body is read.
            return request.reject_owner_not_ready().await;
        }
        Err(RelayError::StreamLimit) => return request.reject_stream_limit().await,
        Err(_) => return Err(PeerRuntimeError::Closed),
    };
    registration.claim_admission();
    let key = registration.key.clone();
    let diagnostic_context = PeerConsumerDiagnosticContext {
        tenant_id: key.tenant_id,
        device_id: key.device_id,
        session_id: key.session_id.clone(),
        epoch: key.epoch,
        service_id,
        request_id,
    };
    let stream_id = registration.stream_id;
    let operation_id = registration.operation_id.clone();
    let (mut send, mut recv) = request.split();
    // The guard carries the admission edge: if membership invalidation drops
    // this future before the loop below can classify the exit, the enqueued
    // cleanup still resolves the typed first cause from that edge.
    let mut cleanup = handle.echo_cleanup_guard(
        key.clone(),
        stream_id,
        operation_id.clone(),
        admission_context.clone(),
    );
    let mut assembler = ConsumerRecordAssembler::new(STREAM_RECORD_LIMIT);
    let mut registration_closed = false;
    let mut terminal_cause = None;
    // The owner bounds this stream by the consumer's absolute authorization
    // deadline itself; the forwarding relay's own timer is not relied upon.
    let expires_in = (consumer_expires_at - Utc::now())
        .to_std()
        .unwrap_or_default();
    let expires = tokio::time::sleep(expires_in);
    tokio::pin!(expires);
    let result: Result<(), PeerRuntimeError> = async {
        if let Err(error) = send.respond(StatusCode::OK).await {
            if matches!(error, PeerRuntimeError::MembershipExpired) {
                terminal_cause = Some(StreamTerminalCause::PeerMembershipExpired);
            }
            let (outcome, h3_code) = peer_consumer_diagnostic_outcome(&error);
            handle.record_peer_consumer_diagnostic(
                &diagnostic_context,
                PeerConsumerDiagnosticRole::OwnerSend,
                outcome,
                h3_code,
            );
            return Err(error);
        }
        'peer: loop {
            tokio::select! {
                _ = &mut admission_cancelled => {
                    if admission_context.as_ref().is_some_and(|admission| {
                        admission.reason() == Some(crate::PeerInvalidationReason::TrustExpired)
                    }) {
                        terminal_cause = Some(StreamTerminalCause::PeerMembershipExpired);
                    }
                    break;
                }
                _ = registration.closed.cancelled() => {
                    registration_closed = true;
                    break;
                }
                _ = &mut expires => {
                    // Authorization expiry ends the idle owner-side stream on
                    // the same graceful path as owner-initiated closure.
                    break;
                }
                inbound = recv.recv_message() => {
                    let record = match inbound {
                        Ok(Some(record)) => record,
                        Ok(None) => {
                            handle.record_peer_consumer_diagnostic(
                                &diagnostic_context,
                                PeerConsumerDiagnosticRole::OwnerReceive,
                                PeerTransportDiagnosticOutcome::Closed,
                                None,
                            );
                            tracing::debug!(phase = "consumer_peer_stream_end", "consumer peer stream ended");
                            break;
                        }
                        Err(error) => {
                            if matches!(error, PeerRuntimeError::MembershipExpired) {
                                terminal_cause = Some(StreamTerminalCause::PeerMembershipExpired);
                            }
                            let (outcome, h3_code) = peer_consumer_diagnostic_outcome(&error);
                            handle.record_peer_consumer_diagnostic(
                                &diagnostic_context,
                                PeerConsumerDiagnosticRole::OwnerReceive,
                                outcome,
                                h3_code,
                            );
                            return Err(error);
                        }
                    };
                    if record.kind() != PeerRecordKind::ConsumerChunk {
                        tracing::debug!(kind = ?record.kind(), phase = "consumer_peer_record_kind", "consumer peer record kind rejected");
                        break;
                    }
                    // Count the authenticated peer record synchronously before
                    // any bounded input parsing or application dispatch.
                    handle.record_consumer_chunk_read();
                    // The same shared decision as both public ingress paths:
                    // an over-limit prefix from a peer is rejected as soon as
                    // it is complete instead of being retained as an
                    // incomplete record.
                    if let Err(rejection) = assembler.push(record.body()) {
                        tracing::debug!(
                            rejection = ?rejection,
                            phase = rejection.phase(),
                            ingress = "owner_peer",
                            "consumer peer record rejected"
                        );
                        break;
                    }
                    loop {
                        let body = match assembler.next_body() {
                            Ok(Some(body)) => body,
                            Ok(None) => break,
                            Err(rejection) => {
                                tracing::debug!(
                                    rejection = ?rejection,
                                    phase = rejection.phase(),
                                    ingress = "owner_peer",
                                    "consumer peer record rejected"
                                );
                                break 'peer;
                            }
                        };
                        let body_len = body.len();
                        let response = tokio::select! {
                            _ = &mut admission_cancelled => {
                                if admission_context.as_ref().is_some_and(|admission| {
                                    admission.reason() == Some(crate::PeerInvalidationReason::TrustExpired)
                                }) {
                                    terminal_cause = Some(StreamTerminalCause::PeerMembershipExpired);
                                    return Err(PeerRuntimeError::MembershipExpired);
                                }
                                return Err(PeerRuntimeError::Closed);
                            }
                            waited = write_until_closed_or_expired(
                                handle.write_echo_stream(
                                    key.clone(),
                                    stream_id,
                                    operation_id.clone(),
                                    body,
                                ),
                                &registration.closed,
                                &mut expires,
                            ) => match waited {
                                BoundedStreamWrite::Completed(Ok(response)) => response,
                                BoundedStreamWrite::Completed(Err(error)) => {
                                    tracing::debug!(
                                        error = ?error,
                                        body_len,
                                        phase = "consumer_actor_response",
                                        "consumer actor response failed"
                                    );
                                    return Err(PeerRuntimeError::Closed);
                                }
                                BoundedStreamWrite::StreamClosed => {
                                    // The owner closed the stream while this
                                    // record was outstanding.  Its outcome is
                                    // unknown, exactly like a failed actor
                                    // reply, so the same typed error applies.
                                    registration_closed = true;
                                    tracing::debug!(
                                        body_len,
                                        phase = "consumer_actor_stream_closed",
                                        "owner closed the stream while a record was outstanding"
                                    );
                                    return Err(PeerRuntimeError::Closed);
                                }
                                BoundedStreamWrite::Expired => {
                                    tracing::debug!(
                                        body_len,
                                        phase = "consumer_actor_write_expired",
                                        "consumer authorization expired while a record was outstanding"
                                    );
                                    return Err(PeerRuntimeError::Closed);
                                }
                            }
                        };
                        // The actor returns the complete length-prefixed echo record,
                        // exactly as it does for local consumer ingress.
                        if response.len() < 4 {
                            tracing::debug!(body_len, phase = "consumer_peer_response_length", "consumer actor response omitted length");
                            return Err(PeerRuntimeError::Closed);
                        }
                        let response_len = u32::from_be_bytes([response[0], response[1], response[2], response[3]]) as usize;
                        if response_len > MAX_BODY_BYTES.saturating_add(MAX_ECHO_CANARY_BYTES)
                            || response_len.saturating_add(4) != response.len()
                        {
                            tracing::debug!(
                                body_len,
                                response_len,
                                response_bytes = response.len(),
                                phase = "consumer_peer_response_limit",
                                "consumer actor response exceeded bounded length"
                            );
                            return Err(PeerRuntimeError::Closed);
                        }
                        for chunk in response.chunks(MAX_CONSUMER_PEER_BODY) {
                            if let Err(error) =
                                send.send_message(PeerRecordKind::ConsumerChunk, chunk).await
                            {
                                if matches!(error, PeerRuntimeError::MembershipExpired) {
                                    terminal_cause = Some(StreamTerminalCause::PeerMembershipExpired);
                                }
                                let (outcome, h3_code) =
                                    peer_consumer_diagnostic_outcome(&error);
                                handle.record_peer_consumer_diagnostic(
                                    &diagnostic_context,
                                    PeerConsumerDiagnosticRole::OwnerSend,
                                    outcome,
                                    h3_code,
                                );
                                return Err(error);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
    .await;
    // Context-aware first cause, sampled at loop exit: the ingress relay
    // enforces the same signed trust deadline and may reset or end this
    // pooled stream before the owner's invalidation dispatcher runs.  The
    // admission edge's typed reason or its own passed monotonic deadline is
    // positive evidence of the earlier cause; a stream the actor closed
    // itself keeps the actor's recorded reason.
    if terminal_cause.is_none()
        && !registration_closed
        && admission_context
            .as_ref()
            .is_some_and(|admission| admission.trust_expired())
    {
        terminal_cause = Some(StreamTerminalCause::PeerMembershipExpired);
    }
    let result = match result {
        Ok(()) => match send.finish().await {
            Ok(()) => Ok(()),
            Err(error) => {
                if !registration_closed && matches!(error, PeerRuntimeError::MembershipExpired) {
                    terminal_cause = Some(StreamTerminalCause::PeerMembershipExpired);
                }
                let (outcome, h3_code) = peer_consumer_diagnostic_outcome(&error);
                handle.record_peer_consumer_diagnostic(
                    &diagnostic_context,
                    PeerConsumerDiagnosticRole::OwnerSend,
                    outcome,
                    h3_code,
                );
                Err(error)
            }
        },
        Err(error) => Err(error),
    };
    if result.is_err() {
        send.cancel();
        recv.cancel();
    }
    if matches!(
        timeout(
            Duration::from_secs(5),
            handle.close_echo_stream_with_cause(key, stream_id, operation_id, terminal_cause,),
        )
        .await,
        Ok(true)
    ) {
        cleanup.disarm();
    }
    result
}

async fn handle_control(mut socket: WebSocket, identity: TlsIdentity, handle: RelayHandle) {
    let first = match timeout(Duration::from_secs(10), socket.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => text,
        _ => return,
    };
    let hello = match wire::parse_control(first.as_bytes()) {
        Ok(value) => value,
        Err(_) => return,
    };
    let registration = match handle.register_control(identity, hello).await {
        Ok(value) => value,
        Err(error) => {
            if matches!(error, RelayError::OwnerBusy) {
                let _ = send_socket(&mut socket, owner_busy_close()).await;
            }
            return;
        }
    };
    let key = registration.key.clone();
    let mut cleanup = handle.control_cleanup_guard(key.clone());
    if !send_socket(&mut socket, Message::Text(registration.welcome.into())).await {
        if matches!(
            timeout(Duration::from_secs(5), handle.disconnect_control(key)).await,
            Ok(true)
        ) {
            cleanup.disarm();
        }
        return;
    }
    let mut rx = registration.rx;
    loop {
        tokio::select! {
            inbound = socket.next() => {
                match inbound {
                    Some(Ok(Message::Text(text))) if text.len() <= MAX_CONTROL_BYTES => {
                        if let Ok(message) = wire::parse_control(text.as_bytes()) {
                            let _ = handle.inbound_control(key.clone(), message).await;
                        } else { break; }
                    }
                    Some(Ok(Message::Ping(payload))) => { if !send_socket(&mut socket, Message::Pong(payload)).await { break; } }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => break,
                }
            }
            outbound = rx.recv() => {
                match outbound {
                    Some(crate::actor::ControlOutbound::Text(text)) => {
                        let (text, mut charge) = text.into_parts();
                        let sent = send_socket(&mut socket, Message::Text(text.into())).await;
                        charge.release();
                        if !sent { break; }
                    }
                    Some(crate::actor::ControlOutbound::Close) | None => { let _ = send_socket(&mut socket, Message::Close(None)).await; break; }
                }
            }
        }
    }
    // Close admission to this writer before releasing every queued charge.
    // The actor may still hold a sender until it processes the disconnect.
    rx.close();
    while rx.try_recv().is_ok() {}
    if matches!(
        timeout(Duration::from_secs(5), handle.disconnect_control(key)).await,
        Ok(true)
    ) {
        cleanup.disarm();
    }
}

async fn handle_data(
    mut socket: WebSocket,
    identity: TlsIdentity,
    ticket: String,
    handle: RelayHandle,
) {
    let registration = match handle.attach_data(identity, ticket).await {
        Ok(value) => value,
        Err(_) => return,
    };
    let carrier = registration.carrier.clone();
    let mut cleanup = handle.data_cleanup_guard(carrier.clone());
    let mut rx = registration.rx;
    loop {
        tokio::select! {
            inbound = socket.next() => {
                match inbound {
                    Some(Ok(Message::Binary(bytes))) if bytes.len() <= tunnel_protocol::frame::MAX_FRAME_LEN => {
                        let _ = handle.inbound_data(carrier.clone(), bytes.to_vec()).await;
                    }
                    Some(Ok(Message::Ping(payload))) => { if !send_socket(&mut socket, Message::Pong(payload)).await { break; } }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => break,
                }
            }
            outbound = rx.recv() => {
                match outbound {
                    Some(crate::actor::DataOutbound::Binary(bytes)) => {
                        let (bytes, mut charge) = bytes.into_parts();
                        let sent = send_socket(&mut socket, Message::Binary(bytes.into())).await;
                        charge.release();
                        if !sent { break; }
                    }
                    Some(crate::actor::DataOutbound::Barrier(done)) => {
                        let _ = done.send(());
                    }
                    Some(crate::actor::DataOutbound::Close) | None => { let _ = send_socket(&mut socket, Message::Close(None)).await; break; }
                }
            }
        }
    }
    rx.close();
    while rx.try_recv().is_ok() {}
    if matches!(
        timeout(Duration::from_secs(5), handle.disconnect_data(carrier)).await,
        Ok(true)
    ) {
        cleanup.disarm();
    }
}

fn owner_busy_close() -> Message {
    Message::Close(Some(CloseFrame {
        code: CONTROL_OWNER_BUSY_CLOSE_CODE,
        reason: CONTROL_OWNER_BUSY_CLOSE_REASON.into(),
    }))
}

async fn send_socket(socket: &mut WebSocket, message: Message) -> bool {
    send_socket_outcome(socket, message).await.is_sent()
}

async fn send_socket_until(
    socket: &mut WebSocket,
    message: Message,
    deadline: tokio::time::Instant,
) -> bool {
    send_socket_outcome_until(socket, message, deadline)
        .await
        .is_sent()
}

async fn send_socket_outcome(socket: &mut WebSocket, message: Message) -> ConsumerWriteOutcome {
    send_until(
        socket.send(message),
        tokio::time::Instant::now() + Duration::from_secs(5),
    )
    .await
}

async fn send_socket_outcome_until(
    socket: &mut WebSocket,
    message: Message,
    deadline: tokio::time::Instant,
) -> ConsumerWriteOutcome {
    send_until_or_expired(
        socket.send(message),
        tokio::time::Instant::now() + Duration::from_secs(5),
        deadline,
    )
    .await
}

/// Outcome of awaiting one actor stream write while the stream's closure
/// token and the consumer's absolute authorization deadline stay observable.
enum BoundedStreamWrite<T> {
    Completed(T),
    StreamClosed,
    Expired,
}

/// Await one actor stream write without losing sight of the stream.  The
/// actor fails waiters when it closes a stream, but a record parked behind a
/// pending device authorization is otherwise bounded by nothing the handler
/// observes.  Closure and the absolute deadline are checked first, matching
/// the handlers' read loops, so a ready or late response cannot outlive the
/// consumer's authorization.  An abandoned write has an unknown outcome; the
/// caller classifies it exactly as a failed actor reply.
async fn write_until_closed_or_expired<F>(
    write: F,
    closed: &tokio_util::sync::CancellationToken,
    expires: &mut std::pin::Pin<&mut tokio::time::Sleep>,
) -> BoundedStreamWrite<F::Output>
where
    F: std::future::Future,
{
    tokio::select! {
        biased;
        _ = closed.cancelled() => BoundedStreamWrite::StreamClosed,
        _ = expires.as_mut() => BoundedStreamWrite::Expired,
        result = write => BoundedStreamWrite::Completed(result),
    }
}

fn peer_transport_diagnostic_outcome(error: &PeerRuntimeError) -> PeerTransportDiagnosticOutcome {
    match error {
        PeerRuntimeError::Transport(error) => match error {
            PeerTransportError::Timeout => PeerTransportDiagnosticOutcome::TimedOut,
            PeerTransportError::GoAway => PeerTransportDiagnosticOutcome::GoAway,
            PeerTransportError::Cancelled => PeerTransportDiagnosticOutcome::Cancelled,
            PeerTransportError::H3(_) => PeerTransportDiagnosticOutcome::H3Error,
            PeerTransportError::Quic(_) => PeerTransportDiagnosticOutcome::QuicError,
            _ => PeerTransportDiagnosticOutcome::Other,
        },
        PeerRuntimeError::MembershipExpired => PeerTransportDiagnosticOutcome::TrustExpired,
        PeerRuntimeError::Closed => PeerTransportDiagnosticOutcome::Closed,
        PeerRuntimeError::Envelope(_)
        | PeerRuntimeError::Frame(_)
        | PeerRuntimeError::UnexpectedRecord(_) => PeerTransportDiagnosticOutcome::ProtocolError,
        _ => PeerTransportDiagnosticOutcome::Other,
    }
}

fn peer_consumer_diagnostic_outcome(
    error: &PeerRuntimeError,
) -> (
    PeerTransportDiagnosticOutcome,
    Option<PeerConsumerDiagnosticH3Code>,
) {
    let outcome = peer_transport_diagnostic_outcome(error);
    let h3_code = match error {
        PeerRuntimeError::Transport(PeerTransportError::H3(message)) => {
            Some(classify_h3_code(message))
        }
        _ => None,
    };
    (outcome, h3_code)
}

fn catalog_error(error: tunnel_catalog::CatalogError) -> Response {
    let _ = error;
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "AUTHORIZATION_UNAVAILABLE",
        "authorization catalog unavailable",
        "not_dispatched",
    )
}

fn failure_outcome(code: &'static str, execution: &'static str) -> Response {
    let status = if execution == "not_dispatched" && code == "FORBIDDEN" {
        StatusCode::FORBIDDEN
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    error_response(
        status,
        code,
        "reverse channel operation did not complete",
        execution,
    )
}

fn peer_failure_response(error: PeerRuntimeError) -> Response {
    let (status, code, execution) = match error {
        PeerRuntimeError::RemoteStatus(status) if status == StatusCode::UNAUTHORIZED => {
            (StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "not_dispatched")
        }
        PeerRuntimeError::RemoteStatus(status) if status == StatusCode::FORBIDDEN => {
            (StatusCode::FORBIDDEN, "FORBIDDEN", "not_dispatched")
        }
        PeerRuntimeError::PeerIdentityMismatch
        | PeerRuntimeError::Membership(_)
        | PeerRuntimeError::Routing(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "PEER_UNTRUSTED",
            "not_dispatched",
        ),
        PeerRuntimeError::Transport(PeerTransportError::GoAway) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "PEER_UNAVAILABLE",
            "not_dispatched",
        ),
        PeerRuntimeError::OwnerNotReady { retry_after_ms } => {
            return retryable_peer_failure_response(retry_after_ms);
        }
        PeerRuntimeError::Capacity { retry_after_ms } => {
            return stream_limit_response(retry_after_ms);
        }
        PeerRuntimeError::RemoteStatus(_)
        | PeerRuntimeError::Transport(_)
        | PeerRuntimeError::Envelope(_)
        | PeerRuntimeError::Frame(_)
        | PeerRuntimeError::InvalidEndpoint(_)
        | PeerRuntimeError::InvalidRoute(_)
        | PeerRuntimeError::UnexpectedRecord(_)
        | PeerRuntimeError::MembershipExpired
        | PeerRuntimeError::Closed => (
            StatusCode::SERVICE_UNAVAILABLE,
            "PEER_UNAVAILABLE",
            "unknown",
        ),
    };
    error_response(status, code, "owner forwarding did not complete", execution)
}

fn local_consumer_admission_response(error: RelayError) -> Response {
    match error {
        RelayError::OwnerNotReady => {
            retryable_peer_failure_response(OWNER_NOT_READY_RETRY_AFTER_MS)
        }
        RelayError::StreamLimit => stream_limit_response(STREAM_LIMIT_RETRY_AFTER_MS),
        RelayError::Forbidden => error_response(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "echo stream is not authorized",
            "not_dispatched",
        ),
        RelayError::NotFound => error_response(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "device or service was not found",
            "not_dispatched",
        ),
        _ => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "REVERSE_CHANNEL_UNAVAILABLE",
            "reverse channel operation did not complete",
            "unknown",
        ),
    }
}

fn retryable_peer_failure_response(retry_after_ms: u64) -> Response {
    let retry_after_ms = retry_after_ms.clamp(1, OWNER_NOT_READY_RETRY_AFTER_MS.max(1));
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorBody {
            code: "PEER_UNAVAILABLE",
            execution: "not_dispatched",
            message: "selected owner is not ready; retry after the bounded hint",
            retryable: Some(true),
            retry_after_ms: Some(retry_after_ms),
        }),
    )
        .into_response();
    let retry_after_seconds = retry_after_ms.saturating_add(999) / 1_000;
    if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// The typed consumer admission refusal, used for both the relay-global and
/// the per-owner bound.  Both are capacity, both are `not_dispatched`, and both
/// clear as soon as an in-flight operation completes, so the existing closed
/// refusal vocabulary already covers them: reusing `ADMISSION_LIMIT` with the
/// bounded retry hint keeps one typed outcome instead of inventing a second
/// code for the same condition.
fn admission_limit_response(retry_after_ms: u64) -> Response {
    let retry_after_ms = retry_after_ms.clamp(1, MAX_ADMISSION_LIMIT_RETRY_AFTER_MS);
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(ErrorBody {
            code: "ADMISSION_LIMIT",
            execution: "not_dispatched",
            message: "request capacity exhausted",
            retryable: Some(true),
            retry_after_ms: Some(retry_after_ms),
        }),
    )
        .into_response();
    let retry_after_seconds = retry_after_ms.saturating_add(999) / 1_000;
    if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

fn stream_limit_response(retry_after_ms: u64) -> Response {
    let retry_after_ms = retry_after_ms.clamp(1, STREAM_LIMIT_RETRY_AFTER_MS.max(1));
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(ErrorBody {
            code: "STREAM_LIMIT",
            execution: "not_dispatched",
            message: "selected owner stream capacity is exhausted; retry after the bounded hint",
            retryable: Some(true),
            retry_after_ms: Some(retry_after_ms),
        }),
    )
        .into_response();
    let retry_after_seconds = retry_after_ms.saturating_add(999) / 1_000;
    if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    execution: &'a str,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    retryable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_ms: Option<u64>,
}

/// The single public mapping of a shared service-resolution outcome.  Every
/// consumer route that names a service reports the same code for the same
/// decision, so a duplicate label is `409 SERVICE_AMBIGUOUS` on the echo route
/// and on the stream upgrade alike.
fn service_resolution_response(error: ServiceResolutionError) -> Response {
    match error {
        ServiceResolutionError::NotFound => error_response(
            StatusCode::NOT_FOUND,
            "SERVICE_NOT_FOUND",
            "not found",
            "not_dispatched",
        ),
        ServiceResolutionError::Ambiguous => error_response(
            StatusCode::CONFLICT,
            "SERVICE_AMBIGUOUS",
            "service label matches more than one active service",
            "not_dispatched",
        ),
    }
}

/// A known public path reached with a method it does not serve.  The relay
/// performs no automatic reselection on any method, so a GET, HEAD or OPTIONS
/// shaped request at the POST-only echo route ends here with a typed
/// `not_dispatched` outcome before authentication, owner selection or any
/// body read.
async fn method_not_allowed() -> Response {
    error_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "METHOD_NOT_ALLOWED",
        "method is not served on this route",
        "not_dispatched",
    )
}

fn error_response(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    execution: &'static str,
) -> Response {
    (
        status,
        Json(ErrorBody {
            code,
            execution,
            message,
            retryable: None,
            retry_after_ms: None,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{
        ConsumerUpgradeBarrier, PeerAdmissionBarrier, PeerAdmissionBarrierError,
        PeerAdmissionScope, forwarded_bearer_token, is_no_live_owner, method_not_allowed,
        owner_busy_close, peer_consumer_diagnostic_outcome, peer_failure_response,
        service_resolution_response, stream_limit_response,
    };
    use crate::{
        peer_runtime::PeerRuntimeError,
        routing::{OwnerRoutingError, OwnerScope, ServiceResolutionError},
    };
    use axum::{
        extract::ws::Message,
        http::{HeaderMap, HeaderValue, StatusCode, header},
    };
    use tunnel_catalog::CatalogError;
    use tunnel_protocol::{CONTROL_OWNER_BUSY_CLOSE_CODE, CONTROL_OWNER_BUSY_CLOSE_REASON};
    use uuid::Uuid;

    #[tokio::test]
    async fn consumer_upgrade_barrier_is_one_shot_and_bounded() {
        let barrier = ConsumerUpgradeBarrier::default();
        assert!(barrier.arm());
        assert!(!barrier.arm());

        let waiter = tokio::spawn({
            let barrier = barrier.clone();
            async move {
                barrier
                    .wait_before_upgrade(std::time::Duration::from_secs(1))
                    .await;
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), barrier.wait_reached())
            .await
            .expect("barrier should be reached");
        assert_eq!(barrier.hit_count(), 1);
        assert!(barrier.is_held());
        assert!(!barrier.arm());
        barrier.release();
        assert!(!barrier.is_held());
        waiter.await.expect("bounded barrier waiter");
        assert!(!barrier.arm());
    }

    fn peer_admission_test_scope(seed: u128) -> PeerAdmissionScope {
        PeerAdmissionScope {
            tenant_id: Uuid::from_u128(seed),
            device_id: Uuid::from_u128(seed.saturating_add(1)),
            service_id: Uuid::from_u128(seed.saturating_add(2)),
            deployment_incarnation: format!("deployment-{seed}"),
            node_id: format!("node-{seed}"),
            boot_id: format!("boot-{seed}"),
            session_id: format!("session-{seed}"),
            epoch: seed as u64,
        }
    }

    #[tokio::test]
    async fn peer_admission_barrier_matches_scope_once_and_releases_waiter() {
        let barrier = PeerAdmissionBarrier::default();
        let expected = peer_admission_test_scope(10);
        let other = peer_admission_test_scope(20);
        assert!(barrier.arm(expected.clone()));
        assert!(!barrier.arm(other.clone()));

        let waiter = tokio::spawn({
            let barrier = barrier.clone();
            async move {
                barrier
                    .wait_before_peer_admission(expected, std::time::Duration::from_secs(1))
                    .await
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), barrier.wait_reached())
            .await
            .expect("peer admission barrier should be reached");
        assert_eq!(barrier.hit_count(), 1);
        assert_eq!(
            barrier.observed_scope(),
            Some(peer_admission_test_scope(10))
        );
        barrier.release();
        assert!(
            waiter
                .await
                .expect("peer admission waiter task should join")
                .expect("peer admission scope should match")
        );
        assert!(!barrier.arm(other));
    }

    #[tokio::test]
    async fn peer_admission_barrier_rejects_wrong_scope_and_is_bounded() {
        let barrier = PeerAdmissionBarrier::default();
        let expected = peer_admission_test_scope(30);
        let wrong = peer_admission_test_scope(40);
        assert!(barrier.arm(expected));
        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                barrier.wait_before_peer_admission(wrong, std::time::Duration::from_secs(1)),
            )
            .await
            .expect("wrong-scope barrier should finish"),
            Err(PeerAdmissionBarrierError::ScopeMismatch)
        );
        assert_eq!(barrier.hit_count(), 0);
        assert_eq!(barrier.observed_scope(), None);
        assert!(!barrier.arm(peer_admission_test_scope(50)));

        let timeout_barrier = PeerAdmissionBarrier::default();
        let timeout_scope = peer_admission_test_scope(60);
        assert!(timeout_barrier.arm(timeout_scope.clone()));
        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                timeout_barrier.wait_before_peer_admission(
                    timeout_scope,
                    std::time::Duration::from_millis(5),
                ),
            )
            .await
            .expect("timed barrier should finish"),
            Err(PeerAdmissionBarrierError::TimedOut)
        );
        assert_eq!(timeout_barrier.hit_count(), 1);
    }

    #[tokio::test]
    async fn peer_admission_barrier_release_before_wait_notifies_both_waiters() {
        let barrier = PeerAdmissionBarrier::default();
        let scope = peer_admission_test_scope(70);
        assert!(barrier.arm(scope.clone()));

        let reached = barrier.state.reached.notified();
        tokio::pin!(reached);
        reached.as_mut().enable();
        let released = barrier.state.release.notified();
        tokio::pin!(released);
        released.as_mut().enable();

        barrier.release();
        tokio::time::timeout(std::time::Duration::from_secs(1), reached)
            .await
            .expect("release should notify reached waiters");
        tokio::time::timeout(std::time::Duration::from_secs(1), released)
            .await
            .expect("release should notify admission waiters");
        assert_eq!(
            barrier
                .wait_before_peer_admission(scope, std::time::Duration::from_secs(1))
                .await,
            Err(PeerAdmissionBarrierError::ReleasedBeforeHit)
        );
    }

    #[test]
    fn forwarded_bearer_contains_only_the_validated_token() {
        let mut headers = HeaderMap::new();
        for authorization in [
            "Bearer synthetic.jwt.signature",
            "bearer synthetic.jwt.signature",
        ] {
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_static(authorization),
            );
            assert_eq!(forwarded_bearer_token(&headers), "synthetic.jwt.signature");
        }
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic synthetic"),
        );
        assert!(forwarded_bearer_token(&headers).is_empty());
        headers.clear();
        assert!(forwarded_bearer_token(&headers).is_empty());
    }

    #[test]
    fn only_a_missing_owner_allows_fresh_control_registration() {
        let scope = OwnerScope::new(Uuid::from_u128(1), Uuid::from_u128(2));
        assert!(is_no_live_owner(&PeerRuntimeError::Routing(
            OwnerRoutingError::NoLiveOwner(scope),
        )));
        assert!(!is_no_live_owner(&PeerRuntimeError::Routing(
            OwnerRoutingError::Catalog(CatalogError::InvalidInput("catalog unavailable")),
        )));
        assert!(!is_no_live_owner(&PeerRuntimeError::Routing(
            OwnerRoutingError::OwnerScopeMismatch,
        )));
    }

    #[test]
    fn owner_busy_close_is_fixed_and_bounded() {
        assert!(matches!(
            owner_busy_close(),
            Message::Close(Some(frame))
                if frame.code == CONTROL_OWNER_BUSY_CLOSE_CODE
                    && &*frame.reason == CONTROL_OWNER_BUSY_CLOSE_REASON
        ));
    }

    #[tokio::test]
    async fn owner_not_ready_response_is_retryable_before_dispatch() {
        let response = peer_failure_response(PeerRuntimeError::OwnerNotReady {
            retry_after_ms: 250,
        });
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("1")
        );
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("bounded retry body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("retry response JSON");
        assert_eq!(body["code"], "PEER_UNAVAILABLE");
        assert_eq!(body["execution"], "not_dispatched");
        assert_eq!(body["retryable"], true);
        assert_eq!(body["retry_after_ms"], 250);

        let generic = peer_failure_response(PeerRuntimeError::Closed);
        let generic_body = axum::body::to_bytes(generic.into_body(), 1024)
            .await
            .expect("bounded generic body");
        let generic_body: serde_json::Value =
            serde_json::from_slice(&generic_body).expect("generic response JSON");
        assert_eq!(generic_body["execution"], "unknown");
        assert!(generic_body.get("retryable").is_none());
        assert!(generic_body.get("retry_after_ms").is_none());

        let capacity = peer_failure_response(PeerRuntimeError::Capacity {
            retry_after_ms: 250,
        });
        assert_eq!(capacity.status(), StatusCode::TOO_MANY_REQUESTS);
        let capacity_body = axum::body::to_bytes(capacity.into_body(), 1024)
            .await
            .expect("bounded capacity response body");
        let capacity_body: serde_json::Value =
            serde_json::from_slice(&capacity_body).expect("capacity response JSON");
        assert_eq!(capacity_body["code"], "STREAM_LIMIT");
        assert_eq!(capacity_body["execution"], "not_dispatched");
        assert_eq!(capacity_body["retryable"], true);
    }

    #[tokio::test]
    async fn shared_service_resolution_outcomes_map_to_one_public_code_each() {
        // M7-C47: the ambiguous and missing outcomes have exactly one public
        // envelope, so every route that uses the shared resolver reports the
        // same code for the same decision.
        let ambiguous = service_resolution_response(ServiceResolutionError::Ambiguous);
        assert_eq!(ambiguous.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(ambiguous.into_body(), 1024)
            .await
            .expect("bounded ambiguous body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("ambiguous JSON");
        assert_eq!(body["code"], "SERVICE_AMBIGUOUS");
        assert_eq!(body["execution"], "not_dispatched");
        assert!(body.get("retryable").is_none());

        let missing = service_resolution_response(ServiceResolutionError::NotFound);
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(missing.into_body(), 1024)
            .await
            .expect("bounded not-found body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("not-found JSON");
        assert_eq!(body["code"], "SERVICE_NOT_FOUND");
        assert_eq!(body["execution"], "not_dispatched");
    }

    #[tokio::test]
    async fn unserved_method_on_a_known_route_is_a_typed_not_dispatched_rejection() {
        // M7-C46: the relay never reselects on any method; a safe method shape
        // at the POST-only echo route ends here with a typed envelope.
        let response = method_not_allowed().await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("bounded method body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("method JSON");
        assert_eq!(body["code"], "METHOD_NOT_ALLOWED");
        assert_eq!(body["execution"], "not_dispatched");
        assert!(body.get("retryable").is_none());
    }

    #[test]
    fn unrelated_h3_error_is_not_classified_as_goaway() {
        let (outcome, h3_code) = peer_consumer_diagnostic_outcome(&PeerRuntimeError::Transport(
            tunnel_transport::PeerTransportError::H3("H3_FRAME_UNEXPECTED".to_owned()),
        ));
        assert_eq!(
            outcome,
            crate::peer_transport_diagnostics::PeerTransportDiagnosticOutcome::H3Error
        );
        assert_ne!(
            outcome,
            crate::peer_transport_diagnostics::PeerTransportDiagnosticOutcome::GoAway
        );
        assert_eq!(
            h3_code,
            Some(crate::peer_consumer_transport_diagnostics::PeerConsumerDiagnosticH3Code::FrameUnexpected)
        );
    }

    type EchoWrite = Result<Vec<u8>, crate::actor::EchoOutcome>;

    // The relay's tokio build has no paused test clock, so these bounds use
    // short real timers with generous upper margins, like the response-write
    // deadline tests in `consumer_write_diagnostics`.

    #[tokio::test]
    async fn outstanding_stream_write_observes_stream_closure() {
        let closed = tokio_util::sync::CancellationToken::new();
        let expires = tokio::time::sleep(std::time::Duration::from_secs(60));
        tokio::pin!(expires);
        let waiter = super::write_until_closed_or_expired(
            std::future::pending::<EchoWrite>(),
            &closed,
            &mut expires,
        );
        let closer = async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            closed.cancel();
        };
        let (outcome, ()) = tokio::join!(waiter, closer);
        assert!(matches!(outcome, super::BoundedStreamWrite::StreamClosed));
    }

    #[tokio::test]
    async fn outstanding_stream_write_is_bounded_by_the_absolute_deadline() {
        let closed = tokio_util::sync::CancellationToken::new();
        let expires = tokio::time::sleep(std::time::Duration::from_millis(50));
        tokio::pin!(expires);
        let started = tokio::time::Instant::now();
        let outcome = super::write_until_closed_or_expired(
            std::future::pending::<EchoWrite>(),
            &closed,
            &mut expires,
        )
        .await;
        assert!(matches!(outcome, super::BoundedStreamWrite::Expired));
        let elapsed = started.elapsed();
        assert!(
            elapsed >= std::time::Duration::from_millis(50)
                && elapsed < std::time::Duration::from_secs(5),
            "the wait must end at the stream's absolute deadline, observed {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn completed_stream_write_is_returned_while_the_stream_is_live() {
        let closed = tokio_util::sync::CancellationToken::new();
        let expires = tokio::time::sleep(std::time::Duration::from_secs(60));
        tokio::pin!(expires);
        let outcome = super::write_until_closed_or_expired(
            async { Ok::<Vec<u8>, crate::actor::EchoOutcome>(vec![0, 0, 0, 1, 7]) },
            &closed,
            &mut expires,
        )
        .await;
        assert!(matches!(
            outcome,
            super::BoundedStreamWrite::Completed(Ok(bytes)) if bytes == vec![0, 0, 0, 1, 7]
        ));
    }

    #[tokio::test]
    async fn closure_and_expiry_take_precedence_over_a_ready_write() {
        let closed = tokio_util::sync::CancellationToken::new();
        closed.cancel();
        let expires = tokio::time::sleep(std::time::Duration::from_secs(60));
        tokio::pin!(expires);
        let outcome = super::write_until_closed_or_expired(
            std::future::ready(Ok::<Vec<u8>, crate::actor::EchoOutcome>(Vec::new())),
            &closed,
            &mut expires,
        )
        .await;
        assert!(matches!(outcome, super::BoundedStreamWrite::StreamClosed));

        // A deadline that has already fired stays observable: the handlers
        // poll the same pinned timer again after their read loop saw it.
        let live = tokio_util::sync::CancellationToken::new();
        let expired = tokio::time::sleep(std::time::Duration::ZERO);
        tokio::pin!(expired);
        expired.as_mut().await;
        let outcome = super::write_until_closed_or_expired(
            std::future::ready(Ok::<Vec<u8>, crate::actor::EchoOutcome>(Vec::new())),
            &live,
            &mut expired,
        )
        .await;
        assert!(matches!(outcome, super::BoundedStreamWrite::Expired));
    }

    #[tokio::test]
    async fn goaway_response_is_typed_not_dispatched() {
        let response = peer_failure_response(PeerRuntimeError::Transport(
            tunnel_transport::PeerTransportError::GoAway,
        ));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("bounded GOAWAY response body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("GOAWAY response JSON");
        assert_eq!(body["code"], "PEER_UNAVAILABLE");
        assert_eq!(body["execution"], "not_dispatched");
        assert!(body.get("retryable").is_none());
        assert!(body.get("retry_after_ms").is_none());
    }

    #[tokio::test]
    async fn stream_limit_response_is_exactly_bounded_and_pre_dispatch() {
        let response = stream_limit_response(250);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("1")
        );
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("bounded capacity body");
        let body: serde_json::Value =
            serde_json::from_slice(&body).expect("capacity response JSON");
        assert_eq!(body["code"], "STREAM_LIMIT");
        assert_eq!(body["execution"], "not_dispatched");
        assert_eq!(body["retryable"], true);
        assert_eq!(body["retry_after_ms"], 250);

        let clamped = stream_limit_response(60_000);
        let body = axum::body::to_bytes(clamped.into_body(), 1024)
            .await
            .expect("bounded clamped body");
        let body: serde_json::Value =
            serde_json::from_slice(&body).expect("clamped capacity response JSON");
        assert_eq!(body["retry_after_ms"], super::STREAM_LIMIT_RETRY_AFTER_MS);
    }
}

#[cfg(test)]
mod peer_cleanup_tests;

#[cfg(test)]
mod pending_open_abandon_tests;

#[cfg(test)]
mod tenant_admission_tests;
