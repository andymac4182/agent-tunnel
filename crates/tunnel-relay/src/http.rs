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
use tunnel_catalog::{DeviceListFilter, OidcError, OidcVerifier, SharedCatalog};
use tunnel_protocol::{
    CONTROL_IDENTITY_REJECTED_CLOSE_CODE, CONTROL_IDENTITY_REJECTED_CLOSE_REASON,
    CONTROL_OWNER_BUSY_CLOSE_CODE, CONTROL_OWNER_BUSY_CLOSE_REASON,
    CONTROL_PROTOCOL_UNSUPPORTED_CLOSE_CODE, CONTROL_PROTOCOL_UNSUPPORTED_CLOSE_REASON,
    DEVICE_CONTROL_IDLE_TIMEOUT, DEVICE_CONTROL_PING_INTERVAL,
};
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

/// One-shot fixture seam immediately after the device's `HELLO` has been
/// received and parsed on an owner-local device control socket, and
/// immediately before the relay registers the control stream and produces the
/// `WELCOME`.  It mirrors [`ConsumerUpgradeBarrier`] exactly: it is optional,
/// is `None` on every ordinary relay path, and changes no product behaviour
/// when absent.  The harness can arm it, observe the exact server-side point
/// between `HELLO` and `WELCOME`, change device ownership while the handler is
/// held, and release, without relying on a timing sleep.
///
/// Like [`ConsumerUpgradeBarrier`] and unlike [`PeerAdmissionBarrier`], a
/// released barrier is a *pass-through*, never a refusal: a later control
/// attach observes the failed `ARMED -> HELD` transition and proceeds
/// immediately.  It is nonetheless single-use, because `arm` only succeeds
/// from `IDLE`, so a fixture must make its phase order explicit and hold the
/// one control attach it actually intends to race.
#[derive(Clone, Debug)]
pub struct ControlAttachBarrier {
    state: Arc<ControlAttachBarrierState>,
}

#[derive(Debug)]
struct ControlAttachBarrierState {
    /// One-shot state machine: idle -> armed -> held -> released, identical to
    /// the consumer upgrade barrier so a stale second arm cannot reset the
    /// state of a request already held between HELLO and WELCOME.
    phase: AtomicU8,
    hits: AtomicU64,
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl Default for ControlAttachBarrier {
    fn default() -> Self {
        Self {
            state: Arc::new(ControlAttachBarrierState {
                phase: AtomicU8::new(BARRIER_IDLE),
                hits: AtomicU64::new(0),
                reached: tokio::sync::Notify::new(),
                release: tokio::sync::Notify::new(),
            }),
        }
    }
}

impl ControlAttachBarrier {
    /// Arm exactly one device control-attach interception.  A second arm is
    /// rejected so a stale notification cannot be mistaken for the selected
    /// control socket.
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

    /// Wait until the selected handler reaches the post-HELLO, pre-WELCOME
    /// boundary.
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

    /// Release the held control attach.  The release is sticky, so a
    /// cancellation/reordering race cannot strand the handler.
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
    /// control attach between HELLO and WELCOME.
    pub fn is_held(&self) -> bool {
        self.state.phase.load(Ordering::Acquire) == BARRIER_HELD
    }

    async fn wait_before_control_attach(&self, budget: Duration) {
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
            // A bounded fallback prevents a fixture bug or shutdown race from
            // holding a device control task forever.
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
    peer_frame::{PeerRecord, PeerRecordKind},
};

use crate::{
    actor::{
        CarrierKey, ConsumerStreamRegistration, EchoOutcome, RelayError, RelayHandle, SessionKey,
        TerminalCleanupGuard,
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
    peer_fault_diagnostics::{
        PeerFaultCause, PeerFaultContext, PeerFaultObserver, PeerFaultRole, TaskClosureCause,
        TaskClosureScope, TaskClosureStage,
    },
    peer_runtime::{
        InboundPeerRequest, OWNER_NOT_READY_RETRY_AFTER_MS, PeerExchangeRecv, PeerExchangeSend,
        PeerIngressHandler, PeerOpenDiagnostic, PeerOpenDiagnosticStage, PeerRuntime,
        PeerRuntimeError, STREAM_LIMIT_RETRY_AFTER_MS, device_authentication_context,
        forwarded_consumer_bearer,
    },
    peer_transport_diagnostics::{PeerTransportDiagnosticOutcome, PeerTransportDiagnosticRole},
    routing::{OwnerRoute, OwnerRoutingError, OwnerScope, ServiceResolutionError, ServiceTarget},
    runtime::StreamTerminalCause,
    wire::{self, MAX_BODY_BYTES, MAX_CONTROL_BYTES},
};

pub(crate) mod forward;
/// The filesystem endpoint: descriptor, WSS upgrade and byte pump.
pub(crate) mod fs;

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
    /// Fixture-only one-shot gate on an owner-local device control socket,
    /// after the device's HELLO is received and before the relay registers
    /// the control stream and emits the WELCOME.  `None` on every ordinary
    /// relay path, including every consumer route.
    pub(crate) control_attach_barrier: Option<Arc<ControlAttachBarrier>>,
    /// The `http-forward/1` export served on this relay's public routes.  `None`
    /// (every production caller today) leaves the HTTP routes answering 404:
    /// per-profile allowlists are implementation gate 5.
    pub(crate) http_forward: Option<crate::http::forward::HttpForwardExports>,
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
        None,
    )
}

/// Build consumer routes with the two independent fixture-only seams. The
/// pre-H3 admission barrier is deliberately separate from the older post-
/// admission upgrade barrier; ordinary production callers pass `None` for
/// both and retain the existing route.
#[allow(clippy::too_many_arguments)]
pub(crate) fn consumer_router_with_peer_and_barriers(
    handle: RelayHandle,
    catalog: SharedCatalog,
    oidc: Arc<OidcVerifier>,
    limits: RelayLimits,
    peer: Option<Arc<PeerRuntime>>,
    consumer_upgrade_barrier: Option<Arc<ConsumerUpgradeBarrier>>,
    peer_admission_barrier: Option<Arc<PeerAdmissionBarrier>>,
    http_forward: Option<crate::http::forward::HttpForwardExports>,
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
        control_attach_barrier: None,
        http_forward,
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
        .route(
            "/v1/devices/{device}/services/{service}/http/{*path}",
            axum::routing::any(crate::http::forward::http_forward_route),
        )
        // One URL for the descriptor and the upgrade, registered for every
        // method so the 405 is this route's own typed answer rather than the
        // router's fallback: the contract requires the filesystem error body
        // there too.
        .route(
            "/v1/devices/{device}/services/{service}/fs",
            axum::routing::any(crate::http::fs::fs_route),
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
    device_router_with_peer_and_barrier(handle, catalog, limits, peer, None)
}

/// Build device routes with an optional fixture-only control-attach barrier.
/// The barrier is deliberately separate from the ordinary device route so
/// production callers keep the existing no-gate behaviour; passing `None`
/// reproduces `device_router_with_peer` exactly.
pub fn device_router_with_peer_and_barrier(
    handle: RelayHandle,
    catalog: Option<SharedCatalog>,
    limits: RelayLimits,
    peer: Option<Arc<PeerRuntime>>,
    control_attach_barrier: Option<Arc<ControlAttachBarrier>>,
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
        control_attach_barrier,
        http_forward: None,
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
    let principal = match authenticate(&state, &headers, None, "devices").await {
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
    let principal = match authenticate(&state, &headers, None, "services").await {
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
        Err(error) => {
            return consumer_authentication_response(&error, "echo");
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
        log_consumer_grant_refusal("echo", &validated.consumer, device_id, Some(service_id));
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
        // One bounded stage/cause tuple per dispatch attempt.  The observer
        // starts unrouted and gains the owner identity once selected, so a
        // routing fault and an owner fault carry exactly the identifiers the
        // relay had at that stage.
        let mut fault = PeerFaultObserver::new(
            PeerFaultRole::Ingress,
            PeerFaultContext::unrouted(grant.tenant_id, device_id, Some(service_id)),
        );
        match peer.resolve(scope, Utc::now()).await {
            Ok(route @ OwnerRoute::Remote { .. }) => {
                let request_id = Uuid::new_v4().to_string();
                fault.set_context(PeerFaultContext::for_owner(
                    route.owner_token(),
                    Some(service_id),
                    Some(request_id.clone()),
                ));
                let destination = Destination::new(route.owner_token().clone(), service_id);
                let forwarded =
                    match forwarded_consumer_bearer(&bearer_token, route.owner_token().clone()) {
                        Ok(value) => value,
                        Err(_) => {
                            // The token was already accepted above; only
                            // re-framing it for the owner failed.  Same text
                            // as every other refused token (M6-C53).
                            return error_response(
                                StatusCode::UNAUTHORIZED,
                                "UNAUTHORIZED",
                                CONSUMER_TOKEN_REFUSED,
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
                match peer
                    .forward_unary_with_diagnostics(&route, envelope, &body, fault.diagnostic())
                    .await
                {
                    Ok(bytes) => {
                        return (
                            StatusCode::OK,
                            [(header::CONTENT_TYPE, "application/octet-stream")],
                            bytes,
                        )
                            .into_response();
                    }
                    Err(error) => {
                        state.handle.record_peer_fault(&fault, &error);
                        return peer_failure_response(error);
                    }
                }
            }
            Ok(OwnerRoute::Local { .. }) => {}
            Err(error) => {
                state.handle.record_peer_fault(&fault, &error);
                return peer_failure_response(error);
            }
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

#[allow(clippy::too_many_arguments)]
async fn open_remote_consumer_admission(
    peer: &PeerRuntime,
    route: &OwnerRoute,
    service_id: Uuid,
    bearer_token: &str,
    request_id: String,
    peer_admission_barrier: Option<(&PeerAdmissionBarrier, PeerAdmissionScope)>,
    peer_admission_budget: Duration,
    diagnostic: &PeerOpenDiagnostic,
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
        peer.open_with_admission_barrier(
            route,
            envelope,
            barrier,
            scope,
            peer_admission_budget,
            Some(diagnostic),
        )
        .await?
    } else {
        peer.open_with_diagnostics(route, envelope, diagnostic)
            .await?
    };
    let (send, recv) = exchange.split();
    let mut admission = RemoteConsumerAdmission::new(request_id, send, recv);
    diagnostic.mark(PeerOpenDiagnosticStage::Head);
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
        Err(error) => {
            return consumer_authentication_response(&error, "stream");
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
        log_consumer_grant_refusal("stream", &validated.consumer, device_id, Some(service_id));
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
    let mut fault = PeerFaultObserver::new(
        PeerFaultRole::Ingress,
        PeerFaultContext::unrouted(grant.tenant_id, device_id, Some(service_id)),
    );
    if let Some(peer) = state.peer.clone() {
        match peer
            .resolve(OwnerScope::new(grant.tenant_id, device_id), Utc::now())
            .await
        {
            Ok(route @ OwnerRoute::Remote { .. }) => {
                let request_id = Uuid::new_v4().to_string();
                fault.set_context(PeerFaultContext::for_owner(
                    route.owner_token(),
                    Some(service_id),
                    Some(request_id.clone()),
                ));
                let peer_admission_barrier =
                    if let Some(barrier) = state.peer_admission_barrier.as_ref() {
                        let scope = match PeerAdmissionScope::from_route(&route, service_id) {
                            Some(scope) => scope,
                            None => {
                                let error = PeerRuntimeError::PeerIdentityMismatch;
                                handle.record_peer_fault(&fault, &error);
                                return peer_failure_response(error);
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
                        fault.diagnostic(),
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
                            handle.record_peer_fault(&fault, &error);
                            return peer_failure_response(error);
                        }
                    },
                    Err(_) => {
                        // The relay's own operation deadline elapsed; the
                        // observer still reports the exact stage reached.
                        handle.record_peer_fault_tuple(
                            &fault,
                            fault.stage(),
                            PeerFaultCause::Deadline,
                        );
                        return peer_failure_response(PeerRuntimeError::Closed);
                    }
                };
                selected_route = Some(route.clone());
                remote = Some((route, admission));
            }
            Ok(route @ OwnerRoute::Local { .. }) => {
                selected_route = Some(route);
            }
            Err(error) => {
                handle.record_peer_fault(&fault, &error);
                return peer_failure_response(error);
            }
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
        if matches!(route, OwnerRoute::Remote { .. }) {
            fault.mark(PeerOpenDiagnosticStage::Lease);
            handle.record_peer_fault(&fault, &error);
        }
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
    // The typed first cause this handler can prove for itself.  Only the
    // relay's own physical response-write deadline is established here; every
    // other exit stays unclassified so the actor's own close site keeps
    // whatever it can prove.
    let mut terminal_cause: Option<StreamTerminalCause> = None;
    // EC-061: the bounded closure cause for this adapter.  It is distinct
    // from `terminal_cause` above, which is the stream's typed terminal
    // classification carried to the actor's close site and can stay `None`;
    // this one always names the structural reason the adapter loop stopped.
    // It is observational: no exit decision below reads it.
    // Deliberately uninitialised: every exit from the loop below assigns a
    // cause before it breaks, and leaving this without a default makes the
    // compiler prove that rather than a comment claim it.  A new exit path
    // that forgets to name its cause fails to compile.
    let closure_cause: TaskClosureCause;
    let expires_in = (consumer_expires_at - Utc::now())
        .to_std()
        .unwrap_or_default();
    let expires = tokio::time::sleep(expires_in);
    tokio::pin!(expires);
    'connection: loop {
        let message = tokio::select! {
            biased;
            _ = registration.closed.cancelled() => { closure_cause = TaskClosureCause::StreamClosed; break; }
            _ = &mut expires => { closure_cause = TaskClosureCause::Expired; break; }
            message = socket.next() => message,
        };
        let Some(message) = message else {
            closure_cause = TaskClosureCause::PeerClosed;
            break;
        };
        let message = match message {
            Ok(message) => message,
            Err(_) => {
                closure_cause = TaskClosureCause::PeerClosed;
                break;
            }
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
                    closure_cause = TaskClosureCause::ProtocolError;
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
                            closure_cause = TaskClosureCause::ProtocolError;
                            break 'connection;
                        }
                    };
                    // The write stays inside the same closure/deadline scope
                    // as the read loop: a parked record cannot hold this
                    // stream past its absolute authorization deadline or past
                    // the owner closing it.
                    // The public WebSocket has no peer receive direction to
                    // service while the write is outstanding.
                    let write = handle.write_echo_stream(
                        key.clone(),
                        stream_id,
                        operation_id.clone(),
                        body,
                    );
                    tokio::pin!(write);
                    let result = match write_until_closed_or_expired(
                        write.as_mut(),
                        &registration.closed,
                        &mut expires,
                        std::future::pending::<std::convert::Infallible>(),
                    )
                    .await
                    {
                        BoundedStreamWrite::Completed(result) => result,
                        BoundedStreamWrite::StreamClosed => {
                            closure_cause = TaskClosureCause::StreamClosed;
                            break 'connection;
                        }
                        BoundedStreamWrite::Expired => {
                            closure_cause = TaskClosureCause::Expired;
                            break 'connection;
                        }
                        BoundedStreamWrite::PeerEvent(never) => match never {},
                    };
                    let Ok(response) = result else {
                        closure_cause = TaskClosureCause::StreamFailed;
                        break 'connection;
                    };
                    if response.len() < 4 {
                        closure_cause = TaskClosureCause::StreamFailed;
                        break 'connection;
                    }
                    let response_len =
                        u32::from_be_bytes([response[0], response[1], response[2], response[3]])
                            as usize;
                    if response_len > MAX_BODY_BYTES.saturating_add(MAX_ECHO_CANARY_BYTES)
                        || response_len.saturating_add(4) != response.len()
                    {
                        closure_cause = TaskClosureCause::StreamFailed;
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
                    // The stall itself is the proof, taken from the same
                    // outcome the bounded diagnostic already counts. The
                    // first such outcome wins; nothing about the loop's exit
                    // decision below changes.
                    if terminal_cause.is_none() {
                        terminal_cause = outcome.terminal_cause();
                    }
                    if !outcome.is_sent() {
                        closure_cause = TaskClosureCause::WriteFailed;
                        break 'connection;
                    }
                }
            }
            Message::Ping(payload) => {
                if !send_socket(&mut socket, Message::Pong(payload)).await {
                    closure_cause = TaskClosureCause::WriteFailed;
                    break;
                }
            }
            Message::Close(_) => {
                // Tungstenite queues the peer's close reply while reading.
                // Flush it before dropping the upgraded TLS connection.
                let _ = timeout(Duration::from_secs(5), socket.flush()).await;
                closure_cause = TaskClosureCause::PeerClosed;
                break;
            }
            Message::Pong(_) => {}
            Message::Text(_) => {
                closure_cause = TaskClosureCause::UnexpectedMessage;
                break;
            }
        }
    }
    let _ = send_socket(&mut socket, Message::Close(None)).await;
    finish_consumer_task(
        &handle,
        key,
        stream_id,
        operation_id,
        terminal_cause,
        closure_cause,
        &mut cleanup,
    )
    .await;
}

/// EC-061: the single exit of the public consumer stream adapter.
///
/// The closure tuple is recorded before the close command is sent, so it is
/// strictly below the `ConsumerStream` unregister tombstone the actor stamps
/// at the first terminal transition inside `close_echo_stream_with_cause`,
/// where this stream's owner-side registration is actually released.
///
/// `terminal_cause` and the closure cause are deliberately separate.  The
/// first is the stream's typed terminal classification and is allowed to stay
/// `None` so the actor's own close site keeps whatever it can prove; the
/// second always names why this adapter stopped.  Neither is read by any exit
/// decision, and recording performs no I/O and enters no mailbox.
#[allow(clippy::too_many_arguments)]
async fn finish_consumer_task(
    handle: &RelayHandle,
    key: SessionKey,
    stream_id: u64,
    operation_id: String,
    terminal_cause: Option<StreamTerminalCause>,
    closure_cause: TaskClosureCause,
    cleanup: &mut TerminalCleanupGuard,
) {
    handle.record_task_closure(
        &TaskClosureScope {
            tenant_id: key.tenant_id,
            device_id: key.device_id,
            session_id: key.session_id.clone(),
            epoch: key.epoch,
            stream_id: Some(stream_id),
        },
        TaskClosureStage::ConsumerStream,
        closure_cause,
    );
    if matches!(
        timeout(
            Duration::from_secs(5),
            handle.close_echo_stream_with_cause(key, stream_id, operation_id, terminal_cause),
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
    let fault = PeerFaultObserver::new(
        PeerFaultRole::Ingress,
        PeerFaultContext::for_owner(owner, Some(service_id), Some(request_id.clone())),
    );
    fault.mark(PeerOpenDiagnosticStage::Body);
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
    // The owner response read is bounded by the consumer's absolute
    // deadline, not by the peer transport idle timeout.  A saturated but
    // healthy owner is legitimately silent while it queues this response, so
    // an idle-window fault here fails the consumer's request with
    // `H3_REQUEST_CANCELLED` while its own authorization deadline is still
    // far away (the ingress mirror of the owner-side bound).  Owner reset,
    // GOAWAY, response end and membership loss still end the read promptly,
    // and the QUIC connection idle timeout remains armed underneath for a
    // peer that has actually gone away.
    let mut pending_forward = None;
    loop {
        let event = if pending_forward.is_some() {
            if prefer_remote {
                tokio::select! {
                    biased;
                    _ = &mut expires => RemoteConsumerEvent::Expired,
                    forward_done = &mut forwarder => RemoteConsumerEvent::ForwardDone(forward_done),
                    remote = recv.recv_message_until(consumer_deadline) => RemoteConsumerEvent::Remote(remote),
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
                    remote = recv.recv_message_until(consumer_deadline) => RemoteConsumerEvent::Remote(remote),
                }
            }
        } else if prefer_remote {
            tokio::select! {
                biased;
                _ = &mut expires => RemoteConsumerEvent::Expired,
                forward_done = &mut forwarder => RemoteConsumerEvent::ForwardDone(forward_done),
                remote = recv.recv_message_until(consumer_deadline) => RemoteConsumerEvent::Remote(remote),
                inbound = socket.next() => RemoteConsumerEvent::Inbound(inbound),
            }
        } else {
            tokio::select! {
                biased;
                _ = &mut expires => RemoteConsumerEvent::Expired,
                forward_done = &mut forwarder => RemoteConsumerEvent::ForwardDone(forward_done),
                inbound = socket.next() => RemoteConsumerEvent::Inbound(inbound),
                remote = recv.recv_message_until(consumer_deadline) => RemoteConsumerEvent::Remote(remote),
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
                        handle.record_peer_fault(&fault, &error);
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
                        handle.record_peer_fault(&fault, &error);
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
    service_and_grant_of_type(
        state,
        consumer,
        device_id,
        service,
        crate::ECHO_SERVICE_TYPE,
    )
    .await
    .map(|(service_id, grant, _)| (service_id, grant))
}

pub(crate) async fn service_and_grant_of_type(
    state: &HttpState,
    consumer: &tunnel_catalog::AuthenticatedConsumer,
    device_id: Uuid,
    service: &str,
    service_type: &str,
) -> Result<(Uuid, tunnel_catalog::GrantSnapshot, serde_json::Value), Response> {
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
    let service_id = crate::routing::resolve_service(
        &device.services,
        ServiceTarget::parse(service),
        service_type,
    )
    .map_err(service_resolution_response)?;
    let capabilities = device
        .services
        .iter()
        .find(|candidate| candidate.service_id == service_id)
        .map_or(serde_json::Value::Null, |candidate| {
            candidate.capabilities.clone()
        });
    let read_started = Utc::now();
    let grant = catalog
        .authorize(consumer, device_id, service_id, read_started, Utc::now())
        .await
        .map_err(catalog_error)?
        .ok_or_else(|| {
            log_consumer_grant_refusal(service_type, consumer, device_id, Some(service_id));
            error_response(
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                "service is not authorized",
                "not_dispatched",
            )
        })?;
    Ok((service_id, grant, capabilities))
}

async fn authenticate(
    state: &HttpState,
    headers: &HeaderMap,
    scope: Option<&str>,
    route: &'static str,
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
    .map_err(|error| consumer_authentication_response(&error, route))
}

/// One consumer credential refusal, classified once for every route (task
/// rows M6-C53 and M6-C52).
///
/// `status` and `message` are what the consumer is told; each route renders
/// them in its own documented code vocabulary (the flat body's
/// `UNAUTHORIZED`/`FORBIDDEN`/`AUTHORIZATION_UNAVAILABLE`, the filesystem
/// contract's `UNAUTHENTICATED`/`ACCESS_DENIED`/`BACKEND_UNAVAILABLE`), so the
/// same cause gets the same status and the same message on every route.
/// `stage` is logged by the relay and never sent: the consumer is not told
/// which check failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConsumerRefusal {
    pub(crate) status: StatusCode,
    pub(crate) message: &'static str,
    pub(crate) stage: &'static str,
}

/// The message for every presented-but-refused credential.  It is true of
/// each such cause and names none of them.
pub(crate) const CONSUMER_TOKEN_REFUSED: &str = "the consumer access token was not accepted";

/// Classify one consumer authentication failure.
///
/// * No bearer credential at all is `401` "a consumer access token is
///   required" -- and only that; before M6-C53 the filesystem route said so
///   of every refused token, including a validly signed one.
/// * A presented credential the relay evaluated and refused -- malformed,
///   badly signed, unknown key, refused claims, unknown consumer -- is `401`
///   with one message that does not say which check failed.
/// * A credential whose signature, claims and consumer all passed but that
///   lacks the route's scope is `403`: the token is fine, the route is not
///   in it (RFC 6750 section 3.1, `insufficient_scope`).  The verifier checks
///   scope only after the identity lookup, so this is never said of an
///   unknown consumer.
/// * A catalog the relay could not reach is `503`: the credential was never
///   evaluated, and reporting a rejection would tell a consumer holding good
///   credentials that they were refused.
pub(crate) fn classify_consumer_refusal(error: &OidcError) -> ConsumerRefusal {
    let refused = |stage| ConsumerRefusal {
        status: StatusCode::UNAUTHORIZED,
        message: CONSUMER_TOKEN_REFUSED,
        stage,
    };
    match error {
        OidcError::Catalog(_) => ConsumerRefusal {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "consumer authorization is unavailable",
            stage: "identity_lookup_unavailable",
        },
        OidcError::MissingBearer => ConsumerRefusal {
            status: StatusCode::UNAUTHORIZED,
            message: "a consumer access token is required",
            stage: "bearer",
        },
        OidcError::InvalidToken => refused("token"),
        OidcError::DisallowedAlgorithm => refused("algorithm"),
        OidcError::MissingKeyId | OidcError::UnknownKey => refused("kid"),
        OidcError::ClaimsRejected => refused("claims"),
        OidcError::UnknownConsumer => refused("identity"),
        // The relay's own verifier configuration, not the consumer's token:
        // a server-side fault, so the consumer is told it is unavailable.
        OidcError::InvalidConfiguration => ConsumerRefusal {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: "consumer authorization is unavailable",
            stage: "verifier_configuration",
        },
        OidcError::InsufficientScope => ConsumerRefusal {
            status: StatusCode::FORBIDDEN,
            message: "the consumer access token does not grant this route's scope",
            stage: "scope",
        },
    }
}

/// The process-wide limit on credential-stage `consumer request refused`
/// lines.  Every such stage is reachable before the consumer is identified --
/// no token at all is one -- so anyone who can reach the consumer listener
/// could otherwise set the growth rate of the relay's `info` log (review of
/// M6-C52).  `grant` refusals, which follow authentication, are not limited.
static CONSUMER_REFUSAL_LOG: std::sync::LazyLock<tunnel_transport::log_limit::RefusalLogLimiter> =
    std::sync::LazyLock::new(tunnel_transport::log_limit::RefusalLogLimiter::with_defaults);

/// Task row M6-C52: one bounded, payload-free line per refused consumer
/// request, rate limited per stage.  Every field is a fixed label, a status,
/// a count or an identifier the relay resolved itself; the token, its claims,
/// the request path and the body are never logged.
pub(crate) fn log_consumer_refusal(route: &'static str, refusal: &ConsumerRefusal) {
    log_consumer_refusal_with(&CONSUMER_REFUSAL_LOG, route, refusal);
}

/// [`log_consumer_refusal`] against an explicit limiter; returns whether the
/// line was written.  An admitted line carries `suppressed`, the number of
/// lines for its stage dropped since the previous one.
pub(crate) fn log_consumer_refusal_with(
    limiter: &tunnel_transport::log_limit::RefusalLogLimiter,
    route: &'static str,
    refusal: &ConsumerRefusal,
) -> bool {
    let Some(suppressed) = limiter.admit(refusal.stage) else {
        return false;
    };
    tracing::info!(
        phase = "consumer_refused",
        route,
        stage = refusal.stage,
        status = refusal.status.as_u16(),
        suppressed,
        "consumer request refused"
    );
    true
}

/// Task row M6-C52: an authenticated consumer refused by its grant.  The
/// tenant, device and service are catalog identifiers already resolved for
/// this principal.
pub(crate) fn log_consumer_grant_refusal(
    route: &str,
    consumer: &tunnel_catalog::AuthenticatedConsumer,
    device_id: Uuid,
    service_id: Option<Uuid>,
) {
    tracing::info!(
        phase = "consumer_refused",
        route,
        stage = "grant",
        status = StatusCode::FORBIDDEN.as_u16(),
        tenant_id = %consumer.tenant_id,
        device_id = %device_id,
        service_id = ?service_id,
        "consumer request refused"
    );
}

/// Map a consumer authentication failure onto the flat-body routes' public
/// response, and log it (M6-C52).  Every outcome remains `not_dispatched`:
/// none reaches an owner.
fn consumer_authentication_response(error: &OidcError, route: &'static str) -> Response {
    let refusal = classify_consumer_refusal(error);
    log_consumer_refusal(route, &refusal);
    let code = match refusal.status {
        StatusCode::SERVICE_UNAVAILABLE => "AUTHORIZATION_UNAVAILABLE",
        StatusCode::FORBIDDEN => "FORBIDDEN",
        _ => "UNAUTHORIZED",
    };
    error_response(refusal.status, code, refusal.message, "not_dispatched")
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

/// Why a cluster relay's device ingress could not route a device socket.
#[derive(Debug)]
enum DeviceRouteError {
    /// The catalog holds no active device and credential for this
    /// certificate's key (task rows M6-C38 and M6-C43).  Unlike every other
    /// routing failure this one cannot heal by retrying, so the control
    /// ingress answers it with the typed identity close, as the owner-local
    /// path does, rather than a dropped socket.
    UnknownCredential,
    Peer(PeerRuntimeError),
}

impl From<PeerRuntimeError> for DeviceRouteError {
    fn from(error: PeerRuntimeError) -> Self {
        Self::Peer(error)
    }
}

async fn remote_device_route(
    state: &HttpState,
    identity: &TlsIdentity,
    allow_fresh_control: bool,
) -> Result<Option<(Arc<PeerRuntime>, OwnerRoute)>, DeviceRouteError> {
    if state.peer.as_ref().is_some_and(|peer| !peer.is_ready()) {
        return Err(
            PeerRuntimeError::Membership("cluster readiness unavailable".to_owned()).into(),
        );
    }
    let Some(peer) = state.peer.clone() else {
        return Ok(None);
    };
    let Some(catalog) = state.catalog.as_ref() else {
        return Err(
            PeerRuntimeError::Membership("device owner catalog unavailable".to_owned()).into(),
        );
    };
    let device = catalog
        .resolve_device(&identity.spki_sha256().to_hex(), Utc::now())
        .await
        .map_err(|error| {
            PeerRuntimeError::Routing(crate::routing::OwnerRoutingError::Catalog(error))
        })?
        .ok_or(DeviceRouteError::UnknownCredential)?;
    let route = match peer
        .resolve(
            OwnerScope::new(device.tenant_id, device.device_id),
            Utc::now(),
        )
        .await
    {
        Ok(route) => route,
        Err(error) if allow_fresh_control && is_no_live_owner(&error) => return Ok(None),
        Err(error) => return Err(error.into()),
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
    peer_admits_public_work(state.peer.as_ref())
}

/// Whether public work may be admitted, given this relay's optional peer
/// runtime.
///
/// Public admission and `/readyz` are deliberately the same single call to
/// [`PeerRuntime::is_ready`], which reads the transport pin set, membership
/// readiness and the whole peer readiness state. There is therefore no second
/// admission fence to raise or lower: readiness and admission withdraw
/// together and recover together, and no observer can see one without the
/// other. See `peer_readiness_and_admission_never_disagree`.
pub(crate) fn peer_admits_public_work(peer: Option<&Arc<PeerRuntime>>) -> bool {
    peer.is_none_or(|peer| peer.is_ready())
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
            // The forwarded attach is answered on its own request stream, and
            // a duplicate exact-scope owner is answered `409 CONFLICT`.  That
            // is the same refusal the owner-local path closes with
            // `OWNER_BUSY`, so the device must see the same typed, bounded,
            // non-retryable close whichever relay it reached.  Dropping the
            // status here left a remote duplicate claim reporting an untyped
            // transport failure while a local one reported the exact terminal
            // diagnostic, for the same condition.
            let mut socket = socket;
            let device = identity.role_id().to_owned();
            let forwarded = handle_remote_device_control(&mut socket, identity, peer, route).await;
            if let Err(error) = forwarded {
                // M6-C38/M6-C43: every owner refusal no retry can fix reaches
                // the device typed, exactly as the owner-local path closes it.
                if let Some((close, refusal)) = remote_control_refusal_close(&error) {
                    log_device_refusal("control_forwarded", refusal, &device);
                    let _ = send_socket(&mut socket, close).await;
                }
                tracing::debug!(?error, "remote device control forwarding stopped");
            }
        }
        Ok(None) => {
            if !cluster_is_ready(&state) {
                let mut socket = socket;
                let _ = send_socket(&mut socket, Message::Close(None)).await;
                return;
            }
            let control_attach_barrier = state.control_attach_barrier.clone();
            let operation_timeout = state.limits.operation_timeout;
            handle_control(
                socket,
                identity,
                state.handle,
                control_attach_barrier,
                operation_timeout,
            )
            .await;
        }
        Err(DeviceRouteError::UnknownCredential) => {
            // M6-C43: the owner-local path's identity refusal, on the cluster
            // path.  Before this the socket closed without a reason, which the
            // device's reconnect loop retried indefinitely.
            log_device_refusal("control_route", "credential_not_active", identity.role_id());
            let mut socket = socket;
            let _ = send_socket(&mut socket, identity_rejected_close()).await;
        }
        Err(DeviceRouteError::Peer(error)) => {
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
    socket: &mut WebSocket,
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
                        if !send_socket(&mut *socket, Message::Pong(payload)).await { break; }
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
                        if !send_socket(&mut *socket, Message::Text(text.to_owned().into())).await { break; }
                    }
                    PeerRecordKind::Close => break,
                    _ => break,
                }
            }
        }
    }
    send.cancel();
    recv.cancel();
    let _ = send_socket(&mut *socket, Message::Close(None)).await;
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
    peer_ingress_handler_with_http_forward(
        handle,
        catalog,
        oidc,
        local_node_id,
        local_boot_id,
        None,
    )
}

/// [`peer_ingress_handler`] for an owner that also validates relayed
/// `http-forward/1` exchanges against `http_forward`'s profile.  Without an
/// export the owner refuses forwarded HTTP streams.
pub fn peer_ingress_handler_with_http_forward(
    handle: RelayHandle,
    catalog: SharedCatalog,
    oidc: Arc<OidcVerifier>,
    local_node_id: String,
    local_boot_id: String,
    http_forward: Option<crate::http::forward::HttpForwardExports>,
) -> impl PeerIngressHandler {
    move |request: InboundPeerRequest| {
        let handle = handle.clone();
        let catalog = catalog.clone();
        let oidc = oidc.clone();
        let local_node_id = local_node_id.clone();
        let local_boot_id = local_boot_id.clone();
        let http_forward = http_forward.clone();
        async move {
            handle_peer_ingress(
                request,
                handle,
                catalog,
                oidc,
                &local_node_id,
                &local_boot_id,
                http_forward,
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
    http_forward: Option<crate::http::forward::HttpForwardExports>,
) -> Result<(), PeerRuntimeError> {
    // The owner-side observer starts at the `owner` stage: every check
    // before the stream is split is this relay's own admission decision.
    // Handlers that unregister owner state record their tuple themselves
    // before that removal; this outer mapping only classifies faults that
    // escaped without a recorded tuple.
    let envelope = request.envelope();
    let service_id = match &envelope.request {
        InternalRequest::ConsumerStreams(_) => Some(envelope.destination.service_id),
        _ => None,
    };
    let fault = PeerFaultObserver::new(
        PeerFaultRole::Owner,
        PeerFaultContext::for_owner(
            &envelope.destination.owner_token,
            service_id,
            Some(envelope.request_id.clone()),
        ),
    );
    fault.mark(PeerOpenDiagnosticStage::Owner);
    let result = handle_peer_ingress_inner(
        request,
        &handle,
        catalog,
        oidc,
        local_node_id,
        local_boot_id,
        &fault,
        http_forward,
    )
    .await;
    if let Err(error) = &result {
        handle.record_peer_fault(&fault, error);
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn handle_peer_ingress_inner(
    request: InboundPeerRequest,
    handle: &RelayHandle,
    catalog: SharedCatalog,
    oidc: Arc<OidcVerifier>,
    local_node_id: &str,
    local_boot_id: &str,
    fault: &PeerFaultObserver,
    http_forward: Option<crate::http::forward::HttpForwardExports>,
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
    {
        return Err(PeerRuntimeError::Membership(
            "peer request is not for this owner".to_owned(),
        ));
    }
    if owner.lease_expires_at <= now {
        // The claim is this relay's, but its Redis lease has lapsed: a
        // distinct bounded stage from an owner mismatch.
        fault.mark(PeerOpenDiagnosticStage::Lease);
        return Err(PeerRuntimeError::Membership(
            "peer owner lease has expired".to_owned(),
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
            handle_peer_device_control(request, handle.clone(), device, fault).await
        }
        InternalRequest::DeviceData(request_body) => {
            let device = resolve_peer_device(&catalog, &request_body.authentication, now).await?;
            handle_peer_device_data(request, handle.clone(), device, fault).await
        }
        InternalRequest::ConsumerStreams(request_body)
            if request_body.required_scope == crate::HTTP_FORWARD_OPERATION =>
        {
            // The owner re-runs the shared resolver for the HTTP export type
            // and re-authorizes the grant operation itself; mTLS only
            // authenticated the forwarding relay.
            let access = owner_access.ok_or_else(|| {
                PeerRuntimeError::Membership("consumer authentication failed".to_owned())
            })?;
            let (grant, capabilities) = owner_stream_grant_of_type(
                &catalog,
                &access.consumer,
                destination.device_id,
                destination.service_id,
                access.expires_at,
                crate::HTTP_FORWARD_SERVICE_TYPE,
                crate::HTTP_FORWARD_OPERATION,
            )
            .await?;
            // The owner selects the profile from its own catalog read, never
            // from the forwarding relay's choice.
            let export = http_forward
                .as_ref()
                .and_then(|exports| exports.select(&capabilities));
            crate::http::forward::handle_peer_http_stream(
                request,
                handle.clone(),
                access.consumer,
                destination.device_id,
                destination.service_id,
                grant,
                access.expires_at,
                fault,
                export,
            )
            .await
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
                handle.clone(),
                access.consumer,
                destination.device_id,
                destination.service_id,
                grant,
                access.expires_at,
                request_body.stream_id,
                fault,
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
    owner_stream_grant_of_type(
        catalog,
        consumer,
        device_id,
        service_id,
        expires_at,
        crate::ECHO_SERVICE_TYPE,
        crate::ECHO_OPERATION,
    )
    .await
    .map(|(grant, _)| grant)
}

async fn owner_stream_grant_of_type(
    catalog: &SharedCatalog,
    consumer: &tunnel_catalog::AuthenticatedConsumer,
    device_id: Uuid,
    service_id: Uuid,
    expires_at: chrono::DateTime<Utc>,
    service_type: &str,
    operation: &str,
) -> Result<(tunnel_catalog::GrantSnapshot, serde_json::Value), PeerRuntimeError> {
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
    let service_id = crate::routing::resolve_service(
        &device.services,
        ServiceTarget::Id(service_id),
        service_type,
    )
    .map_err(|error| PeerRuntimeError::Membership(error.to_string()))?;
    let capabilities = device
        .services
        .iter()
        .find(|candidate| candidate.service_id == service_id)
        .map_or(serde_json::Value::Null, |candidate| {
            candidate.capabilities.clone()
        });
    let grant = catalog
        .authorize(consumer, device_id, service_id, Utc::now(), Utc::now())
        .await
        .map_err(|_| PeerRuntimeError::Membership("authorization unavailable".to_owned()))?
        .ok_or_else(|| PeerRuntimeError::Membership("service is not authorized".to_owned()))?;
    if !grant.permissions.allows(operation) {
        return Err(PeerRuntimeError::Membership(
            "service is not authorized".to_owned(),
        ));
    }
    let mut grant = grant;
    grant.valid_until = grant.valid_until.min(expires_at);
    Ok((grant, capabilities))
}

async fn handle_peer_device_control(
    request: InboundPeerRequest,
    handle: RelayHandle,
    device: tunnel_catalog::DeviceIdentity,
    fault: &PeerFaultObserver,
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
    // A refused registration -- a duplicate owner claim, an unauthorized
    // device, or a HELLO this cluster will not admit -- is an ordinary outcome
    // of this request, not a peer protocol violation.  It must be answered on
    // this request stream and finished, for the same reason the forwarded data
    // attachment below must be: returning here without responding finishes the
    // HTTP/3 request stream with no response headers, which the ingress
    // relay's h3 client raises as a CONNECTION-level `H3_FRAME_UNEXPECTED`,
    // tearing down the whole peer connection to this owner along with every
    // other forwarded device carrier multiplexed on it.
    let registration = match handle.register_forwarded_control(device, spki, hello).await {
        Ok(registration) => registration,
        Err(error) => {
            // A duplicate exact-scope owner keeps its own status, because the
            // local control path treats that refusal as its own typed outcome
            // rather than folding it in with an unauthorized device.  Neither
            // status carries session, owner, or device detail.
            let status = forwarded_control_refusal_status(&error);
            send.respond(status).await?;
            return send.finish().await;
        }
    };
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
    if let Err(error) = &result {
        // Recorded before the owner's control registration is removed.
        handle.record_peer_fault(fault, error);
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
    fault: &PeerFaultObserver,
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
    // A refused attachment -- a spent, unknown, or wrong-session attachment
    // ticket -- is an ordinary outcome of this request, not a peer protocol
    // violation.  It must be answered on this request stream and finished.
    //
    // Returning here without responding leaves the HTTP/3 request stream
    // finished with no response headers, which the ingress relay's h3 client
    // raises as a CONNECTION-level `H3_FRAME_UNEXPECTED`.  That tears down the
    // whole peer connection to this owner and with it every other forwarded
    // device carrier multiplexed on it, including healthy installed ones; the
    // owner then sees those carriers vanish and closes their sessions with
    // `RECOVERY_START_FAILED`.  One refused attachment must never cost another
    // device its session.
    let registration = match handle.attach_forwarded_data(device, spki, ticket).await {
        Ok(registration) => registration,
        Err(_) => {
            // Forbidden, not unavailable: the ticket was refused on its merits
            // and retrying the same attachment cannot succeed.  The status
            // carries no ticket, session, or owner detail.
            send.respond(StatusCode::FORBIDDEN).await?;
            return send.finish().await;
        }
    };
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
    if let Err(error) = &result {
        // Recorded before the forwarded data carrier is disconnected.
        handle.record_peer_fault(fault, error);
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
    fault: &PeerFaultObserver,
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
            handle.record_peer_fault_tuple(
                fault,
                PeerOpenDiagnosticStage::Owner,
                PeerFaultCause::OwnerNotReady,
            );
            return request.reject_owner_not_ready().await;
        }
        Err(RelayError::StreamLimit) => {
            handle.record_peer_fault_tuple(
                fault,
                PeerOpenDiagnosticStage::Owner,
                PeerFaultCause::Capacity,
            );
            return request.reject_stream_limit().await;
        }
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
    // The receive direction stays serviced while an actor write is
    // outstanding, so a peer reset or membership cancellation arriving on it
    // cannot be suppressed by the parked send direction.  At most one peer
    // event read ahead of the parked write is retained here; it is replayed
    // by the loop below once the write resolves.  Beyond that single bounded
    // slot the transport's own flow control applies, exactly as before.
    let mut lookahead: Option<Option<PeerRecord>> = None;
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
        fault.mark(PeerOpenDiagnosticStage::Body);
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
                inbound = async {
                    match lookahead.take() {
                        Some(inbound) => Ok(inbound),
                        None => recv.recv_message().await,
                    }
                } => {
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
                        let write = handle.write_echo_stream(
                            key.clone(),
                            stream_id,
                            operation_id.clone(),
                            body,
                        );
                        tokio::pin!(write);
                        // Keep the receive direction serviced while this
                        // write is outstanding.  A record or request end
                        // read ahead of the write is retained in the single
                        // lookahead slot and replayed after the response; a
                        // receive failure (peer reset or membership
                        // cancellation) ends the wait now instead of at the
                        // consumer's absolute deadline.  The transport idle
                        // timeout does not apply here: the ingress is
                        // legitimately silent while it waits for this parked
                        // response, so the read is bounded by the consumer's
                        // absolute deadline, the same instant `expires`
                        // observes.
                        let receive_deadline = expires.deadline();
                        let waited = loop {
                            let waited = tokio::select! {
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
                                    write.as_mut(),
                                    &registration.closed,
                                    &mut expires,
                                    async {
                                        if lookahead.is_some() {
                                            std::future::pending::<()>().await;
                                        }
                                        recv.recv_message_until(receive_deadline).await
                                    },
                                ) => waited,
                            };
                            match waited {
                                BoundedStreamWrite::PeerEvent(Ok(inbound)) => {
                                    lookahead = Some(inbound);
                                }
                                other => break other,
                            }
                        };
                        let response = match waited {
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
                            BoundedStreamWrite::PeerEvent(Ok(_)) => {
                                unreachable!("read-ahead peer events are retained, not returned")
                            }
                            BoundedStreamWrite::PeerEvent(Err(error)) => {
                                // The receive direction failed while this
                                // record was outstanding.  The write's
                                // outcome is unknown, like a closed stream,
                                // but the receive failure is the typed first
                                // cause and is recorded as such.
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
                                tracing::debug!(
                                    error = ?error,
                                    body_len,
                                    phase = "consumer_actor_write_receive_failed",
                                    "peer receive direction failed while a record was outstanding"
                                );
                                return Err(error);
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
    if let Err(error) = &result {
        // The tuple is recorded before the owner's stream registration is
        // closed so the fault outlives the owner state it describes.
        handle.record_peer_fault(fault, error);
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

async fn handle_control(
    mut socket: WebSocket,
    identity: TlsIdentity,
    handle: RelayHandle,
    control_attach_barrier: Option<Arc<ControlAttachBarrier>>,
    operation_timeout: Duration,
) {
    let first = match timeout(Duration::from_secs(10), socket.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => text,
        _ => return,
    };
    let hello = match wire::parse_control(first.as_bytes()) {
        Ok(value) => value,
        Err(_) => return,
    };
    // Fixture-only seam strictly between the device's HELLO and the
    // registration that produces its WELCOME.  Absent on every ordinary path.
    if let Some(barrier) = control_attach_barrier.as_ref() {
        barrier.wait_before_control_attach(operation_timeout).await;
    }
    let device = identity.role_id().to_owned();
    let registration = match handle.register_control(identity, hello).await {
        Ok(value) => value,
        Err(error) => {
            // M6-C32: `register_control` answers `Unauthorized` only for an
            // identity it will never accept -- a HELLO whose `connector_id` is
            // not the certificate's device, a non-device role, or no active
            // catalog device and credential for this key.  M6-C38: a HELLO on
            // another protocol major is refused typed too.  Closing without a
            // frame left the device reporting a retryable transport loss for
            // faults no retry can fix.
            if let Some((close, refusal)) = control_refusal_close(&error) {
                log_device_refusal("control_hello", refusal, &device);
                let _ = send_socket(&mut socket, close).await;
            }
            return;
        }
    };
    let key = registration.key.clone();
    let mut cleanup = handle.control_cleanup_guard(key.clone());
    if !send_socket(&mut socket, Message::Text(registration.welcome.into())).await {
        finish_control_task(&handle, key, TaskClosureCause::WriteFailed, &mut cleanup).await;
        return;
    }
    let mut rx = registration.rx;
    // EC-061: the closure cause for this task body.  Every exit from the loop
    // below sets it before breaking, so the tuple names the structural reason
    // the socket stopped rather than being reconstructed afterwards.  It is
    // observational: no branch, timeout or wire emission depends on it.
    // Deliberately uninitialised: every exit from the loop below assigns a
    // cause before it breaks, and leaving this without a default makes the
    // compiler prove that rather than a comment claim it.  A new exit path
    // that forgets to name its cause fails to compile.
    let closure_cause: TaskClosureCause;
    // M6-C68: the relay, not the device, must notice a vanished path.  It
    // pings every `DEVICE_CONTROL_PING_INTERVAL` and ends the session once
    // nothing at all has arrived for `DEVICE_CONTROL_IDLE_TIMEOUT`; the exit
    // is the same `finish_control_task` hand-off as a device's own close, so
    // the owner slot is released exactly as it is then.
    let mut liveness = ControlLiveness::new(tokio::time::Instant::now());
    let mut pings = control_ping_ticker();
    loop {
        let idle_deadline = liveness.deadline();
        // `biased`: arms are polled in the order written.  An unbiased select
        // picks at random among ready arms, so an inbound frame already
        // buffered when the idle deadline fires could lose to it and a live
        // device would be evicted.  Inbound therefore comes first and the
        // deadline last.  Under a constant inbound stream the Ping and
        // deadline arms may never be polled; that is intended, because every
        // inbound frame moves the deadline and a Ping would prove nothing
        // more.  The outbound arm can be delayed the same way, but only by
        // this device's own inbound traffic, so a device can slow nobody's
        // session but its own.
        tokio::select! {
            biased;
            inbound = socket.next() => {
                liveness.observe_inbound(tokio::time::Instant::now());
                match inbound {
                    Some(Ok(Message::Text(text))) if text.len() <= MAX_CONTROL_BYTES => {
                        if let Ok(message) = wire::parse_control(text.as_bytes()) {
                            let _ = handle.inbound_control(key.clone(), message).await;
                        } else { closure_cause = TaskClosureCause::ProtocolError; break; }
                    }
                    Some(Ok(Message::Ping(payload))) => { if !send_socket(&mut socket, Message::Pong(payload)).await { closure_cause = TaskClosureCause::WriteFailed; break; } }
                    // The answer to the relay's own liveness Ping.  Its only
                    // effect is the `observe_inbound` above.
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => { closure_cause = TaskClosureCause::PeerClosed; break; }
                    // The guarded text arm above already took every in-window
                    // control frame, so this arm is exactly the over-window
                    // one.  It breaks as it always did; only the attribution
                    // is new.
                    Some(Ok(Message::Text(_))) => { closure_cause = TaskClosureCause::RecordTooLarge; break; }
                    _ => { closure_cause = TaskClosureCause::UnexpectedMessage; break; }
                }
            }
            outbound = rx.recv() => {
                match outbound {
                    Some(crate::actor::ControlOutbound::Text(text)) => {
                        let (text, mut charge) = text.into_parts();
                        let sent = send_socket(&mut socket, Message::Text(text.into())).await;
                        charge.release();
                        if !sent { closure_cause = TaskClosureCause::WriteFailed; break; }
                    }
                    Some(crate::actor::ControlOutbound::Close) | None => { let _ = send_socket(&mut socket, Message::Close(None)).await; closure_cause = TaskClosureCause::ServerClose; break; }
                }
            }
            _ = pings.tick() => {
                if !send_socket(&mut socket, Message::Ping(Default::default())).await { closure_cause = TaskClosureCause::WriteFailed; break; }
            }
            () = tokio::time::sleep_until(idle_deadline) => {
                tracing::info!(
                    device_id = %key.device_id,
                    session_id = %key.session_id,
                    epoch = key.epoch,
                    idle_timeout_ms = u64::try_from(DEVICE_CONTROL_IDLE_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
                    phase = "control_liveness_timeout",
                );
                closure_cause = TaskClosureCause::LivenessTimeout;
                break;
            }
        }
    }
    // Close admission to this writer before releasing every queued charge.
    // The actor may still hold a sender until it processes the disconnect.
    rx.close();
    while rx.try_recv().is_ok() {}
    finish_control_task(&handle, key, closure_cause, &mut cleanup).await;
}

/// Task row M6-C68: the idle deadline of one device control socket.
///
/// Only inbound frames move the deadline.  A relay write completes into the
/// kernel's send buffer whether or not anyone is still at the other end, so
/// it proves nothing about the path; the device's Pong to the relay's Ping
/// does.
#[derive(Clone, Copy, Debug)]
struct ControlLiveness {
    last_inbound: tokio::time::Instant,
}

impl ControlLiveness {
    fn new(admitted_at: tokio::time::Instant) -> Self {
        Self {
            last_inbound: admitted_at,
        }
    }

    fn observe_inbound(&mut self, at: tokio::time::Instant) {
        self.last_inbound = self.last_inbound.max(at);
    }

    fn deadline(&self) -> tokio::time::Instant {
        self.last_inbound + DEVICE_CONTROL_IDLE_TIMEOUT
    }
}

/// The relay's Ping schedule on one device control socket: the first Ping one
/// interval after admission, and a late tick is delayed rather than burst.
fn control_ping_ticker() -> tokio::time::Interval {
    let mut pings = tokio::time::interval_at(
        tokio::time::Instant::now() + DEVICE_CONTROL_PING_INTERVAL,
        DEVICE_CONTROL_PING_INTERVAL,
    );
    pings.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    pings
}

/// EC-061: the single exit of the owner-local control task.
///
/// The bounded closure tuple is recorded *before* the disconnect command is
/// sent, so it is strictly below the `Session` unregister tombstone the actor
/// stamps when `close_session` removes the session this key names.  Both
/// statements live in one function precisely so the ordering is exercised by
/// a regression instead of being asserted in prose.  Recording takes only the
/// diagnostics mutex: it performs no I/O, enters no actor mailbox and takes
/// no session lock, so it cannot change when the disconnect lands.
async fn finish_control_task(
    handle: &RelayHandle,
    key: SessionKey,
    cause: TaskClosureCause,
    cleanup: &mut TerminalCleanupGuard,
) {
    handle.record_task_closure(
        &TaskClosureScope {
            tenant_id: key.tenant_id,
            device_id: key.device_id,
            session_id: key.session_id.clone(),
            epoch: key.epoch,
            stream_id: None,
        },
        TaskClosureStage::Control,
        cause,
    );
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
    // EC-061: see `handle_control`.  Every break below sets this first.
    // Deliberately uninitialised: every exit from the loop below assigns a
    // cause before it breaks, and leaving this without a default makes the
    // compiler prove that rather than a comment claim it.  A new exit path
    // that forgets to name its cause fails to compile.
    let closure_cause: TaskClosureCause;
    loop {
        tokio::select! {
            inbound = socket.next() => {
                match inbound {
                    Some(Ok(Message::Binary(bytes))) if bytes.len() <= tunnel_protocol::frame::MAX_FRAME_LEN => {
                        let _ = handle.inbound_data(carrier.clone(), bytes.to_vec()).await;
                    }
                    Some(Ok(Message::Ping(payload))) => { if !send_socket(&mut socket, Message::Pong(payload)).await { closure_cause = TaskClosureCause::WriteFailed; break; } }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => { closure_cause = TaskClosureCause::PeerClosed; break; }
                    // The guarded binary arm above took every in-window data
                    // frame, so this arm is exactly the over-window one.
                    Some(Ok(Message::Binary(_))) => { closure_cause = TaskClosureCause::RecordTooLarge; break; }
                    _ => { closure_cause = TaskClosureCause::UnexpectedMessage; break; }
                }
            }
            outbound = rx.recv() => {
                match outbound {
                    Some(crate::actor::DataOutbound::Binary(bytes)) => {
                        let (bytes, mut charge) = bytes.into_parts();
                        let sent = send_socket(&mut socket, Message::Binary(bytes.into())).await;
                        charge.release();
                        if !sent { closure_cause = TaskClosureCause::WriteFailed; break; }
                    }
                    Some(crate::actor::DataOutbound::Barrier(done)) => {
                        let _ = done.send(());
                    }
                    Some(crate::actor::DataOutbound::Close) | None => { let _ = send_socket(&mut socket, Message::Close(None)).await; closure_cause = TaskClosureCause::ServerClose; break; }
                }
            }
        }
    }
    rx.close();
    while rx.try_recv().is_ok() {}
    finish_data_task(&handle, carrier, closure_cause, &mut cleanup).await;
}

/// EC-061: the single exit of the owner-local data carrier task.
///
/// The closure tuple is recorded before the disconnect command is sent, so it
/// is strictly below the `DataCarrier` unregister tombstone the actor stamps
/// in `disconnect_data_at` when it drops `data_tx` and `active_carrier`.
async fn finish_data_task(
    handle: &RelayHandle,
    carrier: CarrierKey,
    cause: TaskClosureCause,
    cleanup: &mut TerminalCleanupGuard,
) {
    handle.record_task_closure(
        &TaskClosureScope {
            tenant_id: carrier.session.tenant_id,
            device_id: carrier.session.device_id,
            session_id: carrier.session.session_id.clone(),
            epoch: carrier.session.epoch,
            stream_id: None,
        },
        TaskClosureStage::Data,
        cause,
    );
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

fn identity_rejected_close() -> Message {
    Message::Close(Some(CloseFrame {
        code: CONTROL_IDENTITY_REJECTED_CLOSE_CODE,
        reason: CONTROL_IDENTITY_REJECTED_CLOSE_REASON.into(),
    }))
}

fn protocol_unsupported_close() -> Message {
    Message::Close(Some(CloseFrame {
        code: CONTROL_PROTOCOL_UNSUPPORTED_CLOSE_CODE,
        reason: CONTROL_PROTOCOL_UNSUPPORTED_CLOSE_REASON.into(),
    }))
}

/// The typed close, and the bounded refusal label logged with it, for a
/// control registration the owner-local path refused.  `None` for a refusal
/// that may heal (catalog, capacity, shutdown), which keeps its untyped close
/// and is retried by the device.
fn control_refusal_close(error: &RelayError) -> Option<(Message, &'static str)> {
    match error {
        RelayError::OwnerBusy => Some((owner_busy_close(), "owner_busy")),
        RelayError::Unauthorized => Some((identity_rejected_close(), "identity_rejected")),
        RelayError::UnsupportedProtocolMajor => {
            Some((protocol_unsupported_close(), "protocol_major_unsupported"))
        }
        _ => None,
    }
}

/// The HTTP status an owner answers a forwarded control registration's
/// refusal with.  The ingress turns exactly these three back into the typed
/// closes of [`control_refusal_close`] (see [`remote_control_refusal_close`]),
/// so a device reaching a non-owner relay is told the same thing as one
/// reaching the owner.  Every other refusal -- catalog, capacity, shutdown --
/// may heal and is `503`, which the ingress keeps as an untyped close.
///
/// **The statuses are chosen so a mixed-version cluster is safe during a
/// rolling upgrade (review of M6-C38).**  An owner from before M6-C38 answers
/// `409` for owner busy and `403` for *every* other refusal, a catalog outage
/// included.  A refused identity is therefore `401` here, a status an older
/// owner never sends for a control registration, and the ingress treats `403`
/// as that older owner's catch-all: an untyped, retried close, exactly as
/// before M6-C38.  So no new ingress can turn an old owner's transient
/// refusal into a terminal exit, and the only cost of the mix is that an old
/// owner's genuine identity refusal is still retried until it is upgraded.
/// The protocol-major refusal (`426`) is likewise never sent by an old owner.
fn forwarded_control_refusal_status(error: &RelayError) -> StatusCode {
    match error {
        RelayError::OwnerBusy => StatusCode::CONFLICT,
        RelayError::Unauthorized => StatusCode::UNAUTHORIZED,
        RelayError::UnsupportedProtocolMajor => StatusCode::UPGRADE_REQUIRED,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// The ingress half of [`forwarded_control_refusal_status`].
fn remote_control_refusal_close(error: &PeerRuntimeError) -> Option<(Message, &'static str)> {
    match error {
        PeerRuntimeError::RemoteStatus(StatusCode::CONFLICT) => {
            Some((owner_busy_close(), "owner_busy"))
        }
        PeerRuntimeError::RemoteStatus(StatusCode::UNAUTHORIZED) => {
            Some((identity_rejected_close(), "identity_rejected"))
        }
        // `403` is only ever an owner from before M6-C38, whose `403` also
        // covers refusals that heal: keep it retryable (see above).
        PeerRuntimeError::RemoteStatus(StatusCode::UPGRADE_REQUIRED) => {
            Some((protocol_unsupported_close(), "protocol_major_unsupported"))
        }
        _ => None,
    }
}

/// Task row M6-C52: one bounded, payload-free line per refused device
/// session.  `stage` and `refusal` are fixed labels; `certificate_device` is
/// the identifier in the TLS-verified certificate's role SAN, never anything
/// the device sent in its HELLO, and nothing else about the device, the
/// session or its credential is logged.
fn log_device_refusal(stage: &'static str, refusal: &'static str, certificate_device: &str) {
    // The role SAN is a bounded identifier the verifier already parsed, but
    // it is still certificate content: log it only when it is a UUID.
    let certificate_device = certificate_device
        .parse::<Uuid>()
        .map_or_else(|_| "not_a_uuid".to_owned(), |id| id.to_string());
    tracing::info!(
        phase = "device_refused",
        stage,
        refusal,
        certificate_device = %certificate_device,
        "device session refused"
    );
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
/// token, the consumer's absolute authorization deadline, and the peer
/// receive direction stay observable.
enum BoundedStreamWrite<T, P> {
    Completed(T),
    StreamClosed,
    Expired,
    /// The peer receive direction produced an event first.  The write is
    /// still outstanding: the caller retains a successful read and keeps
    /// waiting, or treats a receive failure as the typed first cause.
    PeerEvent(P),
}

/// Await one actor stream write without losing sight of the stream or of the
/// peer.  The actor fails waiters when it closes a stream, but a record parked
/// behind a pending device authorization is otherwise bounded by nothing the
/// handler observes.  Closure and the absolute deadline are checked first,
/// matching the handlers' read loops, so a ready or late response cannot
/// outlive the consumer's authorization; a completed write is returned before
/// a concurrent peer event so a known outcome is never discarded.  The write
/// is pinned by the caller so a peer read-ahead does not abandon it.  An
/// abandoned write has an unknown outcome; the caller classifies it exactly
/// as a failed actor reply.
async fn write_until_closed_or_expired<F, P>(
    write: std::pin::Pin<&mut F>,
    closed: &tokio_util::sync::CancellationToken,
    expires: &mut std::pin::Pin<&mut tokio::time::Sleep>,
    peer: P,
) -> BoundedStreamWrite<F::Output, P::Output>
where
    F: std::future::Future,
    P: std::future::Future,
{
    tokio::select! {
        biased;
        _ = closed.cancelled() => BoundedStreamWrite::StreamClosed,
        _ = expires.as_mut() => BoundedStreamWrite::Expired,
        result = write => BoundedStreamWrite::Completed(result),
        event = peer => BoundedStreamWrite::PeerEvent(event),
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
        // Every site that raises transport capacity does so strictly before
        // anything is written to the owner: acquiring a connection permit,
        // acquiring a stream permit on an existing connection, and the dial
        // pool's destination bound.  The request cannot have reached the
        // owner, so this is `not_dispatched`, and reporting it as `unknown`
        // denied a consumer a retry it is entitled to make for a safe request.
        // It stays `PEER_UNAVAILABLE`: from the consumer's side this ingress
        // could not reach the owner at all.
        PeerRuntimeError::Transport(PeerTransportError::Capacity) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "PEER_UNAVAILABLE",
            "not_dispatched",
        ),
        // This relay currently publishes no approved peer trust evidence, so
        // the dial was refused by its own verifier before a socket was opened
        // or a certificate examined: nothing reached any owner, which makes
        // this `not_dispatched` rather than the `unknown` the generic
        // transport arm below gives.  Reporting it as `unknown` denied a
        // consumer the retry it is entitled to make for a safe request, which
        // is what `verify-m3-mcp-isolation` saw a request issued just after a
        // membership re-sign receive (M7-C83).  The condition is this relay's
        // own transient state and its membership coordinator republishes on a
        // bounded schedule, so the answer carries the retry hint too.
        PeerRuntimeError::Transport(PeerTransportError::PinsUnavailable) => {
            return peer_trust_unavailable_response();
        }
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

/// How long a consumer should wait before retrying a request refused because
/// this relay publishes no approved peer trust evidence.
///
/// The membership coordinator republishes the pin set on its own bounded
/// refresh tick, which the cluster configuration caps at five seconds, so this
/// is that cap rather than the much shorter owner-readiness hint: a consumer
/// that retried in 250 ms would simply be refused again.
const PEER_TRUST_UNAVAILABLE_RETRY_AFTER_MS: u64 = 5_000;

/// The typed answer for a dial refused before it left this relay because no
/// approved peer trust evidence is currently published.
///
/// Distinct from [`retryable_peer_failure_response`] in its hint and its
/// message only: both are `PEER_UNAVAILABLE` / `not_dispatched` / retryable,
/// because in both cases nothing reached the owner and the condition clears
/// on its own.
fn peer_trust_unavailable_response() -> Response {
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorBody {
            code: "PEER_UNAVAILABLE",
            execution: "not_dispatched",
            message: "no approved peer trust evidence is published; retry after the bounded hint",
            retryable: Some(true),
            retry_after_ms: Some(PEER_TRUST_UNAVAILABLE_RETRY_AFTER_MS),
        }),
    )
        .into_response();
    let retry_after_seconds = PEER_TRUST_UNAVAILABLE_RETRY_AFTER_MS.div_ceil(1_000);
    if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
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
    // M6-C68: the device control idle deadline.  Only an inbound frame moves
    // it, it never moves backwards, and a live device's Pong -- due every
    // Ping interval -- keeps it ahead of the next Ping with room for two
    // missed ones.
    #[test]
    fn control_liveness_deadline_follows_only_the_latest_inbound_frame() {
        use super::{ControlLiveness, DEVICE_CONTROL_IDLE_TIMEOUT, DEVICE_CONTROL_PING_INTERVAL};
        let admitted = tokio::time::Instant::now();
        let mut liveness = ControlLiveness::new(admitted);
        assert_eq!(liveness.deadline(), admitted + DEVICE_CONTROL_IDLE_TIMEOUT);
        let pong = admitted + DEVICE_CONTROL_PING_INTERVAL;
        liveness.observe_inbound(pong);
        assert_eq!(liveness.deadline(), pong + DEVICE_CONTROL_IDLE_TIMEOUT);
        liveness.observe_inbound(admitted);
        assert_eq!(
            liveness.deadline(),
            pong + DEVICE_CONTROL_IDLE_TIMEOUT,
            "an older observation must not pull the deadline back"
        );
        assert!(liveness.deadline() >= pong + DEVICE_CONTROL_PING_INTERVAL * 3);
    }

    use super::{
        ConsumerUpgradeBarrier, ControlAttachBarrier, PeerAdmissionBarrier,
        PeerAdmissionBarrierError, PeerAdmissionScope, control_refusal_close,
        forwarded_bearer_token, forwarded_control_refusal_status, is_no_live_owner,
        method_not_allowed, owner_busy_close, peer_consumer_diagnostic_outcome,
        peer_failure_response, remote_control_refusal_close, service_resolution_response,
        stream_limit_response,
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

    #[tokio::test]
    async fn control_attach_barrier_is_one_shot_and_bounded() {
        let barrier = ControlAttachBarrier::default();
        assert!(barrier.arm());
        assert!(!barrier.arm());

        let waiter = tokio::spawn({
            let barrier = barrier.clone();
            async move {
                barrier
                    .wait_before_control_attach(std::time::Duration::from_secs(1))
                    .await;
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), barrier.wait_reached())
            .await
            .expect("control attach barrier should be reached");
        assert_eq!(barrier.hit_count(), 1);
        assert!(barrier.is_held());
        assert!(!barrier.arm());
        barrier.release();
        assert!(!barrier.is_held());
        waiter.await.expect("bounded control attach waiter");
        assert!(!barrier.arm());
    }

    /// A released control-attach barrier is a pass-through, never a refusal:
    /// a later control attach returns immediately and adds no hit.  This is
    /// the property that makes the seam invisible to every control socket
    /// other than the single one a fixture deliberately races.
    #[tokio::test]
    async fn released_control_attach_barrier_passes_later_attaches_through() {
        let barrier = ControlAttachBarrier::default();
        assert!(barrier.arm());
        barrier.release();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            barrier.wait_before_control_attach(std::time::Duration::from_secs(30)),
        )
        .await
        .expect("a released barrier must not hold a later control attach");
        assert_eq!(barrier.hit_count(), 0);
        assert!(!barrier.is_held());
    }

    /// An unarmed barrier holds nothing at all, so the seam cannot change
    /// relay behaviour before a fixture arms it.
    #[tokio::test]
    async fn idle_control_attach_barrier_holds_nothing() {
        let barrier = ControlAttachBarrier::default();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            barrier.wait_before_control_attach(std::time::Duration::from_secs(30)),
        )
        .await
        .expect("an idle barrier must not hold a control attach");
        assert_eq!(barrier.hit_count(), 0);
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

    /// M6-C38/M6-C43: every HELLO refusal no retry can fix closes typed, on
    /// the owner-local path and -- through the owner's status and the
    /// ingress's reverse mapping -- on the forwarded path, and each path
    /// gives the device the same close for the same refusal.  A refusal that
    /// may heal stays untyped (`None`) so the device retries it, and on the
    /// forwarded path it is no longer the `403` the ingress now reads as a
    /// refused identity.
    #[test]
    fn control_refusals_close_typed_on_the_local_and_the_forwarded_path() {
        use crate::actor::RelayError;
        fn close_of(message: &Message) -> (u16, String) {
            match message {
                Message::Close(Some(frame)) => (frame.code, frame.reason.to_string()),
                other => panic!("not a close frame: {other:?}"),
            }
        }
        let cases = [
            (
                RelayError::OwnerBusy,
                (
                    CONTROL_OWNER_BUSY_CLOSE_CODE,
                    CONTROL_OWNER_BUSY_CLOSE_REASON,
                ),
            ),
            (
                RelayError::Unauthorized,
                (
                    tunnel_protocol::CONTROL_IDENTITY_REJECTED_CLOSE_CODE,
                    tunnel_protocol::CONTROL_IDENTITY_REJECTED_CLOSE_REASON,
                ),
            ),
            (
                RelayError::UnsupportedProtocolMajor,
                (
                    tunnel_protocol::CONTROL_PROTOCOL_UNSUPPORTED_CLOSE_CODE,
                    tunnel_protocol::CONTROL_PROTOCOL_UNSUPPORTED_CLOSE_REASON,
                ),
            ),
        ];
        for (error, (code, reason)) in cases {
            let (local, local_label) = control_refusal_close(&error).expect("typed locally");
            assert_eq!(close_of(&local), (code, reason.to_owned()), "{error}");
            let status = forwarded_control_refusal_status(&error);
            let (remote, remote_label) =
                remote_control_refusal_close(&PeerRuntimeError::RemoteStatus(status))
                    .expect("typed through the ingress");
            assert_eq!(close_of(&remote), (code, reason.to_owned()), "{error}");
            assert_eq!(local_label, remote_label);
        }
        for transient in [
            RelayError::Catalog("catalog unavailable".to_owned()),
            RelayError::Overloaded("relay device capacity is exhausted"),
            RelayError::Shutdown,
            RelayError::Protocol("cluster session requires owner-fencing-v1".to_owned()),
        ] {
            assert!(control_refusal_close(&transient).is_none(), "{transient}");
            let status = forwarded_control_refusal_status(&transient);
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{transient}");
            assert!(
                remote_control_refusal_close(&PeerRuntimeError::RemoteStatus(status)).is_none(),
                "{transient}"
            );
        }
        // Review of M6-C38, mixed-version cluster: an owner from before
        // M6-C38 answers `403` for every non-busy refusal, a catalog outage
        // included, so a new ingress must keep `403` retryable.  Only `409`
        // means the same thing to both versions.
        assert!(
            remote_control_refusal_close(&PeerRuntimeError::RemoteStatus(StatusCode::FORBIDDEN))
                .is_none(),
            "an old owner's catch-all 403 must not become a terminal close"
        );
        for error in [
            RelayError::Unauthorized,
            RelayError::UnsupportedProtocolMajor,
            RelayError::Catalog("catalog unavailable".to_owned()),
        ] {
            assert_ne!(
                forwarded_control_refusal_status(&error),
                StatusCode::FORBIDDEN,
                "{error}: a new owner never sends the old catch-all"
            );
        }
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

        // Ingress-local transport capacity: every site that raises it does so
        // before anything is written to the owner -- the connection permit,
        // the per-connection stream permit, and the dial pool's destination
        // bound -- so the request provably never reached the owner.  Reporting
        // it as `unknown` claimed uncertainty the relay does not have and
        // denied a consumer the retry a safe request is entitled to.
        let transport_capacity = peer_failure_response(PeerRuntimeError::Transport(
            tunnel_transport::PeerTransportError::Capacity,
        ));
        assert_eq!(transport_capacity.status(), StatusCode::SERVICE_UNAVAILABLE);
        let transport_capacity_body = axum::body::to_bytes(transport_capacity.into_body(), 1024)
            .await
            .expect("bounded transport capacity body");
        let transport_capacity_body: serde_json::Value =
            serde_json::from_slice(&transport_capacity_body)
                .expect("transport capacity response JSON");
        assert_eq!(transport_capacity_body["code"], "PEER_UNAVAILABLE");
        assert_eq!(transport_capacity_body["execution"], "not_dispatched");
    }

    #[tokio::test]
    async fn unpublished_peer_trust_is_not_dispatched_and_retryable() {
        // M7-C83.  A dial refused because this relay publishes no approved
        // peer trust evidence never opened a socket, never examined a peer
        // certificate and never wrote anything, so it is `not_dispatched`.
        // It used to fall into the generic transport arm below and answer
        // `unknown`, which is what a request issued just after a membership
        // re-sign received: certainty the relay did not have, and no retry a
        // safe request could act on.  The condition is this relay's own
        // transient state and clears on the bounded membership refresh tick,
        // so the answer also carries the hint.
        let response = peer_failure_response(PeerRuntimeError::Transport(
            tunnel_transport::PeerTransportError::PinsUnavailable,
        ));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("5")
        );
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("bounded trust-unavailable body");
        let body: serde_json::Value =
            serde_json::from_slice(&body).expect("trust-unavailable response JSON");
        assert_eq!(body["code"], "PEER_UNAVAILABLE");
        assert_eq!(body["execution"], "not_dispatched");
        assert_eq!(body["retryable"], true);
        assert_eq!(body["retry_after_ms"], 5_000);

        // An authentication failure against a peer that *was* dialled stays
        // `unknown`: a certificate was examined, so the relay cannot claim
        // nothing happened.  The two must not collapse into one arm.
        let authentication = peer_failure_response(PeerRuntimeError::Transport(
            tunnel_transport::PeerTransportError::Authentication("peer".to_owned()),
        ));
        let authentication_body = axum::body::to_bytes(authentication.into_body(), 1024)
            .await
            .expect("bounded authentication body");
        let authentication_body: serde_json::Value =
            serde_json::from_slice(&authentication_body).expect("authentication response JSON");
        assert_eq!(authentication_body["execution"], "unknown");
        assert!(authentication_body.get("retryable").is_none());
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
    type PeerRead = Result<Option<()>, PeerRuntimeError>;

    // The relay's tokio build has no paused test clock, so these bounds use
    // short real timers with generous upper margins, like the response-write
    // deadline tests in `consumer_write_diagnostics`.

    #[tokio::test]
    async fn outstanding_stream_write_observes_stream_closure() {
        let closed = tokio_util::sync::CancellationToken::new();
        let expires = tokio::time::sleep(std::time::Duration::from_secs(60));
        tokio::pin!(expires);
        let write = std::future::pending::<EchoWrite>();
        tokio::pin!(write);
        let waiter = super::write_until_closed_or_expired(
            write.as_mut(),
            &closed,
            &mut expires,
            std::future::pending::<PeerRead>(),
        );
        let closer = async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            closed.cancel();
        };
        let (outcome, ()) = tokio::join!(waiter, closer);
        assert!(matches!(outcome, super::BoundedStreamWrite::StreamClosed));
    }

    #[tokio::test]
    async fn outstanding_stream_write_observes_a_peer_receive_failure() {
        // EC-045: the receive direction stays observable while the send
        // direction is parked on the write, and it ends the wait promptly
        // rather than at the absolute deadline.
        let closed = tokio_util::sync::CancellationToken::new();
        let expires = tokio::time::sleep(std::time::Duration::from_secs(60));
        tokio::pin!(expires);
        let write = std::future::pending::<EchoWrite>();
        tokio::pin!(write);
        let started = tokio::time::Instant::now();
        let outcome =
            super::write_until_closed_or_expired(write.as_mut(), &closed, &mut expires, async {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                Err::<Option<()>, _>(PeerRuntimeError::Transport(
                    tunnel_transport::PeerTransportError::H3("H3_REQUEST_CANCELLED".to_owned()),
                ))
            })
            .await;
        assert!(matches!(
            outcome,
            super::BoundedStreamWrite::PeerEvent(Err(PeerRuntimeError::Transport(
                tunnel_transport::PeerTransportError::H3(_)
            )))
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        // The write itself was not abandoned by the peer event: the caller
        // still holds the pinned future and may keep waiting on it.
        assert!(matches!(
            futures_util::poll!(write.as_mut()),
            std::task::Poll::Pending
        ));
    }

    #[tokio::test]
    async fn outstanding_stream_write_is_bounded_by_the_absolute_deadline() {
        let closed = tokio_util::sync::CancellationToken::new();
        let expires = tokio::time::sleep(std::time::Duration::from_millis(50));
        tokio::pin!(expires);
        let started = tokio::time::Instant::now();
        let write = std::future::pending::<EchoWrite>();
        tokio::pin!(write);
        let outcome = super::write_until_closed_or_expired(
            write.as_mut(),
            &closed,
            &mut expires,
            std::future::pending::<PeerRead>(),
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
        let write = async { Ok::<Vec<u8>, crate::actor::EchoOutcome>(vec![0, 0, 0, 1, 7]) };
        tokio::pin!(write);
        // A ready peer event never discards a completed write's known outcome.
        let outcome = super::write_until_closed_or_expired(
            write.as_mut(),
            &closed,
            &mut expires,
            std::future::ready(Ok::<Option<()>, PeerRuntimeError>(None)),
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
        let write = std::future::ready(Ok::<Vec<u8>, crate::actor::EchoOutcome>(Vec::new()));
        tokio::pin!(write);
        let outcome = super::write_until_closed_or_expired(
            write.as_mut(),
            &closed,
            &mut expires,
            std::future::pending::<PeerRead>(),
        )
        .await;
        assert!(matches!(outcome, super::BoundedStreamWrite::StreamClosed));

        // A deadline that has already fired stays observable: the handlers
        // poll the same pinned timer again after their read loop saw it.
        let live = tokio_util::sync::CancellationToken::new();
        let expired = tokio::time::sleep(std::time::Duration::ZERO);
        tokio::pin!(expired);
        expired.as_mut().await;
        let write = std::future::ready(Ok::<Vec<u8>, crate::actor::EchoOutcome>(Vec::new()));
        tokio::pin!(write);
        let outcome = super::write_until_closed_or_expired(
            write.as_mut(),
            &live,
            &mut expired,
            std::future::pending::<PeerRead>(),
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
mod task_closure_tests;

#[cfg(test)]
mod consumer_authentication_status_tests {
    use super::{StatusCode, consumer_authentication_response};
    use tunnel_catalog::{CatalogError, OidcError};

    #[tokio::test]
    async fn a_catalog_failure_is_unavailable_not_a_credential_rejection() {
        // The credential was never evaluated, so calling it rejected tells a
        // consumer holding good credentials that they were refused, and is
        // indistinguishable at the HTTP boundary from a real refusal.
        let response = consumer_authentication_response(
            &OidcError::Catalog(CatalogError::Conflict("catalog unreachable")),
            "unit",
        );
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("bounded body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("response JSON");
        assert_eq!(body["code"], "AUTHORIZATION_UNAVAILABLE");
        assert_eq!(body["execution"], "not_dispatched");
    }

    #[tokio::test]
    async fn an_evaluated_credential_is_still_rejected_as_unauthorized() {
        // The other direction matters just as much: an availability status
        // must not start swallowing genuine credential rejections.
        // `InsufficientScope` is no longer among them: since M6-C53 it is a
        // `403`, asserted in `consumer_refusal_tests`.
        for error in [
            OidcError::MissingBearer,
            OidcError::InvalidToken,
            OidcError::ClaimsRejected,
            OidcError::DisallowedAlgorithm,
            OidcError::MissingKeyId,
            OidcError::UnknownKey,
            OidcError::UnknownConsumer,
        ] {
            let response = consumer_authentication_response(&error, "unit");
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "an evaluated credential failure must stay a rejection"
            );
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .expect("bounded body");
            let body: serde_json::Value = serde_json::from_slice(&body).expect("response JSON");
            assert_eq!(body["code"], "UNAUTHORIZED");
            assert_eq!(body["execution"], "not_dispatched");
        }
    }
}

#[cfg(test)]
mod tenant_admission_tests;

#[cfg(test)]
mod consumer_refusal_tests;
