use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    error::Error,
    future::Future,
    panic::AssertUnwindSafe,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use axum::Router;
use chrono::{Duration as ChronoDuration, Utc};
use futures_util::FutureExt;
use tokio::{
    net::TcpListener,
    sync::{Notify, mpsc, oneshot},
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{
    AttachmentTicket, AttachmentTicketBinding, AttachmentTicketConsumeRequest,
    AttachmentTicketIssueRequest, AuthenticatedConsumer, CatalogError, ConsumedAttachmentTicket,
    DeviceIdentity, GrantSnapshot, OwnerClaimRequest, OwnerToken, SharedCatalog,
};
use tunnel_protocol::control_journal::{
    ControlJournal, JournalError, Observation as JournalObservation,
};
use tunnel_protocol::rotation::{
    ClosureEvidence, RecoveryReason, RotationPhase, RotationSide, RotationState, RotationStatus,
    ValidatedRecovery, recovery_retry_delay_ms,
};
use tunnel_protocol::rotation_control::{
    DataAttachmentPurpose, DrainProof, DrainProofRef, DrainSet, FenceSnapshot, RecoverySide,
    ResumeDirectionState, ResumeStage, RotationAttemptIdentity, StreamFence, StreamRoster,
};
use tunnel_protocol::{
    AuthorizationChallenge, ControlMessage, Direction, Frame, FrameKind, Hello, OwnerFence,
    OwnerFenced, ReceiveDisposition, RecoveryClosed, RecoveryPlan, StreamSnapshot, StreamState,
    Terminal,
};
use tunnel_transport::{
    CertificateRole, PeerServer, PeerServerDiagnostics, PeerTransportError, PeerTransportLimits,
    SharedPeerPins, TlsIdentity,
};
use uuid::Uuid;

use crate::{
    config::{RelayLimits, RelayOptions},
    consumer_write_diagnostics::{ConsumerWriteDiagnostics, ConsumerWriteScope},
    http,
    membership_runtime::PeerAdmissionCancellation,
    peer_consumer_transport_diagnostics::{
        PeerConsumerDiagnosticContext, PeerConsumerDiagnosticH3Code, PeerConsumerDiagnosticRole,
        PeerConsumerDiagnostics,
    },
    peer_runtime::peer_readiness::PeerListenerState,
    peer_transport_diagnostics::{
        PeerTransportDiagnosticOutcome, PeerTransportDiagnosticRole, PeerTransportDiagnostics,
    },
    runtime::{
        self, CarrierContext, RelayRotationSnapshot, RelaySessionSnapshot, RelaySnapshot,
        RelayStreamSnapshot, RotationDeadlineEvent, RuntimeProfile, SessionTerminalEvent,
        StreamTerminalCause, StreamTerminalEvent, StreamTerminalReceiptEvent,
    },
    wire::{self, WireError},
};

const AUTHORIZATION_LIFETIME: Duration = Duration::from_secs(5);
/// Reason recorded when a device answers with a challenge whose frozen
/// identity does not match the in-flight authorization.  It is outside the
/// narrower reasons mapped in `authorization_failure_code`, so it carries the
/// existing `AUTHORIZATION_INVALIDATED` code rather than adding a new one.
const CHALLENGE_MISMATCH_REASON: &str = "challenge mismatch";
const OWNER_LEASE_SAFETY_MARGIN: Duration = Duration::from_secs(5);
const MAX_ECHO_RESPONSE_EXTRA_BYTES: usize = 256;
const INITIAL_ATTACHMENT_PURPOSE: &str = "initial";
const CLEANUP_QUEUE_CAPACITY: usize = 64;
const CLEANUP_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);
const CLEANUP_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const RUNNING_RELAY_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const TERMINAL_CLEANUP_QUEUE_CAPACITY: usize = 64;
const MAX_ROTATION_DEADLINE_EVENTS: usize = 8;
const MAX_SESSION_TERMINAL_EVENTS: usize = 16;
const MAX_STREAM_TERMINAL_EVENTS: usize = 32;
const MAX_STREAM_TERMINAL_RECEIPT_EVENTS: usize = 32;
const OWNER_FORGET_FAILURE_TIMEOUT: Duration = Duration::from_secs(5);
// Terminal stream state is retained until the connector proves its final
// cursors with STREAM_FORGET.  A failed/closed writer cannot deliver that
// proof, so bound the retained table without evicting an identity that could
// still arrive late.  The active stream ceiling is separately enforced
// below, making this an explicit total-entry bound of at most 2 * N.
const RETAINED_ECHO_STREAM_FACTOR: usize = 2;
const AUTHORITY_UNAVAILABLE: &str = "AUTHORITY_UNAVAILABLE";
/// Typed session close reason when the pure rotation machine has claimed its
/// bounded connection-ID history.  Identifiers are never reused within a
/// session, so the connector must establish a fresh session/epoch.
const CONNECTION_HISTORY_EXHAUSTED: &str = "CONNECTION_HISTORY_EXHAUSTED";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MaintenanceAuthorityOperation {
    RenewOwner,
    ResolveDevice,
}

impl MaintenanceAuthorityOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::RenewOwner => "renew_owner",
            Self::ResolveDevice => "resolve_device",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MaintenanceAuthorityCategory {
    Timeout,
    RedisIo,
    RedisBackend,
    WrongType,
    Serialization,
    Conflict,
    Authorization,
    NotFound,
    InvalidInput,
    RevisionOverflow,
}

impl MaintenanceAuthorityCategory {
    fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::RedisIo => "redis_io",
            Self::RedisBackend => "redis_backend",
            Self::WrongType => "wrongtype",
            Self::Serialization => "serialization",
            Self::Conflict => "conflict",
            Self::Authorization => "authorization",
            Self::NotFound => "not_found",
            Self::InvalidInput => "invalid_input",
            Self::RevisionOverflow => "revision_overflow",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MaintenanceAuthorityFailure {
    operation: MaintenanceAuthorityOperation,
    category: MaintenanceAuthorityCategory,
    elapsed_ms: u64,
}

impl MaintenanceAuthorityFailure {
    fn from_catalog(
        operation: MaintenanceAuthorityOperation,
        error: &CatalogError,
        elapsed: Duration,
    ) -> Self {
        Self {
            operation,
            category: maintenance_authority_category(error),
            elapsed_ms: elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
        }
    }
}

fn maintenance_authority_category(error: &CatalogError) -> MaintenanceAuthorityCategory {
    match error {
        CatalogError::Database(error) => {
            let timed_out = error.source().and_then(|source| {
                source
                    .downcast_ref::<std::io::Error>()
                    .map(std::io::Error::kind)
            }) == Some(std::io::ErrorKind::TimedOut);
            if timed_out {
                MaintenanceAuthorityCategory::Timeout
            } else if error
                .detail()
                .is_some_and(|detail| detail.contains("WRONGTYPE"))
                || error.category() == "type error"
            {
                MaintenanceAuthorityCategory::WrongType
            } else if error.is_io_error() {
                MaintenanceAuthorityCategory::RedisIo
            } else {
                MaintenanceAuthorityCategory::RedisBackend
            }
        }
        CatalogError::Serialization(_) => MaintenanceAuthorityCategory::Serialization,
        CatalogError::Conflict(_)
        | CatalogError::OwnerBusy
        | CatalogError::StaleOwner
        | CatalogError::InvalidOwner => MaintenanceAuthorityCategory::Conflict,
        CatalogError::Unauthorized => MaintenanceAuthorityCategory::Authorization,
        CatalogError::NotFound => MaintenanceAuthorityCategory::NotFound,
        CatalogError::InvalidInput(_) => MaintenanceAuthorityCategory::InvalidInput,
        CatalogError::RevisionOverflow => MaintenanceAuthorityCategory::RevisionOverflow,
    }
}

#[derive(Clone, Default)]
struct ActorCompletion {
    done: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl ActorCompletion {
    fn mark_done(&self, failed: bool) {
        self.failed.store(failed, Ordering::Release);
        self.done.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    fn mark_aborted(&self) {
        if !self.done.swap(true, Ordering::AcqRel) {
            self.failed.store(true, Ordering::Release);
            self.notify.notify_waiters();
        }
    }

    async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.done.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }
}

/// Owns a join handle while it is being awaited.  If the surrounding
/// bounded shutdown future is cancelled before the join completes, abort the
/// task instead of dropping the handle and detaching its supervisor.
struct AbortOnDropJoinHandle<T> {
    handle: Option<JoinHandle<T>>,
}

impl<T> AbortOnDropJoinHandle<T> {
    fn new(handle: JoinHandle<T>) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    fn abort(&self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }

    async fn join(mut self) -> Result<T, tokio::task::JoinError> {
        let result = (&mut *self.handle.as_mut().expect("join handle present")).await;
        self.handle.take();
        result
    }
}

impl<T> Drop for AbortOnDropJoinHandle<T> {
    fn drop(&mut self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}

/// A bounded cleanup item.  A claim request is retained while the catalog
/// claim is in flight so cancellation can perform a fenced lookup before
/// releasing a claim that may have committed just as its task was aborted.
#[derive(Clone)]
enum OwnerCleanupItem {
    Token(OwnerToken),
    Claim(OwnerClaimRequest),
}

/// Synchronous sender used by owner-claim guards.  Queue saturation is a
/// fail-closed signal: the exact token, or the complete claim identity, stays
/// fenced until lease expiry rather than being replaced by an unsafe guess.
#[derive(Clone)]
struct CleanupDispatcher {
    tx: mpsc::Sender<OwnerCleanupItem>,
    pending: Arc<AtomicUsize>,
    overflowed: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl CleanupDispatcher {
    fn enqueue(&self, item: OwnerCleanupItem) {
        // Reserve the in-flight count before handing the item to the worker;
        // otherwise a fast worker could decrement before the increment and
        // wrap the bounded counter.  try_send never waits, so failed sends
        // release this reservation immediately rather than counting work
        // that was never queued.
        self.pending.fetch_add(1, Ordering::AcqRel);
        let fields = match &item {
            OwnerCleanupItem::Token(owner) => (owner.tenant_id, owner.device_id),
            OwnerCleanupItem::Claim(request) => (request.tenant_id, request.device_id),
        };
        match self.tx.try_send(item) {
            Ok(()) => self.notify.notify_one(),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.pending.fetch_sub(1, Ordering::AcqRel);
                self.fail_closed(fields.0, fields.1, "saturated");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.pending.fetch_sub(1, Ordering::AcqRel);
                self.fail_closed(fields.0, fields.1, "closed");
            }
        }
    }

    fn fail_closed(&self, tenant_id: Uuid, device_id: Uuid, state: &'static str) {
        if !self.overflowed.swap(true, Ordering::AcqRel) {
            tracing::error!(
                %tenant_id,
                %device_id,
                state,
                capacity = CLEANUP_QUEUE_CAPACITY,
                "owner cleanup unavailable; lease expiry is the fencing fallback"
            );
        }
        self.notify.notify_one();
    }
}

/// RAII cleanup for a claim started by an asynchronous registration task.
/// The guard is armed with the full request before `claim_owner` begins and
/// upgraded to the exact returned token after it succeeds.  It is disarmed
/// only after the actor admits the session or explicitly queues that token.
struct OwnerClaimCleanup {
    dispatcher: CleanupDispatcher,
    item: Option<OwnerCleanupItem>,
}

impl OwnerClaimCleanup {
    fn new(dispatcher: CleanupDispatcher) -> Self {
        Self {
            dispatcher,
            item: None,
        }
    }

    fn arm_request(&mut self, request: OwnerClaimRequest) {
        self.item = Some(OwnerCleanupItem::Claim(request));
    }

    fn arm_token(&mut self, owner: OwnerToken) {
        self.item = Some(OwnerCleanupItem::Token(owner));
    }

    fn disarm(&mut self) {
        self.item = None;
    }
}

impl Drop for OwnerClaimCleanup {
    fn drop(&mut self) {
        if let Some(item) = self.item.take() {
            self.dispatcher.enqueue(item);
        }
    }
}

/// Serializes owner-lease cleanup behind one bounded queue.
///
/// Closing a session must not retain one `JoinHandle` per close until relay
/// shutdown.  A single worker preserves asynchronous catalog cleanup while
/// bounding both the queue and the number of task handles retained by the
/// actor.  Queue saturation is a fail-closed lease-expiry fallback: the
/// exact owner token remains in Redis until its lease expires, and can never
/// delete a successor.  Shutdown drains accepted work only within a bounded
/// deadline, then aborts the worker and leaves any remaining owners fenced
/// until lease expiry.
struct CleanupWorker {
    dispatcher: Option<CleanupDispatcher>,
    task: Option<AbortOnDropJoinHandle<()>>,
}

impl CleanupWorker {
    #[cfg(test)]
    fn spawn(catalog: SharedCatalog) -> Self {
        Self::spawn_with_signal(
            catalog,
            Arc::new(AtomicBool::new(false)),
            Arc::new(Notify::new()),
        )
    }

    fn spawn_with_signal(
        catalog: SharedCatalog,
        overflowed: Arc<AtomicBool>,
        notify: Arc<Notify>,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel(CLEANUP_QUEUE_CAPACITY);
        let pending = Arc::new(AtomicUsize::new(0));
        let worker_pending = pending.clone();
        let worker_catalog = catalog.clone();
        let task = tokio::spawn(async move {
            while let Some(item) = rx.recv().await {
                match item {
                    OwnerCleanupItem::Token(owner) => {
                        release_owner_bounded(&worker_catalog, &owner).await;
                    }
                    OwnerCleanupItem::Claim(request) => {
                        release_claim_bounded(&worker_catalog, &request).await;
                    }
                }
                worker_pending.fetch_sub(1, Ordering::AcqRel);
            }
        });
        Self {
            dispatcher: Some(CleanupDispatcher {
                tx,
                pending,
                overflowed,
                notify,
            }),
            task: Some(AbortOnDropJoinHandle::new(task)),
        }
    }

    fn dispatcher(&self) -> CleanupDispatcher {
        self.dispatcher
            .as_ref()
            .expect("cleanup dispatcher present")
            .clone()
    }

    fn enqueue(&self, owner: OwnerToken) {
        if let Some(dispatcher) = &self.dispatcher {
            dispatcher.enqueue(OwnerCleanupItem::Token(owner));
        }
    }

    #[cfg(test)]
    async fn shutdown(self) {
        self.shutdown_until(tokio::time::Instant::now() + CLEANUP_SHUTDOWN_TIMEOUT)
            .await;
    }

    async fn shutdown_until(mut self, deadline: tokio::time::Instant) -> bool {
        let pending = self
            .dispatcher
            .as_ref()
            .map_or(0, |dispatcher| dispatcher.pending.load(Ordering::Acquire));
        // Closing the worker-owned sender lets the worker drain every item
        // already accepted by the bounded queue.  The actor drops its own
        // dispatcher clone before taking this worker in `close_all`.
        self.dispatcher.take();
        if let Some(task) = self.task.take() {
            match tokio::time::timeout_at(deadline, task.join()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::warn!(
                        pending,
                        panic = error.is_panic(),
                        cancelled = error.is_cancelled(),
                        "owner cleanup worker failed during relay shutdown; remaining leases will expire"
                    );
                    return false;
                }
                Err(_) => {
                    tracing::warn!(
                        pending,
                        "owner cleanup worker exceeded relay shutdown deadline; remaining leases will expire"
                    );
                    return false;
                }
            }
        }
        true
    }
}

/// A terminal transport event that must reach the owning actor even when the
/// task carrying the peer stream is dropped by transport cancellation.  Each
/// variant carries the complete immutable identity required by the actor's
/// existing stale-generation checks.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum TerminalCleanup {
    Control(SessionKey),
    Data(CarrierKey),
    EchoStream {
        key: SessionKey,
        stream_id: u64,
        operation_id: String,
        /// First terminal cause resolved when the guard fired.  A forwarded
        /// stream whose handler was dropped at the membership cancellation
        /// edge still records its typed expiry cause on the stream latch.
        cause: Option<StreamTerminalCause>,
    },
}

/// Synchronous sender used by terminal cleanup guards.  The channel is
/// deliberately independent from normal actor commands: a saturated request
/// path cannot make a dropped transport task wait for actor capacity.
#[derive(Clone)]
struct TerminalCleanupDispatcher {
    tx: mpsc::Sender<TerminalCleanup>,
    overflowed: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl TerminalCleanupDispatcher {
    fn new(tx: mpsc::Sender<TerminalCleanup>) -> Self {
        Self {
            tx,
            overflowed: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    fn guard(&self, cleanup: TerminalCleanup) -> TerminalCleanupGuard {
        TerminalCleanupGuard {
            dispatcher: self.clone(),
            cleanup: Some(cleanup),
            admission: None,
        }
    }

    /// Guard a forwarded echo stream together with its membership admission
    /// edge so a drop at the cancellation boundary can still attribute the
    /// first terminal cause.
    fn guard_with_admission(
        &self,
        cleanup: TerminalCleanup,
        admission: Option<PeerAdmissionCancellation>,
    ) -> TerminalCleanupGuard {
        TerminalCleanupGuard {
            dispatcher: self.clone(),
            cleanup: Some(cleanup),
            admission,
        }
    }

    fn enqueue(&self, cleanup: TerminalCleanup) {
        match self.tx.try_send(cleanup) {
            Ok(()) => self.notify.notify_one(),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // The actor has already left its joined close_all path.  Its
                // sessions are no longer live, so a late guard has nothing
                // to enqueue and must not create a spurious overflow signal.
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                // There is no safe identity-preserving fallback once the
                // dedicated bounded lane is full. Ask the actor to close all
                // current sessions through its normal exact-key path instead
                // of guessing which owner a dropped event belonged to. Notify
                // is synchronous and wakes an idle actor even when the
                // ordinary command lane is saturated.
                if !self.overflowed.swap(true, Ordering::AcqRel) {
                    tracing::error!("terminal cleanup queue saturated; failing closed");
                }
                self.notify.notify_one();
            }
        }
    }
}

/// RAII cleanup for a registered terminal stream.  Normal result paths
/// disarm this guard after their awaited command is accepted.  If transport
/// cancellation drops the handler future first, `Drop` performs one bounded,
/// nonblocking actor enqueue.
pub(crate) struct TerminalCleanupGuard {
    dispatcher: TerminalCleanupDispatcher,
    cleanup: Option<TerminalCleanup>,
    /// Membership admission edge of a forwarded echo stream.  When the
    /// handler future is dropped immediately at that edge, the first cause is
    /// read from the edge itself at drop time: a typed trust-expiry
    /// invalidation or a passed monotonic trust deadline.  It is never
    /// inferred from a later missing stream or session.
    admission: Option<PeerAdmissionCancellation>,
}

impl TerminalCleanupGuard {
    pub(crate) fn disarm(&mut self) {
        self.cleanup = None;
    }
}

impl Drop for TerminalCleanupGuard {
    fn drop(&mut self) {
        if let Some(mut cleanup) = self.cleanup.take() {
            if let TerminalCleanup::EchoStream { cause, .. } = &mut cleanup
                && cause.is_none()
                && self
                    .admission
                    .as_ref()
                    .is_some_and(PeerAdmissionCancellation::trust_expired)
            {
                *cause = Some(StreamTerminalCause::PeerMembershipExpired);
            }
            self.dispatcher.enqueue(cleanup);
        }
    }
}

async fn release_owner_bounded(catalog: &SharedCatalog, owner: &OwnerToken) {
    match tokio::time::timeout(CLEANUP_OPERATION_TIMEOUT, catalog.release_owner(owner)).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            tracing::warn!(
                tenant_id = %owner.tenant_id,
                device_id = %owner.device_id,
                epoch = owner.epoch,
                error = %error,
                "owner cleanup failed; lease expiry remains the fencing fallback"
            );
        }
        Err(_) => {
            tracing::warn!(
                tenant_id = %owner.tenant_id,
                device_id = %owner.device_id,
                epoch = owner.epoch,
                timeout_ms = CLEANUP_OPERATION_TIMEOUT.as_millis(),
                "owner cleanup timed out; lease expiry remains the fencing fallback"
            );
        }
    }
}

async fn release_claim_bounded(catalog: &SharedCatalog, request: &OwnerClaimRequest) {
    let current = match tokio::time::timeout(
        CLEANUP_OPERATION_TIMEOUT,
        catalog.current_owner(request.tenant_id, request.device_id, Utc::now()),
    )
    .await
    {
        Ok(Ok(current)) => current,
        Ok(Err(error)) => {
            tracing::warn!(
                tenant_id = %request.tenant_id,
                device_id = %request.device_id,
                error = %error,
                "owner claim cleanup lookup failed; lease expiry remains the fencing fallback"
            );
            return;
        }
        Err(_) => {
            tracing::warn!(
                tenant_id = %request.tenant_id,
                device_id = %request.device_id,
                timeout_ms = CLEANUP_OPERATION_TIMEOUT.as_millis(),
                "owner claim cleanup lookup timed out; lease expiry remains the fencing fallback"
            );
            return;
        }
    };
    let Some(owner) = current.map(|claim| claim.token) else {
        return;
    };
    if owner.deployment_incarnation == request.deployment_incarnation
        && owner.tenant_id == request.tenant_id
        && owner.device_id == request.device_id
        && owner.node_id == request.node_id
        && owner.boot_id == request.boot_id
        && owner.session_id == request.session_id
    {
        release_owner_bounded(catalog, &owner).await;
    }
}

/// Deliver a result from an actor-owned background task without allowing a
/// full command queue to strand that task during shutdown.  Dropping the
/// command also drops any owner-claim cleanup guard carried by it.
async fn send_background_command(
    cancel: &CancellationToken,
    command_tx: &mpsc::Sender<Command>,
    command: Command,
) {
    tokio::select! {
        _ = cancel.cancelled() => {}
        result = command_tx.send(command) => {
            let _ = result;
        }
    }
}

/// Errors returned by the relay API.  HTTP handlers map these to bounded,
/// sanitized responses; certificate details, tokens, and backend payloads are
/// never included in this type's public message.
#[derive(Debug)]
pub enum RelayError {
    Config(String),
    Catalog(String),
    Unauthorized,
    Forbidden,
    OwnerBusy,
    /// The selected owner is authenticated and committed, but its M2 data
    /// carrier or owner-fence acknowledgement has not completed yet.  This
    /// and bounded stream capacity are the only retryable echo-admission
    /// states; profile and scope errors remain ordinary
    /// authorization/conflict failures.
    OwnerNotReady,
    /// The owner has reached its bounded concurrent stream limit.
    StreamLimit,
    Conflict(&'static str),
    NotFound,
    Overloaded(&'static str),
    Protocol(String),
    Transport(String),
    Shutdown,
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(message)
            | Self::Catalog(message)
            | Self::Protocol(message)
            | Self::Transport(message) => formatter.write_str(message),
            Self::Unauthorized => formatter.write_str("authentication failed"),
            Self::Forbidden => formatter.write_str("operation is not authorized"),
            Self::OwnerBusy => formatter.write_str("device owner is still live"),
            Self::OwnerNotReady => formatter.write_str("peer owner is not ready"),
            Self::StreamLimit => formatter.write_str("stream limit reached"),
            Self::Conflict(message) => formatter.write_str(message),
            Self::NotFound => formatter.write_str("device or service was not found"),
            Self::Overloaded(message) => formatter.write_str(message),
            Self::Shutdown => formatter.write_str("relay is shutting down"),
        }
    }
}

impl std::error::Error for RelayError {}

impl From<WireError> for RelayError {
    fn from(error: WireError) -> Self {
        Self::Protocol(error.to_string())
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct DeviceScope {
    pub(crate) tenant_id: Uuid,
    pub(crate) device_id: Uuid,
}

impl DeviceScope {
    fn new(tenant_id: Uuid, device_id: Uuid) -> Self {
        Self {
            tenant_id,
            device_id,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PendingRegistrationKey {
    device_id: Uuid,
    spki: String,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct SessionKey {
    pub(crate) tenant_id: Uuid,
    pub(crate) device_id: Uuid,
    pub(crate) session_id: String,
    pub(crate) epoch: u64,
}

impl SessionKey {
    fn scope(&self) -> DeviceScope {
        DeviceScope::new(self.tenant_id, self.device_id)
    }
}

/// A data-socket event must identify the complete physical carrier.  The
/// generation and connection ID are intentionally part of the event rather
/// than inferred from the current session so delayed old-socket events cannot
/// mutate the replacement.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct CarrierKey {
    pub(crate) session: SessionKey,
    pub(crate) generation: u64,
    pub(crate) connection_id: String,
}

impl CarrierKey {
    fn context(&self) -> CarrierContext {
        CarrierContext::new(
            self.session.session_id.clone(),
            self.session.epoch,
            self.generation,
            self.connection_id.clone(),
        )
    }
}

#[derive(Debug)]
pub(crate) enum ControlOutbound {
    Text(QueuedText),
    Close,
}

#[derive(Debug)]
pub(crate) enum DataOutbound {
    Binary(QueuedBytes),
    Barrier(oneshot::Sender<()>),
    Close,
}

/// A charge held by one outbound queue item.  The socket task normally calls
/// `release` after the write completes; `Drop` is the bounded cancellation
/// fallback when a handler disappears while the item is still queued or
/// being written.
#[derive(Debug)]
pub(crate) struct QueueCharge {
    budget: QueueBudget,
    bytes: usize,
    released: bool,
}

impl QueueCharge {
    fn new(budget: QueueBudget, bytes: usize) -> Self {
        Self {
            budget,
            bytes,
            released: false,
        }
    }

    pub(crate) fn release(&mut self) {
        if !self.released {
            self.released = true;
            self.budget.release(self.bytes);
        }
    }
}

impl Drop for QueueCharge {
    fn drop(&mut self) {
        self.release();
    }
}

#[derive(Debug)]
pub(crate) struct QueuedText {
    text: String,
    charge: QueueCharge,
}

impl QueuedText {
    fn new(text: String, budget: QueueBudget) -> Self {
        let bytes = text.len();
        Self {
            text,
            charge: QueueCharge::new(budget, bytes),
        }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.text.as_bytes()
    }

    pub(crate) fn release(&mut self) {
        self.charge.release();
    }

    pub(crate) fn into_parts(self) -> (String, QueueCharge) {
        (self.text, self.charge)
    }
}

#[derive(Debug)]
pub(crate) struct QueuedBytes {
    bytes: Vec<u8>,
    charge: QueueCharge,
}

impl QueuedBytes {
    fn new(bytes: Vec<u8>, budget: QueueBudget) -> Self {
        let length = bytes.len();
        Self {
            bytes,
            charge: QueueCharge::new(budget, length),
        }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn release(&mut self) {
        self.charge.release();
    }

    pub(crate) fn into_parts(self) -> (Vec<u8>, QueueCharge) {
        (self.bytes, self.charge)
    }
}

pub(crate) struct ControlRegistration {
    pub(crate) key: SessionKey,
    pub(crate) welcome: String,
    pub(crate) rx: mpsc::Receiver<ControlOutbound>,
}

pub(crate) struct DataRegistration {
    pub(crate) carrier: CarrierKey,
    pub(crate) rx: mpsc::Receiver<DataOutbound>,
}

/// Shared per-device byte accounting for pending request bodies and encoded
/// outbound control/data queue items.  Socket tasks release an item when they
/// take ownership of it from a bounded channel.
#[derive(Clone, Debug)]
pub(crate) struct QueueBudget {
    used: Arc<AtomicUsize>,
    limit: usize,
}

impl QueueBudget {
    fn new(limit: usize) -> Self {
        Self {
            used: Arc::new(AtomicUsize::new(0)),
            limit,
        }
    }

    fn reserve(&self, bytes: usize) -> bool {
        if bytes > self.limit {
            return false;
        }
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.limit)
            })
            .is_ok()
    }

    pub(crate) fn release(&self, bytes: usize) {
        self.used.fetch_sub(bytes, Ordering::AcqRel);
    }

    fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
}

struct DispatchRequest {
    consumer: AuthenticatedConsumer,
    device_id: Uuid,
    service_id: Uuid,
    grant: GrantSnapshot,
    body: Vec<u8>,
    consumer_expires_at: chrono::DateTime<Utc>,
    response: oneshot::Sender<EchoOutcome>,
}

#[derive(Debug)]
pub(crate) enum EchoOutcome {
    Success(Vec<u8>),
    Failure {
        code: &'static str,
        execution: &'static str,
    },
}

struct PendingEcho {
    operation_id: String,
    send_sequence: u64,
    response: oneshot::Sender<EchoOutcome>,
    response_sequence: u64,
    response_body: Vec<u8>,
    challenge_id: Option<String>,
    consumer: AuthenticatedConsumer,
    service_id: Uuid,
    grant: GrantSnapshot,
    consumer_expires_at: chrono::DateTime<Utc>,
    body: Vec<u8>,
    created_at: Instant,
    dispatched: bool,
    authorization_in_flight: bool,
}

struct DeviceChallenge {
    message_id: String,
    stream_id: u64,
    service_id: String,
    challenge_id: String,
    nonce: String,
    permission_digest: String,
    grant_revision: u64,
    received_at: Instant,
    lifetime: Duration,
}

enum ResponseFrameUpdate {
    Accepted,
    Complete(Vec<u8>, oneshot::Sender<EchoOutcome>),
    Invalid,
}

type ChallengeAuthorizationResult = Result<
    (
        Option<GrantSnapshot>,
        Option<tunnel_catalog::OwnerClaim>,
        Option<DeviceIdentity>,
        Option<Instant>,
    ),
    String,
>;

type RegisterResolvedResult = Result<
    (
        DeviceIdentity,
        tunnel_catalog::OwnerClaim,
        Option<AttachmentTicket>,
    ),
    RegisterControlFailure,
>;

enum RegisterControlFailure {
    OwnerBusy,
    Relay(RelayError),
    RelayAfterOwnerClaim(RelayError),
}

impl From<RelayError> for RegisterControlFailure {
    fn from(error: RelayError) -> Self {
        Self::Relay(error)
    }
}
type AttachResolvedResult = Result<
    (
        Option<DeviceIdentity>,
        Option<tunnel_catalog::OwnerClaim>,
        Option<ConsumedAttachmentTicket>,
    ),
    String,
>;

#[derive(Clone)]
struct Ticket {
    value: String,
    tenant_id: Uuid,
    device_id: Uuid,
    spki: String,
    session_id: String,
    epoch: u64,
    generation: u64,
    welcome_message_id: String,
    connection_id: String,
    issued_at_wall: chrono::DateTime<Utc>,
    expires_at_wall: chrono::DateTime<Utc>,
    expires_at: Instant,
    consuming: bool,
    owner: OwnerToken,
    candidate: bool,
    attachment_purpose: DataAttachmentPurpose,
    /// The catalog purpose is kept separately from the protocol enum because
    /// initial attachment is not a rotation purpose.  It is part of the
    /// authoritative consume binding and never appears in diagnostics.
    catalog_purpose: String,
    binding_digest: String,
    locator_digest: String,
    catalog_backed: bool,
}

impl Ticket {
    fn scope(&self) -> DeviceScope {
        DeviceScope::new(self.tenant_id, self.device_id)
    }

    fn catalog_binding(&self) -> AttachmentTicketBinding {
        AttachmentTicketBinding {
            tenant_id: self.tenant_id,
            device_id: self.device_id,
            spki_fingerprint: self.spki.clone(),
            owner: self.owner.clone(),
            generation: self.generation,
            connection_id: self.connection_id.clone(),
            purpose: self.catalog_purpose.clone(),
            binding_digest: self.binding_digest.clone(),
        }
    }
}

struct DataCarrier {
    context: CarrierContext,
    tx: mpsc::Sender<DataOutbound>,
}

#[derive(Clone, Debug)]
struct PendingOwnerForget {
    /// Stable across control-queue retries. A retry must not create a second
    /// authenticated identity for the same retained stream.
    message_id: String,
    operation_id: String,
    direction: Direction,
    final_state: ResumeDirectionState,
}

struct M2Stream {
    /// The connector's OPEN message ID is retained so a REJECTED response
    /// can be correlated to the one still-pending admission.  Operation and
    /// stream IDs alone are insufficient once a terminal/tombstone is kept.
    open_message_id: String,
    operation_id: String,
    /// Request identity forwarded from a peer consumer.  It lets a typed
    /// membership-expiry diagnostic be correlated to this exact logical
    /// stream without retaining payloads.
    request_id: Option<String>,
    service_id: Uuid,
    consumer: AuthenticatedConsumer,
    grant: GrantSnapshot,
    sequence: StreamState,
    response_bytes: Vec<u8>,
    response_records: VecDeque<oneshot::Sender<Result<Vec<u8>, EchoOutcome>>>,
    send_bytes: usize,
    receive_bytes: usize,
    authorized_until: Option<Instant>,
    consumer_expires_at: chrono::DateTime<Utc>,
    challenge_id: Option<String>,
    authorization_in_flight: bool,
    authorization_started_at_ms: Option<u64>,
    authorization_deadline_ms: Option<u64>,
    authorization_admission_deadline_ms: Option<u64>,
    pending_records: VecDeque<PendingConsumerRecord>,
    pending_record_bytes: usize,
    /// Bytes charged to the session-wide retained/reorder/application budget.
    /// This covers deferred consumer records, response reassembly and the
    /// sequence replay/reorder state; socket queue charges are separate and
    /// released when a writer takes ownership.
    budget_bytes: usize,
    terminal: bool,
    /// A relay->connector terminal frame (relay FIN or the reply to a peer
    /// FIN/RESET) that arrived while the relay writer was frozen at its
    /// rotation fence.  It is held behind any deferred application records and
    /// emitted after COMMITTED on the activated carrier with the continuing
    /// sequence, or resumed on the old carrier after a coordinated ABORTED.
    /// docs/protocol.md "Freeze each writer": a frozen writer emits no
    /// sequenced frame, so the terminal waits rather than being dropped or
    /// emitted on the old carrier.
    pending_terminal: Option<Terminal>,
    /// The relay attempted to close this stream but could not publish its
    /// terminal FIN. This debt is separate from owner FORGET queue debt so an
    /// unrelated successful FORGET cannot clear its fail-closed deadline.
    terminal_fin_failure: bool,
    /// True only until the connector acknowledges this exact OPEN.  A later
    /// REJECTED with the same operation must not reclaim an admitted stream.
    open_pending: bool,
    /// The public registration disappeared before OPENED was observed.  The
    /// OPEN remains live until the owner proves either rejection or admission;
    /// after admission the relay emits a real local FIN/RESET before FORGET.
    registration_dropped: bool,
    /// Typed cause supplied by a close that arrived while OPEN was still
    /// pending.  It is applied to the deferred terminal transition once the
    /// connector admits the stream; a rejected OPEN never has a terminal.
    deferred_terminal_cause: Option<StreamTerminalCause>,
    closed: CancellationToken,
    /// The public WebSocket upgrade owns this lease until Axum invokes its
    /// callback.  The actor tick expires an unclaimed lease so a client that
    /// stalls Hyper's `OnUpgrade` future cannot consume a stream slot forever.
    admission_lease: CancellationToken,
    admission_deadline: Instant,
    /// Closed payload-free authorization cause retained for the bounded
    /// diagnostic snapshot.  This is one failure marker, never a history.
    authorization_failure_code: Option<&'static str>,
}

type PendingConsumerRecord = (Vec<u8>, oneshot::Sender<Result<Vec<u8>, EchoOutcome>>);

struct RotationRuntime {
    state: RotationState,
    attempt: Option<RotationAttemptIdentity>,
    attempt_deadline_ms: Option<u64>,
    snapshot_id: String,
    /// The writer-flush barrier is supervised by the actor's bounded
    /// maintenance tick.  Keeping the receiver here avoids a detached task
    /// that could outlive the session or wait past the attempt deadline.
    barrier_rx: Option<oneshot::Receiver<()>>,
    candidate: Option<DataCarrier>,
    old_connection_id: String,
    prepare_message_id: String,
    last_message_id: String,
    /// Message id of the coordinator's unsolicited ABORT, when one has been
    /// queued for this attempt.  A separate marker is required because an
    /// owner ABORT has an empty `reply_to` and therefore is not a journal
    /// completion of any peer phase message.
    abort_message_id: Option<String>,
    /// Most recent authenticated peer phase message.  It stays separate from
    /// owner-generated replies so COMMIT/COMPLETE never reference an outbound
    /// ID that cannot be completed in the inbound journal.
    peer_message_id: String,
    /// Outbound phase IDs are retained separately so a delayed peer message
    /// is correlated with the phase it acknowledges even after a later local
    /// response has been emitted on the other control ordering.
    quiesce_message_id: String,
    frozen_message_id: String,
    commit_message_id: String,
    retire_message_id: String,
    /// Pin the first authenticated peer message for each phase.  A fresh
    /// message ID with the same attempt and reply target is not an idempotent
    /// retry and must not overwrite the source used by the next transition.
    peer_frozen_message_id: Option<String>,
    peer_drained_message_id: Option<String>,
    peer_committed_message_id: Option<String>,
    peer_retired_message_id: Option<String>,
    peer_aborted_message_id: Option<String>,
    /// Connector ABORTED may arrive before the relay's physical candidate
    /// close event.  Keep that authenticated acknowledgement pending until
    /// the owner-side closure proof is present.
    pending_abort_ack: Option<tunnel_protocol::rotation_control::RotateAborted>,
    tombstones: VecDeque<RotationTombstone>,
    remote_fences: [Option<FenceSnapshot>; 2],
    own_fence: Option<FenceSnapshot>,
    replayed_frames: u64,
    pending_ticket: Option<PendingCatalogTicket>,
    journal: ControlJournal,
    recovery: Option<RecoveryRuntime>,
    /// Last attempt proof retained through COMPLETE for bounded diagnostics.
    /// It is captured with the exact drain set at COMMIT, then latched with
    /// both old-carrier closure bits before the pure state clears its attempt.
    completed_rotation_diagnostics: Option<RelayRotationSnapshot>,
}

/// A catalog issue is asynchronous so the actor never waits on Redis while
/// holding rotation state.  The pure attempt is reserved first; this bounded
/// record retains the exact purpose/context until the catalog result returns.
#[derive(Clone)]
struct PendingCatalogTicket {
    attempt: RotationAttemptIdentity,
    purpose: DataAttachmentPurpose,
    catalog_purpose: String,
    binding_digest: String,
    reply_to: String,
    request: Option<ControlMessage>,
}

struct RotationTombstone {
    attempt: RotationAttemptIdentity,
    deadline_ms: u64,
    journal: ControlJournal,
}

const MAX_ROTATION_TOMBSTONES: usize = 8;

/// The result of observing one authenticated rotation-control message in the
/// bounded per-attempt journal.  A duplicate is deliberately distinct from a
/// new message: pending work must not be dispatched twice, while a completed
/// reply can be retransmitted byte-for-byte without running the pure state
/// transition again.
#[derive(Debug)]
enum RotationJournalDecision {
    New,
    PendingDuplicate,
    CompletedDuplicate(Vec<Vec<u8>>),
    Error(JournalError),
}

#[derive(Debug)]
enum RotationStart {
    Started(String),
    Pending,
    Rejected,
    /// The pure machine consumed an attempt that can never be published to
    /// the connector, or closed itself.  The caller must end the session with
    /// this typed reason; leaving the machine as is would strand an
    /// attempt-less `Preparing` state or a never-rotating `Active` carrier.
    Failed(&'static str),
}

/// Outcome of attempting to publish one relay->connector terminal frame.
#[derive(Debug)]
enum TerminalDisposition {
    /// Queued on the session's active carrier.
    Emitted,
    /// Held because the relay writer is frozen at its rotation fence; the
    /// terminal is emitted after activation (or resumed after a coordinated
    /// abort).  This is bounded backpressure, never a publication failure.
    Deferred,
    /// A genuine publication failure on an unfrozen writer; the tombstone is
    /// retained and its fail-closed deadline armed.
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryReadyProgress {
    Pending,
    Sent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryRetryDispatch {
    Started,
    Rescheduled,
    NotPending,
    DeadlineExpired,
    Failed,
}

struct RecoveryRuntime {
    episode_id: String,
    attempt_no: u64,
    episode_deadline_ms: u64,
    roster: StreamRoster,
    /// IDs released since the preceding authenticated closure pair. Older
    /// IDs remain fenced by RotationState and are intentionally omitted from
    /// this bounded per-attempt wire proof.
    expected_closed_connection_ids: Vec<String>,
    local_closed: Option<RecoveryClosed>,
    peer_closed: Option<RecoveryClosed>,
    closure_digest: Option<String>,
    candidate_ready: bool,
    resume_message_ids: [Option<String>; 2],
    snapshot_reply_ids: [Option<String>; 2],
    local_snapshots: [Vec<ResumeDirectionState>; 2],
    /// Fresh local cursors captured only after retained replay and peer-prefix
    /// obligations have been accounted for.  READY is validated against these
    /// entries rather than the initial SNAPSHOT fence.
    ready_snapshots: [Vec<ResumeDirectionState>; 2],
    ready_message_ids: [Option<String>; 2],
    remote_snapshots: [HashMap<u64, ResumeDirectionState>; 2],
    ready_remote_snapshots: [HashMap<u64, ResumeDirectionState>; 2],
    remote_ready: [bool; 2],
    local_plans: HashMap<u64, RecoveryPlan>,
    ready_sent: [bool; 2],
    deferred_frames: VecDeque<(CarrierKey, Frame, usize)>,
    deferred_bytes: usize,
    activated: bool,
    /// Candidate-loss retries are scheduled by the relay coordinator.  The
    /// client receives the authenticated RECOVERY_BEGIN immediately when this
    /// deadline expires and therefore never runs a second, skewed timer.
    retry_not_before_ms: Option<u64>,
    retry_failed_connection_id: Option<String>,
}

struct DeviceSession {
    identity: DeviceIdentity,
    owner: OwnerToken,
    key: SessionKey,
    control_tx: mpsc::Sender<ControlOutbound>,
    data_tx: Option<mpsc::Sender<DataOutbound>>,
    active_carrier: Option<DataCarrier>,
    generation: u64,
    connection_id: String,
    profile: RuntimeProfile,
    /// M7 cluster profile is selected by the optional cluster configuration;
    /// M1/M2 development sessions retain their existing local ticket path.
    cluster_profile: bool,
    /// Owner fencing is a persistent session latch.  Its bounded deadline is
    /// used only while waiting for the initial OWNER_FENCED acknowledgement;
    /// ongoing dispatch freshness remains challenge-bound authorization.
    owner_fence: Option<OwnerFence>,
    owner_fenced: bool,
    owner_fence_ack: Option<OwnerFenced>,
    owner_fence_deadline: Option<Instant>,
    next_stream_id: u64,
    pending: HashMap<u64, PendingEcho>,
    streams: HashMap<u64, M2Stream>,
    /// Highest stream ID whose authenticated owner FORGET completed. Stream
    /// IDs never reuse, so late frames at or below this watermark are stale
    /// data and must be ignored rather than treated as a session-wide fault.
    forgotten_stream_through: u64,
    /// Absolute fail-closed deadline for a critical owner FORGET that cannot
    /// enter the authenticated control queue. Retries never extend it.
    owner_forget_deadline: Option<Instant>,
    /// Independent fail-closed deadline for a terminal FIN that could not be
    /// published. It is retained while the marked stream tombstone remains,
    /// regardless of unrelated owner FORGET progress.
    terminal_fin_failure_deadline: Option<Instant>,
    rotation: Option<RotationRuntime>,
    last_rotation: Instant,
    rotations_completed: u64,
    total_replayed_frames: u64,
    queued_bytes: usize,
    queue_budget: QueueBudget,
    last_lease_renewal: Instant,
    maintenance_in_flight: bool,
    closed: bool,
}

enum Command {
    RegisterControl {
        identity: TlsIdentity,
        hello: ControlMessage,
        response: oneshot::Sender<Result<ControlRegistration, RelayError>>,
    },
    AttachData {
        identity: TlsIdentity,
        ticket: String,
        response: oneshot::Sender<Result<DataRegistration, RelayError>>,
    },
    InboundControl {
        key: SessionKey,
        message: ControlMessage,
    },
    InboundData {
        carrier: CarrierKey,
        bytes: Vec<u8>,
    },
    DisconnectControl(SessionKey),
    DisconnectData(CarrierKey),
    DispatchEcho {
        consumer: AuthenticatedConsumer,
        device_id: Uuid,
        service_id: Uuid,
        grant: GrantSnapshot,
        body: Vec<u8>,
        consumer_expires_at: chrono::DateTime<Utc>,
        response: oneshot::Sender<EchoOutcome>,
    },
    Tick,
    /// Wake one coordinator-owned recovery retry after its immutable policy
    /// delay. The actor rechecks the absolute episode deadline and session
    /// identity before allocating a fresh candidate.
    RetryRecovery {
        key: SessionKey,
    },
    Shutdown(oneshot::Sender<()>),
    RegisterResolved {
        device_id: Uuid,
        tenant_id: Option<Uuid>,
        spki: String,
        hello: Hello,
        data_connection_id: String,
        response: oneshot::Sender<Result<ControlRegistration, RelayError>>,
        owner_cleanup: Option<OwnerClaimCleanup>,
        result: Box<RegisterResolvedResult>,
    },
    RegisterForwardedControl {
        device: DeviceIdentity,
        spki: String,
        hello: Hello,
        response: oneshot::Sender<Result<ControlRegistration, RelayError>>,
    },
    AttachResolved {
        spki: String,
        ticket: Ticket,
        response: oneshot::Sender<Result<DataRegistration, RelayError>>,
        result: Box<AttachResolvedResult>,
    },
    AttachForwardedData {
        device: DeviceIdentity,
        spki: String,
        ticket: String,
        response: oneshot::Sender<Result<DataRegistration, RelayError>>,
    },
    CatalogTicketResolved {
        key: SessionKey,
        attempt: RotationAttemptIdentity,
        result: Result<AttachmentTicket, String>,
    },
    ChallengeAuthorized {
        key: SessionKey,
        challenge: DeviceChallenge,
        result: ChallengeAuthorizationResult,
    },
    MaintenanceResult {
        key: SessionKey,
        renewed: Option<Result<bool, MaintenanceAuthorityFailure>>,
        identity: Result<Option<DeviceIdentity>, MaintenanceAuthorityFailure>,
    },
    OpenEchoStream {
        consumer: AuthenticatedConsumer,
        device_id: Uuid,
        service_id: Uuid,
        grant: GrantSnapshot,
        consumer_expires_at: chrono::DateTime<Utc>,
        request_id: Option<String>,
        response: oneshot::Sender<Result<ConsumerStreamRegistration, RelayError>>,
    },
    WriteEchoStream {
        key: SessionKey,
        stream_id: u64,
        operation_id: String,
        body: Vec<u8>,
        response: oneshot::Sender<Result<Vec<u8>, EchoOutcome>>,
    },
    CloseEchoStream {
        key: SessionKey,
        stream_id: u64,
        operation_id: String,
        cause: Option<StreamTerminalCause>,
        response: oneshot::Sender<bool>,
    },
    RecordConsumerResponseTimeout {
        scope: ConsumerWriteScope,
    },
    Snapshot {
        response: oneshot::Sender<RelaySnapshot>,
    },
}

/// Registration returned to an authenticated consumer WebSocket.  The
/// operation and stream identifiers remain stable for the lifetime of that
/// socket; application records are multiplexed within the one logical stream.
/// The admission lease is claimed only when Axum enters the upgrade callback;
/// an unclaimed registration is left for the actor tick to expire.  The
/// transport cleanup guard still closes it sooner when that guard is present.
pub(crate) struct ConsumerStreamRegistration {
    pub(crate) key: SessionKey,
    pub(crate) stream_id: u64,
    pub(crate) operation_id: String,
    pub(crate) closed: CancellationToken,
    admission_lease: CancellationToken,
}

impl ConsumerStreamRegistration {
    pub(crate) fn claim_admission(&self) {
        self.admission_lease.cancel();
    }
}

/// A cloneable, bounded command handle used by HTTP and WebSocket tasks.
#[derive(Clone)]
pub struct RelayHandle {
    tx: mpsc::Sender<Command>,
    cancel: CancellationToken,
    terminal_cleanup: TerminalCleanupDispatcher,
    consumer_chunk_reads: Arc<AtomicU64>,
    consumer_write_diagnostics: ConsumerWriteDiagnostics,
    peer_transport_diagnostics: PeerTransportDiagnostics,
    peer_consumer_diagnostics: PeerConsumerDiagnostics,
    actor_completion: ActorCompletion,
    maintenance_completion: ActorCompletion,
    background_failure: Arc<AtomicBool>,
    actor_task: Arc<Mutex<Option<JoinHandle<()>>>>,
    maintenance_task: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl RelayHandle {
    pub(crate) fn spawn(options: RelayOptions, catalog: SharedCatalog) -> Self {
        let capacity = options.limits.max_queue_messages.max(32);
        let (tx, rx) = mpsc::channel(capacity);
        let (terminal_cleanup_tx, terminal_cleanup_rx) =
            mpsc::channel(TERMINAL_CLEANUP_QUEUE_CAPACITY);
        let terminal_cleanup = TerminalCleanupDispatcher::new(terminal_cleanup_tx);
        let cleanup = CleanupWorker::spawn_with_signal(
            catalog.clone(),
            terminal_cleanup.overflowed.clone(),
            terminal_cleanup.notify.clone(),
        );
        let actor_cancel = options.shutdown.clone();
        let maintenance_cancel = options.shutdown.clone();
        let actor_completion = ActorCompletion::default();
        let maintenance_completion = ActorCompletion::default();
        let background_failure = Arc::new(AtomicBool::new(false));
        let actor_task_slot = Arc::new(Mutex::new(None));
        let maintenance_task_slot = Arc::new(Mutex::new(None));
        let consumer_chunk_reads = Arc::new(AtomicU64::new(0));
        let handle = Self {
            tx: tx.clone(),
            cancel: options.shutdown.clone(),
            terminal_cleanup: terminal_cleanup.clone(),
            consumer_chunk_reads: consumer_chunk_reads.clone(),
            consumer_write_diagnostics: ConsumerWriteDiagnostics::default(),
            peer_transport_diagnostics: PeerTransportDiagnostics::default(),
            peer_consumer_diagnostics: PeerConsumerDiagnostics::default(),
            actor_completion: actor_completion.clone(),
            maintenance_completion: maintenance_completion.clone(),
            background_failure: background_failure.clone(),
            actor_task: actor_task_slot.clone(),
            maintenance_task: maintenance_task_slot.clone(),
        };
        let actor = RelayActor {
            options,
            catalog,
            command_tx: tx.clone(),
            rx,
            terminal_cleanup_rx,
            terminal_cleanup_overflowed: terminal_cleanup.overflowed.clone(),
            terminal_cleanup_notify: terminal_cleanup.notify.clone(),
            sessions: HashMap::new(),
            registering: HashSet::new(),
            pending_registering: HashSet::new(),
            tickets: HashMap::new(),
            owner_forgets: HashMap::new(),
            lifetime_application_dispatches: 0,
            control_registration_conflicts: 0,
            rotation_deadline_events: VecDeque::new(),
            session_terminal_events: VecDeque::new(),
            stream_terminal_events: VecDeque::new(),
            stream_terminal_receipt_events: VecDeque::new(),
            consumer_chunk_reads,
            consumer_write_diagnostics: handle.consumer_write_diagnostics.clone(),
            peer_transport_diagnostics: handle.peer_transport_diagnostics.clone(),
            peer_consumer_diagnostics: handle.peer_consumer_diagnostics.clone(),
            cleanup_dispatcher: Some(cleanup.dispatcher()),
            cleanup: Some(cleanup),
            background_tasks: JoinSet::new(),
            background_failure,
            shutting_down: false,
        };
        // Keep the actor failure boundary attached to the relay-wide
        // cancellation token.  A panic in the actor must not leave listener
        // tasks serving with no owner for their state.
        let actor_task = tokio::spawn(async move {
            let failed = AssertUnwindSafe(actor.run()).catch_unwind().await.is_err();
            // Any actor termination leaves the listener pair without an
            // owner, including a normal explicit shutdown or a terminal
            // cleanup overflow.  Propagate it to every relay task.
            actor_cancel.cancel();
            actor_completion.mark_done(failed);
        });
        *actor_task_slot
            .lock()
            .expect("actor task slot mutex poisoned") = Some(actor_task);
        let ticker = handle.clone();
        let maintenance_shared_cancel = maintenance_cancel.clone();
        let maintenance_completion_for_task = maintenance_completion.clone();
        let maintenance_task = tokio::spawn(async move {
            let failed = AssertUnwindSafe(async move {
                let mut interval = tokio::time::interval(Duration::from_millis(500));
                loop {
                    tokio::select! {
                        _ = maintenance_cancel.cancelled() => break,
                        _ = interval.tick() => {
                            tokio::select! {
                                _ = maintenance_cancel.cancelled() => break,
                                result = ticker.tx.send(Command::Tick) => {
                                    if result.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            })
            .catch_unwind()
            .await
            .is_err();
            if failed && !maintenance_shared_cancel.is_cancelled() {
                maintenance_shared_cancel.cancel();
            }
            maintenance_completion_for_task.mark_done(failed);
        });
        *maintenance_task_slot
            .lock()
            .expect("maintenance task slot mutex poisoned") = Some(maintenance_task);
        handle
    }

    pub(crate) fn control_cleanup_guard(&self, key: SessionKey) -> TerminalCleanupGuard {
        self.terminal_cleanup.guard(TerminalCleanup::Control(key))
    }

    pub(crate) fn data_cleanup_guard(&self, carrier: CarrierKey) -> TerminalCleanupGuard {
        self.terminal_cleanup.guard(TerminalCleanup::Data(carrier))
    }

    /// Guard one admitted echo stream.  Forwarded consumer streams pass their
    /// membership admission edge so a handler dropped at that edge still
    /// records the typed first cause; local public streams pass `None`.
    pub(crate) fn echo_cleanup_guard(
        &self,
        key: SessionKey,
        stream_id: u64,
        operation_id: String,
        admission: Option<PeerAdmissionCancellation>,
    ) -> TerminalCleanupGuard {
        self.terminal_cleanup.guard_with_admission(
            TerminalCleanup::EchoStream {
                key,
                stream_id,
                operation_id,
                cause: None,
            },
            admission,
        )
    }

    pub(crate) async fn register_control(
        &self,
        identity: TlsIdentity,
        hello: ControlMessage,
    ) -> Result<ControlRegistration, RelayError> {
        let (response, receiver) = oneshot::channel();
        self.tx
            .send(Command::RegisterControl {
                identity,
                hello,
                response,
            })
            .await
            .map_err(|_| RelayError::Shutdown)?;
        receiver.await.map_err(|_| RelayError::Shutdown)?
    }

    /// Register a device control stream that arrived through an authenticated
    /// relay peer. The caller has already validated the device certificate
    /// context against the owner envelope and supplies the catalog identity;
    /// no synthetic TLS identity is constructed.
    pub(crate) async fn register_forwarded_control(
        &self,
        device: DeviceIdentity,
        spki: String,
        hello: Hello,
    ) -> Result<ControlRegistration, RelayError> {
        let (response, receiver) = oneshot::channel();
        self.tx
            .send(Command::RegisterForwardedControl {
                device,
                spki,
                hello,
                response,
            })
            .await
            .map_err(|_| RelayError::Shutdown)?;
        receiver.await.map_err(|_| RelayError::Shutdown)?
    }

    pub(crate) async fn attach_data(
        &self,
        identity: TlsIdentity,
        ticket: String,
    ) -> Result<DataRegistration, RelayError> {
        let (response, receiver) = oneshot::channel();
        self.tx
            .send(Command::AttachData {
                identity,
                ticket,
                response,
            })
            .await
            .map_err(|_| RelayError::Shutdown)?;
        receiver.await.map_err(|_| RelayError::Shutdown)?
    }

    /// Attach a data carrier whose device TLS session terminated at another
    /// relay. The owner still consumes the same one-use ticket and checks the
    /// catalog identity before installing the carrier.
    pub(crate) async fn attach_forwarded_data(
        &self,
        device: DeviceIdentity,
        spki: String,
        ticket: String,
    ) -> Result<DataRegistration, RelayError> {
        let (response, receiver) = oneshot::channel();
        self.tx
            .send(Command::AttachForwardedData {
                device,
                spki,
                ticket,
                response,
            })
            .await
            .map_err(|_| RelayError::Shutdown)?;
        receiver.await.map_err(|_| RelayError::Shutdown)?
    }

    pub(crate) async fn inbound_control(
        &self,
        key: SessionKey,
        message: ControlMessage,
    ) -> Result<(), RelayError> {
        self.tx
            .send(Command::InboundControl { key, message })
            .await
            .map_err(|_| RelayError::Shutdown)
    }

    pub(crate) async fn inbound_data(
        &self,
        carrier: CarrierKey,
        bytes: Vec<u8>,
    ) -> Result<(), RelayError> {
        self.tx
            .send(Command::InboundData { carrier, bytes })
            .await
            .map_err(|_| RelayError::Shutdown)
    }

    pub(crate) async fn disconnect_control(&self, key: SessionKey) -> bool {
        self.tx.send(Command::DisconnectControl(key)).await.is_ok()
    }

    pub(crate) async fn disconnect_data(&self, carrier: CarrierKey) -> bool {
        self.tx.send(Command::DisconnectData(carrier)).await.is_ok()
    }

    pub(crate) async fn open_echo_stream(
        &self,
        consumer: AuthenticatedConsumer,
        device_id: Uuid,
        service_id: Uuid,
        grant: GrantSnapshot,
        consumer_expires_at: chrono::DateTime<Utc>,
    ) -> Result<ConsumerStreamRegistration, RelayError> {
        self.open_echo_stream_inner(
            consumer,
            device_id,
            service_id,
            grant,
            consumer_expires_at,
            None,
        )
        .await
    }

    pub(crate) async fn open_forwarded_echo_stream(
        &self,
        consumer: AuthenticatedConsumer,
        device_id: Uuid,
        service_id: Uuid,
        grant: GrantSnapshot,
        consumer_expires_at: chrono::DateTime<Utc>,
        request_id: String,
    ) -> Result<ConsumerStreamRegistration, RelayError> {
        self.open_echo_stream_inner(
            consumer,
            device_id,
            service_id,
            grant,
            consumer_expires_at,
            Some(request_id),
        )
        .await
    }

    async fn open_echo_stream_inner(
        &self,
        consumer: AuthenticatedConsumer,
        device_id: Uuid,
        service_id: Uuid,
        grant: GrantSnapshot,
        consumer_expires_at: chrono::DateTime<Utc>,
        request_id: Option<String>,
    ) -> Result<ConsumerStreamRegistration, RelayError> {
        let (response, receiver) = oneshot::channel();
        self.tx
            .send(Command::OpenEchoStream {
                consumer,
                device_id,
                service_id,
                grant,
                consumer_expires_at,
                request_id,
                response,
            })
            .await
            .map_err(|_| RelayError::Shutdown)?;
        receiver.await.map_err(|_| RelayError::Shutdown)?
    }

    pub(crate) async fn write_echo_stream(
        &self,
        key: SessionKey,
        stream_id: u64,
        operation_id: String,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, EchoOutcome> {
        let (response, receiver) = oneshot::channel();
        self.tx
            .send(Command::WriteEchoStream {
                key,
                stream_id,
                operation_id,
                body,
                response,
            })
            .await
            .map_err(|_| EchoOutcome::Failure {
                code: "REVERSE_CHANNEL_UNAVAILABLE",
                execution: "not_dispatched",
            })?;
        receiver.await.map_err(|_| EchoOutcome::Failure {
            code: "REVERSE_CHANNEL_INTERRUPTED",
            execution: "unknown",
        })?
    }

    pub(crate) async fn close_echo_stream(
        &self,
        key: SessionKey,
        stream_id: u64,
        operation_id: String,
    ) -> bool {
        self.close_echo_stream_with_cause(key, stream_id, operation_id, None)
            .await
    }

    pub(crate) async fn close_echo_stream_with_cause(
        &self,
        key: SessionKey,
        stream_id: u64,
        operation_id: String,
        cause: Option<StreamTerminalCause>,
    ) -> bool {
        let (response, receiver) = oneshot::channel();
        if self
            .tx
            .send(Command::CloseEchoStream {
                key,
                stream_id,
                operation_id,
                cause,
                response,
            })
            .await
            .is_err()
        {
            return false;
        }
        receiver.await.unwrap_or(false)
    }

    /// Record a bounded timeout from an exact public consumer response-write
    /// callsite.  This remains an actor command so the snapshot observes the
    /// event in the same order as the stream's cleanup command.
    pub(crate) async fn record_consumer_response_timeout(&self, scope: ConsumerWriteScope) -> bool {
        self.tx
            .send(Command::RecordConsumerResponseTimeout { scope })
            .await
            .is_ok()
    }

    /// Record one authenticated owner-side `ConsumerChunk` synchronously.
    /// This is a shared diagnostic counter rather than an actor command so
    /// forwarding has no extra await, failure path, or mailbox pressure.
    pub(crate) fn record_consumer_chunk_read(&self) {
        self.consumer_chunk_reads.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one terminal observation for a forwarded device carrier without
    /// entering the actor mailbox.  The physical identity is copied before a
    /// session can be removed so a bounded failure snapshot survives cleanup.
    pub(crate) fn record_peer_transport_diagnostic(
        &self,
        device_id: Uuid,
        carrier: &CarrierKey,
        role: PeerTransportDiagnosticRole,
        outcome: PeerTransportDiagnosticOutcome,
    ) {
        self.peer_transport_diagnostics
            .record(device_id, carrier, role, outcome);
    }

    /// Record one terminal event on a forwarded consumer peer stream without
    /// entering the actor mailbox.  This route has no device carrier key, so
    /// it intentionally retains only the relay-local side and category.
    pub(crate) fn record_peer_consumer_diagnostic(
        &self,
        context: &PeerConsumerDiagnosticContext,
        role: PeerConsumerDiagnosticRole,
        outcome: PeerTransportDiagnosticOutcome,
        h3_code: Option<PeerConsumerDiagnosticH3Code>,
    ) {
        self.peer_consumer_diagnostics
            .record(context, role, outcome, h3_code);
    }

    /// Redacted diagnostics for an internal harness.  No route exposes this
    /// method; callers need a clone of the typed relay handle.
    pub async fn snapshot(&self) -> Result<RelaySnapshot, RelayError> {
        let (response, receiver) = oneshot::channel();
        self.tx
            .send(Command::Snapshot { response })
            .await
            .map_err(|_| RelayError::Shutdown)?;
        receiver.await.map_err(|_| RelayError::Shutdown)
    }

    pub(crate) async fn dispatch_echo(
        &self,
        consumer: AuthenticatedConsumer,
        device_id: Uuid,
        service_id: Uuid,
        grant: GrantSnapshot,
        body: Vec<u8>,
        consumer_expires_at: chrono::DateTime<Utc>,
    ) -> Result<EchoOutcome, RelayError> {
        let (response, receiver) = oneshot::channel();
        self.tx
            .send(Command::DispatchEcho {
                consumer,
                device_id,
                service_id,
                grant,
                body,
                consumer_expires_at,
                response,
            })
            .await
            .map_err(|_| RelayError::Shutdown)?;
        receiver.await.map_err(|_| RelayError::Shutdown)
    }

    pub async fn shutdown(&self) -> Result<(), RelayError> {
        // A supervisor that has already terminated cannot consume a newly
        // queued Shutdown command.  Observe its recorded outcome first so a
        // panic or externally-aborted task is reported instead of awaiting a
        // response that can never arrive.
        if self.actor_completion.done.load(Ordering::Acquire) {
            self.maintenance_completion.wait().await;
            self.join_actor_task().await;
            self.join_maintenance_task().await;
            return self.shutdown_result(false);
        }
        let (response, receiver) = oneshot::channel();
        if self.tx.send(Command::Shutdown(response)).await.is_err() {
            self.actor_completion.wait().await;
            self.maintenance_completion.wait().await;
            self.join_actor_task().await;
            self.join_maintenance_task().await;
            return self.shutdown_result(false);
        }
        if receiver.await.is_err() {
            self.actor_completion.wait().await;
            self.maintenance_completion.wait().await;
            self.join_actor_task().await;
            self.join_maintenance_task().await;
            return self.shutdown_result(false);
        }
        self.actor_completion.wait().await;
        self.maintenance_completion.wait().await;
        self.join_actor_task().await;
        self.join_maintenance_task().await;
        self.shutdown_result(true)
    }

    fn shutdown_result(&self, clean_command: bool) -> Result<(), RelayError> {
        if self.actor_completion.failed() {
            Err(RelayError::Transport("relay actor task failed".to_owned()))
        } else if self.maintenance_completion.failed() {
            Err(RelayError::Transport(
                "relay maintenance task failed".to_owned(),
            ))
        } else if self.background_failure.load(Ordering::Acquire) {
            Err(RelayError::Transport(
                "relay background task shutdown failed".to_owned(),
            ))
        } else if clean_command {
            Ok(())
        } else {
            Err(RelayError::Shutdown)
        }
    }

    async fn abort_actor_task(&self) {
        self.cancel.cancel();
        let task = self
            .actor_task
            .lock()
            .expect("actor task slot mutex poisoned")
            .take();
        if let Some(task) = task {
            let task = AbortOnDropJoinHandle::new(task);
            task.abort();
            let _ = task.join().await;
            self.actor_completion.mark_aborted();
        }
    }

    async fn abort_maintenance_task(&self) {
        self.cancel.cancel();
        let task = self
            .maintenance_task
            .lock()
            .expect("maintenance task slot mutex poisoned")
            .take();
        if let Some(task) = task {
            let task = AbortOnDropJoinHandle::new(task);
            task.abort();
            let _ = task.join().await;
            self.maintenance_completion.mark_done(false);
        }
    }

    async fn join_actor_task(&self) {
        let task = self
            .actor_task
            .lock()
            .expect("actor task slot mutex poisoned")
            .take();
        if let Some(task) = task {
            let task = AbortOnDropJoinHandle::new(task);
            let _ = task.join().await;
        }
    }

    async fn join_maintenance_task(&self) {
        let task = self
            .maintenance_task
            .lock()
            .expect("maintenance task slot mutex poisoned")
            .take();
        if let Some(task) = task {
            let task = AbortOnDropJoinHandle::new(task);
            let _ = task.join().await;
        }
    }
}

/// Admission scope hint; the resolved catalog identity remains authoritative.
struct RegistrationTarget {
    device_id: Uuid,
    tenant_id: Option<Uuid>,
    spki: String,
}

struct RelayActor {
    options: RelayOptions,
    catalog: SharedCatalog,
    command_tx: mpsc::Sender<Command>,
    rx: mpsc::Receiver<Command>,
    terminal_cleanup_rx: mpsc::Receiver<TerminalCleanup>,
    terminal_cleanup_overflowed: Arc<AtomicBool>,
    terminal_cleanup_notify: Arc<Notify>,
    sessions: HashMap<DeviceScope, DeviceSession>,
    /// Registrations that have already resolved a catalog tenant and are
    /// being admitted through the peer path.
    registering: HashSet<DeviceScope>,
    /// Local TLS registration starts with only a device role and SPKI.  The
    /// tenant is learned from the catalog asynchronously, so this bounded
    /// pre-resolution set is keyed by the complete observed credential rather
    /// than collapsing distinct tenant/device pairs onto a UUID.
    pending_registering: HashSet<PendingRegistrationKey>,
    tickets: HashMap<String, Ticket>,
    /// Owner-originated STREAM_FORGETs waiting for bounded control-queue
    /// capacity. The complete SessionKey fences a retry from a successor
    /// owner, and the per-session map is bounded by the retained stream table.
    owner_forgets: HashMap<SessionKey, BTreeMap<u64, PendingOwnerForget>>,
    /// Monotonic actor lifetime count of application records accepted for
    /// outbound data dispatch.  It intentionally survives session cleanup;
    /// control frames and replay bookkeeping are not counted.
    lifetime_application_dispatches: u64,
    /// Monotonic count of authoritative duplicate-control/owner-busy
    /// rejections.  This is deliberately global and payload-free so bounded
    /// diagnostics can prove a real conflict without retaining identities.
    control_registration_conflicts: u64,
    /// Bounded relay-local latches for rotation deadlines that caused a
    /// fail-closed session removal.  These survive owner/session cleanup so a
    /// diagnostic reader cannot confuse an absent session with an unobserved
    /// deadline, while the bounded FIFO keeps retention independent of load.
    rotation_deadline_events: VecDeque<RotationDeadlineEvent>,
    /// Bounded relay-local latches captured immediately before fail-closed
    /// session removal. These are diagnostics-only and never keep a session
    /// alive or change the close decision.
    session_terminal_events: VecDeque<SessionTerminalEvent>,
    /// Bounded stream terminal latches captured at the actual first terminal
    /// transition. They survive STREAM_FORGET/session removal so a snapshot
    /// can prove the transition without treating generic session shutdown as
    /// stream expiry.
    stream_terminal_events: VecDeque<StreamTerminalEvent>,
    /// Bounded receipts for the actual connector FIN/RESET cursor. These are
    /// separate from the immutable first-terminal latches above because a
    /// connector terminal frame may arrive after the logical stream's first
    /// terminal transition, and a fast STREAM_FORGET could otherwise remove
    /// the only live evidence of that receipt.
    stream_terminal_receipt_events: VecDeque<StreamTerminalReceiptEvent>,
    consumer_chunk_reads: Arc<AtomicU64>,
    consumer_write_diagnostics: ConsumerWriteDiagnostics,
    peer_transport_diagnostics: PeerTransportDiagnostics,
    peer_consumer_diagnostics: PeerConsumerDiagnostics,
    cleanup_dispatcher: Option<CleanupDispatcher>,
    cleanup: Option<CleanupWorker>,
    background_tasks: JoinSet<()>,
    background_failure: Arc<AtomicBool>,
    shutting_down: bool,
}

impl RelayActor {
    async fn run(mut self) {
        loop {
            tokio::select! {
                biased;
                _ = self.terminal_cleanup_notify.notified() => {
                    if self.terminal_cleanup_overflowed.load(Ordering::Acquire) {
                        self.shutting_down = true;
                    } else {
                        self.drain_terminal_cleanup().await;
                    }
                }
                _ = self.options.shutdown.cancelled() => {
                    self.shutting_down = true;
                }
                background = self.background_tasks.join_next(), if !self.background_tasks.is_empty() => {
                    match background {
                        Some(Ok(())) => {}
                        Some(Err(error)) => {
                            tracing::error!(
                                panic = error.is_panic(),
                                cancelled = error.is_cancelled(),
                                "relay background task terminated unexpectedly"
                            );
                            if error.is_panic() {
                                // JoinSet completion is the wakeup path for a
                                // task that panics while the actor is idle.
                                // Marking shutdown here propagates through the
                                // actor supervisor without waiting for a new
                                // customer command.
                                self.options.shutdown.cancel();
                                self.background_failure.store(true, Ordering::Release);
                                self.shutting_down = true;
                            }
                        }
                        None => {}
                    }
                }
                command = self.rx.recv() => {
                    let Some(command) = command else { break; };
                    let shutdown = matches!(command, Command::Shutdown(_));
                    self.handle(command).await;
                    if shutdown || self.shutting_down {
                        break;
                    }
                }
            }
            if self.shutting_down {
                break;
            }
        }
        self.close_all().await;
    }

    fn spawn_background<F>(&mut self, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.background_tasks.spawn(task);
    }

    async fn shutdown_background_tasks(
        &mut self,
        graceful_deadline: tokio::time::Instant,
        abort_deadline: tokio::time::Instant,
    ) -> bool {
        let mut joined = true;
        while !self.background_tasks.is_empty() {
            match tokio::time::timeout_at(graceful_deadline, self.background_tasks.join_next())
                .await
            {
                Ok(Some(Ok(()))) => {}
                Ok(Some(Err(error))) => {
                    tracing::warn!(
                        panic = error.is_panic(),
                        cancelled = error.is_cancelled(),
                        "relay background task failed during shutdown"
                    );
                    if error.is_panic() {
                        self.background_failure.store(true, Ordering::Release);
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    joined = false;
                    self.background_tasks.abort_all();
                    // Reserve the remainder of the one relay deadline for an
                    // actual abort/join.  A task that still cannot be joined
                    // is reported as a shutdown failure; its JoinSet is
                    // dropped only after owner guards have been given this
                    // bounded chance to enqueue cleanup.
                    if tokio::time::timeout_at(abort_deadline, self.background_tasks.shutdown())
                        .await
                        .is_ok()
                    {
                        joined = true;
                    }
                    break;
                }
            }
        }
        if !joined {
            self.background_failure.store(true, Ordering::Release);
        }
        joined
    }

    async fn drain_terminal_cleanup(&mut self) {
        for _ in 0..TERMINAL_CLEANUP_QUEUE_CAPACITY {
            if self.terminal_cleanup_overflowed.load(Ordering::Acquire) {
                self.shutting_down = true;
                return;
            }
            let Ok(cleanup) = self.terminal_cleanup_rx.try_recv() else {
                return;
            };
            self.handle_terminal_cleanup(cleanup).await;
            if self.shutting_down {
                return;
            }
        }
    }

    async fn handle_terminal_cleanup(&mut self, cleanup: TerminalCleanup) {
        match cleanup {
            TerminalCleanup::Control(key) => self.disconnect_control(key).await,
            TerminalCleanup::Data(carrier) => self.disconnect_data(carrier).await,
            TerminalCleanup::EchoStream {
                key,
                stream_id,
                operation_id,
                cause,
            } => {
                let _ = self.close_echo_stream_with_cause(&key, stream_id, &operation_id, cause);
            }
        }
    }

    async fn handle(&mut self, command: Command) {
        match command {
            Command::RegisterControl {
                identity,
                hello,
                response,
            } => {
                self.begin_register_control(identity, hello, response);
            }
            Command::RegisterResolved {
                device_id,
                tenant_id,
                spki,
                hello,
                data_connection_id,
                response,
                owner_cleanup,
                result,
            } => {
                self.finish_register_control(
                    RegistrationTarget {
                        device_id,
                        tenant_id,
                        spki,
                    },
                    hello,
                    data_connection_id,
                    response,
                    owner_cleanup,
                    *result,
                )
                .await;
            }
            Command::RegisterForwardedControl {
                device,
                spki,
                hello,
                response,
            } => {
                self.begin_register_forwarded_control(device, spki, hello, response);
            }
            Command::AttachData {
                identity,
                ticket,
                response,
            } => {
                self.begin_attach_data(identity, ticket, response);
            }
            Command::AttachResolved {
                spki,
                ticket,
                response,
                result,
            } => {
                self.finish_attach_data(spki, ticket, response, *result)
                    .await;
            }
            Command::AttachForwardedData {
                device,
                spki,
                ticket,
                response,
            } => {
                self.begin_attach_forwarded_data(device, spki, ticket, response);
            }
            Command::CatalogTicketResolved {
                key,
                attempt,
                result,
            } => {
                self.finish_catalog_ticket(&key, &attempt, result).await;
            }
            Command::InboundControl { key, message } => self.inbound_control(key, message).await,
            Command::InboundData { carrier, bytes } => self.inbound_data(carrier, bytes).await,
            Command::DisconnectControl(key) => self.disconnect_control(key).await,
            Command::DisconnectData(carrier) => self.disconnect_data(carrier).await,
            Command::DispatchEcho {
                consumer,
                device_id,
                service_id,
                grant,
                consumer_expires_at,
                body,
                response,
            } => {
                self.dispatch_echo(DispatchRequest {
                    consumer,
                    device_id,
                    service_id,
                    grant,
                    body,
                    consumer_expires_at,
                    response,
                })
                .await;
            }
            Command::Tick => self.tick().await,
            Command::RetryRecovery { key } => self.handle_recovery_retry(key).await,
            Command::ChallengeAuthorized {
                key,
                challenge,
                result,
            } => {
                self.finish_device_challenge(key, challenge, result);
            }
            Command::MaintenanceResult {
                key,
                renewed,
                identity,
            } => {
                self.finish_maintenance(key, renewed, identity).await;
            }
            Command::OpenEchoStream {
                consumer,
                device_id,
                service_id,
                grant,
                consumer_expires_at,
                request_id,
                response,
            } => {
                self.open_echo_stream_with_request_id(
                    consumer,
                    device_id,
                    service_id,
                    grant,
                    consumer_expires_at,
                    request_id,
                    response,
                );
            }
            Command::WriteEchoStream {
                key,
                stream_id,
                operation_id,
                body,
                response,
            } => {
                self.write_echo_stream(key, stream_id, operation_id, body, response);
            }
            Command::CloseEchoStream {
                key,
                stream_id,
                operation_id,
                cause,
                response,
            } => {
                let _ = response.send(self.close_echo_stream_with_cause(
                    &key,
                    stream_id,
                    &operation_id,
                    cause,
                ));
            }
            Command::RecordConsumerResponseTimeout { scope } => {
                self.consumer_write_diagnostics.record_timeout(scope);
            }
            Command::Snapshot { response } => {
                let _ = response.send(self.snapshot());
            }
            Command::Shutdown(response) => {
                self.shutting_down = true;
                let _ = response.send(());
            }
        }
    }

    fn begin_register_control(
        &mut self,
        identity: TlsIdentity,
        hello: ControlMessage,
        response: oneshot::Sender<Result<ControlRegistration, RelayError>>,
    ) {
        if !matches!(identity.role(), CertificateRole::Device { .. }) {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        }
        let device_id = match identity.role_id().parse::<Uuid>() {
            Ok(device_id) => device_id,
            Err(_) => {
                let _ = response.send(Err(RelayError::Unauthorized));
                return;
            }
        };
        let hello = match hello {
            ControlMessage::Hello(hello) => hello,
            _ => {
                let _ = response.send(Err(RelayError::Protocol(
                    "first control message must be HELLO".into(),
                )));
                return;
            }
        };
        if let Err(error) = validate_hello(&hello, device_id) {
            let _ = response.send(Err(error));
            return;
        }
        if self.options.cluster.is_some()
            && !hello
                .features
                .iter()
                .any(|feature| feature == wire::OWNER_FENCING_FEATURE)
        {
            let _ = response.send(Err(RelayError::Protocol(
                "cluster session requires owner-fencing-v1".into(),
            )));
            return;
        }
        let spki = identity.spki_sha256().to_hex();
        let pending_key = PendingRegistrationKey {
            device_id,
            spki: spki.clone(),
        };
        if !self.pending_registering.insert(pending_key.clone()) {
            // The catalog has not resolved this local credential yet.  Keep
            // the existing bounded admission rejection, but only count a
            // conflict after identity/scope resolution or an OwnerBusy claim.
            let _ = response.send(Err(RelayError::Conflict(
                "device already has an active control connection",
            )));
            return;
        }
        if self
            .sessions
            .len()
            .saturating_add(self.registering.len())
            .saturating_add(self.pending_registering.len())
            > self.options.limits.max_devices
        {
            self.pending_registering.remove(&pending_key);
            let _ = response.send(Err(RelayError::Overloaded(
                "relay device capacity is exhausted",
            )));
            return;
        }

        let catalog = self.catalog.clone();
        let command_tx = self.command_tx.clone();
        let options = self.options.clone();
        let data_connection_id = wire::random_token();
        let cluster_profile = options.cluster.is_some();
        let cancel = self.options.shutdown.clone();
        let cleanup_dispatcher = self.cleanup_dispatcher.clone();
        self.spawn_background(async move {
            let mut owner_cleanup = cleanup_dispatcher.map(OwnerClaimCleanup::new);
            let result = async {
                let at = Utc::now();
                let device_identity = catalog
                    .resolve_device(&spki, at)
                    .await
                    .map_err(|error| RelayError::Catalog(error.to_string()))?
                    .filter(|record| {
                        record.device_id == device_id
                            && record.spki_fingerprint == spki
                            && record.device_active
                            && record.credential_active
                            && record.credential_revoked_at.is_none()
                            && record.expires_at > at
                    })
                    .ok_or(RelayError::Unauthorized)?;
                let session_id = wire::random_token();
                let lease_expires_at = at
                    + ChronoDuration::from_std(options.owner_lease)
                        .map_err(|_| RelayError::Config("owner lease is invalid".into()))?;
                let owner_request = OwnerClaimRequest {
                    deployment_incarnation: options.deployment_incarnation.clone(),
                    tenant_id: device_identity.tenant_id,
                    device_id,
                    node_id: options.node_id.clone(),
                    boot_id: options.boot_id.clone(),
                    session_id,
                    lease_expires_at,
                };
                if let Some(cleanup) = owner_cleanup.as_mut() {
                    cleanup.arm_request(owner_request.clone());
                }
                let claim = match catalog.claim_owner(&owner_request).await {
                    Ok(claim) => {
                        if let Some(cleanup) = owner_cleanup.as_mut() {
                            cleanup.arm_token(claim.token.clone());
                        }
                        claim
                    }
                    Err(CatalogError::OwnerBusy) => {
                        if let Some(cleanup) = owner_cleanup.as_mut() {
                            cleanup.disarm();
                        }
                        return Err(RegisterControlFailure::OwnerBusy);
                    }
                    Err(error) => {
                        return Err(RegisterControlFailure::RelayAfterOwnerClaim(
                            RelayError::Catalog(error.to_string()),
                        ));
                    }
                };
                let ticket = if cluster_profile {
                    let expires_at = at
                        + ChronoDuration::from_std(wire::TICKET_TTL)
                            .map_err(|_| RelayError::Config("ticket TTL is invalid".into()))?;
                    let purpose = INITIAL_ATTACHMENT_PURPOSE.to_owned();
                    let binding_digest = runtime::attachment_binding_digest(
                        &claim.token,
                        1,
                        &data_connection_id,
                        &purpose,
                    );
                    match catalog
                        .issue_attachment_ticket(&AttachmentTicketIssueRequest {
                            tenant_id: device_identity.tenant_id,
                            device_id,
                            spki_fingerprint: spki.clone(),
                            owner: claim.token.clone(),
                            generation: 1,
                            connection_id: data_connection_id.clone(),
                            purpose,
                            binding_digest,
                            expires_at,
                        })
                        .await
                    {
                        Ok(ticket) => Some(ticket),
                        Err(error) => {
                            return Err(RegisterControlFailure::RelayAfterOwnerClaim(
                                RelayError::Catalog(error.to_string()),
                            ));
                        }
                    }
                } else {
                    None
                };
                Ok((device_identity, claim, ticket))
            }
            .await;
            send_background_command(
                &cancel,
                &command_tx,
                Command::RegisterResolved {
                    device_id,
                    tenant_id: None,
                    spki: spki.clone(),
                    hello,
                    data_connection_id,
                    response,
                    owner_cleanup,
                    result: Box::new(result),
                },
            )
            .await;
        });
    }

    fn begin_register_forwarded_control(
        &mut self,
        device: DeviceIdentity,
        spki: String,
        hello: Hello,
        response: oneshot::Sender<Result<ControlRegistration, RelayError>>,
    ) {
        if device.spki_fingerprint != spki
            || !device.device_active
            || !device.credential_active
            || device.credential_revoked_at.is_some()
            || device.expires_at <= Utc::now()
        {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        }
        if let Err(error) = validate_hello(&hello, device.device_id) {
            let _ = response.send(Err(error));
            return;
        }
        if self.options.cluster.is_some()
            && !hello
                .features
                .iter()
                .any(|feature| feature == wire::OWNER_FENCING_FEATURE)
        {
            let _ = response.send(Err(RelayError::Protocol(
                "cluster session requires owner-fencing-v1".into(),
            )));
            return;
        }
        let scope = DeviceScope::new(device.tenant_id, device.device_id);
        if self.sessions.contains_key(&scope) || !self.registering.insert(scope.clone()) {
            self.record_control_registration_conflict();
            let _ = response.send(Err(RelayError::OwnerBusy));
            return;
        }
        if self
            .sessions
            .len()
            .saturating_add(self.registering.len())
            .saturating_add(self.pending_registering.len())
            > self.options.limits.max_devices
        {
            self.registering.remove(&scope);
            let _ = response.send(Err(RelayError::Overloaded(
                "relay device capacity is exhausted",
            )));
            return;
        }

        let catalog = self.catalog.clone();
        let command_tx = self.command_tx.clone();
        let options = self.options.clone();
        let device_id = device.device_id;
        let tenant_id = device.tenant_id;
        let data_connection_id = wire::random_token();
        let cluster_profile = options.cluster.is_some();
        let cancel = self.options.shutdown.clone();
        let cleanup_dispatcher = self.cleanup_dispatcher.clone();
        self.spawn_background(async move {
            let mut owner_cleanup = cleanup_dispatcher.map(OwnerClaimCleanup::new);
            let result = async {
                let at = Utc::now();
                let session_id = wire::random_token();
                let lease_expires_at = at
                    + ChronoDuration::from_std(options.owner_lease)
                        .map_err(|_| RelayError::Config("owner lease is invalid".into()))?;
                let owner_request = OwnerClaimRequest {
                    deployment_incarnation: options.deployment_incarnation.clone(),
                    tenant_id: device.tenant_id,
                    device_id,
                    node_id: options.node_id.clone(),
                    boot_id: options.boot_id.clone(),
                    session_id,
                    lease_expires_at,
                };
                if let Some(cleanup) = owner_cleanup.as_mut() {
                    cleanup.arm_request(owner_request.clone());
                }
                let claim = match catalog.claim_owner(&owner_request).await {
                    Ok(claim) => {
                        if let Some(cleanup) = owner_cleanup.as_mut() {
                            cleanup.arm_token(claim.token.clone());
                        }
                        claim
                    }
                    Err(CatalogError::OwnerBusy) => {
                        if let Some(cleanup) = owner_cleanup.as_mut() {
                            cleanup.disarm();
                        }
                        return Err(RegisterControlFailure::OwnerBusy);
                    }
                    Err(error) => {
                        return Err(RegisterControlFailure::RelayAfterOwnerClaim(
                            RelayError::Catalog(error.to_string()),
                        ));
                    }
                };
                let ticket = if cluster_profile {
                    let expires_at = at
                        + ChronoDuration::from_std(wire::TICKET_TTL)
                            .map_err(|_| RelayError::Config("ticket TTL is invalid".into()))?;
                    let purpose = INITIAL_ATTACHMENT_PURPOSE.to_owned();
                    let binding_digest = runtime::attachment_binding_digest(
                        &claim.token,
                        1,
                        &data_connection_id,
                        &purpose,
                    );
                    match catalog
                        .issue_attachment_ticket(&AttachmentTicketIssueRequest {
                            tenant_id: device.tenant_id,
                            device_id,
                            spki_fingerprint: spki.clone(),
                            owner: claim.token.clone(),
                            generation: 1,
                            connection_id: data_connection_id.clone(),
                            purpose,
                            binding_digest,
                            expires_at,
                        })
                        .await
                    {
                        Ok(ticket) => Some(ticket),
                        Err(error) => {
                            return Err(RegisterControlFailure::RelayAfterOwnerClaim(
                                RelayError::Catalog(error.to_string()),
                            ));
                        }
                    }
                } else {
                    None
                };
                Ok((device, claim, ticket))
            }
            .await;
            send_background_command(
                &cancel,
                &command_tx,
                Command::RegisterResolved {
                    device_id,
                    tenant_id: Some(tenant_id),
                    spki,
                    hello,
                    data_connection_id,
                    response,
                    owner_cleanup,
                    result: Box::new(result),
                },
            )
            .await;
        });
    }

    async fn enqueue_cleanup(&self, owner: OwnerToken) {
        if let Some(cleanup) = self.cleanup.as_ref() {
            cleanup.enqueue(owner);
        } else {
            // The worker is only absent after shutdown has taken ownership of
            // it. Keep cleanup exact if a late command races with teardown.
            release_owner_bounded(&self.catalog, &owner).await;
        }
    }

    async fn finish_register_control(
        &mut self,
        target: RegistrationTarget,
        hello: Hello,
        data_connection_id: String,
        response: oneshot::Sender<Result<ControlRegistration, RelayError>>,
        mut owner_cleanup: Option<OwnerClaimCleanup>,
        result: RegisterResolvedResult,
    ) {
        let RegistrationTarget {
            device_id,
            tenant_id,
            spki,
        } = target;
        self.pending_registering.remove(&PendingRegistrationKey {
            device_id,
            spki: spki.clone(),
        });
        if let Some(tenant_id) = tenant_id {
            self.registering
                .remove(&DeviceScope::new(tenant_id, device_id));
        }
        let (device_identity, claim, catalog_ticket) = match result {
            Ok(value) => value,
            Err(RegisterControlFailure::OwnerBusy) => {
                if let Some(cleanup) = owner_cleanup.as_mut() {
                    cleanup.disarm();
                }
                self.record_control_registration_conflict();
                let _ = response.send(Err(RelayError::OwnerBusy));
                return;
            }
            Err(RegisterControlFailure::Relay(error)) => {
                if let Some(cleanup) = owner_cleanup.as_mut() {
                    cleanup.disarm();
                }
                let _ = response.send(Err(error));
                return;
            }
            Err(RegisterControlFailure::RelayAfterOwnerClaim(error)) => {
                // The guard still owns the exact token returned by the
                // catalog claim.  Dropping it after this error queues the
                // fenced release even when the caller disappeared.
                let _ = response.send(Err(error));
                return;
            }
        };
        let scope = DeviceScope::new(device_identity.tenant_id, device_id);
        self.registering.remove(&scope);
        if self.sessions.contains_key(&scope) {
            self.record_control_registration_conflict();
            let token = claim.token;
            if let Some(cleanup) = owner_cleanup.as_mut() {
                cleanup.disarm();
            }
            self.enqueue_cleanup(token).await;
            let _ = response.send(Err(RelayError::OwnerBusy));
            return;
        }
        let user_sessions = self
            .sessions
            .values()
            .filter(|session| {
                session.identity.tenant_id == device_identity.tenant_id
                    && session.identity.owner_user_id == device_identity.owner_user_id
            })
            .count();
        if user_sessions >= self.options.limits.max_devices_per_user {
            let token = claim.token;
            if let Some(cleanup) = owner_cleanup.as_mut() {
                cleanup.disarm();
            }
            self.enqueue_cleanup(token).await;
            let _ = response.send(Err(RelayError::Overloaded(
                "per-user device capacity is exhausted",
            )));
            return;
        }
        let session_id = claim.token.session_id.clone();
        let key = SessionKey {
            tenant_id: device_identity.tenant_id,
            device_id,
            session_id: session_id.clone(),
            epoch: claim.token.epoch,
        };
        let (control_tx, rx) = mpsc::channel(self.options.limits.max_queue_messages);
        let queue_budget = QueueBudget::new(self.options.limits.max_queue_bytes);
        let welcome_message_id = wire::random_token();
        let cluster_profile = self.options.cluster.is_some();
        if cluster_profile && catalog_ticket.is_none() {
            let token = claim.token;
            if let Some(cleanup) = owner_cleanup.as_mut() {
                cleanup.disarm();
            }
            self.enqueue_cleanup(token).await;
            let _ = response.send(Err(RelayError::Catalog(
                "cluster attachment ticket was not issued".into(),
            )));
            return;
        }
        if !cluster_profile && catalog_ticket.is_some() {
            let token = claim.token;
            if let Some(cleanup) = owner_cleanup.as_mut() {
                cleanup.disarm();
            }
            self.enqueue_cleanup(token).await;
            let _ = response.send(Err(RelayError::Config(
                "unexpected cluster attachment ticket".into(),
            )));
            return;
        }
        let ticket = catalog_ticket
            .as_ref()
            .map(|ticket| ticket.ticket.clone())
            .unwrap_or_else(wire::random_token);
        let profile = if hello
            .features
            .iter()
            .any(|feature| feature == wire::ORDERED_ROTATION_FEATURE)
        {
            RuntimeProfile::M2
        } else {
            RuntimeProfile::M1
        };
        let relay_interval_ms = self.options.rotation.interval_seconds.saturating_mul(1_000);
        let relay_handshake_ms = self
            .options
            .rotation
            .handshake_timeout_seconds
            .saturating_mul(1_000);
        let relay_overlap_ms = self.options.rotation.overlap_seconds.saturating_mul(1_000);
        let (rotation_interval_ms, handshake_timeout_ms, overlap_timeout_ms) =
            if profile.supports_rotation() {
                let requested = hello.rotation_policy.as_ref();
                (
                    requested
                        .map_or(relay_interval_ms, |policy| policy.interval_ms)
                        .min(relay_interval_ms),
                    requested
                        .map_or(relay_handshake_ms, |policy| policy.handshake_timeout_ms)
                        .min(relay_handshake_ms),
                    requested
                        .map_or(relay_overlap_ms, |policy| policy.overlap_timeout_ms)
                        .min(relay_overlap_ms),
                )
            } else {
                (relay_interval_ms, relay_handshake_ms, relay_overlap_ms)
            };
        let ticket_issued_at_wall = Utc::now();
        let ticket_expires_at_wall = catalog_ticket
            .as_ref()
            .map(|ticket| ticket.expires_at)
            .unwrap_or_else(|| {
                ticket_issued_at_wall
                    + ChronoDuration::from_std(wire::TICKET_TTL)
                        .unwrap_or_else(|_| ChronoDuration::seconds(10))
            });
        let ticket_locator_digest = catalog_ticket
            .as_ref()
            .map(|ticket| ticket.locator.digest.clone())
            .unwrap_or_default();
        let ticket_binding_digest = if catalog_ticket.is_some() {
            runtime::attachment_binding_digest(
                &claim.token,
                1,
                &data_connection_id,
                INITIAL_ATTACHMENT_PURPOSE,
            )
        } else {
            String::new()
        };
        self.tickets.insert(
            ticket.clone(),
            Ticket {
                value: ticket.clone(),
                tenant_id: device_identity.tenant_id,
                device_id,
                spki: spki.clone(),
                session_id: session_id.clone(),
                epoch: claim.token.epoch,
                generation: 1,
                welcome_message_id: welcome_message_id.clone(),
                connection_id: data_connection_id.clone(),
                issued_at_wall: ticket_issued_at_wall,
                expires_at_wall: ticket_expires_at_wall,
                expires_at: Instant::now() + wire::TICKET_TTL,
                consuming: false,
                owner: claim.token.clone(),
                candidate: false,
                attachment_purpose: DataAttachmentPurpose::RotationCandidate,
                catalog_purpose: catalog_ticket
                    .as_ref()
                    .map(|_| INITIAL_ATTACHMENT_PURPOSE.to_owned())
                    .unwrap_or_default(),
                binding_digest: ticket_binding_digest,
                locator_digest: ticket_locator_digest,
                catalog_backed: cluster_profile,
            },
        );
        let welcome = match profile {
            RuntimeProfile::M1 => wire::welcome(
                &welcome_message_id,
                &hello.message_id,
                &session_id,
                claim.token.epoch,
                1,
                &data_connection_id,
                &ticket,
                cluster_profile,
            ),
            RuntimeProfile::M2 => wire::welcome_m2(wire::WelcomeM2Params {
                message_id: &welcome_message_id,
                reply_to: &hello.message_id,
                session_id: &session_id,
                epoch: claim.token.epoch,
                generation: 1,
                connection_id: &data_connection_id,
                ticket: &ticket,
                owner: &claim.token,
                rotation_interval_ms,
                handshake_timeout_ms,
                overlap_timeout_ms,
                owner_fencing: cluster_profile,
            }),
        };
        let welcome = match wire::encode_control_message(&welcome) {
            Ok(value) => value,
            Err(error) => {
                let token = claim.token;
                if let Some(cleanup) = owner_cleanup.as_mut() {
                    cleanup.disarm();
                }
                self.enqueue_cleanup(token).await;
                let _ = response.send(Err(RelayError::Protocol(error.to_string())));
                return;
            }
        };
        let (owner_fence, owner_fence_deadline) = if cluster_profile {
            let lease_budget = self
                .options
                .owner_lease
                .checked_sub(OWNER_LEASE_SAFETY_MARGIN)
                .unwrap_or_else(|| Duration::from_secs(1));
            let remaining_ms = lease_budget.as_millis().clamp(1, 20_000) as u64;
            let fence = match wire::owner_fence(
                &session_id,
                claim.token.epoch,
                &runtime::owner_id(&claim.token),
                remaining_ms,
            ) {
                ControlMessage::OwnerFence(fence) => fence,
                _ => unreachable!("owner_fence always returns OWNER_FENCE"),
            };
            let encoded =
                match wire::encode_control_message(&ControlMessage::OwnerFence(fence.clone())) {
                    Ok(encoded) => encoded,
                    Err(error) => {
                        let token = claim.token;
                        if let Some(cleanup) = owner_cleanup.as_mut() {
                            cleanup.disarm();
                        }
                        self.enqueue_cleanup(token).await;
                        let _ = response.send(Err(RelayError::Protocol(error.to_string())));
                        return;
                    }
                };
            if queue_control(&control_tx, &queue_budget, encoded).is_err() {
                let token = claim.token;
                if let Some(cleanup) = owner_cleanup.as_mut() {
                    cleanup.disarm();
                }
                self.enqueue_cleanup(token).await;
                let _ = response.send(Err(RelayError::Overloaded("control queue is full")));
                return;
            }
            (
                Some(fence),
                Some(Instant::now() + Duration::from_millis(remaining_ms)),
            )
        } else {
            (None, None)
        };
        let trace_tenant_id = device_identity.tenant_id;
        let trace_epoch = claim.token.epoch;
        let rotation = if profile.supports_rotation() {
            let protocol_config = match runtime::protocol_rotation_config_ms(
                rotation_interval_ms,
                handshake_timeout_ms,
                overlap_timeout_ms,
            ) {
                Ok(config) => config,
                Err(error) => {
                    let token = claim.token;
                    if let Some(cleanup) = owner_cleanup.as_mut() {
                        cleanup.disarm();
                    }
                    self.enqueue_cleanup(token).await;
                    let _ = response.send(Err(RelayError::Config(error.into())));
                    return;
                }
            };
            match RotationState::new(
                session_id.clone(),
                runtime::owner_id(&claim.token),
                claim.token.epoch,
                1,
                data_connection_id.clone(),
                protocol_config,
            ) {
                Ok(state) => Some(RotationRuntime {
                    state,
                    attempt: None,
                    attempt_deadline_ms: None,
                    snapshot_id: String::new(),
                    barrier_rx: None,
                    candidate: None,
                    old_connection_id: data_connection_id.clone(),
                    prepare_message_id: String::new(),
                    last_message_id: String::new(),
                    abort_message_id: None,
                    peer_message_id: String::new(),
                    quiesce_message_id: String::new(),
                    frozen_message_id: String::new(),
                    commit_message_id: String::new(),
                    retire_message_id: String::new(),
                    peer_frozen_message_id: None,
                    peer_drained_message_id: None,
                    peer_committed_message_id: None,
                    peer_retired_message_id: None,
                    peer_aborted_message_id: None,
                    pending_abort_ack: None,
                    tombstones: VecDeque::new(),
                    remote_fences: [None, None],
                    own_fence: None,
                    replayed_frames: 0,
                    pending_ticket: None,
                    journal: ControlJournal::new(
                        128,
                        self.options.limits.max_queue_bytes.min(4 * 1024 * 1024),
                        monotonic_millis(),
                        monotonic_millis().saturating_add(overlap_timeout_ms),
                    )
                    .expect("validated rotation journal bounds"),
                    recovery: None,
                    completed_rotation_diagnostics: None,
                }),
                Err(error) => {
                    let token = claim.token;
                    if let Some(cleanup) = owner_cleanup.as_mut() {
                        cleanup.disarm();
                    }
                    self.enqueue_cleanup(token).await;
                    let _ = response.send(Err(RelayError::Config(error.to_string())));
                    return;
                }
            }
        } else {
            None
        };
        self.sessions.insert(
            scope,
            DeviceSession {
                identity: device_identity,
                owner: claim.token,
                key: key.clone(),
                control_tx,
                data_tx: None,
                active_carrier: None,
                generation: 1,
                connection_id: data_connection_id.clone(),
                profile,
                cluster_profile,
                owner_fence,
                owner_fenced: !cluster_profile,
                owner_fence_ack: None,
                owner_fence_deadline,
                next_stream_id: 1,
                pending: HashMap::new(),
                streams: HashMap::new(),
                forgotten_stream_through: 0,
                owner_forget_deadline: None,
                terminal_fin_failure_deadline: None,
                rotation,
                last_rotation: Instant::now(),
                rotations_completed: 0,
                total_replayed_frames: 0,
                queued_bytes: 0,
                queue_budget: queue_budget.clone(),
                last_lease_renewal: Instant::now(),
                maintenance_in_flight: false,
                closed: false,
            },
        );
        // The session now owns this exact token.  Its close path performs the
        // only subsequent release, so the registration guard must not enqueue
        // a duplicate cleanup when it is dropped.
        if let Some(cleanup) = owner_cleanup.as_mut() {
            cleanup.disarm();
        }
        tracing::info!(
            tenant_id = %trace_tenant_id,
            device_id = %device_id,
            session_id = %session_id,
            epoch = trace_epoch,
            phase = "session_admitted",
        );
        let registration = ControlRegistration { key, welcome, rx };
        self.send_control_registration(response, registration).await;
    }

    fn begin_attach_data(
        &mut self,
        identity: TlsIdentity,
        ticket_value: String,
        response: oneshot::Sender<Result<DataRegistration, RelayError>>,
    ) {
        if !matches!(identity.role(), CertificateRole::Device { .. }) {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        }
        let spki = identity.spki_sha256().to_hex();
        let now_wall = Utc::now();
        let Some(existing_ticket) = self.tickets.get(&ticket_value).cloned() else {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        };
        if existing_ticket.value != ticket_value
            || existing_ticket.expires_at <= Instant::now()
            || now_wall < existing_ticket.issued_at_wall
            || now_wall >= existing_ticket.expires_at_wall
            || existing_ticket.spki != spki
            || existing_ticket.consuming
            || (existing_ticket.catalog_backed
                && !runtime::attachment_locator_matches(
                    &existing_ticket.value,
                    &existing_ticket.locator_digest,
                ))
        {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        }
        if existing_ticket.catalog_backed
            && !self
                .sessions
                .get(&existing_ticket.scope())
                .is_some_and(|session| {
                    session.key.session_id == existing_ticket.session_id
                        && session.key.epoch == existing_ticket.epoch
                        && session.owner_fenced
                })
        {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        }
        let Some(ticket) = self.tickets.get_mut(&ticket_value) else {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        };
        ticket.consuming = true;
        let ticket = ticket.clone();
        let catalog = self.catalog.clone();
        let command_tx = self.command_tx.clone();
        let cancel = self.options.shutdown.clone();
        self.spawn_background(async move {
            let result = async {
                let device = catalog
                    .resolve_device(&spki, Utc::now())
                    .await
                    .map_err(|error| error.to_string())?;
                let Some(device) = device else {
                    return Ok((None, None, None));
                };
                let owner = catalog
                    .current_owner(device.tenant_id, ticket.device_id, Utc::now())
                    .await
                    .map_err(|error| error.to_string())?;
                let consumed = if ticket.catalog_backed {
                    let consumed = catalog
                        .consume_attachment_ticket(&AttachmentTicketConsumeRequest {
                            ticket: ticket.value.clone(),
                            tenant_id: ticket.tenant_id,
                            device_id: ticket.device_id,
                            spki_fingerprint: ticket.spki.clone(),
                            owner: ticket.owner.clone(),
                            generation: ticket.generation,
                            connection_id: ticket.connection_id.clone(),
                            purpose: ticket.catalog_purpose.clone(),
                            binding_digest: ticket.binding_digest.clone(),
                        })
                        .await
                        .map_err(|error| error.to_string())?;
                    Some(consumed)
                } else {
                    None
                };
                Ok((Some(device), owner, consumed))
            }
            .await;
            send_background_command(
                &cancel,
                &command_tx,
                Command::AttachResolved {
                    spki,
                    ticket,
                    response,
                    result: Box::new(result),
                },
            )
            .await;
        });
    }

    fn begin_attach_forwarded_data(
        &mut self,
        device: DeviceIdentity,
        spki: String,
        ticket_value: String,
        response: oneshot::Sender<Result<DataRegistration, RelayError>>,
    ) {
        let now_wall = Utc::now();
        let Some(existing_ticket) = self.tickets.get(&ticket_value).cloned() else {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        };
        if device.spki_fingerprint != spki
            || device.tenant_id != existing_ticket.tenant_id
            || device.device_id != existing_ticket.device_id
            || !device.device_active
            || !device.credential_active
            || device.credential_revoked_at.is_some()
            || device.expires_at <= now_wall
        {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        }
        if existing_ticket.value != ticket_value
            || existing_ticket.expires_at <= Instant::now()
            || now_wall < existing_ticket.issued_at_wall
            || now_wall >= existing_ticket.expires_at_wall
            || existing_ticket.spki != spki
            || existing_ticket.consuming
            || (existing_ticket.catalog_backed
                && !runtime::attachment_locator_matches(
                    &existing_ticket.value,
                    &existing_ticket.locator_digest,
                ))
        {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        }
        if existing_ticket.catalog_backed
            && !self
                .sessions
                .get(&existing_ticket.scope())
                .is_some_and(|session| {
                    session.key.session_id == existing_ticket.session_id
                        && session.key.epoch == existing_ticket.epoch
                        && session.owner_fenced
                })
        {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        }
        let Some(ticket) = self.tickets.get_mut(&ticket_value) else {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        };
        ticket.consuming = true;
        let ticket = ticket.clone();
        let catalog = self.catalog.clone();
        let command_tx = self.command_tx.clone();
        let cancel = self.options.shutdown.clone();
        self.spawn_background(async move {
            let result = async {
                let owner = catalog
                    .current_owner(device.tenant_id, ticket.device_id, Utc::now())
                    .await
                    .map_err(|error| error.to_string())?;
                let consumed = if ticket.catalog_backed {
                    let consumed = catalog
                        .consume_attachment_ticket(&AttachmentTicketConsumeRequest {
                            ticket: ticket.value.clone(),
                            tenant_id: ticket.tenant_id,
                            device_id: ticket.device_id,
                            spki_fingerprint: ticket.spki.clone(),
                            owner: ticket.owner.clone(),
                            generation: ticket.generation,
                            connection_id: ticket.connection_id.clone(),
                            purpose: ticket.catalog_purpose.clone(),
                            binding_digest: ticket.binding_digest.clone(),
                        })
                        .await
                        .map_err(|error| error.to_string())?;
                    Some(consumed)
                } else {
                    None
                };
                Ok((Some(device), owner, consumed))
            }
            .await;
            send_background_command(
                &cancel,
                &command_tx,
                Command::AttachResolved {
                    spki,
                    ticket,
                    response,
                    result: Box::new(result),
                },
            )
            .await;
        });
    }

    async fn finish_attach_data(
        &mut self,
        spki: String,
        ticket: Ticket,
        response: oneshot::Sender<Result<DataRegistration, RelayError>>,
        result: AttachResolvedResult,
    ) {
        let now_wall = Utc::now();
        if !self.ticket_matches(&ticket) {
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        }
        if ticket.expires_at <= Instant::now()
            || now_wall < ticket.issued_at_wall
            || now_wall >= ticket.expires_at_wall
        {
            self.remove_ticket_if_matches(&ticket);
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        }
        let (identity_result, owner_result, consumed) = match result {
            Ok(value) => value,
            Err(_) => {
                self.remove_ticket_if_matches(&ticket);
                let _ = response.send(Err(RelayError::Unauthorized));
                return;
            }
        };
        let valid_identity = identity_result.filter(|record| {
            record.tenant_id == ticket.tenant_id
                && record.device_id == ticket.device_id
                && record.spki_fingerprint == ticket.spki
                && record.device_active
                && record.credential_active
                && record.credential_revoked_at.is_none()
                && record.expires_at > Utc::now()
        });
        let Some(device_identity) = valid_identity else {
            self.remove_ticket_if_matches(&ticket);
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        };
        if ticket.catalog_backed
            && consumed
                .as_ref()
                .is_none_or(|consumed| consumed.binding != ticket.catalog_binding())
        {
            self.remove_ticket_if_matches(&ticket);
            let _ = response.send(Err(RelayError::Unauthorized));
            return;
        }
        let result = self.attach_data_verified(spki, ticket.clone(), device_identity, owner_result);
        let should_start_recovery = result.is_ok()
            && ticket.candidate
            && matches!(
                &ticket.attachment_purpose,
                DataAttachmentPurpose::Recovery { .. }
            );
        let should_quiesce = result.is_ok()
            && ticket.candidate
            && matches!(
                &ticket.attachment_purpose,
                DataAttachmentPurpose::RotationCandidate
            );
        if result.is_ok() {
            self.remove_ticket_if_matches(&ticket);
        } else if let Some(pending) = self.tickets.get_mut(&ticket.value) {
            pending.consuming = false;
        }
        if should_quiesce {
            let key = SessionKey {
                tenant_id: ticket.tenant_id,
                device_id: ticket.device_id,
                session_id: ticket.session_id.clone(),
                epoch: ticket.epoch,
            };
            self.begin_rotation_quiesce(&key);
        }
        if should_start_recovery {
            let key = SessionKey {
                tenant_id: ticket.tenant_id,
                device_id: ticket.device_id,
                session_id: ticket.session_id.clone(),
                epoch: ticket.epoch,
            };
            self.start_recovery_snapshots(&key);
        }
        self.send_data_registration(response, result).await;
    }

    async fn send_control_registration(
        &mut self,
        response: oneshot::Sender<Result<ControlRegistration, RelayError>>,
        registration: ControlRegistration,
    ) {
        if let Some(registration) = send_registration(response, Ok(registration)) {
            // The caller can disappear after admission and before this reply.
            // Drop the receiver before removing the exact session so every
            // queued item releases its shared charge.
            let key = registration.key.clone();
            drop(registration);
            self.disconnect_control(key).await;
        }
    }

    async fn send_data_registration(
        &mut self,
        response: oneshot::Sender<Result<DataRegistration, RelayError>>,
        result: Result<DataRegistration, RelayError>,
    ) {
        if let Some(registration) = send_registration(response, result) {
            // The carrier was installed before the reply crossed the oneshot.
            // Reclaim that immutable carrier identity immediately; a later
            // generation cannot match this disconnect.
            self.disconnect_data(registration.carrier).await;
        }
    }

    fn attach_data_verified(
        &mut self,
        spki: String,
        ticket: Ticket,
        current_identity: DeviceIdentity,
        current_owner: Option<tunnel_catalog::OwnerClaim>,
    ) -> Result<DataRegistration, RelayError> {
        if current_identity.spki_fingerprint != spki {
            return Err(RelayError::Unauthorized);
        }
        let session = self
            .sessions
            .get_mut(&ticket.scope())
            .ok_or(RelayError::Conflict("control connection is not active"))?;
        if session.key.session_id != ticket.session_id
            || session.key.epoch != ticket.epoch
            || (ticket.candidate && !session.profile.supports_rotation())
        {
            return Err(RelayError::Unauthorized);
        }
        if ticket.catalog_backed && (!session.cluster_profile || !session.owner_fenced) {
            return Err(RelayError::Unauthorized);
        }
        if !ticket.candidate && session.data_tx.is_some() {
            return Err(RelayError::Conflict("data connection is already active"));
        }
        if session.identity.spki_fingerprint != spki {
            return Err(RelayError::Unauthorized);
        }
        if session.identity.device_version != current_identity.device_version {
            return Err(RelayError::Unauthorized);
        }
        if session.owner.epoch != current_identity.owner_epoch {
            return Err(RelayError::Unauthorized);
        }
        let now_wall = Utc::now();
        let Some(current_owner) = current_owner else {
            return Err(RelayError::Unauthorized);
        };
        if ticket.owner != session.owner
            || current_owner.token != session.owner
            || current_owner.lease_expires_at
                <= now_wall
                    + ChronoDuration::from_std(OWNER_LEASE_SAFETY_MARGIN)
                        .unwrap_or_else(|_| ChronoDuration::seconds(5))
        {
            return Err(RelayError::Unauthorized);
        }
        let (data_tx, rx) = mpsc::channel(self.options.limits.max_queue_messages);
        let carrier = CarrierKey {
            session: session.key.clone(),
            generation: ticket.generation,
            connection_id: ticket.connection_id.clone(),
        };
        let context = carrier.context();
        if ticket.candidate {
            let Some(rotation) = session.rotation.as_mut() else {
                return Err(RelayError::Conflict("rotation candidate is not expected"));
            };
            let Some(attempt) = rotation.attempt.as_ref() else {
                return Err(RelayError::Conflict("rotation candidate is not expected"));
            };
            if rotation.candidate.is_some()
                || attempt.new_generation != ticket.generation
                || attempt.new_connection_id != ticket.connection_id
            {
                return Err(RelayError::Unauthorized);
            }
            match &ticket.attachment_purpose {
                DataAttachmentPurpose::RotationCandidate => {
                    if rotation
                        .state
                        .candidate_ready(attempt, monotonic_millis())
                        .is_err()
                    {
                        return Err(RelayError::Conflict("rotation candidate deadline elapsed"));
                    }
                }
                DataAttachmentPurpose::Recovery {
                    episode_id,
                    attempt_no,
                    closure_digest,
                } => {
                    let Some(recovery) = rotation.recovery.as_ref() else {
                        return Err(RelayError::Conflict("recovery candidate is not expected"));
                    };
                    if recovery.episode_id != *episode_id
                        || recovery.attempt_no != *attempt_no
                        || recovery.closure_digest.as_deref() != Some(closure_digest.as_str())
                    {
                        return Err(RelayError::Unauthorized);
                    }
                    rotation
                        .state
                        .reserve_recovery_socket(monotonic_millis())
                        .map_err(|_| RelayError::Conflict("recovery candidate deadline elapsed"))?;
                }
            }
        }
        if !ticket.candidate && ticket.generation != session.generation {
            // A stale initial-generation ticket cannot attach once the session
            // has moved on.  Refuse it before DATA_READY is queued so the
            // connector never observes readiness for a carrier that was not
            // installed.
            return Err(RelayError::Unauthorized);
        }
        let ready = wire::encode_control_message(&wire::data_ready(
            &ticket.welcome_message_id,
            &session.key.session_id,
            session.key.epoch,
            ticket.generation,
            &ticket.connection_id,
        ))
        .map_err(|error| RelayError::Protocol(error.to_string()))?;
        queue_control(&session.control_tx, &session.queue_budget, ready)
            .map_err(|_| RelayError::Overloaded("control queue is full"))?;
        if ticket.candidate {
            let rotation = session
                .rotation
                .as_mut()
                .ok_or(RelayError::Conflict("rotation candidate is not expected"))?;
            rotation.candidate = Some(DataCarrier {
                context,
                tx: data_tx.clone(),
            });
            if matches!(
                &ticket.attachment_purpose,
                DataAttachmentPurpose::Recovery { .. }
            ) && let Some(recovery) = rotation.recovery.as_mut()
            {
                recovery.candidate_ready = true;
            }
        } else {
            session.active_carrier = Some(DataCarrier {
                context,
                tx: data_tx.clone(),
            });
            session.data_tx = Some(data_tx.clone());
        }
        tracing::info!(
            tenant_id = %session.identity.tenant_id,
            device_id = %ticket.device_id,
            session_id = %session.key.session_id,
            epoch = session.key.epoch,
            phase = "data_attached",
        );
        Ok(DataRegistration { carrier, rx })
    }

    async fn dispatch_echo(&mut self, request: DispatchRequest) {
        let DispatchRequest {
            consumer,
            device_id,
            service_id,
            grant,
            body,
            consumer_expires_at,
            response,
        } = request;
        if response.is_closed() {
            return;
        }
        if body.len() > self.options.limits.max_body_bytes {
            let _ = response.send(EchoOutcome::Failure {
                code: "BODY_LIMIT",
                execution: "not_dispatched",
            });
            return;
        }
        if grant.tenant_id != consumer.tenant_id
            || grant.principal_id != consumer.principal_id
            || grant.device_id != device_id
            || grant.service_id != service_id
            || !grant.permissions.allows(crate::ECHO_OPERATION)
        {
            let _ = response.send(EchoOutcome::Failure {
                code: "FORBIDDEN",
                execution: "not_dispatched",
            });
            return;
        }
        let scope = DeviceScope::new(consumer.tenant_id, device_id);
        let Some(session) = self.sessions.get_mut(&scope) else {
            let _ = response.send(EchoOutcome::Failure {
                code: "DEVICE_OFFLINE",
                execution: "not_dispatched",
            });
            return;
        };
        if session.identity.tenant_id != consumer.tenant_id || session.data_tx.is_none() {
            let _ = response.send(EchoOutcome::Failure {
                code: "DEVICE_OFFLINE",
                execution: "not_dispatched",
            });
            return;
        }
        if session.cluster_profile && !session.owner_fenced {
            let _ = response.send(EchoOutcome::Failure {
                code: "OWNER_FENCING_REQUIRED",
                execution: "not_dispatched",
            });
            return;
        }
        if Self::rotation_frozen(session) {
            // The finite echo also enters `session.pending`, which is part of
            // the immutable QUIESCE roster.  Pause its admission during a
            // rotation/recovery freeze with the retryable overload the protocol
            // permits (docs/protocol.md "Quiesce admission") so a late pending
            // entry cannot drift the roster.
            let _ = response.send(EchoOutcome::Failure {
                code: "RESOURCE_EXHAUSTED",
                execution: "not_dispatched",
            });
            return;
        }
        if session.pending.len() >= self.options.limits.max_pending_operations
            || session.pending.len() >= self.options.limits.max_streams_per_device
        {
            let _ = response.send(EchoOutcome::Failure {
                code: "RESOURCE_EXHAUSTED",
                execution: "not_dispatched",
            });
            return;
        }
        if session.queued_bytes.saturating_add(body.len()) > self.options.limits.max_queue_bytes {
            let _ = response.send(EchoOutcome::Failure {
                code: "RESOURCE_EXHAUSTED",
                execution: "not_dispatched",
            });
            return;
        }
        let sequence = 1;
        let Some(stream_id) = allocate_stream_id(&mut session.next_stream_id) else {
            let _ = response.send(EchoOutcome::Failure {
                code: "STREAM_LIMIT",
                execution: "not_dispatched",
            });
            return;
        };
        let operation_id = Uuid::new_v4().to_string();
        let queued_len = body.len();
        let digest = wire::permission_digest(&grant, &service_id.to_string());
        let service_name = service_id.to_string();
        let open = match wire::encode_control_message(&wire::open(wire::OpenRequest {
            session_id: &session.key.session_id,
            epoch: session.key.epoch,
            stream_id,
            operation_id: &operation_id,
            service_id: &service_name,
            body_len: body.len(),
            grant_revision: grant.revision,
            digest: &digest,
            operation: "echo",
        })) {
            Ok(value) => value,
            Err(_) => {
                let _ = response.send(EchoOutcome::Failure {
                    code: "CONTROL_LIMIT",
                    execution: "not_dispatched",
                });
                return;
            }
        };
        if !session.queue_budget.reserve(queued_len) {
            let _ = response.send(EchoOutcome::Failure {
                code: "RESOURCE_EXHAUSTED",
                execution: "not_dispatched",
            });
            return;
        }
        session.pending.insert(
            stream_id,
            PendingEcho {
                operation_id: operation_id.clone(),
                send_sequence: sequence,
                response,
                response_sequence: 0,
                response_body: Vec::new(),
                challenge_id: None,
                consumer,
                service_id,
                grant,
                consumer_expires_at,
                body,
                created_at: Instant::now(),
                dispatched: false,
                authorization_in_flight: false,
            },
        );
        session.queued_bytes = session.queued_bytes.saturating_add(queued_len);
        if queue_control(&session.control_tx, &session.queue_budget, open).is_err() {
            if let Some(pending) = session.pending.remove(&stream_id) {
                release_pending_budget(session, &pending);
                let _ = pending.response.send(EchoOutcome::Failure {
                    code: "CONTROL_UNAVAILABLE",
                    execution: "not_dispatched",
                });
            }
            return;
        }
        tracing::debug!(
            tenant_id = %session.identity.tenant_id,
            device_id = %device_id,
            session_id = %session.key.session_id,
            epoch = session.key.epoch,
            stream_id,
            operation_id = %operation_id,
            service_id = %service_id,
            bytes = queued_len,
            phase = "stream_admitted",
        );
    }

    /// Admit one long-lived M2 echo stream.  The HTTP layer has already
    /// authenticated the consumer and resolved the catalog grant; the actor
    /// repeats the tenant/device/service checks while it owns the live
    /// session and allocates the logical stream ID without wrapping.
    #[cfg(test)]
    fn open_echo_stream(
        &mut self,
        consumer: AuthenticatedConsumer,
        device_id: Uuid,
        service_id: Uuid,
        grant: GrantSnapshot,
        consumer_expires_at: chrono::DateTime<Utc>,
        response: oneshot::Sender<Result<ConsumerStreamRegistration, RelayError>>,
    ) {
        self.open_echo_stream_with_request_id(
            consumer,
            device_id,
            service_id,
            grant,
            consumer_expires_at,
            None,
            response,
        );
    }

    #[allow(clippy::too_many_arguments)] // Exact authorization, lifetime, request, and reply context.
    fn open_echo_stream_with_request_id(
        &mut self,
        consumer: AuthenticatedConsumer,
        device_id: Uuid,
        service_id: Uuid,
        grant: GrantSnapshot,
        consumer_expires_at: chrono::DateTime<Utc>,
        request_id: Option<String>,
        response: oneshot::Sender<Result<ConsumerStreamRegistration, RelayError>>,
    ) {
        if grant.valid_until <= Utc::now()
            || consumer_expires_at <= Utc::now()
            || grant.tenant_id != consumer.tenant_id
            || grant.principal_id != consumer.principal_id
            || grant.device_id != device_id
            || grant.service_id != service_id
            || !grant.permissions.allows(crate::ECHO_OPERATION)
        {
            let _ = response.send(Err(RelayError::Forbidden));
            return;
        }
        let scope = DeviceScope::new(consumer.tenant_id, device_id);
        let Some(session) = self.sessions.get_mut(&scope) else {
            let _ = response.send(Err(RelayError::NotFound));
            return;
        };
        if !session.profile.supports_rotation() {
            let _ = response.send(Err(RelayError::Conflict(
                "M2 ordered stream is not available",
            )));
            return;
        }
        if session.identity.tenant_id != consumer.tenant_id {
            let _ = response.send(Err(RelayError::Forbidden));
            return;
        }
        if session.active_carrier.is_none() || (session.cluster_profile && !session.owner_fenced) {
            let _ = response.send(Err(RelayError::OwnerNotReady));
            return;
        }
        if Self::rotation_frozen(session) {
            // docs/protocol.md "Quiesce admission": new OPEN admission is paused
            // from QUIESCE until COMMITTED/ABORTED (and throughout recovery) so
            // the immutable roster fixed at quiesce cannot drift.  An OPEN
            // landing mid-attempt would be excluded from the roster and make
            // the pure machine's `frozen()` roster-equality check fail with
            // RosterMismatch, stalling the attempt until the deadline.  The
            // protocol permits a "retryable overload" here; `OwnerNotReady` is
            // the existing pending-owner outcome (the owner is live but
            // momentarily not admitting) and already carries `not_dispatched`
            // plus a bounded retry-after, so no new code or HTTP mapping is
            // needed.  Streams already admitted continue unaffected.
            let _ = response.send(Err(RelayError::OwnerNotReady));
            return;
        }
        let active_streams = session
            .streams
            .values()
            .filter(|stream| !stream.terminal)
            .count();
        let retained_stream_limit = self
            .options
            .limits
            .max_streams_per_device
            .saturating_mul(RETAINED_ECHO_STREAM_FACTOR);
        if active_streams >= self.options.limits.max_streams_per_device
            || session.streams.len() >= retained_stream_limit
        {
            let _ = response.send(Err(RelayError::StreamLimit));
            return;
        }
        let Some(stream_id) = allocate_stream_id(&mut session.next_stream_id) else {
            let _ = response.send(Err(RelayError::Conflict("stream ID space exhausted")));
            return;
        };
        let operation_id = Uuid::new_v4().to_string();
        let service_name = service_id.to_string();
        let digest = wire::permission_digest(&grant, &service_name);
        let open_message = wire::open(wire::OpenRequest {
            session_id: &session.key.session_id,
            epoch: session.key.epoch,
            stream_id,
            operation_id: &operation_id,
            service_id: &service_name,
            body_len: 0,
            grant_revision: grant.revision,
            digest: &digest,
            operation: "echo_stream",
        });
        let open_message_id = match &open_message {
            ControlMessage::Open(open) => open.message_id.clone(),
            _ => unreachable!("wire::open must return an OPEN control message"),
        };
        let open = match wire::encode_control_message(&open_message) {
            Ok(value) => value,
            Err(_) => {
                let _ = response.send(Err(RelayError::Protocol(
                    "stream OPEN exceeds the control bound".into(),
                )));
                return;
            }
        };
        if queue_control(&session.control_tx, &session.queue_budget, open).is_err() {
            let _ = response.send(Err(RelayError::Overloaded("control queue is full")));
            return;
        }
        let stream_slots = self.options.limits.max_streams_per_device.max(1);
        // Keep enough retained capacity for one legal response record even
        // when the fair-share value is smaller.  The actual aggregate budget
        // remains the session queue budget; this floor prevents a maximum
        // 64 KiB request plus canary from being rejected merely because it
        // spans two tunnel frames.
        let minimum_record_bytes = wire::MAX_BODY_BYTES
            .saturating_add(MAX_ECHO_RESPONSE_EXTRA_BYTES)
            .saturating_add(4);
        let per_stream_queue =
            (self.options.limits.max_queue_bytes / stream_slots).max(minimum_record_bytes);
        let per_stream_frames = (self.options.limits.max_queue_messages / stream_slots).max(1);
        let limits = tunnel_protocol::sequence::SequenceLimits::new(
            tunnel_protocol::sequence::DEFAULT_MAX_REPLAY_FRAMES,
            tunnel_protocol::sequence::DEFAULT_MAX_REPLAY_BYTES.min(per_stream_queue),
            tunnel_protocol::sequence::DEFAULT_MAX_REORDER_FRAMES.min(per_stream_frames),
            tunnel_protocol::sequence::DEFAULT_MAX_REORDER_BYTES.min(per_stream_queue),
        );
        let sequence = match StreamState::with_credits_and_limits(
            stream_id,
            wire::M2_INITIAL_WINDOW_BYTES as u64,
            wire::M2_INITIAL_WINDOW_BYTES as u64,
            limits,
        ) {
            Ok(sequence) => sequence,
            Err(error) => {
                let _ = response.send(Err(RelayError::Protocol(error.to_string())));
                return;
            }
        };
        let closed = CancellationToken::new();
        let admission_lease = CancellationToken::new();
        let admission_deadline = Instant::now() + self.options.limits.operation_timeout;
        let registration_key = session.key.clone();
        session.streams.insert(
            stream_id,
            M2Stream {
                open_message_id,
                operation_id: operation_id.clone(),
                request_id,
                service_id,
                consumer,
                grant,
                sequence,
                response_bytes: Vec::new(),
                response_records: VecDeque::new(),
                send_bytes: 0,
                receive_bytes: 0,
                authorized_until: None,
                consumer_expires_at,
                challenge_id: None,
                authorization_in_flight: false,
                authorization_started_at_ms: None,
                authorization_deadline_ms: None,
                authorization_admission_deadline_ms: None,
                pending_records: VecDeque::new(),
                pending_record_bytes: 0,
                budget_bytes: 0,
                terminal: false,
                pending_terminal: None,
                terminal_fin_failure: false,
                open_pending: true,
                registration_dropped: false,
                deferred_terminal_cause: None,
                closed: closed.clone(),
                admission_lease: admission_lease.clone(),
                admission_deadline,
                authorization_failure_code: None,
            },
        );
        let registration = ConsumerStreamRegistration {
            key: registration_key.clone(),
            stream_id,
            operation_id: operation_id.clone(),
            closed,
            admission_lease,
        };
        self.send_echo_registration(response, registration);
    }

    fn send_echo_registration(
        &mut self,
        response: oneshot::Sender<Result<ConsumerStreamRegistration, RelayError>>,
        registration: ConsumerStreamRegistration,
    ) {
        if let Some(registration) = send_registration(response, Ok(registration)) {
            self.remove_echo_stream(
                &registration.key,
                registration.stream_id,
                &registration.operation_id,
            );
        }
    }

    /// Reconcile a consumer whose registration reply was dropped. A pending
    /// OPEN remains until the owner reports OPENED or an exact REJECTED; an
    /// admitted OPEN uses the normal terminal FIN/RESET path before physical
    /// removal. A full or closed queue leaves the exact tombstone for the
    /// actor tick to retry.
    fn remove_echo_stream(&mut self, key: &SessionKey, stream_id: u64, operation_id: &str) {
        let Some(session) = self.session_for(key) else {
            return;
        };
        let Some(stream) = session.streams.get(&stream_id) else {
            return;
        };
        if stream.operation_id != operation_id {
            return;
        }
        if stream.open_pending {
            // A dropped registration does not prove that the connector
            // rejected OPEN. Keep the exact OPEN identity until OPENED or a
            // matching REJECTED arrives; after OPENED, the branch below uses
            // the normal transactional FIN path.  The close path performs
            // exactly this deferral for a pending OPEN.
            let _ = self.close_echo_stream(key, stream_id, operation_id);
            return;
        }

        // OPENED was already observed, so a dropped registration is a real
        // consumer-side close. Emit FIN/RESET through the existing
        // transactional close path before attempting owner FORGET.
        self.close_echo_stream(key, stream_id, operation_id);
        let _ = self.flush_owner_stream_forgets(key);
    }

    /// Fence a stream and release its waiter/application state.  A retained
    /// terminal tombstone keeps its budget charge until STREAM_FORGET because
    /// the StreamState replay/reorder buffers remain live for late-frame
    /// fencing; physical removal is the only path that may release it.
    fn release_echo_stream_state(
        stream: &mut M2Stream,
        queue_budget: &QueueBudget,
        release_budget: bool,
    ) {
        stream.closed.cancel();
        if release_budget {
            queue_budget.release(stream.budget_bytes);
            stream.budget_bytes = 0;
        }
        stream.pending_record_bytes = 0;
        stream.response_bytes.clear();
        for (_, waiter) in stream.pending_records.drain(..) {
            let _ = waiter.send(Err(EchoOutcome::Failure {
                code: "REVERSE_CHANNEL_INTERRUPTED",
                execution: "unknown",
            }));
        }
        for waiter in stream.response_records.drain(..) {
            let _ = waiter.send(Err(EchoOutcome::Failure {
                code: "REVERSE_CHANNEL_INTERRUPTED",
                execution: "unknown",
            }));
        }
    }

    /// Return the owner-side final cursor only when both logical directions
    /// have reached an authenticated terminal state and no retained work can
    /// still be replayed or delivered. This is derived from live StreamState,
    /// not the local delivery marker alone.
    fn owner_stream_forget_state(
        session: &DeviceSession,
        stream: &M2Stream,
    ) -> Option<ResumeDirectionState> {
        if !stream.terminal || stream.open_pending {
            return None;
        }
        // PREPARING is allowed because the caller queues FORGET before it
        // constructs QUIESCE. Once quiescing or recovering, roster/replay
        // references make reclamation unsafe.
        if session.rotation.as_ref().is_some_and(|rotation| {
            rotation.recovery.is_some()
                || !matches!(
                    rotation.state.phase(),
                    RotationPhase::Active | RotationPhase::Preparing
                )
        }) {
            return None;
        }
        if !stream.response_bytes.is_empty()
            || !stream.pending_records.is_empty()
            || !stream.response_records.is_empty()
        {
            return None;
        }
        let snapshot = stream.sequence.snapshot();
        let sent = snapshot.direction(Direction::RelayToConnector);
        let received = snapshot.direction(Direction::ConnectorToRelay);
        // Both terminals and all receive/replay cursors are checked from the
        // authoritative sequence state. A short ACK or receive gap retains
        // the tombstone.
        if sent.send_terminal.is_none()
            || sent.send_terminal_sequence != Some(sent.last_emitted)
            || sent.peer_acked < sent.last_emitted
            || sent.replay_floor.is_some()
            || sent.replay_bytes != 0
            || received.receive_terminal.is_none()
            || received.receive_terminal_sequence != Some(received.recv_contiguous)
            || received.recv_contiguous != received.delivered_contiguous
            || received.reorder_frames != 0
            || received.reorder_bytes != 0
            || !stream
                .sequence
                .ready_frames(Direction::ConnectorToRelay)
                .is_empty()
        {
            return None;
        }
        ResumeDirectionState::from_sequence_snapshot(stream.sequence.stream_id(), sent).ok()
    }

    /// Retain one owner FORGET identity before trying the control queue. A
    /// stable message ID makes queue-full retries idempotent; the bounded
    /// stream table, rather than an eviction policy, bounds this map.
    fn stage_owner_stream_forget(
        &mut self,
        key: &SessionKey,
        stream_id: u64,
        operation_id: &str,
        direction: Direction,
        final_state: ResumeDirectionState,
    ) -> bool {
        let Some(session) = self.session_for(key) else {
            return false;
        };
        let Some(stream) = session.streams.get(&stream_id) else {
            return false;
        };
        if stream.operation_id != operation_id || final_state.stream_id != stream_id {
            return false;
        }
        let limit = self
            .options
            .limits
            .max_streams_per_device
            .max(1)
            .saturating_mul(RETAINED_ECHO_STREAM_FACTOR);
        let pending = self.owner_forgets.entry(key.clone()).or_default();
        if let Some(existing) = pending.get(&stream_id) {
            return existing.operation_id == operation_id
                && existing.direction == direction
                && existing.final_state == final_state;
        }
        if pending.len() >= limit {
            // Never evict an old identity to make room for a new one.
            return false;
        }
        pending.insert(
            stream_id,
            PendingOwnerForget {
                message_id: wire::random_token(),
                operation_id: operation_id.to_owned(),
                direction,
                final_state,
            },
        );
        true
    }

    /// Start one absolute fail-closed window for a critical FORGET that could
    /// not be published. Retries do not extend the deadline: a stalled or
    /// closed authenticated control path must close the owner session instead
    /// of retaining terminal state indefinitely.
    fn arm_owner_forget_deadline(&mut self, key: &SessionKey) {
        if let Some(session) = self.session_mut(key)
            && session.owner_forget_deadline.is_none()
        {
            session.owner_forget_deadline = Some(Instant::now() + OWNER_FORGET_FAILURE_TIMEOUT);
        }
    }

    /// Start one absolute fail-closed window for a terminal FIN publication
    /// failure. This debt is deliberately separate from owner FORGET queue
    /// debt: an unrelated FORGET may complete and clear its own deadline
    /// while the failed-FIN tombstone remains impossible to compact.
    fn arm_terminal_fin_failure_deadline(&mut self, key: &SessionKey) {
        if let Some(session) = self.session_mut(key)
            && session.terminal_fin_failure_deadline.is_none()
        {
            session.terminal_fin_failure_deadline =
                Some(Instant::now() + OWNER_FORGET_FAILURE_TIMEOUT);
        }
    }

    /// Clear terminal-FIN debt only after every stream carrying that marker
    /// has been physically removed. Successful unrelated FORGETs must never
    /// clear this latch while the failed stream remains retained.
    fn clear_terminal_fin_failure_deadline_if_clear(&mut self, key: &SessionKey) {
        let clear = self.session_for(key).is_none_or(|session| {
            !session
                .streams
                .values()
                .any(|stream| stream.terminal_fin_failure)
        });
        if clear && let Some(session) = self.session_mut(key) {
            session.terminal_fin_failure_deadline = None;
        }
    }

    /// Publish staged owner FORGETs and newly eligible terminal tombstones.
    /// Queueing and state removal are one actor-thread transaction: a full or
    /// closed control queue leaves both the stable pending identity and the
    /// stream budget/tombstone intact for the next tick. The same FIFO is used
    /// by QUIESCE, so successful FORGETs precede the next immutable roster.
    fn flush_owner_stream_forgets(&mut self, key: &SessionKey) -> bool {
        if self.session_for(key).is_none() {
            self.owner_forgets.remove(key);
            return true;
        }

        // FORGET is serialized with QUIESCE: an entry leaves a snapshot only
        // when its FORGET precedes QUIESCE (docs/protocol.md RESET/terminal
        // paragraph).  While the immutable roster is frozen
        // (QUIESCE..COMMITTED/ABORTED, and recovery), publishing a FORGET would
        // remove a roster entry mid-attempt and fail the pure machine's
        // roster-equality check; keep every staged FORGET pending — including a
        // REJECTED-open reclamation — until the attempt releases the roster.
        // `begin_rotation_quiesce` flushes while still `Preparing`, before this
        // guard engages, preserving the pre-QUIESCE serialization.
        if self.session_for(key).is_some_and(Self::rotation_frozen) {
            return true;
        }

        let candidates = self
            .session_for(key)
            .map(|session| {
                session
                    .streams
                    .iter()
                    .filter(|(stream_id, _)| {
                        !self
                            .owner_forgets
                            .get(key)
                            .is_some_and(|pending| pending.contains_key(stream_id))
                    })
                    .filter_map(|(stream_id, stream)| {
                        Self::owner_stream_forget_state(session, stream).map(|final_state| {
                            (*stream_id, stream.operation_id.clone(), final_state)
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for (stream_id, operation_id, final_state) in candidates {
            let staged = self.stage_owner_stream_forget(
                key,
                stream_id,
                &operation_id,
                Direction::RelayToConnector,
                final_state,
            );
            if !staged {
                self.arm_owner_forget_deadline(key);
            }
        }

        let stream_ids = self
            .owner_forgets
            .get(key)
            .map(|pending| pending.keys().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        for stream_id in stream_ids {
            // A terminal stream may receive a final ACK/window update while
            // its control queue entry waits for capacity. Refresh the cursor
            // evidence under the same stable message ID; never publish a
            // stale final state. Rejected OPEN tombstones intentionally have
            // no live sequence terminal and keep their no-stream evidence.
            let is_rejected_open = self
                .session_for(key)
                .and_then(|session| session.streams.get(&stream_id))
                .is_some_and(|stream| stream.open_pending);
            if !is_rejected_open {
                let Some(current_state) = self.session_for(key).and_then(|session| {
                    session
                        .streams
                        .get(&stream_id)
                        .and_then(|stream| Self::owner_stream_forget_state(session, stream))
                }) else {
                    self.arm_owner_forget_deadline(key);
                    return false;
                };
                if let Some(pending) = self
                    .owner_forgets
                    .get_mut(key)
                    .and_then(|pending| pending.get_mut(&stream_id))
                {
                    pending.final_state = current_state;
                }
            }
            let Some(pending) = self
                .owner_forgets
                .get(key)
                .and_then(|pending| pending.get(&stream_id))
                .cloned()
            else {
                continue;
            };
            let message =
                ControlMessage::StreamForget(tunnel_protocol::rotation_control::StreamForget {
                    message_id: pending.message_id.clone(),
                    reply_to: String::new(),
                    session_id: key.session_id.clone(),
                    epoch: key.epoch,
                    stream_id,
                    operation_id: pending.operation_id.clone(),
                    direction: pending.direction,
                    final_state: pending.final_state.clone(),
                });
            let Ok(encoded) = wire::encode_control_message(&message) else {
                // Encoding failure is also a failed critical publication: do
                // not allow QUIESCE to overtake the retained identity.
                self.arm_owner_forget_deadline(key);
                return false;
            };
            let queued = self.session_for(key).is_some_and(|session| {
                queue_control(&session.control_tx, &session.queue_budget, encoded).is_ok()
            });
            if !queued {
                // Keep this exact message ID and tombstone for a later
                // bounded retry; never synthesize a replacement or evict it.
                self.arm_owner_forget_deadline(key);
                return false;
            }

            let removed = if let Some(session) = self.session_mut(key) {
                let matches = session
                    .streams
                    .get(&stream_id)
                    .is_some_and(|stream| stream.operation_id == pending.operation_id);
                if !matches {
                    false
                } else if let Some(mut stream) = session.streams.remove(&stream_id) {
                    Self::release_echo_stream_state(&mut stream, &session.queue_budget, true);
                    session.forgotten_stream_through =
                        session.forgotten_stream_through.max(stream_id);
                    true
                } else {
                    false
                }
            } else {
                false
            };
            if !removed {
                // A sent FORGET must never remove a different operation.
                self.arm_owner_forget_deadline(key);
                return false;
            }
            self.clear_terminal_fin_failure_deadline_if_clear(key);
            let pending_empty = self.owner_forgets.get_mut(key).is_some_and(|pending| {
                pending.remove(&stream_id);
                pending.is_empty()
            });
            if pending_empty {
                self.owner_forgets.remove(key);
                if let Some(session) = self.session_mut(key) {
                    session.owner_forget_deadline = None;
                }
            }
        }
        true
    }

    /// True while the relay->connector sequenced-frame writer is frozen at its
    /// immutable rotation fence and new stream admission is paused.  Per
    /// docs/protocol.md "Rotation state machine", the `Quiescing`, `Draining`,
    /// `Committing` and `Aborting` rows freeze both old sequenced-frame writers
    /// and new OPEN admission; the old writer stays frozen until the candidate
    /// is activated by COMMITTED (phase advances to `Retiring`) or the old
    /// carrier resumes after the final ABORTED (phase returns to `Active`).
    /// The "Recovery control handshake" freezes admission and application
    /// writes the same way for the duration of `Recovering`.  DATA/FIN/RESET
    /// are held in the bounded per-stream FIFO while this holds; ACKs, window
    /// updates, heartbeats and rotation control remain responsive.
    fn rotation_frozen(session: &DeviceSession) -> bool {
        session.rotation.as_ref().is_some_and(|rotation| {
            matches!(
                rotation.state.phase(),
                RotationPhase::Quiescing
                    | RotationPhase::Draining
                    | RotationPhase::Committing
                    | RotationPhase::Aborting
                    | RotationPhase::Recovering
            )
        })
    }

    /// Build, sequence and queue one relay->connector terminal frame on the
    /// session's current data carrier.  Returns false only on a genuine
    /// publication failure (no writable carrier or a rejected writer queue);
    /// the sequence cursor is committed on the stream only after the encoded
    /// frame is accepted, so a full writer never leaves a phantom terminal.
    /// An already-terminal send direction is treated as done.
    fn queue_stream_terminal_frame(
        session: &mut DeviceSession,
        stream_id: u64,
        terminal: Terminal,
    ) -> bool {
        let Some(data_tx) = session.data_tx.clone() else {
            return false;
        };
        let queue_budget = session.queue_budget.clone();
        let generation = session.generation;
        let epoch = session.key.epoch;
        let Some(stream) = session.streams.get_mut(&stream_id) else {
            return true;
        };
        let send_direction = stream.sequence.direction(Direction::RelayToConnector);
        if send_direction.send_terminal().is_some() {
            return true;
        }
        let Some(sequence) = send_direction.last_emitted().checked_add(1) else {
            return false;
        };
        let ack = stream
            .sequence
            .direction(Direction::ConnectorToRelay)
            .recv_contiguous();
        let frame = match terminal {
            Terminal::Fin => Frame::fin(epoch, generation, stream_id, sequence, ack),
            Terminal::Reset(reason) => {
                Frame::reset(epoch, generation, stream_id, sequence, ack, reason)
            }
        };
        let mut candidate_sequence = stream.sequence.clone();
        if candidate_sequence
            .send_frame(Direction::RelayToConnector, &frame)
            .is_err()
        {
            return false;
        }
        let Ok(encoded) = frame.encode() else {
            return false;
        };
        if queue_data(&data_tx, &queue_budget, encoded).is_err() {
            return false;
        }
        stream.sequence = candidate_sequence;
        true
    }

    /// After the relay writer resumes on a writable carrier (the candidate
    /// after COMMITTED, or the old carrier after a coordinated ABORTED), emit
    /// every frame held while the writer was frozen: deferred application
    /// records first, in FIFO order, then any deferred terminal, each with the
    /// continuing sequence.  A no-op while still frozen or without an active
    /// carrier, so it is safe to call opportunistically.
    fn flush_frozen_writes(&mut self, key: &SessionKey) {
        let ready = self
            .session_for(key)
            .is_some_and(|session| !Self::rotation_frozen(session) && session.data_tx.is_some());
        if !ready {
            return;
        }
        let stream_ids = self
            .session_for(key)
            .map(|session| {
                let mut ids: Vec<u64> = session.streams.keys().copied().collect();
                ids.sort_unstable();
                ids
            })
            .unwrap_or_default();
        for stream_id in stream_ids {
            self.retry_pending_echo_records(key, stream_id);
            self.flush_pending_terminal(key, stream_id);
        }
    }

    /// Emit one stream's deferred terminal once every deferred application
    /// record ahead of it has been emitted and the writer is unfrozen.  The
    /// terminal keeps its place at the tail of the stream's sequence space.
    fn flush_pending_terminal(&mut self, key: &SessionKey, stream_id: u64) {
        let terminal = self.session_for(key).and_then(|session| {
            if Self::rotation_frozen(session) || session.data_tx.is_none() {
                return None;
            }
            let stream = session.streams.get(&stream_id)?;
            if !stream.pending_records.is_empty() {
                return None;
            }
            stream.pending_terminal
        });
        let Some(terminal) = terminal else {
            return;
        };
        let emitted = self
            .session_mut(key)
            .is_some_and(|session| Self::queue_stream_terminal_frame(session, stream_id, terminal));
        if emitted {
            if let Some(session) = self.session_mut(key)
                && let Some(stream) = session.streams.get_mut(&stream_id)
            {
                stream.pending_terminal = None;
                stream.terminal_fin_failure = false;
            }
            self.clear_terminal_fin_failure_deadline_if_clear(key);
        } else {
            if let Some(session) = self.session_mut(key)
                && let Some(stream) = session.streams.get_mut(&stream_id)
            {
                stream.terminal_fin_failure = true;
            }
            self.arm_terminal_fin_failure_deadline(key);
        }
    }

    /// Queue one length-prefixed application record without waiting for a
    /// socket writer.  The shared queue budget charges every encoded frame;
    /// a dropped/retired candidate therefore cannot create a second budget.
    fn write_echo_stream(
        &mut self,
        key: SessionKey,
        stream_id: u64,
        operation_id: String,
        body: Vec<u8>,
        response: oneshot::Sender<Result<Vec<u8>, EchoOutcome>>,
    ) {
        self.write_echo_stream_inner(key, stream_id, operation_id, body, response, false);
    }

    fn write_echo_stream_inner(
        &mut self,
        key: SessionKey,
        stream_id: u64,
        operation_id: String,
        body: Vec<u8>,
        response: oneshot::Sender<Result<Vec<u8>, EchoOutcome>>,
        from_pending_credit: bool,
    ) {
        if body.len() > wire::MAX_BODY_BYTES {
            let _ = response.send(Err(EchoOutcome::Failure {
                code: "BODY_LIMIT",
                execution: "not_dispatched",
            }));
            return;
        }
        let max_pending_operations = self.options.limits.max_pending_operations;
        let max_queue_bytes = self.options.limits.max_queue_bytes;
        let now = Utc::now();
        let Some(session) = self.session_mut(&key) else {
            let _ = response.send(Err(EchoOutcome::Failure {
                code: "DEVICE_OFFLINE",
                execution: "not_dispatched",
            }));
            return;
        };
        let data_tx = session.data_tx.clone();
        let recovering = session
            .rotation
            .as_ref()
            .is_some_and(|rotation| rotation.state.phase() == RotationPhase::Recovering);
        let writer_frozen = Self::rotation_frozen(session);
        if data_tx.is_none() && !recovering {
            let _ = response.send(Err(EchoOutcome::Failure {
                code: "DEVICE_OFFLINE",
                execution: "not_dispatched",
            }));
            return;
        }
        let queue_budget = session.queue_budget.clone();
        let generation = session.generation;
        let Some(stream) = session.streams.get_mut(&stream_id) else {
            let _ = response.send(Err(EchoOutcome::Failure {
                code: "STREAM_NOT_FOUND",
                execution: "not_dispatched",
            }));
            return;
        };
        if stream.operation_id != operation_id || stream.terminal {
            let _ = response.send(Err(EchoOutcome::Failure {
                code: "STREAM_NOT_FOUND",
                execution: "not_dispatched",
            }));
            return;
        }
        if stream.grant.valid_until <= now || stream.consumer_expires_at <= now {
            stream.authorization_failure_code = Some("AUTHORIZATION_EXPIRED");
            let _ = response.send(Err(EchoOutcome::Failure {
                code: "AUTHORIZATION_EXPIRED",
                execution: "not_dispatched",
            }));
            return;
        }
        if writer_frozen {
            // docs/protocol.md "Freeze each writer": from QUIESCE until the
            // candidate is activated by COMMITTED (or the old carrier resumes
            // after a coordinated ABORTED), and throughout recovery, the
            // relay->connector writer emits no sequenced frame.  Hold the
            // record in the existing bounded FIFO, charged to the session queue
            // budget, and flush it on the writable carrier afterwards with the
            // continuing sequence.  The record is never emitted on the frozen
            // carrier and never silently dropped; the bound produces the same
            // typed capacity refusal used elsewhere.
            if stream.pending_records.len() >= max_pending_operations
                || stream.pending_record_bytes.saturating_add(body.len()) > max_queue_bytes
                || !reserve_m2_bytes(&queue_budget, stream, body.len())
            {
                let _ = response.send(Err(EchoOutcome::Failure {
                    code: "RESOURCE_EXHAUSTED",
                    execution: "not_dispatched",
                }));
            } else {
                stream.pending_record_bytes =
                    stream.pending_record_bytes.saturating_add(body.len());
                stream.pending_records.push_back((body, response));
            }
            return;
        }
        if stream
            .authorized_until
            .is_none_or(|deadline| deadline <= Instant::now())
        {
            if stream.pending_records.len() >= max_pending_operations
                || stream.pending_record_bytes.saturating_add(body.len()) > max_queue_bytes
                || !reserve_m2_bytes(&queue_budget, stream, body.len())
            {
                let _ = response.send(Err(EchoOutcome::Failure {
                    code: "RESOURCE_EXHAUSTED",
                    execution: "not_dispatched",
                }));
            } else {
                stream.pending_record_bytes =
                    stream.pending_record_bytes.saturating_add(body.len());
                stream.pending_records.push_back((body, response));
            }
            return;
        }
        let Some(data_tx) = data_tx else {
            if stream.pending_records.len() >= max_pending_operations
                || stream.pending_record_bytes.saturating_add(body.len()) > max_queue_bytes
                || !reserve_m2_bytes(&queue_budget, stream, body.len())
            {
                let _ = response.send(Err(EchoOutcome::Failure {
                    code: "RESOURCE_EXHAUSTED",
                    execution: "not_dispatched",
                }));
            } else {
                stream.pending_record_bytes =
                    stream.pending_record_bytes.saturating_add(body.len());
                stream.pending_records.push_back((body, response));
            }
            return;
        };
        // A record already held for credit or a recovering carrier owns the
        // next logical response slot.  Queue subsequent writes behind it so
        // the public consumer cannot overtake the blocked prefix.
        if !from_pending_credit && !stream.pending_records.is_empty() {
            if stream.pending_records.len() >= max_pending_operations
                || stream.pending_record_bytes.saturating_add(body.len()) > max_queue_bytes
                || !reserve_m2_bytes(&queue_budget, stream, body.len())
            {
                let _ = response.send(Err(EchoOutcome::Failure {
                    code: "RESOURCE_EXHAUSTED",
                    execution: "not_dispatched",
                }));
            } else {
                stream.pending_record_bytes =
                    stream.pending_record_bytes.saturating_add(body.len());
                stream.pending_records.push_back((body, response));
            }
            return;
        }
        let Some(record_len) = body.len().checked_add(4) else {
            let _ = response.send(Err(EchoOutcome::Failure {
                code: "BODY_LIMIT",
                execution: "not_dispatched",
            }));
            return;
        };
        let Ok(record_len_u32) = u32::try_from(body.len()) else {
            let _ = response.send(Err(EchoOutcome::Failure {
                code: "BODY_LIMIT",
                execution: "not_dispatched",
            }));
            return;
        };
        // A logical record may span multiple tunnel DATA frames.  Admit the
        // complete record against the cumulative send credit before emitting
        // its first chunk; otherwise a maximum record can partially emit and
        // turn a transient lack of WINDOW_UPDATE into a terminal consumer
        // failure.  Keep the whole record in the bounded FIFO until the
        // connector advertises enough absolute credit.
        let record_len_u64 = u64::try_from(record_len).unwrap_or(u64::MAX);
        let send_direction = stream.sequence.direction(Direction::RelayToConnector);
        let record_fits_credit = send_direction
            .sent_bytes()
            .checked_add(record_len_u64)
            .is_some_and(|attempted| attempted <= send_direction.send_credit());
        if !record_fits_credit {
            if stream.pending_records.len() >= max_pending_operations
                || stream.pending_record_bytes.saturating_add(body.len()) > max_queue_bytes
                || !reserve_m2_bytes(&queue_budget, stream, body.len())
            {
                let _ = response.send(Err(EchoOutcome::Failure {
                    code: "RESOURCE_EXHAUSTED",
                    execution: "not_dispatched",
                }));
            } else {
                stream.pending_record_bytes =
                    stream.pending_record_bytes.saturating_add(body.len());
                stream.pending_records.push_back((body, response));
            }
            return;
        }

        let mut record = Vec::with_capacity(record_len);
        record.extend_from_slice(&record_len_u32.to_be_bytes());
        record.extend_from_slice(&body);
        let mut response = Some(response);
        for chunk in record.chunks(tunnel_protocol::MAX_PAYLOAD_LEN) {
            let sequence = match stream
                .sequence
                .direction(Direction::RelayToConnector)
                .last_emitted()
                .checked_add(1)
            {
                Some(sequence) => sequence,
                None => {
                    let _ = response.take().expect("response available").send(Err(
                        EchoOutcome::Failure {
                            code: "STREAM_LIMIT",
                            execution: "not_dispatched",
                        },
                    ));
                    return;
                }
            };
            let ack = stream
                .sequence
                .direction(Direction::ConnectorToRelay)
                .recv_contiguous();
            let frame = Frame::data(
                key.epoch,
                generation,
                stream_id,
                sequence,
                ack,
                chunk.to_vec(),
            );
            if !reserve_m2_bytes(&queue_budget, stream, chunk.len()) {
                let _ =
                    response
                        .take()
                        .expect("response available")
                        .send(Err(EchoOutcome::Failure {
                            code: "RESOURCE_EXHAUSTED",
                            execution: "not_dispatched",
                        }));
                return;
            }
            if stream
                .sequence
                .send_frame(Direction::RelayToConnector, &frame)
                .is_err()
            {
                release_m2_bytes(&queue_budget, stream, chunk.len());
                let _ =
                    response
                        .take()
                        .expect("response available")
                        .send(Err(EchoOutcome::Failure {
                            code: "RESOURCE_EXHAUSTED",
                            execution: "not_dispatched",
                        }));
                return;
            }
            let Ok(encoded) = frame.encode() else {
                let _ =
                    response
                        .take()
                        .expect("response available")
                        .send(Err(EchoOutcome::Failure {
                            code: "FRAME_LIMIT",
                            execution: "not_dispatched",
                        }));
                return;
            };
            if queue_data(&data_tx, &queue_budget, encoded).is_err() {
                let _ =
                    response
                        .take()
                        .expect("response available")
                        .send(Err(EchoOutcome::Failure {
                            code: "REVERSE_CHANNEL_UNAVAILABLE",
                            execution: "unknown",
                        }));
                return;
            }
        }
        stream.send_bytes = stream.send_bytes.saturating_add(body.len());
        stream
            .response_records
            .push_back(response.take().expect("response available"));
        self.record_application_dispatch();
    }

    /// Retry records held back by cumulative send credit in FIFO order.  The
    /// first record remains at the head until its complete length fits, so a
    /// later consumer write can never overtake a blocked maximum record.
    fn retry_pending_echo_records(&mut self, key: &SessionKey, stream_id: u64) {
        loop {
            let Some((body_len, record_fits_credit, operation_id)) = self
                .session_for(key)
                .and_then(|session| {
                    // While the writer is frozen at its rotation fence, held
                    // records stay queued; flushing would emit on the old
                    // carrier past the fence.  They flush after activation.
                    if Self::rotation_frozen(session) {
                        return None;
                    }
                    session.data_tx.as_ref()?;
                    session.streams.get(&stream_id)
                })
                .and_then(|stream| {
                    if stream.pending_records.is_empty()
                        || stream.terminal
                        || stream.authorization_in_flight
                        || stream
                            .authorized_until
                            .is_none_or(|deadline| deadline <= Instant::now())
                    {
                        return None;
                    }
                    let (body, _) = stream.pending_records.front()?;
                    let record_len = body.len().checked_add(4)?;
                    let record_len = u64::try_from(record_len).ok()?;
                    let direction = stream.sequence.direction(Direction::RelayToConnector);
                    Some((
                        body.len(),
                        direction
                            .sent_bytes()
                            .checked_add(record_len)
                            .is_some_and(|attempted| attempted <= direction.send_credit()),
                        stream.operation_id.clone(),
                    ))
                })
            else {
                return;
            };
            if !record_fits_credit {
                return;
            }

            let Some((body, response)) = self.session_mut(key).and_then(|session| {
                let queue_budget = session.queue_budget.clone();
                let stream = session.streams.get_mut(&stream_id)?;
                let pending = stream.pending_records.pop_front()?;
                stream.pending_record_bytes = stream.pending_record_bytes.saturating_sub(body_len);
                release_m2_bytes(&queue_budget, stream, body_len);
                Some(pending)
            }) else {
                return;
            };
            self.write_echo_stream_inner(
                key.clone(),
                stream_id,
                operation_id,
                body,
                response,
                true,
            );
        }
    }

    fn close_echo_stream(&mut self, key: &SessionKey, stream_id: u64, operation_id: &str) -> bool {
        self.close_echo_stream_with_cause(key, stream_id, operation_id, None)
    }

    fn close_echo_stream_with_cause(
        &mut self,
        key: &SessionKey,
        stream_id: u64,
        operation_id: &str,
        cause: Option<StreamTerminalCause>,
    ) -> bool {
        // A consumer can disappear while its OPEN is still pending admission:
        // the public handler was dropped before the 101, the socket closed
        // before OPENED, or the unclaimed lease expired.  No sequenced frame
        // and no terminal result may exist for a stream the connector has not
        // admitted.  Keep the exact OPEN identity, stop the unclaimed-lease
        // path, and defer the real terminal transition until the owner proves
        // OPENED (a real FIN) or REJECTED (a no-stream FORGET).  The actor
        // tick fails the fenced session closed if neither arrives by the
        // admission deadline.  Repeated closes are idempotent here.
        if let Some(session) = self.session_mut(key) {
            let queue_budget = session.queue_budget.clone();
            if let Some(stream) = session.streams.get_mut(&stream_id)
                && stream.operation_id == operation_id
                && stream.open_pending
                && !stream.terminal
            {
                stream.registration_dropped = true;
                stream.admission_lease.cancel();
                if stream.deferred_terminal_cause.is_none() {
                    stream.deferred_terminal_cause = cause;
                }
                Self::release_echo_stream_state(stream, &queue_budget, false);
                return true;
            }
        }
        let disposition = {
            let Some(session) = self.session_mut(key) else {
                return true;
            };
            // The relay->connector writer is frozen at its immutable rotation
            // fence from QUIESCE until the candidate is activated (or the old
            // carrier resumes after a coordinated ABORTED); recovery freezes it
            // the same way.  docs/protocol.md "Freeze each writer".
            let writer_frozen = Self::rotation_frozen(session);
            {
                let Some(stream) = session.streams.get_mut(&stream_id) else {
                    return true;
                };
                if stream.operation_id != operation_id || stream.terminal {
                    return true;
                }
                // The public ingress also enforces the verified token deadline
                // and can close its peer stream before an in-flight
                // authorization refresh returns. Preserve the owner-held expiry
                // at this first terminal transition instead of losing it as a
                // generic close. An earlier explicit failure or terminal result
                // remains final.
                if stream.consumer_expires_at <= Utc::now()
                    && stream.authorization_failure_code.is_none()
                {
                    stream.authorization_failure_code = Some("AUTHORIZATION_EXPIRED");
                }
                if writer_frozen {
                    // Hold the terminal behind any deferred application
                    // records; it is emitted after activation with the
                    // continuing sequence, never on the frozen carrier.  This
                    // is bounded backpressure, not a publication failure.
                    stream.pending_terminal.get_or_insert(Terminal::Fin);
                }
            }
            if writer_frozen {
                TerminalDisposition::Deferred
            } else if Self::queue_stream_terminal_frame(session, stream_id, Terminal::Fin) {
                TerminalDisposition::Emitted
            } else {
                TerminalDisposition::Failed
            }
        };
        let fin_queued = !matches!(disposition, TerminalDisposition::Failed);
        if matches!(disposition, TerminalDisposition::Failed) {
            tracing::debug!(
                stream_id,
                operation_id = %operation_id,
                phase = "echo_terminal_without_fin",
                "echo close retained a terminal tombstone because the FIN was not queued"
            );
            // A terminal tombstone without an authenticated FIN cannot ever
            // satisfy owner_stream_forget_state. Start the same absolute
            // fail-closed window used by a blocked STREAM_FORGET so a closed
            // writer cannot retain the session indefinitely. The transactional
            // sequence above remains unchanged; no phantom FIN is published.
            // A *deferred* terminal is not a failure and arms no deadline.
            self.arm_terminal_fin_failure_deadline(key);
        }
        // Keep the exact stream sequence as a bounded terminal tombstone so
        // a valid late ACK/FIN cannot become UNKNOWN_STREAM and tear down an
        // unrelated sibling.  Terminal entries do not count against the
        // active admission ceiling, but the total retained table is capped at
        // RETAINED_ECHO_STREAM_FACTOR * max_streams_per_device.  Once that
        // bound is reached, admission returns STREAM_LIMIT until the
        // connector's StreamForget proof removes a tombstone; no identity is
        // silently evicted while late frames remain possible.
        let mut transitioned = false;
        if let Some(session) = self.session_mut(key) {
            let queue_budget = session.queue_budget.clone();
            if let Some(stream) = session.streams.get_mut(&stream_id)
                && stream.operation_id == operation_id
            {
                transitioned = !stream.terminal;
                stream.terminal = true;
                if !fin_queued {
                    stream.terminal_fin_failure = true;
                }
                Self::release_echo_stream_state(stream, &queue_budget, false);
            }
        }
        if transitioned
            && let Some(event) =
                self.stream_terminal_event(key, stream_id, operation_id, "STREAM_CLOSED", cause)
        {
            self.retain_stream_terminal_event(event);
        }
        true
    }

    /// Complete the relay-to-connector half of a connector terminal event.
    /// A peer FIN/RESET is a half-close until the relay publishes its own
    /// terminal frame; queue and sequence publication stay transactional so a
    /// full writer cannot create a phantom terminal cursor.
    fn queue_peer_terminal_reply(
        &mut self,
        key: &SessionKey,
        stream_id: u64,
        terminal: Terminal,
    ) -> bool {
        let queued = {
            let Some(session) = self.session_mut(key) else {
                return true;
            };
            // While the relay writer is frozen at its rotation fence, the
            // reply to a peer FIN/RESET is held (behind any deferred records)
            // and emitted after activation with the continuing sequence, never
            // on the frozen carrier.  docs/protocol.md "Freeze each writer".
            if Self::rotation_frozen(session) {
                if let Some(stream) = session.streams.get_mut(&stream_id) {
                    stream.pending_terminal.get_or_insert(terminal);
                }
                return true;
            }
            let queued = Self::queue_stream_terminal_frame(session, stream_id, terminal);
            if !queued && let Some(stream) = session.streams.get_mut(&stream_id) {
                stream.terminal_fin_failure = true;
            }
            queued
        };
        if !queued {
            self.arm_terminal_fin_failure_deadline(key);
        }
        queued
    }

    fn start_rotation(
        &mut self,
        key: &SessionKey,
        reply_to: Option<String>,
        reason: &str,
        request: Option<ControlMessage>,
    ) -> RotationStart {
        if self
            .session_for(key)
            .is_some_and(|session| session.cluster_profile)
        {
            return self.start_catalog_rotation(key, reply_to, reason, request);
        }
        self.start_rotation_local(key, reply_to, reason)
    }

    /// Map a refused pure-machine PREPARE to the start outcome.  History
    /// exhaustion has already closed the machine, so it is a typed session
    /// termination; every other refusal leaves the machine `Active`.
    fn rotation_prepare_failure(error: tunnel_protocol::rotation::RotationError) -> RotationStart {
        match error {
            tunnel_protocol::rotation::RotationError::ConnectionHistoryExhausted { .. } => {
                RotationStart::Failed(CONNECTION_HISTORY_EXHAUSTED)
            }
            _ => RotationStart::Rejected,
        }
    }

    fn start_catalog_rotation(
        &mut self,
        key: &SessionKey,
        reply_to: Option<String>,
        reason: &str,
        request: Option<ControlMessage>,
    ) -> RotationStart {
        let now_ms = monotonic_millis();
        let journal_bytes = self.options.limits.max_queue_bytes.min(4 * 1024 * 1024);
        let prepared = {
            let Some(session) = self.session_mut(key) else {
                return RotationStart::Rejected;
            };
            if !session.profile.supports_rotation()
                || session.data_tx.is_none()
                || session.rotation.as_ref().is_some_and(|rotation| {
                    !matches!(rotation.state.phase(), RotationPhase::Active)
                        || rotation.pending_ticket.is_some()
                })
            {
                return RotationStart::Rejected;
            }
            let Some(rotation) = session.rotation.as_mut() else {
                return RotationStart::Rejected;
            };
            if !Self::rotation_tombstone_capacity_available(rotation, now_ms) {
                return RotationStart::Rejected;
            }
            let overlap_ms = rotation.state.config().overlap_timeout_ms;
            let Some(new_generation) = rotation.state.generation_high_watermark().checked_add(1)
            else {
                return RotationStart::Rejected;
            };
            let attempt = RotationAttemptIdentity::new(
                session.key.session_id.clone(),
                session.key.epoch,
                runtime::owner_id(&session.owner),
                wire::random_token(),
                session.generation,
                new_generation,
                session.connection_id.clone(),
                wire::random_token(),
            );
            if let Err(error) = rotation.state.prepare(attempt.clone(), now_ms) {
                return Self::rotation_prepare_failure(error);
            }
            let journal_deadline = rotation.state.status().deadline_ms.unwrap_or(now_ms);
            let Ok(journal) = ControlJournal::new(128, journal_bytes, now_ms, journal_deadline)
            else {
                // The pure machine has already consumed this attempt; an
                // unjournaled attempt cannot be left `Preparing`.
                return RotationStart::Failed("ROTATION_PREPARE_INVALID");
            };
            rotation.journal = journal;
            rotation.attempt_deadline_ms = Some(journal_deadline);
            let catalog_purpose = "rotation-candidate".to_owned();
            let binding_digest = runtime::attachment_binding_digest(
                &session.owner,
                attempt.new_generation,
                &attempt.new_connection_id,
                &catalog_purpose,
            );
            rotation.pending_ticket = Some(PendingCatalogTicket {
                attempt: attempt.clone(),
                purpose: DataAttachmentPurpose::RotationCandidate,
                catalog_purpose,
                binding_digest,
                reply_to: reply_to.clone().unwrap_or_default(),
                request,
            });
            rotation.attempt = Some(attempt.clone());
            rotation.completed_rotation_diagnostics = None;
            rotation.snapshot_id.clear();
            rotation.old_connection_id = session.connection_id.clone();
            rotation.prepare_message_id.clear();
            rotation.last_message_id.clear();
            rotation.abort_message_id = None;
            rotation.peer_message_id = reply_to.unwrap_or_default();
            rotation.pending_abort_ack = None;
            Self::clear_phase_message_ids(rotation);
            rotation.remote_fences = [None, None];
            rotation.own_fence = None;
            (
                attempt,
                session.owner.clone(),
                session.identity.tenant_id,
                session.identity.spki_fingerprint.clone(),
                overlap_ms,
                session.control_tx.clone(),
                session.queue_budget.clone(),
            )
        };
        let (attempt, owner, tenant_id, spki, _overlap_ms, _control_tx, _budget) = prepared;
        let expires_at = Utc::now()
            + ChronoDuration::from_std(wire::TICKET_TTL)
                .unwrap_or_else(|_| ChronoDuration::seconds(10));
        let catalog = self.catalog.clone();
        let command_tx = self.command_tx.clone();
        let key_for_task = key.clone();
        let binding_digest = runtime::attachment_binding_digest(
            &owner,
            attempt.new_generation,
            &attempt.new_connection_id,
            "rotation-candidate",
        );
        let connection_id = attempt.new_connection_id.clone();
        let attempt_for_task = attempt.clone();
        let cancel = self.options.shutdown.clone();
        self.spawn_background(async move {
            let result = catalog
                .issue_attachment_ticket(&AttachmentTicketIssueRequest {
                    tenant_id,
                    device_id: key_for_task.device_id,
                    spki_fingerprint: spki,
                    owner,
                    generation: attempt_for_task.new_generation,
                    connection_id,
                    purpose: "rotation-candidate".to_owned(),
                    binding_digest,
                    expires_at,
                })
                .await
                .map_err(|error| error.to_string());
            send_background_command(
                &cancel,
                &command_tx,
                Command::CatalogTicketResolved {
                    key: key_for_task,
                    attempt: attempt_for_task,
                    result,
                },
            )
            .await;
        });
        tracing::info!(
            device_id = %key.device_id,
            session_id = %key.session_id,
            epoch = key.epoch,
            generation = attempt.new_generation,
            reason = %reason,
            phase = "rotation_ticket_pending",
        );
        RotationStart::Pending
    }

    fn start_rotation_local(
        &mut self,
        key: &SessionKey,
        reply_to: Option<String>,
        reason: &str,
    ) -> RotationStart {
        let now_ms = monotonic_millis();
        let journal_bytes = self.options.limits.max_queue_bytes.min(4 * 1024 * 1024);
        let (
            attempt,
            ticket,
            prepare_message_id,
            encoded,
            owner,
            spki,
            tenant_id,
            control_tx,
            budget,
        ) = {
            let Some(session) = self.session_mut(key) else {
                return RotationStart::Rejected;
            };
            if !session.profile.supports_rotation()
                || session.data_tx.is_none()
                || session.rotation.as_ref().is_some_and(|rotation| {
                    !matches!(rotation.state.phase(), RotationPhase::Active)
                })
            {
                return RotationStart::Rejected;
            }
            let Some(rotation) = session.rotation.as_mut() else {
                return RotationStart::Rejected;
            };
            if !Self::rotation_tombstone_capacity_available(rotation, now_ms) {
                return RotationStart::Rejected;
            }
            let overlap_ms = rotation.state.config().overlap_timeout_ms;
            let Some(new_generation) = rotation.state.generation_high_watermark().checked_add(1)
            else {
                return RotationStart::Rejected;
            };
            let rotation_id = wire::random_token();
            let new_connection_id = wire::random_token();
            let attempt = RotationAttemptIdentity::new(
                session.key.session_id.clone(),
                session.key.epoch,
                runtime::owner_id(&session.owner),
                rotation_id,
                session.generation,
                new_generation,
                session.connection_id.clone(),
                new_connection_id,
            );
            if let Err(error) = rotation.state.prepare(attempt.clone(), now_ms) {
                return Self::rotation_prepare_failure(error);
            }
            // From here on the pure machine has consumed this attempt.  Any
            // failure before PREPARE is queued must fail closed: returning
            // `Rejected` would strand an attempt-less `Preparing` machine
            // that only ROTATION_DEADLINE_EXPIRED could end.
            //
            // Journal retention belongs to this attempt, not to the session
            // admission instant.  A session may remain active past the
            // previous overlap deadline before its policy timer fires; using
            // that stale journal would silently drop the connector's phase
            // acknowledgements as expired.
            let journal_deadline = rotation.state.status().deadline_ms.unwrap_or(now_ms);
            let Ok(journal) = ControlJournal::new(128, journal_bytes, now_ms, journal_deadline)
            else {
                return RotationStart::Failed("ROTATION_PREPARE_INVALID");
            };
            rotation.journal = journal;
            rotation.attempt_deadline_ms = Some(journal_deadline);
            let ticket = wire::random_token();
            let prepare = wire::rotate_prepare(
                reply_to.as_deref().unwrap_or(""),
                attempt.clone(),
                tunnel_protocol::rotation_control::DataAttachmentPurpose::RotationCandidate,
                &ticket,
                overlap_ms,
            );
            let Ok(encoded) = wire::encode_control_message(&prepare) else {
                return RotationStart::Failed("ROTATION_PREPARE_INVALID");
            };
            let prepare_message_id = prepare.message_id().to_owned();
            (
                attempt,
                ticket,
                prepare_message_id,
                encoded,
                session.owner.clone(),
                session.identity.spki_fingerprint.clone(),
                session.identity.tenant_id,
                session.control_tx.clone(),
                session.queue_budget.clone(),
            )
        };
        let issued_at_wall = Utc::now();
        let expires_at_wall = issued_at_wall
            + ChronoDuration::from_std(wire::TICKET_TTL)
                .unwrap_or_else(|_| ChronoDuration::seconds(10));
        self.tickets.insert(
            ticket.clone(),
            Ticket {
                value: ticket.clone(),
                tenant_id,
                device_id: key.device_id,
                spki,
                session_id: key.session_id.clone(),
                epoch: key.epoch,
                generation: attempt.new_generation,
                welcome_message_id: prepare_message_id.clone(),
                connection_id: attempt.new_connection_id.clone(),
                issued_at_wall,
                expires_at_wall,
                expires_at: Instant::now() + wire::TICKET_TTL,
                consuming: false,
                owner,
                candidate: true,
                attachment_purpose: DataAttachmentPurpose::RotationCandidate,
                catalog_purpose: String::new(),
                binding_digest: String::new(),
                locator_digest: String::new(),
                catalog_backed: false,
            },
        );
        let journal_response = encoded.clone();
        if queue_control(&control_tx, &budget, encoded).is_err() {
            // The connector can never learn about this consumed attempt.
            // Fail closed with the same typed outcome as the catalog-ticket
            // path instead of leaving the machine `Preparing` without an
            // attempt the abort/deadline paths could act on.
            self.tickets.remove(&ticket);
            return RotationStart::Failed("ROTATION_PREPARE_QUEUE");
        }
        let new_generation = attempt.new_generation;
        if let Some(session) = self.session_mut(key)
            && let Some(rotation) = session.rotation.as_mut()
        {
            rotation.attempt = Some(attempt);
            rotation.completed_rotation_diagnostics = None;
            rotation.snapshot_id.clear();
            rotation.old_connection_id = session.connection_id.clone();
            rotation.prepare_message_id = prepare_message_id.clone();
            rotation.last_message_id = prepare_message_id.clone();
            rotation.abort_message_id = None;
            rotation.peer_message_id = reply_to.unwrap_or_default();
            rotation.pending_abort_ack = None;
            Self::clear_phase_message_ids(rotation);
            rotation.remote_fences = [None, None];
            rotation.own_fence = None;
        }
        tracing::info!(
            device_id = %key.device_id,
            session_id = %key.session_id,
            epoch = key.epoch,
            generation = new_generation,
            reason = %reason,
            phase = "rotation_prepare",
        );
        RotationStart::Started(journal_response)
    }

    /// Finish one asynchronous catalog ticket issue without holding the actor
    /// across the Redis await.  The prepare message and local expected
    /// binding are published together, so no candidate can be admitted with a
    /// ticket whose authoritative record has not been created.
    async fn finish_catalog_ticket(
        &mut self,
        key: &SessionKey,
        attempt: &RotationAttemptIdentity,
        result: Result<AttachmentTicket, String>,
    ) {
        let Some(pending) = self
            .session_for(key)
            .and_then(|session| session.rotation.as_ref())
            .and_then(|rotation| rotation.pending_ticket.as_ref())
            .filter(|pending| &pending.attempt == attempt)
            .cloned()
        else {
            // A recovery transition clears the pending catalog operation. A
            // late result belongs to that canceled attempt and must not
            // close or mutate the fresh recovery episode.
            return;
        };
        let ticket = match result {
            Ok(ticket) => ticket,
            Err(_) => {
                self.close_session(key, "ATTACHMENT_TICKET_UNAVAILABLE")
                    .await;
                return;
            }
        };
        let Some((owner, spki, tenant_id, control_tx, budget)) =
            self.session_for(key).map(|session| {
                (
                    session.owner.clone(),
                    session.identity.spki_fingerprint.clone(),
                    session.identity.tenant_id,
                    session.control_tx.clone(),
                    session.queue_budget.clone(),
                )
            })
        else {
            return;
        };
        let now = Utc::now();
        let remaining_ms = self
            .session_for(key)
            .and_then(|session| session.rotation.as_ref())
            .map(|rotation| {
                rotation
                    .state
                    .status()
                    .deadline_ms
                    .unwrap_or(monotonic_millis())
                    .saturating_sub(monotonic_millis())
            })
            .unwrap_or_default();
        if remaining_ms == 0 || ticket.expires_at <= now {
            self.close_session(key, "ATTACHMENT_TICKET_EXPIRED").await;
            return;
        }
        let prepare = wire::rotate_prepare(
            &pending.reply_to,
            attempt.clone(),
            pending.purpose.clone(),
            &ticket.ticket,
            remaining_ms,
        );
        let Ok(encoded) = wire::encode_control_message(&prepare) else {
            self.close_session(key, "ROTATION_PREPARE_INVALID").await;
            return;
        };
        let prepare_id = prepare.message_id().to_owned();
        let expires_at = ticket.expires_at;
        let expires_in = (expires_at - now)
            .to_std()
            .unwrap_or(wire::TICKET_TTL)
            .min(wire::TICKET_TTL);
        let expected = Ticket {
            value: ticket.ticket.clone(),
            tenant_id,
            device_id: key.device_id,
            spki,
            session_id: key.session_id.clone(),
            epoch: key.epoch,
            generation: attempt.new_generation,
            welcome_message_id: prepare_id.clone(),
            connection_id: attempt.new_connection_id.clone(),
            issued_at_wall: now,
            expires_at_wall: expires_at,
            expires_at: Instant::now() + expires_in,
            consuming: false,
            owner,
            candidate: true,
            attachment_purpose: pending.purpose.clone(),
            catalog_purpose: pending.catalog_purpose.clone(),
            binding_digest: pending.binding_digest.clone(),
            locator_digest: ticket.locator.digest,
            catalog_backed: true,
        };
        self.tickets.insert(expected.value.clone(), expected);
        if queue_control(&control_tx, &budget, encoded.clone()).is_err() {
            self.tickets.remove(&ticket.ticket);
            self.close_session(key, "ROTATION_PREPARE_QUEUE").await;
            return;
        }
        let mut journal_error = None;
        if let Some(session) = self.session_mut(key)
            && let Some(rotation) = session.rotation.as_mut()
        {
            rotation.pending_ticket = None;
            rotation.prepare_message_id = prepare_id.clone();
            rotation.last_message_id = prepare_id;
            if pending.request.is_none()
                && Self::complete_rotation_reply(rotation, &prepare, &encoded).is_err()
            {
                journal_error = Some("ROTATION_JOURNAL_PREPARE");
            }
        }
        if journal_error.is_none()
            && let Some(request) = pending.request
            && let Err(error) = self.record_rotation_request_response(key, &request, &encoded)
        {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                stage = "rotation_journal_complete_request",
                error = %error,
            );
            journal_error = Some("ROTATION_JOURNAL_REQUEST");
        }
        if let Some(reason) = journal_error {
            self.protocol_failure(key, reason).await;
        }
    }

    /// Start the coordinator-owned retained recovery episode after a physical
    /// data carrier disappears.  The pure rotation state is advanced before a
    /// control message is queued: the old carrier is released with explicit
    /// closure evidence, the immutable roster is captured, and one fresh
    /// generation/connection identity is reserved for this episode.
    fn begin_recovery_after_loss(&mut self, key: &SessionKey, old_connection_id: &str) -> bool {
        let now_ms = monotonic_millis();
        let maximum_streams = self.options.limits.max_streams_per_device.min(128);
        let journal_bytes = self.options.limits.max_queue_bytes.min(4 * 1024 * 1024);
        let prepared = {
            let Some(session) = self.session_mut(key) else {
                return false;
            };
            if !session.profile.supports_rotation() || session.data_tx.is_some() {
                return false;
            }
            let Some(rotation) = session.rotation.as_mut() else {
                return false;
            };
            if !Self::rotation_tombstone_capacity_available(rotation, now_ms) {
                return false;
            }
            // A PREPARING attempt can be coalesced into recovery after the
            // old carrier disappears: if PREPARE was already queued, its
            // candidate identity is carried in the closure roster below so
            // the connector cannot leave a phantom candidate behind.
            let pending_rotation_attempt = if rotation.state.phase() == RotationPhase::Preparing
                && rotation.candidate.is_none()
            {
                rotation.attempt.clone()
            } else {
                None
            };
            let canceled_prepare_was_queued =
                pending_rotation_attempt.is_some() && !rotation.prepare_message_id.is_empty();
            // protocol.md, "Abort, deadline and loss during handover": "Old
            // transport fails before drain completes: do not declare a
            // successful drain or discard an unacknowledged prefix. Close
            // failed/candidate transports as needed to preserve the socket
            // bound and enter retained-state recovery with a fresh greater
            // generation. The original overlap deadline still retires the
            // abandoned attempt."  The attached candidate of an uncommitted
            // attempt is therefore released here rather than failing the
            // session closed, which also retires the abandoned attempt
            // immediately, well inside its original overlap deadline.  The
            // commit-uncertain rule is unchanged: COMMITTING has not accepted a
            // commit, so the episode anchors on the retained old generation and
            // allocates a fresh greater one instead of resuming either carrier.
            // ABORTING keeps its bilateral closure protocol and stays
            // fail-closed rather than letting RECOVERY_BEGIN overtake an
            // in-flight ROTATE_ABORT.
            let abandoned_rotation_attempt = if matches!(
                rotation.state.phase(),
                RotationPhase::Quiescing | RotationPhase::Draining | RotationPhase::Committing
            ) {
                rotation.attempt.clone()
            } else {
                None
            };
            let released_attempt = pending_rotation_attempt
                .as_ref()
                .or(abandoned_rotation_attempt.as_ref());
            let canceled_candidate_connection_id = released_attempt
                .filter(|_| canceled_prepare_was_queued || abandoned_rotation_attempt.is_some())
                .map(|attempt| attempt.new_connection_id.clone());
            let active_rotation = rotation.state.phase() == RotationPhase::Active;
            if !active_rotation && released_attempt.is_none() {
                return false;
            }
            if rotation.state.active_connection_id() != old_connection_id {
                return false;
            }
            let mut stream_ids: Vec<u64> = session.streams.keys().copied().collect();
            stream_ids.sort_unstable();
            if stream_ids.len() > maximum_streams {
                return false;
            }
            let snapshot_id = wire::random_token();
            let roster = StreamRoster::new(snapshot_id.clone(), stream_ids);
            let Some(new_generation) = rotation.state.generation_high_watermark().checked_add(1)
            else {
                return false;
            };
            let old_generation =
                released_attempt.map_or(session.generation, |attempt| attempt.old_generation);
            let attempt = RotationAttemptIdentity::new(
                session.key.session_id.clone(),
                session.key.epoch,
                runtime::owner_id(&session.owner),
                wire::random_token(),
                old_generation,
                new_generation,
                old_connection_id.to_owned(),
                wire::random_token(),
            );
            let Some(episode_deadline_ms) =
                now_ms.checked_add(rotation.state.config().recovery_timeout_ms)
            else {
                return false;
            };
            let transport_attempt = released_attempt.unwrap_or(&attempt);
            // Release the abandoned attempt's candidate transport before the
            // episode starts so the session is back inside the documented
            // one-control/one-candidate shape.  A failure below closes the
            // session, which releases the carrier anyway.
            if abandoned_rotation_attempt.is_some()
                && let Some(candidate) = rotation.candidate.take()
            {
                let _ = candidate.tx.try_send(DataOutbound::Close);
            }
            if rotation
                .state
                .transport_lost(transport_attempt, now_ms, RecoveryReason::OldTransportLost)
                .is_err()
                || rotation
                    .state
                    .close_for_recovery(
                        old_connection_id,
                        ClosureEvidence::closed(old_connection_id),
                        now_ms,
                    )
                    .is_err()
                || released_attempt.is_some_and(|released| {
                    rotation
                        .state
                        .close_for_recovery(
                            &released.new_connection_id,
                            ClosureEvidence::closed(released.new_connection_id.clone()),
                            now_ms,
                        )
                        .is_err()
                })
                || rotation
                    .state
                    .begin_recovery(
                        attempt.clone(),
                        roster.clone(),
                        now_ms,
                        RecoveryReason::OldTransportLost,
                        episode_deadline_ms,
                    )
                    .is_err()
            {
                return false;
            }
            let begin = wire::recovery_begin(
                "",
                attempt.clone(),
                &snapshot_id,
                1,
                roster.clone(),
                episode_deadline_ms.saturating_sub(now_ms),
            );
            let begin_id = begin.message_id().to_owned();
            let mut closed_connection_ids = vec![old_connection_id.to_owned()];
            if let Some(connection_id) = canceled_candidate_connection_id {
                closed_connection_ids.push(connection_id);
            }
            closed_connection_ids.sort_unstable();
            let mut local_closed = RecoveryClosed {
                message_id: wire::random_token(),
                reply_to: begin_id.clone(),
                attempt: attempt.clone(),
                episode_id: snapshot_id.clone(),
                attempt_no: 1,
                closed_connection_ids,
                closure_digest: String::new(),
            };
            let Ok(local_digest) = local_closed.closure_digest_for(RecoverySide::Relay) else {
                return false;
            };
            local_closed.closure_digest = local_digest;
            let closed = wire::recovery_closed(
                &begin_id,
                attempt.clone(),
                &snapshot_id,
                1,
                local_closed.closed_connection_ids.clone(),
                &local_closed.closure_digest,
            );
            let Ok(begin) = wire::encode_control_message(&begin) else {
                return false;
            };
            let Ok(closed) = wire::encode_control_message(&closed) else {
                return false;
            };
            rotation.attempt = Some(attempt);
            rotation.completed_rotation_diagnostics = None;
            rotation.snapshot_id = snapshot_id;
            rotation.prepare_message_id = begin_id.clone();
            rotation.last_message_id = begin_id;
            rotation.abort_message_id = None;
            rotation.peer_message_id.clear();
            rotation.pending_abort_ack = None;
            Self::clear_phase_message_ids(rotation);
            rotation.remote_fences = [None, None];
            rotation.own_fence = None;
            rotation.barrier_rx = None;
            rotation.candidate = None;
            rotation.pending_ticket = None;
            rotation.recovery = Some(RecoveryRuntime {
                episode_id: local_closed.episode_id.clone(),
                attempt_no: 1,
                episode_deadline_ms,
                roster,
                expected_closed_connection_ids: local_closed.closed_connection_ids.clone(),
                local_closed: Some(local_closed.clone()),
                peer_closed: None,
                closure_digest: Some(local_closed.closure_digest.clone()),
                candidate_ready: false,
                resume_message_ids: [None, None],
                snapshot_reply_ids: [None, None],
                local_snapshots: [Vec::new(), Vec::new()],
                ready_snapshots: [Vec::new(), Vec::new()],
                ready_message_ids: [None, None],
                remote_snapshots: [HashMap::new(), HashMap::new()],
                ready_remote_snapshots: [HashMap::new(), HashMap::new()],
                remote_ready: [false, false],
                local_plans: HashMap::new(),
                ready_sent: [false, false],
                deferred_frames: VecDeque::new(),
                deferred_bytes: 0,
                activated: false,
                retry_not_before_ms: None,
                retry_failed_connection_id: None,
            });
            // Recovery has its own immutable retention window.  This journal
            // cannot silently inherit an expired overlap deadline.
            if let Ok(journal) =
                ControlJournal::new(128, journal_bytes, now_ms, episode_deadline_ms)
            {
                rotation.journal = journal;
                rotation.attempt_deadline_ms = Some(episode_deadline_ms);
            }
            Some((
                session.control_tx.clone(),
                session.queue_budget.clone(),
                begin,
                closed,
                pending_rotation_attempt.or(abandoned_rotation_attempt),
            ))
        };
        let Some((control_tx, budget, begin, closed, canceled_attempt)) = prepared else {
            return false;
        };
        if let Some(canceled_attempt) = canceled_attempt {
            self.tickets.retain(|_, ticket| {
                !(ticket.tenant_id == key.tenant_id
                    && ticket.device_id == key.device_id
                    && ticket.session_id == key.session_id
                    && ticket.epoch == key.epoch
                    && ticket.generation == canceled_attempt.new_generation
                    && ticket.connection_id == canceled_attempt.new_connection_id
                    && ticket.candidate)
            });
        }
        queue_control(&control_tx, &budget, begin).is_ok()
            && queue_control(&control_tx, &budget, closed).is_ok()
    }

    fn recovery_remaining_ms(rotation: &RotationRuntime, now_ms: u64) -> u64 {
        rotation
            .state
            .status()
            .deadline_ms
            .unwrap_or(now_ms)
            .saturating_sub(now_ms)
    }

    fn recovery_local_entries(
        session: &DeviceSession,
        roster: &StreamRoster,
        direction: Direction,
    ) -> Result<Vec<ResumeDirectionState>, RelayError> {
        let mut entries = Vec::with_capacity(roster.stream_ids.len());
        for stream_id in &roster.stream_ids {
            let Some(stream) = session.streams.get(stream_id) else {
                return Err(RelayError::Conflict(
                    "recovery roster stream is unavailable",
                ));
            };
            let snapshot = stream.sequence.snapshot();
            let entry = ResumeDirectionState::from_sequence_snapshot(
                *stream_id,
                snapshot.direction(direction),
            )
            .map_err(|error| RelayError::Protocol(error.to_string()))?;
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Arm the coordinator-owned delay after a recovery candidate disappears.
    /// The initial RECOVERY_BEGIN path remains immediate; only a failed
    /// candidate attempt is paced. The failed identity is retained until the
    /// delayed retry proves it is still the same authenticated episode.
    fn schedule_recovery_retry(
        &mut self,
        key: &SessionKey,
        failed_connection_id: &str,
    ) -> Option<u64> {
        let now_ms = monotonic_millis();
        let delay_ms = {
            let session = self.session_mut(key)?;
            let rotation = session.rotation.as_mut()?;
            if rotation.state.phase() != RotationPhase::Recovering {
                return None;
            }
            let attempt = rotation.attempt.as_ref()?;
            if attempt.new_connection_id != failed_connection_id {
                return None;
            }
            let recovery = rotation.recovery.as_mut()?;
            if !recovery.candidate_ready
                || recovery.retry_not_before_ms.is_some()
                || recovery.retry_failed_connection_id.is_some()
            {
                return None;
            }
            let delay_ms = recovery_retry_delay_ms(recovery.attempt_no)?;
            let not_before_ms = now_ms.checked_add(delay_ms)?;
            recovery.retry_not_before_ms = Some(not_before_ms);
            recovery.retry_failed_connection_id = Some(failed_connection_id.to_owned());
            delay_ms
        };
        self.spawn_recovery_retry_timer(key.clone(), delay_ms);
        Some(delay_ms)
    }

    /// Keep the short retry timer owned by the actor's JoinSet. A timer that
    /// fires after session cleanup only sends an ignored command; it never
    /// retains a session or allocates a replacement carrier by itself.
    fn spawn_recovery_retry_timer(&mut self, key: SessionKey, delay_ms: u64) {
        let command_tx = self.command_tx.clone();
        let shutdown = self.options.shutdown.clone();
        self.spawn_background(async move {
            tokio::select! {
                _ = shutdown.cancelled() => {}
                _ = tokio::time::sleep(Duration::from_millis(delay_ms)) => {
                    tokio::select! {
                        _ = shutdown.cancelled() => {}
                        _ = command_tx.send(Command::RetryRecovery { key }) => {}
                    }
                }
            }
        });
    }

    fn dispatch_recovery_retry(&mut self, key: &SessionKey) -> RecoveryRetryDispatch {
        let Some((not_before_ms, failed_connection_id, episode_deadline_ms)) = self
            .session_for(key)
            .and_then(|session| session.rotation.as_ref())
            .and_then(|rotation| rotation.recovery.as_ref())
            .and_then(|recovery| {
                Some((
                    recovery.retry_not_before_ms?,
                    recovery.retry_failed_connection_id.clone()?,
                    recovery.episode_deadline_ms,
                ))
            })
        else {
            return RecoveryRetryDispatch::NotPending;
        };
        let now_ms = monotonic_millis();
        if now_ms < not_before_ms {
            self.spawn_recovery_retry_timer(key.clone(), not_before_ms - now_ms);
            return RecoveryRetryDispatch::Rescheduled;
        }
        if now_ms >= episode_deadline_ms {
            return RecoveryRetryDispatch::DeadlineExpired;
        }
        if let Some(session) = self.session_mut(key)
            && let Some(rotation) = session.rotation.as_mut()
            && let Some(recovery) = rotation.recovery.as_mut()
        {
            recovery.retry_not_before_ms = None;
            recovery.retry_failed_connection_id = None;
        } else {
            return RecoveryRetryDispatch::NotPending;
        }
        if self.retry_recovery_after_candidate_loss(key, &failed_connection_id) {
            RecoveryRetryDispatch::Started
        } else {
            RecoveryRetryDispatch::Failed
        }
    }

    async fn handle_recovery_retry(&mut self, key: SessionKey) {
        match self.dispatch_recovery_retry(&key) {
            RecoveryRetryDispatch::Started
            | RecoveryRetryDispatch::Rescheduled
            | RecoveryRetryDispatch::NotPending => {}
            RecoveryRetryDispatch::DeadlineExpired => {
                self.close_session(&key, "ROTATION_DEADLINE_EXPIRED").await;
            }
            RecoveryRetryDispatch::Failed => {
                self.close_session(&key, "RECOVERY_CANDIDATE_FAILED").await;
            }
        }
    }

    /// Consume one physical recovery candidate and start the next attempt
    /// under the same absolute episode deadline.  The old logical carrier ID
    /// remains the recovery anchor while every candidate gets a fresh ID and
    /// generation. Each retry attests only the newly released candidate;
    /// earlier IDs remain fenced in the pure state and are already covered by
    /// the preceding authenticated closure pair.
    fn retry_recovery_after_candidate_loss(
        &mut self,
        key: &SessionKey,
        failed_connection_id: &str,
    ) -> bool {
        let now_ms = monotonic_millis();
        let journal_bytes = self.options.limits.max_queue_bytes.min(4 * 1024 * 1024);
        let prepared = {
            let Some(session) = self.session_mut(key) else {
                return false;
            };
            let Some(rotation) = session.rotation.as_mut() else {
                return false;
            };
            if !Self::rotation_tombstone_capacity_available(rotation, now_ms) {
                return false;
            }
            let Some(previous_attempt) = rotation.attempt.clone() else {
                return false;
            };
            let Some(previous_recovery) = rotation.recovery.as_ref() else {
                return false;
            };
            if rotation.state.phase() != RotationPhase::Recovering
                || !previous_recovery.candidate_ready
                || previous_attempt.new_connection_id != failed_connection_id
            {
                return false;
            }
            let previous_episode_id = previous_recovery.episode_id.clone();
            let previous_attempt_no = previous_recovery.attempt_no;
            let previous_deadline = previous_recovery.episode_deadline_ms;
            let roster = previous_recovery.roster.clone();
            // RECOVERY_CLOSED attests the carriers that became unallocated
            // since the preceding authenticated closure record. Historical
            // IDs remain fenced in RotationState's bounded connection
            // history, but repeating them would exceed the wire's two-entry
            // physical closure bound before attempt three.
            let expected = vec![failed_connection_id.to_owned()];
            if rotation
                .state
                .close_for_recovery(
                    failed_connection_id,
                    ClosureEvidence::closed(failed_connection_id),
                    now_ms,
                )
                .is_err()
            {
                return false;
            }
            let Some(new_generation) = rotation.state.generation_high_watermark().checked_add(1)
            else {
                return false;
            };
            let Some(attempt_no) = previous_attempt_no.checked_add(1) else {
                return false;
            };
            if attempt_no > 3 {
                return false;
            }
            let attempt = RotationAttemptIdentity::new(
                session.key.session_id.clone(),
                session.key.epoch,
                runtime::owner_id(&session.owner),
                wire::random_token(),
                previous_attempt.old_generation,
                new_generation,
                previous_attempt.old_connection_id.clone(),
                wire::random_token(),
            );
            if rotation
                .state
                .begin_recovery(
                    attempt.clone(),
                    roster.clone(),
                    now_ms,
                    RecoveryReason::CandidateTransportLost,
                    previous_deadline,
                )
                .is_err()
            {
                return false;
            }
            let begin = wire::recovery_begin(
                "",
                attempt.clone(),
                &previous_episode_id,
                attempt_no,
                roster.clone(),
                previous_deadline.saturating_sub(now_ms),
            );
            let begin_id = begin.message_id().to_owned();
            let mut local_closed = RecoveryClosed {
                message_id: wire::random_token(),
                reply_to: begin_id.clone(),
                attempt: attempt.clone(),
                episode_id: previous_episode_id.clone(),
                attempt_no,
                closed_connection_ids: expected.clone(),
                closure_digest: String::new(),
            };
            let Ok(digest) = local_closed.closure_digest_for(RecoverySide::Relay) else {
                return false;
            };
            local_closed.closure_digest = digest;
            let closed = wire::recovery_closed(
                &begin_id,
                attempt.clone(),
                &previous_episode_id,
                attempt_no,
                expected.clone(),
                &local_closed.closure_digest,
            );
            let Ok(begin) = wire::encode_control_message(&begin) else {
                return false;
            };
            let Ok(closed) = wire::encode_control_message(&closed) else {
                return false;
            };
            rotation.attempt = Some(attempt);
            rotation.completed_rotation_diagnostics = None;
            rotation.candidate = None;
            rotation.prepare_message_id = begin_id.clone();
            rotation.last_message_id = begin_id;
            rotation.abort_message_id = None;
            rotation.peer_message_id.clear();
            rotation.pending_abort_ack = None;
            Self::clear_phase_message_ids(rotation);
            rotation.snapshot_id = roster.snapshot_id.clone();
            rotation.recovery = Some(RecoveryRuntime {
                episode_id: previous_episode_id,
                attempt_no,
                episode_deadline_ms: previous_deadline,
                roster,
                expected_closed_connection_ids: expected,
                local_closed: Some(local_closed),
                peer_closed: None,
                closure_digest: None,
                candidate_ready: false,
                resume_message_ids: [None, None],
                snapshot_reply_ids: [None, None],
                local_snapshots: [Vec::new(), Vec::new()],
                ready_snapshots: [Vec::new(), Vec::new()],
                ready_message_ids: [None, None],
                remote_snapshots: [HashMap::new(), HashMap::new()],
                ready_remote_snapshots: [HashMap::new(), HashMap::new()],
                remote_ready: [false, false],
                local_plans: HashMap::new(),
                ready_sent: [false, false],
                deferred_frames: VecDeque::new(),
                deferred_bytes: 0,
                activated: false,
                retry_not_before_ms: None,
                retry_failed_connection_id: None,
            });
            if let Ok(journal) = ControlJournal::new(128, journal_bytes, now_ms, previous_deadline)
            {
                rotation.journal = journal;
                rotation.attempt_deadline_ms = Some(previous_deadline);
            }
            Some((
                session.control_tx.clone(),
                session.queue_budget.clone(),
                begin,
                closed,
            ))
        };
        let Some((control_tx, budget, begin, closed)) = prepared else {
            return false;
        };
        queue_control(&control_tx, &budget, begin).is_ok()
            && queue_control(&control_tx, &budget, closed).is_ok()
    }

    fn begin_rotation_quiesce(&mut self, key: &SessionKey) {
        // FORGET shares the authenticated control FIFO with QUIESCE. If the
        // queue is full, leave the terminal entry in the roster and retry.
        if !self.flush_owner_stream_forgets(key) {
            return;
        }
        let maximum_streams = self.options.limits.max_streams_per_device.min(128);
        let (quiesce, active_tx, prepared_state) = {
            let Some(session) = self.session_for(key) else {
                return;
            };
            let Some(rotation) = session.rotation.as_ref() else {
                return;
            };
            let Some(attempt) = rotation.attempt.clone() else {
                return;
            };
            if !matches!(rotation.state.phase(), RotationPhase::Preparing) {
                return;
            }
            if !rotation.quiesce_message_id.is_empty() || rotation.barrier_rx.is_some() {
                return;
            }
            let mut stream_ids: Vec<u64> = session
                .pending
                .keys()
                .chain(session.streams.keys())
                .copied()
                .collect();
            stream_ids.sort_unstable();
            stream_ids.dedup();
            if stream_ids.len() > maximum_streams {
                return;
            }
            let snapshot_id = wire::random_token();
            let roster = StreamRoster::new(snapshot_id.clone(), stream_ids);
            let now_ms = monotonic_millis();
            let mut prepared_state = rotation.state.clone();
            if prepared_state
                .quiesce(&attempt, roster.clone(), now_ms)
                .is_err()
            {
                return;
            }
            let remaining_ms = rotation
                .state
                .status()
                .deadline_ms
                .unwrap_or(now_ms)
                .saturating_sub(now_ms);
            let quiesce = wire::rotate_quiesce(
                &rotation.prepare_message_id,
                attempt.clone(),
                roster.clone(),
                remaining_ms,
            );
            let Some(active) = session.active_carrier.as_ref() else {
                return;
            };
            (quiesce, active.tx.clone(), prepared_state)
        };
        let Ok(encoded) = wire::encode_control_message(&quiesce) else {
            return;
        };
        let Some(session) = self.session_mut(key) else {
            return;
        };
        if session.rotation.is_none() {
            return;
        }
        let budget = session.queue_budget.clone();
        if !budget.reserve(encoded.len()) {
            return;
        }
        let control_permit = match session.control_tx.try_reserve() {
            Ok(permit) => permit,
            Err(_) => {
                budget.release(encoded.len());
                return;
            }
        };
        let barrier_permit = match active_tx.try_reserve() {
            Ok(permit) => permit,
            Err(_) => {
                budget.release(encoded.len());
                return;
            }
        };
        let (barrier_tx, barrier_rx) = oneshot::channel();
        control_permit.send(ControlOutbound::Text(QueuedText::new(
            encoded,
            budget.clone(),
        )));
        barrier_permit.send(DataOutbound::Barrier(barrier_tx));
        let Some(rotation) = session.rotation.as_mut() else {
            return;
        };
        rotation.state = prepared_state;
        if let ControlMessage::RotateQuiesce(ref value) = quiesce {
            rotation.snapshot_id = value.roster.snapshot_id.clone();
        }
        rotation.last_message_id = quiesce.message_id().to_owned();
        rotation.quiesce_message_id = quiesce.message_id().to_owned();
        rotation.frozen_message_id.clear();
        rotation.commit_message_id.clear();
        rotation.retire_message_id.clear();
        rotation.barrier_rx = Some(barrier_rx);
    }

    /// Poll the one in-flight writer barrier from the actor loop.  The
    /// channel is bounded to one receiver per rotation attempt, and the
    /// absolute attempt deadline is checked on every maintenance tick.
    fn poll_rotation_barrier(&mut self, key: &SessionKey) {
        let mut ready = false;
        let mut expired = false;
        {
            let Some(session) = self.session_mut(key) else {
                return;
            };
            let Some(rotation) = session.rotation.as_mut() else {
                return;
            };
            let Some(result) = rotation
                .barrier_rx
                .as_mut()
                .map(|receiver| receiver.try_recv())
            else {
                return;
            };
            match result {
                Ok(()) => {
                    ready = true;
                    rotation.barrier_rx = None;
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {
                    if rotation
                        .state
                        .status()
                        .deadline_ms
                        .is_some_and(|deadline| monotonic_millis() >= deadline)
                    {
                        expired = true;
                        rotation.barrier_rx = None;
                        let _ = rotation.state.tick(monotonic_millis());
                    }
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                    expired = true;
                    rotation.barrier_rx = None;
                    let _ = rotation.state.tick(monotonic_millis());
                }
            }
        }
        if !ready || expired {
            return;
        }
        let Some((attempt, carrier)) = self.session_for(key).and_then(|session| {
            let attempt = session
                .rotation
                .as_ref()
                .and_then(|rotation| rotation.attempt.clone())?;
            let active = session.active_carrier.as_ref()?;
            Some((
                attempt,
                CarrierKey {
                    session: key.clone(),
                    generation: active.context.generation,
                    connection_id: active.context.connection_id.clone(),
                },
            ))
        }) else {
            return;
        };
        self.finish_rotation_barrier(key, &attempt, &carrier);
    }

    fn finish_rotation_barrier(
        &mut self,
        key: &SessionKey,
        attempt: &RotationAttemptIdentity,
        carrier: &CarrierKey,
    ) {
        let Some(session) = self.session_for(key) else {
            return;
        };
        let Some(rotation) = session.rotation.as_ref() else {
            return;
        };
        if rotation.attempt.as_ref() != Some(attempt)
            || !session.active_carrier.as_ref().is_some_and(|active| {
                active.context.generation == carrier.generation
                    && active.context.connection_id == carrier.connection_id
            })
        {
            return;
        }
        let snapshot =
            Self::build_fence_snapshot(session, &rotation.snapshot_id, Direction::RelayToConnector);
        if let Err(error) = self.with_rotation_mut(key, |_session, rotation| {
            rotation.state.frozen(
                attempt,
                snapshot.clone(),
                Direction::RelayToConnector,
                monotonic_millis(),
            )?;
            rotation.own_fence = Some(snapshot.clone());
            Ok::<(), tunnel_protocol::rotation::RotationError>(())
        }) {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                phase = ?self
                    .session_for(key)
                    .and_then(|session| session.rotation.as_ref())
                    .map(|rotation| rotation.state.phase()),
                stage = "relay_frozen",
                error = %error,
            );
            return;
        }
        if let Err(error) = self.progress_rotation_drain(key) {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                phase = ?self
                    .session_for(key)
                    .and_then(|session| session.rotation.as_ref())
                    .map(|rotation| rotation.state.phase()),
                stage = "drain_progress_after_barrier",
                error = %error,
            );
        }
    }

    /// Re-evaluate the coordinator's drain proof and commit decision after
    /// every fence, barrier, ACK, and data-delivery event.  Control messages
    /// can cross the writer barrier, so a single FROZEN or DRAINED callback
    /// cannot be the only place that attempts the next phase.
    fn progress_rotation_drain(
        &mut self,
        key: &SessionKey,
    ) -> Result<(), tunnel_protocol::rotation::RotationError> {
        if self
            .session_for(key)
            .is_none_or(|session| session.rotation.is_none())
        {
            return Ok(());
        }
        self.with_rotation_mut(key, |session, rotation| {
            let status = rotation.state.status();
            if status.phase == RotationPhase::Draining && rotation.frozen_message_id.is_empty() {
                let source = rotation.peer_message_id.clone();
                if source.is_empty() {
                    return Err(tunnel_protocol::rotation::RotationError::MissingAttempt);
                }
                let attempt = rotation
                    .attempt
                    .clone()
                    .ok_or(tunnel_protocol::rotation::RotationError::MissingAttempt)?;
                let snapshot = rotation.own_fence.clone().ok_or(
                    tunnel_protocol::rotation::RotationError::MissingFrozenFence {
                        direction: Direction::RelayToConnector,
                    },
                )?;
                let message = wire::rotate_frozen(&source, attempt, snapshot);
                let encoded = wire::encode_control_message(&message)
                    .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
                Self::complete_rotation_reply(rotation, &message, &encoded)
                    .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
                queue_control(&session.control_tx, &session.queue_budget, encoded)
                    .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
                rotation.frozen_message_id = message.message_id().to_owned();
                rotation.last_message_id = message.message_id().to_owned();
            }
            if status.phase == RotationPhase::Draining
                && !status.drain_proofs[direction_index(Direction::ConnectorToRelay)]
            {
                let direction = Direction::ConnectorToRelay;
                let Some(fences) = rotation.remote_fences[direction_index(direction)].clone()
                else {
                    return Ok::<(), tunnel_protocol::rotation::RotationError>(());
                };
                let fence_digest = fences.digest().map_err(|_| {
                    tunnel_protocol::rotation::RotationError::FenceDigestUnavailable
                })?;
                let mut acks = Vec::with_capacity(fences.entries.len());
                for fence in &fences.entries {
                    let acknowledged = session
                        .streams
                        .get(&fence.stream_id)
                        .map(|stream| {
                            stream
                                .sequence
                                .direction(Direction::ConnectorToRelay)
                                .recv_contiguous()
                        })
                        .or_else(|| {
                            session
                                .pending
                                .get(&fence.stream_id)
                                .map(|pending| pending.response_sequence)
                        })
                        .unwrap_or_default();
                    acks.push(tunnel_protocol::rotation_control::StreamAck::new(
                        fence.stream_id,
                        acknowledged,
                    ));
                }
                let proof =
                    DrainProof::new(rotation.snapshot_id.clone(), fence_digest, direction, acks);
                let attempt = rotation
                    .attempt
                    .clone()
                    .ok_or(tunnel_protocol::rotation::RotationError::MissingAttempt)?;
                rotation
                    .state
                    .drained(&attempt, proof.clone(), monotonic_millis())?;
                // The connector's DRAINED may arrive before the relay has
                // observed enough ACK progress for its own proof. That
                // inbound message updates `peer_message_id`, but this
                // DRAINED must reply to the connector's immutable FROZEN
                // message. Use the phase-pinned ID so a crossed DRAINED
                // cannot make the next retry fail client correlation.
                let source = rotation
                    .peer_frozen_message_id
                    .clone()
                    .ok_or(tunnel_protocol::rotation::RotationError::MissingAttempt)?;
                let message = wire::rotate_drained(&source, attempt, proof);
                let encoded = wire::encode_control_message(&message)
                    .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
                Self::complete_rotation_reply(rotation, &message, &encoded)
                    .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
                queue_control(&session.control_tx, &session.queue_budget, encoded)
                    .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
                rotation.last_message_id = message.message_id().to_owned();
            }

            let status = rotation.state.status();
            if status.phase == RotationPhase::Committing && !status.commit_sent {
                let attempt = rotation
                    .attempt
                    .clone()
                    .ok_or(tunnel_protocol::rotation::RotationError::MissingAttempt)?;
                let drain_set = rotation.state.drain_set(&attempt)?;
                rotation.state.commit(&attempt, monotonic_millis())?;
                let status_after_commit = rotation.state.status();
                rotation.completed_rotation_diagnostics = Self::rotation_diagnostics_for(
                    rotation,
                    &status_after_commit,
                    Some(&drain_set),
                );
                let refs = vec![
                    DrainProofRef {
                        snapshot_id: drain_set.relay_to_connector.snapshot_id.clone(),
                        fence_digest: drain_set.relay_to_connector.fence_digest.clone(),
                        direction: Direction::RelayToConnector,
                    },
                    DrainProofRef {
                        snapshot_id: drain_set.connector_to_relay.snapshot_id.clone(),
                        fence_digest: drain_set.connector_to_relay.fence_digest.clone(),
                        direction: Direction::ConnectorToRelay,
                    },
                ];
                let source = rotation.peer_message_id.clone();
                if source.is_empty() {
                    return Err(tunnel_protocol::rotation::RotationError::MissingAttempt);
                }
                let message = wire::rotate_commit(&source, attempt, &rotation.snapshot_id, refs);
                let encoded = wire::encode_control_message(&message)
                    .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
                Self::complete_rotation_reply(rotation, &message, &encoded)
                    .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
                queue_control(&session.control_tx, &session.queue_budget, encoded)
                    .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
                rotation.commit_message_id = message.message_id().to_owned();
                rotation.last_message_id = message.message_id().to_owned();
            }
            Ok::<(), tunnel_protocol::rotation::RotationError>(())
        })
    }

    fn build_fence_snapshot(
        session: &DeviceSession,
        snapshot_id: &str,
        direction: Direction,
    ) -> FenceSnapshot {
        let mut entries = Vec::new();
        for (stream_id, pending) in &session.pending {
            if direction == Direction::RelayToConnector {
                entries.push(StreamFence::new(
                    *stream_id,
                    direction,
                    pending.send_sequence,
                ));
            } else {
                entries.push(StreamFence::new(
                    *stream_id,
                    direction,
                    pending.response_sequence,
                ));
            }
        }
        for (stream_id, stream) in &session.streams {
            let last = stream.sequence.direction(direction).last_emitted();
            entries.push(StreamFence::new(*stream_id, direction, last));
        }
        entries.sort_by_key(|entry| entry.stream_id);
        entries.dedup_by_key(|entry| entry.stream_id);
        FenceSnapshot::new(snapshot_id, entries)
    }

    fn observe_rotation_message(
        &mut self,
        key: &SessionKey,
        message: &ControlMessage,
    ) -> RotationJournalDecision {
        let Some(session) = self.session_mut(key) else {
            return RotationJournalDecision::Error(JournalError::MissingMessage);
        };
        let Some(rotation) = session.rotation.as_mut() else {
            return RotationJournalDecision::Error(JournalError::MissingMessage);
        };
        Self::observe_rotation_journal(rotation, message, monotonic_millis())
    }

    fn observe_rotation_journal(
        rotation: &mut RotationRuntime,
        message: &ControlMessage,
        now: u64,
    ) -> RotationJournalDecision {
        let Ok(canonical) = wire::encode_control_message(message) else {
            return RotationJournalDecision::Error(JournalError::OversizedMessage);
        };
        Self::prune_rotation_tombstones(rotation, now);
        let journal = if let Some(attempt) = Self::message_attempt(message) {
            if rotation.attempt.as_ref() == Some(attempt) {
                &mut rotation.journal
            } else if let Some(tombstone) = rotation
                .tombstones
                .iter_mut()
                .find(|tombstone| tombstone.attempt == *attempt)
            {
                &mut tombstone.journal
            } else {
                return RotationJournalDecision::Error(JournalError::MissingMessage);
            }
        } else {
            &mut rotation.journal
        };
        match journal.observe(message.idempotency_key(), canonical.as_bytes(), now) {
            Ok(JournalObservation::New) => RotationJournalDecision::New,
            Ok(JournalObservation::PendingDuplicate) => RotationJournalDecision::PendingDuplicate,
            Ok(JournalObservation::CompletedDuplicate) => {
                match journal.responses(message.idempotency_key(), now) {
                    Ok(Some(responses)) => RotationJournalDecision::CompletedDuplicate(
                        responses
                            .into_iter()
                            .map(|response| response.to_vec())
                            .collect(),
                    ),
                    Ok(None) => RotationJournalDecision::PendingDuplicate,
                    Err(error) => RotationJournalDecision::Error(error),
                }
            }
            Err(error) => RotationJournalDecision::Error(error),
        }
    }

    /// Cache the exact encoded reply for an inbound journaled message.  Some
    /// rotation replies reference an owner-generated message rather than an
    /// inbound request; `MissingMessage` is therefore intentionally benign.
    /// Every other journal failure remains visible to the caller so a reply
    /// cannot silently lose its idempotency record.
    fn complete_rotation_reply(
        rotation: &mut RotationRuntime,
        response: &ControlMessage,
        encoded: &str,
    ) -> Result<(), JournalError> {
        let Some(reply_to) = response.reply_to().filter(|value| !value.is_empty()) else {
            return Ok(());
        };
        match rotation.journal.append_response(
            reply_to,
            response.message_id(),
            encoded.as_bytes(),
            monotonic_millis(),
        ) {
            Ok(()) | Err(JournalError::MissingMessage) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn complete_rotation_entry(
        rotation: &mut RotationRuntime,
        message_id: &str,
        response: &[u8],
    ) -> Result<(), JournalError> {
        match rotation
            .journal
            .complete(message_id, response, monotonic_millis())
        {
            Ok(()) | Err(JournalError::MissingMessage) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn record_rotation_request_response(
        &mut self,
        key: &SessionKey,
        request: &ControlMessage,
        response: &str,
    ) -> Result<(), JournalError> {
        let canonical =
            wire::encode_control_message(request).map_err(|_| JournalError::OversizedMessage)?;
        let Some(session) = self.session_mut(key) else {
            return Err(JournalError::MissingMessage);
        };
        let Some(rotation) = session.rotation.as_mut() else {
            return Err(JournalError::MissingMessage);
        };
        let now = monotonic_millis();
        match rotation
            .journal
            .observe(request.idempotency_key(), canonical.as_bytes(), now)?
        {
            JournalObservation::New => {}
            JournalObservation::PendingDuplicate | JournalObservation::CompletedDuplicate => {
                return Err(JournalError::ConflictingMessage);
            }
        }
        rotation
            .journal
            .complete(request.idempotency_key(), response.as_bytes(), now)
    }

    fn attempt_matches(rotation: &RotationRuntime, attempt: &RotationAttemptIdentity) -> bool {
        rotation.attempt.as_ref() == Some(attempt)
    }

    fn clear_phase_message_ids(rotation: &mut RotationRuntime) {
        rotation.quiesce_message_id.clear();
        rotation.frozen_message_id.clear();
        rotation.commit_message_id.clear();
        rotation.retire_message_id.clear();
        rotation.peer_frozen_message_id = None;
        rotation.peer_drained_message_id = None;
        rotation.peer_committed_message_id = None;
        rotation.peer_retired_message_id = None;
        rotation.peer_aborted_message_id = None;
    }

    fn peer_message_id_is_acceptable(pinned: Option<&str>, incoming: &str) -> bool {
        !incoming.is_empty() && pinned.is_none_or(|existing| existing == incoming)
    }

    fn pin_peer_message_id(pinned: &mut Option<String>, incoming: &str) -> bool {
        if !Self::peer_message_id_is_acceptable(pinned.as_deref(), incoming) {
            return false;
        }
        if pinned.is_none() {
            *pinned = Some(incoming.to_owned());
        }
        true
    }

    fn placeholder_journal() -> ControlJournal {
        ControlJournal::new(128, 4 * 1024 * 1024, 0, u64::MAX)
            .expect("bounded placeholder journal limits")
    }

    fn prune_rotation_tombstones(rotation: &mut RotationRuntime, now_ms: u64) {
        rotation
            .tombstones
            .retain(|tombstone| tombstone.deadline_ms > now_ms);
    }

    fn rotation_tombstone_capacity_available(rotation: &mut RotationRuntime, now_ms: u64) -> bool {
        Self::prune_rotation_tombstones(rotation, now_ms);
        rotation.tombstones.len() < MAX_ROTATION_TOMBSTONES
    }

    fn retain_rotation_tombstone(rotation: &mut RotationRuntime) -> bool {
        let Some(attempt) = rotation.attempt.clone() else {
            return false;
        };
        let Some(deadline_ms) = rotation.attempt_deadline_ms else {
            return false;
        };
        if rotation.tombstones.len() >= MAX_ROTATION_TOMBSTONES {
            // The caller must reject the next attempt before allocating a new
            // generation.  Evicting a live tombstone would make an old
            // message indistinguishable from a fresh attempt and permit
            // duplicate side effects after the retention window is full.
            return false;
        };
        let journal = std::mem::replace(&mut rotation.journal, Self::placeholder_journal());
        rotation.tombstones.push_back(RotationTombstone {
            attempt,
            deadline_ms,
            journal,
        });
        true
    }

    fn message_attempt(message: &ControlMessage) -> Option<&RotationAttemptIdentity> {
        match message {
            ControlMessage::RotatePrepare(value) => Some(&value.attempt),
            ControlMessage::RotateQuiesce(value) => Some(&value.attempt),
            ControlMessage::RotateFrozen(value) => Some(&value.attempt),
            ControlMessage::RotateDrained(value) => Some(&value.attempt),
            ControlMessage::RotateCommit(value) => Some(&value.attempt),
            ControlMessage::RotateCommitted(value) => Some(&value.attempt),
            ControlMessage::RotateRetire(value) => Some(&value.attempt),
            ControlMessage::RotateRetired(value) => Some(&value.attempt),
            ControlMessage::RotateComplete(value) => Some(&value.attempt),
            ControlMessage::RotateAbort(value) => Some(&value.attempt),
            ControlMessage::RotateAborted(value) => Some(&value.attempt),
            ControlMessage::RecoveryBegin(value) => Some(&value.attempt),
            ControlMessage::RecoveryClosed(value) => Some(&value.attempt),
            ControlMessage::Resume(value) => Some(&value.attempt),
            ControlMessage::Resumed(value) => Some(&value.attempt),
            _ => None,
        }
    }

    fn pending_abort_ack_if_active(
        phase: RotationPhase,
        pending: &Option<tunnel_protocol::rotation_control::RotateAborted>,
    ) -> Option<tunnel_protocol::rotation_control::RotateAborted> {
        (phase == RotationPhase::Active)
            .then(|| pending.clone())
            .flatten()
    }

    async fn handle_rotate_frozen(
        &mut self,
        key: &SessionKey,
        frozen: tunnel_protocol::rotation_control::RotateFrozen,
    ) {
        let Some(session) = self.session_for(key) else {
            return;
        };
        let Some(rotation) = session.rotation.as_ref() else {
            return;
        };
        if !Self::attempt_matches(rotation, &frozen.attempt)
            || frozen.attempt.session_id != key.session_id
            || frozen.attempt.epoch != key.epoch
            || frozen.attempt.owner_id != runtime::owner_id(&session.owner)
            || frozen.reply_to != rotation.quiesce_message_id
            || !Self::peer_message_id_is_acceptable(
                rotation.peer_frozen_message_id.as_deref(),
                &frozen.message_id,
            )
        {
            return;
        }
        // The relay receives the connector's fence, so the direction is
        // authenticated by endpoint role rather than inferred from entries.
        // Empty rosters therefore remain unambiguous and every non-empty
        // entry is checked by the pure state machine against this direction.
        let direction = Direction::ConnectorToRelay;
        let result = self.with_rotation_mut(key, |_session, rotation| {
            rotation.state.frozen(
                &frozen.attempt,
                frozen.snapshot.clone(),
                direction,
                monotonic_millis(),
            )?;
            if !Self::pin_peer_message_id(&mut rotation.peer_frozen_message_id, &frozen.message_id)
            {
                return Err(tunnel_protocol::rotation::RotationError::AttemptMismatch);
            }
            rotation.remote_fences[direction_index(direction)] = Some(frozen.snapshot.clone());
            rotation.peer_message_id = frozen.message_id.clone();
            Ok::<(), tunnel_protocol::rotation::RotationError>(())
        });
        if let Err(error) = result {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                phase = ?self
                    .session_for(key)
                    .and_then(|session| session.rotation.as_ref())
                    .map(|rotation| rotation.state.phase()),
                stage = "connector_frozen",
                error = %error,
            );
            return;
        }
        if let Err(error) = self.progress_rotation_drain(key) {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                phase = ?self
                    .session_for(key)
                    .and_then(|session| session.rotation.as_ref())
                    .map(|rotation| rotation.state.phase()),
                stage = "drain_progress_after_connector_frozen",
                error = %error,
            );
        }
    }

    async fn handle_rotate_drained(
        &mut self,
        key: &SessionKey,
        drained: tunnel_protocol::rotation_control::RotateDrained,
    ) {
        let Some(session) = self.session_for(key) else {
            return;
        };
        let Some(rotation) = session.rotation.as_ref() else {
            return;
        };
        if !Self::attempt_matches(rotation, &drained.attempt)
            || drained.reply_to != rotation.frozen_message_id
            || !Self::peer_message_id_is_acceptable(
                rotation.peer_drained_message_id.as_deref(),
                &drained.message_id,
            )
        {
            return;
        }
        let result = self.with_rotation_mut(key, |_session, rotation| {
            rotation
                .state
                .drained(&drained.attempt, drained.proof.clone(), monotonic_millis())?;
            if !Self::pin_peer_message_id(
                &mut rotation.peer_drained_message_id,
                &drained.message_id,
            ) {
                return Err(tunnel_protocol::rotation::RotationError::AttemptMismatch);
            }
            // The coordinator's COMMIT must reply to the connector's proof
            // when that proof is the event that completes both directions.
            rotation.peer_message_id = drained.message_id.clone();
            Ok::<(), tunnel_protocol::rotation::RotationError>(())
        });
        if let Err(error) = result {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                phase = ?self
                    .session_for(key)
                    .and_then(|session| session.rotation.as_ref())
                    .map(|rotation| rotation.state.phase()),
                stage = "connector_drained",
                error = %error,
            );
            return;
        }
        if let Err(error) = self.progress_rotation_drain(key) {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                phase = ?self
                    .session_for(key)
                    .and_then(|session| session.rotation.as_ref())
                    .map(|rotation| rotation.state.phase()),
                stage = "drain_progress_after_connector_drained",
                error = %error,
            );
        }
    }

    async fn handle_rotate_committed(
        &mut self,
        key: &SessionKey,
        committed: tunnel_protocol::rotation_control::RotateCommitted,
    ) {
        let Some(session) = self.session_for(key) else {
            return;
        };
        let Some(rotation) = session.rotation.as_ref() else {
            return;
        };
        if !Self::attempt_matches(rotation, &committed.attempt)
            || committed.reply_to != rotation.commit_message_id
            || !Self::peer_message_id_is_acceptable(
                rotation.peer_committed_message_id.as_deref(),
                &committed.message_id,
            )
        {
            return;
        }
        let _ = self.with_rotation_mut(key, |session, rotation| {
            if !Self::peer_message_id_is_acceptable(
                rotation.peer_committed_message_id.as_deref(),
                &committed.message_id,
            ) {
                return Err(tunnel_protocol::rotation::RotationError::AttemptMismatch);
            }
            rotation
                .state
                .committed(&committed.attempt, monotonic_millis())?;
            let status_after_commit = rotation.state.status();
            Self::latch_rotation_lifecycle(rotation, &status_after_commit);
            if !Self::pin_peer_message_id(
                &mut rotation.peer_committed_message_id,
                &committed.message_id,
            ) {
                return Err(tunnel_protocol::rotation::RotationError::AttemptMismatch);
            }
            let Some(candidate) = rotation.candidate.take() else {
                return Err(tunnel_protocol::rotation::RotationError::CandidateNotReady);
            };
            let old = session.active_carrier.take();
            session.active_carrier = Some(candidate);
            session.data_tx = session
                .active_carrier
                .as_ref()
                .map(|carrier| carrier.tx.clone());
            session.generation = committed.attempt.new_generation;
            session.connection_id = committed.attempt.new_connection_id.clone();
            if let Some(old) = old {
                let _ = old.tx.try_send(DataOutbound::Close);
            }
            rotation
                .state
                .retire(&committed.attempt, monotonic_millis())?;
            let message = wire::rotate_retire(
                &committed.message_id,
                committed.attempt.clone(),
                &rotation.snapshot_id,
            );
            let encoded = wire::encode_control_message(&message)
                .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
            Self::complete_rotation_reply(rotation, &message, &encoded)
                .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
            queue_control(&session.control_tx, &session.queue_budget, encoded)
                .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
            rotation.retire_message_id = message.message_id().to_owned();
            rotation.last_message_id = message.message_id().to_owned();
            Ok::<(), tunnel_protocol::rotation::RotationError>(())
        });
        // The candidate is now the active carrier and the relay writer has
        // resumed on the new generation (phase Retiring).  Emit every frame
        // held while the writer was frozen, each with the continuing sequence.
        self.flush_frozen_writes(key);
    }

    async fn handle_rotate_retired(
        &mut self,
        key: &SessionKey,
        retired: tunnel_protocol::rotation_control::RotateRetired,
    ) {
        let Some(session) = self.session_for(key) else {
            return;
        };
        let Some(rotation) = session.rotation.as_ref() else {
            return;
        };
        if !Self::attempt_matches(rotation, &retired.attempt)
            || retired.reply_to != rotation.retire_message_id
            || !Self::peer_message_id_is_acceptable(
                rotation.peer_retired_message_id.as_deref(),
                &retired.message_id,
            )
        {
            return;
        }
        let _ = self.with_rotation_mut(key, |_session, rotation| {
            if !Self::peer_message_id_is_acceptable(
                rotation.peer_retired_message_id.as_deref(),
                &retired.message_id,
            ) {
                return Err(tunnel_protocol::rotation::RotationError::AttemptMismatch);
            }
            let status_before_close = rotation.state.status();
            Self::latch_rotation_lifecycle(rotation, &status_before_close);
            rotation.state.retired(
                &retired.attempt,
                tunnel_protocol::rotation::RotationSide::Connector,
                tunnel_protocol::rotation::ClosureEvidence::closed(
                    retired.closed_connection_id.clone(),
                ),
                monotonic_millis(),
            )?;
            let status_after_close = rotation.state.status();
            Self::latch_rotation_lifecycle(rotation, &status_after_close);
            if !Self::pin_peer_message_id(
                &mut rotation.peer_retired_message_id,
                &retired.message_id,
            ) {
                return Err(tunnel_protocol::rotation::RotationError::AttemptMismatch);
            }
            // The connector's RETIRED is only one half of physical closure.
            // Keep the attempt and immutable roster until the old relay-side
            // WebSocket reports its own close; `finish_rotation_if_ready`
            // emits COMPLETE exactly once after both proofs are present.
            rotation.peer_message_id = retired.message_id;
            Ok::<(), tunnel_protocol::rotation::RotationError>(())
        });
        self.finish_rotation_if_ready(key);
    }

    fn finish_rotation_if_ready(&mut self, key: &SessionKey) {
        let _ = self.with_rotation_mut(key, |session, rotation| {
            if rotation.state.phase() != RotationPhase::Active {
                return Ok::<(), tunnel_protocol::rotation::RotationError>(());
            }
            let Some(attempt) = rotation.attempt.clone() else {
                return Ok::<(), tunnel_protocol::rotation::RotationError>(());
            };
            let forced = rotation.state.status().deadline_forced_retirement;
            let mut completed_diagnostics = rotation.completed_rotation_diagnostics.clone();
            if let Some(diagnostics) = completed_diagnostics.as_mut() {
                diagnostics.attempt_active = false;
                diagnostics.old_socket_closed = [true, true];
            }
            let source = if rotation.peer_message_id.is_empty() {
                return Ok::<(), tunnel_protocol::rotation::RotationError>(());
            } else {
                rotation.peer_message_id.clone()
            };
            let message = wire::rotate_complete(
                &source,
                attempt,
                &rotation.snapshot_id,
                forced,
                forced.then(|| "overlap deadline forced retirement".to_owned()),
            );
            let encoded = wire::encode_control_message(&message)
                .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
            match Self::complete_rotation_reply(rotation, &message, &encoded) {
                Ok(()) => {}
                // A deadline-forced retirement completes after this attempt's
                // immutable journal window has closed.  The forced COMPLETE is
                // the owner's terminal record for an attempt that is tombstoned
                // immediately below, so an expired retention window must not
                // strand the already-committed candidate.  Every other journal
                // failure stays fail-closed.
                Err(JournalError::Expired) if forced => {}
                Err(_) => return Err(tunnel_protocol::rotation::RotationError::Closed),
            }
            queue_control(&session.control_tx, &session.queue_budget, encoded)
                .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
            rotation.last_message_id = message.message_id().to_owned();
            Self::retain_rotation_tombstone(rotation);
            rotation.attempt = None;
            rotation.attempt_deadline_ms = None;
            rotation.snapshot_id.clear();
            rotation.abort_message_id = None;
            rotation.peer_message_id.clear();
            rotation.pending_abort_ack = None;
            Self::clear_phase_message_ids(rotation);
            rotation.remote_fences = [None, None];
            rotation.own_fence = None;
            rotation.completed_rotation_diagnostics = completed_diagnostics;
            session.rotations_completed = session.rotations_completed.saturating_add(1);
            session.last_rotation = Instant::now();
            Ok::<(), tunnel_protocol::rotation::RotationError>(())
        });
    }

    fn rotation_deadline_event(
        key: &SessionKey,
        rotation: &RotationRuntime,
        fired_at_ms: u64,
    ) -> Option<RotationDeadlineEvent> {
        let status = rotation.state.status();
        let attempt = status.attempt.as_ref()?;
        let started_at_ms = status.started_at_ms?;
        let deadline_ms = status.deadline_ms?;
        if fired_at_ms < deadline_ms
            || deadline_ms <= started_at_ms
            || attempt.session_id != key.session_id
            || attempt.epoch != key.epoch
            || status.active_generation != attempt.old_generation
            || status.active_connection_id != attempt.old_connection_id
        {
            return None;
        }
        Some(RotationDeadlineEvent {
            tenant_id: key.tenant_id.to_string(),
            device_id: key.device_id.to_string(),
            session_id: attempt.session_id.clone(),
            epoch: attempt.epoch,
            old_generation: attempt.old_generation,
            old_connection_id: attempt.old_connection_id.clone(),
            candidate_generation: attempt.new_generation,
            candidate_connection_id: attempt.new_connection_id.clone(),
            started_at_ms,
            deadline_ms,
            fired_at_ms,
            reason: "deadline",
        })
    }

    fn retain_rotation_deadline_event(&mut self, event: RotationDeadlineEvent) {
        let duplicate = self.rotation_deadline_events.iter().any(|existing| {
            existing.device_id == event.device_id
                && existing.session_id == event.session_id
                && existing.epoch == event.epoch
                && existing.old_generation == event.old_generation
                && existing.old_connection_id == event.old_connection_id
                && existing.candidate_generation == event.candidate_generation
                && existing.candidate_connection_id == event.candidate_connection_id
                && existing.started_at_ms == event.started_at_ms
                && existing.deadline_ms == event.deadline_ms
                && existing.reason == event.reason
        });
        if duplicate {
            return;
        }
        if self.rotation_deadline_events.len() >= MAX_ROTATION_DEADLINE_EVENTS {
            self.rotation_deadline_events.pop_front();
        }
        self.rotation_deadline_events.push_back(event);
    }

    fn session_terminal_event(
        key: &SessionKey,
        session: &DeviceSession,
        reason: &str,
        closed_at_ms: u64,
    ) -> SessionTerminalEvent {
        let status = session
            .rotation
            .as_ref()
            .map(|rotation| rotation.state.status());
        let active_generation = status
            .as_ref()
            .map_or(session.generation, |status| status.active_generation);
        let active_connection_id = status.as_ref().map_or_else(
            || session.connection_id.clone(),
            |status| status.active_connection_id.clone(),
        );
        let (candidate_generation, candidate_connection_id) = status
            .as_ref()
            .and_then(|status| status.attempt.as_ref())
            .map(|attempt| {
                (
                    Some(attempt.new_generation),
                    Some(attempt.new_connection_id.clone()),
                )
            })
            .unwrap_or((None, None));
        let rotation_id = status
            .as_ref()
            .and_then(|status| status.attempt.as_ref())
            .map(|attempt| attempt.rotation_id.clone());
        SessionTerminalEvent {
            tenant_id: session.identity.tenant_id.to_string(),
            device_id: key.device_id.to_string(),
            session_id: key.session_id.clone(),
            epoch: key.epoch,
            active_generation,
            active_connection_id,
            candidate_generation,
            candidate_connection_id,
            rotation_id,
            rotation_started_at_ms: status.as_ref().and_then(|status| status.started_at_ms),
            rotation_deadline_ms: status.as_ref().and_then(|status| status.deadline_ms),
            closed_at_ms,
            reason: runtime::terminal_close_reason(reason),
        }
    }

    /// Build a bounded, payload-free receipt for a connector FIN/RESET that
    /// was just accepted on `carrier`.  Unlike the first-terminal latch this
    /// may be captured on a later frame, so it records the final connector
    /// receive cursor, terminal sequence and the exact physical carrier that
    /// authenticated the frame.  It returns `None` unless the stream still
    /// matches the operation and the connector direction carries a terminal
    /// sequence, so an absence of receipt can never be synthesized.
    fn stream_terminal_receipt_event(
        &self,
        key: &SessionKey,
        carrier: &CarrierKey,
        stream_id: u64,
        operation_id: &str,
    ) -> Option<StreamTerminalReceiptEvent> {
        let session = self.session_for(key)?;
        let stream = session.streams.get(&stream_id)?;
        if stream.operation_id != operation_id {
            return None;
        }
        // Only the authenticated active or candidate carrier reaches stream
        // state in `inbound_data`; record the physical carrier that processed
        // the frame rather than inferring it from mutable rotation state.
        let carrier_is_active = session
            .active_carrier
            .as_ref()
            .is_some_and(|active| active.context == carrier.context());
        let carrier_is_candidate = session
            .rotation
            .as_ref()
            .and_then(|rotation| rotation.candidate.as_ref())
            .is_some_and(|candidate| candidate.context == carrier.context());
        if !carrier_is_active && !carrier_is_candidate {
            return None;
        }
        let snapshot = stream.sequence.snapshot();
        let relay = snapshot.direction(Direction::RelayToConnector);
        let connector = snapshot.direction(Direction::ConnectorToRelay);
        let receive_terminal_sequence = connector.receive_terminal_sequence?;
        Some(StreamTerminalReceiptEvent {
            tenant_id: session.identity.tenant_id.to_string(),
            device_id: key.device_id.to_string(),
            session_id: key.session_id.clone(),
            epoch: key.epoch,
            deployment_incarnation: session.owner.deployment_incarnation.clone(),
            node_id: session.owner.node_id.clone(),
            boot_id: session.owner.boot_id.clone(),
            owner_id: runtime::owner_id(&session.owner),
            stream_id,
            operation_id: stream.operation_id.clone(),
            request_id: stream.request_id.clone(),
            active_generation: carrier.generation,
            active_connection_id: carrier.connection_id.clone(),
            recv_contiguous_connector_to_relay: connector.recv_contiguous,
            delivered_contiguous_connector_to_relay: connector.delivered_contiguous,
            receive_terminal_sequence,
            last_emitted_relay_to_connector: relay.last_emitted,
            peer_acked_relay_to_connector: relay.peer_acked,
            replay_bytes_relay_to_connector: relay.replay_bytes,
            queue_bytes: stream.budget_bytes,
            observed_at_ms: monotonic_millis(),
        })
    }

    fn stream_terminal_event(
        &self,
        key: &SessionKey,
        stream_id: u64,
        operation_id: &str,
        reason: &str,
        cause: Option<StreamTerminalCause>,
    ) -> Option<StreamTerminalEvent> {
        let session = self.session_for(key)?;
        let stream = session.streams.get(&stream_id)?;
        if stream.operation_id != operation_id {
            return None;
        }
        let status = session
            .rotation
            .as_ref()
            .map(|rotation| rotation.state.status());
        let active_generation = status
            .as_ref()
            .map_or(session.generation, |status| status.active_generation);
        let active_connection_id = status.as_ref().map_or_else(
            || session.connection_id.clone(),
            |status| status.active_connection_id.clone(),
        );
        let snapshot = stream.sequence.snapshot();
        let relay = snapshot.direction(Direction::RelayToConnector);
        let connector = snapshot.direction(Direction::ConnectorToRelay);
        Some(StreamTerminalEvent {
            tenant_id: session.identity.tenant_id.to_string(),
            device_id: key.device_id.to_string(),
            session_id: key.session_id.clone(),
            epoch: key.epoch,
            deployment_incarnation: session.owner.deployment_incarnation.clone(),
            node_id: session.owner.node_id.clone(),
            boot_id: session.owner.boot_id.clone(),
            owner_id: runtime::owner_id(&session.owner),
            stream_id,
            operation_id: stream.operation_id.clone(),
            request_id: stream.request_id.clone(),
            active_generation,
            active_connection_id,
            rotations_completed: session.rotations_completed,
            total_replayed_frames: session.total_replayed_frames,
            last_emitted_relay_to_connector: relay.last_emitted,
            peer_acked_relay_to_connector: relay.peer_acked,
            recv_contiguous_connector_to_relay: connector.recv_contiguous,
            delivered_contiguous_connector_to_relay: connector.delivered_contiguous,
            closed_at_ms: monotonic_millis(),
            authorization_failure_code: stream.authorization_failure_code,
            reason: runtime::terminal_close_reason(reason),
            cause,
        })
    }

    fn retain_session_terminal_event(&mut self, event: SessionTerminalEvent) {
        if self.session_terminal_events.len() >= MAX_SESSION_TERMINAL_EVENTS {
            self.session_terminal_events.pop_front();
        }
        self.session_terminal_events.push_back(event);
    }

    fn retain_stream_terminal_event(&mut self, event: StreamTerminalEvent) {
        retain_bounded_stream_terminal_event(&mut self.stream_terminal_events, event);
    }

    fn retain_stream_terminal_receipt_event(&mut self, event: StreamTerminalReceiptEvent) {
        retain_bounded_stream_terminal_receipt_event(
            &mut self.stream_terminal_receipt_events,
            event,
        );
    }

    /// Advance the attempt deadline independently of the writer barrier.  A
    /// candidate dial can fail before it is registered as a data carrier, so
    /// no disconnect event will ever arrive to drive the owner decision.  The
    /// coordinator therefore polls the pure state clock on every maintenance
    /// tick and emits one unsolicited ABORT as soon as the handshake budget
    /// expires.  Once the absolute overlap budget expires, a pre-commit attempt
    /// fails closed rather than leaving an old or candidate carrier allocated
    /// indefinitely; after commit the lingering old transport is force-retired
    /// instead, because the candidate is already serving the retained streams.
    fn poll_rotation_deadline(&mut self, key: &SessionKey) -> bool {
        self.poll_rotation_deadline_at(key, monotonic_millis())
    }

    /// Explicit-clock body of [`Self::poll_rotation_deadline`].  Deterministic
    /// regressions drive the absolute deadline directly instead of waiting on
    /// the process monotonic clock; the production caller above always passes
    /// the real sample.
    fn poll_rotation_deadline_at(&mut self, key: &SessionKey, now_ms: u64) -> bool {
        let mut send_abort = false;
        let mut expired = false;
        let mut force_retirement = false;
        let mut deadline_event = None;
        let result = self.with_rotation_mut(key, |_session, rotation| {
            let Some(deadline_ms) = rotation.state.status().deadline_ms else {
                return Ok::<(), tunnel_protocol::rotation::RotationError>(());
            };
            if now_ms >= deadline_ms {
                // protocol.md, "Abort, deadline and loss during handover":
                // "Absolute overlap deadline: after commit, forcibly close any
                // old transport still lingering."  The recover-or-fail rule in
                // the same bullet is scoped to "an unfinished abort or drain",
                // and the state diagram has no `Retiring --> Recovering` edge,
                // so a committed candidate that is already serving the retained
                // streams is not demoted here.  The lingering old transport is
                // force-retired instead and the forced closure is recorded
                // distinctly; no budget is extended.
                if rotation.state.phase() == RotationPhase::Retiring {
                    force_retirement = true;
                    return Ok::<(), tunnel_protocol::rotation::RotationError>(());
                }
                deadline_event = Self::rotation_deadline_event(key, rotation, now_ms);
                expired = true;
                return Ok::<(), tunnel_protocol::rotation::RotationError>(());
            }
            if rotation.abort_message_id.is_none()
                && rotation.state.phase() == RotationPhase::Preparing
            {
                let _ = rotation.state.tick(now_ms);
            }
            send_abort = rotation.abort_message_id.is_none()
                && rotation.state.phase() == RotationPhase::Aborting;
            Ok::<(), tunnel_protocol::rotation::RotationError>(())
        });
        if result.is_err() {
            return false;
        }
        if force_retirement {
            self.force_rotation_retirement(key, now_ms);
            return false;
        }
        if let Some(event) = deadline_event {
            self.retain_rotation_deadline_event(event);
        }
        if send_abort {
            self.emit_rotation_abort(key, "candidate handshake timeout");
        }
        expired
    }

    /// Force-retire the old transport of a committed handover whose absolute
    /// overlap deadline has expired.
    ///
    /// protocol.md retires the old carrier here rather than demoting the
    /// session: "after commit, forcibly close any old transport still
    /// lingering" and "`ROTATE_COMPLETE` ends the attempt after retirement
    /// evidence; deadline-forced closure is recorded distinctly."  The relay
    /// released its own old carrier at COMMITTED, so the forced step is to stop
    /// waiting on that close handshake and record the owner-side closure.  The
    /// connector's attestation is never fabricated: with its `ROTATE_RETIRED`
    /// already present the attempt completes on the committed candidate, and
    /// without it the session keeps serving the retained streams on the new
    /// generation with the forced closure visible in diagnostics.  Nothing here
    /// extends a budget and no path returns to the old generation.
    fn force_rotation_retirement(&mut self, key: &SessionKey, now_ms: u64) {
        let mut deadline_event = None;
        let _ = self.with_rotation_mut(key, |_session, rotation| {
            if rotation.state.phase() != RotationPhase::Retiring {
                return Ok::<(), tunnel_protocol::rotation::RotationError>(());
            }
            let Some(attempt) = rotation.attempt.clone() else {
                return Ok::<(), tunnel_protocol::rotation::RotationError>(());
            };
            // Latch the forced flag even when the closure record below is
            // already present, so diagnostics distinguish this attempt from a
            // handover that retired inside its budget.
            let _ = rotation.state.tick(now_ms);
            deadline_event = Self::rotation_deadline_event(key, rotation, now_ms).map(|event| {
                RotationDeadlineEvent {
                    reason: "forced_retirement",
                    ..event
                }
            });
            let status_before_close = rotation.state.status();
            Self::latch_rotation_lifecycle(rotation, &status_before_close);
            if !status_before_close.old_socket_closed[rotation_side_index(RotationSide::Owner)] {
                rotation.state.old_socket_closed(
                    &attempt,
                    RotationSide::Owner,
                    ClosureEvidence::closed(attempt.old_connection_id.clone()),
                    now_ms,
                )?;
                let status_after_close = rotation.state.status();
                Self::latch_rotation_lifecycle(rotation, &status_after_close);
            }
            Ok::<(), tunnel_protocol::rotation::RotationError>(())
        });
        if let Some(event) = deadline_event {
            self.retain_rotation_deadline_event(event);
        }
        // A no-op unless the connector's RETIRED was already journaled: the
        // forced owner closure alone leaves the attempt open while the session
        // keeps serving on the committed candidate.
        self.finish_rotation_if_ready(key);
    }

    /// Queue the coordinator's physical-failure decision exactly once.  The
    /// empty reply target is intentional: a timeout is an owner-generated
    /// decision and must not overwrite a cached FROZEN/DRAINED journal reply.
    fn emit_rotation_abort(&mut self, key: &SessionKey, reason: &str) {
        let Some((attempt, remaining_ms, control_tx, budget)) =
            self.session_for(key).and_then(|session| {
                let rotation = session.rotation.as_ref()?;
                if rotation.abort_message_id.is_some()
                    || rotation.state.phase() != RotationPhase::Aborting
                {
                    return None;
                }
                let attempt = rotation.attempt.clone()?;
                let remaining_ms = rotation
                    .state
                    .status()
                    .deadline_ms
                    .unwrap_or_default()
                    .saturating_sub(monotonic_millis());
                Some((
                    attempt,
                    remaining_ms,
                    session.control_tx.clone(),
                    session.queue_budget.clone(),
                ))
            })
        else {
            return;
        };
        if remaining_ms == 0 {
            return;
        }
        let message = wire::rotate_abort("", attempt.clone(), reason, remaining_ms);
        let Ok(encoded) = wire::encode_control_message(&message) else {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                stage = "rotation_abort_encode",
            );
            return;
        };
        if queue_control(&control_tx, &budget, encoded).is_err() {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                stage = "rotation_abort_queue",
            );
            return;
        }
        let ticket_matches_attempt = |ticket: &Ticket| {
            ticket.device_id == key.device_id
                && ticket.session_id == key.session_id
                && ticket.epoch == key.epoch
                && ticket.generation == attempt.new_generation
                && ticket.connection_id == attempt.new_connection_id
                && ticket.candidate
        };
        // Reject any still-unconsumed candidate ticket before claiming the
        // relay side has no outstanding attachment.  An accepted candidate
        // is closed only by its physical DisconnectData event below.
        self.tickets
            .retain(|_, ticket| !ticket_matches_attempt(ticket));
        if let Some(session) = self.session_mut(key)
            && let Some(rotation) = session.rotation.as_mut()
            && rotation.attempt.as_ref() == Some(&attempt)
            && rotation.state.phase() == RotationPhase::Aborting
            && rotation.abort_message_id.is_none()
        {
            if rotation.candidate.is_some() {
                if let Some(candidate) = rotation.candidate.as_ref() {
                    let _ = candidate.tx.try_send(DataOutbound::Close);
                }
            } else if rotation
                .state
                .candidate_closed(
                    &attempt,
                    RotationSide::Owner,
                    ClosureEvidence::closed(attempt.new_connection_id.clone()),
                    monotonic_millis(),
                )
                .is_err()
            {
                tracing::warn!(
                    device_id = %key.device_id,
                    session_id = %key.session_id,
                    epoch = key.epoch,
                    stage = "rotation_abort_owner_closure",
                );
                return;
            }
            rotation.abort_message_id = Some(message.message_id().to_owned());
            rotation.last_message_id = message.message_id().to_owned();
        }
    }

    fn finish_rotation_abort_if_ready(
        &mut self,
        key: &SessionKey,
    ) -> Result<(), tunnel_protocol::rotation::RotationError> {
        self.with_rotation_mut(key, |session, rotation| {
            if rotation.state.phase() != RotationPhase::Active {
                return Ok(());
            }
            let Some(aborted) = Self::pending_abort_ack_if_active(
                rotation.state.phase(),
                &rotation.pending_abort_ack,
            ) else {
                return Ok(());
            };
            let response = wire::rotate_aborted(
                &aborted.message_id,
                aborted.attempt.clone(),
                &aborted.reason,
            );
            let encoded = wire::encode_control_message(&response)
                .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
            Self::complete_rotation_reply(rotation, &response, &encoded)
                .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
            queue_control(&session.control_tx, &session.queue_budget, encoded)
                .map_err(|_| tunnel_protocol::rotation::RotationError::Closed)?;
            Self::retain_rotation_tombstone(rotation);
            rotation.pending_abort_ack = None;
            rotation.candidate = None;
            rotation.attempt = None;
            rotation.attempt_deadline_ms = None;
            rotation.snapshot_id.clear();
            rotation.prepare_message_id.clear();
            rotation.last_message_id = response.message_id().to_owned();
            rotation.abort_message_id = None;
            rotation.peer_message_id.clear();
            Self::clear_phase_message_ids(rotation);
            rotation.remote_fences = [None, None];
            rotation.own_fence = None;
            rotation.barrier_rx = None;
            session.last_rotation = Instant::now();
            Ok(())
        })
    }

    async fn handle_rotate_aborted(
        &mut self,
        key: &SessionKey,
        aborted: tunnel_protocol::rotation_control::RotateAborted,
    ) {
        let result = self.with_rotation_mut(key, |_session, rotation| {
            if !Self::attempt_matches(rotation, &aborted.attempt) {
                return Err(tunnel_protocol::rotation::RotationError::MissingAttempt);
            }
            if rotation.abort_message_id.as_deref() != Some(aborted.reply_to.as_str()) {
                return Err(tunnel_protocol::rotation::RotationError::AttemptMismatch);
            }
            if !Self::peer_message_id_is_acceptable(
                rotation.peer_aborted_message_id.as_deref(),
                &aborted.message_id,
            ) {
                return Err(tunnel_protocol::rotation::RotationError::AttemptMismatch);
            }
            rotation.state.aborted(
                &aborted.attempt,
                tunnel_protocol::rotation::RotationSide::Connector,
                tunnel_protocol::rotation::ClosureEvidence::closed(
                    aborted.closed_connection_id.clone(),
                ),
                monotonic_millis(),
            )?;
            if !Self::pin_peer_message_id(
                &mut rotation.peer_aborted_message_id,
                &aborted.message_id,
            ) {
                return Err(tunnel_protocol::rotation::RotationError::AttemptMismatch);
            }
            // Keep the inbound journal entry pending until the owner's local
            // closure proof is also present.  The final owner response is
            // emitted by the shared helper, either now or after the local
            // DisconnectData event.
            rotation.pending_abort_ack = Some(aborted.clone());
            Ok::<(), tunnel_protocol::rotation::RotationError>(())
        });
        if let Err(error) = result {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                phase = ?self
                    .session_for(key)
                    .and_then(|session| session.rotation.as_ref())
                    .map(|rotation| rotation.state.phase()),
                stage = "connector_aborted",
                error = %error,
            );
        } else if let Err(error) = self.finish_rotation_abort_if_ready(key) {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                stage = "owner_aborted",
                error = %error,
            );
        } else {
            // If the final ABORTED just returned the session to Active, the old
            // carrier resumes: flush frames held while the writer was frozen
            // back onto it with the continuing sequence (no gap).  A no-op
            // while the bilateral abort is still completing.
            self.flush_frozen_writes(key);
        }
    }

    /// Complete the coordinator side of the recovery closure handshake.  A
    /// recovery ticket is minted only after the connector's role-bound record
    /// matches the exact physical IDs captured before teardown and combines
    /// with the relay record under the immutable attempt context.
    async fn handle_recovery_closed(&mut self, key: &SessionKey, closed: RecoveryClosed) {
        let Some(session) = self.session_for(key) else {
            return;
        };
        let Some(rotation) = session.rotation.as_ref() else {
            return;
        };
        let Some(attempt) = rotation.attempt.as_ref().cloned() else {
            return;
        };
        let Some(recovery) = rotation.recovery.as_ref() else {
            return;
        };
        if rotation.state.phase() != RotationPhase::Recovering
            || closed.attempt != attempt
            || closed.episode_id != recovery.episode_id
            || closed.attempt_no != recovery.attempt_no
            || closed.reply_to != rotation.last_message_id
            || closed.closed_connection_ids != recovery.expected_closed_connection_ids
            || closed
                .verify_closure_digest(RecoverySide::Connector)
                .is_err()
            || recovery.peer_closed.is_some()
        {
            return;
        }
        let Some(local_closed) = recovery.local_closed.as_ref() else {
            return;
        };
        let episode_id = recovery.episode_id.clone();
        let attempt_no = recovery.attempt_no;
        let Ok(combined_digest) = tunnel_protocol::combined_closure_digest(local_closed, &closed)
        else {
            return;
        };
        let remaining_ms = Self::recovery_remaining_ms(rotation, monotonic_millis());
        if remaining_ms == 0 {
            return;
        }
        if session.cluster_profile {
            let purpose = DataAttachmentPurpose::Recovery {
                episode_id: episode_id.clone(),
                attempt_no,
                closure_digest: combined_digest.clone(),
            };
            let catalog_purpose = "recovery".to_owned();
            let binding_digest = runtime::attachment_binding_digest(
                &session.owner,
                attempt.new_generation,
                &attempt.new_connection_id,
                &catalog_purpose,
            );
            let owner = session.owner.clone();
            let tenant_id = session.identity.tenant_id;
            let spki = session.identity.spki_fingerprint.clone();
            let command_tx = self.command_tx.clone();
            let catalog = self.catalog.clone();
            let key_for_task = key.clone();
            let attempt_for_task = attempt.clone();
            if let Some(session) = self.session_mut(key)
                && let Some(rotation) = session.rotation.as_mut()
                && let Some(recovery) = rotation.recovery.as_mut()
            {
                rotation.pending_ticket = Some(PendingCatalogTicket {
                    attempt: attempt.clone(),
                    purpose,
                    catalog_purpose,
                    binding_digest: binding_digest.clone(),
                    reply_to: closed.message_id.clone(),
                    request: None,
                });
                recovery.peer_closed = Some(closed.clone());
                recovery.closure_digest = Some(combined_digest.clone());
            } else {
                return;
            }
            let expires_at = Utc::now()
                + ChronoDuration::from_std(wire::TICKET_TTL)
                    .unwrap_or_else(|_| ChronoDuration::seconds(10));
            let cancel = self.options.shutdown.clone();
            self.spawn_background(async move {
                let result = catalog
                    .issue_attachment_ticket(&AttachmentTicketIssueRequest {
                        tenant_id,
                        device_id: key_for_task.device_id,
                        spki_fingerprint: spki,
                        owner,
                        generation: attempt_for_task.new_generation,
                        connection_id: attempt_for_task.new_connection_id.clone(),
                        purpose: "recovery".to_owned(),
                        binding_digest,
                        expires_at,
                    })
                    .await
                    .map_err(|error| error.to_string());
                send_background_command(
                    &cancel,
                    &command_tx,
                    Command::CatalogTicketResolved {
                        key: key_for_task,
                        attempt: attempt_for_task,
                        result,
                    },
                )
                .await;
            });
            return;
        }
        let ticket = wire::random_token();
        let prepare = wire::rotate_prepare(
            &closed.message_id,
            attempt.clone(),
            DataAttachmentPurpose::Recovery {
                episode_id: episode_id.clone(),
                attempt_no,
                closure_digest: combined_digest.clone(),
            },
            &ticket,
            remaining_ms,
        );
        let Ok(encoded) = wire::encode_control_message(&prepare) else {
            return;
        };
        let prepare_message_id = prepare.message_id().to_owned();
        let (owner, spki, tenant_id, control_tx, budget) = (
            session.owner.clone(),
            session.identity.spki_fingerprint.clone(),
            session.identity.tenant_id,
            session.control_tx.clone(),
            session.queue_budget.clone(),
        );
        if let Some(session) = self.session_mut(key)
            && let Some(rotation) = session.rotation.as_mut()
            && Self::complete_rotation_reply(rotation, &prepare, &encoded).is_err()
        {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                stage = "recovery_journal_complete_prepare",
            );
            return;
        }
        let issued_at_wall = Utc::now();
        let expires_at_wall = issued_at_wall
            + ChronoDuration::from_std(wire::TICKET_TTL)
                .unwrap_or_else(|_| ChronoDuration::seconds(10));
        if queue_control(&control_tx, &budget, encoded).is_err() {
            return;
        }
        self.tickets.insert(
            ticket.clone(),
            Ticket {
                value: ticket.clone(),
                tenant_id,
                device_id: key.device_id,
                spki,
                session_id: key.session_id.clone(),
                epoch: key.epoch,
                generation: attempt.new_generation,
                welcome_message_id: prepare_message_id.clone(),
                connection_id: attempt.new_connection_id.clone(),
                issued_at_wall,
                expires_at_wall,
                expires_at: Instant::now() + wire::TICKET_TTL,
                consuming: false,
                owner,
                candidate: true,
                attachment_purpose: DataAttachmentPurpose::Recovery {
                    episode_id: episode_id.clone(),
                    attempt_no,
                    closure_digest: combined_digest.clone(),
                },
                catalog_purpose: String::new(),
                binding_digest: String::new(),
                locator_digest: String::new(),
                catalog_backed: false,
            },
        );
        if let Some(session) = self.session_mut(key)
            && let Some(rotation) = session.rotation.as_mut()
            && let Some(recovery) = rotation.recovery.as_mut()
        {
            recovery.peer_closed = Some(closed);
            recovery.closure_digest = Some(combined_digest);
            rotation.prepare_message_id = prepare_message_id.clone();
            rotation.last_message_id = prepare_message_id;
            rotation.abort_message_id = None;
            rotation.pending_abort_ack = None;
            Self::clear_phase_message_ids(rotation);
        }
    }

    /// Send both immutable relay snapshots after the recovery candidate is
    /// authenticated.  Snapshot construction is bounded by the roster and
    /// happens before any candidate payload can be admitted.
    fn start_recovery_snapshots(&mut self, key: &SessionKey) {
        let prepared = {
            let Some(session) = self.session_for(key) else {
                return;
            };
            let Some(rotation) = session.rotation.as_ref() else {
                return;
            };
            let Some(attempt) = rotation.attempt.clone() else {
                return;
            };
            let Some(recovery) = rotation.recovery.as_ref() else {
                return;
            };
            if rotation.state.phase() != RotationPhase::Recovering
                || !recovery.candidate_ready
                || rotation.candidate.is_none()
            {
                return;
            }
            let roster = recovery.roster.clone();
            let relay_entries = match [
                Self::recovery_local_entries(session, &roster, Direction::RelayToConnector),
                Self::recovery_local_entries(session, &roster, Direction::ConnectorToRelay),
            ] {
                [Ok(relay), Ok(connector)] => [relay, connector],
                _ => return,
            };
            let remaining_ms = Self::recovery_remaining_ms(rotation, monotonic_millis());
            if remaining_ms == 0 {
                return;
            }
            let mut messages = Vec::with_capacity(2);
            for direction in [Direction::RelayToConnector, Direction::ConnectorToRelay] {
                let message = wire::resume(
                    &rotation.prepare_message_id,
                    attempt.clone(),
                    &roster.snapshot_id,
                    ResumeStage::Snapshot,
                    direction,
                    relay_entries[direction_index(direction)].clone(),
                    remaining_ms,
                );
                let Ok(encoded) = wire::encode_control_message(&message) else {
                    return;
                };
                messages.push((message.message_id().to_owned(), encoded));
            }
            Some((
                attempt,
                roster,
                relay_entries,
                messages,
                session.control_tx.clone(),
                session.queue_budget.clone(),
            ))
        };
        let Some((attempt, roster, relay_entries, messages, control_tx, budget)) = prepared else {
            return;
        };
        for (_, encoded) in &messages {
            if queue_control(&control_tx, &budget, encoded.clone()).is_err() {
                return;
            }
        }
        if let Some(session) = self.session_mut(key)
            && let Some(rotation) = session.rotation.as_mut()
            && rotation.attempt.as_ref() == Some(&attempt)
            && let Some(recovery) = rotation.recovery.as_mut()
        {
            recovery.local_snapshots = relay_entries;
            recovery.resume_message_ids =
                [Some(messages[0].0.clone()), Some(messages[1].0.clone())];
            recovery.snapshot_reply_ids = [None, None];
            recovery.ready_snapshots = [Vec::new(), Vec::new()];
            recovery.ready_message_ids = [None, None];
            recovery.remote_snapshots = [HashMap::new(), HashMap::new()];
            recovery.ready_remote_snapshots = [HashMap::new(), HashMap::new()];
            recovery.remote_ready = [false, false];
            recovery.local_plans.clear();
            recovery.ready_sent = [false, false];
            rotation.last_message_id = messages[1].0.clone();
            rotation.snapshot_id = roster.snapshot_id;
        }
    }

    /// Convert a connector RESUMED snapshot into a bounded map and ensure it
    /// is exactly the immutable stream roster.  This rejects omission,
    /// duplication and cross-stream injection before sequence reconciliation.
    fn recovery_entries_map(
        entries: &[ResumeDirectionState],
        roster: &StreamRoster,
    ) -> Option<HashMap<u64, ResumeDirectionState>> {
        if entries.len() != roster.stream_ids.len() {
            return None;
        }
        let mut result = HashMap::with_capacity(entries.len());
        let mut previous = 0;
        for entry in entries {
            if entry.stream_id <= previous
                || roster.stream_ids.binary_search(&entry.stream_id).is_err()
                || result.insert(entry.stream_id, entry.clone()).is_some()
            {
                return None;
            }
            previous = entry.stream_id;
        }
        Some(result)
    }

    /// Reconcile again immediately before READY.  The initial SNAPSHOT pair
    /// is only a fence for retained replay; ACKs, windows, and peer-prefix
    /// replay may advance the local sequence state before the coordinator can
    /// commit candidate reception.  READY therefore carries a fresh cursor
    /// pair and is withheld while either direction still needs peer data.
    fn send_recovery_ready(
        &mut self,
        key: &SessionKey,
    ) -> Result<RecoveryReadyProgress, RelayError> {
        let prepared = {
            let Some(session) = self.session_for(key) else {
                return Err(RelayError::NotFound);
            };
            let Some(rotation) = session.rotation.as_ref() else {
                return Err(RelayError::Conflict("recovery state is unavailable"));
            };
            let Some(recovery) = rotation.recovery.as_ref() else {
                return Err(RelayError::Conflict("recovery state is unavailable"));
            };
            if rotation.state.phase() != RotationPhase::Recovering
                || recovery.snapshot_reply_ids.iter().any(Option::is_none)
                || recovery.ready_sent != [false, false]
            {
                return Ok(RecoveryReadyProgress::Pending);
            }
            let Some(attempt) = rotation.attempt.clone() else {
                return Err(RelayError::Conflict("recovery attempt is unavailable"));
            };
            let roster = recovery.roster.clone();
            let remote_snapshots = recovery.remote_snapshots.clone();
            let sources = recovery
                .snapshot_reply_ids
                .clone()
                .map(|value| value.unwrap_or_else(|| rotation.prepare_message_id.clone()));
            let mut entries = [
                Vec::with_capacity(roster.stream_ids.len()),
                Vec::with_capacity(roster.stream_ids.len()),
            ];
            for stream_id in &roster.stream_ids {
                let Some(stream) = session.streams.get(stream_id) else {
                    return Err(RelayError::Conflict(
                        "recovery roster stream is unavailable",
                    ));
                };
                let Some(relay_entry) = remote_snapshots[0].get(stream_id) else {
                    return Ok(RecoveryReadyProgress::Pending);
                };
                let Some(connector_entry) = remote_snapshots[1].get(stream_id) else {
                    return Ok(RecoveryReadyProgress::Pending);
                };
                let snapshot = stream.sequence.snapshot();
                // These are the immutable obligations established by the
                // initial pair.  Do not feed stale peer snapshots back into
                // `reconcile`: ACKs received after SNAPSHOT are legitimate
                // progress, not an ACK regression.
                for (direction, remote) in [
                    (Direction::RelayToConnector, relay_entry),
                    (Direction::ConnectorToRelay, connector_entry),
                ] {
                    let local = snapshot.direction(direction);
                    if local.recv_contiguous < remote.last_emitted
                        || local.peer_acked < local.last_emitted
                    {
                        // The peer prefix or our sender ACK obligation is not
                        // complete yet.  Housekeeping and retained replay are
                        // handled by the normal candidate path; retry here
                        // after each accepted frame.
                        return Ok(RecoveryReadyProgress::Pending);
                    }
                }
                entries[0].push(
                    tunnel_protocol::rotation_control::ResumeDirectionState::from_sequence_snapshot(
                        *stream_id,
                        snapshot.direction(Direction::RelayToConnector),
                    )
                    .map_err(|error| RelayError::Protocol(error.to_string()))?,
                );
                entries[1].push(
                    tunnel_protocol::rotation_control::ResumeDirectionState::from_sequence_snapshot(
                        *stream_id,
                        snapshot.direction(Direction::ConnectorToRelay),
                    )
                    .map_err(|error| RelayError::Protocol(error.to_string()))?,
                );
            }
            let remaining_ms = Self::recovery_remaining_ms(rotation, monotonic_millis());
            if remaining_ms == 0 {
                return Err(RelayError::Conflict("recovery deadline elapsed"));
            }
            let mut messages = Vec::with_capacity(2);
            for direction in [Direction::RelayToConnector, Direction::ConnectorToRelay] {
                let index = direction_index(direction);
                let message = wire::resume(
                    &sources[index],
                    attempt.clone(),
                    &roster.snapshot_id,
                    ResumeStage::Ready,
                    direction,
                    entries[index].clone(),
                    remaining_ms,
                );
                let encoded = wire::encode_control_message(&message)
                    .map_err(|error| RelayError::Protocol(error.to_string()))?;
                messages.push((index, message, encoded));
            }
            Some((attempt, entries, messages))
        };
        let Some((attempt, entries, messages)) = prepared else {
            return Ok(RecoveryReadyProgress::Pending);
        };
        let Some(session) = self.session_mut(key) else {
            return Err(RelayError::NotFound);
        };
        let Some(rotation) = session.rotation.as_mut() else {
            return Err(RelayError::Conflict("recovery state is unavailable"));
        };
        if rotation.attempt.as_ref() != Some(&attempt) {
            return Ok(RecoveryReadyProgress::Pending);
        }
        if rotation.recovery.is_none() {
            return Err(RelayError::Conflict("recovery state is unavailable"));
        }
        for (_, message, encoded) in &messages {
            Self::complete_rotation_reply(rotation, message, encoded)
                .map_err(|error| RelayError::Protocol(error.to_string()))?;
            queue_control(&session.control_tx, &session.queue_budget, encoded.clone())
                .map_err(|_| RelayError::Overloaded("control queue is full"))?;
        }
        let recovery = rotation.recovery.as_mut().expect("recovery checked above");
        recovery.ready_snapshots = entries;
        recovery.ready_message_ids = [
            Some(messages[0].1.message_id().to_owned()),
            Some(messages[1].1.message_id().to_owned()),
        ];
        recovery.ready_sent = [true, true];
        rotation.last_message_id = messages[1].1.message_id().to_owned();
        Ok(RecoveryReadyProgress::Sent)
    }

    async fn handle_recovery_resumed(
        &mut self,
        key: &SessionKey,
        resumed: tunnel_protocol::rotation_control::Resumed,
    ) {
        let Some(session) = self.session_for(key) else {
            return;
        };
        let Some(rotation) = session.rotation.as_ref() else {
            return;
        };
        let Some(attempt) = rotation.attempt.as_ref() else {
            return;
        };
        let Some(recovery) = rotation.recovery.as_ref() else {
            return;
        };
        let index = direction_index(resumed.direction);
        let expected_reply_to = match resumed.stage {
            ResumeStage::Snapshot => recovery.resume_message_ids[index].as_deref(),
            ResumeStage::Ready => recovery.ready_message_ids[index].as_deref(),
        }
        .unwrap_or_default();
        if rotation.state.phase() != RotationPhase::Recovering
            || resumed.attempt != *attempt
            || resumed.snapshot_id != recovery.roster.snapshot_id
            || resumed.reply_to != expected_reply_to
        {
            return;
        }
        let Some(entries) = Self::recovery_entries_map(&resumed.entries, &recovery.roster) else {
            return;
        };
        match resumed.stage {
            ResumeStage::Snapshot => {
                // The empty roster is valid. Key duplicate detection by the
                // retained reply id, otherwise the first empty RESUMED is
                // mistaken for a duplicate and READY is never sent.
                if recovery.snapshot_reply_ids[index].is_some() {
                    if recovery.remote_snapshots[index] != entries {
                        return;
                    }
                    return;
                }
                if !recovery.remote_snapshots[index].is_empty() {
                    return;
                }
                let reply_id = resumed.message_id.clone();
                if let Some(session) = self.session_mut(key)
                    && let Some(rotation) = session.rotation.as_mut()
                    && let Some(recovery) = rotation.recovery.as_mut()
                {
                    recovery.remote_snapshots[index] = entries;
                    recovery.snapshot_reply_ids[index] = Some(reply_id);
                }
                let snapshot_ready = self.session_for(key).is_some_and(|session| {
                    session
                        .rotation
                        .as_ref()
                        .and_then(|rotation| rotation.recovery.as_ref())
                        .is_some_and(|recovery| {
                            recovery.snapshot_reply_ids.iter().all(Option::is_some)
                        })
                });
                if snapshot_ready {
                    self.prepare_recovery_plans(key).await;
                }
            }
            ResumeStage::Ready => {
                if !recovery.ready_sent[index] || recovery.remote_ready[index] {
                    return;
                }
                if let Some(session) = self.session_mut(key)
                    && let Some(rotation) = session.rotation.as_mut()
                    && let Some(recovery) = rotation.recovery.as_mut()
                {
                    recovery.ready_remote_snapshots[index] = entries;
                    recovery.remote_ready[index] = true;
                }
                let ready_pair = self.session_for(key).is_some_and(|session| {
                    session
                        .rotation
                        .as_ref()
                        .and_then(|rotation| rotation.recovery.as_ref())
                        .is_some_and(|recovery| recovery.remote_ready == [true, true])
                });
                if !ready_pair {
                    return;
                }
                let plans = {
                    let Some(session) = self.session_for(key) else {
                        return;
                    };
                    let Some(rotation) = session.rotation.as_ref() else {
                        return;
                    };
                    let Some(recovery) = rotation.recovery.as_ref() else {
                        return;
                    };
                    let mut plans = HashMap::with_capacity(recovery.roster.stream_ids.len());
                    let mut failed = false;
                    for stream_id in &recovery.roster.stream_ids {
                        let Some(stream) = session.streams.get(stream_id) else {
                            failed = true;
                            break;
                        };
                        let Some(relay_entry) = recovery.ready_remote_snapshots[0].get(stream_id)
                        else {
                            failed = true;
                            break;
                        };
                        let Some(connector_entry) =
                            recovery.ready_remote_snapshots[1].get(stream_id)
                        else {
                            failed = true;
                            break;
                        };
                        let peer = StreamSnapshot {
                            stream_id: *stream_id,
                            directions: [
                                direction_snapshot_from_resume(relay_entry),
                                direction_snapshot_from_resume(connector_entry),
                            ],
                        };
                        let Ok(plan) = stream.sequence.reconcile(&peer) else {
                            failed = true;
                            break;
                        };
                        if [Direction::RelayToConnector, Direction::ConnectorToRelay]
                            .into_iter()
                            .any(|direction| plan.peer_missing(direction).is_some())
                        {
                            failed = true;
                            break;
                        }
                        plans.insert(*stream_id, plan);
                    }
                    (!failed).then_some(plans)
                };
                let Some(plans) = plans else {
                    self.close_session(key, "RECOVERY_READY_CONFLICT").await;
                    return;
                };
                if let Some(session) = self.session_mut(key)
                    && let Some(rotation) = session.rotation.as_mut()
                    && let Some(recovery) = rotation.recovery.as_mut()
                {
                    recovery.local_plans = plans;
                }
                self.activate_recovery(key).await;
            }
        }
    }

    /// Reconcile both directions against the immutable connector snapshots,
    /// queue only retained relay-to-connector frames, and issue both READY
    /// decisions.  All work is actor-local and bounded; no application waiter
    /// or socket writer is awaited here.
    async fn prepare_recovery_plans(&mut self, key: &SessionKey) {
        let prepared = {
            let Some(session) = self.session_for(key) else {
                return;
            };
            let Some(rotation) = session.rotation.as_ref() else {
                return;
            };
            let Some(recovery) = rotation.recovery.as_ref() else {
                return;
            };
            if recovery.remote_snapshots.iter().any(HashMap::is_empty)
                && !recovery.roster.stream_ids.is_empty()
            {
                return;
            }
            if recovery.ready_sent != [false, false] {
                return;
            }
            let mut plans = HashMap::with_capacity(recovery.roster.stream_ids.len());
            for stream_id in &recovery.roster.stream_ids {
                let Some(stream) = session.streams.get(stream_id) else {
                    return;
                };
                let Some(relay_entry) = recovery.remote_snapshots[0].get(stream_id) else {
                    return;
                };
                let Some(connector_entry) = recovery.remote_snapshots[1].get(stream_id) else {
                    return;
                };
                let peer = StreamSnapshot {
                    stream_id: *stream_id,
                    directions: [
                        direction_snapshot_from_resume(relay_entry),
                        direction_snapshot_from_resume(connector_entry),
                    ],
                };
                let Ok(plan) = stream.sequence.reconcile(&peer) else {
                    return;
                };
                plans.insert(*stream_id, plan);
            }
            let Some(candidate) = rotation.candidate.as_ref() else {
                return;
            };
            let Some(attempt) = rotation.attempt.clone() else {
                return;
            };
            Some((
                plans,
                candidate.tx.clone(),
                session.queue_budget.clone(),
                session.key.epoch,
                attempt,
            ))
        };
        let Some((plans, candidate_tx, budget, epoch, attempt)) = prepared else {
            return;
        };
        let mut replayed = 0_u64;
        for plan in plans.values() {
            for frame in plan.replay(Direction::RelayToConnector) {
                let mut frame = frame.clone();
                frame.epoch = epoch;
                frame.generation = attempt.new_generation;
                let Ok(encoded) = frame.encode() else {
                    return;
                };
                if queue_data(&candidate_tx, &budget, encoded).is_err() {
                    return;
                }
                replayed = replayed.saturating_add(1);
            }
        }
        {
            let Some(session) = self.session_mut(key) else {
                return;
            };
            let Some(rotation) = session.rotation.as_mut() else {
                return;
            };
            if rotation.recovery.is_none() {
                return;
            }
            rotation
                .recovery
                .as_mut()
                .expect("recovery checked above")
                .local_plans = plans;
            rotation.replayed_frames = rotation.replayed_frames.saturating_add(replayed);
            session.total_replayed_frames = session.total_replayed_frames.saturating_add(replayed);
        }
        if let Err(error) = self.send_recovery_ready(key) {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                stage = "recovery_ready",
                error = %error,
            );
            self.close_session(key, "RECOVERY_READY_FAILED").await;
        }
    }

    /// Activate a recovered candidate only after both READY acknowledgements.
    /// Deferred candidate frames are released into sequence state afterwards,
    /// preserving the immutable snapshot verdicts used by the rotation model.
    async fn activate_recovery(&mut self, key: &SessionKey) {
        let verdicts = {
            let Some(session) = self.session_for(key) else {
                return;
            };
            let Some(rotation) = session.rotation.as_ref() else {
                return;
            };
            let Some(recovery) = rotation.recovery.as_ref() else {
                return;
            };
            recovery
                .local_plans
                .values()
                .map(ValidatedRecovery::from_sequence_plan)
                .collect::<Result<Vec<_>, _>>()
        };
        let Ok(verdicts) = verdicts else {
            self.close_session(key, "RECOVERY_STATE_LOST").await;
            return;
        };
        let Some((attempt, peer_snapshots)) = self.session_for(key).and_then(|session| {
            let rotation = session.rotation.as_ref()?;
            let recovery = rotation.recovery.as_ref()?;
            Some((
                rotation.attempt.clone()?,
                recovery.ready_remote_snapshots.clone(),
            ))
        }) else {
            return;
        };
        let mut deferred = VecDeque::new();
        let mut sequence_state_lost = false;
        if let Some(session) = self.session_mut(key)
            && let Some(rotation) = session.rotation.as_mut()
            && let Some(recovery) = rotation.recovery.as_mut()
        {
            if recovery.activated {
                return;
            }
            recovery.activated = true;
            deferred = std::mem::take(&mut recovery.deferred_frames);
            recovery.deferred_bytes = 0;
            for (stream_id, stream) in &mut session.streams {
                let Some(relay_entry) = peer_snapshots[0].get(stream_id) else {
                    continue;
                };
                let Some(connector_entry) = peer_snapshots[1].get(stream_id) else {
                    continue;
                };
                let peer = StreamSnapshot {
                    stream_id: *stream_id,
                    directions: [
                        direction_snapshot_from_resume(relay_entry),
                        direction_snapshot_from_resume(connector_entry),
                    ],
                };
                if stream.sequence.reconcile_and_apply(&peer).is_err() {
                    sequence_state_lost = true;
                    break;
                }
            }
        }
        if sequence_state_lost {
            self.close_session(key, "RECOVERY_STATE_LOST").await;
            return;
        }
        let recovery_ok = self.with_rotation_mut(key, |_session, rotation| {
            rotation
                .state
                .reconcile_validated(&attempt, verdicts, monotonic_millis())
                .map(|_| ())
                .map_err(|_| tunnel_protocol::rotation::RotationError::RecoveryReplayPending)
        });
        if recovery_ok.is_err() {
            self.close_session(key, "RECOVERY_STATE_LOST").await;
            return;
        }
        if let Some(session) = self.session_mut(key)
            && let Some(rotation) = session.rotation.as_mut()
            && let Some(candidate_carrier) = rotation.candidate.take()
        {
            session.active_carrier = Some(candidate_carrier);
            session.data_tx = session
                .active_carrier
                .as_ref()
                .map(|carrier| carrier.tx.clone());
            session.generation = attempt.new_generation;
            session.connection_id = attempt.new_connection_id.clone();
            Self::retain_rotation_tombstone(rotation);
            rotation.recovery = None;
            rotation.attempt = None;
            rotation.attempt_deadline_ms = None;
            rotation.snapshot_id.clear();
            rotation.prepare_message_id.clear();
            rotation.last_message_id.clear();
            rotation.abort_message_id = None;
            rotation.peer_message_id.clear();
            rotation.pending_abort_ack = None;
            Self::clear_phase_message_ids(rotation);
            rotation.remote_fences = [None, None];
            rotation.own_fence = None;
            session.last_rotation = Instant::now();
        }
        for (carrier, frame, charged) in deferred {
            if let Some(session) = self.session_mut(key)
                && let Some(stream) = session.streams.get_mut(&frame.stream_id)
            {
                release_m2_bytes(&session.queue_budget, stream, charged);
            }
            self.inbound_m2_stream_data(carrier, frame, false).await;
        }
        self.flush_recovered_records(key);
    }

    fn flush_recovered_records(&mut self, key: &SessionKey) {
        let mut queued = Vec::new();
        if let Some(session) = self.session_mut(key) {
            for (stream_id, stream) in &mut session.streams {
                queued.extend(
                    stream
                        .authorized_until
                        .filter(|deadline| *deadline > Instant::now())
                        .map(|_| {
                            std::mem::take(&mut stream.pending_records)
                                .into_iter()
                                .map(|(body, waiter)| (*stream_id, body, waiter))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default(),
                );
                stream.pending_record_bytes = 0;
            }
        }
        for (stream_id, body, waiter) in queued {
            let operation_id = self
                .session_for(key)
                .and_then(|session| session.streams.get(&stream_id))
                .map(|stream| stream.operation_id.clone())
                .unwrap_or_default();
            self.write_echo_stream(key.clone(), stream_id, operation_id, body, waiter);
        }
    }

    async fn handle_resumed(
        &mut self,
        key: &SessionKey,
        resumed: tunnel_protocol::rotation_control::Resumed,
    ) {
        self.handle_recovery_resumed(key, resumed).await;
    }

    fn with_rotation_mut<T>(
        &mut self,
        key: &SessionKey,
        function: impl FnOnce(
            &mut DeviceSession,
            &mut RotationRuntime,
        ) -> Result<T, tunnel_protocol::rotation::RotationError>,
    ) -> Result<T, tunnel_protocol::rotation::RotationError> {
        let session = self
            .sessions
            .get_mut(&key.scope())
            .filter(|session| session.key == *key)
            .ok_or(tunnel_protocol::rotation::RotationError::Closed)?;
        let rotation = session
            .rotation
            .take()
            .ok_or(tunnel_protocol::rotation::RotationError::Closed)?;
        let (result, deadline_event) = {
            let mut rotation = rotation;
            let result = function(session, &mut rotation);
            let deadline_event = match &result {
                Err(tunnel_protocol::rotation::RotationError::DeadlineExpired {
                    now,
                    deadline,
                }) => RelayActor::rotation_deadline_event(key, &rotation, *now)
                    .filter(|event| event.deadline_ms == *deadline),
                _ => None,
            };
            session.rotation = Some(rotation);
            (result, deadline_event)
        };
        if let Some(event) = deadline_event {
            self.retain_rotation_deadline_event(event);
        }
        result
    }

    async fn inbound_control(&mut self, key: SessionKey, message: ControlMessage) {
        if self.session_for(&key).is_none() {
            return;
        }
        let starts_new_rotation = matches!(&message, ControlMessage::RotateRequest(_))
            && self.session_for(&key).is_some_and(|session| {
                session.rotation.as_ref().is_some_and(|rotation| {
                    rotation.attempt.is_none() && rotation.state.phase() == RotationPhase::Active
                })
            });
        if is_rotation_message(&message) {
            if !self.rotation_context_is_valid(&key, &message) {
                return;
            }
            // The first request of a new attempt must be journaled after
            // `start_rotation` installs that attempt's fresh deadline.  The
            // admission journal may have expired while the session remained
            // idle; observing it first would incorrectly reject a valid new
            // request and then reset the journal underneath the transition.
            if !starts_new_rotation {
                if let ControlMessage::RotateRequest(request) = &message
                    && self.pending_catalog_rotation_request_matches(&key, request)
                {
                    // The first catalog-backed request owns the pending
                    // ticket and will complete its journal entry when the
                    // authority callback arrives. An identical retry before
                    // that callback must not create a second pending journal
                    // entry, or the original completion would be treated as
                    // a conflicting duplicate.
                    return;
                }
                match self.observe_rotation_message(&key, &message) {
                    RotationJournalDecision::New => {}
                    RotationJournalDecision::PendingDuplicate => return,
                    RotationJournalDecision::CompletedDuplicate(responses) => {
                        // Some phase acknowledgements have no wire reply;
                        // their completed empty journal value is still useful
                        // for suppressing redispatch, but there is nothing to
                        // enqueue on the control socket.  Progressive replies
                        // are replayed in their original append order.
                        for response in responses {
                            if response.is_empty() {
                                continue;
                            }
                            let Ok(text) = String::from_utf8(response) else {
                                self.protocol_failure(&key, "ROTATION_JOURNAL_RESPONSE")
                                    .await;
                                return;
                            };
                            let queued = self
                                .session_for(&key)
                                .map(|session| {
                                    queue_control(&session.control_tx, &session.queue_budget, text)
                                        .is_ok()
                                })
                                .unwrap_or(false);
                            if !queued {
                                self.protocol_failure(&key, "ROTATION_JOURNAL_REPLAY").await;
                                return;
                            }
                        }
                        return;
                    }
                    RotationJournalDecision::Error(error) => {
                        tracing::warn!(
                            device_id = %key.device_id,
                            session_id = %key.session_id,
                            epoch = key.epoch,
                            phase = ?self
                                .session_for(&key)
                                .and_then(|session| session.rotation.as_ref())
                                .map(|rotation| rotation.state.phase()),
                            stage = "rotation_journal_observe",
                            error = %error,
                        );
                        self.protocol_failure(&key, "ROTATION_JOURNAL_INVALID")
                            .await;
                        return;
                    }
                }
            }
        }
        match message {
            ControlMessage::OwnerFenced(fenced) => {
                self.handle_owner_fenced(&key, fenced).await;
            }
            ControlMessage::AuthorizationChallenge(challenge) => {
                self.begin_device_challenge(key, challenge);
            }
            ControlMessage::Opened(opened) => {
                if opened.session_id != key.session_id || opened.epoch != key.epoch {
                    self.protocol_failure(&key, "STALE_CONTROL").await;
                } else {
                    let detached = self
                        .session_for(&key)
                        .and_then(|session| session.streams.get(&opened.stream_id))
                        .filter(|stream| {
                            stream.operation_id == opened.operation_id
                                && stream.open_message_id == opened.reply_to
                        })
                        .map(|stream| stream.registration_dropped)
                        .unwrap_or(false);
                    if let Some(session) = self.session_mut(&key)
                        && let Some(stream) = session.streams.get_mut(&opened.stream_id)
                        && stream.operation_id == opened.operation_id
                        && stream.open_message_id == opened.reply_to
                    {
                        stream.open_pending = false;
                    }
                    if detached {
                        // The OPEN was admitted after the public registration
                        // disappeared. Reconcile it with a real local FIN;
                        // only a matching REJECTED may use no-stream FORGET.
                        // The cause recorded by the deferred close, if any,
                        // labels this exact terminal transition.
                        let cause = self
                            .session_for(&key)
                            .and_then(|session| session.streams.get(&opened.stream_id))
                            .and_then(|stream| stream.deferred_terminal_cause);
                        self.close_echo_stream_with_cause(
                            &key,
                            opened.stream_id,
                            &opened.operation_id,
                            cause,
                        );
                        let _ = self.flush_owner_stream_forgets(&key);
                    }
                }
            }
            ControlMessage::Pong(pong) => {
                if pong.session_id != key.session_id || pong.epoch != key.epoch {
                    self.protocol_failure(&key, "STALE_CONTROL").await;
                }
            }
            ControlMessage::Rejected(rejected) => {
                if rejected.session_id != key.session_id || rejected.epoch != key.epoch {
                    return;
                }
                if let Some(session) = self.session_mut(&key)
                    && session
                        .pending
                        .get(&rejected.stream_id)
                        .is_some_and(|pending| pending.operation_id == rejected.operation_id)
                    && let Some(pending) = session.pending.remove(&rejected.stream_id)
                {
                    tracing::debug!(
                        tenant_id = %session.identity.tenant_id,
                        device_id = %key.device_id,
                        session_id = %key.session_id,
                        epoch = key.epoch,
                        stream_id = rejected.stream_id,
                        operation_id = %rejected.operation_id,
                        phase = "stream_rejected",
                    );
                    release_pending_budget(session, &pending);
                    let _ = pending.response.send(EchoOutcome::Failure {
                        code: "DEVICE_REJECTED",
                        execution: "not_dispatched",
                    });
                }
                // M2 OPENs are represented by `session.streams`, not the M1
                // `pending` map. A connector can reject an OPEN after the
                // relay has returned the consumer registration; keep the
                // exact operation and OPEN correlation until an ordered owner
                // FORGET is accepted by the control queue. Never match by
                // stream ID alone, and never reclaim before that control item
                // is queued.
                let rejected_m2 = self
                    .session_for(&key)
                    .and_then(|session| session.streams.get(&rejected.stream_id))
                    .is_some_and(|stream| stream.operation_id == rejected.operation_id);
                if rejected_m2 {
                    let pending = self
                        .session_for(&key)
                        .and_then(|session| session.streams.get(&rejected.stream_id))
                        .is_some_and(|stream| {
                            stream.open_pending
                                && !stream.open_message_id.is_empty()
                                && stream.operation_id == rejected.operation_id
                                && stream.open_message_id == rejected.reply_to
                        });
                    if pending {
                        let final_state = ResumeDirectionState {
                            stream_id: rejected.stream_id,
                            ..ResumeDirectionState::default()
                        };
                        let staged = self.stage_owner_stream_forget(
                            &key,
                            rejected.stream_id,
                            &rejected.operation_id,
                            Direction::RelayToConnector,
                            final_state,
                        );
                        if !staged {
                            self.arm_owner_forget_deadline(&key);
                        }
                        let _ = self.flush_owner_stream_forgets(&key);
                    }
                }
            }
            ControlMessage::AuthorizationInvalidated(invalidated) => {
                if invalidated.session_id != key.session_id || invalidated.epoch != key.epoch {
                    return;
                }
                if let Some(session) = self.session_mut(&key)
                    && session
                        .pending
                        .get(&invalidated.stream_id)
                        .is_some_and(|pending| {
                            pending.challenge_id.as_deref()
                                == Some(invalidated.challenge_id.as_str())
                                && pending.grant.revision == invalidated.grant_revision
                        })
                    && let Some(pending) = session.pending.remove(&invalidated.stream_id)
                {
                    release_pending_budget(session, &pending);
                    let _ = pending.response.send(EchoOutcome::Failure {
                        code: "AUTHORIZATION_REVOKED",
                        execution: "not_dispatched",
                    });
                }
            }
            ControlMessage::Cancel(cancel) => {
                if cancel.session_id != key.session_id || cancel.epoch != key.epoch {
                    return;
                }
                self.cancel(&key, cancel.stream_id, cancel.operation_id);
            }
            ControlMessage::RotateRequest(request) => {
                if request.session_id == key.session_id {
                    // A data-loss request can arrive after the relay has
                    // already observed the carrier close and entered the
                    // retained recovery episode.  It is the same
                    // authenticated loss notification, not a second
                    // rotation.  Complete its journal entry with an empty
                    // response so retransmission is suppressed without
                    // issuing a fresh attempt.
                    match self.recovery_already_consumed_loss_request(&key, &request) {
                        Ok(true) => return,
                        Ok(false) => {}
                        Err(error) => {
                            tracing::warn!(
                                device_id = %key.device_id,
                                session_id = %key.session_id,
                                epoch = key.epoch,
                                stage = "rotation_journal_recovery_loss",
                                error = %error,
                            );
                            self.protocol_failure(&key, "ROTATION_JOURNAL_RECOVERY_LOSS")
                                .await;
                            return;
                        }
                    }
                    let request_message = ControlMessage::RotateRequest(request.clone());
                    let response = self.start_rotation(
                        &key,
                        Some(request.message_id.clone()),
                        "client_request",
                        Some(request_message.clone()),
                    );
                    if starts_new_rotation {
                        match response {
                            RotationStart::Started(response) => {
                                if let Err(error) = self.record_rotation_request_response(
                                    &key,
                                    &request_message,
                                    &response,
                                ) {
                                    tracing::warn!(
                                        device_id = %key.device_id,
                                        session_id = %key.session_id,
                                        epoch = key.epoch,
                                        phase = ?self
                                            .session_for(&key)
                                            .and_then(|session| session.rotation.as_ref())
                                            .map(|rotation| rotation.state.phase()),
                                        stage = "rotation_journal_complete_request",
                                        error = %error,
                                    );
                                    self.protocol_failure(&key, "ROTATION_JOURNAL_INVALID")
                                        .await;
                                }
                            }
                            RotationStart::Pending => {}
                            RotationStart::Rejected => {
                                self.protocol_failure(&key, "ROTATION_START_FAILED").await;
                            }
                            RotationStart::Failed(close_reason) => {
                                self.protocol_failure(&key, close_reason).await;
                            }
                        }
                    } else if matches!(response, RotationStart::Started(_)) {
                        self.protocol_failure(&key, "ROTATION_DUPLICATE_STATE")
                            .await;
                    } else if let RotationStart::Failed(close_reason) = response {
                        self.protocol_failure(&key, close_reason).await;
                    }
                }
            }
            ControlMessage::RotateFrozen(frozen) => {
                self.handle_rotate_frozen(&key, frozen).await;
            }
            ControlMessage::RotateDrained(drained) => {
                self.handle_rotate_drained(&key, drained).await;
            }
            ControlMessage::RotateCommitted(committed) => {
                self.handle_rotate_committed(&key, committed).await;
            }
            ControlMessage::RotateRetired(retired) => {
                self.handle_rotate_retired(&key, retired).await;
            }
            ControlMessage::RotateAbort(_) => {
                // The relay is the owner and the only endpoint permitted to
                // decide ABORT.  An authenticated connector must acknowledge
                // our decision with ROTATE_ABORTED; an inbound ABORT is a
                // protocol violation rather than a second state transition.
                self.protocol_failure(&key, "UNEXPECTED_ROTATE_ABORT").await;
            }
            ControlMessage::RotateAborted(aborted) => {
                self.handle_rotate_aborted(&key, aborted).await;
            }
            ControlMessage::RecoveryClosed(closed) => {
                self.handle_recovery_closed(&key, closed).await;
            }
            ControlMessage::RecoveryBegin(_) => {
                // The relay is the recovery coordinator.  A connector cannot
                // introduce a second episode or replace the immutable roster.
                self.protocol_failure(&key, "UNEXPECTED_RECOVERY_BEGIN")
                    .await;
            }
            ControlMessage::Resumed(resumed) => {
                self.handle_resumed(&key, resumed).await;
            }
            ControlMessage::StreamForget(_) => {
                // STREAM_FORGET is owner-originated reclamation. The relay
                // owns this actor and must never let the connector erase a
                // retained tombstone or clear terminal-send debt by sending
                // a forged opposite-direction cursor proof. Fail closed at
                // the authenticated session boundary instead.
                self.protocol_failure(&key, "UNEXPECTED_STREAM_FORGET")
                    .await;
            }
            ControlMessage::Ping(ping) => {
                if ping.session_id != key.session_id || ping.epoch != key.epoch {
                    self.protocol_failure(&key, "STALE_CONTROL").await;
                } else {
                    let pong = ControlMessage::Pong(tunnel_protocol::Pong::new(
                        wire::random_token(),
                        ping.message_id,
                        key.session_id.clone(),
                        key.epoch,
                        ping.nonce,
                    ));
                    let _ = self.send_control(&key, pong);
                }
            }
            _ => {
                let _ = self.send_control(
                    &key,
                    wire::rejected(
                        &wire::random_token(),
                        &key.session_id,
                        key.epoch,
                        1,
                        "control",
                        "UNKNOWN_CONTROL",
                        "unsupported control message",
                    ),
                );
            }
        }
    }

    fn recovery_already_consumed_loss_request(
        &mut self,
        key: &SessionKey,
        request: &tunnel_protocol::rotation_control::RotateRequest,
    ) -> Result<bool, JournalError> {
        let matches_recovery = self.session_for(key).is_some_and(|session| {
            request.reason.as_deref() == Some("data_loss")
                && request.generation == session.generation
                && request.connection_id == session.connection_id
                && session
                    .rotation
                    .as_ref()
                    .is_some_and(|rotation| rotation.state.phase() == RotationPhase::Recovering)
        });
        if !matches_recovery {
            return Ok(false);
        }
        let Some(session) = self.session_mut(key) else {
            return Err(JournalError::MissingMessage);
        };
        let Some(rotation) = session.rotation.as_mut() else {
            return Err(JournalError::MissingMessage);
        };
        Self::complete_rotation_entry(rotation, &request.message_id, &[]).map(|()| true)
    }

    fn pending_catalog_rotation_request_matches(
        &self,
        key: &SessionKey,
        request: &tunnel_protocol::rotation_control::RotateRequest,
    ) -> bool {
        self.session_for(key)
            .and_then(|session| session.rotation.as_ref())
            .and_then(|rotation| rotation.pending_ticket.as_ref())
            .is_some_and(|pending| {
                pending.attempt.old_generation == request.generation
                    && pending.attempt.old_connection_id == request.connection_id
                    && matches!(
                        pending.request.as_ref(),
                        Some(ControlMessage::RotateRequest(pending_request))
                            if pending_request == request
                    )
            })
    }

    fn rotation_context_is_valid(&self, key: &SessionKey, message: &ControlMessage) -> bool {
        let Some(session) = self.session_for(key) else {
            return false;
        };
        let Some(rotation) = session.rotation.as_ref() else {
            return false;
        };
        if let Some(attempt) = Self::message_attempt(message) {
            if attempt.session_id != key.session_id
                || attempt.epoch != key.epoch
                || attempt.owner_id != runtime::owner_id(&session.owner)
            {
                return false;
            }
            let now_ms = monotonic_millis();
            return rotation.attempt.as_ref() == Some(attempt)
                || rotation.tombstones.iter().any(|tombstone| {
                    tombstone.deadline_ms > now_ms && tombstone.attempt == *attempt
                });
        }
        match message {
            ControlMessage::RotateRequest(request) => {
                request.session_id == key.session_id
                    && request.epoch == key.epoch
                    && request.owner_id == runtime::owner_id(&session.owner)
                    && request.generation == session.generation
                    && request.connection_id == session.connection_id
            }
            ControlMessage::StreamForget(value) => {
                value.session_id == key.session_id && value.epoch == key.epoch
            }
            _ => false,
        }
    }

    fn begin_device_challenge(&mut self, key: SessionKey, message: AuthorizationChallenge) {
        if message.session_id != key.session_id || message.epoch != key.epoch {
            return;
        }
        let service_id = message.service_id.clone();
        let challenge = DeviceChallenge {
            message_id: message.message_id,
            stream_id: message.stream_id,
            service_id,
            challenge_id: message.challenge_id,
            nonce: message.nonce,
            permission_digest: message.permission_digest,
            grant_revision: message.grant_revision,
            received_at: Instant::now(),
            lifetime: self.options.challenge_interval.min(AUTHORIZATION_LIFETIME),
        };
        let authorization_started_at_ms = monotonic_millis();
        let authorization_deadline_ms = authorization_started_at_ms
            .saturating_add(u64::try_from(challenge.lifetime.as_millis()).unwrap_or(u64::MAX));
        // Which in-flight record rejected a mismatched challenge.  The pending
        // and admitted-stream paths carry different typed refusals, and both
        // must be applied after the session borrow below ends.
        enum MismatchedChallenge {
            Pending,
            Stream,
        }
        let mut mismatched = None;
        let Some(session) = self.session_mut(&key) else {
            return;
        };
        let resolved = if let Some(pending) = session.pending.get_mut(&message.stream_id) {
            if pending.dispatched || pending.authorization_in_flight {
                return;
            }
            let expected_digest =
                wire::permission_digest(&pending.grant, &pending.service_id.to_string());
            if challenge.permission_digest != expected_digest
                || challenge.grant_revision != pending.grant.revision
                || challenge.service_id != pending.service_id.to_string()
            {
                mismatched = Some(MismatchedChallenge::Pending);
                None
            } else {
                pending.authorization_in_flight = true;
                pending.challenge_id = Some(challenge.challenge_id.clone());
                Some((
                    pending.consumer.clone(),
                    pending.service_id,
                    pending.grant.read_started_at,
                    session.identity.spki_fingerprint.clone(),
                ))
            }
        } else if let Some(stream) = session.streams.get_mut(&message.stream_id) {
            if stream.authorization_in_flight || stream.terminal {
                return;
            }
            let expected_digest =
                wire::permission_digest(&stream.grant, &stream.service_id.to_string());
            if challenge.permission_digest != expected_digest
                || challenge.grant_revision != stream.grant.revision
                || challenge.service_id != stream.service_id.to_string()
            {
                mismatched = Some(MismatchedChallenge::Stream);
                None
            } else {
                stream.open_pending = false;
                stream.authorization_in_flight = true;
                stream.authorization_started_at_ms = Some(authorization_started_at_ms);
                stream.authorization_deadline_ms = Some(authorization_deadline_ms);
                stream.challenge_id = Some(challenge.challenge_id.clone());
                Some((
                    stream.consumer.clone(),
                    stream.service_id,
                    // A streaming challenge is a fresh authorization read.
                    // Redis bounds the catalog read to five seconds from
                    // `read_started_at`; reusing the initial grant's start
                    // time would make every later refresh appear stale even
                    // when the consumer and grant are still valid.
                    Utc::now(),
                    session.identity.spki_fingerprint.clone(),
                ))
            }
        } else {
            return;
        };
        // A mismatched challenge can never be confirmed, so the operation must
        // not keep waiting for its authorization deadline.  Both refusals reuse
        // the existing closed authorization-failure vocabulary: the reason maps
        // to `AUTHORIZATION_INVALIDATED` and the waiters receive the existing
        // `AUTHORIZATION_REVOKED` outcome.  The reason is a fixed literal, so no
        // payload or credential reaches the diagnostic.
        let Some((consumer, service_id, read_started_at, spki)) = resolved else {
            match mismatched {
                Some(MismatchedChallenge::Pending) => self.invalidate_pending(
                    &key,
                    message.stream_id,
                    &challenge,
                    CHALLENGE_MISMATCH_REASON,
                ),
                Some(MismatchedChallenge::Stream) => {
                    self.invalidate_stream_challenge(&key, &challenge, CHALLENGE_MISMATCH_REASON);
                }
                None => {}
            }
            return;
        };
        let catalog = self.catalog.clone();
        let command_tx = self.command_tx.clone();
        let cancel = self.options.shutdown.clone();
        self.spawn_background(async move {
            let result = async {
                let current = catalog
                    .authorize(
                        &consumer,
                        key.device_id,
                        service_id,
                        read_started_at,
                        Utc::now(),
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let Some(current) = current else {
                    return Ok((None, None, None, None));
                };
                let owner = catalog
                    .current_owner(current.tenant_id, key.device_id, Utc::now())
                    .await
                    .map_err(|error| error.to_string())?;
                let owner_deadline = owner.as_ref().and_then(|claim| {
                    (claim.lease_expires_at - Utc::now())
                        .to_std()
                        .ok()
                        .and_then(|remaining| remaining.checked_sub(OWNER_LEASE_SAFETY_MARGIN))
                        .map(|remaining| Instant::now() + remaining)
                });
                let identity = catalog
                    .resolve_device(&spki, Utc::now())
                    .await
                    .map_err(|error| error.to_string())?;
                Ok((Some(current), owner, identity, owner_deadline))
            }
            .await;
            send_background_command(
                &cancel,
                &command_tx,
                Command::ChallengeAuthorized {
                    key,
                    challenge,
                    result,
                },
            )
            .await;
        });
    }

    fn finish_device_challenge(
        &mut self,
        key: SessionKey,
        challenge: DeviceChallenge,
        result: ChallengeAuthorizationResult,
    ) {
        let pending_exists = self
            .session_for(&key)
            .is_some_and(|session| session.pending.contains_key(&challenge.stream_id));
        if !pending_exists {
            self.finish_stream_challenge(key, challenge, result);
            return;
        }
        let Some(session) = self.session_for(&key) else {
            return;
        };
        let Some(pending) = session.pending.get(&challenge.stream_id) else {
            return;
        };
        if !pending.authorization_in_flight
            || pending.dispatched
            || pending.grant.revision != challenge.grant_revision
            || pending.service_id.to_string() != challenge.service_id
        {
            return;
        }
        let consumer_expires_at = pending.consumer_expires_at;
        let (current, owner, identity, owner_deadline) = match result {
            Ok(value) => value,
            Err(_) => {
                self.invalidate_pending(
                    &key,
                    challenge.stream_id,
                    &challenge,
                    "authorization unavailable",
                );
                return;
            }
        };
        let Some(current) = current else {
            self.invalidate_pending(&key, challenge.stream_id, &challenge, "grant unavailable");
            return;
        };
        let Some(owner) = owner else {
            self.invalidate_pending(&key, challenge.stream_id, &challenge, "owner unavailable");
            return;
        };
        let Some(identity) = identity else {
            self.invalidate_pending(
                &key,
                challenge.stream_id,
                &challenge,
                "device authorization unavailable",
            );
            return;
        };
        let now_wall = Utc::now();
        let Some(session) = self.session_for(&key) else {
            return;
        };
        if owner.token != session.owner
            || identity.tenant_id != key.tenant_id
            || identity.device_id != key.device_id
            || identity.spki_fingerprint != session.identity.spki_fingerprint
            || identity.device_version != session.identity.device_version
            || identity.owner_epoch != session.owner.epoch
            || !identity.device_active
            || !identity.credential_active
            || identity.credential_revoked_at.is_some()
            || identity.expires_at <= now_wall
            || current.tenant_id != key.tenant_id
            || current.device_id != key.device_id
            || current.revision != challenge.grant_revision
            || wire::permission_digest(&current, &challenge.service_id)
                != challenge.permission_digest
            || current.valid_until <= now_wall
        {
            self.invalidate_pending(
                &key,
                challenge.stream_id,
                &challenge,
                "authorization changed",
            );
            return;
        }
        let challenge_remaining = challenge
            .lifetime
            .checked_sub(challenge.received_at.elapsed())
            .unwrap_or_default();
        let snapshot_remaining = (current.valid_until - now_wall)
            .to_std()
            .unwrap_or_default();
        let token_remaining = (consumer_expires_at - now_wall)
            .to_std()
            .unwrap_or_default();
        let owner_remaining = owner_deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_default();
        let credential_remaining = (identity.expires_at - now_wall)
            .to_std()
            .unwrap_or_default();
        let remaining = challenge_remaining
            .min(snapshot_remaining)
            .min(token_remaining)
            .min(owner_remaining)
            .min(credential_remaining);
        let remaining_ms = remaining.as_millis().min(5_000) as u64;
        if remaining_ms == 0 {
            self.invalidate_pending(
                &key,
                challenge.stream_id,
                &challenge,
                "authorization expired",
            );
            return;
        }
        let dispatch_deadline = Instant::now() + Duration::from_millis(remaining_ms);
        let owner_safe_until = owner.lease_expires_at
            - ChronoDuration::from_std(OWNER_LEASE_SAFETY_MARGIN)
                .unwrap_or_else(|_| ChronoDuration::seconds(5));
        let grant_read_started_at = current.read_started_at;
        let authorization_is_live = || {
            let now = Utc::now();
            Instant::now() < dispatch_deadline
                && now >= grant_read_started_at
                && now < current.valid_until
                && now < consumer_expires_at
                && now < identity.expires_at
                && now < owner_safe_until
        };

        if self
            .session_for(&key)
            .and_then(|session| session.data_tx.as_ref())
            .is_none()
        {
            self.fail_pending(
                &key,
                challenge.stream_id,
                "DEVICE_OFFLINE",
                "not_dispatched",
            );
            return;
        }
        let (control_tx, data_tx, queue_budget, generation, send_sequence, body) = {
            let Some(session) = self.session_for(&key) else {
                return;
            };
            let Some(pending) = session.pending.get(&challenge.stream_id) else {
                return;
            };
            let data_tx = session.data_tx.clone().expect("data socket checked above");
            (
                session.control_tx.clone(),
                data_tx,
                session.queue_budget.clone(),
                session.generation,
                pending.send_sequence,
                pending.body.clone(),
            )
        };
        if data_tx.is_closed() {
            self.fail_pending(
                &key,
                challenge.stream_id,
                "DEVICE_OFFLINE",
                "not_dispatched",
            );
            return;
        }
        let confirmed = wire::authorization_confirmed(wire::AuthorizationConfirmation {
            reply_to: &challenge.message_id,
            session_id: &key.session_id,
            epoch: key.epoch,
            stream_id: challenge.stream_id,
            challenge_id: &challenge.challenge_id,
            nonce: &challenge.nonce,
            permission_digest: &challenge.permission_digest,
            grant_revision: challenge.grant_revision,
            remaining_ms,
        });
        let Ok(confirmed) = wire::encode_control_message(&confirmed) else {
            self.fail_pending(&key, challenge.stream_id, "CONTROL_LIMIT", "not_dispatched");
            return;
        };
        let frame = match wire::data_frame(
            key.epoch,
            generation,
            challenge.stream_id,
            send_sequence,
            body,
        ) {
            Ok(frame) => frame,
            Err(_) => {
                self.fail_pending(&key, challenge.stream_id, "FRAME_LIMIT", "not_dispatched");
                return;
            }
        };
        let fin_sequence = match send_sequence.checked_add(1) {
            Some(sequence) => sequence,
            None => {
                self.fail_pending(&key, challenge.stream_id, "STREAM_LIMIT", "not_dispatched");
                return;
            }
        };
        let fin = match wire::fin_frame(key.epoch, generation, challenge.stream_id, fin_sequence) {
            Ok(frame) => frame,
            Err(_) => {
                self.fail_pending(&key, challenge.stream_id, "FRAME_LIMIT", "not_dispatched");
                return;
            }
        };
        if !authorization_is_live() {
            self.invalidate_pending(
                &key,
                challenge.stream_id,
                &challenge,
                "authorization expired",
            );
            return;
        }
        if queue_control(&control_tx, &queue_budget, confirmed).is_err() {
            self.fail_pending(
                &key,
                challenge.stream_id,
                "CONTROL_UNAVAILABLE",
                "not_dispatched",
            );
            return;
        }
        if !authorization_is_live() {
            self.invalidate_pending(
                &key,
                challenge.stream_id,
                &challenge,
                "authorization expired",
            );
            return;
        }
        if queue_data(&data_tx, &queue_budget, frame).is_err() {
            self.fail_pending(
                &key,
                challenge.stream_id,
                "REVERSE_CHANNEL_UNAVAILABLE",
                "unknown",
            );
            let _ = data_tx.try_send(DataOutbound::Close);
            let _ = control_tx.try_send(ControlOutbound::Close);
            let _ = self
                .command_tx
                .try_send(Command::DisconnectControl(key.clone()));
            return;
        }
        if queue_data(&data_tx, &queue_budget, fin).is_err() {
            self.fail_pending(
                &key,
                challenge.stream_id,
                "REVERSE_CHANNEL_UNAVAILABLE",
                "unknown",
            );
            let _ = data_tx.try_send(DataOutbound::Close);
            let _ = control_tx.try_send(ControlOutbound::Close);
            let _ = self
                .command_tx
                .try_send(Command::DisconnectControl(key.clone()));
            return;
        }
        let mut application_dispatched = false;
        if let Some(session) = self.session_mut(&key)
            && let Some(pending) = session.pending.get_mut(&challenge.stream_id)
        {
            let body_len = pending.body.len();
            pending.body.clear();
            pending.authorization_in_flight = false;
            pending.dispatched = true;
            session.queued_bytes = session.queued_bytes.saturating_sub(body_len);
            session.queue_budget.release(body_len);
            application_dispatched = true;
        }
        if application_dispatched {
            // Count the owner-local non-stream request only after the
            // authenticated body and FIN are both queued successfully.  This
            // is the same logical-dispatch boundary used by M2 records and
            // prevents failed authorization/queue paths or duplicate control
            // observations from inflating no-dispatch evidence.
            self.record_application_dispatch();
        }
    }

    fn finish_stream_challenge(
        &mut self,
        key: SessionKey,
        challenge: DeviceChallenge,
        result: ChallengeAuthorizationResult,
    ) {
        let Some((grant, consumer_expires_at, challenge_id)) = self
            .session_for(&key)
            .and_then(|session| session.streams.get(&challenge.stream_id))
            .filter(|stream| {
                stream.authorization_in_flight
                    && !stream.terminal
                    && stream.grant.revision == challenge.grant_revision
                    && stream.service_id.to_string() == challenge.service_id
            })
            .map(|stream| {
                (
                    stream.grant.clone(),
                    stream.consumer_expires_at,
                    stream.challenge_id.clone(),
                )
            })
        else {
            return;
        };
        if challenge_id.as_deref() != Some(challenge.challenge_id.as_str()) {
            return;
        }
        let (current, owner, identity, owner_deadline) = match result {
            Ok(value) => value,
            Err(_) => {
                self.invalidate_stream_challenge(&key, &challenge, "authorization unavailable");
                return;
            }
        };
        let Some(current) = current else {
            self.invalidate_stream_challenge(&key, &challenge, "grant unavailable");
            return;
        };
        let Some(owner) = owner else {
            self.invalidate_stream_challenge(&key, &challenge, "owner unavailable");
            return;
        };
        let Some(identity) = identity else {
            self.invalidate_stream_challenge(&key, &challenge, "device authorization unavailable");
            return;
        };
        // Anchor the confirmation before reading the wall clock that bounds
        // `remaining_ms`.  The retained admission deadline and dispatch gate
        // then never postdate the earliest real deadline they were derived
        // from, so an `AUTHORIZATION_EXPIRED` terminal can only be observed
        // at or after the retained deadline, never before it.
        let confirmed_at = Instant::now();
        let now_wall = Utc::now();
        let valid = self.session_for(&key).is_some_and(|session| {
            owner.token == session.owner
                && identity.tenant_id == key.tenant_id
                && identity.device_id == key.device_id
                && identity.spki_fingerprint == session.identity.spki_fingerprint
                && identity.device_version == session.identity.device_version
                && identity.owner_epoch == session.owner.epoch
                && identity.device_active
                && identity.credential_active
                && identity.credential_revoked_at.is_none()
                && identity.expires_at > now_wall
                && current.tenant_id == key.tenant_id
                && current.device_id == key.device_id
                && current.revision == challenge.grant_revision
                && wire::permission_digest(&current, &challenge.service_id)
                    == challenge.permission_digest
                && current.valid_until > now_wall
                && grant.tenant_id == current.tenant_id
                && grant.service_id == current.service_id
        });
        if !valid {
            self.invalidate_stream_challenge(&key, &challenge, "authorization changed");
            return;
        }
        let challenge_remaining = challenge
            .lifetime
            .checked_sub(challenge.received_at.elapsed())
            .unwrap_or_default();
        let snapshot_remaining = (current.valid_until - now_wall)
            .to_std()
            .unwrap_or_default();
        let token_remaining = (consumer_expires_at - now_wall)
            .to_std()
            .unwrap_or_default();
        let owner_remaining = owner_deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_default();
        let credential_remaining = (identity.expires_at - now_wall)
            .to_std()
            .unwrap_or_default();
        let remaining_ms = challenge_remaining
            .min(snapshot_remaining)
            .min(token_remaining)
            .min(owner_remaining)
            .min(credential_remaining)
            .as_millis()
            .min(5_000) as u64;
        if remaining_ms == 0 {
            self.invalidate_stream_challenge(&key, &challenge, "authorization expired");
            return;
        }
        let confirmation = wire::authorization_confirmed(wire::AuthorizationConfirmation {
            reply_to: &challenge.message_id,
            session_id: &key.session_id,
            epoch: key.epoch,
            stream_id: challenge.stream_id,
            challenge_id: &challenge.challenge_id,
            nonce: &challenge.nonce,
            permission_digest: &challenge.permission_digest,
            grant_revision: challenge.grant_revision,
            remaining_ms,
        });
        if self.send_control(&key, confirmation).is_err() {
            self.invalidate_stream_challenge(&key, &challenge, "control unavailable");
            return;
        }
        let pending = if let Some(session) = self.session_mut(&key)
            && let Some(stream) = session.streams.get_mut(&challenge.stream_id)
        {
            stream.authorization_in_flight = false;
            stream.authorization_started_at_ms = None;
            stream.authorization_deadline_ms = None;
            let authorized_until = confirmed_at + Duration::from_millis(remaining_ms);
            stream.authorization_admission_deadline_ms =
                Some(runtime::monotonic_millis_at(confirmed_at).saturating_add(remaining_ms));
            stream.authorized_until = Some(authorized_until);
            stream.challenge_id = Some(challenge.challenge_id);
            stream.grant = current;
            let pending_bytes = stream.pending_record_bytes;
            stream.pending_record_bytes = 0;
            session.queue_budget.release(pending_bytes);
            stream.budget_bytes = stream.budget_bytes.saturating_sub(pending_bytes);
            std::mem::take(&mut stream.pending_records)
        } else {
            VecDeque::new()
        };
        let operation_id = self
            .session_for(&key)
            .and_then(|session| session.streams.get(&challenge.stream_id))
            .map(|stream| stream.operation_id.clone())
            .unwrap_or_default();
        for (body, waiter) in pending {
            self.write_echo_stream(
                key.clone(),
                challenge.stream_id,
                operation_id.clone(),
                body,
                waiter,
            );
        }
    }

    fn authorization_failure_code(reason: &str) -> &'static str {
        match reason {
            "authorization expired" => "AUTHORIZATION_EXPIRED",
            "authorization changed" => "AUTHORIZATION_CHANGED",
            "authorization unavailable" | "control unavailable" => "AUTHORIZATION_UNAVAILABLE",
            "grant unavailable" => "GRANT_UNAVAILABLE",
            "owner unavailable" => "OWNER_UNAVAILABLE",
            "device authorization unavailable" => "DEVICE_AUTHORIZATION_UNAVAILABLE",
            _ => "AUTHORIZATION_INVALIDATED",
        }
    }

    fn invalidate_stream_challenge(
        &mut self,
        key: &SessionKey,
        challenge: &DeviceChallenge,
        reason: &str,
    ) {
        let _ = self.send_control(
            key,
            wire::authorization_invalidated(
                &key.session_id,
                key.epoch,
                challenge.stream_id,
                &challenge.challenge_id,
                challenge.grant_revision,
                reason,
            ),
        );
        let invalidated_stream = self
            .session_for(key)
            .is_some_and(|session| session.streams.contains_key(&challenge.stream_id));
        let mut transitioned = false;
        if let Some(session) = self.session_mut(key)
            && let Some(stream) = session.streams.get_mut(&challenge.stream_id)
        {
            stream.authorization_failure_code = Some(Self::authorization_failure_code(reason));
            stream.authorization_in_flight = false;
            stream.authorization_started_at_ms = None;
            stream.authorization_deadline_ms = None;
            stream.authorization_admission_deadline_ms = None;
            stream.authorized_until = None;
            transitioned = !stream.terminal;
            stream.terminal = true;
            stream.terminal_fin_failure = true;
            let pending_bytes = stream.pending_record_bytes;
            stream.pending_record_bytes = 0;
            let response_bytes = stream.response_bytes.len();
            stream.response_bytes.clear();
            session
                .queue_budget
                .release(pending_bytes.saturating_add(response_bytes));
            stream.budget_bytes = stream
                .budget_bytes
                .saturating_sub(pending_bytes.saturating_add(response_bytes));
            for (_, waiter) in std::mem::take(&mut stream.pending_records) {
                let _ = waiter.send(Err(EchoOutcome::Failure {
                    code: "AUTHORIZATION_REVOKED",
                    execution: "not_dispatched",
                }));
            }
            for waiter in std::mem::take(&mut stream.response_records) {
                let _ = waiter.send(Err(EchoOutcome::Failure {
                    code: "AUTHORIZATION_REVOKED",
                    execution: "unknown",
                }));
            }
            stream.closed.cancel();
        }
        if transitioned
            && let Some(operation_id) = self
                .session_for(key)
                .and_then(|session| session.streams.get(&challenge.stream_id))
                .map(|stream| stream.operation_id.clone())
            && let Some(event) = self.stream_terminal_event(
                key,
                challenge.stream_id,
                &operation_id,
                "AUTHORIZATION_REVOKED",
                None,
            )
        {
            self.retain_stream_terminal_event(event);
        }
        if invalidated_stream {
            self.arm_terminal_fin_failure_deadline(key);
        }
    }

    async fn inbound_data(&mut self, carrier: CarrierKey, bytes: Vec<u8>) {
        let key = carrier.session.clone();
        if bytes.len() > tunnel_protocol::frame::MAX_FRAME_LEN {
            return self.protocol_failure(&key, "FRAME_LIMIT").await;
        }
        let frame = match wire::decode_frame(&bytes) {
            Ok(frame) => frame,
            Err(_) => return self.protocol_failure(&key, "INVALID_FRAME").await,
        };
        let Some(session) = self.session_for(&key) else {
            return;
        };
        if frame.epoch != key.epoch
            || frame.generation != carrier.generation
            || frame.generation != session.generation
                && session
                    .active_carrier
                    .as_ref()
                    .is_some_and(|active| active.context.connection_id == carrier.connection_id)
        {
            return self.protocol_failure(&key, "STALE_DATA").await;
        }
        let carrier_is_active = session
            .active_carrier
            .as_ref()
            .is_some_and(|active| active.context == carrier.context());
        let carrier_is_candidate = session
            .rotation
            .as_ref()
            .and_then(|rotation| rotation.candidate.as_ref())
            .is_some_and(|candidate| candidate.context == carrier.context());
        if !carrier_is_active && !carrier_is_candidate {
            // Delayed bytes from a retired generation are ignored at the
            // carrier boundary; they cannot reach stream state.
            return;
        }
        let stream_is_known = session.streams.contains_key(&frame.stream_id)
            || session.pending.contains_key(&frame.stream_id);
        if !stream_is_known && frame.stream_id <= session.forgotten_stream_through {
            // An authenticated owner FORGET has already compacted this
            // monotonic stream ID. Late DATA/FIN/RESET cannot be allowed to
            // turn an expected stale frame into a session-wide UNKNOWN_STREAM
            // failure or affect a successor stream.
            return;
        }
        if session.profile.supports_rotation()
            && self
                .session_for(&key)
                .is_some_and(|session| session.streams.contains_key(&frame.stream_id))
        {
            self.inbound_m2_stream_data(carrier, frame, carrier_is_candidate)
                .await;
            return;
        }
        let stream_id = frame.stream_id;
        let max_response_bytes = self
            .options
            .limits
            .max_body_bytes
            .saturating_add(MAX_ECHO_RESPONSE_EXTRA_BYTES);
        match frame.kind {
            FrameKind::Data | FrameKind::Fin => {
                if !self
                    .session_for(&key)
                    .is_some_and(|session| session.pending.contains_key(&stream_id))
                {
                    return self.protocol_failure(&key, "UNKNOWN_STREAM").await;
                }
                let (update, data_tx, queue_budget, tenant_id, operation_id) = {
                    let Some(session) = self.session_mut(&key) else {
                        return;
                    };
                    let Some(pending) = session.pending.get_mut(&stream_id) else {
                        return;
                    };
                    let data_tx = if carrier_is_candidate {
                        session
                            .rotation
                            .as_ref()
                            .and_then(|rotation| rotation.candidate.as_ref())
                            .map(|candidate| candidate.tx.clone())
                    } else {
                        session.data_tx.clone()
                    };
                    let queue_budget = session.queue_budget.clone();
                    let tenant_id = session.identity.tenant_id;
                    let operation_id = pending.operation_id.clone();
                    let invalid_frame = !pending.dispatched
                        || frame.ack > pending.send_sequence.saturating_add(1)
                        || frame.sequence <= pending.response_sequence
                        || frame.sequence != pending.response_sequence.saturating_add(1)
                        || (frame.kind == FrameKind::Data
                            && (pending
                                .response_body
                                .len()
                                .saturating_add(frame.payload.len())
                                > max_response_bytes
                                || !queue_budget.reserve(frame.payload.len())));
                    if invalid_frame {
                        (
                            ResponseFrameUpdate::Invalid,
                            data_tx,
                            queue_budget,
                            tenant_id,
                            operation_id,
                        )
                    } else {
                        pending.response_sequence = frame.sequence;
                        if frame.kind == FrameKind::Data {
                            pending.response_body.extend_from_slice(&frame.payload);
                            (
                                ResponseFrameUpdate::Accepted,
                                data_tx,
                                queue_budget,
                                tenant_id,
                                operation_id,
                            )
                        } else {
                            let body = std::mem::take(&mut pending.response_body);
                            let pending = session
                                .pending
                                .remove(&stream_id)
                                .expect("pending entry exists");
                            let released = pending.body.len().saturating_add(body.len());
                            session.queued_bytes = session.queued_bytes.saturating_sub(released);
                            session.queue_budget.release(released);
                            (
                                ResponseFrameUpdate::Complete(body, pending.response),
                                data_tx,
                                queue_budget,
                                tenant_id,
                                operation_id,
                            )
                        }
                    }
                };
                if matches!(&update, ResponseFrameUpdate::Accepted)
                    && let Some(session) = self.session_mut(&key)
                {
                    session.queued_bytes = session.queued_bytes.saturating_add(frame.payload.len());
                }
                let ack_sequence = match &update {
                    ResponseFrameUpdate::Accepted | ResponseFrameUpdate::Complete(_, _) => {
                        frame.sequence
                    }
                    ResponseFrameUpdate::Invalid => {
                        self.protocol_failure(&key, "INVALID_SEQUENCE").await;
                        return;
                    }
                };
                let Some(data_tx) = data_tx else {
                    if let ResponseFrameUpdate::Complete(_, response) = update {
                        let _ = response.send(EchoOutcome::Failure {
                            code: "DEVICE_OFFLINE",
                            execution: "unknown",
                        });
                    }
                    self.protocol_failure(&key, "DEVICE_OFFLINE").await;
                    return;
                };
                let Ok(ack) = tunnel_protocol::Frame::ack(
                    key.epoch,
                    carrier.generation,
                    stream_id,
                    ack_sequence,
                )
                .encode() else {
                    self.protocol_failure(&key, "FRAME_LIMIT").await;
                    return;
                };
                if queue_data(&data_tx, &queue_budget, ack).is_err() {
                    if let ResponseFrameUpdate::Complete(_, response) = update {
                        let _ = response.send(EchoOutcome::Failure {
                            code: "REVERSE_CHANNEL_UNAVAILABLE",
                            execution: "unknown",
                        });
                    }
                    self.protocol_failure(&key, "REVERSE_CHANNEL_UNAVAILABLE")
                        .await;
                    return;
                }
                if let ResponseFrameUpdate::Complete(body, response) = update {
                    let response_bytes = body.len();
                    let _ = response.send(EchoOutcome::Success(body));
                    tracing::debug!(
                        tenant_id = %tenant_id,
                        device_id = %key.device_id,
                        session_id = %key.session_id,
                        epoch = key.epoch,
                        stream_id,
                        operation_id = %operation_id,
                        bytes = response_bytes,
                        phase = "stream_completed",
                    );
                }
            }
            FrameKind::Ack => {
                let stale_ack = self
                    .session_for(&key)
                    .and_then(|session| session.pending.get(&stream_id))
                    .is_some_and(|pending| {
                        !pending.dispatched || frame.ack > pending.send_sequence.saturating_add(1)
                    });
                if stale_ack {
                    self.protocol_failure(&key, "STALE_ACK").await;
                }
            }
            FrameKind::WindowUpdate => {
                // M1 has no receive-window state to update; the bounded queue is
                // governed by the per-session budget and the frame size limit.
            }
            FrameKind::Reset => {
                let valid_reset = self
                    .session_for(&key)
                    .and_then(|session| session.pending.get(&stream_id))
                    .is_some_and(|pending| {
                        pending.dispatched
                            && frame.ack <= pending.send_sequence.saturating_add(1)
                            && pending.response_sequence.checked_add(1) == Some(frame.sequence)
                    });
                if valid_reset {
                    self.fail_pending(&key, stream_id, "DEVICE_RESET", "unknown");
                } else {
                    self.protocol_failure(&key, "INVALID_RESET").await;
                }
            }
        }
    }

    const fn should_ack_m2_frame(kind: FrameKind) -> bool {
        matches!(kind, FrameKind::Data | FrameKind::Fin | FrameKind::Reset)
    }

    /// Apply one connector-to-relay M2 frame to the pure stream state, parse
    /// complete length-prefixed response records, and acknowledge receipt on
    /// the same physical carrier.  This method never waits for a consumer or
    /// socket writer; both response delivery and ACKs use bounded channels.
    async fn inbound_m2_stream_data(
        &mut self,
        carrier: CarrierKey,
        frame: Frame,
        carrier_is_candidate: bool,
    ) {
        let key = carrier.session.clone();
        let received_stream_id = frame.stream_id;
        let retry_stream = (!carrier_is_candidate && frame.kind == FrameKind::WindowUpdate)
            .then_some(frame.stream_id);
        let mut invalid = false;
        let mut deferred_rejected = false;
        let deferred_limit = self.options.limits.max_queue_messages;
        let mut queue: Option<(mpsc::Sender<DataOutbound>, QueueBudget, Vec<u8>)> = None;
        let mut window_queue: Option<(mpsc::Sender<DataOutbound>, QueueBudget, Vec<u8>)> = None;
        let mut reset_queue: Option<(mpsc::Sender<DataOutbound>, QueueBudget, Vec<u8>)> = None;
        let mut reset_sequence: Option<StreamState> = None;
        let mut released_receive_bytes = 0usize;
        let mut replayed_inbound = false;
        let mut peer_terminal: Option<Terminal> = None;
        let mut stream_terminal_transitioned = false;
        let mut stream_terminal_receipt_observed = false;
        'data: {
            let Some(session) = self.session_mut(&key) else {
                return;
            };
            let writer_frozen = Self::rotation_frozen(session);
            let defer_candidate_data = carrier_is_candidate
                && matches!(
                    frame.kind,
                    FrameKind::Data | FrameKind::Fin | FrameKind::Reset
                )
                && session
                    .rotation
                    .as_ref()
                    .and_then(|rotation| rotation.recovery.as_ref())
                    .is_some_and(|recovery| {
                        if recovery.activated {
                            return false;
                        }
                        let immutable_fence = recovery.remote_snapshots
                            [direction_index(Direction::ConnectorToRelay)]
                        .get(&frame.stream_id)
                        .map(|entry| entry.last_emitted);
                        let beyond_fence = immutable_fence
                            .is_none_or(|last_emitted| frame.sequence > last_emitted);
                        if !beyond_fence {
                            return false;
                        }
                        // New DATA beyond the connector's immutable
                        // snapshot is legal only after the coordinator has
                        // issued both READY decisions.  Before that point a
                        // frame would be an unaccounted application write.
                        recovery.ready_sent == [true, true]
                    });
            if carrier_is_candidate
                && matches!(
                    frame.kind,
                    FrameKind::Data | FrameKind::Fin | FrameKind::Reset
                )
                && !defer_candidate_data
                && session
                    .rotation
                    .as_ref()
                    .and_then(|rotation| rotation.recovery.as_ref())
                    .is_some_and(|recovery| {
                        !recovery.activated
                            && recovery.remote_snapshots
                                [direction_index(Direction::ConnectorToRelay)]
                            .get(&frame.stream_id)
                            .is_none_or(|entry| frame.sequence > entry.last_emitted)
                            && recovery.ready_sent != [true, true]
                    })
            {
                deferred_rejected = true;
                break 'data;
            }
            if defer_candidate_data {
                let queue_budget = session.queue_budget.clone();
                let input_bytes = frame.payload.len();
                let deferred_available = session
                    .rotation
                    .as_ref()
                    .and_then(|rotation| rotation.recovery.as_ref())
                    .is_some_and(|recovery| recovery.deferred_frames.len() < deferred_limit);
                let Some(stream) = session.streams.get_mut(&frame.stream_id) else {
                    return;
                };
                let can_charge =
                    deferred_available && reserve_m2_bytes(&queue_budget, stream, input_bytes);
                if !can_charge {
                    deferred_rejected = true;
                } else if let Some(rotation) = session.rotation.as_mut()
                    && let Some(recovery) = rotation.recovery.as_mut()
                {
                    recovery.deferred_bytes = recovery.deferred_bytes.saturating_add(input_bytes);
                    // Clone the carrier identity so the owned value stays
                    // available for the post-'data terminal receipt capture;
                    // this deferral path returns immediately below, so the
                    // clone is only paid on recovery-deferred frames.
                    recovery
                        .deferred_frames
                        .push_back((carrier.clone(), frame, input_bytes));
                }
                if !deferred_rejected {
                    return;
                }
                break 'data;
            }
            let data_tx = if carrier_is_candidate {
                session
                    .rotation
                    .as_ref()
                    .and_then(|rotation| rotation.candidate.as_ref())
                    .map(|candidate| candidate.tx.clone())
            } else {
                session.data_tx.clone()
            };
            let Some(data_tx) = data_tx else {
                return;
            };
            let queue_budget = session.queue_budget.clone();
            let input_bytes = frame.payload.len();
            let is_retained_replay = carrier_is_candidate
                && matches!(
                    frame.kind,
                    FrameKind::Data | FrameKind::Fin | FrameKind::Reset
                )
                && session
                    .rotation
                    .as_ref()
                    .and_then(|rotation| rotation.recovery.as_ref())
                    .and_then(|recovery| {
                        recovery.remote_snapshots[direction_index(Direction::ConnectorToRelay)]
                            .get(&frame.stream_id)
                    })
                    .is_some_and(|entry| frame.sequence <= entry.last_emitted);
            let Some(stream) = session.streams.get_mut(&frame.stream_id) else {
                return;
            };
            let charged_input = reserve_m2_bytes(&queue_budget, stream, input_bytes);
            let replay_before = stream
                .sequence
                .direction(Direction::RelayToConnector)
                .replay_bytes();
            let disposition = if !charged_input {
                invalid = true;
                ReceiveDisposition::Duplicate
            } else {
                match stream
                    .sequence
                    .receive_frame(Direction::ConnectorToRelay, &frame)
                {
                    Ok(disposition) => disposition,
                    Err(error) => {
                        let receive = stream
                            .sequence
                            .direction(Direction::ConnectorToRelay)
                            .snapshot();
                        let send = stream
                            .sequence
                            .direction(Direction::RelayToConnector)
                            .snapshot();
                        tracing::warn!(
                            device_id = %key.device_id,
                            session_id = %key.session_id,
                            epoch = key.epoch,
                            stream_id = frame.stream_id,
                            carrier_generation = carrier.generation,
                            carrier_connection_id = %carrier.connection_id,
                            frame_kind = ?frame.kind,
                            frame_sequence = frame.sequence,
                            frame_ack = frame.ack,
                            receive_contiguous = receive.recv_contiguous,
                            send_last_emitted = send.last_emitted,
                            error = %error,
                            stage = "m2_receive_sequence",
                        );
                        invalid = true;
                        ReceiveDisposition::Duplicate
                    }
                }
            };
            let replay_after = stream
                .sequence
                .direction(Direction::RelayToConnector)
                .replay_bytes();
            if replay_before > replay_after {
                release_m2_bytes(&queue_budget, stream, replay_before - replay_after);
            }
            if charged_input && (disposition == ReceiveDisposition::Duplicate || invalid) {
                release_m2_bytes(&queue_budget, stream, input_bytes);
            }
            if !invalid && disposition != ReceiveDisposition::Duplicate {
                replayed_inbound = is_retained_replay;
                let ready = stream.sequence.ready_frames(Direction::ConnectorToRelay);
                let mut delivered_through = None;
                for ready_frame in ready {
                    delivered_through = Some(ready_frame.sequence);
                    if ready_frame.kind == FrameKind::Data {
                        if stream
                            .response_bytes
                            .len()
                            .saturating_add(ready_frame.payload.len())
                            > wire::MAX_BODY_BYTES
                                .saturating_add(MAX_ECHO_RESPONSE_EXTRA_BYTES)
                                .saturating_add(4)
                        {
                            invalid = true;
                            break;
                        }
                        stream
                            .response_bytes
                            .extend_from_slice(&ready_frame.payload);
                    }
                    if matches!(ready_frame.kind, FrameKind::Fin | FrameKind::Reset) {
                        // The connector's terminal frame may arrive after the
                        // first logical terminal transition (for example when
                        // the public side closed first). Record a receipt for
                        // the actual FIN/RESET independently of that latch.
                        stream_terminal_receipt_observed = true;
                        if !stream.terminal {
                            stream_terminal_transitioned = true;
                            stream.terminal = true;
                        }
                    }
                }
                if let Some(through) = delivered_through
                    && stream
                        .sequence
                        .mark_delivered(Direction::ConnectorToRelay, through)
                        .is_err()
                {
                    invalid = true;
                }
                while !invalid && stream.response_bytes.len() >= 4 {
                    let declared = u32::from_be_bytes([
                        stream.response_bytes[0],
                        stream.response_bytes[1],
                        stream.response_bytes[2],
                        stream.response_bytes[3],
                    ]) as usize;
                    if declared > wire::MAX_BODY_BYTES.saturating_add(MAX_ECHO_RESPONSE_EXTRA_BYTES)
                    {
                        invalid = true;
                        break;
                    }
                    let total = match declared.checked_add(4) {
                        Some(total) => total,
                        None => {
                            invalid = true;
                            break;
                        }
                    };
                    if stream.response_bytes.len() < total {
                        break;
                    }
                    let record: Vec<u8> = stream.response_bytes.drain(..total).collect();
                    let Some(waiter) = stream.response_records.pop_front() else {
                        invalid = true;
                        break;
                    };
                    release_m2_bytes(&queue_budget, stream, total);
                    stream.receive_bytes = stream.receive_bytes.saturating_add(declared);
                    released_receive_bytes = match released_receive_bytes.checked_add(total) {
                        Some(bytes) => bytes,
                        None => {
                            invalid = true;
                            break;
                        }
                    };
                    let _ = waiter.send(Ok(record));
                }
            }
            if !invalid {
                peer_terminal = stream
                    .sequence
                    .direction(Direction::ConnectorToRelay)
                    .receive_terminal();
            }
            if !invalid && Self::should_ack_m2_frame(frame.kind) {
                let ack_sequence = stream
                    .sequence
                    .direction(Direction::ConnectorToRelay)
                    .recv_contiguous();
                let ack = Frame::ack(key.epoch, carrier.generation, frame.stream_id, ack_sequence);
                if let Ok(bytes) = ack.encode() {
                    queue = Some((data_tx.clone(), queue_budget.clone(), bytes));
                } else {
                    invalid = true;
                }
            }
            if !invalid && released_receive_bytes > 0 {
                let released = match u64::try_from(released_receive_bytes) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        invalid = true;
                        0
                    }
                };
                let current_credit = stream
                    .sequence
                    .direction(Direction::ConnectorToRelay)
                    .receive_credit();
                let limit = match current_credit.checked_add(released) {
                    Some(limit) => limit,
                    None => {
                        invalid = true;
                        0
                    }
                };
                let update =
                    Frame::window_update(key.epoch, carrier.generation, frame.stream_id, limit);
                if !invalid
                    && stream
                        .sequence
                        .send_frame(Direction::RelayToConnector, &update)
                        .is_ok()
                {
                    match update.encode() {
                        Ok(bytes) => {
                            window_queue = Some((data_tx.clone(), queue_budget.clone(), bytes));
                        }
                        Err(_) => invalid = true,
                    }
                }
            }
            if !invalid
                && frame.kind == FrameKind::Reset
                && disposition == ReceiveDisposition::Accepted
                && !writer_frozen
                && stream
                    .sequence
                    .direction(Direction::RelayToConnector)
                    .send_terminal()
                    .is_none()
            {
                // While the writer is frozen, the relay's RESET reply is
                // deferred like any other terminal: the inline fast path is
                // skipped and `peer_terminal` (the connector's RESET) routes
                // through `queue_peer_terminal_reply`, which holds it until
                // activation.  docs/protocol.md "Freeze each writer".
                let reason = frame.reset_reason().ok().flatten().unwrap_or(4_002);
                let send_direction = stream.sequence.direction(Direction::RelayToConnector);
                let Some(sequence) = send_direction.last_emitted().checked_add(1) else {
                    invalid = true;
                    break 'data;
                };
                let reset = Frame::reset(
                    key.epoch,
                    carrier.generation,
                    frame.stream_id,
                    sequence,
                    stream
                        .sequence
                        .direction(Direction::ConnectorToRelay)
                        .recv_contiguous(),
                    reason,
                );
                let mut candidate_sequence = stream.sequence.clone();
                if candidate_sequence
                    .send_frame(Direction::RelayToConnector, &reset)
                    .is_ok()
                    && let Ok(bytes) = reset.encode()
                {
                    reset_sequence = Some(candidate_sequence);
                    reset_queue = Some((data_tx.clone(), queue_budget.clone(), bytes));
                } else {
                    invalid = true;
                }
            }
        }
        // Capture the first terminal transition before any later sequence or
        // reverse-channel error can close the session.  This latch is tied to
        // the exact stream/owner/request identity and remains in snapshots
        // after STREAM_FORGET removes the live stream.
        if stream_terminal_transitioned
            && let Some(operation_id) = self
                .session_for(&key)
                .and_then(|session| session.streams.get(&received_stream_id))
                .map(|stream| stream.operation_id.clone())
            && let Some(event) = self.stream_terminal_event(
                &key,
                received_stream_id,
                &operation_id,
                "STREAM_CLOSED",
                None,
            )
        {
            self.retain_stream_terminal_event(event);
        }
        // Capture an independent receipt for the actual connector FIN/RESET.
        // The first-terminal latch above is intentionally immutable and may
        // predate this frame, so a late DATA/FIN receipt needs its own record
        // with the final receive cursor before STREAM_FORGET can reclaim the
        // stream on the following ACK.
        if stream_terminal_receipt_observed
            && let Some(operation_id) = self
                .session_for(&key)
                .and_then(|session| session.streams.get(&received_stream_id))
                .map(|stream| stream.operation_id.clone())
            && let Some(event) = self.stream_terminal_receipt_event(
                &key,
                &carrier,
                received_stream_id,
                &operation_id,
            )
        {
            self.retain_stream_terminal_receipt_event(event);
        }
        if deferred_rejected {
            self.protocol_failure(&key, "RECOVERY_QUEUE_LIMIT").await;
            return;
        }
        if invalid {
            self.protocol_failure(&key, "INVALID_SEQUENCE").await;
            return;
        }
        if replayed_inbound && let Some(session) = self.session_mut(&key) {
            if let Some(rotation) = session.rotation.as_mut() {
                rotation.replayed_frames = rotation.replayed_frames.saturating_add(1);
            }
            session.total_replayed_frames = session.total_replayed_frames.saturating_add(1);
        }
        if let Some((data_tx, budget, bytes)) = queue
            && queue_data(&data_tx, &budget, bytes).is_err()
        {
            self.protocol_failure(&key, "REVERSE_CHANNEL_UNAVAILABLE")
                .await;
            return;
        }
        if let Some((data_tx, budget, bytes)) = window_queue
            && queue_data(&data_tx, &budget, bytes).is_err()
        {
            self.protocol_failure(&key, "REVERSE_CHANNEL_UNAVAILABLE")
                .await;
            return;
        }
        if let Some((data_tx, budget, bytes)) = reset_queue {
            if queue_data(&data_tx, &budget, bytes).is_err() {
                self.protocol_failure(&key, "REVERSE_CHANNEL_UNAVAILABLE")
                    .await;
                return;
            }
            if let Some(sequence) = reset_sequence.take()
                && let Some(session) = self.session_mut(&key)
                && let Some(stream) = session.streams.get_mut(&received_stream_id)
            {
                stream.sequence = sequence;
            }
        }
        if let Some(terminal) = peer_terminal {
            let _ = self.queue_peer_terminal_reply(&key, received_stream_id, terminal);
        }
        if let Some(stream_id) = retry_stream {
            self.retry_pending_echo_records(&key, stream_id);
            // A WINDOW_UPDATE after activation may unblock a deferred terminal
            // that was held behind credit-bound records.
            self.flush_pending_terminal(&key, stream_id);
        }
        // A peer FIN/RESET may have accounted for the final receive cursor.
        // Publish FORGET before rotation progress can enqueue QUIESCE.
        let _ = self.flush_owner_stream_forgets(&key);
        if carrier_is_candidate
            && self.session_for(&key).is_some_and(|session| {
                session
                    .rotation
                    .as_ref()
                    .is_some_and(|rotation| rotation.recovery.is_some())
            })
            && let Err(error) = self.send_recovery_ready(&key)
        {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                stage = "recovery_ready_after_frame",
                error = %error,
            );
            self.close_session(&key, "RECOVERY_READY_FAILED").await;
            return;
        }
        if let Err(error) = self.progress_rotation_drain(&key) {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                phase = ?self
                    .session_for(&key)
                    .and_then(|session| session.rotation.as_ref())
                    .map(|rotation| rotation.state.phase()),
                stage = "drain_progress_after_data",
                error = %error,
            );
        }
    }

    fn cancel(&mut self, key: &SessionKey, stream_id: u64, operation_id: String) {
        if let Some(session) = self.session_mut(key)
            && session
                .pending
                .get(&stream_id)
                .is_some_and(|pending| pending.operation_id == operation_id)
            && let Some(pending) = session.pending.remove(&stream_id)
        {
            release_pending_budget(session, &pending);
            let _ = pending.response.send(EchoOutcome::Failure {
                code: "CANCELLED",
                execution: "unknown",
            });
            if let Ok(message) = wire::encode_control_message(&wire::cancel(
                &key.session_id,
                key.epoch,
                stream_id,
                &operation_id,
            )) {
                let _ = queue_control(&session.control_tx, &session.queue_budget, message);
            }
        }
    }

    async fn tick(&mut self) {
        let now = Instant::now();
        let keys: Vec<_> = self
            .sessions
            .values()
            .map(|session| session.key.clone())
            .collect();
        for key in keys {
            let owner_fence_expired = self.session_for(&key).is_some_and(|session| {
                session.cluster_profile
                    && !session.owner_fenced
                    && session
                        .owner_fence_deadline
                        .is_some_and(|deadline| now >= deadline)
            });
            if owner_fence_expired {
                self.close_session(&key, "OWNER_FENCE_TIMEOUT").await;
                continue;
            }
            let detached_open_expired = self.session_for(&key).is_some_and(|session| {
                session.streams.values().any(|stream| {
                    stream.registration_dropped
                        && stream.open_pending
                        && now >= stream.admission_deadline
                })
            });
            if detached_open_expired {
                // A dropped registration cannot be compacted until the
                // owner proves OPENED or REJECTED. If neither arrives by the
                // admission deadline, close the fenced session instead of
                // inventing a no-stream terminal proof.
                self.close_session(&key, "OPEN_ADMISSION_TIMEOUT").await;
                continue;
            }
            self.expire_unclaimed_echo_streams(&key, now);
            let owner_forgets_ready = self.flush_owner_stream_forgets(&key);
            let retry_quiesce = owner_forgets_ready
                && self.session_for(&key).is_some_and(|session| {
                    session.rotation.as_ref().is_some_and(|rotation| {
                        rotation.state.phase() == RotationPhase::Preparing
                            && rotation.state.status().candidate_ready
                            && rotation.candidate.is_some()
                    })
                });
            if retry_quiesce {
                // Candidate attachment can have succeeded while the control
                // queue was full of an earlier terminal item. Retry the
                // single PREPARING attempt from the actor tick; the phase and
                // message IDs make this idempotent once QUIESCE is queued.
                self.begin_rotation_quiesce(&key);
            }
            let terminal_fin_failure_expired = self.session_for(&key).is_some_and(|session| {
                session
                    .terminal_fin_failure_deadline
                    .is_some_and(|deadline| now >= deadline)
            });
            if terminal_fin_failure_expired {
                self.close_session(&key, "TERMINAL_FIN_TIMEOUT").await;
                continue;
            }
            let owner_forget_expired = self.session_for(&key).is_some_and(|session| {
                session
                    .owner_forget_deadline
                    .is_some_and(|deadline| now >= deadline)
            });
            if owner_forget_expired {
                self.close_session(&key, "OWNER_FORGET_TIMEOUT").await;
                continue;
            }
            if self.poll_rotation_deadline(&key) {
                self.close_session(&key, "ROTATION_DEADLINE_EXPIRED").await;
                continue;
            }
            self.poll_rotation_barrier(&key);
            if let Err(error) = self.progress_rotation_drain(&key) {
                tracing::warn!(
                    device_id = %key.device_id,
                    session_id = %key.session_id,
                    epoch = key.epoch,
                    phase = ?self
                        .session_for(&key)
                        .and_then(|session| session.rotation.as_ref())
                        .map(|rotation| rotation.state.phase()),
                    stage = "drain_progress_tick",
                    error = %error,
                );
            }
            // Safety net for frames held while the writer was frozen: once the
            // carrier is writable again, flush any that a transiently full
            // writer queue (or a recovery reactivation) could not emit at the
            // activation/abort callback.  A no-op while still frozen.
            self.flush_frozen_writes(&key);
            let rotation_due = self.session_for(&key).is_some_and(|session| {
                session.profile.supports_rotation()
                    && session.data_tx.is_some()
                    && session.rotation.as_ref().is_some_and(|rotation| {
                        matches!(rotation.state.phase(), RotationPhase::Active)
                            && session.last_rotation.elapsed()
                                >= Duration::from_millis(
                                    rotation.state.config().rotation_interval_ms,
                                )
                    })
            });
            if rotation_due
                && let RotationStart::Failed(close_reason) =
                    self.start_rotation(&key, None, "policy_timer", None)
            {
                self.close_session(&key, close_reason).await;
                continue;
            }
            let expired: Vec<_> = self
                .session_for(&key)
                .map(|session| {
                    session
                        .pending
                        .iter()
                        .filter(|(_, pending)| {
                            pending.response.is_closed()
                                || pending.created_at.elapsed()
                                    > self.options.limits.operation_timeout
                        })
                        .map(|(stream_id, _)| *stream_id)
                        .collect()
                })
                .unwrap_or_default();
            for stream_id in expired {
                self.fail_pending(&key, stream_id, "REVERSE_CHANNEL_INTERRUPTED", "unknown");
            }
            let Some(snapshot) = self.session_for(&key).map(|session| {
                (
                    session.identity.spki_fingerprint.clone(),
                    session.identity.device_version,
                    session.owner.clone(),
                    session.last_lease_renewal,
                    session.maintenance_in_flight,
                )
            }) else {
                continue;
            };
            if snapshot.4 {
                continue;
            }
            if let Some(session) = self.session_mut(&key) {
                session.maintenance_in_flight = true;
            }
            let catalog = self.catalog.clone();
            let command_tx = self.command_tx.clone();
            let owner_lease = self.options.owner_lease;
            let renew = snapshot.3.elapsed() >= owner_lease / 3;
            let cancel = self.options.shutdown.clone();
            self.spawn_background(async move {
                let renewed = if renew {
                    let lease_expires_at = Utc::now()
                        + ChronoDuration::from_std(owner_lease)
                            .unwrap_or_else(|_| ChronoDuration::seconds(30));
                    let started = Instant::now();
                    Some(
                        catalog
                            .renew_owner(&snapshot.2, lease_expires_at)
                            .await
                            .map_err(|error| {
                                MaintenanceAuthorityFailure::from_catalog(
                                    MaintenanceAuthorityOperation::RenewOwner,
                                    &error,
                                    started.elapsed(),
                                )
                            }),
                    )
                } else {
                    None
                };
                let started = Instant::now();
                let identity = catalog
                    .resolve_device(&snapshot.0, Utc::now())
                    .await
                    .map_err(|error| {
                        MaintenanceAuthorityFailure::from_catalog(
                            MaintenanceAuthorityOperation::ResolveDevice,
                            &error,
                            started.elapsed(),
                        )
                    });
                send_background_command(
                    &cancel,
                    &command_tx,
                    Command::MaintenanceResult {
                        key,
                        renewed,
                        identity,
                    },
                )
                .await;
            });
        }
        let wall_now = Utc::now();
        self.tickets.retain(|_, ticket| {
            ticket.expires_at > now
                && wall_now >= ticket.issued_at_wall
                && wall_now < ticket.expires_at_wall
        });
    }

    fn expire_unclaimed_echo_streams(&mut self, key: &SessionKey, now: Instant) {
        let expired_admissions = self
            .session_for(key)
            .map(|session| {
                session
                    .streams
                    .iter()
                    .filter(|(_, stream)| {
                        !stream.terminal
                            && !stream.admission_lease.is_cancelled()
                            && now >= stream.admission_deadline
                    })
                    .map(|(stream_id, stream)| (*stream_id, stream.operation_id.clone()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for (stream_id, operation_id) in expired_admissions {
            let _ = self.close_echo_stream(key, stream_id, &operation_id);
        }
    }

    async fn finish_maintenance(
        &mut self,
        key: SessionKey,
        renewed: Option<Result<bool, MaintenanceAuthorityFailure>>,
        identity: Result<Option<DeviceIdentity>, MaintenanceAuthorityFailure>,
    ) {
        let mut close_reason = None;
        let mut authority_failure = None;
        if let Some(session) = self.sessions.get_mut(&key.scope()) {
            if session.key != key {
                return;
            }
            session.maintenance_in_flight = false;
            if let Some(renewed) = renewed {
                match renewed {
                    Ok(true) => session.last_lease_renewal = Instant::now(),
                    Ok(false) => close_reason = Some("OWNER_FENCED"),
                    Err(error) => {
                        authority_failure = Some(error);
                        close_reason = Some(AUTHORITY_UNAVAILABLE);
                    }
                }
            }
            match identity {
                Ok(Some(current))
                    if current.tenant_id == key.tenant_id
                        && current.device_id == key.device_id
                        && current.device_version == session.identity.device_version
                        && current.spki_fingerprint == session.identity.spki_fingerprint
                        && current.device_active
                        && current.credential_active
                        && current.credential_revoked_at.is_none() => {}
                Ok(None) | Ok(Some(_)) => {
                    // A confirmed authorization denial is more specific than
                    // an independent authority error, while an exact owner
                    // fence remains the strongest terminal signal.
                    if !matches!(close_reason, Some("OWNER_FENCED")) {
                        close_reason = Some("AUTHORIZATION_REVOKED");
                    }
                }
                Err(error) => {
                    authority_failure.get_or_insert(error);
                    if close_reason.is_none() {
                        close_reason = Some(AUTHORITY_UNAVAILABLE);
                    }
                }
            };
        }
        if let Some(reason) = close_reason {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                reason = %reason,
                phase = "owner_check_failed",
                authority_operation = authority_failure
                    .map_or("none", |failure| failure.operation.as_str()),
                authority_category = authority_failure
                    .map_or("none", |failure| failure.category.as_str()),
                authority_elapsed_ms = authority_failure.map_or(0, |failure| failure.elapsed_ms),
            );
            self.close_session(&key, reason).await;
        }
    }

    async fn disconnect_control(&mut self, key: SessionKey) {
        let matches = self
            .sessions
            .get(&key.scope())
            .is_some_and(|session| session.key == key);
        if !matches {
            return;
        }
        self.close_session(&key, "CONTROL_CLOSED").await;
    }

    async fn disconnect_data(&mut self, carrier: CarrierKey) {
        let key = carrier.session.clone();
        let mut old_closed = false;
        let mut active_lost = false;
        let mut recovery_candidate_lost = false;
        let mut candidate_abort: Option<(RotationAttemptIdentity, String, u64)> = None;
        let mut candidate_failure = false;
        if let Some(session) = self.sessions.get_mut(&key.scope()) {
            if session.key != key {
                return;
            }
            let active = session
                .active_carrier
                .as_ref()
                .is_some_and(|active| active.context == carrier.context());
            let candidate = session
                .rotation
                .as_ref()
                .and_then(|rotation| rotation.candidate.as_ref())
                .is_some_and(|candidate| candidate.context == carrier.context());
            let retiring_old = session.rotation.as_ref().is_some_and(|rotation| {
                rotation.old_connection_id == carrier.connection_id
                    && matches!(rotation.state.phase(), RotationPhase::Retiring)
            });
            if !active && !candidate && !retiring_old {
                return;
            }
            if active {
                session.data_tx = None;
                session.active_carrier = None;
                active_lost = true;
            }
            if candidate && let Some(rotation) = session.rotation.as_mut() {
                if rotation.recovery.is_some() {
                    // Recovery retries carry the immutable episode roster and
                    // close evidence into a fresh attempt.  They never reuse
                    // this candidate's generation or connection identity.
                    rotation.candidate = None;
                    recovery_candidate_lost = true;
                } else {
                    let now_ms = monotonic_millis();
                    let phase = rotation.state.phase();
                    let known_uncommitted = matches!(
                        phase,
                        RotationPhase::Preparing
                            | RotationPhase::Quiescing
                            | RotationPhase::Draining
                            | RotationPhase::Aborting
                    );
                    if let Some(attempt) = rotation.attempt.clone() {
                        if !known_uncommitted {
                            // Once COMMIT has been sent or accepted, a vanished
                            // candidate is ambiguous.  Do not restore the old
                            // carrier or silently continue with a partial handover.
                            candidate_failure = true;
                            rotation.candidate = None;
                        } else {
                            if phase != RotationPhase::Aborting
                                && rotation
                                    .state
                                    .abort(&attempt, now_ms, RecoveryReason::CandidateTransportLost)
                                    .is_err()
                            {
                                candidate_failure = true;
                            }
                            if !candidate_failure
                                && rotation
                                    .state
                                    .candidate_closed(
                                        &attempt,
                                        RotationSide::Owner,
                                        ClosureEvidence::closed(carrier.connection_id.clone()),
                                        now_ms,
                                    )
                                    .is_err()
                            {
                                candidate_failure = true;
                            }
                            rotation.candidate = None;
                            if !candidate_failure && phase != RotationPhase::Aborting {
                                let remaining_ms = rotation
                                    .state
                                    .status()
                                    .deadline_ms
                                    .unwrap_or(now_ms)
                                    .saturating_sub(now_ms);
                                // Physical candidate loss is an unsolicited
                                // owner decision.  It must not reuse a peer
                                // phase id that may already have a cached
                                // DRAINED reply; an empty reply_to keeps the
                                // abort journal-independent.
                                candidate_abort = Some((attempt, String::new(), remaining_ms));
                            }
                        }
                    } else {
                        candidate_failure = true;
                        // There is no authenticated attempt identity to
                        // coordinate a bilateral abort with.
                        rotation.candidate = None;
                    }
                }
            }
            if retiring_old {
                let attempt = session
                    .rotation
                    .as_ref()
                    .and_then(|rotation| rotation.attempt.clone());
                if let Some(attempt) = attempt
                    && let Some(rotation) = session.rotation.as_mut()
                {
                    let status_before_close = rotation.state.status();
                    Self::latch_rotation_lifecycle(rotation, &status_before_close);
                    let close_result = rotation.state.old_socket_closed(
                        &attempt,
                        RotationSide::Owner,
                        ClosureEvidence::closed(carrier.connection_id.clone()),
                        monotonic_millis(),
                    );
                    if close_result.is_ok() {
                        let status_after_close = rotation.state.status();
                        Self::latch_rotation_lifecycle(rotation, &status_after_close);
                    }
                    old_closed = close_result.is_ok();
                }
            }
            if active {
                let pending = std::mem::take(&mut session.pending);
                session.queued_bytes = 0;
                for (_, pending) in pending {
                    release_pending_budget(session, &pending);
                    let _ = pending.response.send(EchoOutcome::Failure {
                        code: "REVERSE_CHANNEL_INTERRUPTED",
                        execution: "unknown",
                    });
                }
            }
        }
        if let Some((attempt, reply_to, remaining_ms)) = candidate_abort {
            if remaining_ms == 0 {
                candidate_failure = true;
            } else {
                let message = wire::rotate_abort(
                    &reply_to,
                    attempt,
                    "candidate transport lost",
                    remaining_ms,
                );
                match wire::encode_control_message(&message) {
                    Ok(encoded) => {
                        let queued = self
                            .session_for(&key)
                            .map(|session| {
                                queue_control(
                                    &session.control_tx,
                                    &session.queue_budget,
                                    encoded.clone(),
                                )
                                .is_ok()
                            })
                            .unwrap_or(false);
                        if queued {
                            if let Some(session) = self.session_mut(&key)
                                && let Some(rotation) = session.rotation.as_mut()
                            {
                                if Self::complete_rotation_reply(rotation, &message, &encoded)
                                    .is_err()
                                {
                                    candidate_failure = true;
                                } else {
                                    rotation.abort_message_id =
                                        Some(message.message_id().to_owned());
                                    rotation.last_message_id = message.message_id().to_owned();
                                }
                            } else {
                                candidate_failure = true;
                            }
                        } else {
                            candidate_failure = true;
                        }
                    }
                    Err(_) => {
                        // The message is bounded by the wire encoder; an
                        // encode failure cannot be recovered by retrying this
                        // attempt.
                        candidate_failure = true;
                    }
                }
            }
        }
        if candidate_failure {
            self.close_session(&key, "ROTATION_CANDIDATE_FAILED").await;
            return;
        }
        // A late physical-close event may outlive its session, and M1 has no
        // rotation state. Neither case is a failed rotation abort.
        if self
            .session_for(&key)
            .is_some_and(|session| session.rotation.is_some())
            && let Err(error) = self.finish_rotation_abort_if_ready(&key)
        {
            tracing::warn!(
                device_id = %key.device_id,
                session_id = %key.session_id,
                epoch = key.epoch,
                stage = "owner_aborted_after_candidate_close",
                error = %error,
            );
        }
        // A completed owner-side abort resumes the old carrier; flush any
        // frames held while the writer was frozen.  A no-op unless the session
        // is back to Active with a live carrier (e.g. active-loss recovery
        // leaves data_tx cleared and is handled by the recovery path instead).
        self.flush_frozen_writes(&key);
        if old_closed {
            self.finish_rotation_if_ready(&key);
        }
        if active_lost
            && self
                .session_for(&key)
                .is_some_and(|session| session.profile.supports_rotation())
            && !self.begin_recovery_after_loss(&key, &carrier.connection_id)
        {
            self.close_session(&key, "RECOVERY_START_FAILED").await;
        }
        if recovery_candidate_lost
            && self
                .schedule_recovery_retry(&key, &carrier.connection_id)
                .is_none()
        {
            self.close_session(&key, "RECOVERY_CANDIDATE_FAILED").await;
        }
    }

    async fn close_session(&mut self, key: &SessionKey, reason: &str) {
        if !self
            .sessions
            .get(&key.scope())
            .is_some_and(|session| session.key == *key)
        {
            return;
        }
        // Capture the terminal path while the authenticated session and its
        // current rotation attempt are still available. This remains purely
        // diagnostic: the event does not retain the session or alter the
        // fail-closed removal below.
        let terminal_event = self.sessions.get(&key.scope()).and_then(|session| {
            (!session.closed)
                .then(|| Self::session_terminal_event(key, session, reason, monotonic_millis()))
        });
        if let Some(event) = terminal_event {
            self.retain_session_terminal_event(event);
        }
        let Some(mut session) = self.sessions.remove(&key.scope()) else {
            return;
        };
        // A successor session must never inherit a retryable FORGET identity.
        self.owner_forgets.remove(key);
        if session.closed {
            return;
        }
        session.closed = true;
        tracing::info!(
            tenant_id = %session.identity.tenant_id,
            device_id = %key.device_id,
            session_id = %key.session_id,
            epoch = key.epoch,
            reason = %reason,
            phase = "session_closed",
        );
        let rejected = wire::rejected(
            &wire::random_token(),
            &session.key.session_id,
            session.key.epoch,
            1,
            "session",
            reason,
            "device session closed",
        );
        if let Ok(text) = wire::encode_control_message(&rejected) {
            let _ = queue_control(&session.control_tx, &session.queue_budget, text);
        }
        let _ = session.control_tx.try_send(ControlOutbound::Close);
        if let Some(data) = session.data_tx.take() {
            let _ = data.try_send(DataOutbound::Close);
        }
        if let Some(rotation) = session.rotation.as_ref()
            && let Some(candidate) = rotation.candidate.as_ref()
        {
            let _ = candidate.tx.try_send(DataOutbound::Close);
        }
        let queue_budget = session.queue_budget.clone();
        for (_, pending) in session.pending.drain() {
            let bytes = pending
                .body
                .len()
                .saturating_add(pending.response_body.len());
            queue_budget.release(bytes);
            let _ = pending.response.send(EchoOutcome::Failure {
                code: "REVERSE_CHANNEL_INTERRUPTED",
                execution: "unknown",
            });
        }
        for (_, mut stream) in session.streams.drain() {
            stream.closed.cancel();
            queue_budget.release(stream.budget_bytes);
            stream.budget_bytes = 0;
            for (_, waiter) in stream.pending_records.drain(..) {
                let _ = waiter.send(Err(EchoOutcome::Failure {
                    code: "REVERSE_CHANNEL_INTERRUPTED",
                    execution: "unknown",
                }));
            }
            for waiter in stream.response_records.drain(..) {
                let _ = waiter.send(Err(EchoOutcome::Failure {
                    code: "REVERSE_CHANNEL_INTERRUPTED",
                    execution: "unknown",
                }));
            }
        }
        self.tickets
            .retain(|_, ticket| ticket.session_id != key.session_id || ticket.epoch != key.epoch);
        let owner = session.owner.clone();
        self.enqueue_cleanup(owner).await;
    }

    async fn close_all(&mut self) {
        let deadline = tokio::time::Instant::now() + CLEANUP_SHUTDOWN_TIMEOUT;
        // Stop every background result sender before the actor stops draining
        // commands.  Any queued registration command is dropped with its
        // owner-claim guard, which routes the exact token through cleanup.
        self.options.shutdown.cancel();
        self.rx.close();
        while self.rx.recv().await.is_some() {}
        let keys: Vec<_> = self
            .sessions
            .values()
            .map(|session| session.key.clone())
            .collect();
        for key in keys {
            self.close_session(&key, "SHUTDOWN").await;
        }
        self.tickets.clear();
        let graceful_deadline = deadline - CLEANUP_OPERATION_TIMEOUT;
        let joined = self
            .shutdown_background_tasks(graceful_deadline, deadline)
            .await;
        if !joined {
            // Keep this an explicitly failed shutdown path.  Dropping the
            // JoinSet aborts its remaining tasks, but does not synchronously
            // join them or prove that an owner guard has already enqueued its
            // cleanup.  The cleanup worker remains live for its own bounded
            // drain and any lease that cannot be released is left fenced.
            let remaining = std::mem::replace(&mut self.background_tasks, JoinSet::new());
            drop(remaining);
        }
        self.cleanup_dispatcher.take();
        if let Some(cleanup) = self.cleanup.take()
            && !cleanup.shutdown_until(deadline).await
        {
            self.background_failure.store(true, Ordering::Release);
        }
    }

    async fn protocol_failure(&mut self, key: &SessionKey, code: &str) {
        self.close_session(key, code).await;
    }

    fn latch_rotation_lifecycle(rotation: &mut RotationRuntime, status: &RotationStatus) {
        let Some(diagnostics) = rotation.completed_rotation_diagnostics.as_mut() else {
            return;
        };
        if status.attempt.is_some() {
            diagnostics.attempt_active = true;
            diagnostics.writer_barrier_flushed = status.writers_frozen;
            diagnostics.candidate_ready = status.candidate_ready;
            diagnostics.commit_sent = status.commit_sent;
            diagnostics.commit_accepted = status.commit_accepted;
            diagnostics.old_socket_closed = status.old_socket_closed;
        } else {
            // RotationState clears its pure attempt as soon as the second
            // old-carrier close is accepted. Preserve the final bilateral
            // close proof and the exact COMMIT-era identity already latched.
            diagnostics.attempt_active = false;
            diagnostics.old_socket_closed = [true, true];
        }
    }

    fn rotation_diagnostics_for(
        rotation: &RotationRuntime,
        status: &RotationStatus,
        completed_drain_set: Option<&DrainSet>,
    ) -> Option<RelayRotationSnapshot> {
        if rotation.snapshot_id.is_empty() && rotation.attempt.is_none() {
            return None;
        }
        let fence_digest =
            |fence: Option<&FenceSnapshot>| fence.and_then(|fence| fence.digest().ok());
        let fence_sequences = |fence: Option<&FenceSnapshot>| {
            fence
                .map(|fence| {
                    fence
                        .entries
                        .iter()
                        .map(|entry| (entry.stream_id, entry.last_emitted))
                        .collect()
                })
                .unwrap_or_default()
        };
        let drain_set = completed_drain_set.cloned().or_else(|| {
            rotation
                .attempt
                .as_ref()
                .and_then(|attempt| rotation.state.drain_set(attempt).ok())
        });
        let ack_sequences = |proof: Option<&DrainProof>| {
            proof
                .map(|proof| {
                    proof
                        .ack_cursors
                        .iter()
                        .map(|ack| (ack.stream_id, ack.acknowledged))
                        .collect()
                })
                .unwrap_or_default()
        };
        Some(RelayRotationSnapshot {
            snapshot_id: (!rotation.snapshot_id.is_empty()).then(|| rotation.snapshot_id.clone()),
            attempt: rotation.attempt.clone(),
            attempt_active: rotation.attempt.is_some(),
            relay_fence_digest: fence_digest(rotation.own_fence.as_ref()),
            connector_fence_digest: fence_digest(
                rotation.remote_fences[direction_index(Direction::ConnectorToRelay)].as_ref(),
            ),
            relay_fence_sequences: fence_sequences(rotation.own_fence.as_ref()),
            connector_fence_sequences: fence_sequences(
                rotation.remote_fences[direction_index(Direction::ConnectorToRelay)].as_ref(),
            ),
            relay_ack_sequences: ack_sequences(
                drain_set
                    .as_ref()
                    .map(|drain_set| &drain_set.relay_to_connector),
            ),
            connector_ack_sequences: ack_sequences(
                drain_set
                    .as_ref()
                    .map(|drain_set| &drain_set.connector_to_relay),
            ),
            writer_barrier_flushed: status.writers_frozen,
            candidate_ready: status.candidate_ready,
            commit_sent: status.commit_sent,
            commit_accepted: status.commit_accepted,
            old_socket_closed: status.old_socket_closed,
        })
    }

    fn snapshot(&self) -> RelaySnapshot {
        let mut sessions = Vec::with_capacity(self.sessions.len());
        for session in self.sessions.values() {
            let status = session
                .rotation
                .as_ref()
                .map(|rotation| rotation.state.status());
            let phase = status
                .as_ref()
                .map(|status| runtime::phase_name(status.phase))
                .unwrap_or_else(|| "active".to_owned());
            let active_generation = status
                .as_ref()
                .map_or(session.generation, |status| status.active_generation);
            let active_connection_id = status.as_ref().map_or_else(
                || session.connection_id.clone(),
                |status| status.active_connection_id.clone(),
            );
            let (candidate_generation, candidate_connection_id) = status
                .as_ref()
                .and_then(|status| status.attempt.as_ref())
                .map(|attempt| {
                    (
                        Some(attempt.new_generation),
                        Some(attempt.new_connection_id.clone()),
                    )
                })
                .unwrap_or((None, None));
            let drain_fences = status.as_ref().map_or(0, |status| {
                status
                    .writers_frozen
                    .iter()
                    .filter(|frozen| **frozen)
                    .count()
            });
            let drain_proofs = status.as_ref().map_or(0, |status| {
                status.drain_proofs.iter().filter(|proof| **proof).count()
            });
            let sockets = status
                .as_ref()
                .map_or(if session.data_tx.is_some() { 2 } else { 1 }, |status| {
                    status.socket_count
                });
            let rotation_started_at_ms = status.as_ref().and_then(|status| status.started_at_ms);
            let rotation_deadline_ms = status.as_ref().and_then(|status| status.deadline_ms);
            let rotation_recovery_reason = status
                .as_ref()
                .and_then(|status| status.recovery_reason.map(runtime::recovery_reason_name));
            let rotation_deadline_forced_retirement = status
                .as_ref()
                .is_some_and(|status| status.deadline_forced_retirement);
            let rotation_diagnostics = session.rotation.as_ref().and_then(|rotation| {
                if rotation.attempt.is_none() {
                    return rotation.completed_rotation_diagnostics.clone();
                }
                let status = status.as_ref()?;
                Self::rotation_diagnostics_for(rotation, status, None)
            });
            let mut streams = Vec::with_capacity(session.pending.len() + session.streams.len());
            let mut replay_frames = 0usize;
            let mut replay_bytes = 0usize;
            for (stream_id, pending) in &session.pending {
                streams.push(RelayStreamSnapshot {
                    stream_id: *stream_id,
                    operation_id: pending.operation_id.clone(),
                    last_emitted_relay_to_connector: pending.send_sequence,
                    peer_acked_relay_to_connector: 0,
                    recv_contiguous_connector_to_relay: pending.response_sequence,
                    delivered_contiguous_connector_to_relay: pending.response_sequence,
                    replay_frames_relay_to_connector: 0,
                    replay_bytes_relay_to_connector: 0,
                    queue_bytes: pending
                        .body
                        .len()
                        .saturating_add(pending.response_body.len()),
                    terminal: false,
                    admission_claimed: false,
                    authorization_in_flight: pending.authorization_in_flight,
                    authorization_started_at_ms: None,
                    authorization_deadline_ms: None,
                    authorization_admission_deadline_ms: None,
                    authorization_failure_code: None,
                });
            }
            for (stream_id, stream) in &session.streams {
                let stream_snapshot = stream.sequence.snapshot();
                let relay = stream_snapshot.direction(Direction::RelayToConnector);
                let connector = stream_snapshot.direction(Direction::ConnectorToRelay);
                let stream_replay_frames = relay
                    .last_emitted
                    .saturating_sub(relay.peer_acked)
                    .try_into()
                    .unwrap_or(usize::MAX);
                let stream_replay_bytes = relay.replay_bytes;
                replay_frames = replay_frames.saturating_add(stream_replay_frames);
                replay_bytes = replay_bytes.saturating_add(stream_replay_bytes);
                streams.push(RelayStreamSnapshot {
                    stream_id: *stream_id,
                    operation_id: stream.operation_id.clone(),
                    last_emitted_relay_to_connector: relay.last_emitted,
                    peer_acked_relay_to_connector: relay.peer_acked,
                    recv_contiguous_connector_to_relay: connector.recv_contiguous,
                    delivered_contiguous_connector_to_relay: connector.delivered_contiguous,
                    replay_frames_relay_to_connector: stream_replay_frames,
                    replay_bytes_relay_to_connector: stream_replay_bytes,
                    queue_bytes: stream.budget_bytes,
                    terminal: stream.terminal,
                    admission_claimed: stream.admission_lease.is_cancelled(),
                    authorization_failure_code: stream.authorization_failure_code,
                    authorization_in_flight: stream.authorization_in_flight,
                    authorization_started_at_ms: stream.authorization_started_at_ms,
                    authorization_deadline_ms: stream.authorization_deadline_ms,
                    authorization_admission_deadline_ms: stream.authorization_admission_deadline_ms,
                });
            }
            streams.sort_by_key(|stream| stream.stream_id);
            sessions.push(RelaySessionSnapshot {
                tenant_id: session.identity.tenant_id.to_string(),
                device_id: session.identity.device_id.to_string(),
                session_id: session.key.session_id.clone(),
                epoch: session.key.epoch,
                profile: session.profile.as_str(),
                phase,
                active_generation,
                active_connection_id,
                candidate_generation,
                candidate_connection_id,
                sockets,
                queue_bytes: session.queue_budget.used(),
                queue_messages: session.pending.len() + session.streams.len(),
                drain_fences,
                drain_proofs,
                replay_frames,
                replay_bytes,
                rotations_completed: session.rotations_completed,
                total_replayed_frames: session.total_replayed_frames,
                rotation_started_at_ms,
                rotation_deadline_ms,
                rotation_recovery_reason,
                rotation_deadline_forced_retirement,
                rotation_diagnostics,
                streams,
            });
        }
        sessions.sort_by(|left, right| left.device_id.cmp(&right.device_id));
        RelaySnapshot {
            monotonic_now_ms: monotonic_millis(),
            lifetime_application_dispatches: self.lifetime_application_dispatches,
            lifetime_consumer_chunk_reads: self.consumer_chunk_reads.load(Ordering::Acquire),
            control_registration_conflicts: self.control_registration_conflicts,
            consumer_write_diagnostics: self.consumer_write_diagnostics.snapshot(),
            peer_transport_diagnostics: self.peer_transport_diagnostics.snapshot(),
            peer_consumer_diagnostics: self.peer_consumer_diagnostics.snapshot(),
            rotation_deadline_events: self.rotation_deadline_events.iter().cloned().collect(),
            session_terminal_events: self.session_terminal_events.iter().cloned().collect(),
            stream_terminal_events: self.stream_terminal_events.iter().cloned().collect(),
            stream_terminal_receipt_events: self
                .stream_terminal_receipt_events
                .iter()
                .cloned()
                .collect(),
            sessions,
        }
    }

    fn record_control_registration_conflict(&mut self) {
        self.control_registration_conflicts = self.control_registration_conflicts.saturating_add(1);
    }

    fn record_application_dispatch(&mut self) {
        self.lifetime_application_dispatches =
            self.lifetime_application_dispatches.saturating_add(1);
    }

    fn session_for(&self, key: &SessionKey) -> Option<&DeviceSession> {
        self.sessions
            .get(&key.scope())
            .filter(|session| session.key == *key)
    }

    fn ticket_matches(&self, ticket: &Ticket) -> bool {
        self.tickets.get(&ticket.value).is_some_and(|pending| {
            pending.value == ticket.value
                && pending.session_id == ticket.session_id
                && pending.epoch == ticket.epoch
                && pending.generation == ticket.generation
                && pending.connection_id == ticket.connection_id
                && pending.candidate == ticket.candidate
                && pending.attachment_purpose == ticket.attachment_purpose
                && pending.consuming
                && pending.expires_at == ticket.expires_at
                && pending.expires_at_wall == ticket.expires_at_wall
        })
    }

    fn remove_ticket_if_matches(&mut self, ticket: &Ticket) {
        if self.ticket_matches(ticket) {
            self.tickets.remove(&ticket.value);
        }
    }

    fn session_mut(&mut self, key: &SessionKey) -> Option<&mut DeviceSession> {
        self.sessions
            .get_mut(&key.scope())
            .filter(|session| session.key == *key)
    }

    fn fail_pending(
        &mut self,
        key: &SessionKey,
        stream_id: u64,
        code: &'static str,
        execution: &'static str,
    ) {
        if let Some(session) = self.session_mut(key)
            && let Some(pending) = session.pending.remove(&stream_id)
        {
            release_pending_budget(session, &pending);
            let _ = pending
                .response
                .send(EchoOutcome::Failure { code, execution });
        }
    }

    fn invalidate_pending(
        &mut self,
        key: &SessionKey,
        stream_id: u64,
        challenge: &DeviceChallenge,
        reason: &str,
    ) {
        let _ = self.send_control(
            key,
            wire::authorization_invalidated(
                &key.session_id,
                key.epoch,
                stream_id,
                &challenge.challenge_id,
                challenge.grant_revision,
                reason,
            ),
        );
        self.fail_pending(key, stream_id, "AUTHORIZATION_REVOKED", "not_dispatched");
    }

    fn send_control(&self, key: &SessionKey, message: ControlMessage) -> Result<(), RelayError> {
        let text = wire::encode_control_message(&message)
            .map_err(|error| RelayError::Protocol(error.to_string()))?;
        let session = self.session_for(key).ok_or(RelayError::NotFound)?;
        queue_control(&session.control_tx, &session.queue_budget, text)
            .map_err(|_| RelayError::Overloaded("control queue is full"))
    }

    /// Commit the connector's exact OWNER_FENCED acknowledgement.  The
    /// handshake deadline is consumed only before this transition; after the
    /// latch is established, normal dispatch freshness is enforced by the
    /// existing challenge-bound authorization path.
    async fn handle_owner_fenced(&mut self, key: &SessionKey, fenced: OwnerFenced) {
        let mut failure = None;
        if let Some(session) = self.session_mut(key) {
            if !session.cluster_profile {
                failure = Some("UNEXPECTED_OWNER_FENCED");
            } else if let Some(expected) = session.owner_fence.as_ref() {
                if fenced.validate_context(expected).is_err() {
                    failure = Some("OWNER_FENCE_CONTEXT");
                } else if session.owner_fenced {
                    if session.owner_fence_ack.as_ref() != Some(&fenced) {
                        failure = Some("OWNER_FENCE_DUPLICATE");
                    }
                } else if session
                    .owner_fence_deadline
                    .is_some_and(|deadline| Instant::now() >= deadline)
                {
                    failure = Some("OWNER_FENCE_DEADLINE");
                } else {
                    session.owner_fenced = true;
                    session.owner_fence_ack = Some(fenced);
                    session.owner_fence_deadline = None;
                }
            } else {
                failure = Some("OWNER_FENCE_MISSING");
            }
        }
        if let Some(reason) = failure {
            self.protocol_failure(key, reason).await;
        }
    }
}

fn allocate_stream_id(next: &mut u64) -> Option<u64> {
    if *next == 0 {
        return None;
    }
    let following = next.checked_add(1)?;
    let allocated = *next;
    *next = following;
    Some(allocated)
}

fn direction_index(direction: Direction) -> usize {
    match direction {
        Direction::RelayToConnector => 0,
        Direction::ConnectorToRelay => 1,
    }
}

/// Index of one endpoint in the pure machine's per-side closure arrays.  It
/// mirrors the ordering of `RotationStatus::old_socket_closed`.
fn rotation_side_index(side: RotationSide) -> usize {
    match side {
        RotationSide::Owner => 0,
        RotationSide::Connector => 1,
    }
}

fn direction_snapshot_from_resume(
    entry: &ResumeDirectionState,
) -> tunnel_protocol::sequence::DirectionSnapshot {
    tunnel_protocol::sequence::DirectionSnapshot {
        last_emitted: entry.last_emitted,
        peer_acked: entry.peer_acked,
        recv_contiguous: entry.recv_contiguous,
        delivered_contiguous: entry.delivered_contiguous,
        send_credit: entry.send_credit,
        sent_bytes: entry.sent_bytes,
        receive_credit: entry.receive_credit,
        received_bytes: entry.received_bytes,
        send_terminal: entry.send_terminal.map(Into::into),
        send_terminal_sequence: entry.send_terminal_sequence(),
        receive_terminal: entry.receive_terminal.map(Into::into),
        receive_terminal_sequence: entry.receive_terminal_sequence(),
        replay_floor: entry.replay_floor,
        replay_bytes: 0,
        reorder_frames: 0,
        reorder_bytes: 0,
    }
}

fn is_rotation_message(message: &ControlMessage) -> bool {
    matches!(
        message,
        ControlMessage::RotateRequest(_)
            | ControlMessage::RotatePrepare(_)
            | ControlMessage::RotateQuiesce(_)
            | ControlMessage::RotateFrozen(_)
            | ControlMessage::RotateDrained(_)
            | ControlMessage::RotateCommit(_)
            | ControlMessage::RotateCommitted(_)
            | ControlMessage::RotateRetire(_)
            | ControlMessage::RotateRetired(_)
            | ControlMessage::RotateComplete(_)
            | ControlMessage::RotateAbort(_)
            | ControlMessage::RotateAborted(_)
            | ControlMessage::RecoveryBegin(_)
            | ControlMessage::RecoveryClosed(_)
            | ControlMessage::Resume(_)
            | ControlMessage::Resumed(_)
            | ControlMessage::StreamForget(_)
    )
}

fn monotonic_millis() -> u64 {
    runtime::monotonic_millis()
}

fn retain_bounded_stream_terminal_event(
    events: &mut VecDeque<StreamTerminalEvent>,
    event: StreamTerminalEvent,
) {
    // A logical stream has one terminal latch.  Do not admit a second record
    // whose later cause could make a diagnostic reader reverse-search past the
    // first, authoritative transition.
    let duplicate = events.iter().any(|existing| {
        existing.tenant_id == event.tenant_id
            && existing.device_id == event.device_id
            && existing.session_id == event.session_id
            && existing.epoch == event.epoch
            && existing.stream_id == event.stream_id
            && existing.operation_id == event.operation_id
    });
    if duplicate {
        return;
    }
    if events.len() >= MAX_STREAM_TERMINAL_EVENTS {
        events.pop_front();
    }
    events.push_back(event);
}

fn retain_bounded_stream_terminal_receipt_event(
    events: &mut VecDeque<StreamTerminalReceiptEvent>,
    event: StreamTerminalReceiptEvent,
) {
    // A connector terminal frame is idempotent on the retained stream. Dedup
    // on the complete owner/carrier/stream/request identity so a repeated late
    // FIN/RESET cannot grow the bounded ring, while a genuinely distinct
    // carrier or request still records its own receipt.
    let duplicate = events.iter().any(|existing| {
        existing.tenant_id == event.tenant_id
            && existing.device_id == event.device_id
            && existing.session_id == event.session_id
            && existing.epoch == event.epoch
            && existing.deployment_incarnation == event.deployment_incarnation
            && existing.node_id == event.node_id
            && existing.boot_id == event.boot_id
            && existing.owner_id == event.owner_id
            && existing.stream_id == event.stream_id
            && existing.operation_id == event.operation_id
            && existing.request_id == event.request_id
            && existing.active_generation == event.active_generation
            && existing.active_connection_id == event.active_connection_id
    });
    if duplicate {
        return;
    }
    if events.len() >= MAX_STREAM_TERMINAL_RECEIPT_EVENTS {
        events.pop_front();
    }
    events.push_back(event);
}

fn release_pending_budget(session: &mut DeviceSession, pending: &PendingEcho) {
    let bytes = pending
        .body
        .len()
        .saturating_add(pending.response_body.len());
    session.queued_bytes = session.queued_bytes.saturating_sub(bytes);
    session.queue_budget.release(bytes);
}

fn reserve_m2_bytes(budget: &QueueBudget, stream: &mut M2Stream, bytes: usize) -> bool {
    if bytes == 0 {
        return true;
    }
    if !budget.reserve(bytes) {
        return false;
    }
    stream.budget_bytes = stream.budget_bytes.saturating_add(bytes);
    true
}

fn release_m2_bytes(budget: &QueueBudget, stream: &mut M2Stream, bytes: usize) {
    if bytes == 0 {
        return;
    }
    let released = bytes.min(stream.budget_bytes);
    stream.budget_bytes = stream.budget_bytes.saturating_sub(released);
    budget.release(released);
}

/// Send a registration result and return the admitted value when its caller
/// disappeared between actor admission and the oneshot send.  Keeping this
/// boundary explicit makes every registration path reclaimable without
/// treating a dropped error response as an admitted resource.
fn send_registration<T>(
    response: oneshot::Sender<Result<T, RelayError>>,
    result: Result<T, RelayError>,
) -> Option<T> {
    match response.send(result) {
        Ok(()) | Err(Err(_)) => None,
        Err(Ok(value)) => Some(value),
    }
}

fn queue_control(
    sender: &mpsc::Sender<ControlOutbound>,
    budget: &QueueBudget,
    text: String,
) -> Result<(), ()> {
    let bytes = text.len();
    if !budget.reserve(bytes) {
        return Err(());
    }
    if sender
        .try_send(ControlOutbound::Text(QueuedText::new(text, budget.clone())))
        .is_err()
    {
        return Err(());
    }
    Ok(())
}

fn queue_data(
    sender: &mpsc::Sender<DataOutbound>,
    budget: &QueueBudget,
    bytes: Vec<u8>,
) -> Result<(), ()> {
    let length = bytes.len();
    if !budget.reserve(length) {
        return Err(());
    }
    if sender
        .try_send(DataOutbound::Binary(QueuedBytes::new(
            bytes,
            budget.clone(),
        )))
        .is_err()
    {
        return Err(());
    }
    Ok(())
}

fn validate_hello(message: &Hello, device_id: Uuid) -> Result<(), RelayError> {
    if message.protocol_major != u16::from(crate::PROTOCOL_MAJOR) {
        return Err(RelayError::Protocol("unsupported protocol major".into()));
    }
    if message.connector_id.parse::<Uuid>().ok() != Some(device_id) {
        return Err(RelayError::Unauthorized);
    }
    let supports_echo = message.features.iter().any(|value| value == "echo")
        || message
            .services
            .iter()
            .any(|service| service.service_type == crate::ECHO_SERVICE_TYPE);
    if !supports_echo {
        return Err(RelayError::Protocol(
            "device did not advertise fixed echo export".into(),
        ));
    }
    Ok(())
}

/// Supervise one public listener and propagate an unexpected exit to every
/// relay task.  A listener returning while the shared token is still live is
/// itself a failure: keeping sibling listeners alive would leave a partially
/// serving relay with inconsistent ownership state.
fn spawn_transport_listener<F>(
    cancel: CancellationToken,
    serve: F,
) -> JoinHandle<Result<(), tunnel_transport::TransportError>>
where
    F: Future<Output = Result<(), tunnel_transport::TransportError>> + Send + 'static,
{
    tokio::spawn(async move {
        let result = match AssertUnwindSafe(serve).catch_unwind().await {
            Ok(result) => result,
            Err(_) => Err(tunnel_transport::TransportError::Http(
                "listener task panicked".to_owned(),
            )),
        };
        let result = if result.is_ok() && !cancel.is_cancelled() {
            Err(tunnel_transport::TransportError::Http(
                "listener stopped unexpectedly".to_owned(),
            ))
        } else {
            result
        };
        if !cancel.is_cancelled() {
            cancel.cancel();
        }
        result
    })
}

fn record_first_error(slot: &mut Option<RelayError>, error: RelayError) {
    if slot.is_none() {
        *slot = Some(error);
    }
}

async fn join_relay_task<E: std::fmt::Display>(
    task: &mut JoinHandle<Result<(), E>>,
    deadline: tokio::time::Instant,
    role: &str,
) -> Option<RelayError> {
    match tokio::time::timeout_at(deadline, &mut *task).await {
        Ok(Ok(Ok(()))) => None,
        Ok(Ok(Err(error))) => Some(RelayError::Transport(error.to_string())),
        Ok(Err(error)) => Some(RelayError::Transport(format!(
            "{role} listener task failed: {error}"
        ))),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Some(RelayError::Transport(format!(
                "{role} listener shutdown timed out"
            )))
        }
    }
}

/// A running relay owns its two transport listener tasks and actor.  Dropping
/// a running value requests cancellation; callers should prefer `shutdown`
/// to observe all joins and catalog lease cleanup.
pub struct RunningRelay {
    pub(crate) handle: RelayHandle,
    cancel: CancellationToken,
    consumer_task: JoinHandle<Result<(), tunnel_transport::TransportError>>,
    device_task: JoinHandle<Result<(), tunnel_transport::TransportError>>,
    peer_task: Option<JoinHandle<Result<(), PeerTransportError>>>,
    peer_runtime: Option<Arc<crate::PeerRuntime>>,
    peer_diagnostics: Option<Arc<PeerServerDiagnostics>>,
    peer_planned_cancel: Option<CancellationToken>,
    pub consumer_addr: std::net::SocketAddr,
    pub device_addr: std::net::SocketAddr,
}

impl RunningRelay {
    /// Return the same redacted, in-process diagnostics as [`RelayHandle`].
    /// The listener wrapper intentionally adds no unauthenticated debug
    /// route; harnesses holding the running value can inspect counters
    /// directly.
    pub async fn snapshot(&self) -> Result<RelaySnapshot, RelayError> {
        self.handle.snapshot().await
    }

    /// Return bounded target-side diagnostics for the authenticated peer
    /// listener, when this relay was started with a peer listener.
    pub fn peer_server_diagnostics(&self) -> Option<Arc<PeerServerDiagnostics>> {
        self.peer_diagnostics.clone()
    }

    /// Request the explicit planned private-listener drain while leaving the
    /// public/device listeners and relay actor alive.  Emergency relay
    /// shutdown still uses the existing parent cancellation path.
    pub fn request_peer_planned_drain(&self) -> Result<(), RelayError> {
        let planned = self
            .peer_planned_cancel
            .as_ref()
            .ok_or_else(|| RelayError::Transport("relay has no peer listener".to_owned()))?;
        // Withdraw readiness at the same linearization point as the planned
        // drain request.  Existing admitted streams may finish through the
        // bounded GOAWAY path, while new peer selection cannot race ahead of
        // the listener's admission boundary.
        if let Some(peer_runtime) = &self.peer_runtime {
            peer_runtime.set_peer_listener_state(PeerListenerState::Draining);
        }
        planned.cancel();
        Ok(())
    }

    pub async fn shutdown(mut self) -> Result<(), RelayError> {
        if let Some(peer_runtime) = &self.peer_runtime {
            peer_runtime.set_peer_listener_state(PeerListenerState::Draining);
        }
        let deadline = tokio::time::Instant::now() + RUNNING_RELAY_SHUTDOWN_TIMEOUT;
        self.cancel.cancel();
        let mut first_error = None;

        // Cancellation can win the actor's select before the explicit
        // shutdown command is received.  In that expected race, Shutdown is
        // not a listener failure; the actor still runs its close_all path.
        match tokio::time::timeout_at(deadline, self.handle.shutdown()).await {
            Ok(Ok(())) | Ok(Err(RelayError::Shutdown)) => {}
            Ok(Err(error)) => record_first_error(&mut first_error, error),
            Err(_) => {
                self.handle.abort_actor_task().await;
                self.handle.abort_maintenance_task().await;
                record_first_error(
                    &mut first_error,
                    RelayError::Transport("relay actor shutdown timed out".to_owned()),
                );
            }
        }

        if let Some(error) = join_relay_task(&mut self.consumer_task, deadline, "consumer").await {
            record_first_error(&mut first_error, error);
        }
        if let Some(error) = join_relay_task(&mut self.device_task, deadline, "device").await {
            record_first_error(&mut first_error, error);
        }
        if let Some(peer_task) = self.peer_task.as_mut()
            && let Some(error) = join_relay_task(peer_task, deadline, "peer").await
        {
            record_first_error(&mut first_error, error);
        }
        if let Some(peer_runtime) = self.peer_runtime.as_ref() {
            match tokio::time::timeout_at(deadline, peer_runtime.shutdown()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    record_first_error(&mut first_error, RelayError::Transport(error.to_string()));
                }
                Err(_) => record_first_error(
                    &mut first_error,
                    RelayError::Transport("peer runtime shutdown timed out".to_owned()),
                ),
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for RunningRelay {
    fn drop(&mut self) {
        if let Some(peer_runtime) = &self.peer_runtime {
            peer_runtime.set_peer_listener_state(PeerListenerState::Draining);
        }
        self.cancel.cancel();
    }
}

/// Inputs required to run the private relay-to-relay HTTP/3 listener. The
/// endpoint and peer mTLS configuration are constructed by the deployment
/// boundary; dynamic pins come only from verified membership reconciliation.
pub struct PeerListenerConfig {
    pub endpoint: quinn::Endpoint,
    pub pins: SharedPeerPins,
    pub limits: PeerTransportLimits,
}

/// Relay construction and listener startup.
pub struct Relay;

/// Explicit options for the public listener socket boundary.
///
/// Production callers use the default, which preserves operating-system
/// accepted-socket defaults.  The optioned cluster-harness path uses the
/// consumer setting to make a physical writer-stall fixture deterministic.
#[derive(Clone, Debug, Default)]
pub struct ListenerSocketOptions {
    /// Options applied to each accepted public consumer TCP socket.
    pub consumer: tunnel_transport::AcceptedSocketOptions,
    /// Optional one-shot fixture gate after authenticated consumer admission
    /// and before Axum constructs the public WebSocket upgrade response.
    pub consumer_upgrade_barrier: Option<Arc<crate::http::ConsumerUpgradeBarrier>>,
    /// Optional fixture-only hold immediately before remote H3 admission.
    pub consumer_peer_admission_barrier: Option<Arc<crate::http::PeerAdmissionBarrier>>,
}

impl Relay {
    pub async fn start(
        options: RelayOptions,
        catalog: SharedCatalog,
        consumer_listener: TcpListener,
        device_listener: TcpListener,
        consumer_tls: Arc<rustls::ServerConfig>,
        device_tls: Arc<rustls::ServerConfig>,
    ) -> Result<RunningRelay, RelayError> {
        Self::start_inner(
            options,
            catalog,
            consumer_listener,
            device_listener,
            consumer_tls,
            device_tls,
            None,
            ListenerSocketOptions::default(),
        )
        .await
    }

    /// Start the public listeners and an authenticated private HTTP/3 peer
    /// listener. The caller owns construction and membership-driven updates
    /// of the peer endpoint and SPKI pin snapshot.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_with_peer(
        options: RelayOptions,
        catalog: SharedCatalog,
        consumer_listener: TcpListener,
        device_listener: TcpListener,
        consumer_tls: Arc<rustls::ServerConfig>,
        device_tls: Arc<rustls::ServerConfig>,
        peer: PeerListenerConfig,
        peer_runtime: Arc<crate::PeerRuntime>,
    ) -> Result<RunningRelay, RelayError> {
        Self::start_with_peer_and_listener_options(
            options,
            catalog,
            consumer_listener,
            device_listener,
            consumer_tls,
            device_tls,
            peer,
            peer_runtime,
            ListenerSocketOptions::default(),
        )
        .await
    }

    /// Start the public listeners and private peer listener with explicit
    /// accepted-socket options.
    ///
    /// The default [`Self::start_with_peer`] path retains platform socket
    /// defaults.  This narrow extension is used by the production harness to
    /// configure the accepted consumer socket itself; setting a prebound
    /// listener alone is not portable because accepted-socket option
    /// inheritance differs by platform.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_with_peer_and_listener_options(
        options: RelayOptions,
        catalog: SharedCatalog,
        consumer_listener: TcpListener,
        device_listener: TcpListener,
        consumer_tls: Arc<rustls::ServerConfig>,
        device_tls: Arc<rustls::ServerConfig>,
        peer: PeerListenerConfig,
        peer_runtime: Arc<crate::PeerRuntime>,
        listener_options: ListenerSocketOptions,
    ) -> Result<RunningRelay, RelayError> {
        Self::start_inner(
            options,
            catalog,
            consumer_listener,
            device_listener,
            consumer_tls,
            device_tls,
            Some((peer, peer_runtime)),
            listener_options,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn start_inner(
        options: RelayOptions,
        catalog: SharedCatalog,
        consumer_listener: TcpListener,
        device_listener: TcpListener,
        consumer_tls: Arc<rustls::ServerConfig>,
        device_tls: Arc<rustls::ServerConfig>,
        peer: Option<(PeerListenerConfig, Arc<crate::PeerRuntime>)>,
        listener_options: ListenerSocketOptions,
    ) -> Result<RunningRelay, RelayError> {
        options
            .validate()
            .map_err(|error| RelayError::Config(error.to_string()))?;
        let handle = RelayHandle::spawn(options.clone(), catalog.clone());
        let cancel = options.shutdown.clone();
        let consumer_addr = consumer_listener.local_addr().map_err(|error| {
            cancel.cancel();
            RelayError::Transport(error.to_string())
        })?;
        let device_addr = device_listener.local_addr().map_err(|error| {
            cancel.cancel();
            RelayError::Transport(error.to_string())
        })?;
        let (peer_runtime, peer_task, peer_diagnostics, peer_planned_cancel) =
            if let Some((peer, peer_runtime)) = peer {
                let owner_callback = http::peer_ingress_handler(
                    handle.clone(),
                    catalog.clone(),
                    options.oidc.clone(),
                    options.node_id.clone(),
                    options.boot_id.clone(),
                );
                let (policy, handler) = peer_runtime.server_components(owner_callback);
                let server = PeerServer::new_with_pin_provider(
                    peer.endpoint,
                    peer.pins,
                    peer.limits,
                    policy,
                    handler,
                )
                .map_err(|error| {
                    cancel.cancel();
                    RelayError::Transport(error.to_string())
                })?;
                let peer_diagnostics = server.diagnostics();
                // The endpoint has already been constructed and validated by the
                // caller.  Publish Bound from the library lifecycle itself so
                // readiness cannot depend on an executable-specific setter.
                peer_runtime.set_peer_listener_state(PeerListenerState::Bound);
                let peer_cancel = cancel.child_token();
                let peer_planned_cancel = CancellationToken::new();
                let peer_planned_for_task = peer_planned_cancel.clone();
                let peer_state = peer_runtime.clone();
                let peer_shared_cancel = cancel.clone();
                let task = tokio::spawn(async move {
                    // Catch a supervisor panic in this task so the readiness
                    // transition and sibling cancellation still run.
                    let result =
                        match AssertUnwindSafe(server.serve_with_planned_shutdown(
                            peer_cancel,
                            peer_planned_for_task.clone(),
                        ))
                        .catch_unwind()
                        .await
                        {
                            Ok(result) => result,
                            Err(_) => Err(PeerTransportError::H3(
                                "peer listener task panicked".to_owned(),
                            )),
                        };
                    let planned = peer_planned_for_task.is_cancelled();
                    let result = if result.is_ok() && !peer_shared_cancel.is_cancelled() && !planned
                    {
                        Err(PeerTransportError::H3(
                            "peer listener stopped unexpectedly".to_owned(),
                        ))
                    } else {
                        result
                    };
                    peer_state.set_peer_listener_state(PeerListenerState::Draining);
                    if !peer_shared_cancel.is_cancelled() && !planned {
                        peer_shared_cancel.cancel();
                    }
                    result
                });
                (
                    Some(peer_runtime),
                    Some(task),
                    Some(peer_diagnostics),
                    Some(peer_planned_cancel),
                )
            } else {
                (None, None, None, None)
            };
        let consumer_router = http::consumer_router_with_peer_and_barriers(
            handle.clone(),
            catalog.clone(),
            options.oidc.clone(),
            options.limits.clone(),
            peer_runtime.clone(),
            listener_options.consumer_upgrade_barrier.clone(),
            listener_options.consumer_peer_admission_barrier.clone(),
        );
        let device_router = http::device_router_with_peer(
            handle.clone(),
            Some(catalog.clone()),
            options.limits.clone(),
            peer_runtime.clone(),
        );
        let consumer_cancel = cancel.child_token();
        let device_cancel = cancel.child_token();
        let consumer_socket_options = listener_options.consumer;
        let consumer_task = spawn_transport_listener(cancel.clone(), async move {
            tunnel_transport::serve_with_socket_options(
                consumer_listener,
                consumer_router,
                consumer_tls,
                consumer_cancel,
                consumer_socket_options,
            )
            .await
        });
        let device_task = spawn_transport_listener(cancel.clone(), async move {
            tunnel_transport::serve(device_listener, device_router, device_tls, device_cancel).await
        });
        Ok(RunningRelay {
            handle,
            cancel,
            consumer_task,
            device_task,
            peer_task,
            peer_runtime,
            peer_diagnostics,
            peer_planned_cancel,
            consumer_addr,
            device_addr,
        })
    }

    pub async fn spawn(
        options: RelayOptions,
        catalog: SharedCatalog,
    ) -> Result<RelayHandle, RelayError> {
        options
            .validate()
            .map_err(|error| RelayError::Config(error.to_string()))?;
        Ok(RelayHandle::spawn(options, catalog))
    }

    pub fn router(
        handle: RelayHandle,
        catalog: SharedCatalog,
        oidc: Arc<tunnel_catalog::OidcVerifier>,
        limits: RelayLimits,
    ) -> Router {
        http::router(handle, catalog, oidc, limits)
    }
}

#[cfg(test)]
mod stream_identity_tests {
    use std::{
        collections::{BTreeSet, HashMap, VecDeque},
        sync::{Arc, atomic::AtomicU64},
    };

    use super::runtime::CarrierContext;
    use super::{
        AUTHORITY_UNAVAILABLE, CarrierKey, ChallengeAuthorizationResult, ControlOutbound,
        ControlRegistration, DataCarrier, DataOutbound, DataRegistration, DeviceChallenge,
        DeviceSession, DispatchRequest, M2Stream, MAX_ROTATION_TOMBSTONES,
        MaintenanceAuthorityCategory, MaintenanceAuthorityFailure, MaintenanceAuthorityOperation,
        QueueBudget, RecoveryRuntime, RelayActor, RelayError, RelayHandle, RotationJournalDecision,
        RotationRuntime, SessionKey, TerminalCleanupDispatcher, allocate_stream_id,
    };
    use chrono::{Duration, Utc};
    use tokio::sync::{mpsc, oneshot};
    use tunnel_catalog::{
        ApprovedJwk, AttachmentTicket, AttachmentTicketLocator, AuthenticatedConsumer, Catalog,
        CatalogError, CatalogFixture, CredentialRecord, DeviceIdentity, FixtureDevice,
        GrantSnapshot, GrantSpec, MembershipRecord, MembershipRole, MemoryCatalog, OidcConfig,
        OidcVerifier, OwnerClaim, OwnerClaimRequest, OwnerToken, PermissionSet, ServiceSpec,
        SharedCatalog, TenantRecord, UserRecord,
    };
    use tunnel_protocol::control_journal::ControlJournal;
    use tunnel_protocol::rotation::{RotationConfig, RotationPhase, RotationState};
    use tunnel_protocol::rotation_control::{
        DataAttachmentPurpose, DrainProof, FenceSnapshot, RotateAborted, RotateRequest,
        RotationAttemptIdentity, StreamRoster,
    };
    use tunnel_protocol::{ControlMessage, Direction, Frame, FrameKind, StreamState};
    use uuid::Uuid;

    #[test]
    fn m2_ack_filter_replies_only_to_sequenced_frames() {
        for (kind, expected) in [
            (FrameKind::Data, true),
            (FrameKind::Fin, true),
            (FrameKind::Reset, true),
            (FrameKind::Ack, false),
            (FrameKind::WindowUpdate, false),
        ] {
            assert_eq!(
                super::RelayActor::should_ack_m2_frame(kind),
                expected,
                "unexpected ACK feedback policy for {kind:?}"
            );
        }
    }

    #[tokio::test]
    async fn m2_ack_feedback_replies_to_data_and_duplicate_but_not_control() {
        let now = Utc::now();
        let tenant_id = Uuid::from_u128(1);
        let device_id = Uuid::from_u128(2);
        let service_id = Uuid::from_u128(3);
        let principal_id = Uuid::from_u128(4);
        let stream_id = 7;
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "ack-feedback".to_owned(),
            epoch: 1,
        };
        let identity = DeviceIdentity {
            tenant_id,
            device_id,
            owner_user_id: principal_id,
            credential_id: Uuid::from_u128(5),
            spki_fingerprint: "test-spki".to_owned(),
            credential_not_before: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(1),
            credential_revoked_at: None,
            device_active: true,
            credential_active: true,
            device_version: 1,
            owner_epoch: 1,
            last_seen_at: Some(now),
        };
        let (mut actor, _registration) = admitted_control_actor(identity, key.clone());
        let (data_tx, mut data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        let carrier = CarrierKey {
            session: key.clone(),
            generation: 1,
            connection_id: "ack-feedback-data".to_owned(),
        };
        let consumer = AuthenticatedConsumer {
            tenant_id,
            principal_id,
        };
        let grant = GrantSnapshot {
            tenant_id,
            principal_id,
            device_id,
            service_id,
            revision: 1,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            valid_until: now + Duration::minutes(1),
            read_started_at: now,
        };
        let sequence = StreamState::new(stream_id, crate::wire::M2_INITIAL_WINDOW_BYTES as u64)
            .expect("valid M2 stream sequence");
        {
            let session = actor.sessions.get_mut(&key.scope()).expect("test session");
            session.profile = super::RuntimeProfile::M2;
            session.data_tx = Some(data_tx.clone());
            session.active_carrier = Some(DataCarrier {
                context: carrier.context(),
                tx: data_tx,
            });
            session.streams.insert(
                stream_id,
                M2Stream {
                    open_message_id: "ack-feedback-open".to_owned(),
                    operation_id: "ack-feedback-op".to_owned(),
                    request_id: None,
                    service_id,
                    consumer,
                    grant,
                    sequence,
                    response_bytes: Vec::new(),
                    response_records: VecDeque::new(),
                    send_bytes: 0,
                    receive_bytes: 0,
                    authorized_until: None,
                    consumer_expires_at: now + Duration::minutes(1),
                    challenge_id: None,
                    authorization_in_flight: false,
                    authorization_started_at_ms: None,
                    authorization_deadline_ms: None,
                    authorization_admission_deadline_ms: None,
                    pending_records: VecDeque::new(),
                    pending_record_bytes: 0,
                    budget_bytes: 0,
                    terminal: false,
                    pending_terminal: None,
                    terminal_fin_failure: false,
                    open_pending: false,
                    registration_dropped: false,
                    deferred_terminal_cause: None,
                    closed: tokio_util::sync::CancellationToken::new(),
                    admission_lease: tokio_util::sync::CancellationToken::new(),
                    admission_deadline: std::time::Instant::now()
                        + std::time::Duration::from_secs(60),
                    authorization_failure_code: None,
                },
            );
        }

        actor
            .inbound_m2_stream_data(
                carrier.clone(),
                Frame::ack(key.epoch, carrier.generation, stream_id, 0),
                false,
            )
            .await;
        assert!(matches!(
            data_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        actor
            .inbound_m2_stream_data(
                carrier.clone(),
                Frame::window_update(
                    key.epoch,
                    carrier.generation,
                    stream_id,
                    crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                ),
                false,
            )
            .await;
        assert!(matches!(
            data_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        let data = Frame::data(
            key.epoch,
            carrier.generation,
            stream_id,
            1,
            0,
            vec![1, 2, 3],
        );
        for (label, frame) in [("first DATA", data.clone()), ("duplicate DATA", data)] {
            actor
                .inbound_m2_stream_data(carrier.clone(), frame, false)
                .await;
            let Some(DataOutbound::Binary(mut queued)) = data_rx.recv().await else {
                panic!("{label} did not produce an ACK");
            };
            let ack = Frame::decode(queued.as_slice()).expect("encoded ACK frame");
            assert_eq!(ack.kind, FrameKind::Ack, "{label} response kind");
            assert_eq!(ack.stream_id, stream_id, "{label} response stream");
            assert_eq!(ack.ack, 1, "{label} response cursor");
            queued.release();
        }
    }

    #[tokio::test]
    async fn m2_maximum_records_wait_for_absolute_credit_without_partial_terminal() {
        let now = Utc::now();
        let tenant_id = Uuid::from_u128(11);
        let device_id = Uuid::from_u128(12);
        let service_id = Uuid::from_u128(13);
        let principal_id = Uuid::from_u128(14);
        let stream_id = 9;
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "credit-retry".to_owned(),
            epoch: 1,
        };
        let identity = DeviceIdentity {
            tenant_id,
            device_id,
            owner_user_id: principal_id,
            credential_id: Uuid::from_u128(15),
            spki_fingerprint: "credit-retry-spki".to_owned(),
            credential_not_before: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(1),
            credential_revoked_at: None,
            device_active: true,
            credential_active: true,
            device_version: 1,
            owner_epoch: 1,
            last_seen_at: Some(now),
        };
        let (mut actor, _registration) = admitted_control_actor(identity, key.clone());
        let (data_tx, mut data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        let carrier = CarrierKey {
            session: key.clone(),
            generation: 1,
            connection_id: "credit-retry-data".to_owned(),
        };
        let consumer = AuthenticatedConsumer {
            tenant_id,
            principal_id,
        };
        let grant = GrantSnapshot {
            tenant_id,
            principal_id,
            device_id,
            service_id,
            revision: 1,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            valid_until: now + Duration::minutes(1),
            read_started_at: now,
        };
        let sequence = StreamState::new(stream_id, crate::wire::M2_INITIAL_WINDOW_BYTES as u64)
            .expect("valid M2 stream sequence");
        {
            let session = actor.sessions.get_mut(&key.scope()).expect("test session");
            session.profile = super::RuntimeProfile::M2;
            session.data_tx = Some(data_tx.clone());
            session.active_carrier = Some(DataCarrier {
                context: carrier.context(),
                tx: data_tx,
            });
            session.streams.insert(
                stream_id,
                M2Stream {
                    open_message_id: "credit-retry-open".to_owned(),
                    operation_id: "credit-retry-op".to_owned(),
                    request_id: None,
                    service_id,
                    consumer,
                    grant,
                    sequence,
                    response_bytes: Vec::new(),
                    response_records: VecDeque::new(),
                    send_bytes: 0,
                    receive_bytes: 0,
                    authorized_until: Some(
                        std::time::Instant::now() + std::time::Duration::from_secs(60),
                    ),
                    consumer_expires_at: now + Duration::minutes(1),
                    challenge_id: None,
                    authorization_in_flight: false,
                    authorization_started_at_ms: None,
                    authorization_deadline_ms: None,
                    authorization_admission_deadline_ms: None,
                    pending_records: VecDeque::new(),
                    pending_record_bytes: 0,
                    budget_bytes: 0,
                    terminal: false,
                    pending_terminal: None,
                    terminal_fin_failure: false,
                    open_pending: false,
                    registration_dropped: false,
                    deferred_terminal_cause: None,
                    closed: tokio_util::sync::CancellationToken::new(),
                    admission_lease: tokio_util::sync::CancellationToken::new(),
                    admission_deadline: std::time::Instant::now()
                        + std::time::Duration::from_secs(60),
                    authorization_failure_code: None,
                },
            );
        }

        let maximum = vec![0xA5; crate::wire::MAX_BODY_BYTES];
        let mut response_receivers = Vec::new();
        for _ in 0..3 {
            let (response, receiver) = oneshot::channel();
            actor.write_echo_stream(
                key.clone(),
                stream_id,
                "credit-retry-op".to_owned(),
                maximum.clone(),
                response,
            );
            response_receivers.push(receiver);
        }

        let record_len = u64::try_from(maximum.len() + 4).expect("record length fits u64");
        {
            let stream = actor
                .sessions
                .get(&key.scope())
                .and_then(|session| session.streams.get(&stream_id))
                .expect("M2 stream remains active");
            assert_eq!(
                stream
                    .sequence
                    .direction(Direction::RelayToConnector)
                    .last_emitted(),
                2
            );
            assert_eq!(stream.pending_records.len(), 2);
            assert_eq!(stream.pending_record_bytes, maximum.len() * 2);
            assert!(!stream.terminal);
        }
        for expected_sequence in 1..=2 {
            let Some(DataOutbound::Binary(mut bytes)) = data_rx.recv().await else {
                panic!("initial maximum record frame {expected_sequence} missing");
            };
            let frame = Frame::decode(bytes.as_slice()).expect("initial DATA frame decodes");
            assert_eq!(frame.kind, FrameKind::Data);
            assert_eq!(frame.sequence, expected_sequence);
            bytes.release();
        }

        let expanded_credit = record_len * 3;
        actor
            .inbound_m2_stream_data(
                carrier,
                Frame::window_update(key.epoch, 1, stream_id, expanded_credit),
                false,
            )
            .await;

        let stream = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.streams.get(&stream_id))
            .expect("M2 stream remains active after credit update");
        assert_eq!(stream.pending_records.len(), 0);
        assert_eq!(stream.pending_record_bytes, 0);
        assert_eq!(
            stream
                .sequence
                .direction(Direction::RelayToConnector)
                .last_emitted(),
            6
        );
        assert!(!stream.terminal);
        assert_eq!(
            stream
                .sequence
                .direction(Direction::RelayToConnector)
                .send_credit(),
            expanded_credit
        );

        for expected_sequence in 3..=6 {
            let Some(DataOutbound::Binary(mut bytes)) = data_rx.recv().await else {
                panic!("retried maximum record frame {expected_sequence} missing");
            };
            let frame = Frame::decode(bytes.as_slice()).expect("retried DATA frame decodes");
            assert_eq!(frame.kind, FrameKind::Data);
            assert_eq!(frame.sequence, expected_sequence);
            bytes.release();
        }
        assert!(matches!(
            data_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        drop(response_receivers);
    }

    pub(super) fn shared_device_fixture() -> (CatalogFixture, Uuid, Uuid, Uuid, String, String) {
        let tenant_a = Uuid::from_u128(1);
        let tenant_b = Uuid::from_u128(2);
        let user_a = Uuid::from_u128(11);
        let user_b = Uuid::from_u128(12);
        let device_id = Uuid::from_u128(21);
        let service_id = Uuid::from_u128(31);
        let credential_a = Uuid::from_u128(41);
        let credential_b = Uuid::from_u128(42);
        let spki_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let spki_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let now = Utc::now();
        let permissions = || PermissionSet {
            operations: BTreeSet::from(["echo:invoke".to_owned()]),
        };
        let service = |tenant_id| ServiceSpec {
            tenant_id,
            device_id,
            service_id,
            service_type: "echo".to_owned(),
            display_name: "Echo".to_owned(),
            capabilities: serde_json::json!({"operations": ["echo:invoke"]}),
            version: 1,
            active: true,
        };
        let grant = |tenant_id, principal_id| GrantSpec {
            tenant_id,
            principal_id,
            device_id,
            service_id,
            permissions: permissions(),
            constraints: serde_json::json!({}),
            expires_at: Some(now + Duration::hours(1)),
            active: true,
        };
        let fixture = CatalogFixture {
            tenants: vec![
                TenantRecord {
                    tenant_id: tenant_a,
                    display_name: "tenant-a".to_owned(),
                    active: true,
                },
                TenantRecord {
                    tenant_id: tenant_b,
                    display_name: "tenant-b".to_owned(),
                    active: true,
                },
            ],
            users: vec![
                UserRecord {
                    user_id: user_a,
                    display_name: "Alice".to_owned(),
                },
                UserRecord {
                    user_id: user_b,
                    display_name: "Bob".to_owned(),
                },
            ],
            identities: Vec::new(),
            memberships: vec![
                MembershipRecord {
                    tenant_id: tenant_a,
                    user_id: user_a,
                    role: MembershipRole::Member,
                    active: true,
                },
                MembershipRecord {
                    tenant_id: tenant_b,
                    user_id: user_b,
                    role: MembershipRole::Member,
                    active: true,
                },
            ],
            devices: vec![
                FixtureDevice {
                    tenant_id: tenant_a,
                    device_id,
                    owner_user_id: user_a,
                    display_name: "Alice Mac".to_owned(),
                    active: true,
                    last_seen_at: Some(now),
                },
                FixtureDevice {
                    tenant_id: tenant_b,
                    device_id,
                    owner_user_id: user_b,
                    display_name: "Bob Mac".to_owned(),
                    active: true,
                    last_seen_at: Some(now),
                },
            ],
            credentials: vec![
                CredentialRecord {
                    tenant_id: tenant_a,
                    device_id,
                    credential_id: credential_a,
                    spki_fingerprint: spki_a.to_owned(),
                    serial: Some("a".to_owned()),
                    not_before: now - Duration::seconds(1),
                    expires_at: now + Duration::hours(1),
                    revoked_at: None,
                    active: true,
                },
                CredentialRecord {
                    tenant_id: tenant_b,
                    device_id,
                    credential_id: credential_b,
                    spki_fingerprint: spki_b.to_owned(),
                    serial: Some("b".to_owned()),
                    not_before: now - Duration::seconds(1),
                    expires_at: now + Duration::hours(1),
                    revoked_at: None,
                    active: true,
                },
            ],
            services: vec![service(tenant_a), service(tenant_b)],
            grants: vec![grant(tenant_a, user_a), grant(tenant_b, user_b)],
        };
        (
            fixture,
            device_id,
            tenant_a,
            tenant_b,
            spki_a.to_owned(),
            spki_b.to_owned(),
        )
    }

    fn hello(device_id: Uuid, message_id: &str) -> tunnel_protocol::Hello {
        let mut hello = tunnel_protocol::Hello::new(
            message_id,
            device_id.to_string(),
            u16::from(crate::PROTOCOL_MAJOR),
            0,
        );
        hello.features.push("echo".to_owned());
        hello
    }

    pub(super) fn admitted_control_actor(
        identity: DeviceIdentity,
        key: SessionKey,
    ) -> (RelayActor, ControlRegistration) {
        let oidc_key = ApprovedJwk::from_ed25519_der("test", &[0_u8; 32]).expect("test OIDC key");
        let oidc_config = OidcConfig::new(
            "https://issuer.example",
            ["audience".to_owned()],
            vec![oidc_key],
        )
        .expect("test OIDC config");
        let options = super::RelayOptions::new(Arc::new(
            OidcVerifier::new(oidc_config).expect("test OIDC verifier"),
        ));
        let owner = OwnerToken {
            deployment_incarnation: "test-incarnation".to_owned(),
            tenant_id: key.tenant_id,
            device_id: key.device_id,
            node_id: "test-node".to_owned(),
            boot_id: "test-boot".to_owned(),
            session_id: key.session_id.clone(),
            epoch: key.epoch,
        };
        let (control_tx, control_rx) = mpsc::channel(options.limits.max_queue_messages);
        let queue_budget = QueueBudget::new(options.limits.max_queue_bytes);
        let session = DeviceSession {
            identity,
            owner,
            key: key.clone(),
            control_tx,
            data_tx: None,
            active_carrier: None,
            generation: 1,
            connection_id: "test-data".to_owned(),
            profile: super::RuntimeProfile::M1,
            cluster_profile: false,
            owner_fence: None,
            owner_fenced: true,
            owner_fence_ack: None,
            owner_fence_deadline: None,
            next_stream_id: 1,
            pending: HashMap::new(),
            streams: HashMap::new(),
            forgotten_stream_through: 0,
            owner_forget_deadline: None,
            terminal_fin_failure_deadline: None,
            rotation: None,
            last_rotation: std::time::Instant::now(),
            rotations_completed: 0,
            total_replayed_frames: 0,
            queued_bytes: 0,
            queue_budget: queue_budget.clone(),
            last_lease_renewal: std::time::Instant::now(),
            maintenance_in_flight: false,
            closed: false,
        };
        let (command_tx, command_rx) = mpsc::channel(4);
        let (terminal_tx, terminal_cleanup_rx) =
            mpsc::channel(super::TERMINAL_CLEANUP_QUEUE_CAPACITY);
        let dispatcher = TerminalCleanupDispatcher::new(terminal_tx);
        let mut sessions = HashMap::new();
        sessions.insert(key.scope(), session);
        let actor = RelayActor {
            options,
            catalog: Arc::new(MemoryCatalog::new()) as SharedCatalog,
            command_tx,
            rx: command_rx,
            terminal_cleanup_rx,
            terminal_cleanup_overflowed: dispatcher.overflowed.clone(),
            terminal_cleanup_notify: dispatcher.notify.clone(),
            sessions,
            registering: Default::default(),
            pending_registering: Default::default(),
            tickets: Default::default(),
            owner_forgets: Default::default(),
            lifetime_application_dispatches: 0,
            control_registration_conflicts: 0,
            rotation_deadline_events: VecDeque::new(),
            session_terminal_events: VecDeque::new(),
            stream_terminal_events: VecDeque::new(),
            stream_terminal_receipt_events: VecDeque::new(),
            consumer_chunk_reads: Arc::new(AtomicU64::new(0)),
            consumer_write_diagnostics: super::ConsumerWriteDiagnostics::default(),
            peer_transport_diagnostics: super::PeerTransportDiagnostics::default(),
            peer_consumer_diagnostics: super::PeerConsumerDiagnostics::default(),
            cleanup_dispatcher: None,
            cleanup: None,
            background_tasks: tokio::task::JoinSet::new(),
            background_failure: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            shutting_down: false,
        };
        (
            actor,
            ControlRegistration {
                key,
                welcome: String::new(),
                rx: control_rx,
            },
        )
    }

    /// One admitted forwarded M2 echo stream after the real OPEN/OPENED
    /// exchange, so terminal-latch regressions start from a live logical
    /// stream with a committed data carrier.
    struct TerminalLatchFixture {
        actor: RelayActor,
        control: ControlRegistration,
        data_rx: mpsc::Receiver<DataOutbound>,
        key: SessionKey,
        carrier: CarrierKey,
        registration: super::ConsumerStreamRegistration,
    }

    async fn open_terminal_latch_stream(label: &str, request_id: &str) -> TerminalLatchFixture {
        let wait = std::time::Duration::from_secs(1);
        let now = Utc::now();
        let tenant_id = Uuid::from_u128(701);
        let device_id = Uuid::from_u128(702);
        let principal_id = Uuid::from_u128(703);
        let service_id = Uuid::from_u128(704);
        let identity = DeviceIdentity {
            tenant_id,
            device_id,
            owner_user_id: principal_id,
            credential_id: Uuid::from_u128(705),
            spki_fingerprint: format!("{label}-spki"),
            credential_not_before: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(1),
            credential_revoked_at: None,
            device_active: true,
            credential_active: true,
            device_version: 1,
            owner_epoch: 1,
            last_seen_at: Some(now),
        };
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: label.to_owned(),
            epoch: 7,
        };
        let (mut actor, mut control) = admitted_control_actor(identity, key.clone());
        let (data_tx, data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        let carrier = CarrierKey {
            session: key.clone(),
            generation: 3,
            connection_id: format!("{label}-carrier"),
        };
        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            session.profile = super::RuntimeProfile::M2;
            session.generation = carrier.generation;
            session.connection_id = carrier.connection_id.clone();
            session.data_tx = Some(data_tx.clone());
            session.active_carrier = Some(DataCarrier {
                context: carrier.context(),
                tx: data_tx,
            });
        }
        let consumer = AuthenticatedConsumer {
            tenant_id,
            principal_id,
        };
        let grant = GrantSnapshot {
            tenant_id,
            principal_id,
            device_id,
            service_id,
            revision: 9,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            valid_until: now + Duration::minutes(1),
            read_started_at: now,
        };
        let (open_tx, open_rx) = oneshot::channel();
        actor.open_echo_stream_with_request_id(
            consumer,
            device_id,
            service_id,
            grant,
            now + Duration::minutes(1),
            Some(request_id.to_owned()),
            open_tx,
        );
        let registration = tokio::time::timeout(wait, open_rx)
            .await
            .expect("echo registration response timed out")
            .expect("echo registration response")
            .expect("echo stream admitted");
        registration.claim_admission();
        let Some(ControlOutbound::Text(mut open)) = tokio::time::timeout(wait, control.rx.recv())
            .await
            .expect("echo OPEN wait timed out")
        else {
            panic!("echo OPEN was not queued");
        };
        open.release();
        let open_message_id = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.streams.get(&registration.stream_id))
            .map(|stream| stream.open_message_id.clone())
            .expect("OPEN correlation");
        tokio::time::timeout(
            wait,
            actor.inbound_control(
                key.clone(),
                ControlMessage::Opened(tunnel_protocol::Opened::new(
                    format!("{label}-opened"),
                    open_message_id,
                    key.session_id.clone(),
                    key.epoch,
                    registration.stream_id,
                    registration.operation_id.clone(),
                    crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                    crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                )),
            ),
        )
        .await
        .expect("OPENED handling timed out");
        TerminalLatchFixture {
            actor,
            control,
            data_rx,
            key,
            carrier,
            registration,
        }
    }

    /// Consume the relay FIN already queued by a close, answer it with the
    /// connector's terminal FIN, observe the relay ACK, then observe the owner
    /// STREAM_FORGET.  Queuing that FORGET is the real path that removes the
    /// live logical stream from the session table.
    async fn drive_connector_fin_and_owner_forget(fixture: &mut TerminalLatchFixture) {
        let wait = std::time::Duration::from_secs(1);
        let stream_id = fixture.registration.stream_id;
        let Some(DataOutbound::Binary(mut fin)) =
            tokio::time::timeout(wait, fixture.data_rx.recv())
                .await
                .expect("relay FIN wait timed out")
        else {
            panic!("relay FIN was not queued");
        };
        let fin_frame = Frame::decode(fin.as_slice()).expect("relay FIN decodes");
        assert_eq!(fin_frame.kind, FrameKind::Fin);
        assert_eq!(fin_frame.stream_id, stream_id);
        fin.release();
        tokio::time::timeout(
            wait,
            fixture.actor.inbound_m2_stream_data(
                fixture.carrier.clone(),
                Frame::fin(
                    fixture.key.epoch,
                    fixture.carrier.generation,
                    stream_id,
                    1,
                    fin_frame.sequence,
                ),
                false,
            ),
        )
        .await
        .expect("connector FIN handling timed out");
        let Some(DataOutbound::Binary(mut ack)) =
            tokio::time::timeout(wait, fixture.data_rx.recv())
                .await
                .expect("connector FIN ACK wait timed out")
        else {
            panic!("connector FIN ACK was not queued");
        };
        assert_eq!(
            Frame::decode(ack.as_slice())
                .expect("connector FIN ACK decodes")
                .kind,
            FrameKind::Ack
        );
        ack.release();
        let Some(ControlOutbound::Text(mut forget)) =
            tokio::time::timeout(wait, fixture.control.rx.recv())
                .await
                .expect("owner STREAM_FORGET wait timed out")
        else {
            panic!("owner STREAM_FORGET was not queued");
        };
        let forget_message =
            super::wire::parse_control(forget.as_bytes()).expect("owner STREAM_FORGET decodes");
        forget.release();
        assert!(matches!(
            forget_message,
            ControlMessage::StreamForget(ref value)
                if value.stream_id == stream_id
                    && value.operation_id == fixture.registration.operation_id
        ));
    }

    #[tokio::test]
    async fn dropped_forwarded_stream_guard_latches_membership_expiry_cause_before_forget() {
        let mut fixture =
            open_terminal_latch_stream("terminal-latch-expiry", "forwarded-request-701").await;
        let stream_id = fixture.registration.stream_id;
        let operation_id = fixture.registration.operation_id.clone();

        // The forwarded handler is dropped at the membership cancellation
        // edge before its loop can classify the exit.  The admission's own
        // monotonic trust deadline has passed while the local invalidation
        // dispatcher has not cancelled the edge yet (the ingress relay
        // enforces the same deadline and may reset first).  The guard must
        // still resolve the typed first cause instead of a generic close.
        let (cleanup_tx, mut cleanup_rx) = mpsc::channel(super::TERMINAL_CLEANUP_QUEUE_CAPACITY);
        let dispatcher = TerminalCleanupDispatcher::new(cleanup_tx);
        let admission = super::PeerAdmissionCancellation::from_token_with_deadline(
            tokio_util::sync::CancellationToken::new(),
            std::time::Instant::now() - std::time::Duration::from_millis(1),
        );
        assert!(!admission.is_cancelled());
        drop(dispatcher.guard_with_admission(
            super::TerminalCleanup::EchoStream {
                key: fixture.key.clone(),
                stream_id,
                operation_id: operation_id.clone(),
                cause: None,
            },
            Some(admission),
        ));
        let cleanup = cleanup_rx
            .try_recv()
            .expect("dropped guard enqueued exact cleanup without awaiting");
        assert_eq!(
            cleanup,
            super::TerminalCleanup::EchoStream {
                key: fixture.key.clone(),
                stream_id,
                operation_id: operation_id.clone(),
                cause: Some(super::StreamTerminalCause::PeerMembershipExpired),
            }
        );
        fixture.actor.handle_terminal_cleanup(cleanup).await;

        // A later cause-less close of the same logical stream (for example
        // the handler's own cleanup racing the guard) is accepted but can
        // never replace the first terminal transition or queue a second FIN.
        assert!(
            fixture
                .actor
                .close_echo_stream(&fixture.key, stream_id, &operation_id)
        );

        drive_connector_fin_and_owner_forget(&mut fixture).await;

        // STREAM_FORGET reclaimed the exact logical stream while the owner
        // session itself is still live: the latch, not the stream table, is
        // the only remaining evidence and it must carry the typed cause.
        let session = fixture
            .actor
            .sessions
            .get(&fixture.key.scope())
            .expect("owner session remains live after STREAM_FORGET");
        assert!(!session.streams.contains_key(&stream_id));
        let expected_owner = session.owner.clone();
        let snapshot = fixture.actor.snapshot();
        assert!(
            snapshot
                .sessions
                .iter()
                .flat_map(|session| session.streams.iter())
                .all(|stream| stream.stream_id != stream_id)
        );
        let events = snapshot
            .stream_terminal_events
            .iter()
            .filter(|event| event.stream_id == stream_id && event.operation_id == operation_id)
            .collect::<Vec<_>>();
        assert_eq!(
            events.len(),
            1,
            "exactly one terminal latch per logical stream"
        );
        let event = events[0];
        assert_eq!(
            event.cause,
            Some(super::StreamTerminalCause::PeerMembershipExpired)
        );
        assert_eq!(event.reason, "STREAM_CLOSED");
        assert!(event.authorization_failure_code.is_none());
        assert_eq!(event.tenant_id, fixture.key.tenant_id.to_string());
        assert_eq!(event.device_id, fixture.key.device_id.to_string());
        assert_eq!(event.session_id, fixture.key.session_id);
        assert_eq!(event.epoch, fixture.key.epoch);
        assert_eq!(
            event.deployment_incarnation,
            expected_owner.deployment_incarnation
        );
        assert_eq!(event.node_id, expected_owner.node_id);
        assert_eq!(event.boot_id, expected_owner.boot_id);
        assert_eq!(event.owner_id, super::runtime::owner_id(&expected_owner));
        assert_eq!(event.request_id.as_deref(), Some("forwarded-request-701"));
        assert_eq!(event.active_generation, fixture.carrier.generation);
        assert_eq!(event.active_connection_id, fixture.carrier.connection_id);
        assert_eq!(event.last_emitted_relay_to_connector, 1);
        assert_eq!(event.recv_contiguous_connector_to_relay, 0);
    }

    #[test]
    fn dropped_guard_without_trust_expiry_evidence_keeps_unclassified_close() {
        let (cleanup_tx, mut cleanup_rx) = mpsc::channel(super::TERMINAL_CLEANUP_QUEUE_CAPACITY);
        let dispatcher = TerminalCleanupDispatcher::new(cleanup_tx);
        let key = SessionKey {
            tenant_id: Uuid::from_u128(1),
            device_id: Uuid::from_u128(2),
            session_id: "guard-unclassified".to_owned(),
            epoch: 3,
        };
        let cleanup = super::TerminalCleanup::EchoStream {
            key,
            stream_id: 11,
            operation_id: "operation-11".to_owned(),
            cause: None,
        };

        // A local public stream has no admission edge.
        drop(dispatcher.guard(cleanup.clone()));
        // A live admission with a future deadline is not expiry, and neither
        // is an unclassified cancellation of that edge (a closed connection).
        let live = super::PeerAdmissionCancellation::from_token_with_deadline(
            tokio_util::sync::CancellationToken::new(),
            std::time::Instant::now() + std::time::Duration::from_secs(60),
        );
        live.token().cancel();
        drop(dispatcher.guard_with_admission(cleanup.clone(), Some(live)));

        for _ in 0..2 {
            assert_eq!(
                cleanup_rx.try_recv().expect("guard enqueued cleanup"),
                cleanup,
                "no trust-expiry evidence must leave the terminal cause unclassified"
            );
        }
    }

    fn terminal_latch_event(
        stream_id: u64,
        closed_at_ms: u64,
        cause: Option<super::StreamTerminalCause>,
    ) -> super::StreamTerminalEvent {
        super::StreamTerminalEvent {
            tenant_id: "tenant-1".to_owned(),
            device_id: "device-1".to_owned(),
            session_id: "session-1".to_owned(),
            epoch: 7,
            deployment_incarnation: "incarnation-1".to_owned(),
            node_id: "node-1".to_owned(),
            boot_id: "boot-1".to_owned(),
            owner_id: "owner-1".to_owned(),
            stream_id,
            operation_id: format!("operation-{stream_id}"),
            request_id: Some(format!("request-{stream_id}")),
            active_generation: 3,
            active_connection_id: "carrier-3".to_owned(),
            rotations_completed: 2,
            total_replayed_frames: 0,
            last_emitted_relay_to_connector: 11,
            peer_acked_relay_to_connector: 10,
            recv_contiguous_connector_to_relay: 9,
            delivered_contiguous_connector_to_relay: 9,
            closed_at_ms,
            authorization_failure_code: None,
            reason: "STREAM_CLOSED",
            cause,
        }
    }

    #[test]
    fn stream_terminal_latch_retention_is_bounded_and_first_transition_only() {
        let capacity = super::MAX_STREAM_TERMINAL_EVENTS as u64;
        let mut events = VecDeque::new();
        for stream_id in 1..=capacity + 1 {
            super::retain_bounded_stream_terminal_event(
                &mut events,
                terminal_latch_event(stream_id, stream_id, None),
            );
        }
        // Memory stays bounded: the oldest latch is evicted first and the
        // most recent transition is always present.
        assert_eq!(events.len(), super::MAX_STREAM_TERMINAL_EVENTS);
        assert_eq!(events.front().map(|event| event.stream_id), Some(2));
        assert_eq!(
            events.back().map(|event| event.stream_id),
            Some(capacity + 1)
        );

        // One logical stream has one terminal latch.  A later record for the
        // same exact identity, even one carrying a typed cause, neither
        // replaces the first transition nor consumes retention capacity.
        super::retain_bounded_stream_terminal_event(
            &mut events,
            terminal_latch_event(
                10,
                9_999,
                Some(super::StreamTerminalCause::PeerMembershipExpired),
            ),
        );
        assert_eq!(events.len(), super::MAX_STREAM_TERMINAL_EVENTS);
        let retained = events
            .iter()
            .filter(|event| event.stream_id == 10)
            .collect::<Vec<_>>();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].closed_at_ms, 10);
        assert!(retained[0].cause.is_none());

        // A first transition that carries the typed cause keeps it across
        // later eviction pressure until it is itself the oldest entry.
        super::retain_bounded_stream_terminal_event(
            &mut events,
            terminal_latch_event(
                capacity + 2,
                capacity + 2,
                Some(super::StreamTerminalCause::PeerMembershipExpired),
            ),
        );
        assert_eq!(events.len(), super::MAX_STREAM_TERMINAL_EVENTS);
        assert_eq!(events.front().map(|event| event.stream_id), Some(3));
        assert_eq!(
            events.back().and_then(|event| event.cause),
            Some(super::StreamTerminalCause::PeerMembershipExpired)
        );
    }

    #[tokio::test]
    async fn stream_terminal_latch_survives_forget_with_exact_owner_and_request() {
        let wait = std::time::Duration::from_secs(1);
        let now = Utc::now();
        let tenant_id = Uuid::from_u128(601);
        let device_id = Uuid::from_u128(602);
        let principal_id = Uuid::from_u128(603);
        let service_id = Uuid::from_u128(604);
        let identity = DeviceIdentity {
            tenant_id,
            device_id,
            owner_user_id: principal_id,
            credential_id: Uuid::from_u128(605),
            spki_fingerprint: "terminal-latch-spki".to_owned(),
            credential_not_before: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(1),
            credential_revoked_at: None,
            device_active: true,
            credential_active: true,
            device_version: 1,
            owner_epoch: 1,
            last_seen_at: Some(now),
        };
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "terminal-latch".to_owned(),
            epoch: 7,
        };
        let (mut actor, mut control) = admitted_control_actor(identity, key.clone());
        let (data_tx, mut data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        let carrier = CarrierKey {
            session: key.clone(),
            generation: 3,
            connection_id: "terminal-latch-carrier".to_owned(),
        };
        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            session.profile = super::RuntimeProfile::M2;
            session.generation = carrier.generation;
            session.connection_id = carrier.connection_id.clone();
            session.data_tx = Some(data_tx.clone());
            session.active_carrier = Some(DataCarrier {
                context: carrier.context(),
                tx: data_tx,
            });
        }
        let consumer = AuthenticatedConsumer {
            tenant_id,
            principal_id,
        };
        let grant = GrantSnapshot {
            tenant_id,
            principal_id,
            device_id,
            service_id,
            revision: 9,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            valid_until: now + Duration::minutes(1),
            read_started_at: now,
        };
        let (open_tx, open_rx) = oneshot::channel();
        actor.open_echo_stream_with_request_id(
            consumer,
            device_id,
            service_id,
            grant,
            now + Duration::minutes(1),
            Some("forwarded-request-601".to_owned()),
            open_tx,
        );
        let registration = tokio::time::timeout(wait, open_rx)
            .await
            .expect("echo registration response timed out")
            .expect("echo registration response")
            .expect("echo stream admitted");
        registration.claim_admission();
        let Some(ControlOutbound::Text(mut open)) = tokio::time::timeout(wait, control.rx.recv())
            .await
            .expect("echo OPEN wait timed out")
        else {
            panic!("echo OPEN was not queued");
        };
        open.release();
        let open_message_id = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.streams.get(&registration.stream_id))
            .map(|stream| stream.open_message_id.clone())
            .expect("OPEN correlation");
        tokio::time::timeout(
            wait,
            actor.inbound_control(
                key.clone(),
                ControlMessage::Opened(tunnel_protocol::Opened::new(
                    "terminal-latch-opened",
                    open_message_id,
                    key.session_id.clone(),
                    key.epoch,
                    registration.stream_id,
                    registration.operation_id.clone(),
                    crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                    crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                )),
            ),
        )
        .await
        .expect("OPENED handling timed out");

        assert!(actor.close_echo_stream(&key, registration.stream_id, &registration.operation_id,));
        let Some(DataOutbound::Binary(mut fin)) = tokio::time::timeout(wait, data_rx.recv())
            .await
            .expect("relay FIN wait timed out")
        else {
            panic!("relay FIN was not queued");
        };
        let fin_frame = Frame::decode(fin.as_slice()).expect("relay FIN decodes");
        assert_eq!(fin_frame.kind, FrameKind::Fin);
        assert_eq!(fin_frame.stream_id, registration.stream_id);
        fin.release();

        // The connector's terminal frame acknowledges the relay FIN and
        // supplies the receive-side terminal cursor.  This is the real path
        // that makes the owner FORGET eligible and removes the live stream.
        tokio::time::timeout(
            wait,
            actor.inbound_m2_stream_data(
                carrier.clone(),
                Frame::fin(key.epoch, 3, registration.stream_id, 1, fin_frame.sequence),
                false,
            ),
        )
        .await
        .expect("connector FIN handling timed out");
        let Some(DataOutbound::Binary(mut ack)) = tokio::time::timeout(wait, data_rx.recv())
            .await
            .expect("connector FIN ACK wait timed out")
        else {
            panic!("connector FIN ACK was not queued");
        };
        assert_eq!(
            Frame::decode(ack.as_slice())
                .expect("connector FIN ACK decodes")
                .kind,
            FrameKind::Ack
        );
        ack.release();
        let Some(ControlOutbound::Text(mut forget)) = tokio::time::timeout(wait, control.rx.recv())
            .await
            .expect("owner STREAM_FORGET wait timed out")
        else {
            panic!("owner STREAM_FORGET was not queued");
        };
        let forget_message =
            super::wire::parse_control(forget.as_bytes()).expect("owner STREAM_FORGET decodes");
        forget.release();
        assert!(matches!(
            forget_message,
            ControlMessage::StreamForget(ref value)
                if value.stream_id == registration.stream_id
                    && value.operation_id == registration.operation_id
        ));

        // The terminal latch must already exist before a later malformed
        // connector frame takes the session through its protocol-failure
        // close path. This proves the early FIN transition is not inferred
        // from the later session removal.
        let expected_owner = actor
            .sessions
            .get(&key.scope())
            .expect("owner session remains before late error")
            .owner
            .clone();
        tokio::time::timeout(
            wait,
            actor.inbound_m2_stream_data(
                carrier,
                Frame::data(key.epoch, 3, registration.stream_id, 0, 0, Vec::new()),
                false,
            ),
        )
        .await
        .expect("late malformed frame handling timed out");

        let snapshot = actor.snapshot();
        assert!(
            snapshot
                .sessions
                .iter()
                .flat_map(|session| session.streams.iter())
                .all(|stream| stream.stream_id != registration.stream_id)
        );
        let event = snapshot
            .stream_terminal_events
            .iter()
            .find(|event| event.stream_id == registration.stream_id)
            .expect("terminal event survives STREAM_FORGET");
        assert_eq!(event.tenant_id, tenant_id.to_string());
        assert_eq!(event.device_id, device_id.to_string());
        assert_eq!(event.session_id, key.session_id);
        assert_eq!(event.epoch, key.epoch);
        assert_eq!(
            event.deployment_incarnation,
            expected_owner.deployment_incarnation
        );
        assert_eq!(event.node_id, expected_owner.node_id);
        assert_eq!(event.boot_id, expected_owner.boot_id);
        assert_eq!(event.owner_id, super::runtime::owner_id(&expected_owner));
        assert_eq!(event.operation_id, registration.operation_id);
        assert_eq!(event.request_id.as_deref(), Some("forwarded-request-601"));
        assert_eq!(event.active_generation, 3);
        assert_eq!(event.reason, "STREAM_CLOSED");
        assert!(event.cause.is_none());

        // The first-terminal latch above was captured by the relay-initiated
        // close, which predates the connector FIN.  The separate receipt must
        // prove the actual connector FIN was accepted with the final receive
        // cursor and exact forwarded identity, and it must survive the later
        // STREAM_FORGET/removal just like the first-terminal latch.
        let receipt = snapshot
            .stream_terminal_receipt_events
            .iter()
            .find(|receipt| receipt.stream_id == registration.stream_id)
            .expect("connector FIN receipt survives STREAM_FORGET");
        assert_eq!(receipt.tenant_id, tenant_id.to_string());
        assert_eq!(receipt.device_id, device_id.to_string());
        assert_eq!(receipt.session_id, key.session_id);
        assert_eq!(receipt.epoch, key.epoch);
        assert_eq!(
            receipt.deployment_incarnation,
            expected_owner.deployment_incarnation
        );
        assert_eq!(receipt.node_id, expected_owner.node_id);
        assert_eq!(receipt.boot_id, expected_owner.boot_id);
        assert_eq!(receipt.owner_id, super::runtime::owner_id(&expected_owner));
        assert_eq!(receipt.operation_id, registration.operation_id);
        assert_eq!(receipt.request_id.as_deref(), Some("forwarded-request-601"));
        assert_eq!(receipt.active_generation, 3);
        assert_eq!(receipt.active_connection_id, "terminal-latch-carrier");
        assert_eq!(receipt.recv_contiguous_connector_to_relay, 1);
        assert_eq!(receipt.delivered_contiguous_connector_to_relay, 1);
        assert_eq!(receipt.receive_terminal_sequence, 1);
        assert_eq!(receipt.replay_bytes_relay_to_connector, 0);
        assert_eq!(receipt.queue_bytes, 0);
    }

    /// The connector FIN receipt must be observable while the exact terminal
    /// stream is still present, before the owner STREAM_FORGET reclaims it on
    /// the following ACK, and must then persist across that reclamation with
    /// the same exact identity and a gap-free, replay-free terminal cursor.
    #[tokio::test]
    async fn stream_terminal_receipt_observable_before_reclamation() {
        let wait = std::time::Duration::from_secs(1);
        let now = Utc::now();
        let tenant_id = Uuid::from_u128(621);
        let device_id = Uuid::from_u128(622);
        let principal_id = Uuid::from_u128(623);
        let service_id = Uuid::from_u128(624);
        let identity = DeviceIdentity {
            tenant_id,
            device_id,
            owner_user_id: principal_id,
            credential_id: Uuid::from_u128(625),
            spki_fingerprint: "receipt-order-spki".to_owned(),
            credential_not_before: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(1),
            credential_revoked_at: None,
            device_active: true,
            credential_active: true,
            device_version: 1,
            owner_epoch: 1,
            last_seen_at: Some(now),
        };
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "receipt-order".to_owned(),
            epoch: 9,
        };
        let (mut actor, mut control) = admitted_control_actor(identity, key.clone());
        let (data_tx, mut data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        let carrier = CarrierKey {
            session: key.clone(),
            generation: 4,
            connection_id: "receipt-order-carrier".to_owned(),
        };
        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            session.profile = super::RuntimeProfile::M2;
            session.generation = carrier.generation;
            session.connection_id = carrier.connection_id.clone();
            session.data_tx = Some(data_tx.clone());
            session.active_carrier = Some(DataCarrier {
                context: carrier.context(),
                tx: data_tx,
            });
        }
        let consumer = AuthenticatedConsumer {
            tenant_id,
            principal_id,
        };
        let grant = GrantSnapshot {
            tenant_id,
            principal_id,
            device_id,
            service_id,
            revision: 9,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            valid_until: now + Duration::minutes(1),
            read_started_at: now,
        };
        let (open_tx, open_rx) = oneshot::channel();
        actor.open_echo_stream_with_request_id(
            consumer,
            device_id,
            service_id,
            grant,
            now + Duration::minutes(1),
            Some("forwarded-request-621".to_owned()),
            open_tx,
        );
        let registration = tokio::time::timeout(wait, open_rx)
            .await
            .expect("echo registration response timed out")
            .expect("echo registration response")
            .expect("echo stream admitted");
        registration.claim_admission();
        let Some(ControlOutbound::Text(mut open)) = tokio::time::timeout(wait, control.rx.recv())
            .await
            .expect("echo OPEN wait timed out")
        else {
            panic!("echo OPEN was not queued");
        };
        open.release();
        let open_message_id = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.streams.get(&registration.stream_id))
            .map(|stream| stream.open_message_id.clone())
            .expect("OPEN correlation");
        tokio::time::timeout(
            wait,
            actor.inbound_control(
                key.clone(),
                ControlMessage::Opened(tunnel_protocol::Opened::new(
                    "receipt-order-opened",
                    open_message_id,
                    key.session_id.clone(),
                    key.epoch,
                    registration.stream_id,
                    registration.operation_id.clone(),
                    crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                    crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                )),
            ),
        )
        .await
        .expect("OPENED handling timed out");

        let expected_owner = actor
            .sessions
            .get(&key.scope())
            .expect("owner session remains after OPENED")
            .owner
            .clone();

        // The connector half-closes first with a FIN that acks nothing, so
        // the relay replies with its own FIN that stays unacknowledged. The
        // stream therefore remains live and terminal, not yet reclaimable.
        tokio::time::timeout(
            wait,
            actor.inbound_m2_stream_data(
                carrier.clone(),
                Frame::fin(key.epoch, carrier.generation, registration.stream_id, 1, 0),
                false,
            ),
        )
        .await
        .expect("connector FIN handling timed out");
        // Drain the relay's ACK and its own FIN reply from the data writer.
        for _ in 0..2 {
            let Some(DataOutbound::Binary(mut frame)) = tokio::time::timeout(wait, data_rx.recv())
                .await
                .expect("relay terminal writer frame timed out")
            else {
                panic!("relay terminal writer frame was not queued");
            };
            frame.release();
        }

        // The exact terminal stream is still present, so a mismatched carrier
        // must not be able to forge a receipt for it.
        let mismatched_carrier = CarrierKey {
            session: key.clone(),
            generation: 99,
            connection_id: "unrelated-carrier".to_owned(),
        };
        assert!(
            actor
                .stream_terminal_receipt_event(
                    &key,
                    &mismatched_carrier,
                    registration.stream_id,
                    &registration.operation_id,
                )
                .is_none()
        );

        let before = actor.snapshot();
        let live_stream = before
            .sessions
            .iter()
            .flat_map(|session| session.streams.iter())
            .find(|stream| stream.stream_id == registration.stream_id)
            .expect("terminal stream is still present before reclamation");
        assert!(live_stream.terminal);
        assert_eq!(live_stream.recv_contiguous_connector_to_relay, 1);
        assert_eq!(live_stream.delivered_contiguous_connector_to_relay, 1);
        let receipt_before = before
            .stream_terminal_receipt_events
            .iter()
            .find(|receipt| receipt.stream_id == registration.stream_id)
            .expect("connector FIN receipt observable before reclamation");
        assert_eq!(receipt_before.tenant_id, tenant_id.to_string());
        assert_eq!(receipt_before.device_id, device_id.to_string());
        assert_eq!(receipt_before.session_id, key.session_id);
        assert_eq!(receipt_before.epoch, key.epoch);
        assert_eq!(
            receipt_before.owner_id,
            super::runtime::owner_id(&expected_owner)
        );
        assert_eq!(receipt_before.operation_id, registration.operation_id);
        assert_eq!(
            receipt_before.request_id.as_deref(),
            Some("forwarded-request-621")
        );
        assert_eq!(receipt_before.active_generation, carrier.generation);
        assert_eq!(receipt_before.active_connection_id, carrier.connection_id);
        assert_eq!(receipt_before.recv_contiguous_connector_to_relay, 1);
        assert_eq!(receipt_before.delivered_contiguous_connector_to_relay, 1);
        assert_eq!(receipt_before.receive_terminal_sequence, 1);
        // The receipt is captured before the relay queues its own FIN, so the
        // relay-to-connector direction is fully acked with no replay backlog.
        assert_eq!(receipt_before.last_emitted_relay_to_connector, 0);
        assert_eq!(receipt_before.peer_acked_relay_to_connector, 0);
        assert_eq!(receipt_before.replay_bytes_relay_to_connector, 0);
        assert_eq!(receipt_before.queue_bytes, 0);
        let receipt_snapshot = receipt_before.clone();

        // The connector now acks the relay FIN, which makes both directions
        // terminal and fully acked: the owner queues STREAM_FORGET and removes
        // the live stream.
        tokio::time::timeout(
            wait,
            actor.inbound_m2_stream_data(
                carrier.clone(),
                Frame::ack(key.epoch, carrier.generation, registration.stream_id, 1),
                false,
            ),
        )
        .await
        .expect("connector ACK handling timed out");
        let Some(ControlOutbound::Text(mut forget)) = tokio::time::timeout(wait, control.rx.recv())
            .await
            .expect("owner STREAM_FORGET wait timed out")
        else {
            panic!("owner STREAM_FORGET was not queued");
        };
        let forget_message =
            super::wire::parse_control(forget.as_bytes()).expect("owner STREAM_FORGET decodes");
        forget.release();
        assert!(matches!(
            forget_message,
            ControlMessage::StreamForget(ref value)
                if value.stream_id == registration.stream_id
                    && value.operation_id == registration.operation_id
        ));

        let after = actor.snapshot();
        assert!(
            after
                .sessions
                .iter()
                .flat_map(|session| session.streams.iter())
                .all(|stream| stream.stream_id != registration.stream_id),
            "terminal stream must be reclaimed after the acked FIN"
        );
        let receipt_after = after
            .stream_terminal_receipt_events
            .iter()
            .find(|receipt| receipt.stream_id == registration.stream_id)
            .expect("connector FIN receipt persists across reclamation");
        assert_eq!(*receipt_after, receipt_snapshot);
    }

    #[tokio::test]
    async fn lifetime_application_dispatch_counter_survives_session_cleanup() {
        let now = Utc::now();
        let tenant_id = Uuid::from_u128(1);
        let device_id = Uuid::from_u128(2);
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "lifetime-dispatch".to_owned(),
            epoch: 1,
        };
        let identity = DeviceIdentity {
            tenant_id,
            device_id,
            owner_user_id: Uuid::from_u128(3),
            credential_id: Uuid::from_u128(4),
            spki_fingerprint: "test-spki".to_owned(),
            credential_not_before: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(1),
            credential_revoked_at: None,
            device_active: true,
            credential_active: true,
            device_version: 1,
            owner_epoch: 1,
            last_seen_at: Some(now),
        };
        let (mut actor, _registration) = admitted_control_actor(identity, key);

        let (data_tx, mut data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        let session_key = actor
            .sessions
            .values()
            .next()
            .expect("test session")
            .key
            .clone();
        let carrier = CarrierKey {
            session: session_key,
            generation: 1,
            connection_id: "lifetime-data".to_owned(),
        };
        if let Some(session) = actor.sessions.get_mut(&carrier.session.scope()) {
            session.profile = super::RuntimeProfile::M2;
            session.data_tx = Some(data_tx.clone());
            session.active_carrier = Some(DataCarrier {
                context: carrier.context(),
                tx: data_tx,
            });
        }
        let now = Utc::now();
        let consumer = AuthenticatedConsumer {
            tenant_id,
            principal_id: Uuid::from_u128(3),
        };
        let service_id = Uuid::from_u128(5);
        let grant = GrantSnapshot {
            tenant_id,
            principal_id: consumer.principal_id,
            device_id,
            service_id,
            revision: 1,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            valid_until: now + Duration::minutes(1),
            read_started_at: now,
        };
        let (registration_tx, registration_rx) = oneshot::channel();
        actor.open_echo_stream(
            consumer,
            device_id,
            service_id,
            grant,
            now + Duration::minutes(1),
            registration_tx,
        );
        let registration = registration_rx
            .await
            .expect("echo registration response")
            .expect("echo stream admitted");
        actor
            .sessions
            .get_mut(&carrier.session.scope())
            .expect("test session")
            .streams
            .get_mut(&registration.stream_id)
            .expect("test stream")
            .authorized_until =
            Some(std::time::Instant::now() + std::time::Duration::from_secs(60));
        let (write_tx, _write_rx) = oneshot::channel();
        actor.write_echo_stream(
            registration.key.clone(),
            registration.stream_id,
            registration.operation_id,
            b"application-record".to_vec(),
            write_tx,
        );
        let outbound = data_rx.recv().await.expect("application data enqueue");
        assert!(matches!(outbound, DataOutbound::Binary(_)));
        assert_eq!(actor.lifetime_application_dispatches, 1);

        actor.sessions.clear();

        let snapshot = actor.snapshot();
        assert!(snapshot.sessions.is_empty());
        assert_eq!(snapshot.lifetime_application_dispatches, 1);
    }

    #[tokio::test]
    async fn owner_local_non_stream_dispatch_counts_authorized_empty_body_once() {
        let now = Utc::now();
        let tenant_id = Uuid::from_u128(101);
        let device_id = Uuid::from_u128(102);
        let principal_id = Uuid::from_u128(103);
        let service_id = Uuid::from_u128(104);
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "owner-local-empty-dispatch".to_owned(),
            epoch: 1,
        };
        let identity = DeviceIdentity {
            tenant_id,
            device_id,
            owner_user_id: principal_id,
            credential_id: Uuid::from_u128(105),
            spki_fingerprint: "owner-local-empty-spki".to_owned(),
            credential_not_before: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(1),
            credential_revoked_at: None,
            device_active: true,
            credential_active: true,
            device_version: 1,
            owner_epoch: 1,
            last_seen_at: Some(now),
        };
        let (mut actor, _registration) = admitted_control_actor(identity.clone(), key.clone());
        let (data_tx, mut data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        actor
            .sessions
            .get_mut(&key.scope())
            .expect("test session")
            .data_tx = Some(data_tx);

        let consumer = AuthenticatedConsumer {
            tenant_id,
            principal_id,
        };
        let grant = GrantSnapshot {
            tenant_id,
            principal_id,
            device_id,
            service_id,
            revision: 1,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            valid_until: now + Duration::minutes(1),
            read_started_at: now,
        };
        let (response, _response_rx) = oneshot::channel();
        actor
            .dispatch_echo(DispatchRequest {
                consumer: consumer.clone(),
                device_id,
                service_id,
                grant: grant.clone(),
                body: Vec::new(),
                consumer_expires_at: now + Duration::minutes(1),
                response,
            })
            .await;

        let stream_id = 1;
        let challenge_id = "owner-local-empty-challenge";
        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            let pending = session
                .pending
                .get_mut(&stream_id)
                .expect("owner-local pending request");
            assert!(pending.body.is_empty());
            pending.authorization_in_flight = true;
            pending.challenge_id = Some(challenge_id.to_owned());
        } else {
            panic!("test session disappeared before authorization");
        }
        let make_challenge = || DeviceChallenge {
            message_id: "owner-local-empty-auth".to_owned(),
            stream_id,
            service_id: service_id.to_string(),
            challenge_id: challenge_id.to_owned(),
            nonce: "owner-local-empty-nonce".to_owned(),
            permission_digest: super::wire::permission_digest(&grant, &service_id.to_string()),
            grant_revision: grant.revision,
            received_at: std::time::Instant::now(),
            lifetime: std::time::Duration::from_secs(5),
        };
        let owner_token = actor
            .sessions
            .get(&key.scope())
            .expect("test session")
            .owner
            .clone();
        let authorization_result = || -> ChallengeAuthorizationResult {
            Ok((
                Some(grant.clone()),
                Some(OwnerClaim {
                    token: owner_token.clone(),
                    lease_expires_at: now + Duration::minutes(1),
                }),
                Some(identity.clone()),
                Some(std::time::Instant::now() + std::time::Duration::from_secs(60)),
            ))
        };

        actor.finish_device_challenge(key.clone(), make_challenge(), authorization_result());
        assert_eq!(actor.lifetime_application_dispatches, 1);
        assert!(
            actor
                .sessions
                .get(&key.scope())
                .and_then(|session| session.pending.get(&stream_id))
                .is_some_and(|pending| pending.dispatched)
        );

        let Some(DataOutbound::Binary(mut bytes)) = data_rx.recv().await else {
            panic!("authorized empty body DATA frame missing");
        };
        let data = Frame::decode(bytes.as_slice()).expect("empty body DATA frame decodes");
        assert_eq!(data.kind, FrameKind::Data);
        assert!(data.payload.is_empty());
        bytes.release();
        let Some(DataOutbound::Binary(mut bytes)) = data_rx.recv().await else {
            panic!("authorized empty body FIN frame missing");
        };
        let fin = Frame::decode(bytes.as_slice()).expect("empty body FIN frame decodes");
        assert_eq!(fin.kind, FrameKind::Fin);
        bytes.release();

        // A duplicate authorization result is ignored after the logical
        // request is marked dispatched; it must not enqueue or count again.
        actor.finish_device_challenge(key.clone(), make_challenge(), authorization_result());
        assert_eq!(actor.lifetime_application_dispatches, 1);
        assert!(matches!(
            data_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn echo_admission_marks_only_carrier_or_fence_loss_as_retryable() {
        let now = Utc::now();
        let tenant_id = Uuid::from_u128(1);
        let device_id = Uuid::from_u128(2);
        let principal_id = Uuid::from_u128(3);
        let service_id = Uuid::from_u128(4);
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "owner-not-ready".to_owned(),
            epoch: 1,
        };
        let identity = DeviceIdentity {
            tenant_id,
            device_id,
            owner_user_id: principal_id,
            credential_id: Uuid::from_u128(5),
            spki_fingerprint: "owner-not-ready-spki".to_owned(),
            credential_not_before: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(1),
            credential_revoked_at: None,
            device_active: true,
            credential_active: true,
            device_version: 1,
            owner_epoch: 1,
            last_seen_at: Some(now),
        };
        let (mut actor, _registration) = admitted_control_actor(identity, key.clone());
        let grant = || GrantSnapshot {
            tenant_id,
            principal_id,
            device_id,
            service_id,
            revision: 1,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            valid_until: now + Duration::minutes(1),
            read_started_at: now,
        };
        let consumer = || AuthenticatedConsumer {
            tenant_id,
            principal_id,
        };

        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            session.profile = super::RuntimeProfile::M2;
        }
        let (response, receiver) = oneshot::channel();
        actor.open_echo_stream(
            consumer(),
            device_id,
            service_id,
            grant(),
            now + Duration::minutes(1),
            response,
        );
        assert!(matches!(
            receiver.await.expect("carrier readiness response"),
            Err(RelayError::OwnerNotReady)
        ));

        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            session.profile = super::RuntimeProfile::M1;
        }
        let (response, receiver) = oneshot::channel();
        actor.open_echo_stream(
            consumer(),
            device_id,
            service_id,
            grant(),
            now + Duration::minutes(1),
            response,
        );
        assert!(matches!(
            receiver.await.expect("profile readiness response"),
            Err(RelayError::Conflict("M2 ordered stream is not available"))
        ));

        let (data_tx, _data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            session.profile = super::RuntimeProfile::M2;
            session.cluster_profile = true;
            session.owner_fenced = false;
            session.data_tx = Some(data_tx.clone());
            session.active_carrier = Some(DataCarrier {
                context: CarrierKey {
                    session: key.clone(),
                    generation: 1,
                    connection_id: "owner-not-ready-data".to_owned(),
                }
                .context(),
                tx: data_tx,
            });
        }
        let (response, receiver) = oneshot::channel();
        actor.open_echo_stream(
            consumer(),
            device_id,
            service_id,
            grant(),
            now + Duration::minutes(1),
            response,
        );
        assert!(matches!(
            receiver.await.expect("owner fence readiness response"),
            Err(RelayError::OwnerNotReady)
        ));
    }

    #[tokio::test]
    async fn rejected_m2_open_reclaims_exact_stream_without_touching_sibling() {
        let now = Utc::now();
        let tenant_id = Uuid::from_u128(101);
        let device_id = Uuid::from_u128(102);
        let principal_id = Uuid::from_u128(103);
        let service_id = Uuid::from_u128(104);
        let identity = DeviceIdentity {
            tenant_id,
            device_id,
            owner_user_id: principal_id,
            credential_id: Uuid::from_u128(105),
            spki_fingerprint: "rejected-m2-spki".to_owned(),
            credential_not_before: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(1),
            credential_revoked_at: None,
            device_active: true,
            credential_active: true,
            device_version: 1,
            owner_epoch: 1,
            last_seen_at: Some(now),
        };
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "rejected-m2".to_owned(),
            epoch: 1,
        };
        let (mut actor, mut control) = admitted_control_actor(identity, key.clone());
        let (data_tx, _data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            session.profile = super::RuntimeProfile::M2;
            session.active_carrier = Some(DataCarrier {
                context: CarrierContext::new(
                    key.session_id.clone(),
                    key.epoch,
                    1,
                    "rejected-m2-data".to_owned(),
                ),
                tx: data_tx,
            });
        }
        let consumer = AuthenticatedConsumer {
            tenant_id,
            principal_id,
        };
        let grant = GrantSnapshot {
            tenant_id,
            principal_id,
            device_id,
            service_id,
            revision: 1,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            valid_until: now + Duration::minutes(1),
            read_started_at: now,
        };

        let (first_tx, first_rx) = oneshot::channel();
        actor.open_echo_stream(
            consumer.clone(),
            device_id,
            service_id,
            grant.clone(),
            now + Duration::minutes(1),
            first_tx,
        );
        let first = first_rx
            .await
            .expect("first registration response")
            .expect("first M2 stream admission");
        let (sibling_tx, sibling_rx) = oneshot::channel();
        actor.open_echo_stream(
            consumer,
            device_id,
            service_id,
            grant,
            now + Duration::minutes(1),
            sibling_tx,
        );
        let sibling = sibling_rx
            .await
            .expect("sibling registration response")
            .expect("sibling M2 stream admission");
        assert_eq!(
            actor
                .sessions
                .get(&key.scope())
                .expect("session")
                .streams
                .len(),
            2
        );
        let first_open_message_id = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.streams.get(&first.stream_id))
            .map(|stream| stream.open_message_id.clone())
            .expect("first OPEN correlation");

        actor
            .inbound_control(
                key.clone(),
                ControlMessage::Rejected(tunnel_protocol::Rejected::new(
                    "connector-rejected-wrong-reply",
                    "different-open",
                    key.session_id.clone(),
                    key.epoch,
                    first.stream_id,
                    first.operation_id.clone(),
                    "RESOURCE_EXHAUSTED",
                    "stream limit reached",
                )),
            )
            .await;
        assert!(
            actor
                .sessions
                .get(&key.scope())
                .is_some_and(|session| session.streams.contains_key(&first.stream_id)),
            "a mismatched reply_to must not reclaim a pending M2 stream"
        );

        actor
            .inbound_control(
                key.clone(),
                ControlMessage::Rejected(tunnel_protocol::Rejected::new(
                    "connector-rejected",
                    first_open_message_id,
                    key.session_id.clone(),
                    key.epoch,
                    first.stream_id,
                    first.operation_id.clone(),
                    "RESOURCE_EXHAUSTED",
                    "stream limit reached",
                )),
            )
            .await;

        assert!(
            first.closed.is_cancelled(),
            "connector rejection must close the corresponding consumer stream"
        );
        assert!(actor.sessions.get(&key.scope()).is_some_and(|session| {
            !session.streams.contains_key(&first.stream_id)
                && session.streams.contains_key(&sibling.stream_id)
        }));

        // An exact rejected OPEN is a no-stream tombstone, but it still needs
        // an owner FORGET so the connector can compact its operation journal.
        // The two OPENs are already queued ahead of it; inspect the whole
        // bounded FIFO instead of assuming a particular queue position.
        let mut rejected_forget = None;
        while let Ok(outbound) = control.rx.try_recv() {
            if let ControlOutbound::Text(mut text) = outbound {
                let message = super::wire::parse_control(text.as_bytes())
                    .expect("queued rejected OPEN control must decode");
                text.release();
                if let ControlMessage::StreamForget(forget) = message {
                    rejected_forget = Some(forget);
                }
            }
        }
        let rejected_forget = rejected_forget.expect("exact rejected OPEN must queue FORGET");
        assert_eq!(rejected_forget.session_id, key.session_id);
        assert_eq!(rejected_forget.epoch, key.epoch);
        assert_eq!(rejected_forget.stream_id, first.stream_id);
        assert_eq!(rejected_forget.operation_id, first.operation_id);
        assert_eq!(rejected_forget.direction, Direction::RelayToConnector);
        assert_eq!(rejected_forget.final_state.stream_id, first.stream_id);
        assert!(rejected_forget.final_state.send_terminal.is_none());
        assert!(rejected_forget.final_state.receive_terminal.is_none());

        let sibling_open_message_id = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.streams.get(&sibling.stream_id))
            .map(|stream| stream.open_message_id.clone())
            .expect("sibling OPEN correlation");
        actor
            .inbound_control(
                key.clone(),
                ControlMessage::Opened(tunnel_protocol::Opened::new(
                    "connector-opened-sibling",
                    sibling_open_message_id.clone(),
                    key.session_id.clone(),
                    key.epoch,
                    sibling.stream_id,
                    sibling.operation_id.clone(),
                    262_144,
                    262_144,
                )),
            )
            .await;
        actor
            .inbound_control(
                key.clone(),
                ControlMessage::Rejected(tunnel_protocol::Rejected::new(
                    "connector-rejected-admitted",
                    sibling_open_message_id,
                    key.session_id.clone(),
                    key.epoch,
                    sibling.stream_id,
                    sibling.operation_id.clone(),
                    "RESOURCE_EXHAUSTED",
                    "stale rejection",
                )),
            )
            .await;
        assert!(
            actor
                .sessions
                .get(&key.scope())
                .is_some_and(|session| session.streams.contains_key(&sibling.stream_id)),
            "a rejection after OPEN acknowledgement must not remove an admitted stream"
        );
        let mut sibling_forget = false;
        while let Ok(outbound) = control.rx.try_recv() {
            if let ControlOutbound::Text(mut text) = outbound {
                let message = super::wire::parse_control(text.as_bytes())
                    .expect("queued sibling control must decode");
                text.release();
                sibling_forget |= matches!(message, ControlMessage::StreamForget(_));
            }
        }
        assert!(
            !sibling_forget,
            "a stale rejection must not emit FORGET for an admitted sibling"
        );
        drop(sibling);
    }

    #[tokio::test]
    async fn same_device_id_can_register_in_two_tenants_and_disconnect_is_scoped() {
        let (fixture, device_id, tenant_a, tenant_b, spki_a, spki_b) = shared_device_fixture();
        let catalog = MemoryCatalog::new();
        catalog
            .seed_fixture(&fixture)
            .await
            .expect("seed shared-device fixture");
        let identity_a = catalog
            .resolve_device(&spki_a, Utc::now())
            .await
            .expect("resolve tenant A device")
            .expect("tenant A identity");
        let identity_b = catalog
            .resolve_device(&spki_b, Utc::now())
            .await
            .expect("resolve tenant B device")
            .expect("tenant B identity");
        assert_eq!(identity_a.tenant_id, tenant_a);
        assert_eq!(identity_b.tenant_id, tenant_b);
        assert_eq!(identity_a.device_id, identity_b.device_id);

        let oidc_key = ApprovedJwk::from_ed25519_der("test", &[0_u8; 32]).expect("test OIDC key");
        let oidc_config = OidcConfig::new(
            "https://issuer.example",
            ["audience".to_owned()],
            vec![oidc_key],
        )
        .expect("test OIDC config");
        let oidc = Arc::new(OidcVerifier::new(oidc_config).expect("test OIDC verifier"));
        let handle = RelayHandle::spawn(super::RelayOptions::new(oidc), Arc::new(catalog.clone()));

        let registration_a = handle
            .register_forwarded_control(identity_a, spki_a.clone(), hello(device_id, "hello-a"))
            .await
            .expect("register tenant A device");
        let registration_b = handle
            .register_forwarded_control(identity_b, spki_b.clone(), hello(device_id, "hello-b"))
            .await
            .expect("register tenant B device with same device ID");

        let duplicate_a = handle
            .register_forwarded_control(
                catalog
                    .resolve_device(&spki_a, Utc::now())
                    .await
                    .expect("resolve duplicate tenant A device")
                    .expect("duplicate tenant A identity"),
                spki_a.clone(),
                hello(device_id, "hello-a-duplicate"),
            )
            .await;
        assert!(matches!(duplicate_a, Err(RelayError::OwnerBusy)));

        handle.disconnect_control(registration_a.key).await;
        let snapshot = handle
            .snapshot()
            .await
            .expect("snapshot after tenant A close");
        assert_eq!(snapshot.sessions.len(), 1);

        let duplicate_b = handle
            .register_forwarded_control(
                catalog
                    .resolve_device(&spki_b, Utc::now())
                    .await
                    .expect("resolve surviving tenant B device")
                    .expect("surviving tenant B identity"),
                spki_b,
                hello(device_id, "hello-b-duplicate"),
            )
            .await;
        assert!(matches!(duplicate_b, Err(RelayError::OwnerBusy)));
        assert_eq!(registration_b.key.tenant_id, tenant_b);
        let snapshot = handle
            .snapshot()
            .await
            .expect("snapshot after duplicate controls");
        assert_eq!(snapshot.control_registration_conflicts, 2);

        handle.shutdown().await.expect("shutdown relay actor");
    }

    #[tokio::test]
    async fn control_registration_conflict_counter_classifies_owner_busy_only() {
        let (fixture, device_id, tenant_a, _tenant_b, spki_a, _spki_b) = shared_device_fixture();
        let catalog = MemoryCatalog::new();
        catalog
            .seed_fixture(&fixture)
            .await
            .expect("seed owner-busy fixture");
        let identity = catalog
            .resolve_device(&spki_a, Utc::now())
            .await
            .expect("resolve owner-busy identity")
            .expect("owner-busy identity");
        catalog
            .claim_owner(&OwnerClaimRequest {
                deployment_incarnation: "existing-deployment".to_owned(),
                tenant_id: tenant_a,
                device_id,
                node_id: "existing-relay".to_owned(),
                boot_id: "existing-boot".to_owned(),
                session_id: "existing-session".to_owned(),
                lease_expires_at: Utc::now() + Duration::minutes(1),
            })
            .await
            .expect("preclaim owner");

        let oidc_key =
            ApprovedJwk::from_ed25519_der("owner-busy", &[0_u8; 32]).expect("owner-busy OIDC key");
        let oidc_config = OidcConfig::new(
            "https://issuer.example",
            ["audience".to_owned()],
            vec![oidc_key],
        )
        .expect("owner-busy OIDC config");
        let oidc = Arc::new(OidcVerifier::new(oidc_config).expect("owner-busy OIDC verifier"));
        let handle = RelayHandle::spawn(super::RelayOptions::new(oidc), Arc::new(catalog));

        let owner_busy = handle
            .register_forwarded_control(identity.clone(), spki_a.clone(), hello(device_id, "busy"))
            .await;
        assert!(matches!(owner_busy, Err(RelayError::OwnerBusy)));
        let snapshot = handle
            .snapshot()
            .await
            .expect("snapshot after owner-busy rejection");
        assert_eq!(snapshot.control_registration_conflicts, 1);

        let unauthorized = handle
            .register_forwarded_control(identity, "wrong-spki".to_owned(), hello(device_id, "auth"))
            .await;
        assert!(matches!(unauthorized, Err(RelayError::Unauthorized)));
        let snapshot = handle
            .snapshot()
            .await
            .expect("snapshot after unauthorized rejection");
        assert_eq!(snapshot.control_registration_conflicts, 1);

        handle
            .shutdown()
            .await
            .expect("shutdown owner-busy relay actor");
    }

    #[tokio::test]
    async fn dropped_stale_control_cleanup_cannot_close_successor_session() {
        let (fixture, device_id, tenant_a, _tenant_b, spki_a, _spki_b) = shared_device_fixture();
        let catalog = MemoryCatalog::new();
        catalog
            .seed_fixture(&fixture)
            .await
            .expect("seed shared-device fixture");
        let identity = catalog
            .resolve_device(&spki_a, Utc::now())
            .await
            .expect("resolve tenant A device")
            .expect("tenant A identity");
        let oidc_key = ApprovedJwk::from_ed25519_der("test", &[0_u8; 32]).expect("test OIDC key");
        let oidc_config = OidcConfig::new(
            "https://issuer.example",
            ["audience".to_owned()],
            vec![oidc_key],
        )
        .expect("test OIDC config");
        let oidc = Arc::new(OidcVerifier::new(oidc_config).expect("test OIDC verifier"));
        let handle = RelayHandle::spawn(super::RelayOptions::new(oidc), Arc::new(catalog.clone()));

        let first = handle
            .register_forwarded_control(
                identity.clone(),
                spki_a.to_owned(),
                hello(device_id, "stale-first"),
            )
            .await
            .expect("first registration");
        let stale_key = first.key.clone();
        assert!(handle.disconnect_control(stale_key.clone()).await);

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if catalog
                    .current_owner(tenant_a, device_id, Utc::now())
                    .await
                    .expect("current owner")
                    .is_none()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first owner release");

        let successor = handle
            .register_forwarded_control(
                identity,
                spki_a.to_owned(),
                hello(device_id, "stale-successor"),
            )
            .await
            .expect("successor registration");
        assert!(successor.key.epoch > stale_key.epoch);

        drop(handle.control_cleanup_guard(stale_key));
        let snapshot = handle
            .snapshot()
            .await
            .expect("snapshot after stale cleanup");
        assert_eq!(snapshot.sessions.len(), 1);
        assert_eq!(snapshot.sessions[0].session_id, successor.key.session_id);
        assert_eq!(snapshot.sessions[0].epoch, successor.key.epoch);

        handle.shutdown().await.expect("shutdown relay actor");
    }

    #[tokio::test]
    async fn dropped_control_reply_preserves_open_correlation_and_bounded_reclamation() {
        let (fixture, device_id, tenant_id, _tenant_b, spki, _spki_b) = shared_device_fixture();
        let catalog = MemoryCatalog::new();
        catalog
            .seed_fixture(&fixture)
            .await
            .expect("seed shared-device fixture");
        let identity = catalog
            .resolve_device(&spki, Utc::now())
            .await
            .expect("resolve device")
            .expect("device identity");
        let stale_key = SessionKey {
            tenant_id,
            device_id,
            session_id: "dropped-reply".to_owned(),
            epoch: 1,
        };
        let (mut actor, registration) = admitted_control_actor(identity.clone(), stale_key.clone());
        let (response, receiver) = oneshot::channel();
        drop(receiver);
        actor
            .send_control_registration(response, registration)
            .await;
        assert!(actor.sessions.is_empty());

        let successor_key = SessionKey {
            session_id: "successor".to_owned(),
            epoch: 2,
            ..stale_key.clone()
        };
        let (successor, successor_rx) = {
            let (control_tx, control_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
            let queue_budget = QueueBudget::new(actor.options.limits.max_queue_bytes);
            (
                DeviceSession {
                    identity: identity.clone(),
                    owner: OwnerToken {
                        deployment_incarnation: "test-incarnation".to_owned(),
                        tenant_id,
                        device_id,
                        node_id: "test-node".to_owned(),
                        boot_id: "test-boot".to_owned(),
                        session_id: successor_key.session_id.clone(),
                        epoch: successor_key.epoch,
                    },
                    key: successor_key.clone(),
                    control_tx,
                    data_tx: None,
                    active_carrier: None,
                    generation: 1,
                    connection_id: "successor-data".to_owned(),
                    profile: super::RuntimeProfile::M1,
                    cluster_profile: false,
                    owner_fence: None,
                    owner_fenced: true,
                    owner_fence_ack: None,
                    owner_fence_deadline: None,
                    next_stream_id: 1,
                    pending: HashMap::new(),
                    streams: HashMap::new(),
                    forgotten_stream_through: 0,
                    owner_forget_deadline: None,
                    terminal_fin_failure_deadline: None,
                    rotation: None,
                    last_rotation: std::time::Instant::now(),
                    rotations_completed: 0,
                    total_replayed_frames: 0,
                    queued_bytes: 0,
                    queue_budget: queue_budget.clone(),
                    last_lease_renewal: std::time::Instant::now(),
                    maintenance_in_flight: false,
                    closed: false,
                },
                control_rx,
            )
        };
        actor.sessions.insert(successor_key.scope(), successor);
        drop(successor_rx);
        actor.disconnect_control(stale_key.clone()).await;
        assert!(
            actor
                .sessions
                .get(&successor_key.scope())
                .is_some_and(|session| session.key == successor_key)
        );

        let (mut data_actor, control_registration) =
            admitted_control_actor(identity.clone(), stale_key.clone());
        let (data_tx, data_rx) = mpsc::channel(data_actor.options.limits.max_queue_messages);
        let carrier = CarrierKey {
            session: stale_key.clone(),
            generation: 1,
            connection_id: "dropped-data".to_owned(),
        };
        if let Some(session) = data_actor.sessions.get_mut(&stale_key.scope()) {
            session.data_tx = Some(data_tx.clone());
            session.active_carrier = Some(DataCarrier {
                context: CarrierContext::new(
                    stale_key.session_id.clone(),
                    stale_key.epoch,
                    carrier.generation,
                    carrier.connection_id.clone(),
                ),
                tx: data_tx,
            });
        }
        let (data_response, data_receiver) = oneshot::channel();
        drop(data_receiver);
        let data_registration = DataRegistration {
            carrier: carrier.clone(),
            rx: data_rx,
        };
        data_actor
            .send_data_registration(data_response, Ok(data_registration))
            .await;
        assert!(
            data_actor
                .sessions
                .get(&stale_key.scope())
                .is_some_and(
                    |session| session.data_tx.is_none() && session.active_carrier.is_none()
                )
        );
        drop(control_registration);

        let (mut echo_actor, mut control_registration) =
            admitted_control_actor(identity, stale_key.clone());
        let (echo_data_tx, echo_data_rx) =
            mpsc::channel(echo_actor.options.limits.max_queue_messages);
        if let Some(session) = echo_actor.sessions.get_mut(&stale_key.scope()) {
            session.profile = super::RuntimeProfile::M2;
            session.data_tx = Some(echo_data_tx.clone());
            session.active_carrier = Some(DataCarrier {
                context: carrier.context(),
                tx: echo_data_tx,
            });
        }
        drop(echo_data_rx);
        let now = Utc::now();
        let consumer = AuthenticatedConsumer {
            tenant_id,
            principal_id: Uuid::from_u128(11),
        };
        let service_id = Uuid::from_u128(31);
        let grant = GrantSnapshot {
            tenant_id,
            principal_id: consumer.principal_id,
            device_id,
            service_id,
            revision: 1,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            valid_until: now + Duration::minutes(1),
            read_started_at: now,
        };
        let baseline_streams = echo_actor
            .sessions
            .get(&stale_key.scope())
            .expect("echo session remains active")
            .streams
            .len();
        let (echo_response, echo_receiver) = oneshot::channel();
        echo_actor.open_echo_stream(
            consumer.clone(),
            device_id,
            service_id,
            grant.clone(),
            now + Duration::minutes(1),
            echo_response,
        );
        let registration = echo_receiver
            .await
            .expect("echo registration response")
            .expect("echo stream admitted");
        let stream_id = registration.stream_id;
        let operation_id = registration.operation_id.clone();
        let open_message_id = echo_actor
            .sessions
            .get(&stale_key.scope())
            .and_then(|session| session.streams.get(&stream_id))
            .map(|stream| stream.open_message_id.clone())
            .expect("exact OPEN correlation");
        let Some(ControlOutbound::Text(mut open)) = control_registration.rx.recv().await else {
            panic!("echo OPEN was queued");
        };
        open.release();
        let closed = registration.closed.clone();
        let (dropped_response, dropped_receiver) = oneshot::channel();
        drop(dropped_receiver);
        echo_actor.send_echo_registration(dropped_response, registration);
        assert!(
            echo_actor
                .sessions
                .get(&stale_key.scope())
                .is_some_and(|session| {
                    session.streams.len() == baseline_streams + 1
                        && session.streams.get(&stream_id).is_some_and(|stream| {
                            stream.open_pending
                                && stream.registration_dropped
                                && stream.closed.is_cancelled()
                        })
                })
        );
        assert!(closed.is_cancelled());

        // A stale REJECTED cannot reclaim a different OPEN. Exact operation
        // and reply-to correlation is required before owner FORGET is queued.
        echo_actor
            .inbound_control(
                stale_key.clone(),
                ControlMessage::Rejected(tunnel_protocol::Rejected::new(
                    "wrong-reply",
                    "wrong-open-message",
                    stale_key.session_id.clone(),
                    stale_key.epoch,
                    stream_id,
                    operation_id.clone(),
                    "OWNER_REJECTED",
                    "stale test reply",
                )),
            )
            .await;
        assert!(
            echo_actor
                .sessions
                .get(&stale_key.scope())
                .is_some_and(|session| { session.streams.contains_key(&stream_id) })
        );

        // The exact owner rejection queues STREAM_FORGET before removing the
        // pending tombstone. This is the only no-stream reclamation path.
        echo_actor
            .inbound_control(
                stale_key.clone(),
                ControlMessage::Rejected(tunnel_protocol::Rejected::new(
                    "owner-rejected",
                    open_message_id.clone(),
                    stale_key.session_id.clone(),
                    stale_key.epoch,
                    stream_id,
                    operation_id.clone(),
                    "OWNER_REJECTED",
                    "exact test reply",
                )),
            )
            .await;
        let Some(ControlOutbound::Text(mut forget)) = control_registration.rx.recv().await else {
            panic!("exact REJECTED must queue owner STREAM_FORGET");
        };
        let forget_message =
            super::wire::parse_control(forget.as_bytes()).expect("owner STREAM_FORGET decodes");
        forget.release();
        assert!(matches!(
            forget_message,
            ControlMessage::StreamForget(ref message)
                if message.stream_id == stream_id
                    && message.operation_id == operation_id
                    && message.direction == Direction::RelayToConnector
                    && message.final_state.send_terminal.is_none()
                    && message.final_state.receive_terminal.is_none()
        ));
        assert!(
            echo_actor
                .sessions
                .get(&stale_key.scope())
                .is_some_and(|session| {
                    session.streams.len() == baseline_streams
                        && session.forgotten_stream_through == stream_id
                })
        );

        // An exact OPENED after the consumer disappears is an admitted stream,
        // not a no-stream rejection. It must enter the normal terminal path
        // and remain bounded until its terminal proof/debt deadline resolves.
        let (opened_response, opened_receiver) = oneshot::channel();
        echo_actor.open_echo_stream(
            consumer,
            device_id,
            service_id,
            grant,
            now + Duration::minutes(1),
            opened_response,
        );
        let opened_registration = opened_receiver
            .await
            .expect("second echo registration response")
            .expect("second echo stream admitted");
        let opened_stream_id = opened_registration.stream_id;
        let opened_operation_id = opened_registration.operation_id.clone();
        let opened_message_id = echo_actor
            .sessions
            .get(&stale_key.scope())
            .and_then(|session| session.streams.get(&opened_stream_id))
            .map(|stream| stream.open_message_id.clone())
            .expect("second OPEN correlation");
        let Some(ControlOutbound::Text(mut second_open)) = control_registration.rx.recv().await
        else {
            panic!("second echo OPEN was queued");
        };
        second_open.release();
        let (opened_drop_response, opened_drop_receiver) = oneshot::channel();
        drop(opened_drop_receiver);
        echo_actor.send_echo_registration(opened_drop_response, opened_registration);
        echo_actor
            .inbound_control(
                stale_key.clone(),
                ControlMessage::Opened(tunnel_protocol::Opened::new(
                    "opened-after-drop",
                    opened_message_id,
                    stale_key.session_id.clone(),
                    stale_key.epoch,
                    opened_stream_id,
                    opened_operation_id,
                    crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                    crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                )),
            )
            .await;
        assert!(
            echo_actor
                .sessions
                .get(&stale_key.scope())
                .is_some_and(|session| {
                    session.streams.len() == baseline_streams + 1
                        && session
                            .streams
                            .get(&opened_stream_id)
                            .is_some_and(|stream| {
                                !stream.open_pending
                                    && stream.registration_dropped
                                    && stream.terminal
                                    && stream.terminal_fin_failure
                            })
                })
        );
        if let Some(session) = echo_actor.sessions.get_mut(&stale_key.scope()) {
            session.terminal_fin_failure_deadline =
                Some(std::time::Instant::now() - std::time::Duration::from_millis(1));
        }
        echo_actor.tick().await;
        assert!(
            echo_actor.sessions.is_empty(),
            "admitted dropped registration must resolve through bounded terminal debt"
        );
        drop(control_registration);
    }

    #[tokio::test]
    async fn close_echo_stream_records_expired_credential_at_first_terminal_transition() {
        let now = Utc::now();
        let tenant_id = Uuid::from_u128(501);
        let device_id = Uuid::from_u128(502);
        let principal_id = Uuid::from_u128(503);
        let service_id = Uuid::from_u128(504);
        let identity = DeviceIdentity {
            tenant_id,
            device_id,
            owner_user_id: principal_id,
            credential_id: Uuid::from_u128(505),
            spki_fingerprint: "expiry-close-spki".to_owned(),
            credential_not_before: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(1),
            credential_revoked_at: None,
            device_active: true,
            credential_active: true,
            device_version: 1,
            owner_epoch: 1,
            last_seen_at: Some(now),
        };
        let consumer = AuthenticatedConsumer {
            tenant_id,
            principal_id,
        };
        let grant = GrantSnapshot {
            tenant_id,
            principal_id,
            device_id,
            service_id,
            revision: 1,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            valid_until: now + Duration::minutes(1),
            read_started_at: now,
        };
        for (expired, prior_code, expected_code) in [
            (true, None, Some("AUTHORIZATION_EXPIRED")),
            (false, None, None),
            (
                true,
                Some("AUTHORIZATION_REVOKED"),
                Some("AUTHORIZATION_REVOKED"),
            ),
        ] {
            let key = SessionKey {
                tenant_id,
                device_id,
                session_id: "expiry-close".to_owned(),
                epoch: 1,
            };
            let (mut actor, mut control) = admitted_control_actor(identity.clone(), key.clone());
            let (data_tx, mut data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
            let session = actor.sessions.get_mut(&key.scope()).expect("test session");
            session.profile = super::RuntimeProfile::M2;
            session.data_tx = Some(data_tx.clone());
            session.active_carrier = Some(DataCarrier {
                context: CarrierContext::new(
                    key.session_id.clone(),
                    key.epoch,
                    1,
                    "expiry-data".to_owned(),
                ),
                tx: data_tx,
            });
            let (open_tx, open_rx) = oneshot::channel();
            actor.open_echo_stream(
                consumer.clone(),
                device_id,
                service_id,
                grant.clone(),
                now + Duration::minutes(1),
                open_tx,
            );
            let admitted = open_rx
                .await
                .expect("open response")
                .expect("stream admitted");
            drop(control.rx.try_recv().expect("OPEN queued"));
            let stream = actor
                .sessions
                .get_mut(&key.scope())
                .expect("test session")
                .streams
                .get_mut(&admitted.stream_id)
                .expect("admitted stream");
            stream.open_pending = false;
            stream.authorization_in_flight = true;
            stream.authorization_failure_code = prior_code;
            if expired {
                stream.consumer_expires_at = now - Duration::seconds(1);
            }
            // An uncorrelated cleanup cannot terminalize or relabel this stream.
            assert!(actor.close_echo_stream(&key, admitted.stream_id, "different-operation"));
            assert!(!actor.sessions[&key.scope()].streams[&admitted.stream_id].terminal);
            assert!(actor.close_echo_stream(&key, admitted.stream_id, &admitted.operation_id));
            let stream = &actor.sessions[&key.scope()].streams[&admitted.stream_id];
            assert!(stream.terminal && stream.closed.is_cancelled());
            assert_eq!(stream.authorization_failure_code, expected_code);
            assert_eq!(actor.lifetime_application_dispatches, 0);
            let Some(DataOutbound::Binary(mut fin)) = data_rx.try_recv().ok() else {
                panic!("terminal FIN must be queued");
            };
            assert_eq!(
                Frame::decode(fin.as_slice()).expect("FIN decodes").kind,
                FrameKind::Fin
            );
            fin.release();
            // A later duplicate close must not reclassify a valid earlier close
            // just because its credential has expired in the meantime.
            actor
                .sessions
                .get_mut(&key.scope())
                .expect("test session")
                .streams
                .get_mut(&admitted.stream_id)
                .expect("terminal stream")
                .consumer_expires_at = now - Duration::seconds(1);
            assert!(actor.close_echo_stream(&key, admitted.stream_id, &admitted.operation_id));
            assert_eq!(
                actor.sessions[&key.scope()].streams[&admitted.stream_id]
                    .authorization_failure_code,
                expected_code
            );
            assert!(data_rx.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn stream_challenge_confirmation_never_postdates_the_earliest_grant_deadline() {
        let now = Utc::now();
        let tenant_id = Uuid::from_u128(601);
        let device_id = Uuid::from_u128(602);
        let principal_id = Uuid::from_u128(603);
        let service_id = Uuid::from_u128(604);
        let identity = DeviceIdentity {
            tenant_id,
            device_id,
            owner_user_id: principal_id,
            credential_id: Uuid::from_u128(605),
            spki_fingerprint: "admission-anchor-spki".to_owned(),
            credential_not_before: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(1),
            credential_revoked_at: None,
            device_active: true,
            credential_active: true,
            device_version: 1,
            owner_epoch: 1,
            last_seen_at: Some(now),
        };
        let consumer = AuthenticatedConsumer {
            tenant_id,
            principal_id,
        };
        let grant = GrantSnapshot {
            tenant_id,
            principal_id,
            device_id,
            service_id,
            revision: 1,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            valid_until: now + Duration::minutes(1),
            read_started_at: now,
        };
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "admission-anchor".to_owned(),
            epoch: 1,
        };
        let (mut actor, mut control) = admitted_control_actor(identity.clone(), key.clone());
        let (data_tx, _data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        let session = actor.sessions.get_mut(&key.scope()).expect("test session");
        session.profile = super::RuntimeProfile::M2;
        session.data_tx = Some(data_tx.clone());
        session.active_carrier = Some(DataCarrier {
            context: CarrierContext::new(
                key.session_id.clone(),
                key.epoch,
                1,
                "admission-anchor-data".to_owned(),
            ),
            tx: data_tx,
        });
        // The consumer credential is the earliest deadline by a wide margin;
        // the challenge lifetime, grant, owner lease and device credential
        // all remain valid for far longer.
        let consumer_expires_at = now + Duration::milliseconds(1_200);
        let (open_tx, open_rx) = oneshot::channel();
        actor.open_echo_stream(
            consumer,
            device_id,
            service_id,
            grant.clone(),
            consumer_expires_at,
            open_tx,
        );
        let admitted = open_rx
            .await
            .expect("open response")
            .expect("stream admitted");
        drop(control.rx.try_recv().expect("OPEN queued"));
        let challenge_id = "admission-anchor-challenge";
        let started_at_ms = super::monotonic_millis();
        {
            let stream = actor
                .sessions
                .get_mut(&key.scope())
                .expect("test session")
                .streams
                .get_mut(&admitted.stream_id)
                .expect("admitted stream");
            stream.open_pending = false;
            stream.authorization_in_flight = true;
            stream.authorization_started_at_ms = Some(started_at_ms);
            stream.authorization_deadline_ms = Some(started_at_ms + 2_000);
            stream.challenge_id = Some(challenge_id.to_owned());
        }
        let owner_token = actor.sessions[&key.scope()].owner.clone();
        actor.finish_stream_challenge(
            key.clone(),
            DeviceChallenge {
                message_id: "admission-anchor-auth".to_owned(),
                stream_id: admitted.stream_id,
                service_id: service_id.to_string(),
                challenge_id: challenge_id.to_owned(),
                nonce: "admission-anchor-nonce".to_owned(),
                permission_digest: super::wire::permission_digest(&grant, &service_id.to_string()),
                grant_revision: grant.revision,
                received_at: std::time::Instant::now(),
                lifetime: std::time::Duration::from_secs(2),
            },
            Ok((
                Some(grant.clone()),
                Some(OwnerClaim {
                    token: owner_token,
                    lease_expires_at: now + Duration::minutes(1),
                }),
                Some(identity),
                Some(std::time::Instant::now() + std::time::Duration::from_secs(60)),
            )),
        );
        // Sample the wall clock first: this projection of the credential
        // deadline onto the monotonic clock can then only be later than the
        // real instant, never earlier, so the bounds below are exact rather
        // than probabilistic.
        let wall_now = Utc::now();
        let projected_token_expiry = std::time::Instant::now()
            + (consumer_expires_at - wall_now)
                .to_std()
                .unwrap_or_default();
        let stream = &actor.sessions[&key.scope()].streams[&admitted.stream_id];
        assert!(!stream.authorization_in_flight && !stream.terminal);
        assert_eq!(stream.authorization_failure_code, None);
        assert!(
            control.rx.try_recv().is_ok(),
            "AUTHORIZATION_CONFIRMED must be queued"
        );
        let admission_deadline_ms = stream
            .authorization_admission_deadline_ms
            .expect("confirmed grant retains its admission deadline");
        assert!(
            admission_deadline_ms > started_at_ms,
            "admission deadline {admission_deadline_ms} must follow challenge start {started_at_ms}"
        );
        let projected_ms = super::runtime::monotonic_millis_at(projected_token_expiry);
        assert!(
            admission_deadline_ms <= projected_ms,
            "admission deadline {admission_deadline_ms} postdates the consumer deadline {projected_ms}"
        );
        assert!(
            stream
                .authorized_until
                .is_some_and(|until| until <= projected_token_expiry),
            "dispatch gate must not outlive the consumer credential"
        );
    }

    #[tokio::test]
    async fn close_echo_stream_reclaims_when_writer_is_missing_or_closed() {
        let now = Utc::now();
        let tenant_id = Uuid::from_u128(401);
        let device_id = Uuid::from_u128(402);
        let principal_id = Uuid::from_u128(403);
        let service_id = Uuid::from_u128(404);
        let identity = DeviceIdentity {
            tenant_id,
            device_id,
            owner_user_id: principal_id,
            credential_id: Uuid::from_u128(405),
            spki_fingerprint: "close-echo-spki".to_owned(),
            credential_not_before: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(1),
            credential_revoked_at: None,
            device_active: true,
            credential_active: true,
            device_version: 1,
            owner_epoch: 1,
            last_seen_at: Some(now),
        };
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "close-echo-failures".to_owned(),
            epoch: 1,
        };
        let consumer = AuthenticatedConsumer {
            tenant_id,
            principal_id,
        };
        let grant = GrantSnapshot {
            tenant_id,
            principal_id,
            device_id,
            service_id,
            revision: 1,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            valid_until: now + Duration::minutes(1),
            read_started_at: now,
        };

        let (mut actor, mut registration) = admitted_control_actor(identity.clone(), key.clone());
        actor.options.limits.max_streams_per_device = 1;
        let (carrier_tx, carrier_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            session.profile = super::RuntimeProfile::M2;
            session.active_carrier = Some(DataCarrier {
                context: CarrierContext::new(
                    key.session_id.clone(),
                    key.epoch,
                    1,
                    "missing-writer".to_owned(),
                ),
                tx: carrier_tx,
            });
        }
        drop(carrier_rx);
        let (open_tx, open_rx) = oneshot::channel();
        actor.open_echo_stream(
            consumer.clone(),
            device_id,
            service_id,
            grant.clone(),
            now + Duration::minutes(1),
            open_tx,
        );
        let admitted = open_rx
            .await
            .expect("echo registration response")
            .expect("echo stream admitted");
        // Complete the independent OPEN control write so the budget assertion
        // below measures only cleanup and a failed FIN reservation.
        drop(
            registration
                .rx
                .try_recv()
                .expect("OPEN control response queued"),
        );
        let admitted_stream_id = admitted.stream_id;
        // The connector admits the OPEN before the public lease expires: an
        // unadmitted OPEN is deferred rather than terminalized, so the failed
        // FIN reservation below requires an admitted stream.
        let admitted_open_message_id = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.streams.get(&admitted_stream_id))
            .map(|stream| stream.open_message_id.clone())
            .expect("admitted OPEN correlation");
        actor
            .inbound_control(
                key.clone(),
                ControlMessage::Opened(tunnel_protocol::Opened::new(
                    "writer-missing-opened",
                    admitted_open_message_id,
                    key.session_id.clone(),
                    key.epoch,
                    admitted_stream_id,
                    admitted.operation_id.clone(),
                    crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                    crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                )),
            )
            .await;
        if let Some(stream) = actor
            .sessions
            .get_mut(&key.scope())
            .and_then(|session| session.streams.get_mut(&admitted_stream_id))
        {
            stream.admission_deadline =
                std::time::Instant::now() - std::time::Duration::from_secs(1);
        }
        // Dropping the registration before the upgrade callback must leave
        // the actor-owned lease live so the bounded tick can reclaim it.
        drop(admitted);
        actor.expire_unclaimed_echo_streams(&key, std::time::Instant::now());
        assert!(actor.sessions.get(&key.scope()).is_some_and(|session| {
            session
                .streams
                .get(&admitted_stream_id)
                .is_some_and(|stream| stream.terminal && stream.closed.is_cancelled())
        }));
        assert!(
            actor
                .sessions
                .get(&key.scope())
                .and_then(|session| session.streams.get(&admitted_stream_id))
                .is_some_and(|stream| {
                    let snapshot = stream.sequence.snapshot();
                    let direction = snapshot.direction(Direction::RelayToConnector);
                    direction.last_emitted == 0 && direction.send_terminal.is_none()
                })
        );
        assert_eq!(
            actor
                .sessions
                .get(&key.scope())
                .expect("echo session remains active")
                .queue_budget
                .used(),
            0
        );
        assert!(
            actor
                .sessions
                .get(&key.scope())
                .and_then(|session| session.terminal_fin_failure_deadline)
                .is_some(),
            "a failed terminal FIN must start a bounded fail-closed fence"
        );
        let (next_tx, next_rx) = oneshot::channel();
        actor.open_echo_stream(
            consumer.clone(),
            device_id,
            service_id,
            grant.clone(),
            now + Duration::minutes(1),
            next_tx,
        );
        let next = next_rx
            .await
            .expect("second echo registration response")
            .expect("terminal tombstone must not consume active stream capacity");
        assert_ne!(next.stream_id, admitted_stream_id);
        let next_open_message_id = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.streams.get(&next.stream_id))
            .map(|stream| stream.open_message_id.clone())
            .expect("second OPEN correlation");
        actor
            .inbound_control(
                key.clone(),
                ControlMessage::Rejected(tunnel_protocol::Rejected::new(
                    "independent-rejection",
                    next_open_message_id,
                    key.session_id.clone(),
                    key.epoch,
                    next.stream_id,
                    next.operation_id.clone(),
                    "RESOURCE_EXHAUSTED",
                    "independently eligible rejection",
                )),
            )
            .await;
        while let Ok(outbound) = registration.rx.try_recv() {
            if let ControlOutbound::Text(mut text) = outbound {
                text.release();
            }
        }
        assert!(
            actor
                .sessions
                .get(&key.scope())
                .and_then(|session| session.terminal_fin_failure_deadline)
                .is_some(),
            "an unrelated successful FORGET must not clear failed-FIN debt"
        );
        let (retained_tx, retained_rx) = oneshot::channel();
        actor.open_echo_stream(
            consumer.clone(),
            device_id,
            service_id,
            grant.clone(),
            now + Duration::minutes(1),
            retained_tx,
        );
        let retained = retained_rx
            .await
            .expect("retained stream registration response")
            .expect("a removed rejection frees one active slot");
        let retained_open_message_id = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.streams.get(&retained.stream_id))
            .map(|stream| stream.open_message_id.clone())
            .expect("retained OPEN correlation");
        actor
            .inbound_control(
                key.clone(),
                ControlMessage::Opened(tunnel_protocol::Opened::new(
                    "retained-opened",
                    retained_open_message_id,
                    key.session_id.clone(),
                    key.epoch,
                    retained.stream_id,
                    retained.operation_id.clone(),
                    crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                    crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                )),
            )
            .await;
        assert!(actor.close_echo_stream(&key, retained.stream_id, &retained.operation_id));
        let (bounded_tx, bounded_rx) = oneshot::channel();
        actor.open_echo_stream(
            consumer.clone(),
            device_id,
            service_id,
            grant.clone(),
            now + Duration::minutes(1),
            bounded_tx,
        );
        assert!(matches!(
            bounded_rx.await.expect("bounded stream response"),
            Err(RelayError::StreamLimit)
        ));
        assert_eq!(
            actor
                .sessions
                .get(&key.scope())
                .expect("echo session remains active")
                .streams
                .len(),
            2,
            "full retained tombstone table must reject without evicting either identity"
        );
        drop(retained);
        drop(next);
        drop(registration);

        let (mut actor, mut registration) = admitted_control_actor(identity, key.clone());
        let (data_tx, mut data_rx) = mpsc::channel(1);
        data_tx
            .try_send(DataOutbound::Close)
            .expect("fill the data writer queue");
        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            session.profile = super::RuntimeProfile::M2;
            session.data_tx = Some(data_tx.clone());
            session.active_carrier = Some(DataCarrier {
                context: CarrierContext::new(
                    key.session_id.clone(),
                    key.epoch,
                    1,
                    "closed-writer".to_owned(),
                ),
                tx: data_tx,
            });
        }
        let (open_tx, open_rx) = oneshot::channel();
        actor.open_echo_stream(
            consumer,
            device_id,
            service_id,
            grant,
            now + Duration::minutes(1),
            open_tx,
        );
        let admitted = open_rx
            .await
            .expect("echo registration response")
            .expect("echo stream admitted");
        // Complete the independent OPEN control write so the budget assertion
        // below measures only cleanup and a failed FIN reservation.
        drop(
            registration
                .rx
                .try_recv()
                .expect("OPEN control response queued"),
        );
        // Admit the OPEN first: only an admitted stream reaches the terminal
        // FIN reservation that the closed writer must fail.
        let closed_writer_open_message_id = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.streams.get(&admitted.stream_id))
            .map(|stream| stream.open_message_id.clone())
            .expect("closed-writer OPEN correlation");
        actor
            .inbound_control(
                key.clone(),
                ControlMessage::Opened(tunnel_protocol::Opened::new(
                    "closed-writer-opened",
                    closed_writer_open_message_id,
                    key.session_id.clone(),
                    key.epoch,
                    admitted.stream_id,
                    admitted.operation_id.clone(),
                    crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                    crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                )),
            )
            .await;
        assert!(actor.close_echo_stream(&key, admitted.stream_id, &admitted.operation_id));
        assert!(actor.sessions.get(&key.scope()).is_some_and(|session| {
            session
                .streams
                .get(&admitted.stream_id)
                .is_some_and(|stream| stream.terminal && stream.closed.is_cancelled())
        }));
        assert!(
            actor
                .sessions
                .get(&key.scope())
                .and_then(|session| session.streams.get(&admitted.stream_id))
                .is_some_and(|stream| {
                    let snapshot = stream.sequence.snapshot();
                    let direction = snapshot.direction(Direction::RelayToConnector);
                    direction.last_emitted == 0 && direction.send_terminal.is_none()
                })
        );
        assert_eq!(
            actor
                .sessions
                .get(&key.scope())
                .expect("echo session remains active")
                .queue_budget
                .used(),
            0
        );
        assert!(
            actor
                .sessions
                .get(&key.scope())
                .and_then(|session| session.terminal_fin_failure_deadline)
                .is_some(),
            "a full terminal writer queue must start a bounded fail-closed fence"
        );
        assert!(matches!(data_rx.try_recv(), Ok(DataOutbound::Close)));
        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            session.terminal_fin_failure_deadline =
                Some(std::time::Instant::now() - std::time::Duration::from_secs(1));
        }
        actor.tick().await;
        assert!(
            !actor.sessions.contains_key(&key.scope()),
            "an unpublishable terminal FIN must fail closed at its bounded deadline"
        );
        drop(registration);
    }

    #[tokio::test]
    async fn closed_echo_stream_keeps_late_fin_and_credit_fenced() {
        let now = Utc::now();
        let tenant_id = Uuid::from_u128(411);
        let device_id = Uuid::from_u128(412);
        let principal_id = Uuid::from_u128(413);
        let service_id = Uuid::from_u128(414);
        let identity = DeviceIdentity {
            tenant_id,
            device_id,
            owner_user_id: principal_id,
            credential_id: Uuid::from_u128(415),
            spki_fingerprint: "late-fin-spki".to_owned(),
            credential_not_before: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(1),
            credential_revoked_at: None,
            device_active: true,
            credential_active: true,
            device_version: 1,
            owner_epoch: 1,
            last_seen_at: Some(now),
        };
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "late-fin-credit".to_owned(),
            epoch: 1,
        };
        let consumer = AuthenticatedConsumer {
            tenant_id,
            principal_id,
        };
        let grant = GrantSnapshot {
            tenant_id,
            principal_id,
            device_id,
            service_id,
            revision: 1,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            valid_until: now + Duration::minutes(1),
            read_started_at: now,
        };
        let (mut actor, mut registration) = admitted_control_actor(identity, key.clone());
        let (data_tx, mut data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        let carrier = CarrierKey {
            session: key.clone(),
            generation: 1,
            connection_id: "late-fin-data".to_owned(),
        };
        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            session.profile = super::RuntimeProfile::M2;
            session.data_tx = Some(data_tx.clone());
            session.active_carrier = Some(DataCarrier {
                context: carrier.context(),
                tx: data_tx,
            });
        }
        let (open_tx, open_rx) = oneshot::channel();
        actor.open_echo_stream(
            consumer,
            device_id,
            service_id,
            grant,
            now + Duration::minutes(1),
            open_tx,
        );
        let admitted = open_rx
            .await
            .expect("echo registration response")
            .expect("echo stream admitted");
        let stream_id = admitted.stream_id;
        let operation_id = admitted.operation_id.clone();
        let Some(ControlOutbound::Text(mut open)) = registration.rx.recv().await else {
            panic!("echo OPEN was not queued");
        };
        let open_message_id = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.streams.get(&stream_id))
            .map(|stream| stream.open_message_id.clone())
            .expect("OPEN correlation");
        open.release();

        // Drop the public registration while OPEN is still in flight.  The
        // relay must retain the exact OPEN identity and wait for its owner
        // outcome instead of publishing a fabricated no-stream FORGET.
        let (dropped_response, dropped_receiver) = oneshot::channel();
        drop(dropped_receiver);
        actor.send_echo_registration(dropped_response, admitted);
        assert!(actor.sessions.get(&key.scope()).is_some_and(|session| {
            session.streams.get(&stream_id).is_some_and(|stream| {
                stream.open_pending
                    && stream.registration_dropped
                    && !stream.terminal
                    && stream.closed.is_cancelled()
            })
        }));
        assert!(data_rx.try_recv().is_err());

        actor
            .inbound_control(
                key.clone(),
                ControlMessage::Opened(tunnel_protocol::Opened::new(
                    "opened-late-fin",
                    open_message_id,
                    key.session_id.clone(),
                    key.epoch,
                    stream_id,
                    operation_id.clone(),
                    crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                    crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                )),
            )
            .await;
        let Some(DataOutbound::Binary(mut fin)) = data_rx.recv().await else {
            panic!("terminal FIN was not queued");
        };
        assert_eq!(
            Frame::decode(fin.as_slice())
                .expect("terminal FIN decodes")
                .kind,
            FrameKind::Fin
        );
        fin.release();

        actor
            .inbound_m2_stream_data(
                carrier.clone(),
                // The connector's FIN may arrive before it has acknowledged
                // the relay FIN. The owner must retain replay history and
                // emit no FORGET in that intermediate state.
                Frame::fin(key.epoch, carrier.generation, stream_id, 1, 0),
                false,
            )
            .await;
        let Some(DataOutbound::Binary(mut ack)) = data_rx.recv().await else {
            panic!("late FIN was not acknowledged");
        };
        let ack_frame = Frame::decode(ack.as_slice()).expect("late FIN ACK decodes");
        assert_eq!(ack_frame.kind, FrameKind::Ack);
        assert_eq!(ack_frame.stream_id, stream_id);
        assert_eq!(ack_frame.ack, 1);
        ack.release();
        assert!(
            registration.rx.try_recv().is_err(),
            "owner must not forget before the relay FIN is acknowledged"
        );

        // Fill a replacement control queue so the first critical publication
        // has to remain pending. The old registration receiver is deliberately
        // left detached; this exercises the actor-owned queue and retry path.
        let (replacement_tx, mut replacement_rx) = mpsc::channel(2);
        replacement_tx
            .try_send(ControlOutbound::Close)
            .expect("first control queue filler");
        replacement_tx
            .try_send(ControlOutbound::Close)
            .expect("second control queue filler");
        actor
            .sessions
            .get_mut(&key.scope())
            .expect("echo session remains active")
            .control_tx = replacement_tx;

        let now_ms = super::monotonic_millis();
        let recovery_attempt = test_attempt("recovery-hold", 1);
        let mut recovering =
            test_rotation_runtime(now_ms, recovery_attempt, now_ms.saturating_add(20_000));
        recovering.recovery = Some(test_recovery_runtime(now_ms, stream_id));
        actor
            .sessions
            .get_mut(&key.scope())
            .expect("echo session remains active")
            .rotation = Some(recovering);

        actor
            .inbound_m2_stream_data(
                carrier.clone(),
                // A recovery episode owns the immutable roster and its cursor
                // references. Even with both terminal cursors accounted, the
                // owner must retain the tombstone until recovery releases it.
                Frame::ack(key.epoch, carrier.generation, stream_id, 1),
                false,
            )
            .await;
        assert!(
            !actor.owner_forgets.contains_key(&key),
            "active recovery must suppress owner FORGET publication"
        );
        assert!(
            actor
                .sessions
                .get(&key.scope())
                .is_some_and(|session| session.streams.contains_key(&stream_id)),
            "active recovery must retain the terminal tombstone"
        );

        let attempt = test_attempt("forget-order", 2);
        let mut rotation = test_rotation_runtime(now_ms, attempt.clone(), now_ms + 20_000);
        rotation
            .state
            .prepare(attempt.clone(), now_ms)
            .expect("rotation prepares");
        rotation
            .state
            .candidate_ready(&attempt, now_ms)
            .expect("candidate is ready");
        rotation.candidate = Some(DataCarrier {
            context: carrier.context(),
            tx: actor
                .sessions
                .get(&key.scope())
                .and_then(|session| session.data_tx.clone())
                .expect("active data writer for candidate retry"),
        });
        actor
            .sessions
            .get_mut(&key.scope())
            .expect("echo session remains active")
            .rotation = Some(rotation);

        // The recovery hold has been released, but the same full queue still
        // forces the first FORGET attempt to remain pending.
        actor.begin_rotation_quiesce(&key);
        let pending_message_id = actor
            .owner_forgets
            .get(&key)
            .and_then(|pending| pending.get(&stream_id))
            .map(|pending| pending.message_id.clone())
            .expect("full control queue retains owner FORGET");
        actor.tick().await;
        assert_eq!(
            actor
                .owner_forgets
                .get(&key)
                .and_then(|pending| pending.get(&stream_id))
                .map(|pending| pending.message_id.as_str()),
            Some(pending_message_id.as_str()),
            "a full queue retry must retain the original FORGET message ID"
        );
        assert_eq!(
            actor
                .sessions
                .get(&key.scope())
                .and_then(|session| session.rotation.as_ref())
                .map(|rotation| rotation.state.phase()),
            Some(RotationPhase::Preparing),
            "a full control queue must not advance rotation past PREPARING"
        );
        assert!(
            actor
                .sessions
                .get(&key.scope())
                .is_some_and(|session| session.streams.contains_key(&stream_id))
        );
        for _ in 0..2 {
            assert!(matches!(
                replacement_rx.try_recv(),
                Ok(ControlOutbound::Close)
            ));
        }

        // The same message identity is retried before QUIESCE after capacity
        // returns. The tombstone is removed only after FORGET is queued, and
        // the immutable roster is then allowed to omit that stream.
        actor.tick().await;
        let Some(ControlOutbound::Text(mut forget_text)) = replacement_rx.try_recv().ok() else {
            panic!("owner must emit STREAM_FORGET before QUIESCE");
        };
        let forget_message = super::wire::parse_control(forget_text.as_bytes())
            .expect("owner STREAM_FORGET must be valid bounded control");
        forget_text.release();
        assert!(matches!(
            forget_message,
            ControlMessage::StreamForget(ref forget)
                if forget.message_id == pending_message_id
                    && forget.session_id == key.session_id
                    && forget.epoch == key.epoch
                    && forget.stream_id == stream_id
                    && forget.operation_id == operation_id
                    && forget.direction == Direction::RelayToConnector
                    && forget.final_state.stream_id == stream_id
                    && forget.final_state.send_terminal.is_some()
        ));
        let Some(ControlOutbound::Text(mut quiesce_text)) = replacement_rx.try_recv().ok() else {
            panic!("QUIESCE must follow owner STREAM_FORGET");
        };
        let quiesce_message = super::wire::parse_control(quiesce_text.as_bytes())
            .expect("owner ROTATE_QUIESCE must be valid bounded control");
        quiesce_text.release();
        assert!(matches!(
            quiesce_message,
            ControlMessage::RotateQuiesce(ref quiesce)
                if quiesce.roster.stream_ids.is_empty()
        ));

        // The owner removed the stream only after the authenticated control
        // item was queued. A delayed credit frame is now ignored while the
        // session and sibling namespace remain live.
        actor
            .inbound_m2_stream_data(
                carrier.clone(),
                Frame::window_update(
                    key.epoch,
                    1,
                    stream_id,
                    crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                ),
                false,
            )
            .await;
        for frame in [
            Frame::data(key.epoch, 1, stream_id, 1, 0, vec![0x2a]),
            Frame::fin(key.epoch, 1, stream_id, 1, 0),
            Frame::reset(key.epoch, 1, stream_id, 1, 0, 4_002),
        ] {
            actor
                .inbound_data(carrier.clone(), frame.encode().expect("late frame encodes"))
                .await;
        }
        assert!(actor.sessions.contains_key(&key.scope()));
        assert!(
            !actor
                .sessions
                .get(&key.scope())
                .is_some_and(|session| session.streams.contains_key(&stream_id))
        );
        drop(registration);
    }

    #[tokio::test]
    async fn duplicate_peer_reset_does_not_emit_second_reset_or_close_session() {
        let now = Utc::now();
        let tenant_id = Uuid::from_u128(431);
        let device_id = Uuid::from_u128(432);
        let principal_id = Uuid::from_u128(433);
        let service_id = Uuid::from_u128(434);
        let identity = DeviceIdentity {
            tenant_id,
            device_id,
            owner_user_id: principal_id,
            credential_id: Uuid::from_u128(435),
            spki_fingerprint: "duplicate-reset-spki".to_owned(),
            credential_not_before: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(1),
            credential_revoked_at: None,
            device_active: true,
            credential_active: true,
            device_version: 1,
            owner_epoch: 1,
            last_seen_at: Some(now),
        };
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "duplicate-reset".to_owned(),
            epoch: 1,
        };
        let consumer = AuthenticatedConsumer {
            tenant_id,
            principal_id,
        };
        let grant = GrantSnapshot {
            tenant_id,
            principal_id,
            device_id,
            service_id,
            revision: 1,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            valid_until: now + Duration::minutes(1),
            read_started_at: now,
        };
        let (mut actor, mut control) = admitted_control_actor(identity, key.clone());
        let (data_tx, mut data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        let carrier = CarrierKey {
            session: key.clone(),
            generation: 1,
            connection_id: "duplicate-reset-data".to_owned(),
        };
        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            session.profile = super::RuntimeProfile::M2;
            session.data_tx = Some(data_tx.clone());
            session.active_carrier = Some(DataCarrier {
                context: carrier.context(),
                tx: data_tx,
            });
        }
        let (open_tx, open_rx) = oneshot::channel();
        actor.open_echo_stream(
            consumer,
            device_id,
            service_id,
            grant,
            now + Duration::minutes(1),
            open_tx,
        );
        let registration = open_rx
            .await
            .expect("echo registration response")
            .expect("echo stream admitted");
        registration.claim_admission();
        let Some(ControlOutbound::Text(mut open)) = control.rx.recv().await else {
            panic!("echo OPEN was not queued");
        };
        let open_message_id = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.streams.get(&registration.stream_id))
            .map(|stream| stream.open_message_id.clone())
            .expect("OPEN correlation");
        open.release();
        actor
            .inbound_control(
                key.clone(),
                ControlMessage::Opened(tunnel_protocol::Opened::new(
                    "opened-duplicate-reset",
                    open_message_id,
                    key.session_id.clone(),
                    key.epoch,
                    registration.stream_id,
                    registration.operation_id.clone(),
                    crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                    crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                )),
            )
            .await;

        let reset = Frame::reset(
            key.epoch,
            carrier.generation,
            registration.stream_id,
            1,
            0,
            4_002,
        );
        actor
            .inbound_m2_stream_data(carrier.clone(), reset.clone(), false)
            .await;
        let Some(DataOutbound::Binary(mut ack)) = data_rx.recv().await else {
            panic!("first reset ACK was not queued");
        };
        assert_eq!(
            Frame::decode(ack.as_slice()).expect("ACK decodes").kind,
            FrameKind::Ack
        );
        ack.release();
        let Some(DataOutbound::Binary(mut reciprocal)) = data_rx.recv().await else {
            panic!("reciprocal reset was not queued");
        };
        assert_eq!(
            Frame::decode(reciprocal.as_slice())
                .expect("reciprocal reset decodes")
                .kind,
            FrameKind::Reset
        );
        reciprocal.release();

        actor.inbound_m2_stream_data(carrier, reset, false).await;
        let Some(DataOutbound::Binary(mut duplicate_ack)) = data_rx.recv().await else {
            panic!("duplicate reset ACK was not queued");
        };
        assert_eq!(
            Frame::decode(duplicate_ack.as_slice())
                .expect("duplicate ACK decodes")
                .kind,
            FrameKind::Ack
        );
        duplicate_ack.release();
        assert!(data_rx.try_recv().is_err(), "duplicate RESET must not echo");
        assert!(actor.sessions.contains_key(&key.scope()));
        drop(registration);
    }

    #[tokio::test]
    async fn connector_stream_forget_cannot_reclaim_failed_relay_fin() {
        let now = Utc::now();
        let tenant_id = Uuid::from_u128(421);
        let device_id = Uuid::from_u128(422);
        let principal_id = Uuid::from_u128(423);
        let service_id = Uuid::from_u128(424);
        let identity = DeviceIdentity {
            tenant_id,
            device_id,
            owner_user_id: principal_id,
            credential_id: Uuid::from_u128(425),
            spki_fingerprint: "failed-relay-fin-spki".to_owned(),
            credential_not_before: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(1),
            credential_revoked_at: None,
            device_active: true,
            credential_active: true,
            device_version: 1,
            owner_epoch: 1,
            last_seen_at: Some(now),
        };
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "failed-relay-fin".to_owned(),
            epoch: 1,
        };
        let grant = GrantSnapshot {
            tenant_id,
            principal_id,
            device_id,
            service_id,
            revision: 1,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            valid_until: now + Duration::minutes(1),
            read_started_at: now,
        };
        let consumer = AuthenticatedConsumer {
            tenant_id,
            principal_id,
        };
        let (mut actor, mut control) = admitted_control_actor(identity, key.clone());
        let (data_tx, _data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        let carrier = CarrierKey {
            session: key.clone(),
            generation: 1,
            connection_id: "failed-relay-fin-data".to_owned(),
        };
        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            session.profile = super::RuntimeProfile::M2;
            session.data_tx = Some(data_tx.clone());
            session.active_carrier = Some(DataCarrier {
                context: carrier.context(),
                tx: data_tx,
            });
        }

        let (open_response, open_receiver) = oneshot::channel();
        actor.open_echo_stream(
            consumer,
            device_id,
            service_id,
            grant,
            now + Duration::minutes(1),
            open_response,
        );
        let registration = open_receiver
            .await
            .expect("echo registration response")
            .expect("echo stream admitted");
        registration.claim_admission();
        let Some(ControlOutbound::Text(mut open)) = control.rx.recv().await else {
            panic!("echo OPEN was not queued");
        };
        open.release();

        // The connector admits the OPEN; an unadmitted OPEN would be deferred
        // instead of reaching the FIN reservation below.
        let opened_message_id = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.streams.get(&registration.stream_id))
            .map(|stream| stream.open_message_id.clone())
            .expect("failed-relay-fin OPEN correlation");
        actor
            .inbound_control(
                key.clone(),
                ControlMessage::Opened(tunnel_protocol::Opened::new(
                    "failed-relay-fin-opened",
                    opened_message_id,
                    key.session_id.clone(),
                    key.epoch,
                    registration.stream_id,
                    registration.operation_id.clone(),
                    crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                    crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                )),
            )
            .await;
        // Removing the active writer before close forces the relay's FIN
        // publication to fail. The terminal tombstone and its independent
        // failure deadline must remain retained until the owner proof path
        // can reclaim it; a connector-originated FORGET cannot substitute for
        // that proof.
        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            session.data_tx = None;
            session.active_carrier = None;
        }
        assert!(actor.close_echo_stream(&key, registration.stream_id, &registration.operation_id,));
        assert!(actor.sessions.get(&key.scope()).is_some_and(|session| {
            session
                .streams
                .get(&registration.stream_id)
                .is_some_and(|stream| stream.terminal_fin_failure)
                && session.terminal_fin_failure_deadline.is_some()
        }));

        // Restore a live carrier only to account the connector's terminal
        // cursor. This leaves the failed relay FIN debt present while making
        // the forged opposite-direction FORGET evidence realistic.
        let (peer_tx, mut peer_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            session.data_tx = Some(peer_tx.clone());
            session.active_carrier = Some(DataCarrier {
                context: carrier.context(),
                tx: peer_tx,
            });
        }
        let now_ms = super::monotonic_millis();
        let mut recovery = test_rotation_runtime(
            now_ms,
            session_attempt(&key, "owner", "forged-forget", 1),
            now_ms.saturating_add(20_000),
        );
        recovery.recovery = Some(test_recovery_runtime(now_ms, registration.stream_id));
        actor
            .sessions
            .get_mut(&key.scope())
            .expect("echo session remains active")
            .rotation = Some(recovery);
        actor
            .inbound_m2_stream_data(
                carrier.clone(),
                Frame::fin(key.epoch, carrier.generation, registration.stream_id, 1, 0),
                false,
            )
            .await;
        for _ in 0..2 {
            let Some(DataOutbound::Binary(mut bytes)) = peer_rx.recv().await else {
                panic!("peer terminal accounting must emit ACK and local FIN");
            };
            bytes.release();
        }
        let receive_state = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.streams.get(&registration.stream_id))
            .and_then(|stream| {
                assert!(stream.terminal_fin_failure);
                assert!(
                    stream
                        .sequence
                        .direction(Direction::ConnectorToRelay)
                        .receive_terminal()
                        .is_some()
                );
                tunnel_protocol::rotation_control::ResumeDirectionState::from_sequence_snapshot(
                    registration.stream_id,
                    stream
                        .sequence
                        .snapshot()
                        .direction(Direction::ConnectorToRelay),
                )
                .ok()
            })
            .expect("connector terminal cursor remains fenced");

        actor
            .inbound_control(
                key.clone(),
                ControlMessage::StreamForget(tunnel_protocol::rotation_control::StreamForget {
                    message_id: "connector-forged-forget".to_owned(),
                    reply_to: String::new(),
                    session_id: key.session_id.clone(),
                    epoch: key.epoch,
                    stream_id: registration.stream_id,
                    operation_id: registration.operation_id,
                    direction: Direction::ConnectorToRelay,
                    final_state: receive_state,
                }),
            )
            .await;
        assert!(
            !actor.sessions.contains_key(&key.scope()),
            "connector-originated STREAM_FORGET must fail closed, never reclaim selectively"
        );
        let Some(ControlOutbound::Text(mut rejected)) = control.rx.recv().await else {
            panic!("protocol violation must emit bounded rejection");
        };
        let rejected_message =
            super::wire::parse_control(rejected.as_bytes()).expect("protocol rejection decodes");
        rejected.release();
        assert!(matches!(
            rejected_message,
            ControlMessage::Rejected(ref message)
                if message.code == "UNEXPECTED_STREAM_FORGET"
                    && message.reason == "device session closed"
        ));
    }

    async fn maintenance_rejection_reason(
        identity: DeviceIdentity,
        key: SessionKey,
        renewed: Option<Result<bool, MaintenanceAuthorityFailure>>,
        identity_result: Result<Option<DeviceIdentity>, MaintenanceAuthorityFailure>,
    ) -> String {
        let (mut actor, registration) = admitted_control_actor(identity, key.clone());
        actor
            .finish_maintenance(key, renewed, identity_result)
            .await;
        assert!(
            actor.sessions.is_empty(),
            "maintenance failure must close session"
        );
        let mut rx = registration.rx;
        let Some(ControlOutbound::Text(mut text)) = rx.recv().await else {
            panic!("maintenance closure must enqueue REJECTED");
        };
        let message = super::wire::parse_control(text.as_bytes()).expect("REJECTED message");
        text.release();
        match message {
            ControlMessage::Rejected(rejected) => rejected.code,
            other => panic!("expected REJECTED, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn maintenance_diagnostics_distinguish_authority_and_terminal_denials() {
        let (fixture, device_id, tenant_id, _tenant_b, spki, _spki_b) = shared_device_fixture();
        let catalog = MemoryCatalog::new();
        catalog
            .seed_fixture(&fixture)
            .await
            .expect("seed shared-device fixture");
        let identity = catalog
            .resolve_device(&spki, Utc::now())
            .await
            .expect("resolve maintenance identity")
            .expect("maintenance identity");
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "maintenance-diagnostics".to_owned(),
            epoch: 1,
        };

        let cases = [
            (
                Some(Err(MaintenanceAuthorityFailure {
                    operation: MaintenanceAuthorityOperation::RenewOwner,
                    category: MaintenanceAuthorityCategory::Timeout,
                    elapsed_ms: 2_000,
                })),
                Ok(Some(identity.clone())),
                AUTHORITY_UNAVAILABLE,
            ),
            (
                Some(Err(MaintenanceAuthorityFailure {
                    operation: MaintenanceAuthorityOperation::RenewOwner,
                    category: MaintenanceAuthorityCategory::RedisIo,
                    elapsed_ms: 2_001,
                })),
                Ok(None),
                "AUTHORIZATION_REVOKED",
            ),
            (Some(Ok(false)), Ok(Some(identity.clone())), "OWNER_FENCED"),
            (None, Ok(None), "AUTHORIZATION_REVOKED"),
            (
                None,
                Err(MaintenanceAuthorityFailure {
                    operation: MaintenanceAuthorityOperation::ResolveDevice,
                    category: MaintenanceAuthorityCategory::WrongType,
                    elapsed_ms: 17,
                }),
                AUTHORITY_UNAVAILABLE,
            ),
        ];
        for (renewed, identity_result, expected) in cases {
            let actual = maintenance_rejection_reason(
                identity.clone(),
                key.clone(),
                renewed,
                identity_result,
            )
            .await;
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn maintenance_authority_diagnostics_are_typed_and_redacted() {
        let serialization = CatalogError::Serialization("credential-and-payload-secret".to_owned());
        let serialization_failure = MaintenanceAuthorityFailure::from_catalog(
            MaintenanceAuthorityOperation::ResolveDevice,
            &serialization,
            std::time::Duration::from_millis(23),
        );
        assert_eq!(
            serialization_failure,
            MaintenanceAuthorityFailure {
                operation: MaintenanceAuthorityOperation::ResolveDevice,
                category: MaintenanceAuthorityCategory::Serialization,
                elapsed_ms: 23,
            }
        );
        assert_eq!(serialization_failure.operation.as_str(), "resolve_device");
        assert_eq!(serialization_failure.category.as_str(), "serialization");
        assert!(!format!("{serialization_failure:?}").contains("credential-and-payload-secret"));

        let conflict = CatalogError::Conflict("device-id-and-owner-token-secret");
        let conflict_failure = MaintenanceAuthorityFailure::from_catalog(
            MaintenanceAuthorityOperation::RenewOwner,
            &conflict,
            std::time::Duration::from_millis(41),
        );
        assert_eq!(
            conflict_failure.category,
            MaintenanceAuthorityCategory::Conflict
        );
        assert_eq!(conflict_failure.category.as_str(), "conflict");
        assert!(!format!("{conflict_failure:?}").contains("device-id-and-owner-token-secret"));
    }

    #[test]
    fn allocation_never_wraps_or_reuses_an_exhausted_identity() {
        let mut next = 1;
        assert_eq!(allocate_stream_id(&mut next), Some(1));
        assert_eq!(allocate_stream_id(&mut next), Some(2));
        next = u64::MAX - 1;
        assert_eq!(allocate_stream_id(&mut next), Some(u64::MAX - 1));
        assert_eq!(allocate_stream_id(&mut next), None);
        assert_eq!(allocate_stream_id(&mut next), None);
        assert_eq!(next, u64::MAX);
        next = 0;
        assert_eq!(allocate_stream_id(&mut next), None);
    }

    #[test]
    fn abort_ack_waits_for_actual_owner_closure() {
        let pending = Some(RotateAborted::default());
        assert!(
            RelayActor::pending_abort_ack_if_active(RotationPhase::Aborting, &pending).is_none()
        );
        assert!(pending.is_some());
        assert!(RelayActor::pending_abort_ack_if_active(RotationPhase::Active, &pending).is_some());
    }

    fn test_attempt(label: &str, generation: u64) -> RotationAttemptIdentity {
        RotationAttemptIdentity::new(
            "session",
            1,
            "owner",
            format!("rotation-{label}"),
            generation,
            generation + 1,
            format!("old-{label}"),
            format!("new-{label}"),
        )
    }

    pub(super) fn session_attempt(
        key: &SessionKey,
        owner_id: &str,
        label: &str,
        generation: u64,
    ) -> RotationAttemptIdentity {
        RotationAttemptIdentity::new(
            key.session_id.clone(),
            key.epoch,
            owner_id,
            format!("rotation-{label}"),
            generation,
            generation + 1,
            format!("old-{label}"),
            format!("new-{label}"),
        )
    }

    pub(super) fn test_rotation_runtime(
        now: u64,
        attempt: RotationAttemptIdentity,
        deadline: u64,
    ) -> RotationRuntime {
        let session_id = attempt.session_id.clone();
        let owner_id = attempt.owner_id.clone();
        let epoch = attempt.epoch;
        RotationRuntime {
            state: RotationState::new(
                session_id,
                owner_id,
                epoch,
                attempt.old_generation,
                attempt.old_connection_id.clone(),
                RotationConfig::default(),
            )
            .expect("test rotation state"),
            attempt: Some(attempt),
            attempt_deadline_ms: Some(deadline),
            snapshot_id: String::new(),
            barrier_rx: None,
            candidate: None,
            old_connection_id: String::new(),
            prepare_message_id: String::new(),
            last_message_id: String::new(),
            abort_message_id: None,
            peer_message_id: String::new(),
            quiesce_message_id: String::new(),
            frozen_message_id: String::new(),
            commit_message_id: String::new(),
            retire_message_id: String::new(),
            peer_frozen_message_id: None,
            peer_drained_message_id: None,
            peer_committed_message_id: None,
            peer_retired_message_id: None,
            peer_aborted_message_id: None,
            pending_abort_ack: None,
            tombstones: VecDeque::new(),
            remote_fences: [None, None],
            own_fence: None,
            replayed_frames: 0,
            pending_ticket: None,
            journal: ControlJournal::new(128, 4 * 1024 * 1024, now, deadline)
                .expect("test journal"),
            recovery: None,
            completed_rotation_diagnostics: None,
        }
    }

    fn test_recovery_runtime(now: u64, stream_id: u64) -> RecoveryRuntime {
        RecoveryRuntime {
            episode_id: "recovery-episode".to_owned(),
            attempt_no: 1,
            episode_deadline_ms: now.saturating_add(20_000),
            roster: StreamRoster::new("recovery-roster", vec![stream_id]),
            expected_closed_connection_ids: Vec::new(),
            local_closed: None,
            peer_closed: None,
            closure_digest: None,
            candidate_ready: false,
            resume_message_ids: [None, None],
            snapshot_reply_ids: [None, None],
            local_snapshots: [Vec::new(), Vec::new()],
            ready_snapshots: [Vec::new(), Vec::new()],
            ready_message_ids: [None, None],
            remote_snapshots: [HashMap::new(), HashMap::new()],
            ready_remote_snapshots: [HashMap::new(), HashMap::new()],
            remote_ready: [false, false],
            local_plans: HashMap::new(),
            ready_sent: [false, false],
            deferred_frames: VecDeque::new(),
            deferred_bytes: 0,
            activated: false,
            retry_not_before_ms: None,
            retry_failed_connection_id: None,
        }
    }

    fn attach_ready_recovery_candidate(actor: &mut RelayActor, key: &SessionKey) -> (u64, String) {
        let (candidate_tx, _candidate_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        let session = actor
            .sessions
            .get_mut(&key.scope())
            .expect("recovery candidate session");
        let rotation = session.rotation.as_mut().expect("recovery rotation");
        let attempt = rotation.attempt.clone().expect("recovery attempt");
        rotation
            .state
            .reserve_recovery_socket(super::monotonic_millis())
            .expect("reserve recovery candidate");
        rotation
            .recovery
            .as_mut()
            .expect("recovery runtime")
            .candidate_ready = true;
        let context = CarrierContext::new(
            key.session_id.clone(),
            key.epoch,
            attempt.new_generation,
            attempt.new_connection_id.clone(),
        );
        rotation.candidate = Some(DataCarrier {
            context,
            tx: candidate_tx,
        });
        (attempt.new_generation, attempt.new_connection_id)
    }

    fn retired_message(attempt: RotationAttemptIdentity, message_id: &str) -> ControlMessage {
        ControlMessage::RotateRetired(tunnel_protocol::rotation_control::RotateRetired {
            message_id: message_id.to_owned(),
            reply_to: "relay-retire".to_owned(),
            closed_connection_id: attempt.old_connection_id.clone(),
            attempt,
            snapshot_id: "snapshot".to_owned(),
        })
    }

    #[tokio::test]
    async fn duplicate_catalog_rotation_request_waits_for_one_callback() {
        let (fixture, device_id, tenant_id, _tenant_b, spki, _spki_b) = shared_device_fixture();
        let catalog = MemoryCatalog::new();
        catalog
            .seed_fixture(&fixture)
            .await
            .expect("seed duplicate-request fixture");
        let identity = catalog
            .resolve_device(&spki, Utc::now())
            .await
            .expect("resolve duplicate-request identity")
            .expect("duplicate-request identity present");
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "duplicate-catalog-request".to_owned(),
            epoch: 1,
        };
        let (mut actor, _registration) = admitted_control_actor(identity, key.clone());
        let owner_id = actor
            .sessions
            .get(&key.scope())
            .map(|session| super::runtime::owner_id(&session.owner))
            .expect("duplicate-request owner identity");
        let now_ms = super::monotonic_millis();
        let seed_attempt = session_attempt(&key, &owner_id, "duplicate-catalog-request", 1);
        let old_connection_id = seed_attempt.old_connection_id.clone();
        let mut rotation =
            test_rotation_runtime(now_ms, seed_attempt, now_ms.saturating_add(60_000));
        rotation.attempt = None;
        rotation.old_connection_id = old_connection_id.clone();
        let (data_tx, _data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            session.profile = super::RuntimeProfile::M2;
            session.cluster_profile = true;
            session.connection_id = old_connection_id.clone();
            session.data_tx = Some(data_tx.clone());
            session.active_carrier = Some(DataCarrier {
                context: CarrierContext::new(
                    key.session_id.clone(),
                    key.epoch,
                    1,
                    old_connection_id.clone(),
                ),
                tx: data_tx,
            });
            session.rotation = Some(rotation);
        } else {
            panic!("duplicate-request fixture session missing");
        }
        let request = RotateRequest {
            message_id: "duplicate-catalog-request".to_owned(),
            reply_to: String::new(),
            session_id: key.session_id.clone(),
            epoch: key.epoch,
            owner_id: owner_id.clone(),
            generation: 1,
            connection_id: old_connection_id,
            desired_interval_ms: None,
            reason: Some("client_request".to_owned()),
        };

        // The first request reserves the exact attempt and leaves its catalog
        // callback outstanding. The duplicate follows through the actual
        // inbound path before that callback is delivered.
        actor
            .inbound_control(key.clone(), ControlMessage::RotateRequest(request.clone()))
            .await;
        let attempt = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.rotation.as_ref())
            .and_then(|rotation| rotation.pending_ticket.as_ref())
            .map(|pending| pending.attempt.clone())
            .expect("catalog rotation callback still pending");
        actor
            .inbound_control(key.clone(), ControlMessage::RotateRequest(request.clone()))
            .await;
        assert!(
            actor
                .sessions
                .get(&key.scope())
                .and_then(|session| session.rotation.as_ref())
                .and_then(|rotation| rotation.pending_ticket.as_ref())
                .is_some(),
            "duplicate must leave the original callback pending"
        );

        let ticket = AttachmentTicket {
            ticket: "duplicate-catalog-ticket".to_owned(),
            locator: AttachmentTicketLocator {
                tenant_id,
                device_id,
                digest: "duplicate-catalog-digest".to_owned(),
            },
            expires_at: Utc::now() + chrono::Duration::seconds(5),
        };
        actor
            .finish_catalog_ticket(&key, &attempt, Ok(ticket))
            .await;
        assert!(actor.sessions.contains_key(&key.scope()));
        assert!(
            actor
                .sessions
                .get(&key.scope())
                .and_then(|session| session.rotation.as_ref())
                .and_then(|rotation| rotation.pending_ticket.as_ref())
                .is_none(),
            "one callback must clear the original pending ticket"
        );

        // Completion must have recorded the first request exactly once; a
        // later retry replays the cached PREPARE rather than conflicting with
        // the callback or starting another catalog operation.
        actor
            .inbound_control(key, ControlMessage::RotateRequest(request))
            .await;
        assert!(
            actor.sessions.contains_key(
                &SessionKey {
                    tenant_id,
                    device_id,
                    session_id: "duplicate-catalog-request".to_owned(),
                    epoch: 1,
                }
                .scope()
            )
        );
    }

    #[tokio::test]
    async fn active_loss_during_client_rotation_request_enters_recovery() {
        let now_ms = super::monotonic_millis();
        let (fixture, device_id, tenant_id, _tenant_b, spki, _spki_b) = shared_device_fixture();
        let catalog = MemoryCatalog::new();
        catalog
            .seed_fixture(&fixture)
            .await
            .expect("seed lifecycle race fixture");
        let identity = catalog
            .resolve_device(&spki, Utc::now())
            .await
            .expect("resolve race identity")
            .expect("race identity present");
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "client-request-loss-race".to_owned(),
            epoch: 1,
        };
        let (mut actor, _registration) = admitted_control_actor(identity, key.clone());
        let owner_id = actor
            .sessions
            .get(&key.scope())
            .map(|session| super::runtime::owner_id(&session.owner))
            .expect("owner identity");
        let attempt = session_attempt(&key, &owner_id, "client-request-loss-race", 1);
        let old_connection_id = attempt.old_connection_id.clone();
        let mut rotation = test_rotation_runtime(now_ms, attempt.clone(), now_ms + 60_000);
        rotation
            .state
            .prepare(attempt.clone(), now_ms)
            .expect("prepare ordinary client rotation");
        rotation.attempt_deadline_ms = rotation.state.status().deadline_ms;
        rotation.old_connection_id = old_connection_id.clone();
        let request = RotateRequest {
            message_id: "client-request-loss-race".to_owned(),
            reply_to: String::new(),
            session_id: key.session_id.clone(),
            epoch: key.epoch,
            owner_id,
            generation: 1,
            connection_id: old_connection_id.clone(),
            desired_interval_ms: None,
            reason: Some("data_loss".to_owned()),
        };
        rotation.pending_ticket = Some(super::PendingCatalogTicket {
            attempt: attempt.clone(),
            purpose: DataAttachmentPurpose::RotationCandidate,
            catalog_purpose: "rotation-candidate".to_owned(),
            binding_digest: "bounded-test-binding".to_owned(),
            reply_to: "client-request-loss-race".to_owned(),
            request: Some(ControlMessage::RotateRequest(request.clone())),
        });
        let (data_tx, _data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            session.profile = super::RuntimeProfile::M2;
            session.cluster_profile = true;
            session.connection_id = old_connection_id.clone();
            session.data_tx = Some(data_tx.clone());
            session.active_carrier = Some(DataCarrier {
                context: CarrierContext::new(
                    key.session_id.clone(),
                    key.epoch,
                    1,
                    old_connection_id.clone(),
                ),
                tx: data_tx,
            });
            session.rotation = Some(rotation);
        } else {
            panic!("race fixture session missing");
        }

        actor
            .disconnect_data(CarrierKey {
                session: key.clone(),
                generation: 1,
                connection_id: old_connection_id.clone(),
            })
            .await;

        let session = actor
            .sessions
            .get(&key.scope())
            .expect("request/disconnect race must retain session");
        assert!(session.data_tx.is_none());
        assert!(session.active_carrier.is_none());
        let rotation = session.rotation.as_ref().expect("recovery state retained");
        assert!(rotation.pending_ticket.is_none());
        assert!(rotation.candidate.is_none());
        assert!(rotation.recovery.is_some());
        let status = rotation.state.status();
        assert_eq!(status.phase, RotationPhase::Recovering);
        assert_eq!(status.active_generation, 1);
        assert_eq!(status.active_connection_id, old_connection_id);
        let recovery_attempt = status.attempt.expect("recovery attempt");
        assert_eq!(recovery_attempt.old_generation, 1);
        assert_eq!(recovery_attempt.old_connection_id, old_connection_id);
        assert_eq!(recovery_attempt.new_generation, 3);
        assert!(
            status.socket_count <= 3,
            "recovery exceeded the three-socket bound"
        );
        assert!(
            actor.tickets.is_empty(),
            "ordinary candidate ticket was canceled"
        );

        // The client can deliver its loss notification after the relay has
        // already entered recovery. It is authenticated by the same active
        // generation/connection context, so consume it as an idempotent
        // journal entry rather than opening a second attempt.
        actor
            .inbound_control(key.clone(), ControlMessage::RotateRequest(request.clone()))
            .await;
        assert!(
            actor.sessions.contains_key(&key.scope()),
            "late loss request must not close the recovering session"
        );

        let stale_ticket = AttachmentTicket {
            ticket: "late-canceled-ticket".to_owned(),
            locator: AttachmentTicketLocator {
                tenant_id,
                device_id,
                digest: "late-canceled-digest".to_owned(),
            },
            expires_at: Utc::now() + chrono::Duration::seconds(5),
        };
        actor
            .finish_catalog_ticket(&key, &attempt, Err("late canceled error".to_owned()))
            .await;
        actor
            .finish_catalog_ticket(&key, &attempt, Ok(stale_ticket))
            .await;
        assert!(
            actor.sessions.contains_key(&key.scope()),
            "late catalog results must not close the recovering session"
        );
    }

    #[tokio::test]
    async fn queued_prepare_loss_carries_candidate_closure_and_ignores_late_results() {
        let now_ms = super::monotonic_millis();
        let (fixture, device_id, tenant_id, _tenant_b, spki, _spki_b) = shared_device_fixture();
        let catalog = MemoryCatalog::new();
        catalog
            .seed_fixture(&fixture)
            .await
            .expect("seed queued-prepare fixture");
        let identity = catalog
            .resolve_device(&spki, Utc::now())
            .await
            .expect("resolve queued-prepare identity")
            .expect("queued-prepare identity present");
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "queued-prepare-loss".to_owned(),
            epoch: 1,
        };
        let (mut actor, _registration) = admitted_control_actor(identity, key.clone());
        let owner_id = actor
            .sessions
            .get(&key.scope())
            .map(|session| super::runtime::owner_id(&session.owner))
            .expect("queued-prepare owner identity");
        let attempt = session_attempt(&key, &owner_id, "queued-prepare-loss", 1);
        let old_connection_id = attempt.old_connection_id.clone();
        let mut rotation = test_rotation_runtime(now_ms, attempt.clone(), now_ms + 60_000);
        rotation
            .state
            .prepare(attempt.clone(), now_ms)
            .expect("prepare queued candidate");
        rotation.attempt_deadline_ms = rotation.state.status().deadline_ms;
        rotation.old_connection_id = old_connection_id.clone();
        rotation.prepare_message_id = "queued-prepare-message".to_owned();
        // The catalog result has already issued and queued PREPARE. There is
        // no pending ticket left to resolve, but the reserved candidate must
        // still be included in the recovery closure proof.
        assert!(rotation.pending_ticket.is_none());
        let (data_tx, _data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            session.profile = super::RuntimeProfile::M2;
            session.cluster_profile = true;
            session.connection_id = old_connection_id.clone();
            session.data_tx = Some(data_tx.clone());
            session.active_carrier = Some(DataCarrier {
                context: CarrierContext::new(
                    key.session_id.clone(),
                    key.epoch,
                    1,
                    old_connection_id.clone(),
                ),
                tx: data_tx,
            });
            session.rotation = Some(rotation);
        } else {
            panic!("queued-prepare fixture session missing");
        }

        actor
            .disconnect_data(CarrierKey {
                session: key.clone(),
                generation: 1,
                connection_id: old_connection_id.clone(),
            })
            .await;

        let rotation = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.rotation.as_ref())
            .expect("queued-prepare recovery state");
        assert_eq!(rotation.state.phase(), RotationPhase::Recovering);
        let recovery = rotation.recovery.as_ref().expect("recovery runtime");
        let mut expected_closed =
            vec![old_connection_id.clone(), attempt.new_connection_id.clone()];
        expected_closed.sort_unstable();
        assert_eq!(recovery.expected_closed_connection_ids, expected_closed);
        let local_closed = recovery.local_closed.as_ref().expect("local closure proof");
        assert_eq!(local_closed.closed_connection_ids, expected_closed);
        assert_eq!(
            local_closed.closure_digest,
            local_closed
                .closure_digest_for(super::RecoverySide::Relay)
                .expect("local closure digest")
        );

        let request = RotateRequest {
            message_id: "queued-prepare-loss-request".to_owned(),
            reply_to: String::new(),
            session_id: key.session_id.clone(),
            epoch: key.epoch,
            owner_id,
            generation: 1,
            connection_id: old_connection_id,
            desired_interval_ms: None,
            reason: Some("data_loss".to_owned()),
        };
        // The first delivery creates the recovery journal entry and the
        // duplicate must replay its empty, idempotent completion.
        actor
            .inbound_control(key.clone(), ControlMessage::RotateRequest(request.clone()))
            .await;
        actor
            .inbound_control(key.clone(), ControlMessage::RotateRequest(request))
            .await;
        assert!(actor.sessions.contains_key(&key.scope()));

        let stale_ticket = AttachmentTicket {
            ticket: "late-queued-prepare-ticket".to_owned(),
            locator: AttachmentTicketLocator {
                tenant_id,
                device_id,
                digest: "late-queued-prepare-digest".to_owned(),
            },
            expires_at: Utc::now() + chrono::Duration::seconds(5),
        };
        actor
            .finish_catalog_ticket(&key, &attempt, Err("late queued-prepare error".to_owned()))
            .await;
        actor
            .finish_catalog_ticket(&key, &attempt, Ok(stale_ticket))
            .await;
        assert!(
            actor.sessions.contains_key(&key.scope()),
            "late queued-prepare results must not close the recovering session"
        );
    }

    #[tokio::test]
    async fn active_loss_before_client_rotation_request_enters_recovery() {
        let now_ms = super::monotonic_millis();
        let (fixture, device_id, tenant_id, _tenant_b, spki, _spki_b) = shared_device_fixture();
        let catalog = MemoryCatalog::new();
        catalog
            .seed_fixture(&fixture)
            .await
            .expect("seed disconnect-first fixture");
        let identity = catalog
            .resolve_device(&spki, Utc::now())
            .await
            .expect("resolve disconnect-first identity")
            .expect("disconnect-first identity present");
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "disconnect-first-loss".to_owned(),
            epoch: 1,
        };
        let (mut actor, _registration) = admitted_control_actor(identity, key.clone());
        let owner_id = actor
            .sessions
            .get(&key.scope())
            .map(|session| super::runtime::owner_id(&session.owner))
            .expect("disconnect-first owner identity");
        let attempt = session_attempt(&key, &owner_id, "disconnect-first-loss", 1);
        let old_connection_id = attempt.old_connection_id.clone();
        let mut rotation = test_rotation_runtime(now_ms, attempt, now_ms + 60_000);
        rotation.attempt = None;
        rotation.old_connection_id = old_connection_id.clone();
        let (data_tx, _data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            session.profile = super::RuntimeProfile::M2;
            session.cluster_profile = true;
            session.connection_id = old_connection_id.clone();
            session.data_tx = Some(data_tx.clone());
            session.active_carrier = Some(DataCarrier {
                context: CarrierContext::new(
                    key.session_id.clone(),
                    key.epoch,
                    1,
                    old_connection_id.clone(),
                ),
                tx: data_tx,
            });
            session.rotation = Some(rotation);
        } else {
            panic!("disconnect-first fixture session missing");
        }

        actor
            .disconnect_data(CarrierKey {
                session: key.clone(),
                generation: 1,
                connection_id: old_connection_id.clone(),
            })
            .await;
        let status = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.rotation.as_ref())
            .map(|rotation| rotation.state.status())
            .expect("disconnect-first recovery state");
        assert_eq!(status.phase, RotationPhase::Recovering);
        assert_eq!(status.active_connection_id, old_connection_id);
        assert_eq!(status.active_generation, 1);

        let request = RotateRequest {
            message_id: "disconnect-first-loss-request".to_owned(),
            reply_to: String::new(),
            session_id: key.session_id.clone(),
            epoch: key.epoch,
            owner_id,
            generation: 1,
            connection_id: old_connection_id,
            desired_interval_ms: None,
            reason: Some("data_loss".to_owned()),
        };
        actor
            .inbound_control(key.clone(), ControlMessage::RotateRequest(request))
            .await;
        assert!(
            actor.sessions.contains_key(&key.scope()),
            "request after disconnect must be coalesced into recovery"
        );
        assert_eq!(
            actor
                .sessions
                .get(&key.scope())
                .and_then(|session| session.rotation.as_ref())
                .map(|rotation| rotation.state.phase()),
            Some(RotationPhase::Recovering)
        );
    }

    #[tokio::test]
    async fn recovery_retry_waits_for_policy_gap_and_stale_timer_cannot_resurrect() {
        let now_ms = super::monotonic_millis();
        let (fixture, device_id, tenant_id, _tenant_b, spki, _spki_b) = shared_device_fixture();
        let catalog = MemoryCatalog::new();
        catalog
            .seed_fixture(&fixture)
            .await
            .expect("seed paced-recovery fixture");
        let identity = catalog
            .resolve_device(&spki, Utc::now())
            .await
            .expect("resolve paced-recovery identity")
            .expect("paced-recovery identity present");
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "paced-recovery".to_owned(),
            epoch: 1,
        };
        let (mut actor, _registration) = admitted_control_actor(identity, key.clone());
        let owner_id = actor
            .sessions
            .get(&key.scope())
            .map(|session| super::runtime::owner_id(&session.owner))
            .expect("paced-recovery owner identity");
        let initial_attempt = session_attempt(&key, &owner_id, "paced-recovery", 1);
        let old_connection_id = initial_attempt.old_connection_id.clone();
        let mut rotation =
            test_rotation_runtime(now_ms, initial_attempt, now_ms.saturating_add(30_000));
        rotation.attempt = None;
        rotation.old_connection_id = old_connection_id.clone();
        let (active_tx, _active_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            session.profile = super::RuntimeProfile::M2;
            session.connection_id = old_connection_id.clone();
            session.data_tx = Some(active_tx.clone());
            session.active_carrier = Some(DataCarrier {
                context: CarrierContext::new(
                    key.session_id.clone(),
                    key.epoch,
                    1,
                    old_connection_id.clone(),
                ),
                tx: active_tx,
            });
            session.rotation = Some(rotation);
        } else {
            panic!("paced-recovery session missing");
        }

        actor
            .disconnect_data(CarrierKey {
                session: key.clone(),
                generation: 1,
                connection_id: old_connection_id.clone(),
            })
            .await;
        let first_attempt = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.rotation.as_ref())
            .and_then(|rotation| rotation.attempt.clone())
            .expect("initial recovery attempt");
        let first_started_at_ms = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.rotation.as_ref())
            .and_then(|rotation| rotation.state.status().started_at_ms)
            .expect("initial recovery timestamp");
        let episode_deadline_ms = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.rotation.as_ref())
            .and_then(|rotation| rotation.recovery.as_ref())
            .map(|recovery| recovery.episode_deadline_ms)
            .expect("initial recovery episode deadline");
        let (candidate_generation, candidate_connection_id) =
            attach_ready_recovery_candidate(&mut actor, &key);
        let observed_loss_at_ms = super::monotonic_millis();

        actor
            .disconnect_data(CarrierKey {
                session: key.clone(),
                generation: candidate_generation,
                connection_id: candidate_connection_id.clone(),
            })
            .await;

        let session = actor
            .sessions
            .get(&key.scope())
            .expect("candidate loss keeps the recovery session");
        let rotation = session.rotation.as_ref().expect("rotation runtime");
        let recovery = rotation.recovery.as_ref().expect("recovery runtime");
        assert_eq!(recovery.attempt_no, 1);
        assert_eq!(rotation.attempt.as_ref(), Some(&first_attempt));
        assert_eq!(
            recovery.retry_failed_connection_id.as_deref(),
            Some(candidate_connection_id.as_str())
        );
        assert!(
            recovery
                .retry_not_before_ms
                .is_some_and(|not_before| not_before >= observed_loss_at_ms + 100)
        );
        assert!(matches!(
            actor.rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert!(!actor.retry_recovery_after_candidate_loss(&key, "stale-candidate"));

        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        let retry_command =
            tokio::time::timeout(std::time::Duration::from_millis(100), actor.rx.recv())
                .await
                .expect("first retry timer must enqueue its command")
                .expect("retry command channel remains open");
        actor.handle(retry_command).await;
        assert!(matches!(
            actor.rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        let session = actor
            .sessions
            .get(&key.scope())
            .expect("eligible retry keeps the session");
        let rotation = session.rotation.as_ref().expect("retry rotation runtime");
        let recovery = rotation.recovery.as_ref().expect("retry recovery runtime");
        assert_eq!(recovery.attempt_no, 2);
        assert_eq!(recovery.episode_deadline_ms, episode_deadline_ms);
        assert_eq!(
            recovery.expected_closed_connection_ids,
            vec![candidate_connection_id.clone()]
        );
        let second_started_at_ms = rotation
            .state
            .status()
            .started_at_ms
            .expect("second recovery timestamp");
        assert!(second_started_at_ms >= first_started_at_ms + 100);
        let second_attempt = rotation.attempt.clone().expect("second attempt");
        assert_eq!(second_attempt.old_connection_id, old_connection_id);
        assert_eq!(
            second_attempt.new_generation,
            first_attempt.new_generation + 1
        );
        assert_ne!(second_attempt.new_connection_id, candidate_connection_id);

        // A duplicate timer command after the pending marker was consumed is
        // a no-op and cannot allocate a second candidate for the same loss.
        actor.handle_recovery_retry(key.clone()).await;
        let duplicate_attempt = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.rotation.as_ref())
            .and_then(|rotation| rotation.attempt.as_ref())
            .expect("duplicate retry retains the second attempt");
        assert_eq!(duplicate_attempt, &second_attempt);

        let (second_candidate_generation, second_candidate_connection_id) =
            attach_ready_recovery_candidate(&mut actor, &key);
        let second_loss_at_ms = super::monotonic_millis();
        actor
            .disconnect_data(CarrierKey {
                session: key.clone(),
                generation: second_candidate_generation,
                connection_id: second_candidate_connection_id.clone(),
            })
            .await;
        let session = actor
            .sessions
            .get(&key.scope())
            .expect("second candidate loss keeps the session");
        let recovery = session
            .rotation
            .as_ref()
            .and_then(|rotation| rotation.recovery.as_ref())
            .expect("second retry recovery");
        assert_eq!(recovery.attempt_no, 2);
        assert!(
            recovery
                .retry_not_before_ms
                .is_some_and(|not_before| not_before >= second_loss_at_ms + 200)
        );
        assert!(matches!(
            actor.rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        tokio::time::sleep(std::time::Duration::from_millis(220)).await;
        let retry_command =
            tokio::time::timeout(std::time::Duration::from_millis(100), actor.rx.recv())
                .await
                .expect("second retry timer must enqueue its command")
                .expect("retry command channel remains open");
        actor.handle(retry_command).await;
        assert!(matches!(
            actor.rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        let session = actor
            .sessions
            .get(&key.scope())
            .expect("third attempt keeps the session");
        let rotation = session.rotation.as_ref().expect("third retry rotation");
        let recovery = rotation.recovery.as_ref().expect("third retry recovery");
        assert_eq!(recovery.attempt_no, 3);
        assert_eq!(recovery.episode_deadline_ms, episode_deadline_ms);
        assert_eq!(
            recovery.expected_closed_connection_ids,
            vec![second_candidate_connection_id.clone()]
        );
        assert_ne!(
            rotation
                .attempt
                .as_ref()
                .expect("third attempt")
                .new_connection_id,
            second_candidate_connection_id
        );
        let third_started_at_ms = rotation
            .state
            .status()
            .started_at_ms
            .expect("third recovery timestamp");
        assert!(third_started_at_ms >= second_started_at_ms + 200);

        let (third_candidate_generation, third_candidate_connection_id) =
            attach_ready_recovery_candidate(&mut actor, &key);
        actor
            .disconnect_data(CarrierKey {
                session: key.clone(),
                generation: third_candidate_generation,
                connection_id: third_candidate_connection_id,
            })
            .await;
        assert!(!actor.sessions.contains_key(&key.scope()));
        assert_eq!(
            actor
                .session_terminal_events
                .back()
                .map(|event| event.reason),
            Some("RECOVERY_CANDIDATE_FAILED")
        );

        actor.handle_recovery_retry(key.clone()).await;
        assert!(!actor.sessions.contains_key(&key.scope()));
        actor.options.shutdown.cancel();
        let shutdown_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        assert!(
            actor
                .shutdown_background_tasks(shutdown_deadline, shutdown_deadline)
                .await
        );
    }

    #[tokio::test]
    async fn pending_recovery_retry_timer_is_joined_before_shutdown_returns() {
        let now_ms = super::monotonic_millis();
        let (fixture, device_id, tenant_id, _tenant_b, spki, _spki_b) = shared_device_fixture();
        let catalog = MemoryCatalog::new();
        catalog
            .seed_fixture(&fixture)
            .await
            .expect("seed shutdown-timer fixture");
        let identity = catalog
            .resolve_device(&spki, Utc::now())
            .await
            .expect("resolve shutdown-timer identity")
            .expect("shutdown-timer identity present");
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "pending-retry-shutdown".to_owned(),
            epoch: 1,
        };
        let (mut actor, _registration) = admitted_control_actor(identity, key.clone());
        let owner_id = actor
            .sessions
            .get(&key.scope())
            .map(|session| super::runtime::owner_id(&session.owner))
            .expect("shutdown-timer owner identity");
        let initial_attempt = session_attempt(&key, &owner_id, "pending-retry-shutdown", 1);
        let old_connection_id = initial_attempt.old_connection_id.clone();
        let mut rotation =
            test_rotation_runtime(now_ms, initial_attempt, now_ms.saturating_add(30_000));
        rotation.attempt = None;
        rotation.old_connection_id = old_connection_id.clone();
        let (active_tx, _active_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        if let Some(session) = actor.sessions.get_mut(&key.scope()) {
            session.profile = super::RuntimeProfile::M2;
            session.connection_id = old_connection_id.clone();
            session.data_tx = Some(active_tx.clone());
            session.active_carrier = Some(DataCarrier {
                context: CarrierContext::new(
                    key.session_id.clone(),
                    key.epoch,
                    1,
                    old_connection_id.clone(),
                ),
                tx: active_tx,
            });
            session.rotation = Some(rotation);
        } else {
            panic!("shutdown-timer session missing");
        }

        actor
            .disconnect_data(CarrierKey {
                session: key.clone(),
                generation: 1,
                connection_id: old_connection_id,
            })
            .await;
        let (candidate_generation, candidate_connection_id) =
            attach_ready_recovery_candidate(&mut actor, &key);
        actor
            .disconnect_data(CarrierKey {
                session: key.clone(),
                generation: candidate_generation,
                connection_id: candidate_connection_id,
            })
            .await;

        let recovery = actor
            .sessions
            .get(&key.scope())
            .and_then(|session| session.rotation.as_ref())
            .and_then(|rotation| rotation.recovery.as_ref())
            .expect("pending retry recovery");
        assert!(recovery.retry_not_before_ms.is_some());
        assert!(recovery.retry_failed_connection_id.is_some());
        assert_eq!(actor.background_tasks.len(), 1);
        assert!(matches!(
            actor.rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        // Leave the retry timer pending and exercise the supervisor's bounded
        // abort/join path directly.  A timer that remains in the JoinSet after
        // this return could later enqueue RetryRecovery against a torn-down
        // actor and would make shutdown ownership unprovable.
        let graceful_deadline = tokio::time::Instant::now();
        let abort_deadline = graceful_deadline + std::time::Duration::from_secs(1);
        assert!(
            actor
                .shutdown_background_tasks(graceful_deadline, abort_deadline)
                .await
        );
        assert!(actor.background_tasks.is_empty());
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(matches!(
            actor.rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn completed_rotation_journal_replays_after_attempt_clear_and_new_attempt() {
        let now = 1_000;
        let deadline_a = 2_000;
        let attempt_a = test_attempt("a", 1);
        let retired = retired_message(attempt_a.clone(), "retired-a");
        let mut rotation = test_rotation_runtime(now, attempt_a.clone(), deadline_a);
        match RelayActor::observe_rotation_journal(&mut rotation, &retired, now + 1) {
            RotationJournalDecision::New => {}
            other => panic!("expected new retired request, got {other:?}"),
        }
        let complete = super::wire::rotate_complete(
            retired.message_id(),
            attempt_a.clone(),
            "snapshot",
            false,
            None,
        );
        let complete_bytes = super::wire::encode_control_message(&complete)
            .expect("encoded completion")
            .into_bytes();
        rotation
            .journal
            .complete(retired.message_id(), &complete_bytes, now + 2)
            .expect("complete retired journal entry");
        assert!(RelayActor::retain_rotation_tombstone(&mut rotation));
        rotation.attempt = None;
        rotation.attempt_deadline_ms = None;
        rotation.attempt = Some(test_attempt("b", 2));
        rotation.attempt_deadline_ms = Some(3_000);
        rotation.journal =
            ControlJournal::new(128, 4 * 1024 * 1024, now + 2, 3_000).expect("new attempt journal");

        for retry_now in [now + 3, now + 4] {
            match RelayActor::observe_rotation_journal(&mut rotation, &retired, retry_now) {
                RotationJournalDecision::CompletedDuplicate(response) => {
                    assert_eq!(response, vec![complete_bytes.clone()]);
                }
                other => panic!("expected cached completion, got {other:?}"),
            }
        }
        assert_eq!(rotation.tombstones.len(), 1);
        RelayActor::prune_rotation_tombstones(&mut rotation, deadline_a);
        assert!(matches!(
            RelayActor::observe_rotation_journal(&mut rotation, &retired, deadline_a),
            RotationJournalDecision::Error(
                tunnel_protocol::control_journal::JournalError::MissingMessage
            )
        ));
    }

    #[test]
    fn rotation_tombstone_capacity_rejects_without_evicting_live_history() {
        let now = 10_000;
        let mut rotation = test_rotation_runtime(now, test_attempt("0", 1), 20_000);
        for index in 0..MAX_ROTATION_TOMBSTONES {
            let generation = (index as u64) + 1;
            let attempt = test_attempt(&index.to_string(), generation);
            rotation.attempt = Some(attempt);
            rotation.attempt_deadline_ms = Some(20_000 + generation);
            rotation.journal = ControlJournal::new(128, 4 * 1024 * 1024, now, 20_000 + generation)
                .expect("bounded attempt journal");
            assert!(RelayActor::retain_rotation_tombstone(&mut rotation));
        }
        let oldest = rotation
            .tombstones
            .front()
            .map(|tombstone| tombstone.attempt.clone())
            .expect("oldest tombstone");
        rotation.attempt = Some(test_attempt("overflow", 20));
        rotation.attempt_deadline_ms = Some(30_000);
        assert!(!RelayActor::rotation_tombstone_capacity_available(
            &mut rotation,
            now,
        ));
        assert!(!RelayActor::retain_rotation_tombstone(&mut rotation));
        assert_eq!(rotation.tombstones.len(), MAX_ROTATION_TOMBSTONES);
        assert_eq!(
            rotation.tombstones.front().map(|item| &item.attempt),
            Some(&oldest)
        );
    }

    #[test]
    fn drained_deadline_latches_before_session_removal_with_exact_error_identity() {
        let now = Utc::now();
        let tenant_id = Uuid::from_u128(1);
        let device_id = Uuid::from_u128(2);
        let attempt = test_attempt("drained-deadline", 2);
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: attempt.session_id.clone(),
            epoch: attempt.epoch,
        };
        let identity = DeviceIdentity {
            tenant_id,
            device_id,
            owner_user_id: Uuid::from_u128(3),
            credential_id: Uuid::from_u128(4),
            spki_fingerprint: "test-spki".to_owned(),
            credential_not_before: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(1),
            credential_revoked_at: None,
            device_active: true,
            credential_active: true,
            device_version: 1,
            owner_epoch: key.epoch,
            last_seen_at: Some(now),
        };
        let (mut actor, _registration) = admitted_control_actor(identity, key.clone());
        let mut rotation = test_rotation_runtime(0, attempt.clone(), 30_000);
        rotation
            .state
            .prepare(attempt.clone(), 0)
            .expect("prepare rotation");
        rotation
            .state
            .candidate_ready(&attempt, 1)
            .expect("candidate ready");
        rotation
            .state
            .quiesce(
                &attempt,
                tunnel_protocol::rotation_control::StreamRoster::new("drained", vec![]),
                2,
            )
            .expect("quiesce");
        let empty_fence = FenceSnapshot::new("drained", vec![]);
        rotation
            .state
            .frozen(
                &attempt,
                empty_fence.clone(),
                Direction::RelayToConnector,
                3,
            )
            .expect("relay frozen");
        rotation
            .state
            .frozen(
                &attempt,
                empty_fence.clone(),
                Direction::ConnectorToRelay,
                4,
            )
            .expect("connector frozen");
        let proof = DrainProof::new(
            "drained",
            empty_fence.digest().expect("empty fence digest"),
            Direction::RelayToConnector,
            vec![],
        );
        actor
            .sessions
            .get_mut(&key.scope())
            .expect("test session")
            .rotation = Some(rotation);

        let result = actor.with_rotation_mut(&key, |_session, rotation| {
            rotation.state.drained(&attempt, proof, 30_000)
        });
        assert!(matches!(
            result,
            Err(tunnel_protocol::rotation::RotationError::DeadlineExpired {
                now: 30_000,
                deadline: 30_000,
            })
        ));
        let event = actor
            .snapshot()
            .rotation_deadline_events
            .first()
            .cloned()
            .expect("drained deadline event");
        assert_eq!(event.tenant_id, tenant_id.to_string());
        assert_eq!(event.device_id, device_id.to_string());
        assert_eq!(event.session_id, attempt.session_id);
        assert_eq!(event.epoch, attempt.epoch);
        assert_eq!(event.old_generation, attempt.old_generation);
        assert_eq!(event.old_connection_id, attempt.old_connection_id);
        assert_eq!(event.candidate_generation, attempt.new_generation);
        assert_eq!(event.candidate_connection_id, attempt.new_connection_id);
        assert_eq!(event.started_at_ms, 0);
        assert_eq!(event.deadline_ms, 30_000);
        assert_eq!(event.fired_at_ms, 30_000);
        assert_eq!(event.reason, "deadline");

        actor.sessions.clear();
        let snapshot = actor.snapshot();
        assert!(snapshot.sessions.is_empty());
        assert_eq!(snapshot.rotation_deadline_events, vec![event]);
    }

    #[test]
    fn deadline_event_survives_owner_session_removal_with_exact_attempt_identity() {
        let now = 0;
        let attempt = test_attempt("deadline-event", 2);
        let mut rotation = test_rotation_runtime(now, attempt.clone(), 30_000);
        rotation
            .state
            .prepare(attempt.clone(), now)
            .expect("start rotation attempt");
        let key = SessionKey {
            tenant_id: Uuid::from_u128(1),
            device_id: Uuid::from_u128(2),
            session_id: attempt.session_id.clone(),
            epoch: attempt.epoch,
        };
        let event = RelayActor::rotation_deadline_event(&key, &rotation, 30_001)
            .expect("deadline event from authoritative attempt");
        assert_eq!(event.tenant_id, key.tenant_id.to_string());
        assert_eq!(event.device_id, key.device_id.to_string());
        assert_eq!(event.old_generation, attempt.old_generation);
        assert_eq!(event.old_connection_id, attempt.old_connection_id);
        assert_eq!(event.candidate_generation, attempt.new_generation);
        assert_eq!(event.candidate_connection_id, attempt.new_connection_id);
        assert_eq!(event.started_at_ms, 0);
        assert_eq!(event.deadline_ms, 30_000);
        assert_eq!(event.fired_at_ms, 30_001);
        assert_eq!(event.reason, "deadline");

        let identity = DeviceIdentity {
            tenant_id: key.tenant_id,
            device_id: key.device_id,
            owner_user_id: Uuid::from_u128(3),
            credential_id: Uuid::from_u128(4),
            spki_fingerprint: "test-spki".to_owned(),
            credential_not_before: Utc::now() - Duration::minutes(1),
            expires_at: Utc::now() + Duration::minutes(1),
            credential_revoked_at: None,
            device_active: true,
            credential_active: true,
            device_version: 1,
            owner_epoch: key.epoch,
            last_seen_at: Some(Utc::now()),
        };
        let (mut actor, _registration) = admitted_control_actor(identity, key);
        actor.retain_rotation_deadline_event(event.clone());
        actor.sessions.clear();
        let snapshot = actor.snapshot();
        assert!(snapshot.sessions.is_empty());
        assert_eq!(snapshot.rotation_deadline_events, vec![event]);
    }

    #[test]
    fn progressive_rotation_replay_preserves_frozen_then_drained_replies() {
        let now = 40_000;
        let attempt = test_attempt("progressive", 1);
        let request = retired_message(attempt.clone(), "shared-request");
        let snapshot = tunnel_protocol::rotation_control::FenceSnapshot::new("snapshot", vec![]);
        let proof = tunnel_protocol::rotation_control::DrainProof::new(
            "snapshot",
            snapshot.digest().expect("snapshot digest"),
            tunnel_protocol::Direction::ConnectorToRelay,
            vec![],
        );
        let frozen = super::wire::rotate_frozen(request.message_id(), attempt.clone(), snapshot);
        let drained = super::wire::rotate_drained(request.message_id(), attempt, proof);
        let frozen_bytes = super::wire::encode_control_message(&frozen)
            .expect("encoded frozen")
            .into_bytes();
        let drained_bytes = super::wire::encode_control_message(&drained)
            .expect("encoded drained")
            .into_bytes();
        let mut rotation = test_rotation_runtime(now, test_attempt("progressive", 1), 50_000);
        match RelayActor::observe_rotation_journal(&mut rotation, &request, now + 1) {
            RotationJournalDecision::New => {}
            other => panic!("expected new shared request, got {other:?}"),
        }
        rotation
            .journal
            .append_response(
                request.message_id(),
                frozen.message_id(),
                &frozen_bytes,
                now + 2,
            )
            .expect("append frozen response");
        rotation
            .journal
            .append_response(
                request.message_id(),
                drained.message_id(),
                &drained_bytes,
                now + 3,
            )
            .expect("append drained response");
        match RelayActor::observe_rotation_journal(&mut rotation, &request, now + 4) {
            RotationJournalDecision::CompletedDuplicate(responses) => {
                assert_eq!(responses, vec![frozen_bytes, drained_bytes]);
            }
            other => panic!("expected progressive replay, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rotate_drained_reply_stays_pinned_when_connector_proof_arrives_first() {
        let now = super::monotonic_millis();
        let tenant_id = Uuid::from_u128(501);
        let device_id = Uuid::from_u128(502);
        let identity = DeviceIdentity {
            tenant_id,
            device_id,
            owner_user_id: Uuid::from_u128(503),
            credential_id: Uuid::from_u128(504),
            spki_fingerprint: "drained-reply-spki".to_owned(),
            credential_not_before: Utc::now() - Duration::minutes(1),
            expires_at: Utc::now() + Duration::minutes(1),
            credential_revoked_at: None,
            device_active: true,
            credential_active: true,
            device_version: 1,
            owner_epoch: 1,
            last_seen_at: Some(Utc::now()),
        };
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "drained-reply-correlation".to_owned(),
            epoch: 1,
        };
        let (mut actor, mut registration) = admitted_control_actor(identity, key.clone());
        let owner_id = actor
            .sessions
            .get(&key.scope())
            .map(|session| super::runtime::owner_id(&session.owner))
            .expect("rotation owner identity");
        let attempt = session_attempt(&key, &owner_id, "drained-reply-correlation", 1);
        let mut rotation = test_rotation_runtime(now, attempt.clone(), now + 60_000);
        rotation
            .state
            .prepare(attempt.clone(), now)
            .expect("rotation prepares");
        rotation
            .state
            .candidate_ready(&attempt, now)
            .expect("candidate is ready");
        let roster = StreamRoster::new("drained-reply", vec![]);
        rotation
            .state
            .quiesce(&attempt, roster, now)
            .expect("rotation quiesces");
        let relay_fence = FenceSnapshot::new("drained-reply", vec![]);
        let connector_fence = FenceSnapshot::new("drained-reply", vec![]);
        rotation
            .state
            .frozen(
                &attempt,
                relay_fence.clone(),
                Direction::RelayToConnector,
                now,
            )
            .expect("relay fence is accepted");
        rotation
            .state
            .frozen(
                &attempt,
                connector_fence.clone(),
                Direction::ConnectorToRelay,
                now,
            )
            .expect("connector fence is accepted");
        rotation.snapshot_id = "drained-reply".to_owned();
        rotation.frozen_message_id = "relay-frozen".to_owned();
        rotation.peer_frozen_message_id = Some("connector-frozen".to_owned());
        // This is the ordering that used to corrupt the next reply: the
        // connector's DRAINED proof is accepted before the relay's own ACK
        // cursor reaches its fence, so the generic peer ID becomes the
        // connector DRAINED ID instead of the pinned FROZEN ID.
        rotation.peer_message_id = "connector-frozen".to_owned();
        rotation.remote_fences[super::direction_index(Direction::ConnectorToRelay)] =
            Some(connector_fence);
        actor
            .sessions
            .get_mut(&key.scope())
            .expect("test session")
            .rotation = Some(rotation);

        let connector_proof = DrainProof::new(
            "drained-reply",
            relay_fence.digest().expect("relay fence digest"),
            Direction::RelayToConnector,
            vec![],
        );
        actor
            .handle_rotate_drained(
                &key,
                tunnel_protocol::rotation_control::RotateDrained {
                    message_id: "connector-drained".to_owned(),
                    reply_to: "relay-frozen".to_owned(),
                    attempt: attempt.clone(),
                    proof: connector_proof,
                },
            )
            .await;

        let Some(ControlOutbound::Text(mut queued)) =
            tokio::time::timeout(std::time::Duration::from_secs(1), registration.rx.recv())
                .await
                .expect("relay DRAINED must be emitted within the test bound")
        else {
            panic!("relay must emit its DRAINED reply");
        };
        let response =
            super::wire::parse_control(queued.as_bytes()).expect("relay DRAINED response decodes");
        queued.release();
        let ControlMessage::RotateDrained(response) = response else {
            panic!("expected relay DRAINED response");
        };
        assert_eq!(response.reply_to, "connector-frozen");
        assert_eq!(response.attempt, attempt);
        assert_eq!(response.proof.direction, Direction::ConnectorToRelay);

        // Both proofs are now present, so the same handler may queue COMMIT;
        // release that item as part of the test-owned queue cleanup.
        if let Ok(ControlOutbound::Text(mut queued)) = registration.rx.try_recv() {
            queued.release();
        }
    }

    #[test]
    fn peer_phase_message_ids_reject_fresh_same_attempt_messages() {
        for first in ["frozen-first", "retired-first", "aborted-first"] {
            let mut pinned = None;
            assert!(RelayActor::pin_peer_message_id(&mut pinned, first));
            assert!(RelayActor::peer_message_id_is_acceptable(
                pinned.as_deref(),
                first,
            ));
            assert!(!RelayActor::peer_message_id_is_acceptable(
                pinned.as_deref(),
                "fresh-conflicting-id",
            ));
            assert!(!RelayActor::pin_peer_message_id(
                &mut pinned,
                "fresh-conflicting-id",
            ));
            assert_eq!(pinned.as_deref(), Some(first));
        }
    }

    /// Install an M2 session whose pure rotation machine is `Active` on
    /// `old_connection_id` with no attempt, a live data carrier, and a policy
    /// timer that is already due, so the next maintenance tick starts a
    /// local (non-catalog) rotation.
    fn install_rotation_due_session(
        actor: &mut RelayActor,
        key: &SessionKey,
        rotation: RotationRuntime,
        old_connection_id: &str,
        queue_budget: QueueBudget,
    ) -> mpsc::Receiver<DataOutbound> {
        let (data_tx, data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
        let session = actor
            .sessions
            .get_mut(&key.scope())
            .expect("rotation-due session");
        session.profile = super::RuntimeProfile::M2;
        session.generation = 1;
        session.connection_id = old_connection_id.to_owned();
        session.data_tx = Some(data_tx.clone());
        session.active_carrier = Some(DataCarrier {
            context: CarrierContext::new(
                key.session_id.clone(),
                key.epoch,
                1,
                old_connection_id.to_owned(),
            ),
            tx: data_tx,
        });
        session.queue_budget = queue_budget;
        session.rotation = Some(rotation);
        session.last_rotation = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(600))
            .expect("monotonic clock predates one rotation interval");
        data_rx
    }

    #[tokio::test]
    async fn local_prepare_queue_failure_fails_closed_with_typed_reason() {
        let now_ms = super::monotonic_millis();
        let (fixture, device_id, tenant_id, _tenant_b, spki, _spki_b) = shared_device_fixture();
        let catalog = MemoryCatalog::new();
        catalog
            .seed_fixture(&fixture)
            .await
            .expect("seed prepare-queue fixture");
        let identity = catalog
            .resolve_device(&spki, Utc::now())
            .await
            .expect("resolve prepare-queue identity")
            .expect("prepare-queue identity present");
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "local-prepare-queue".to_owned(),
            epoch: 1,
        };
        let (mut actor, _registration) = admitted_control_actor(identity, key.clone());
        let owner_id = actor
            .sessions
            .get(&key.scope())
            .map(|session| super::runtime::owner_id(&session.owner))
            .expect("owner identity");
        let attempt = session_attempt(&key, &owner_id, "local-prepare-queue", 1);
        let old_connection_id = attempt.old_connection_id.clone();
        let mut rotation = test_rotation_runtime(now_ms, attempt, now_ms + 60_000);
        rotation.attempt = None;
        rotation.attempt_deadline_ms = None;
        rotation.old_connection_id = old_connection_id.clone();
        // A budget smaller than any encoded PREPARE makes the bounded control
        // queue refuse the message deterministically.
        let _data_rx = install_rotation_due_session(
            &mut actor,
            &key,
            rotation,
            &old_connection_id,
            QueueBudget::new(1),
        );

        actor.tick().await;

        assert!(
            !actor.sessions.contains_key(&key.scope()),
            "a local PREPARE that cannot be queued must fail closed immediately instead of \
             stranding an attempt-less Preparing machine until ROTATION_DEADLINE_EXPIRED"
        );
        assert_eq!(
            actor
                .session_terminal_events
                .back()
                .map(|event| event.reason),
            Some("ROTATION_PREPARE_QUEUE"),
            "the local path must report the same typed outcome as the catalog ticket path"
        );
        assert!(
            actor.tickets.is_empty(),
            "the never-published candidate ticket must be withdrawn"
        );
    }

    #[tokio::test]
    async fn exhausted_connection_history_terminates_session_with_typed_reason() {
        let now_ms = super::monotonic_millis();
        let (fixture, device_id, tenant_id, _tenant_b, spki, _spki_b) = shared_device_fixture();
        let catalog = MemoryCatalog::new();
        catalog
            .seed_fixture(&fixture)
            .await
            .expect("seed history-exhaustion fixture");
        let identity = catalog
            .resolve_device(&spki, Utc::now())
            .await
            .expect("resolve history-exhaustion identity")
            .expect("history-exhaustion identity present");
        let key = SessionKey {
            tenant_id,
            device_id,
            session_id: "connection-history-exhausted".to_owned(),
            epoch: 1,
        };
        let (mut actor, _registration) = admitted_control_actor(identity, key.clone());
        let owner_id = actor
            .sessions
            .get(&key.scope())
            .map(|session| super::runtime::owner_id(&session.owner))
            .expect("owner identity");
        let attempt = session_attempt(&key, &owner_id, "connection-history-exhausted", 1);
        let old_connection_id = attempt.old_connection_id.clone();
        let mut rotation = test_rotation_runtime(now_ms, attempt, now_ms + 60_000);
        rotation.attempt = None;
        rotation.attempt_deadline_ms = None;
        rotation.old_connection_id = old_connection_id.clone();
        // Drive the pure machine to its bounded connection-ID history with
        // coordinated aborts on the same old carrier.  Every step observes
        // the same instant: the machine accepts equal timestamps, no attempt
        // deadline can expire, and the actor's later real prepare cannot be
        // seen as a clock going backwards.
        let clock = now_ms;
        for index in 0..(tunnel_protocol::rotation::MAX_CONNECTION_ID_HISTORY - 1) {
            let identity = RotationAttemptIdentity::new(
                key.session_id.clone(),
                key.epoch,
                owner_id.clone(),
                format!("history-{index}"),
                1,
                2 + index as u64,
                old_connection_id.clone(),
                format!("history-candidate-{index}"),
            );
            rotation
                .state
                .prepare(identity.clone(), clock)
                .expect("prepare history attempt");
            rotation
                .state
                .abort(
                    &identity,
                    clock,
                    tunnel_protocol::rotation::RecoveryReason::CandidateTransportLost,
                )
                .expect("abort history attempt");
            for side in [
                tunnel_protocol::rotation::RotationSide::Owner,
                tunnel_protocol::rotation::RotationSide::Connector,
            ] {
                rotation
                    .state
                    .candidate_closed(
                        &identity,
                        side,
                        tunnel_protocol::rotation::ClosureEvidence::closed(
                            identity.new_connection_id.clone(),
                        ),
                        clock,
                    )
                    .expect("release history candidate");
            }
        }
        assert_eq!(rotation.state.phase(), RotationPhase::Active);
        assert_eq!(
            rotation.state.connection_history_used(),
            tunnel_protocol::rotation::MAX_CONNECTION_ID_HISTORY
        );
        let queue_budget = QueueBudget::new(actor.options.limits.max_queue_bytes);
        let _data_rx = install_rotation_due_session(
            &mut actor,
            &key,
            rotation,
            &old_connection_id,
            queue_budget,
        );

        actor.tick().await;

        assert!(
            !actor.sessions.contains_key(&key.scope()),
            "an exhausted connection-ID history must end the session explicitly rather than \
             leaving a never-rotating data socket that looks healthy"
        );
        assert_eq!(
            actor
                .session_terminal_events
                .back()
                .map(|event| event.reason),
            Some("CONNECTION_HISTORY_EXHAUSTED")
        );
        assert!(actor.tickets.is_empty(), "no candidate ticket may survive");
    }
}

#[cfg(test)]
#[path = "actor_lifecycle_tests.rs"]
mod lifecycle_tests;

#[cfg(test)]
#[path = "actor_admission_race_tests.rs"]
mod admission_race_tests;

#[cfg(test)]
#[path = "actor_challenge_mismatch_tests.rs"]
mod challenge_mismatch_tests;

#[cfg(test)]
#[path = "actor_rotation_freeze_tests.rs"]
mod rotation_freeze_tests;

#[cfg(test)]
mod cleanup_tests {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use chrono::{Duration as ChronoDuration, Utc};
    use tokio::sync::{mpsc, oneshot};
    use tunnel_catalog::{
        Catalog, CatalogFixture, FixtureDevice, MembershipRecord, MembershipRole, MemoryCatalog,
        OwnerClaimRequest, OwnerToken, SharedCatalog, TenantRecord, UserRecord,
    };
    use uuid::Uuid;

    use super::{
        AbortOnDropJoinHandle, CLEANUP_QUEUE_CAPACITY, CarrierKey, CleanupDispatcher,
        CleanupWorker, ControlOutbound, DataOutbound, OwnerCleanupItem, QueueBudget, SessionKey,
        TERMINAL_CLEANUP_QUEUE_CAPACITY, TerminalCleanup, TerminalCleanupDispatcher, queue_control,
        queue_data, send_registration,
    };

    fn owner_token(epoch: u64) -> OwnerToken {
        OwnerToken {
            deployment_incarnation: "cleanup-test".into(),
            tenant_id: Uuid::from_u128(1),
            device_id: Uuid::from_u128(2),
            node_id: "node".into(),
            boot_id: "boot".into(),
            session_id: format!("session-{epoch}"),
            epoch,
        }
    }

    fn owner_request(session_id: &str) -> OwnerClaimRequest {
        OwnerClaimRequest {
            deployment_incarnation: "cleanup-test".into(),
            tenant_id: Uuid::from_u128(1),
            device_id: Uuid::from_u128(2),
            node_id: "node".into(),
            boot_id: "boot".into(),
            session_id: session_id.into(),
            lease_expires_at: Utc::now() + ChronoDuration::seconds(30),
        }
    }

    fn session_key(label: &str, epoch: u64) -> SessionKey {
        SessionKey {
            tenant_id: Uuid::from_u128(1),
            device_id: Uuid::from_u128(2),
            session_id: label.to_owned(),
            epoch,
        }
    }

    #[tokio::test]
    async fn dropped_terminal_cleanup_guard_enqueues_exact_identity() {
        let (tx, mut rx) = mpsc::channel(TERMINAL_CLEANUP_QUEUE_CAPACITY);
        let dispatcher = TerminalCleanupDispatcher::new(tx);
        let key = session_key("dropped", 7);
        {
            let _guard = dispatcher.guard(TerminalCleanup::Control(key.clone()));
        }
        assert_eq!(
            rx.recv().await,
            Some(TerminalCleanup::Control(key)),
            "a dropped handler must enqueue terminal cleanup without awaiting"
        );
    }

    #[test]
    fn terminal_cleanup_queue_saturation_sets_fail_closed_signal() {
        let (tx, _rx) = mpsc::channel(TERMINAL_CLEANUP_QUEUE_CAPACITY);
        let dispatcher = TerminalCleanupDispatcher::new(tx);
        for index in 0..TERMINAL_CLEANUP_QUEUE_CAPACITY {
            dispatcher
                .tx
                .try_send(TerminalCleanup::Control(session_key(
                    &format!("queued-{index}"),
                    index as u64,
                )))
                .expect("terminal cleanup queue capacity");
        }
        let started = Instant::now();
        drop(dispatcher.guard(TerminalCleanup::Control(session_key("overflow", 999))));
        assert!(started.elapsed() < Duration::from_millis(100));
        assert!(
            dispatcher
                .overflowed
                .load(std::sync::atomic::Ordering::Acquire)
        );
    }

    #[test]
    fn terminal_cleanup_keeps_stale_carrier_generation_distinct() {
        let key = session_key("generation", 1);
        let stale = CarrierKey {
            session: key.clone(),
            generation: 1,
            connection_id: "old-carrier".to_owned(),
        };
        let successor = CarrierKey {
            session: key,
            generation: 2,
            connection_id: "new-carrier".to_owned(),
        };
        assert_ne!(stale, successor);
        assert_ne!(
            TerminalCleanup::Data(stale.clone()),
            TerminalCleanup::Data(successor),
            "a stale dropped carrier cleanup must retain its generation fence"
        );

        let (tx, mut rx) = mpsc::channel(TERMINAL_CLEANUP_QUEUE_CAPACITY);
        let dispatcher = TerminalCleanupDispatcher::new(tx);
        drop(dispatcher.guard(TerminalCleanup::Data(stale.clone())));
        assert_eq!(
            rx.try_recv().expect("stale cleanup command"),
            TerminalCleanup::Data(stale)
        );
    }

    #[test]
    fn owner_claim_guard_enqueues_exact_token_and_fails_closed_on_overflow() {
        let (tx, mut rx) = mpsc::channel(1);
        let overflowed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dispatcher = CleanupDispatcher {
            tx,
            pending: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            overflowed: overflowed.clone(),
            notify: Arc::new(super::Notify::new()),
        };
        let owner = owner_token(7);
        {
            let mut guard = super::OwnerClaimCleanup::new(dispatcher.clone());
            guard.arm_token(owner.clone());
        }
        assert!(matches!(
            rx.try_recv(),
            Ok(OwnerCleanupItem::Token(actual)) if actual == owner
        ));
        assert!(!overflowed.load(std::sync::atomic::Ordering::Acquire));

        let (tx, _rx) = mpsc::channel(CLEANUP_QUEUE_CAPACITY);
        let dispatcher = CleanupDispatcher {
            tx: tx.clone(),
            pending: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            overflowed: overflowed.clone(),
            notify: Arc::new(super::Notify::new()),
        };
        for index in 0..CLEANUP_QUEUE_CAPACITY {
            tx.try_send(OwnerCleanupItem::Token(owner_token(index as u64)))
                .expect("cleanup queue capacity");
        }
        let mut guard = super::OwnerClaimCleanup::new(dispatcher);
        guard.arm_token(owner_token(999));
        drop(guard);
        assert!(overflowed.load(std::sync::atomic::Ordering::Acquire));
    }

    #[tokio::test]
    async fn dropped_claim_request_guard_releases_matching_owner() {
        let catalog = MemoryCatalog::new();
        catalog
            .seed_fixture(&CatalogFixture {
                tenants: vec![TenantRecord {
                    tenant_id: Uuid::from_u128(1),
                    display_name: "tenant".into(),
                    active: true,
                }],
                users: vec![UserRecord {
                    user_id: Uuid::from_u128(3),
                    display_name: "user".into(),
                }],
                identities: vec![],
                memberships: vec![MembershipRecord {
                    tenant_id: Uuid::from_u128(1),
                    user_id: Uuid::from_u128(3),
                    role: MembershipRole::Member,
                    active: true,
                }],
                devices: vec![FixtureDevice {
                    tenant_id: Uuid::from_u128(1),
                    device_id: Uuid::from_u128(2),
                    owner_user_id: Uuid::from_u128(3),
                    display_name: "device".into(),
                    active: true,
                    last_seen_at: None,
                }],
                credentials: vec![],
                services: vec![],
                grants: vec![],
            })
            .await
            .expect("catalog fixture");
        let request = owner_request("guard-request");
        catalog.claim_owner(&request).await.expect("claim owner");
        let worker = CleanupWorker::spawn(Arc::new(catalog.clone()) as SharedCatalog);
        let dispatcher = worker.dispatcher();
        let mut guard = super::OwnerClaimCleanup::new(dispatcher);
        guard.arm_request(request.clone());
        drop(guard);
        worker.shutdown().await;
        assert!(
            catalog
                .current_owner(request.tenant_id, request.device_id, Utc::now())
                .await
                .expect("current owner")
                .is_none()
        );
    }

    #[tokio::test]
    async fn cleanup_worker_reports_failed_join_as_shutdown_failure() {
        let task = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        task.abort();
        let worker = CleanupWorker {
            dispatcher: None,
            task: Some(AbortOnDropJoinHandle::new(task)),
        };

        assert!(
            !worker
                .shutdown_until(tokio::time::Instant::now() + Duration::from_secs(1))
                .await
        );
    }

    #[tokio::test]
    async fn dropped_outbound_receivers_release_shared_queue_budget() {
        let budget = QueueBudget::new(128);
        let (control_tx, control_rx) = mpsc::channel(1);
        assert!(queue_control(&control_tx, &budget, "control".to_owned()).is_ok());
        assert_eq!(budget.used(), "control".len());
        drop(control_rx);
        assert_eq!(budget.used(), 0);

        let (data_tx, data_rx) = mpsc::channel(1);
        let bytes = vec![0_u8; 17];
        assert!(queue_data(&data_tx, &budget, bytes).is_ok());
        assert_eq!(budget.used(), 17);
        drop(data_rx);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn failed_outbound_enqueue_rolls_back_only_its_new_charge() {
        let budget = QueueBudget::new(128);
        let (control_tx, mut control_rx) = mpsc::channel(1);
        assert!(queue_control(&control_tx, &budget, "held".to_owned()).is_ok());
        assert_eq!(budget.used(), 4);
        assert!(queue_control(&control_tx, &budget, "rejected".to_owned()).is_err());
        assert_eq!(
            budget.used(),
            4,
            "a full queue must retain the charge for its accepted item"
        );
        drop(control_rx.recv().await.expect("held control item"));
        assert_eq!(budget.used(), 0);

        let (data_tx, mut data_rx) = mpsc::channel(1);
        assert!(queue_data(&data_tx, &budget, vec![0; 6]).is_ok());
        assert!(queue_data(&data_tx, &budget, vec![0; 7]).is_err());
        assert_eq!(
            budget.used(),
            6,
            "a full data queue must retain the charge for its accepted item"
        );
        drop(data_rx.recv().await.expect("held data item"));
        assert_eq!(budget.used(), 0);

        let (closed_data_tx, closed_data_rx) = mpsc::channel(1);
        drop(closed_data_rx);
        assert!(queue_data(&closed_data_tx, &budget, vec![0; 7]).is_err());
        assert_eq!(
            budget.used(),
            0,
            "a closed queue must roll back the charge for its rejected item"
        );

        assert!(budget.reserve(3));
        let (closed_control_tx, closed_control_rx) = mpsc::channel(1);
        drop(closed_control_rx);
        assert!(queue_control(&closed_control_tx, &budget, "closed".to_owned()).is_err());
        assert_eq!(
            budget.used(),
            3,
            "a closed queue must preserve unrelated in-flight charges"
        );
        budget.release(3);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn into_parts_keeps_in_flight_charge_until_writer_guard_drops() {
        let budget = QueueBudget::new(128);
        let (control_tx, mut control_rx) = mpsc::channel(1);
        assert!(queue_control(&control_tx, &budget, "control".to_owned()).is_ok());
        let ControlOutbound::Text(text) = control_rx.recv().await.expect("control item") else {
            panic!("expected queued control text");
        };
        let (payload, charge) = text.into_parts();
        assert_eq!(payload, "control");
        assert_eq!(budget.used(), payload.len());
        let writer_guard = (payload, charge);
        assert_eq!(budget.used(), "control".len());
        drop(writer_guard);
        assert_eq!(budget.used(), 0);

        let (data_tx, mut data_rx) = mpsc::channel(1);
        assert!(queue_data(&data_tx, &budget, vec![0; 9]).is_ok());
        let DataOutbound::Binary(bytes) = data_rx.recv().await.expect("data item") else {
            panic!("expected queued data bytes");
        };
        let (payload, charge) = bytes.into_parts();
        assert_eq!(payload.len(), 9);
        assert_eq!(budget.used(), payload.len());
        let writer_guard = (payload, charge);
        drop(writer_guard);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn explicit_queue_release_is_idempotent_when_item_drops() {
        let budget = QueueBudget::new(128);
        let (control_tx, mut control_rx) = mpsc::channel(1);
        assert!(queue_control(&control_tx, &budget, "control".to_owned()).is_ok());
        let ControlOutbound::Text(mut text) = control_rx.recv().await.expect("control item") else {
            panic!("expected queued control text");
        };
        text.release();
        assert_eq!(budget.used(), 0);
        drop(text);
        assert_eq!(budget.used(), 0);

        let (data_tx, mut data_rx) = mpsc::channel(1);
        assert!(queue_data(&data_tx, &budget, vec![0; 9]).is_ok());
        let DataOutbound::Binary(mut bytes) = data_rx.recv().await.expect("data item") else {
            panic!("expected queued data bytes");
        };
        bytes.release();
        assert_eq!(budget.used(), 0);
        drop(bytes);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn dropped_registration_reply_returns_admitted_value_for_reclaim() {
        let (response, receiver) = oneshot::channel();
        drop(receiver);
        assert_eq!(send_registration(response, Ok(17_u64)), Some(17));
    }

    #[tokio::test]
    async fn saturated_cleanup_queue_does_not_stall_the_actor() {
        let (tx, _rx) = mpsc::channel(CLEANUP_QUEUE_CAPACITY);
        let pending = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let dispatcher = CleanupDispatcher {
            tx: tx.clone(),
            pending: pending.clone(),
            overflowed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            notify: Arc::new(super::Notify::new()),
        };
        let worker = CleanupWorker {
            dispatcher: Some(dispatcher),
            task: None,
        };
        let queued_owner = owner_token(1);

        for _ in 0..CLEANUP_QUEUE_CAPACITY {
            pending.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            worker
                .dispatcher
                .as_ref()
                .expect("dispatcher")
                .tx
                .try_send(OwnerCleanupItem::Token(queued_owner.clone()))
                .expect("test queue capacity");
        }

        let started = Instant::now();
        worker.enqueue(owner_token(2));
        assert!(started.elapsed() < Duration::from_millis(100));
        assert_eq!(
            pending.load(std::sync::atomic::Ordering::Acquire),
            CLEANUP_QUEUE_CAPACITY
        );

        worker.shutdown().await;
    }

    #[tokio::test]
    async fn repeated_stale_cleanup_cannot_release_a_successor() {
        let catalog = MemoryCatalog::new();
        catalog
            .seed_fixture(&CatalogFixture {
                tenants: vec![TenantRecord {
                    tenant_id: Uuid::from_u128(1),
                    display_name: "tenant".into(),
                    active: true,
                }],
                users: vec![UserRecord {
                    user_id: Uuid::from_u128(3),
                    display_name: "user".into(),
                }],
                identities: vec![],
                memberships: vec![MembershipRecord {
                    tenant_id: Uuid::from_u128(1),
                    user_id: Uuid::from_u128(3),
                    role: MembershipRole::Member,
                    active: true,
                }],
                devices: vec![FixtureDevice {
                    tenant_id: Uuid::from_u128(1),
                    device_id: Uuid::from_u128(2),
                    owner_user_id: Uuid::from_u128(3),
                    display_name: "device".into(),
                    active: true,
                    last_seen_at: None,
                }],
                credentials: vec![],
                services: vec![],
                grants: vec![],
            })
            .await
            .expect("catalog fixture");
        let first = catalog
            .claim_owner(&owner_request("first"))
            .await
            .expect("first owner");
        assert!(
            catalog
                .release_owner(&first.token)
                .await
                .expect("release first")
        );
        let successor = catalog
            .claim_owner(&owner_request("successor"))
            .await
            .expect("successor owner");

        let shared: SharedCatalog = Arc::new(catalog.clone());
        let worker = CleanupWorker::spawn(shared);
        worker.enqueue(first.token.clone());
        worker.enqueue(first.token);
        worker.shutdown().await;

        let current = catalog
            .current_owner(Uuid::from_u128(1), Uuid::from_u128(2), Utc::now())
            .await
            .expect("current owner")
            .expect("successor remains");
        assert_eq!(current.token, successor.token);
    }
}
