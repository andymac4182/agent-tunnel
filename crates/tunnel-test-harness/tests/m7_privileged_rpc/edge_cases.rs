//! EC064/EC067 additions for the M7 privileged-RPC analogue.
//!
//! This child module is included by `m7_privileged_rpc.rs`.  It reuses that
//! file's real mTLS/HTTP/3 `PeerRuntime` fixture and handler factory; it does
//! not create a second transport or a fake in-memory request path.  The
//! factory passes the fixture's constructed `OwnerToken` and service UUID to
//! each manager, so the edge cases use the same epoch, boot, and session as
//! the parent fixture.
//!
//! EC064 is covered by two real HTTP/3 request streams opened through one
//! pooled `PeerRuntime` destination.  The pool is capped at one connection,
//! so the privileged stream can be admitted while the customer stream is
//! held only if the transport reuses the authenticated connection.  The two
//! requests deliberately use the same application identifier while retaining
//! separate route namespaces.  Customer cancellation is then observed while
//! the privileged stream completes on the same pool.
//!
//! EC067 is covered by the bounded [`WorkerRegistry`].  Worker handles remain
//! registered until an explicit join, request deadlines and fixture shutdown
//! both cancel workers, and a verified application receipt/coverage pair is
//! required before the terminal/archive marker.  HTTP `finish()` is tracked
//! as transport completion only; it is never treated as an application
//! receipt.  The partial path permits an effect before interruption and
//! therefore reports an explicit unknown result with no retry or archive.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use chrono::{Duration as ChronoDuration, Utc};
use http::StatusCode;
use tokio::{
    sync::{Mutex, Notify, oneshot},
    task::JoinHandle,
    time::{sleep_until, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{AuthenticatedConsumer, OwnerClaim, OwnerToken, ValidatedAccessToken};
use tunnel_cluster::{
    envelope::{
        Destination, InternalRequest, InternalRoute, RequestEnvelope, VerifiedPeerIdentity,
    },
    membership::{
        MEMBERSHIP_SCHEMA_VERSION, MembershipCheckpoint, MembershipIssuer, MembershipPolicy,
        MembershipRecord, MembershipVerifier, PrivateEndpointPolicy, RELAY_PEER_ROLE, RelayKey,
        TrustedPublisherKey, VerifiedMembership,
    },
    peer_frame::PeerRecordKind,
};
use tunnel_relay::{
    InboundPeerRequest, PeerIngressHandler, PeerRuntimeError,
    peer_runtime::{InboundPeerRecv, InboundPeerSend},
};

pub(super) const SHARED_APPLICATION_ID: &str = "same-application-id";
pub(super) const SHARED_REQUIRED_SCOPE: &str = "service:read";
const CUSTOMER_ACCEPTED_BODY: &[u8] = b"customer-stream-accepted";
const PRIVILEGED_ACCEPTED_BODY: &[u8] = b"privileged-rpc-accepted";
const PRIVILEGED_TERMINAL_BODY: &[u8] = b"privileged-receipt-covered";
const MAX_ACTIVE_WORKERS: usize = 8;
const WORKER_JOIN_BOUND: Duration = Duration::from_secs(3);

/// The route namespace is part of the operation key.  A customer stream and
/// privileged operation may intentionally share the same application ID, but
/// neither may look up the other's state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum StreamNamespace {
    Customer,
    Privileged,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ScopedOperationKey {
    namespace: StreamNamespace,
    application_id: String,
}

impl ScopedOperationKey {
    fn new(namespace: StreamNamespace, application_id: &str) -> Self {
        Self {
            namespace,
            application_id: application_id.to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerDisposition {
    CompleteAfterReceipt,
    HoldUntilDeadlineOrShutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerExit {
    Completed,
    Deadline,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum ApplicationOutcome {
    Unknown = 1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VerifiedReceipt {
    key: ScopedOperationKey,
    coverage_bytes: usize,
}

struct WorkerEntry {
    handle: JoinHandle<WorkerExit>,
}

/// A bounded registry that retains every spawned task handle until an
/// explicit join.  The registry is deliberately independent from the HTTP/3
/// response lifetime: a partial response cannot drop a worker or silently
/// convert a possible backend effect into success.
#[derive(Clone)]
struct WorkerRegistry {
    entries: Arc<Mutex<BTreeMap<u64, WorkerEntry>>>,
    next_id: Arc<AtomicU64>,
    cancellation: CancellationToken,
    active: Arc<AtomicUsize>,
    effects: Arc<AtomicUsize>,
    receipts: Arc<AtomicUsize>,
    coverage: Arc<AtomicUsize>,
    deadline_cancels: Arc<AtomicUsize>,
    shutdown_cancels: Arc<AtomicUsize>,
    events: Arc<Notify>,
}

struct WorkerTicket {
    id: u64,
    receipt: oneshot::Receiver<VerifiedReceipt>,
}

impl WorkerRegistry {
    fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(BTreeMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            cancellation: CancellationToken::new(),
            active: Arc::new(AtomicUsize::new(0)),
            effects: Arc::new(AtomicUsize::new(0)),
            receipts: Arc::new(AtomicUsize::new(0)),
            coverage: Arc::new(AtomicUsize::new(0)),
            deadline_cancels: Arc::new(AtomicUsize::new(0)),
            shutdown_cancels: Arc::new(AtomicUsize::new(0)),
            events: Arc::new(Notify::new()),
        }
    }

    async fn spawn(
        &self,
        key: ScopedOperationKey,
        coverage_bytes: usize,
        disposition: WorkerDisposition,
        deadline: Instant,
    ) -> Result<WorkerTicket, WorkerRegistryError> {
        let mut entries = self.entries.lock().await;
        // Cancellation is the admission fence.  Check it while retaining the
        // entries lock, before allocating an id or touching any lifecycle
        // counters, so a request arriving after shutdown cannot dispatch a
        // worker that merely exits on the already-cancelled token.
        if self.cancellation.is_cancelled() {
            return Err(WorkerRegistryError::Shutdown);
        }
        if entries.len() >= MAX_ACTIVE_WORKERS {
            return Err(WorkerRegistryError::AtCapacity);
        }
        let id = self.next_id.fetch_add(1, Ordering::AcqRel);
        let (receipt_tx, receipt_rx) = oneshot::channel();
        let cancellation = self.cancellation.clone();
        let active = Arc::clone(&self.active);
        let effects = Arc::clone(&self.effects);
        let receipts = Arc::clone(&self.receipts);
        let coverage = Arc::clone(&self.coverage);
        let deadline_cancels = Arc::clone(&self.deadline_cancels);
        let shutdown_cancels = Arc::clone(&self.shutdown_cancels);
        let events = Arc::clone(&self.events);
        active.fetch_add(1, Ordering::AcqRel);
        let handle = tokio::spawn(async move {
            // The synthetic effect begins at dispatch.  It is intentionally
            // before the response terminal, so partial transport failure can
            // leave effect=1 and application success=0.
            effects.fetch_add(1, Ordering::AcqRel);
            events.notify_one();
            match disposition {
                WorkerDisposition::CompleteAfterReceipt => {
                    let receipt = VerifiedReceipt {
                        key,
                        coverage_bytes,
                    };
                    if receipt_tx.send(receipt).is_ok() {
                        receipts.fetch_add(1, Ordering::AcqRel);
                        coverage.fetch_add(coverage_bytes, Ordering::AcqRel);
                    }
                    active.fetch_sub(1, Ordering::AcqRel);
                    events.notify_one();
                    WorkerExit::Completed
                }
                WorkerDisposition::HoldUntilDeadlineOrShutdown => {
                    tokio::select! {
                        _ = cancellation.cancelled() => {
                            shutdown_cancels.fetch_add(1, Ordering::AcqRel);
                            active.fetch_sub(1, Ordering::AcqRel);
                            events.notify_one();
                            WorkerExit::Shutdown
                        }
                        _ = sleep_until(tokio::time::Instant::from_std(deadline)) => {
                            deadline_cancels.fetch_add(1, Ordering::AcqRel);
                            active.fetch_sub(1, Ordering::AcqRel);
                            events.notify_one();
                            WorkerExit::Deadline
                        }
                    }
                }
            }
        });
        entries.insert(id, WorkerEntry { handle });
        Ok(WorkerTicket {
            id,
            receipt: receipt_rx,
        })
    }

    async fn join(&self, id: u64) -> Result<WorkerExit, WorkerRegistryError> {
        let Some(entry) = self.entries.lock().await.remove(&id) else {
            return Err(WorkerRegistryError::MissingHandle);
        };
        let exit = entry
            .handle
            .await
            .map_err(|_| WorkerRegistryError::JoinFailed)?;
        Ok(exit)
    }

    async fn cancel_and_join(&self, deadline: Instant) -> Result<(), WorkerRegistryError> {
        self.cancellation.cancel();
        let ids = self
            .entries
            .lock()
            .await
            .keys()
            .copied()
            .collect::<Vec<_>>();
        for id in ids {
            let Some(entry) = self.entries.lock().await.remove(&id) else {
                continue;
            };
            let mut handle = entry.handle;
            let joined = timeout_at(tokio::time::Instant::from_std(deadline), &mut handle).await;
            let Ok(joined) = joined else {
                // Preserve the handle for a later bounded drain; dropping a
                // timed-out JoinHandle would violate the retain-and-join
                // contract and could leave an adapter task running.
                self.entries.lock().await.insert(id, WorkerEntry { handle });
                return Err(WorkerRegistryError::JoinTimedOut);
            };
            joined.map_err(|_| WorkerRegistryError::JoinFailed)?;
        }
        Ok(())
    }

    async fn wait_for_empty(&self) {
        while !self.entries.lock().await.is_empty() {
            self.events.notified().await;
        }
    }

    async fn wait_for_effect(&self, expected: usize) {
        timeout_at(
            tokio::time::Instant::now() + super::RESPONSE_TIMEOUT,
            async {
                loop {
                    if self.effects.load(Ordering::Acquire) >= expected && self.active() >= expected
                    {
                        return;
                    }
                    self.events.notified().await;
                }
            },
        )
        .await
        .expect("worker effect did not become active");
    }

    async fn wait_for_deadline_cancel(&self, expected: usize) {
        timeout_at(
            tokio::time::Instant::now() + super::RESPONSE_TIMEOUT,
            async {
                loop {
                    if self.deadline_cancels.load(Ordering::Acquire) >= expected {
                        return;
                    }
                    self.events.notified().await;
                }
            },
        )
        .await
        .expect("worker deadline cancellation did not arrive");
    }

    fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerRegistryError {
    AtCapacity,
    Shutdown,
    MissingHandle,
    JoinFailed,
    JoinTimedOut,
}

/// The synthetic adapter boundary admits only the authenticated peer
/// transport.  Keeping the forbidden alternatives as typed configuration
/// variants makes the negative contract executable without searching source
/// text for strings or pretending that an adapter implementation exists.
#[derive(Clone, Debug, Eq, PartialEq)]
enum SyntheticAdapterConfig {
    PeerMtls {
        owner: OwnerClaim,
        service: uuid::Uuid,
        membership_key_ids: BTreeSet<String>,
    },
    DirectUrl,
    BearerToken,
    SecondAuthority,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SyntheticAdapterBoundaryError {
    DirectUrlFallback,
    BearerTokenFallback,
    SecondAuthority,
    MissingMembershipKey,
    ExpiredOwnerLease,
    MembershipOwnerMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SyntheticAdapterAuthority {
    owner: OwnerClaim,
    service: uuid::Uuid,
    membership_key_ids: BTreeSet<String>,
}

impl TryFrom<SyntheticAdapterConfig> for SyntheticAdapterAuthority {
    type Error = SyntheticAdapterBoundaryError;

    fn try_from(config: SyntheticAdapterConfig) -> Result<Self, Self::Error> {
        match config {
            SyntheticAdapterConfig::PeerMtls {
                owner,
                service,
                membership_key_ids,
            } if !membership_key_ids.is_empty() => Ok(Self {
                owner,
                service,
                membership_key_ids,
            }),
            SyntheticAdapterConfig::PeerMtls { .. } => {
                Err(SyntheticAdapterBoundaryError::MissingMembershipKey)
            }
            SyntheticAdapterConfig::DirectUrl => {
                Err(SyntheticAdapterBoundaryError::DirectUrlFallback)
            }
            SyntheticAdapterConfig::BearerToken => {
                Err(SyntheticAdapterBoundaryError::BearerTokenFallback)
            }
            SyntheticAdapterConfig::SecondAuthority => {
                Err(SyntheticAdapterBoundaryError::SecondAuthority)
            }
        }
    }
}

impl SyntheticAdapterAuthority {
    fn from_verified_membership(
        membership: &VerifiedMembership,
        owner: OwnerClaim,
        service: uuid::Uuid,
        now: chrono::DateTime<Utc>,
    ) -> Result<Self, SyntheticAdapterBoundaryError> {
        if owner.lease_expires_at <= now {
            return Err(SyntheticAdapterBoundaryError::ExpiredOwnerLease);
        }
        let membership_key_ids = membership
            .keys()
            .iter()
            .filter(|key| !key.revoked && key.not_before <= now && key.expires_at > now)
            .map(|key| key.key_id.clone())
            .collect::<BTreeSet<_>>();
        Self::try_from(SyntheticAdapterConfig::PeerMtls {
            owner,
            service,
            membership_key_ids,
        })
    }
}

#[derive(Clone)]
struct SignedAuthorityChange {
    membership: VerifiedMembership,
    owner: OwnerClaim,
}

/// Synthetic manager for the shared customer/privileged pool regression.
/// The manager intentionally accepts both route types through the same
/// production peer handler and keys every record by route namespace.
#[derive(Clone)]
struct ScopedManager {
    authority: Arc<Mutex<SyntheticAdapterAuthority>>,
    registry: WorkerRegistry,
    scoped_operations: Arc<Mutex<BTreeMap<ScopedOperationKey, u64>>>,
    privileged_release: CancellationToken,
    seen_customer: Arc<AtomicUsize>,
    seen_privileged: Arc<AtomicUsize>,
    cross_namespace_rejections: Arc<AtomicUsize>,
    authority_rejections: Arc<AtomicUsize>,
    transport_finishes: Arc<AtomicUsize>,
    terminal_records: Arc<AtomicUsize>,
    archive_markers: Arc<AtomicUsize>,
    application_success_acks: Arc<AtomicUsize>,
    events: Arc<Notify>,
}

impl ScopedManager {
    fn new(owner: OwnerToken, service: uuid::Uuid) -> Self {
        let owner = OwnerClaim {
            token: owner,
            lease_expires_at: Utc::now() + ChronoDuration::seconds(60),
        };
        let authority = SyntheticAdapterAuthority::try_from(SyntheticAdapterConfig::PeerMtls {
            owner,
            service,
            membership_key_ids: BTreeSet::from([format!("{}-key", super::SOURCE_NODE)]),
        })
        .expect("initial synthetic peer authority");
        Self::with_authority(authority)
    }

    fn with_authority(authority: SyntheticAdapterAuthority) -> Self {
        Self {
            authority: Arc::new(Mutex::new(authority)),
            registry: WorkerRegistry::new(),
            scoped_operations: Arc::new(Mutex::new(BTreeMap::new())),
            privileged_release: CancellationToken::new(),
            seen_customer: Arc::new(AtomicUsize::new(0)),
            seen_privileged: Arc::new(AtomicUsize::new(0)),
            cross_namespace_rejections: Arc::new(AtomicUsize::new(0)),
            authority_rejections: Arc::new(AtomicUsize::new(0)),
            transport_finishes: Arc::new(AtomicUsize::new(0)),
            terminal_records: Arc::new(AtomicUsize::new(0)),
            archive_markers: Arc::new(AtomicUsize::new(0)),
            application_success_acks: Arc::new(AtomicUsize::new(0)),
            events: Arc::new(Notify::new()),
        }
    }

    async fn apply_signed_authority_change(
        &self,
        change: SignedAuthorityChange,
    ) -> Result<(), SyntheticAdapterBoundaryError> {
        let now = Utc::now();
        let service = self.authority.lock().await.service;
        let next = SyntheticAdapterAuthority::from_verified_membership(
            &change.membership,
            change.owner,
            service,
            now,
        )?;
        let mut current = self.authority.lock().await;
        if next.owner.token.deployment_incarnation != current.owner.token.deployment_incarnation
            || next.owner.token.tenant_id != current.owner.token.tenant_id
            || next.owner.token.device_id != current.owner.token.device_id
            || next.owner.token.node_id != current.owner.token.node_id
            || next.owner.token.boot_id != current.owner.token.boot_id
            || next.owner.token.epoch <= current.owner.token.epoch
        {
            return Err(SyntheticAdapterBoundaryError::MembershipOwnerMismatch);
        }
        *current = next;
        self.events.notify_one();
        Ok(())
    }

    async fn authority_snapshot(&self) -> SyntheticAdapterAuthority {
        self.authority.lock().await.clone()
    }

    fn classify(&self, envelope: &RequestEnvelope) -> Option<StreamNamespace> {
        match (&envelope.route, &envelope.request) {
            (InternalRoute::ConsumerStreams, InternalRequest::ConsumerStreams(request))
                if request.stream_id == SHARED_APPLICATION_ID
                    && request.required_scope == SHARED_REQUIRED_SCOPE
                    && envelope.operation_id.as_deref() == Some(SHARED_APPLICATION_ID) =>
            {
                Some(StreamNamespace::Customer)
            }
            (InternalRoute::OperationStatus, InternalRequest::OperationStatus(request))
                if request.operation_id == SHARED_APPLICATION_ID
                    && envelope.operation_id.as_deref() == Some(SHARED_APPLICATION_ID) =>
            {
                Some(StreamNamespace::Privileged)
            }
            _ => None,
        }
    }

    fn owner_access(&self, owner: &OwnerToken, now: chrono::DateTime<Utc>) -> ValidatedAccessToken {
        ValidatedAccessToken {
            consumer: AuthenticatedConsumer {
                tenant_id: owner.tenant_id,
                principal_id: uuid::Uuid::from_u128(0x5000_0000_0000_0000_0000_0000_0000_0001),
            },
            issuer: "https://m7.synthetic.invalid".to_owned(),
            subject: "m7-synthetic-customer".to_owned(),
            scopes: std::collections::BTreeSet::from([SHARED_REQUIRED_SCOPE.to_owned()]),
            expires_at: now + chrono::Duration::seconds(30),
        }
    }

    async fn reject(
        &self,
        send: &mut InboundPeerSend,
        recv: &mut InboundPeerRecv,
        status: StatusCode,
    ) -> Result<(), PeerRuntimeError> {
        send.respond(status).await?;
        let _ = send.finish().await;
        recv.cancel();
        Ok(())
    }

    async fn handle_request(&self, request: InboundPeerRequest) -> Result<(), PeerRuntimeError> {
        let request_started = Instant::now();
        let envelope = request.envelope().clone();
        let binding = request.binding().clone();
        let (mut send, mut recv) = request.split();
        let authority = self.authority.lock().await.clone();
        let namespace = self.classify(&envelope);
        let Some(namespace) = namespace else {
            self.cross_namespace_rejections
                .fetch_add(1, Ordering::AcqRel);
            return self
                .reject(&mut send, &mut recv, StatusCode::BAD_REQUEST)
                .await;
        };
        let verified_peer = match VerifiedPeerIdentity::from_verified_peer_binding(&binding) {
            Ok(verified_peer) => verified_peer,
            Err(_) => return Err(PeerRuntimeError::PeerIdentityMismatch),
        };
        let expected = Destination::new(authority.owner.token.clone(), authority.service);
        let owner_access = (namespace == StreamNamespace::Customer)
            .then(|| self.owner_access(&authority.owner.token, Utc::now()));
        let authority_valid = authority.owner.lease_expires_at > Utc::now()
            && authority.membership_key_ids.contains(binding.key_id());
        let validation =
            envelope.validate(Utc::now(), &verified_peer, &expected, owner_access.as_ref());
        if !authority_valid || validation.is_err() {
            self.authority_rejections.fetch_add(1, Ordering::AcqRel);
            self.cross_namespace_rejections
                .fetch_add(1, Ordering::AcqRel);
            return self
                .reject(&mut send, &mut recv, StatusCode::BAD_REQUEST)
                .await;
        }
        let Some(record) = recv.recv_message().await? else {
            return Ok(());
        };
        if record.kind() != PeerRecordKind::ConsumerChunk {
            self.cross_namespace_rejections
                .fetch_add(1, Ordering::AcqRel);
            return self
                .reject(&mut send, &mut recv, StatusCode::BAD_REQUEST)
                .await;
        }
        let deadline =
            request_started + Duration::from_millis(u64::from(envelope.remaining_admission_ms));
        let disposition = match namespace {
            StreamNamespace::Customer => WorkerDisposition::HoldUntilDeadlineOrShutdown,
            StreamNamespace::Privileged => WorkerDisposition::CompleteAfterReceipt,
        };
        let key = ScopedOperationKey::new(namespace, SHARED_APPLICATION_ID);
        {
            let mut scoped_operations = self.scoped_operations.lock().await;
            if scoped_operations.contains_key(&key) {
                self.cross_namespace_rejections
                    .fetch_add(1, Ordering::AcqRel);
                drop(scoped_operations);
                return self
                    .reject(&mut send, &mut recv, StatusCode::BAD_REQUEST)
                    .await;
            }
            // Reserve the scoped key before spawning.  A duplicate request
            // must not cause a backend effect merely to discover a namespace
            // collision after dispatch.
            scoped_operations.insert(key.clone(), u64::MAX);
        }
        let ticket = self
            .registry
            .spawn(key.clone(), record.body_len(), disposition, deadline)
            .await;
        let ticket = match ticket {
            Ok(ticket) => ticket,
            Err(_) => {
                self.scoped_operations.lock().await.remove(&key);
                return Err(PeerRuntimeError::Closed);
            }
        };
        self.scoped_operations.lock().await.insert(key, ticket.id);
        match namespace {
            StreamNamespace::Customer => {
                self.seen_customer.fetch_add(1, Ordering::AcqRel);
            }
            StreamNamespace::Privileged => {
                self.seen_privileged.fetch_add(1, Ordering::AcqRel);
            }
        }
        self.events.notify_one();

        send.respond(StatusCode::OK).await?;
        let accepted = match namespace {
            StreamNamespace::Customer => CUSTOMER_ACCEPTED_BODY,
            StreamNamespace::Privileged => PRIVILEGED_ACCEPTED_BODY,
        };
        send.send_message(PeerRecordKind::ConsumerChunk, accepted)
            .await?;
        if namespace == StreamNamespace::Customer {
            // Keep this stream admitted but incomplete while the privileged
            // operation uses the same pooled connection.  Cancellation is
            // classified separately from privileged completion.
            let _ = ticket;
            return Ok(());
        }

        let WorkerTicket { id, receipt } = ticket;
        let result = async {
            // Keep the privileged stream in-flight until the test explicitly
            // releases it.  This makes customer cancellation concurrent with
            // the privileged operation rather than a post-completion check.
            self.privileged_release.cancelled().await;
            let receipt = receipt.await.map_err(|_| PeerRuntimeError::Closed)?;
            let expected_key =
                ScopedOperationKey::new(StreamNamespace::Privileged, SHARED_APPLICATION_ID);
            if receipt.key != expected_key || receipt.coverage_bytes != record.body_len() {
                return Err(PeerRuntimeError::Closed);
            }
            send.send_message(
                PeerRecordKind::CompleteControlText,
                PRIVILEGED_TERMINAL_BODY,
            )
            .await?;
            self.terminal_records.fetch_add(1, Ordering::AcqRel);
            self.archive_markers.fetch_add(1, Ordering::AcqRel);
            let result = send.finish().await;
            if result.is_ok() {
                self.transport_finishes.fetch_add(1, Ordering::AcqRel);
            }
            result
        }
        .await;
        let join_result = self.registry.join(id).await;
        if join_result.is_err() {
            return Err(PeerRuntimeError::Closed);
        }
        result
    }

    /// The consumer confirms application success only after it has validated
    /// the accepted record, the explicit terminal record, and end-of-stream.
    /// A server `finish()` is transport completion and cannot call this.
    fn confirm_application_success(&self) {
        self.application_success_acks.fetch_add(1, Ordering::AcqRel);
    }

    fn release_privileged(&self) {
        self.privileged_release.cancel();
    }

    async fn shutdown_workers(&self, deadline: Instant) -> Result<(), WorkerRegistryError> {
        self.registry.cancel_and_join(deadline).await
    }
}

impl PeerIngressHandler for ScopedManager {
    fn handle(
        &self,
        request: InboundPeerRequest,
    ) -> tunnel_relay::peer_runtime::PeerIngressHandlerFuture {
        let manager = self.clone();
        Box::pin(async move { manager.handle_request(request).await })
    }
}

/// The first request deliberately ends after its accepted record.  The next
/// request receives that pending terminal marker, tagged with the first
/// request id, so the caller must reject it as a late terminal from another
/// operation rather than treating it as its own completion.
#[derive(Clone)]
struct LateTerminalManager {
    expected_owner: OwnerToken,
    expected_service: uuid::Uuid,
    pending_request_id: Arc<Mutex<Option<String>>>,
    dispatches: Arc<AtomicUsize>,
    terminal_attempts: Arc<AtomicUsize>,
}

impl LateTerminalManager {
    fn new(owner: OwnerToken, service: uuid::Uuid) -> Self {
        Self {
            expected_owner: owner,
            expected_service: service,
            pending_request_id: Arc::new(Mutex::new(None)),
            dispatches: Arc::new(AtomicUsize::new(0)),
            terminal_attempts: Arc::new(AtomicUsize::new(0)),
        }
    }

    async fn handle_request(&self, request: InboundPeerRequest) -> Result<(), PeerRuntimeError> {
        let envelope = request.envelope().clone();
        let binding = request.binding().clone();
        let request_id = envelope.request_id.clone();
        let (mut send, mut recv) = request.split();
        let verified_peer = VerifiedPeerIdentity::from_verified_peer_binding(&binding)
            .map_err(|_| PeerRuntimeError::PeerIdentityMismatch)?;
        let expected = Destination::new(self.expected_owner.clone(), self.expected_service);
        if envelope
            .validate(Utc::now(), &verified_peer, &expected, None)
            .is_err()
        {
            send.respond(StatusCode::BAD_REQUEST).await?;
            let _ = send.finish().await;
            recv.cancel();
            return Ok(());
        }
        let Some(record) = recv.recv_message().await? else {
            return Ok(());
        };
        if record.kind() != PeerRecordKind::ConsumerChunk {
            send.respond(StatusCode::BAD_REQUEST).await?;
            let _ = send.finish().await;
            recv.cancel();
            return Ok(());
        }

        self.dispatches.fetch_add(1, Ordering::AcqRel);
        let late_request_id = {
            let mut pending = self.pending_request_id.lock().await;
            let previous = pending.take();
            if previous.is_none() {
                *pending = Some(request_id);
            }
            previous
        };

        send.respond(StatusCode::OK).await?;
        send.send_message(PeerRecordKind::ConsumerChunk, b"late-terminal-accepted")
            .await?;
        if let Some(late_request_id) = late_request_id {
            self.terminal_attempts.fetch_add(1, Ordering::AcqRel);
            let body = format!("terminal:{late_request_id}");
            send.send_message(PeerRecordKind::CompleteControlText, body.as_bytes())
                .await?;
        }
        let result = send.finish().await;
        recv.cancel();
        result
    }
}

impl PeerIngressHandler for LateTerminalManager {
    fn handle(
        &self,
        request: InboundPeerRequest,
    ) -> tunnel_relay::peer_runtime::PeerIngressHandlerFuture {
        let manager = self.clone();
        Box::pin(async move { manager.handle_request(request).await })
    }
}

/// Worker manager for the EC067 partial-response analogue.  It is kept
/// separate from [`ScopedManager`] so the customer/privileged namespace test
/// cannot accidentally become the worker lifecycle proof.
#[derive(Clone)]
struct PartialWorkerManager {
    expected_owner: OwnerToken,
    expected_service: uuid::Uuid,
    registry: WorkerRegistry,
    shutdown_rejections: Arc<AtomicUsize>,
    effects_unknown: Arc<AtomicUsize>,
    outcome: Arc<AtomicU8>,
    application_success: Arc<AtomicUsize>,
    terminal_records: Arc<AtomicUsize>,
    archive_markers: Arc<AtomicUsize>,
    transport_finishes: Arc<AtomicUsize>,
    events: Arc<Notify>,
}

impl PartialWorkerManager {
    fn new(owner: OwnerToken, service: uuid::Uuid) -> Self {
        Self {
            expected_owner: owner,
            expected_service: service,
            registry: WorkerRegistry::new(),
            shutdown_rejections: Arc::new(AtomicUsize::new(0)),
            effects_unknown: Arc::new(AtomicUsize::new(0)),
            outcome: Arc::new(AtomicU8::new(0)),
            application_success: Arc::new(AtomicUsize::new(0)),
            terminal_records: Arc::new(AtomicUsize::new(0)),
            archive_markers: Arc::new(AtomicUsize::new(0)),
            transport_finishes: Arc::new(AtomicUsize::new(0)),
            events: Arc::new(Notify::new()),
        }
    }

    async fn handle_request(&self, request: InboundPeerRequest) -> Result<(), PeerRuntimeError> {
        let request_started = Instant::now();
        let envelope = request.envelope().clone();
        let binding = request.binding().clone();
        let (mut send, mut recv) = request.split();
        let privileged_request = matches!(
            (&envelope.route, &envelope.request),
            (
                InternalRoute::OperationStatus,
                InternalRequest::OperationStatus(operation)
            ) if operation.operation_id == SHARED_APPLICATION_ID
                && envelope.operation_id.as_deref() == Some(SHARED_APPLICATION_ID)
        );
        if !privileged_request {
            return Err(PeerRuntimeError::PeerIdentityMismatch);
        }
        let verified_peer = VerifiedPeerIdentity::from_verified_peer_binding(&binding)
            .map_err(|_| PeerRuntimeError::PeerIdentityMismatch)?;
        let expected = Destination::new(self.expected_owner.clone(), self.expected_service);
        if envelope
            .validate(Utc::now(), &verified_peer, &expected, None)
            .is_err()
        {
            return Err(PeerRuntimeError::PeerIdentityMismatch);
        }
        let Some(record) = recv.recv_message().await? else {
            return Ok(());
        };
        if record.kind() != PeerRecordKind::ConsumerChunk {
            return Err(PeerRuntimeError::Closed);
        }
        let key = ScopedOperationKey::new(StreamNamespace::Privileged, SHARED_APPLICATION_ID);
        let deadline =
            request_started + Duration::from_millis(u64::from(envelope.remaining_admission_ms));
        let ticket = match self
            .registry
            .spawn(
                key,
                record.body_len(),
                WorkerDisposition::HoldUntilDeadlineOrShutdown,
                deadline,
            )
            .await
        {
            Ok(ticket) => ticket,
            Err(WorkerRegistryError::Shutdown) => {
                // Preserve the typed local classification while the peer
                // boundary remains a bounded closed stream.
                self.shutdown_rejections.fetch_add(1, Ordering::AcqRel);
                self.events.notify_one();
                return Err(PeerRuntimeError::Closed);
            }
            Err(_) => return Err(PeerRuntimeError::Closed),
        };
        send.respond(StatusCode::OK).await?;
        send.send_message(PeerRecordKind::ConsumerChunk, PRIVILEGED_ACCEPTED_BODY)
            .await?;
        // The worker may already have caused an external effect.  The
        // response is deliberately incomplete and the handle remains in the
        // registry for the fixture's explicit cancel+join phase.
        self.effects_unknown.fetch_add(1, Ordering::AcqRel);
        self.outcome
            .store(ApplicationOutcome::Unknown as u8, Ordering::Release);
        self.events.notify_one();
        let _ = ticket;
        Ok(())
    }

    async fn shutdown_workers(&self, deadline: Instant) -> Result<(), WorkerRegistryError> {
        self.registry.cancel_and_join(deadline).await
    }
}

impl PeerIngressHandler for PartialWorkerManager {
    fn handle(
        &self,
        request: InboundPeerRequest,
    ) -> tunnel_relay::peer_runtime::PeerIngressHandlerFuture {
        let manager = self.clone();
        Box::pin(async move { manager.handle_request(request).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_authority_change(
        binding: &tunnel_cluster::membership::VerifiedPeerBinding,
        old_owner: &OwnerClaim,
    ) -> SignedAuthorityChange {
        let now = Utc::now();
        let endpoint = binding
            .peer_endpoint()
            .parse::<SocketAddr>()
            .expect("synthetic peer endpoint");
        let endpoint_policy =
            PrivateEndpointPolicy::allowlisted(["127.0.0.1"], ["localhost"], [endpoint.port()])
                .expect("synthetic endpoint policy");
        let policy = MembershipPolicy::new(
            super::super::DEPLOYMENT_ID,
            super::super::DEPLOYMENT_INCARNATION,
            endpoint_policy,
        )
        .expect("synthetic membership policy");
        let (issuer, _) = MembershipIssuer::generate("m7-rpc-rotation-publisher")
            .expect("synthetic membership issuer");
        let trusted = TrustedPublisherKey::new(
            issuer.key_id(),
            issuer.public_key().expect("synthetic issuer key"),
        )
        .expect("synthetic trusted publisher key");
        let mut verifier =
            MembershipVerifier::new(policy, [trusted]).expect("synthetic membership verifier");
        let checkpoint = MembershipCheckpoint {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            deployment_id: super::super::DEPLOYMENT_ID.to_owned(),
            deployment_incarnation: super::super::DEPLOYMENT_INCARNATION.to_owned(),
            checkpoint_version: 1,
            nonce: "m7-rpc-rotation-nonce".to_owned(),
            minimum_versions: BTreeMap::from([(binding.node_id().to_owned(), 1)]),
            issued_at: now - ChronoDuration::seconds(1),
            not_before: now - ChronoDuration::seconds(1),
            expires_at: now + ChronoDuration::seconds(30),
        };
        let checkpoint_bytes = issuer
            .sign_checkpoint_bytes(checkpoint)
            .expect("signed synthetic checkpoint");
        verifier
            .verify_checkpoint(&checkpoint_bytes, "m7-rpc-rotation-nonce", now)
            .expect("verified synthetic checkpoint");

        let replacement_key_id = format!("{}-next", binding.key_id());
        let membership = MembershipRecord {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            deployment_id: super::super::DEPLOYMENT_ID.to_owned(),
            deployment_incarnation: super::super::DEPLOYMENT_INCARNATION.to_owned(),
            node_id: binding.node_id().to_owned(),
            record_version: 2,
            roles: vec![RELAY_PEER_ROLE.to_owned()],
            peer_endpoint: binding.peer_endpoint().to_owned(),
            server_name: binding.server_name().to_owned(),
            keys: vec![
                RelayKey {
                    key_id: binding.key_id().to_owned(),
                    spki_sha256: binding.spki_sha256().to_owned(),
                    not_before: now - ChronoDuration::seconds(1),
                    expires_at: now + ChronoDuration::seconds(30),
                    revoked: false,
                },
                RelayKey {
                    key_id: replacement_key_id.clone(),
                    spki_sha256: binding.spki_sha256().to_owned(),
                    not_before: now,
                    expires_at: now + ChronoDuration::seconds(30),
                    revoked: false,
                },
            ],
            issued_at: now - ChronoDuration::seconds(1),
            not_before: now - ChronoDuration::seconds(1),
            expires_at: now + ChronoDuration::seconds(30),
        };
        let membership_bytes = issuer
            .sign_membership_bytes(membership)
            .expect("signed synthetic membership replacement");
        let verified_membership = verifier
            .verify_membership(&membership_bytes, now)
            .expect("verified synthetic membership replacement");
        let rebound = verified_membership
            .bind_peer(
                binding.node_id(),
                binding.boot_id(),
                binding.spki_sha256(),
                now,
            )
            .expect("replacement key must bind to the same mTLS identity");
        // During overlap the verifier walks the signed key list in order and
        // retains the still-valid predecessor for this certificate.  The
        // explicit removal phase below proves successor selection after the
        // predecessor is revoked.
        assert_eq!(rebound.key_id(), binding.key_id());
        assert!(
            verified_membership
                .keys()
                .iter()
                .any(|key| key.key_id == replacement_key_id && !key.revoked)
        );

        let mut owner_token = old_owner.token.clone();
        owner_token.epoch += 1;
        owner_token.session_id = "m7-rpc-owner-session-replacement".to_owned();
        SignedAuthorityChange {
            membership: verified_membership,
            owner: OwnerClaim {
                token: owner_token,
                lease_expires_at: old_owner.lease_expires_at + ChronoDuration::seconds(30),
            },
        }
    }

    fn signed_authority_key_removal(
        binding: &tunnel_cluster::membership::VerifiedPeerBinding,
        old_owner: &OwnerClaim,
    ) -> SignedAuthorityChange {
        let now = Utc::now();
        let endpoint = binding
            .peer_endpoint()
            .parse::<SocketAddr>()
            .expect("synthetic peer endpoint");
        let endpoint_policy =
            PrivateEndpointPolicy::allowlisted(["127.0.0.1"], ["localhost"], [endpoint.port()])
                .expect("synthetic endpoint policy");
        let policy = MembershipPolicy::new(
            super::super::DEPLOYMENT_ID,
            super::super::DEPLOYMENT_INCARNATION,
            endpoint_policy,
        )
        .expect("synthetic membership policy");
        let (issuer, _) = MembershipIssuer::generate("m7-rpc-removal-publisher")
            .expect("synthetic membership issuer");
        let trusted = TrustedPublisherKey::new(
            issuer.key_id(),
            issuer.public_key().expect("synthetic issuer key"),
        )
        .expect("synthetic trusted publisher key");
        let mut verifier =
            MembershipVerifier::new(policy, [trusted]).expect("synthetic membership verifier");
        let checkpoint = MembershipCheckpoint {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            deployment_id: super::super::DEPLOYMENT_ID.to_owned(),
            deployment_incarnation: super::super::DEPLOYMENT_INCARNATION.to_owned(),
            checkpoint_version: 1,
            nonce: "m7-rpc-removal-nonce".to_owned(),
            minimum_versions: BTreeMap::from([(binding.node_id().to_owned(), 1)]),
            issued_at: now - ChronoDuration::seconds(1),
            not_before: now - ChronoDuration::seconds(1),
            expires_at: now + ChronoDuration::seconds(30),
        };
        let checkpoint_bytes = issuer
            .sign_checkpoint_bytes(checkpoint)
            .expect("signed removal checkpoint");
        verifier
            .verify_checkpoint(&checkpoint_bytes, "m7-rpc-removal-nonce", now)
            .expect("verified removal checkpoint");

        let replacement_key_id = format!("{}-next", binding.key_id());
        let membership = MembershipRecord {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            deployment_id: super::super::DEPLOYMENT_ID.to_owned(),
            deployment_incarnation: super::super::DEPLOYMENT_INCARNATION.to_owned(),
            node_id: binding.node_id().to_owned(),
            record_version: 3,
            roles: vec![RELAY_PEER_ROLE.to_owned()],
            peer_endpoint: binding.peer_endpoint().to_owned(),
            server_name: binding.server_name().to_owned(),
            keys: vec![
                RelayKey {
                    key_id: binding.key_id().to_owned(),
                    spki_sha256: binding.spki_sha256().to_owned(),
                    not_before: now - ChronoDuration::seconds(1),
                    expires_at: now + ChronoDuration::seconds(30),
                    revoked: true,
                },
                RelayKey {
                    key_id: replacement_key_id.clone(),
                    spki_sha256: binding.spki_sha256().to_owned(),
                    not_before: now - ChronoDuration::seconds(1),
                    expires_at: now + ChronoDuration::seconds(30),
                    revoked: false,
                },
            ],
            issued_at: now - ChronoDuration::seconds(1),
            not_before: now - ChronoDuration::seconds(1),
            expires_at: now + ChronoDuration::seconds(30),
        };
        let membership_bytes = issuer
            .sign_membership_bytes(membership)
            .expect("signed membership key removal");
        let verified_membership = verifier
            .verify_membership(&membership_bytes, now)
            .expect("verified membership key removal");
        let rebound = verified_membership
            .bind_peer(
                binding.node_id(),
                binding.boot_id(),
                binding.spki_sha256(),
                now,
            )
            .expect("successor key must bind after predecessor removal");
        assert_eq!(rebound.key_id(), replacement_key_id);

        let mut owner_token = old_owner.token.clone();
        owner_token.epoch += 1;
        owner_token.session_id = "m7-rpc-owner-session-key-removal".to_owned();
        SignedAuthorityChange {
            membership: verified_membership,
            owner: OwnerClaim {
                token: owner_token,
                lease_expires_at: old_owner.lease_expires_at + ChronoDuration::seconds(60),
            },
        }
    }

    #[test]
    fn synthetic_adapter_boundary_rejects_direct_authority_fallbacks_with_typed_errors() {
        let owner = OwnerClaim {
            token: OwnerToken {
                deployment_incarnation: super::super::DEPLOYMENT_INCARNATION.to_owned(),
                tenant_id: super::super::tenant_id(),
                device_id: super::super::device_id(),
                node_id: super::super::DESTINATION_NODE.to_owned(),
                boot_id: super::super::DESTINATION_BOOT.to_owned(),
                session_id: "m7-rpc-boundary-session".to_owned(),
                epoch: 1,
            },
            lease_expires_at: Utc::now() + ChronoDuration::seconds(30),
        };
        let cases = [
            (
                SyntheticAdapterConfig::DirectUrl,
                SyntheticAdapterBoundaryError::DirectUrlFallback,
            ),
            (
                SyntheticAdapterConfig::BearerToken,
                SyntheticAdapterBoundaryError::BearerTokenFallback,
            ),
            (
                SyntheticAdapterConfig::SecondAuthority,
                SyntheticAdapterBoundaryError::SecondAuthority,
            ),
        ];
        for (config, expected) in cases {
            assert_eq!(SyntheticAdapterAuthority::try_from(config), Err(expected));
        }

        let authority = SyntheticAdapterAuthority::try_from(SyntheticAdapterConfig::PeerMtls {
            owner: owner.clone(),
            service: super::super::service_id(),
            membership_key_ids: BTreeSet::from(["peer-key".to_owned()]),
        })
        .expect("peer mTLS is the only accepted synthetic authority");
        assert_eq!(authority.owner, owner);
        assert_eq!(authority.membership_key_ids.len(), 1);
    }

    #[tokio::test]
    async fn privileged_rpc_shared_pool_survives_signed_key_lease_owner_change_and_rejects_stale_dispatch()
     {
        let fixture = super::super::start_rpc_fixture_with_handler(
            |owner, service| Arc::new(ScopedManager::new(owner, service)),
            super::super::shared_pool_limits(),
        )
        .await;
        let manager = Arc::clone(&fixture.manager);
        let mut customer = super::super::sent_exchange(
            &fixture.runtime,
            &fixture.route,
            fixture.customer_envelope(),
            b"customer-before-owner-replacement",
        )
        .await
        .expect("customer stream on the shared pool");
        let customer_ack = customer
            .recv_message()
            .await
            .expect("customer response")
            .expect("customer accepted record");
        assert_eq!(customer_ack.body(), CUSTOMER_ACCEPTED_BODY);
        manager.registry.wait_for_effect(1).await;
        assert_eq!(manager.seen_customer.load(Ordering::Acquire), 1);
        assert_eq!(manager.registry.active(), 1);

        let binding = fixture.source_binding.clone();
        let change = signed_authority_change(&binding, &fixture.owner);
        let replacement_owner = change.owner.clone();
        manager
            .apply_signed_authority_change(change)
            .await
            .expect("signed key, lease, and owner replacement");
        let authority = manager.authority_snapshot().await;
        assert_eq!(authority.owner.token, replacement_owner.token);
        assert!(authority.owner.lease_expires_at > fixture.owner.lease_expires_at);
        assert_eq!(authority.membership_key_ids.len(), 2);

        // The old route is still able to reach the same pooled H3 connection,
        // but its owner epoch is stale.  The manager must reject it before
        // reading the body or creating a privileged worker.
        super::super::rejected_exchange(
            &fixture.runtime,
            &fixture.route,
            fixture.privileged_envelope(),
            b"stale-owner-after-signed-replacement",
        )
        .await;
        assert_eq!(manager.authority_rejections.load(Ordering::Acquire), 1);
        assert_eq!(manager.seen_privileged.load(Ordering::Acquire), 0);
        assert_eq!(manager.registry.effects.load(Ordering::Acquire), 1);
        assert_eq!(manager.registry.active(), 1);

        // The successor owner can reuse the same pooled connection while the
        // old customer stream remains admitted.  The overlap is deliberate:
        // the signed membership record carries both key ids during rotation.
        let successor_route = super::super::OwnerRoute::Remote {
            owner: replacement_owner.clone(),
            peer: Some(
                fixture
                    .route
                    .peer_binding()
                    .expect("successor peer binding")
                    .clone(),
            ),
        };
        let successor_envelope = super::super::operation_envelope(
            fixture.runtime.source().clone(),
            replacement_owner.token.clone(),
            fixture.service,
            SHARED_APPLICATION_ID,
        );
        let mut privileged = super::super::sent_exchange(
            &fixture.runtime,
            &successor_route,
            successor_envelope,
            b"privileged-after-signed-replacement",
        )
        .await
        .expect("successor privileged stream on the shared pool");
        let privileged_ack = privileged
            .recv_message()
            .await
            .expect("successor privileged response")
            .expect("successor privileged accepted record");
        assert_eq!(privileged_ack.body(), PRIVILEGED_ACCEPTED_BODY);
        manager.release_privileged();
        let privileged_terminal = privileged
            .recv_message()
            .await
            .expect("successor privileged terminal response")
            .expect("successor privileged terminal record");
        assert_eq!(
            privileged_terminal.kind(),
            PeerRecordKind::CompleteControlText
        );
        assert_eq!(privileged_terminal.body(), PRIVILEGED_TERMINAL_BODY);
        assert!(
            privileged
                .recv_message()
                .await
                .expect("successor privileged end")
                .is_none()
        );
        assert_eq!(manager.seen_customer.load(Ordering::Acquire), 1);
        assert_eq!(manager.seen_privileged.load(Ordering::Acquire), 1);
        assert_eq!(manager.registry.effects.load(Ordering::Acquire), 2);
        assert_eq!(manager.registry.receipts.load(Ordering::Acquire), 1);
        assert_eq!(manager.registry.active(), 1);

        // Complete the signed key transition by revoking the predecessor.
        // The membership verifier must now select the successor key for the
        // same certificate, and the old pooled source binding must fail
        // closed before a second privileged worker can be created.
        let removal = signed_authority_key_removal(&binding, &replacement_owner);
        let removal_owner = removal.owner.clone();
        manager
            .apply_signed_authority_change(removal)
            .await
            .expect("signed predecessor-key removal");
        let authority = manager.authority_snapshot().await;
        assert_eq!(authority.owner.token, removal_owner.token);
        assert_eq!(authority.membership_key_ids.len(), 1);
        assert!(
            authority
                .membership_key_ids
                .contains(&format!("{}-next", binding.key_id()))
        );
        let removal_route = super::super::OwnerRoute::Remote {
            owner: removal_owner.clone(),
            peer: Some(
                fixture
                    .route
                    .peer_binding()
                    .expect("removed-key peer binding")
                    .clone(),
            ),
        };
        let removal_envelope = super::super::operation_envelope(
            fixture.runtime.source().clone(),
            removal_owner.token,
            fixture.service,
            SHARED_APPLICATION_ID,
        );
        super::super::rejected_exchange(
            &fixture.runtime,
            &removal_route,
            removal_envelope,
            b"predecessor-key-after-removal",
        )
        .await;
        assert_eq!(manager.authority_rejections.load(Ordering::Acquire), 2);
        assert_eq!(manager.seen_privileged.load(Ordering::Acquire), 1);
        assert_eq!(manager.registry.effects.load(Ordering::Acquire), 2);
        assert_eq!(manager.registry.active(), 1);

        customer.cancel();
        manager
            .shutdown_workers(Instant::now() + WORKER_JOIN_BOUND)
            .await
            .expect("customer worker cancel+join after successor dispatch");
        assert_eq!(manager.registry.shutdown_cancels.load(Ordering::Acquire), 1);
        assert_eq!(manager.registry.active(), 0);
        super::super::shutdown_rpc_fixture(fixture).await;
    }

    #[tokio::test]
    async fn privileged_rpc_late_terminal_is_correlated_to_exact_request_id() {
        let fixture = super::super::start_rpc_fixture_with_handler(
            |owner, service| Arc::new(LateTerminalManager::new(owner, service)),
            super::super::shared_pool_limits(),
        )
        .await;
        let manager = Arc::clone(&fixture.manager);

        let mut first_envelope = super::super::operation_envelope(
            fixture.runtime.source().clone(),
            fixture.owner.token.clone(),
            fixture.service,
            SHARED_APPLICATION_ID,
        );
        first_envelope.request_id = "m7-rpc-late-terminal-first".to_owned();
        let mut first = super::super::sent_exchange(
            &fixture.runtime,
            &fixture.route,
            first_envelope,
            b"first-partial-request",
        )
        .await
        .expect("first partial request");
        let first_accepted = first
            .recv_message()
            .await
            .expect("first accepted response")
            .expect("first accepted record");
        assert_eq!(first_accepted.body(), b"late-terminal-accepted");
        assert!(
            first
                .recv_message()
                .await
                .expect("first partial end")
                .is_none()
        );

        let mut second_envelope = super::super::operation_envelope(
            fixture.runtime.source().clone(),
            fixture.owner.token.clone(),
            fixture.service,
            SHARED_APPLICATION_ID,
        );
        second_envelope.request_id = "m7-rpc-late-terminal-second".to_owned();
        let mut second = super::super::sent_exchange(
            &fixture.runtime,
            &fixture.route,
            second_envelope,
            b"second-request-after-late-terminal",
        )
        .await
        .expect("second request after partial response");
        let second_accepted = second
            .recv_message()
            .await
            .expect("second accepted response")
            .expect("second accepted record");
        assert_eq!(second_accepted.body(), b"late-terminal-accepted");
        let late_terminal = second
            .recv_message()
            .await
            .expect("late terminal response")
            .expect("late terminal record");
        assert_eq!(late_terminal.kind(), PeerRecordKind::CompleteControlText);
        assert_eq!(late_terminal.body(), b"terminal:m7-rpc-late-terminal-first");
        assert_ne!(
            late_terminal.body(),
            b"terminal:m7-rpc-late-terminal-second",
            "a terminal from the prior operation cannot acknowledge this request"
        );
        assert!(
            second
                .recv_message()
                .await
                .expect("second response end")
                .is_none()
        );
        assert_eq!(manager.dispatches.load(Ordering::Acquire), 2);
        assert_eq!(manager.terminal_attempts.load(Ordering::Acquire), 1);
        super::super::shutdown_rpc_fixture(fixture).await;
    }

    #[tokio::test]
    async fn privileged_rpc_shared_pool_scopes_colliding_customer_and_privileged_ids() {
        let fixture = super::super::start_rpc_fixture_with_handler(
            |owner, service| Arc::new(ScopedManager::new(owner, service)),
            super::super::shared_pool_limits(),
        )
        .await;
        let manager = Arc::clone(&fixture.manager);
        let mut customer = super::super::sent_exchange(
            &fixture.runtime,
            &fixture.route,
            fixture.customer_envelope(),
            b"customer-body",
        )
        .await
        .expect("customer stream on the shared pool");
        let customer_ack = customer
            .recv_message()
            .await
            .expect("customer response")
            .expect("customer accepted record");
        assert_eq!(customer_ack.body(), CUSTOMER_ACCEPTED_BODY);

        let mut privileged = super::super::sent_exchange(
            &fixture.runtime,
            &fixture.route,
            fixture.privileged_envelope(),
            b"privileged-body",
        )
        .await
        .expect("privileged stream must reuse the one pooled H3 connection");
        let privileged_ack = privileged
            .recv_message()
            .await
            .expect("privileged response")
            .expect("privileged accepted record");
        assert_eq!(privileged_ack.body(), PRIVILEGED_ACCEPTED_BODY);
        customer.cancel();
        manager.release_privileged();
        let privileged_terminal = privileged
            .recv_message()
            .await
            .expect("privileged terminal response")
            .expect("privileged terminal record");
        assert_eq!(
            privileged_terminal.kind(),
            PeerRecordKind::CompleteControlText
        );
        assert_eq!(privileged_terminal.body(), PRIVILEGED_TERMINAL_BODY);
        assert!(
            privileged
                .recv_message()
                .await
                .expect("privileged end")
                .is_none()
        );

        manager
            .shutdown_workers(Instant::now() + WORKER_JOIN_BOUND)
            .await
            .expect("customer worker cancel+join");
        assert_eq!(manager.seen_customer.load(Ordering::Acquire), 1);
        assert_eq!(manager.seen_privileged.load(Ordering::Acquire), 1);
        assert_eq!(
            manager.cross_namespace_rejections.load(Ordering::Acquire),
            0
        );
        let scoped_operations = manager.scoped_operations.lock().await;
        assert_eq!(scoped_operations.len(), 2);
        assert!(scoped_operations.contains_key(&ScopedOperationKey::new(
            StreamNamespace::Customer,
            SHARED_APPLICATION_ID,
        )));
        assert!(scoped_operations.contains_key(&ScopedOperationKey::new(
            StreamNamespace::Privileged,
            SHARED_APPLICATION_ID,
        )));
        drop(scoped_operations);
        assert_eq!(manager.registry.effects.load(Ordering::Acquire), 2);
        assert_eq!(manager.registry.receipts.load(Ordering::Acquire), 1);
        assert_eq!(
            manager.registry.coverage.load(Ordering::Acquire),
            b"privileged-body".len()
        );
        assert_eq!(manager.terminal_records.load(Ordering::Acquire), 1);
        assert_eq!(manager.archive_markers.load(Ordering::Acquire), 1);
        manager.confirm_application_success();
        assert_eq!(manager.application_success_acks.load(Ordering::Acquire), 1);
        assert_eq!(manager.transport_finishes.load(Ordering::Acquire), 1);
        assert_eq!(manager.registry.shutdown_cancels.load(Ordering::Acquire), 1);
        assert_eq!(manager.registry.active(), 0);
        manager.registry.wait_for_empty().await;
        super::super::shutdown_rpc_fixture(fixture).await;
    }

    #[tokio::test]
    async fn privileged_rpc_partial_worker_deadline_cancels_and_joins_without_archive() {
        let fixture = super::super::start_rpc_fixture_with_handler(
            |owner, service| Arc::new(PartialWorkerManager::new(owner, service)),
            super::super::shared_pool_limits(),
        )
        .await;
        let manager = Arc::clone(&fixture.manager);
        let mut response = super::super::sent_exchange(
            &fixture.runtime,
            &fixture.route,
            fixture.privileged_envelope_with_deadline(50),
            b"partial-worker-body",
        )
        .await
        .expect("partial worker request");
        let accepted = response
            .recv_message()
            .await
            .expect("partial response")
            .expect("partial accepted record");
        assert_eq!(accepted.body(), PRIVILEGED_ACCEPTED_BODY);
        let terminal = response.recv_message().await;
        assert!(
            matches!(terminal, Err(_) | Ok(None)),
            "partial response cannot manufacture a terminal record"
        );
        manager.registry.wait_for_deadline_cancel(1).await;
        assert_eq!(manager.registry.deadline_cancels.load(Ordering::Acquire), 1);
        assert_eq!(manager.registry.active(), 0);
        manager
            .shutdown_workers(Instant::now() + WORKER_JOIN_BOUND)
            .await
            .expect("partial worker cancellation and join");
        assert_eq!(manager.effects_unknown.load(Ordering::Acquire), 1);
        assert_eq!(
            manager.outcome.load(Ordering::Acquire),
            ApplicationOutcome::Unknown as u8
        );
        assert_eq!(manager.registry.effects.load(Ordering::Acquire), 1);
        assert_eq!(manager.registry.next_id.load(Ordering::Acquire), 2);
        assert_eq!(manager.application_success.load(Ordering::Acquire), 0);
        assert_eq!(manager.terminal_records.load(Ordering::Acquire), 0);
        assert_eq!(manager.archive_markers.load(Ordering::Acquire), 0);
        assert_eq!(manager.transport_finishes.load(Ordering::Acquire), 0);
        assert_eq!(manager.registry.active(), 0);
        assert_eq!(manager.registry.receipts.load(Ordering::Acquire), 0);
        assert_eq!(manager.registry.coverage.load(Ordering::Acquire), 0);
        manager.registry.wait_for_empty().await;
        super::super::shutdown_rpc_fixture(fixture).await;
    }

    #[tokio::test]
    async fn privileged_rpc_partial_worker_shutdown_while_active_cancels_and_joins() {
        let fixture = super::super::start_rpc_fixture_with_handler(
            |owner, service| Arc::new(PartialWorkerManager::new(owner, service)),
            super::super::shared_pool_limits(),
        )
        .await;
        let manager = Arc::clone(&fixture.manager);
        let mut response = super::super::sent_exchange(
            &fixture.runtime,
            &fixture.route,
            fixture.privileged_envelope_with_deadline(5_000),
            b"active-partial-worker-body",
        )
        .await
        .expect("active partial worker request");
        let accepted = response
            .recv_message()
            .await
            .expect("active partial response")
            .expect("active partial accepted record");
        assert_eq!(accepted.body(), PRIVILEGED_ACCEPTED_BODY);
        manager.registry.wait_for_effect(1).await;
        assert_eq!(manager.registry.active(), 1);
        assert_eq!(manager.registry.deadline_cancels.load(Ordering::Acquire), 0);
        assert_eq!(manager.registry.entries.lock().await.len(), 1);

        let terminal = response.recv_message().await;
        assert!(
            matches!(terminal, Err(_) | Ok(None)),
            "partial response cannot manufacture a terminal record"
        );
        manager
            .shutdown_workers(Instant::now() + WORKER_JOIN_BOUND)
            .await
            .expect("active partial worker cancellation and join");

        assert_eq!(manager.registry.shutdown_cancels.load(Ordering::Acquire), 1);
        assert_eq!(manager.registry.deadline_cancels.load(Ordering::Acquire), 0);
        assert_eq!(manager.registry.active(), 0);
        assert_eq!(manager.effects_unknown.load(Ordering::Acquire), 1);
        assert_eq!(
            manager.outcome.load(Ordering::Acquire),
            ApplicationOutcome::Unknown as u8
        );
        assert_eq!(manager.registry.effects.load(Ordering::Acquire), 1);
        assert_eq!(manager.registry.next_id.load(Ordering::Acquire), 2);
        assert_eq!(manager.application_success.load(Ordering::Acquire), 0);
        assert_eq!(manager.terminal_records.load(Ordering::Acquire), 0);
        assert_eq!(manager.archive_markers.load(Ordering::Acquire), 0);
        assert_eq!(manager.transport_finishes.load(Ordering::Acquire), 0);
        assert_eq!(manager.registry.receipts.load(Ordering::Acquire), 0);
        assert_eq!(manager.registry.coverage.load(Ordering::Acquire), 0);
        manager.registry.wait_for_empty().await;
        assert_eq!(manager.registry.entries.lock().await.len(), 0);
        super::super::shutdown_rpc_fixture(fixture).await;
    }

    #[tokio::test]
    async fn privileged_rpc_post_shutdown_rejects_new_rpc_before_worker_admission() {
        let fixture = super::super::start_rpc_fixture_with_handler(
            |owner, service| Arc::new(PartialWorkerManager::new(owner, service)),
            super::super::shared_pool_limits(),
        )
        .await;
        let manager = Arc::clone(&fixture.manager);

        // Establish one admitted worker so shutdown has a real owned join to
        // complete before the post-shutdown request is attempted.
        let mut first = super::super::sent_exchange(
            &fixture.runtime,
            &fixture.route,
            fixture.privileged_envelope_with_deadline(5_000),
            b"pre-shutdown-active-worker",
        )
        .await
        .expect("pre-shutdown worker request");
        let accepted = first
            .recv_message()
            .await
            .expect("pre-shutdown response")
            .expect("pre-shutdown accepted record");
        assert_eq!(accepted.body(), PRIVILEGED_ACCEPTED_BODY);
        manager.registry.wait_for_effect(1).await;
        assert_eq!(manager.registry.active(), 1);

        manager
            .shutdown_workers(Instant::now() + WORKER_JOIN_BOUND)
            .await
            .expect("existing worker must be cancelled and joined");
        assert_eq!(manager.registry.shutdown_cancels.load(Ordering::Acquire), 1);
        assert_eq!(manager.registry.active(), 0);
        assert_eq!(manager.registry.entries.lock().await.len(), 0);

        let first_terminal = timeout(super::super::RESPONSE_TIMEOUT, first.recv_message()).await;
        assert!(
            matches!(first_terminal, Err(_) | Ok(Err(_)) | Ok(Ok(None))),
            "the pre-shutdown partial response cannot manufacture a terminal record"
        );

        // This is a real authenticated H3 request after the manager's
        // cancellation fence has completed.  The server may expose the local
        // typed shutdown rejection as a closed peer stream, but it must not
        // admit a second worker or mutate any post-admission counters.
        let mut post_shutdown = fixture.privileged_envelope_with_deadline(5_000);
        post_shutdown.request_id = "m7-rpc-after-worker-shutdown".to_owned();
        let post_response_closed = match super::super::sent_exchange(
            &fixture.runtime,
            &fixture.route,
            post_shutdown,
            b"post-shutdown-must-not-dispatch",
        )
        .await
        {
            Ok(mut response) => {
                let result = timeout(super::super::RESPONSE_TIMEOUT, response.recv_message()).await;
                matches!(result, Err(_) | Ok(Err(_)) | Ok(Ok(None)))
            }
            Err(_) => true,
        };
        // Drain any worker admitted by the unfixed implementation before
        // asserting the red-state counters.  The corrected implementation has
        // no second entry and this is an idempotent empty join.
        let post_cleanup_ok = manager
            .shutdown_workers(Instant::now() + WORKER_JOIN_BOUND)
            .await
            .is_ok();
        let entries_empty = manager.registry.entries.lock().await.is_empty();

        // The fixture production patch classifies the admission failure as
        // WorkerRegistryError::Shutdown.  It is observable here through the
        // manager's typed rejection counter while the H3 boundary remains a
        // closed stream; a transport error alone cannot satisfy this check.
        let observed_shutdown_rejections = manager.shutdown_rejections.load(Ordering::Acquire);
        let observed_next_id = manager.registry.next_id.load(Ordering::Acquire);
        let observed_effects = manager.registry.effects.load(Ordering::Acquire);
        let observed_effects_unknown = manager.effects_unknown.load(Ordering::Acquire);
        let observed_receipts = manager.registry.receipts.load(Ordering::Acquire);
        let observed_coverage = manager.registry.coverage.load(Ordering::Acquire);
        let observed_active = manager.registry.active();
        let observed_application_success = manager.application_success.load(Ordering::Acquire);
        let observed_terminal_records = manager.terminal_records.load(Ordering::Acquire);
        let observed_archive_markers = manager.archive_markers.load(Ordering::Acquire);
        let observed_transport_finishes = manager.transport_finishes.load(Ordering::Acquire);
        super::super::shutdown_rpc_fixture(fixture).await;

        assert!(
            post_cleanup_ok,
            "post-shutdown cleanup must retain worker ownership"
        );
        assert!(
            entries_empty,
            "post-shutdown cleanup must leave no worker entry"
        );
        assert!(
            post_response_closed,
            "post-shutdown request cannot receive an accepted or terminal record"
        );
        assert_eq!(
            observed_shutdown_rejections, 1,
            "the post-shutdown H3 request must reach the typed shutdown branch"
        );
        assert_eq!(observed_next_id, 2);
        assert_eq!(observed_effects, 1);
        assert_eq!(observed_effects_unknown, 1);
        assert_eq!(observed_receipts, 0);
        assert_eq!(observed_coverage, 0);
        assert_eq!(observed_active, 0);
        assert_eq!(observed_application_success, 0);
        assert_eq!(observed_terminal_records, 0);
        assert_eq!(observed_archive_markers, 0);
        assert_eq!(observed_transport_finishes, 0);
    }
}
