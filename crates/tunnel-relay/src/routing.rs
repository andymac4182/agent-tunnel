//! Owner selection for direct, single-hop relay routing.
//!
//! The catalog remains the only owner authority.  [`OwnerRouter`] does not
//! claim, renew, release, or otherwise mutate an owner lease.  It may retain
//! a short-lived route observation to avoid repeating a read, but the
//! observation is bounded by the owner lease and (for a remote destination)
//! the verified peer membership lifetime.  The owner still has to validate
//! the complete token at admission time.

use std::{
    collections::HashMap,
    error::Error,
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use tokio::sync::Mutex;
use tunnel_catalog::{Catalog, CatalogError, OwnerClaim, OwnerToken, SharedCatalog};
use tunnel_cluster::{
    envelope::REQUIRED_HOP_BUDGET, error::ClusterError, membership::VerifiedPeerBinding,
};
use uuid::Uuid;

/// The maximum time a route observation may be reused.
pub const MAX_OWNER_ROUTE_CACHE: Duration = Duration::from_secs(5);

/// A deliberately finite cache bound.  The owner route cache is an admission
/// optimisation, not durable state; an entry that is evicted is reread from
/// the authoritative catalog.
pub const MAX_OWNER_ROUTE_CACHE_ENTRIES: usize = 1_024;

const MAX_ROUTING_IDENTIFIER_BYTES: usize = 256;

/// The tenant/device key used by the owner catalog and route cache.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OwnerScope {
    pub tenant_id: Uuid,
    pub device_id: Uuid,
}

impl OwnerScope {
    #[must_use]
    pub const fn new(tenant_id: Uuid, device_id: Uuid) -> Self {
        Self {
            tenant_id,
            device_id,
        }
    }
}

/// The local relay identity against which a canonical owner token is
/// classified.  The boot identity is required: a restarted process with the
/// same node ID is not the same destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayIdentity {
    deployment_incarnation: String,
    node_id: String,
    boot_id: String,
}

impl RelayIdentity {
    /// Build a local identity after validating the bounded identifier fields.
    pub fn new(
        deployment_incarnation: impl Into<String>,
        node_id: impl Into<String>,
        boot_id: impl Into<String>,
    ) -> Result<Self, OwnerRouterConfigError> {
        let identity = Self {
            deployment_incarnation: deployment_incarnation.into(),
            node_id: node_id.into(),
            boot_id: boot_id.into(),
        };
        validate_identifier("deployment_incarnation", &identity.deployment_incarnation)?;
        validate_identifier("node_id", &identity.node_id)?;
        validate_identifier("boot_id", &identity.boot_id)?;
        Ok(identity)
    }

    #[must_use]
    pub fn deployment_incarnation(&self) -> &str {
        &self.deployment_incarnation
    }

    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    #[must_use]
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    fn owns(&self, token: &OwnerToken) -> bool {
        token.deployment_incarnation == self.deployment_incarnation
            && token.node_id == self.node_id
            && token.boot_id == self.boot_id
    }
}

/// A destination selected from the authoritative owner claim.
///
/// The remote variant carries the complete [`OwnerClaim`], including the
/// canonical owner token and its exact node/boot identity.  `peer` is
/// optional because an ingress may select the exact owner before establishing
/// the authenticated HTTP/3 connection.  A remote cache hit requires a
/// [`VerifiedPeerBinding`]; a fresh authoritative read can return the exact
/// token first and let the transport establish that binding before admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnerRoute {
    Local {
        owner: OwnerClaim,
    },
    Remote {
        owner: OwnerClaim,
        peer: Option<VerifiedPeerBinding>,
    },
}

impl OwnerRoute {
    #[must_use]
    pub fn owner(&self) -> &OwnerClaim {
        match self {
            Self::Local { owner } | Self::Remote { owner, .. } => owner,
        }
    }

    #[must_use]
    pub fn owner_token(&self) -> &OwnerToken {
        &self.owner().token
    }

    /// The exact destination node from the owner token.
    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.owner_token().node_id
    }

    /// The exact destination boot identity from the owner token.
    #[must_use]
    pub fn boot_id(&self) -> &str {
        &self.owner_token().boot_id
    }

    #[must_use]
    pub const fn is_local(&self) -> bool {
        matches!(self, Self::Local { .. })
    }

    /// Every owner route is direct.  A peer receiving the resulting
    /// envelope must consume this one hop and return `OWNER_CHANGED` instead
    /// of forwarding recursively.
    #[must_use]
    pub const fn hop_budget() -> u8 {
        REQUIRED_HOP_BUDGET
    }

    #[must_use]
    pub fn peer_binding(&self) -> Option<&VerifiedPeerBinding> {
        match self {
            Self::Local { .. } => None,
            Self::Remote { peer, .. } => peer.as_ref(),
        }
    }
}

/// A single admission retry budget for one request.
///
/// The underlying [`ClusterError`] is the canonical policy source.  Its
/// `can_retry_admission` method already requires an authenticated request, an
/// admission-class error, `NotDispatched` certainty, and the `AdmissionOnce`
/// hint.  This wrapper adds the per-request state that prevents two such
/// errors from producing two retries.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AdmissionRetryBudget {
    consumed: bool,
    sealed: bool,
}

impl AdmissionRetryBudget {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            consumed: false,
            sealed: false,
        }
    }

    #[must_use]
    pub const fn consumed(self) -> bool {
        self.consumed
    }

    /// Decide whether this error authorises the one bounded admission retry.
    ///
    /// A dispatched or unknown operation, an unauthenticated error, and a
    /// second retry request all return [`AdmissionRetryDecision::DoNotRetry`].
    pub fn decide(&mut self, error: &ClusterError) -> AdmissionRetryDecision {
        if self.sealed {
            return AdmissionRetryDecision::DoNotRetry;
        }
        // A request gets exactly one admission decision.  Sealing before
        // examining the error prevents a later contradictory error from
        // turning a dispatched/unknown attempt into a replay.
        self.sealed = true;
        if !error.can_retry_admission() {
            return AdmissionRetryDecision::DoNotRetry;
        }
        self.consumed = true;
        AdmissionRetryDecision::RetryAdmission
    }
}

/// The pure result of applying an [`AdmissionRetryBudget`] to an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionRetryDecision {
    RetryAdmission,
    DoNotRetry,
}

/// Configuration failures for the local routing policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerRouterConfigError {
    InvalidIdentifier { field: &'static str },
    InvalidCacheTtl,
}

impl fmt::Display for OwnerRouterConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier { field } => write!(formatter, "invalid routing {field}"),
            Self::InvalidCacheTtl => formatter.write_str("owner route cache TTL must be 1..=5s"),
        }
    }
}

impl Error for OwnerRouterConfigError {}

/// Errors produced before a peer stream or adapter operation is admitted.
#[derive(Debug)]
pub enum OwnerRoutingError {
    Catalog(CatalogError),
    NoLiveOwner(OwnerScope),
    OwnerScopeMismatch,
    OwnerIncarnationMismatch,
    MalformedOwner,
    DestinationTrustExpired,
    DestinationMismatch,
    AdmissionRetryDenied,
}

impl fmt::Display for OwnerRoutingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Catalog(_) => formatter.write_str("authoritative owner lookup failed"),
            Self::NoLiveOwner(_) => formatter.write_str("device has no live owner"),
            Self::OwnerScopeMismatch => formatter.write_str("owner scope does not match route"),
            Self::OwnerIncarnationMismatch => {
                formatter.write_str("owner deployment incarnation does not match local policy")
            }
            Self::MalformedOwner => formatter.write_str("owner claim is malformed"),
            Self::DestinationTrustExpired => formatter.write_str("destination trust has expired"),
            Self::DestinationMismatch => {
                formatter.write_str("verified destination does not match owner token")
            }
            Self::AdmissionRetryDenied => formatter.write_str("admission retry is not permitted"),
        }
    }
}

impl Error for OwnerRoutingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Catalog(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CatalogError> for OwnerRoutingError {
    fn from(error: CatalogError) -> Self {
        Self::Catalog(error)
    }
}

/// A narrow owner lookup seam.  The blanket implementation delegates to the
/// catalog's authoritative `current_owner`; it exists so pure routing tests
/// can use a bounded test directory without creating a second production
/// authority.
pub trait OwnerDirectory: Send + Sync {
    fn current_owner<'a>(
        &'a self,
        tenant_id: Uuid,
        device_id: Uuid,
        at: DateTime<Utc>,
    ) -> OwnerLookupFuture<'a>;
}

/// Boxed future returned by [`OwnerDirectory`].
pub type OwnerLookupFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<OwnerClaim>, CatalogError>> + Send + 'a>>;

impl<T> OwnerDirectory for T
where
    T: Catalog + ?Sized,
{
    fn current_owner<'a>(
        &'a self,
        tenant_id: Uuid,
        device_id: Uuid,
        at: DateTime<Utc>,
    ) -> OwnerLookupFuture<'a> {
        Box::pin(Catalog::current_owner(self, tenant_id, device_id, at))
    }
}

#[derive(Clone)]
struct CachedOwner {
    owner: OwnerClaim,
    expires_at: Instant,
    /// `None` is used for a local route.  Remote cache entries always carry
    /// the expiry of the verified membership/key evidence used to admit them.
    trust_expires_at: Option<DateTime<Utc>>,
}

/// Direct owner resolver with a bounded, non-authoritative route cache.
#[derive(Clone)]
pub struct OwnerRouter<D: ?Sized = dyn Catalog>
where
    D: OwnerDirectory,
{
    directory: Arc<D>,
    local: RelayIdentity,
    cache: Arc<Mutex<HashMap<OwnerScope, CachedOwner>>>,
    cache_ttl: Duration,
}

impl OwnerRouter<dyn Catalog> {
    /// Construct a router backed by the shared authoritative catalog.
    pub fn new(
        catalog: SharedCatalog,
        local: RelayIdentity,
    ) -> Result<Self, OwnerRouterConfigError> {
        Self::with_cache_ttl(catalog, local, MAX_OWNER_ROUTE_CACHE)
    }
}

impl<D> OwnerRouter<D>
where
    D: OwnerDirectory + ?Sized,
{
    /// Construct a router with a shorter cache TTL, primarily for deployment
    /// policy and deterministic tests.  A caller cannot configure a TTL
    /// beyond the five-second cluster contract.
    pub fn with_cache_ttl(
        directory: Arc<D>,
        local: RelayIdentity,
        cache_ttl: Duration,
    ) -> Result<Self, OwnerRouterConfigError> {
        if cache_ttl.is_zero() || cache_ttl > MAX_OWNER_ROUTE_CACHE {
            return Err(OwnerRouterConfigError::InvalidCacheTtl);
        }
        Ok(Self {
            directory,
            local,
            cache: Arc::new(Mutex::new(HashMap::new())),
            cache_ttl,
        })
    }

    /// Resolve the current owner for a tenant/device scope.
    ///
    /// `destination` is optional only for a fresh remote lookup: the owner
    /// token itself still names the exact node and boot identity, and the
    /// transport must obtain and verify a matching peer binding before
    /// admission.  A remote cached result is never returned without that
    /// binding, because its signed membership/key validity is part of the
    /// cache lifetime proof.
    pub async fn resolve(
        &self,
        scope: OwnerScope,
        now: DateTime<Utc>,
        destination: Option<&VerifiedPeerBinding>,
    ) -> Result<OwnerRoute, OwnerRoutingError> {
        if let Some(route) = self.try_cached(scope, now, destination).await {
            return Ok(route);
        }

        let lookup_started = Instant::now();
        let owner = self
            .directory
            .current_owner(scope.tenant_id, scope.device_id, now)
            .await?;
        let lookup_now = wall_after(now, lookup_started.elapsed());
        let owner = owner.ok_or(OwnerRoutingError::NoLiveOwner(scope))?;
        let route = self.classify(scope, owner, lookup_now, destination)?;

        // A response that spent most of the lease waiting in the catalog
        // client must not receive a fresh cache lifetime from response time.
        // `lookup_now` is anchored at the caller's wall time plus the
        // monotonic lookup duration.
        if let Some(trust_expires_at) = match &route {
            OwnerRoute::Local { .. } => None,
            OwnerRoute::Remote { peer, .. } => peer.as_ref().map(VerifiedPeerBinding::valid_until),
        } {
            self.cache_owner(
                scope,
                route.owner().clone(),
                lookup_now,
                Some(trust_expires_at),
            )
            .await;
        } else if route.is_local() {
            self.cache_owner(scope, route.owner().clone(), lookup_now, None)
                .await;
        }
        Ok(route)
    }

    /// Re-read the authoritative owner after an authenticated owner-admission
    /// failure.  This consumes the one retry budget and invalidates the stale
    /// route first; it never retries a dispatched or ambiguous operation.
    pub async fn resolve_after_admission_failure(
        &self,
        scope: OwnerScope,
        now: DateTime<Utc>,
        destination: Option<&VerifiedPeerBinding>,
        budget: &mut AdmissionRetryBudget,
        error: &ClusterError,
    ) -> Result<OwnerRoute, OwnerRoutingError> {
        if budget.decide(error) != AdmissionRetryDecision::RetryAdmission {
            return Err(OwnerRoutingError::AdmissionRetryDenied);
        }
        self.invalidate(scope).await;
        self.resolve(scope, now, destination).await
    }

    /// Drop one cached route.  This is used after a peer returns an
    /// authenticated `OWNER_CHANGED`/`NOT_DISPATCHED` admission result.
    pub async fn invalidate(&self, scope: OwnerScope) {
        self.cache.lock().await.remove(&scope);
    }

    /// Drop all cached routes.  This is a local optimisation reset used when
    /// membership trust is invalidated; it does not mutate catalog authority.
    pub async fn invalidate_all(&self) {
        self.cache.lock().await.clear();
    }

    async fn try_cached(
        &self,
        scope: OwnerScope,
        now: DateTime<Utc>,
        destination: Option<&VerifiedPeerBinding>,
    ) -> Option<OwnerRoute> {
        let monotonic_now = Instant::now();
        let mut cache = self.cache.lock().await;
        let entry = cache.get(&scope)?.clone();
        if entry.owner.lease_expires_at <= now {
            cache.remove(&scope);
            return None;
        }
        // Keep an expired observation as a generation fence until the owner
        // lease itself expires.  Otherwise a delayed, lower-epoch catalog
        // response could repopulate the cache after the short route TTL and
        // resurrect a predecessor during a handover.
        if monotonic_now >= entry.expires_at {
            return None;
        }

        let local = self.local.owns(&entry.owner.token);
        if !local {
            let binding = destination?;
            let trust_expires_at = entry.trust_expires_at?;
            if trust_expires_at <= now || binding.valid_until() <= now {
                return None;
            }
            if !binding_matches(&entry.owner.token, binding) {
                // Keep the entry for a caller that still has evidence for the
                // cached owner; a different boot/node must not reuse it.
                return None;
            }
            return Some(OwnerRoute::Remote {
                owner: entry.owner,
                peer: Some(binding.clone()),
            });
        }

        Some(OwnerRoute::Local { owner: entry.owner })
    }

    fn classify(
        &self,
        scope: OwnerScope,
        owner: OwnerClaim,
        now: DateTime<Utc>,
        destination: Option<&VerifiedPeerBinding>,
    ) -> Result<OwnerRoute, OwnerRoutingError> {
        validate_owner(&owner, scope, self.local.deployment_incarnation())?;
        if owner.lease_expires_at <= now {
            return Err(OwnerRoutingError::NoLiveOwner(scope));
        }
        if self.local.owns(&owner.token) {
            return Ok(OwnerRoute::Local { owner });
        }
        if let Some(binding) = destination {
            if binding.valid_until() <= now {
                return Err(OwnerRoutingError::DestinationTrustExpired);
            }
            if !binding_matches(&owner.token, binding) {
                return Err(OwnerRoutingError::DestinationMismatch);
            }
            return Ok(OwnerRoute::Remote {
                owner,
                peer: Some(binding.clone()),
            });
        }
        Ok(OwnerRoute::Remote { owner, peer: None })
    }

    async fn cache_owner(
        &self,
        scope: OwnerScope,
        owner: OwnerClaim,
        now: DateTime<Utc>,
        trust_expires_at: Option<DateTime<Utc>>,
    ) {
        let Some(ttl) = bounded_cache_lifetime(
            self.cache_ttl,
            owner.lease_expires_at,
            trust_expires_at,
            now,
        ) else {
            return;
        };
        let Some(expires_at) = Instant::now().checked_add(ttl) else {
            return;
        };
        let mut cache = self.cache.lock().await;

        // Catalog reads can complete out of order during a handover.  Never
        // let a response for an older owner generation replace a newer route
        // that was already observed.  An equal epoch with different fencing
        // material is a conflict, so evict it and force the next admission
        // to consult the authority rather than choosing either owner.
        if let Some(existing) = cache.get(&scope) {
            if existing.owner.lease_expires_at <= now {
                cache.remove(&scope);
            } else if existing.owner.token.epoch > owner.token.epoch {
                return;
            } else if existing.owner.token.epoch == owner.token.epoch
                && existing.owner.token != owner.token
            {
                cache.remove(&scope);
                return;
            }
        }
        if !cache.contains_key(&scope)
            && cache.len() >= MAX_OWNER_ROUTE_CACHE_ENTRIES
            && let Some(evicted) = cache.keys().next().copied()
        {
            cache.remove(&evicted);
        }
        cache.insert(
            scope,
            CachedOwner {
                owner,
                expires_at,
                trust_expires_at,
            },
        );
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), OwnerRouterConfigError> {
    if value.trim().is_empty()
        || value.len() > MAX_ROUTING_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(OwnerRouterConfigError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_owner(
    owner: &OwnerClaim,
    scope: OwnerScope,
    deployment_incarnation: &str,
) -> Result<(), OwnerRoutingError> {
    if owner.token.tenant_id != scope.tenant_id || owner.token.device_id != scope.device_id {
        return Err(OwnerRoutingError::OwnerScopeMismatch);
    }
    if owner.token.deployment_incarnation != deployment_incarnation {
        return Err(OwnerRoutingError::OwnerIncarnationMismatch);
    }
    if owner.token.epoch == 0
        || owner.token.node_id.trim().is_empty()
        || owner.token.boot_id.trim().is_empty()
        || owner.token.session_id.trim().is_empty()
    {
        return Err(OwnerRoutingError::MalformedOwner);
    }
    Ok(())
}

fn binding_matches(owner: &OwnerToken, binding: &VerifiedPeerBinding) -> bool {
    owner.node_id == binding.node_id() && owner.boot_id == binding.boot_id()
}

fn wall_after(now: DateTime<Utc>, elapsed: Duration) -> DateTime<Utc> {
    ChronoDuration::from_std(elapsed)
        .ok()
        .and_then(|delta| now.checked_add_signed(delta))
        .unwrap_or(now)
}

fn bounded_cache_lifetime(
    configured: Duration,
    owner_expires_at: DateTime<Utc>,
    trust_expires_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Option<Duration> {
    let lease = owner_expires_at.signed_duration_since(now).to_std().ok()?;
    // Local routes have no independent membership-trust deadline.  Treat the
    // absent remote trust bound as unbounded and still cap the result by the
    // owner lease and the configured route-cache TTL.
    let trust = match trust_expires_at {
        Some(deadline) => deadline.signed_duration_since(now).to_std().ok()?,
        None => Duration::MAX,
    };
    let ttl = lease.min(trust).min(configured);
    (!ttl.is_zero()).then_some(ttl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tunnel_cluster::error::{ErrorScope, ExecutionCertainty, InternalErrorCode, RetryHint};

    fn identity() -> RelayIdentity {
        RelayIdentity::new("inc-1", "node-a", "boot-a").expect("identity")
    }

    fn owner(node_id: &str, boot_id: &str, lease_expires_at: DateTime<Utc>) -> OwnerClaim {
        owner_with_session(node_id, boot_id, "session-1", 1, lease_expires_at)
    }

    fn owner_with_epoch(
        node_id: &str,
        boot_id: &str,
        epoch: u64,
        lease_expires_at: DateTime<Utc>,
    ) -> OwnerClaim {
        owner_with_session(node_id, boot_id, "session-1", epoch, lease_expires_at)
    }

    fn owner_with_session(
        node_id: &str,
        boot_id: &str,
        session_id: &str,
        epoch: u64,
        lease_expires_at: DateTime<Utc>,
    ) -> OwnerClaim {
        OwnerClaim {
            token: OwnerToken {
                deployment_incarnation: "inc-1".into(),
                tenant_id: Uuid::from_u128(1),
                device_id: Uuid::from_u128(2),
                node_id: node_id.into(),
                boot_id: boot_id.into(),
                session_id: session_id.into(),
                epoch,
            },
            lease_expires_at,
        }
    }

    #[test]
    fn exact_node_and_boot_are_local_only() {
        let now = Utc::now();
        let local = identity();
        let scope = OwnerScope::new(Uuid::from_u128(1), Uuid::from_u128(2));
        let router = OwnerRouter::<TestDirectory> {
            directory: Arc::new(TestDirectory::new(owner(
                "node-a",
                "boot-a",
                now + ChronoDuration::seconds(10),
            ))),
            local,
            cache: Arc::new(Mutex::new(HashMap::new())),
            cache_ttl: MAX_OWNER_ROUTE_CACHE,
        };
        let local_route = router
            .classify(
                scope,
                owner("node-a", "boot-a", now + ChronoDuration::seconds(10)),
                now,
                None,
            )
            .expect("local route");
        assert!(local_route.is_local());

        let rebooted = owner("node-a", "boot-b", now + ChronoDuration::seconds(10));
        let remote_route = router
            .classify(scope, rebooted, now, None)
            .expect("remote route");
        assert!(!remote_route.is_local());
        assert_eq!(remote_route.boot_id(), "boot-b");
    }

    #[test]
    fn owner_scope_and_incarnation_are_checked_before_local_classification() {
        let now = Utc::now();
        let local = identity();
        let scope = OwnerScope::new(Uuid::from_u128(1), Uuid::from_u128(2));
        let router = OwnerRouter::<TestDirectory> {
            directory: Arc::new(TestDirectory::new(owner(
                "node-a",
                "boot-a",
                now + ChronoDuration::seconds(10),
            ))),
            local,
            cache: Arc::new(Mutex::new(HashMap::new())),
            cache_ttl: MAX_OWNER_ROUTE_CACHE,
        };

        let mut wrong_scope = owner("node-a", "boot-a", now + ChronoDuration::seconds(10));
        wrong_scope.token.device_id = Uuid::from_u128(99);
        assert!(matches!(
            router.classify(scope, wrong_scope, now, None),
            Err(OwnerRoutingError::OwnerScopeMismatch)
        ));

        let mut wrong_incarnation = owner("node-a", "boot-a", now + ChronoDuration::seconds(10));
        wrong_incarnation.token.deployment_incarnation = "inc-2".into();
        assert!(matches!(
            router.classify(scope, wrong_incarnation, now, None),
            Err(OwnerRoutingError::OwnerIncarnationMismatch)
        ));
    }

    #[test]
    fn cache_lifetime_is_capped_by_lease_and_trust() {
        let now = Utc::now();
        assert_eq!(
            bounded_cache_lifetime(
                Duration::from_secs(5),
                now + ChronoDuration::seconds(30),
                None,
                now,
            ),
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            bounded_cache_lifetime(
                Duration::from_secs(5),
                now + ChronoDuration::seconds(30),
                Some(now + ChronoDuration::seconds(2)),
                now,
            ),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            bounded_cache_lifetime(
                Duration::from_secs(5),
                now + ChronoDuration::seconds(2),
                Some(now + ChronoDuration::seconds(30)),
                now,
            ),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            bounded_cache_lifetime(
                Duration::from_secs(5),
                now - ChronoDuration::seconds(1),
                Some(now + ChronoDuration::seconds(2)),
                now,
            ),
            None
        );
    }

    #[tokio::test]
    async fn local_route_cache_is_reused_until_lease_expiry() {
        let now = Utc::now();
        let scope = OwnerScope::new(Uuid::from_u128(1), Uuid::from_u128(2));
        let directory = Arc::new(TestDirectory::new(owner(
            "node-a",
            "boot-a",
            now + ChronoDuration::seconds(10),
        )));
        let router =
            OwnerRouter::with_cache_ttl(directory.clone(), identity(), Duration::from_secs(5))
                .expect("cache policy");

        assert!(
            router
                .resolve(scope, now, None)
                .await
                .expect("first route")
                .is_local()
        );
        assert!(
            router
                .resolve(scope, now + ChronoDuration::milliseconds(1), None)
                .await
                .expect("cached route")
                .is_local()
        );
        assert_eq!(directory.lookups(), 1, "local route should be cached");

        directory.set_owner(None);
        assert!(matches!(
            router
                .resolve(scope, now + ChronoDuration::seconds(11), None)
                .await,
            Err(OwnerRoutingError::NoLiveOwner(found)) if found == scope
        ));
        assert_eq!(directory.lookups(), 2, "expired lease must force a reread");
    }

    #[tokio::test]
    async fn stale_owner_lookup_cannot_overwrite_newer_cached_generation() {
        let now = Utc::now();
        let scope = OwnerScope::new(Uuid::from_u128(1), Uuid::from_u128(2));
        let router = OwnerRouter::with_cache_ttl(
            Arc::new(TestDirectory::new(owner_with_epoch(
                "node-b",
                "boot-b",
                2,
                now + ChronoDuration::seconds(30),
            ))),
            identity(),
            Duration::from_secs(5),
        )
        .expect("cache policy");

        router
            .cache_owner(
                scope,
                owner_with_epoch("node-a", "boot-a", 2, now + ChronoDuration::seconds(30)),
                now,
                None,
            )
            .await;
        router
            .cache_owner(
                scope,
                owner_with_epoch("node-a", "boot-a", 1, now + ChronoDuration::seconds(30)),
                now,
                None,
            )
            .await;

        let route = router
            .try_cached(scope, now, None)
            .await
            .expect("newer route remains cached");
        assert_eq!(route.owner_token().epoch, 2);
        assert_eq!(route.node_id(), "node-a");
        assert_eq!(route.boot_id(), "boot-a");
    }

    #[tokio::test]
    async fn expired_cache_observation_still_fences_a_delayed_predecessor() {
        let now = Utc::now();
        let scope = OwnerScope::new(Uuid::from_u128(1), Uuid::from_u128(2));
        let router = OwnerRouter::with_cache_ttl(
            Arc::new(TestDirectory::new(owner_with_epoch(
                "node-a",
                "boot-a",
                2,
                now + ChronoDuration::seconds(30),
            ))),
            identity(),
            Duration::from_secs(5),
        )
        .expect("cache policy");
        router.cache.lock().await.insert(
            scope,
            CachedOwner {
                owner: owner_with_epoch("node-a", "boot-a", 2, now + ChronoDuration::seconds(30)),
                expires_at: Instant::now() - Duration::from_secs(1),
                trust_expires_at: None,
            },
        );

        router
            .cache_owner(
                scope,
                owner_with_epoch("node-b", "boot-b", 1, now + ChronoDuration::seconds(30)),
                now,
                None,
            )
            .await;

        let cache = router.cache.lock().await;
        assert_eq!(
            cache
                .get(&scope)
                .expect("generation fence")
                .owner
                .token
                .epoch,
            2
        );
        drop(cache);
        assert!(router.try_cached(scope, now, None).await.is_none());
        assert!(router.cache.lock().await.contains_key(&scope));
    }

    #[tokio::test]
    async fn same_epoch_conflict_evicts_cache_instead_of_picking_an_owner() {
        let now = Utc::now();
        let scope = OwnerScope::new(Uuid::from_u128(1), Uuid::from_u128(2));
        let router = OwnerRouter::with_cache_ttl(
            Arc::new(TestDirectory::new(owner(
                "node-b",
                "boot-b",
                now + ChronoDuration::seconds(30),
            ))),
            identity(),
            Duration::from_secs(5),
        )
        .expect("cache policy");

        router
            .cache_owner(
                scope,
                owner_with_session(
                    "node-a",
                    "boot-a",
                    "session-b",
                    2,
                    now + ChronoDuration::seconds(30),
                ),
                now,
                None,
            )
            .await;
        router
            .cache_owner(
                scope,
                owner_with_session(
                    "node-c",
                    "boot-c",
                    "session-c",
                    2,
                    now + ChronoDuration::seconds(30),
                ),
                now,
                None,
            )
            .await;

        assert!(
            !router.cache.lock().await.contains_key(&scope),
            "equal-epoch fencing conflict must fail closed"
        );
    }

    #[tokio::test]
    async fn admission_reselection_invalidates_stale_route_once() {
        let now = Utc::now();
        let scope = OwnerScope::new(Uuid::from_u128(1), Uuid::from_u128(2));
        let directory = Arc::new(TestDirectory::new(owner_with_epoch(
            "node-a",
            "boot-a",
            1,
            now + ChronoDuration::seconds(30),
        )));
        let router =
            OwnerRouter::with_cache_ttl(directory.clone(), identity(), Duration::from_secs(5))
                .expect("cache policy");
        let first = router.resolve(scope, now, None).await.expect("first route");
        assert_eq!(first.owner_token().epoch, 1);

        directory.set_owner(Some(owner_with_epoch(
            "node-b",
            "boot-b",
            2,
            now + ChronoDuration::seconds(30),
        )));
        let error = ClusterError::new(
            InternalErrorCode::OwnerChanged,
            ErrorScope::default(),
            "request-1",
            None,
            ExecutionCertainty::NotDispatched,
            RetryHint::AdmissionOnce,
            true,
        );
        let mut budget = AdmissionRetryBudget::new();
        let replacement = router
            .resolve_after_admission_failure(scope, now, None, &mut budget, &error)
            .await
            .expect("one bounded reselection");
        assert_eq!(replacement.owner_token().epoch, 2);
        assert_eq!(replacement.node_id(), "node-b");
        assert!(budget.consumed());
        assert_eq!(directory.lookups(), 2);

        assert_eq!(
            router
                .resolve_after_admission_failure(scope, now, None, &mut budget, &error)
                .await
                .expect_err("second reselection is forbidden")
                .to_string(),
            "admission retry is not permitted"
        );
        assert_eq!(directory.lookups(), 2);
    }

    #[tokio::test]
    async fn postdispatch_or_ambiguous_failure_keeps_cached_route() {
        let now = Utc::now();
        let scope = OwnerScope::new(Uuid::from_u128(1), Uuid::from_u128(2));
        let directory = Arc::new(TestDirectory::new(owner(
            "node-a",
            "boot-a",
            now + ChronoDuration::seconds(30),
        )));
        let router =
            OwnerRouter::with_cache_ttl(directory.clone(), identity(), Duration::from_secs(5))
                .expect("cache policy");
        let _ = router.resolve(scope, now, None).await.expect("route");
        directory.set_owner(Some(owner_with_epoch(
            "node-b",
            "boot-b",
            2,
            now + ChronoDuration::seconds(30),
        )));

        for certainty in [ExecutionCertainty::Dispatched, ExecutionCertainty::Unknown] {
            let error = ClusterError::new(
                InternalErrorCode::PeerUnavailable,
                ErrorScope::default(),
                "request-1",
                None,
                certainty,
                RetryHint::AdmissionOnce,
                true,
            );
            let mut budget = AdmissionRetryBudget::new();
            assert!(matches!(
                router
                    .resolve_after_admission_failure(scope, now, None, &mut budget, &error)
                    .await,
                Err(OwnerRoutingError::AdmissionRetryDenied)
            ));
            assert!(!budget.consumed());
            assert_eq!(
                router
                    .try_cached(scope, now, None)
                    .await
                    .expect("post-dispatch failures retain route")
                    .owner_token()
                    .epoch,
                1
            );
        }
        assert_eq!(directory.lookups(), 1);
    }

    #[test]
    fn retry_policy_allows_one_authenticated_not_dispatched_attempt() {
        let scope = ErrorScope {
            tenant_id: Some(Uuid::from_u128(1)),
            device_id: Some(Uuid::from_u128(2)),
            service_id: None,
        };
        let error = ClusterError::new(
            InternalErrorCode::PeerUnavailable,
            scope,
            "request-1",
            None,
            ExecutionCertainty::NotDispatched,
            RetryHint::AdmissionOnce,
            true,
        );
        let mut budget = AdmissionRetryBudget::new();
        assert_eq!(
            budget.decide(&error),
            AdmissionRetryDecision::RetryAdmission
        );
        assert_eq!(budget.decide(&error), AdmissionRetryDecision::DoNotRetry);
    }

    #[test]
    fn retry_policy_refuses_effects_unknown_and_unauthenticated() {
        let scope = ErrorScope::default();
        for certainty in [ExecutionCertainty::Dispatched, ExecutionCertainty::Unknown] {
            let error = ClusterError::new(
                InternalErrorCode::PeerUnavailable,
                scope.clone(),
                "request-1",
                None,
                certainty,
                RetryHint::AdmissionOnce,
                true,
            );
            let mut budget = AdmissionRetryBudget::new();
            assert_eq!(budget.decide(&error), AdmissionRetryDecision::DoNotRetry);
        }
        let unauthenticated = ClusterError::new(
            InternalErrorCode::PeerUnavailable,
            scope,
            "request-1",
            None,
            ExecutionCertainty::NotDispatched,
            RetryHint::AdmissionOnce,
            false,
        );
        let mut budget = AdmissionRetryBudget::new();
        assert_eq!(
            budget.decide(&unauthenticated),
            AdmissionRetryDecision::DoNotRetry
        );
    }

    #[test]
    fn retry_budget_cannot_be_reopened_after_a_denied_attempt() {
        let scope = ErrorScope::default();
        let dispatched = ClusterError::new(
            InternalErrorCode::PeerUnavailable,
            scope.clone(),
            "request-1",
            None,
            ExecutionCertainty::Dispatched,
            RetryHint::AdmissionOnce,
            true,
        );
        let safe = ClusterError::new(
            InternalErrorCode::OwnerChanged,
            scope,
            "request-1",
            None,
            ExecutionCertainty::NotDispatched,
            RetryHint::AdmissionOnce,
            true,
        );
        let mut budget = AdmissionRetryBudget::new();
        assert_eq!(
            budget.decide(&dispatched),
            AdmissionRetryDecision::DoNotRetry
        );
        assert_eq!(budget.decide(&safe), AdmissionRetryDecision::DoNotRetry);
        assert!(!budget.consumed());
    }

    struct TestDirectory {
        owner: std::sync::Mutex<Option<OwnerClaim>>,
        lookups: AtomicUsize,
    }

    impl TestDirectory {
        fn new(owner: OwnerClaim) -> Self {
            Self {
                owner: std::sync::Mutex::new(Some(owner)),
                lookups: AtomicUsize::new(0),
            }
        }

        fn set_owner(&self, owner: Option<OwnerClaim>) {
            *self.owner.lock().expect("test owner lock") = owner;
        }

        fn lookups(&self) -> usize {
            self.lookups.load(Ordering::SeqCst)
        }
    }

    impl OwnerDirectory for TestDirectory {
        fn current_owner<'a>(
            &'a self,
            _tenant_id: Uuid,
            _device_id: Uuid,
            _at: DateTime<Utc>,
        ) -> OwnerLookupFuture<'a> {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(self.owner.lock().expect("test owner lock").clone()) })
        }
    }
}
