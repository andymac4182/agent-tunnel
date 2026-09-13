//! Bounded readiness state for the private relay-to-relay routes.
//!
//! Membership readiness is necessary but not sufficient for a cluster relay.
//! This module keeps the additional process-local facts which must be true
//! before public work is admitted: the private listener is bound, every
//! verified route required by the current membership snapshot has completed a
//! bounded authenticated probe, and a non-zero amount of peer capacity is
//! available.  It deliberately stores only bounded state and never exposes
//! endpoint or certificate details through its status snapshot.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use tunnel_cluster::membership::VerifiedMembership;

/// The signed membership policy caps an authorized deployment at 32 nodes.
/// Keep the readiness state no larger than that policy even if a caller is
/// handed an invalid or unbounded route iterator.
pub const MAX_REQUIRED_PEER_ROUTES: usize = 32;

/// The smallest amount of peer capacity that can support a ready relay.
pub const MIN_REQUIRED_PEER_CAPACITY: usize = 1;

/// The maximum number of authenticated probes allowed to be in flight during
/// one refresh pass.  This bounds bootstrap and recovery work independently
/// of the number of signed membership records.
pub const MAX_CONCURRENT_PEER_PROBES: usize = 4;

/// Default monotonic freshness bound for a successful route probe.
pub const DEFAULT_PEER_PROBE_TTL: Duration = Duration::from_secs(15);

/// Absolute deadline for one complete authenticated route probe.
///
/// This covers connection checkout or setup, request-stream reservation,
/// response headers, and the terminating empty-body read.  It is deliberately
/// independent of the transport's per-operation idle timeout so a peer which
/// sends periodic unrelated bytes cannot keep readiness admission alive.
pub const PEER_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Revision of the currently installed verified route and pin set.
pub type PeerReadinessRevision = u64;

/// The state of the private listener relevant to public readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerListenerState {
    /// The private listener has not completed its bind.
    Unbound,
    /// The private listener is accepting authenticated peer connections.
    Bound,
    /// Shutdown or drain has begun; new public work must fail closed.
    Draining,
}

/// The result of one bounded, authenticated route probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerProbeState {
    /// A route is in the required set but has not completed a current probe.
    Pending,
    /// The route completed mTLS, role, pin, and endpoint checks.
    Reachable,
    /// The route could not be reached or failed identity validation.
    Unreachable,
    /// The route could not obtain bounded transport capacity.
    CapacityExhausted,
}

/// Redacted state for one uniquely identified signed peer route.
///
/// The accessor intentionally returns only the signed node identifier and the
/// bounded probe state.  Endpoint, server-name, and SPKI values remain
/// private so diagnostics cannot turn route evidence into trust material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerRouteReadiness {
    pub node_id: String,
    pub state: PeerProbeState,
}

/// A route target derived from one verified signed membership record.
///
/// A signed membership record does not contain a boot ID.  The boot ID is
/// therefore intentionally absent here and is checked later when an owner
/// binding is selected.  The authenticated probe still verifies the relay
/// node role and one of the currently approved SPKI keys from this record.
#[derive(Clone, Eq, PartialEq)]
pub struct PeerRouteTarget {
    node_id: String,
    peer_endpoint: String,
    server_name: String,
    approved_spki_sha256: Vec<String>,
}

impl fmt::Debug for PeerRouteTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerRouteTarget")
            .field("node_id", &self.node_id)
            .field("approved_key_count", &self.approved_spki_sha256.len())
            .finish_non_exhaustive()
    }
}

impl PeerRouteTarget {
    #[cfg(test)]
    pub(crate) fn for_test(
        node_id: impl Into<String>,
        peer_endpoint: impl Into<String>,
        server_name: impl Into<String>,
        approved_spki_sha256: Vec<String>,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            peer_endpoint: peer_endpoint.into(),
            server_name: server_name.into(),
            approved_spki_sha256,
        }
    }

    /// Build a target from a membership record which has already passed the
    /// signed verifier.  Expired, revoked, and not-yet-active keys are
    /// excluded from the bounded probe pin set.
    #[must_use]
    pub fn from_verified_membership(
        membership: &VerifiedMembership,
        now: DateTime<Utc>,
    ) -> Option<Self> {
        if membership.record().not_before > now || membership.record().expires_at <= now {
            return None;
        }
        let mut approved_spki_sha256 = membership
            .keys()
            .iter()
            .filter(|key| !key.revoked && key.not_before <= now && key.expires_at > now)
            .map(|key| key.spki_sha256.clone())
            .collect::<Vec<_>>();
        approved_spki_sha256.sort_unstable();
        approved_spki_sha256.dedup();
        if approved_spki_sha256.is_empty() {
            return None;
        }
        Some(Self {
            node_id: membership.node_id().to_owned(),
            peer_endpoint: membership.peer_endpoint().to_owned(),
            server_name: membership.server_name().to_owned(),
            approved_spki_sha256,
        })
    }

    /// Build a one-pin route identity from an already verified binding.  This
    /// is used to mark an established route unavailable after a failed owner
    /// open without accepting caller-provided endpoint or pin strings.
    #[must_use]
    pub fn from_verified_binding(
        binding: &tunnel_cluster::membership::VerifiedPeerBinding,
    ) -> Self {
        Self {
            node_id: binding.node_id().to_owned(),
            peer_endpoint: binding.peer_endpoint().to_owned(),
            server_name: binding.server_name().to_owned(),
            approved_spki_sha256: vec![binding.spki_sha256().to_owned()],
        }
    }

    /// Return the signed node identifier used by the peer certificate role.
    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Return the signed private endpoint for the transport adapter.
    #[must_use]
    pub fn peer_endpoint(&self) -> &str {
        &self.peer_endpoint
    }

    /// Return the signed TLS server name for the transport adapter.
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Return the currently approved SPKI digests for this target.
    #[must_use]
    pub fn approved_spki_sha256(&self) -> &[String] {
        &self.approved_spki_sha256
    }

    fn key(&self) -> PeerRouteKey {
        PeerRouteKey {
            node_id: self.node_id.clone(),
            peer_endpoint: self.peer_endpoint.clone(),
            server_name: self.server_name.clone(),
        }
    }

    fn same_pins(&self, other: &Self) -> bool {
        self.approved_spki_sha256 == other.approved_spki_sha256
    }

    /// Match an observation derived from one authenticated binding to the
    /// signed route target.  Endpoint and node identity must match exactly;
    /// the observed binding pin only needs to be a member of the signed pin
    /// overlap set.
    fn matches_route_observation(&self, observation: &Self) -> bool {
        self.key() == observation.key()
            && observation.approved_spki_sha256.iter().any(|pin| {
                self.approved_spki_sha256
                    .iter()
                    .any(|approved| approved == pin)
            })
    }
}

/// A redacted readiness snapshot suitable for bounded in-process checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerReadinessSnapshot {
    /// Current listener state.
    pub listener: PeerListenerState,
    /// Whether the current verified route set has been installed.
    pub routes_known: bool,
    /// Number of routes required by that set.
    pub required_routes: usize,
    /// Number of routes with a successful current probe.
    pub reachable_routes: usize,
    /// Number of routes with a current successful probe and capacity floor.
    pub capacity_ready_routes: usize,
    /// Current observed/configured available peer capacity.
    pub available_capacity: Option<usize>,
    /// Minimum capacity required for readiness.
    pub required_capacity: usize,
    /// Monotonic revision of the installed route and pin set.
    pub revision: PeerReadinessRevision,
}

/// Bounded readiness errors.  They do not include endpoints, pins, payloads,
/// or backend error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerReadinessError {
    /// The required capacity floor is zero or otherwise invalid.
    InvalidCapacity,
    /// A zero probe freshness bound would immediately make every route stale.
    InvalidProbeTtl,
    /// A route set exceeded the signed deployment bound.
    TooManyRoutes { observed: usize, maximum: usize },
    /// A probe result referred to a route which is not currently required.
    UnknownRoute,
}

impl fmt::Display for PeerReadinessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCapacity => formatter.write_str("peer readiness capacity is invalid"),
            Self::InvalidProbeTtl => {
                formatter.write_str("peer readiness probe freshness is invalid")
            }
            Self::TooManyRoutes { observed, maximum } => write!(
                formatter,
                "peer readiness route count exceeds bound: {observed} > {maximum}"
            ),
            Self::UnknownRoute => formatter.write_str("peer readiness route is not required"),
        }
    }
}

impl std::error::Error for PeerReadinessError {}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct PeerRouteKey {
    node_id: String,
    peer_endpoint: String,
    server_name: String,
}

#[derive(Clone, Debug)]
struct RequiredRoute {
    target: PeerRouteTarget,
    state: PeerProbeState,
    last_probe: Option<Instant>,
    available_capacity: Option<usize>,
}

#[derive(Debug)]
struct ReadinessState {
    listener: PeerListenerState,
    routes_known: bool,
    routes: BTreeMap<PeerRouteKey, RequiredRoute>,
    available_capacity: Option<usize>,
    required_capacity: usize,
    probe_ttl: Duration,
    revision: PeerReadinessRevision,
}

/// Thread-safe process-local peer route readiness.
#[derive(Clone, Debug)]
pub struct PeerReadiness {
    state: Arc<Mutex<ReadinessState>>,
}

impl PeerReadiness {
    /// Construct a readiness state with a positive capacity floor.
    pub fn new(required_capacity: usize) -> Result<Self, PeerReadinessError> {
        Self::new_with_probe_ttl(required_capacity, DEFAULT_PEER_PROBE_TTL)
    }

    /// Construct readiness with an explicit monotonic probe freshness bound.
    pub fn new_with_probe_ttl(
        required_capacity: usize,
        probe_ttl: Duration,
    ) -> Result<Self, PeerReadinessError> {
        if required_capacity < MIN_REQUIRED_PEER_CAPACITY {
            return Err(PeerReadinessError::InvalidCapacity);
        }
        if probe_ttl.is_zero() {
            return Err(PeerReadinessError::InvalidProbeTtl);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(ReadinessState {
                listener: PeerListenerState::Unbound,
                routes_known: false,
                routes: BTreeMap::new(),
                available_capacity: None,
                required_capacity,
                probe_ttl,
                revision: 0,
            })),
        })
    }

    /// Mark the private listener bound or draining.  A draining listener can
    /// never make readiness true again until a new state is installed.
    pub fn set_listener_state(&self, listener: PeerListenerState) {
        self.state
            .lock()
            .expect("peer readiness mutex poisoned")
            .listener = listener;
    }

    /// Record the currently available bounded peer capacity.  Zero is valid
    /// input and deliberately makes readiness fail closed.
    pub fn set_available_capacity(&self, available_capacity: usize) {
        self.state
            .lock()
            .expect("peer readiness mutex poisoned")
            .available_capacity = Some(available_capacity);
    }

    /// Forget capacity evidence until the next transport/configuration
    /// observation.  This is used when the pool is shut down or revoked.
    pub fn clear_available_capacity(&self) {
        self.state
            .lock()
            .expect("peer readiness mutex poisoned")
            .available_capacity = None;
    }

    /// Replace the required route set from current verified membership.
    /// Existing successful state is retained only when the endpoint, server
    /// name, and approved pin set are unchanged.  An explicitly empty set is
    /// valid for a verified one-node deployment; an uninstalled set is not.
    pub fn replace_required_routes<I>(&self, targets: I) -> Result<(), PeerReadinessError>
    where
        I: IntoIterator<Item = PeerRouteTarget>,
    {
        self.replace_required_routes_with_revision(targets)
            .map(|_| ())
    }

    /// Replace the required route set and return its new revision.
    ///
    /// Every refresh pass gets a distinct revision, even when the signed
    /// endpoint and pin set is unchanged.  An in-flight result from an older
    /// pass therefore cannot publish into a newer pass merely because it has
    /// the same route key.
    pub fn replace_required_routes_with_revision<I>(
        &self,
        targets: I,
    ) -> Result<PeerReadinessRevision, PeerReadinessError>
    where
        I: IntoIterator<Item = PeerRouteTarget>,
    {
        let mut state = self.state.lock().expect("peer readiness mutex poisoned");
        let mut next = BTreeMap::new();
        for target in targets {
            if next.len() >= MAX_REQUIRED_PEER_ROUTES && !next.contains_key(&target.key()) {
                return Err(PeerReadinessError::TooManyRoutes {
                    observed: next.len().saturating_add(1),
                    maximum: MAX_REQUIRED_PEER_ROUTES,
                });
            }
            let key = target.key();
            let previous = state
                .routes
                .get(&key)
                .filter(|previous| previous.target.same_pins(&target));
            let route_state = previous.map_or(PeerProbeState::Pending, |previous| previous.state);
            let last_probe = previous.and_then(|previous| previous.last_probe);
            let available_capacity = previous.and_then(|previous| previous.available_capacity);
            next.entry(key).or_insert(RequiredRoute {
                target,
                state: route_state,
                last_probe,
                available_capacity,
            });
        }
        let revision = state.revision.saturating_add(1);
        state.routes = next;
        state.routes_known = true;
        state.revision = revision;
        Ok(revision)
    }

    /// Withdraw every reachability and capacity observation while keeping the
    /// currently installed verified route and pin set.
    ///
    /// This is the readiness withdrawal used when the relay's *own* cluster
    /// prerequisites are lost: readiness becomes false and no stale probe can
    /// keep it true, but the verified route set stays installed so the relay
    /// can still answer an authenticated peer's bounded reachability probe.
    /// Dropping the route set instead would make two relays wait on each
    /// other: each side's probe admission would require the other to already
    /// be ready, and neither readiness could ever converge.
    ///
    /// The revision is bumped so an in-flight probe result from before the
    /// withdrawal cannot publish into the withdrawn state.
    pub fn reset_route_probes(&self) {
        let mut state = self.state.lock().expect("peer readiness mutex poisoned");
        state.revision = state.revision.saturating_add(1);
        state.available_capacity = None;
        for route in state.routes.values_mut() {
            route.state = PeerProbeState::Pending;
            route.last_probe = None;
            route.available_capacity = None;
        }
    }

    /// Record a bounded probe result for one required route.
    pub fn record_probe(
        &self,
        target: &PeerRouteTarget,
        probe: PeerProbeState,
    ) -> Result<(), PeerReadinessError> {
        let revision = self.current_revision();
        self.record_probe_at(revision, target, probe).map(|_| ())
    }

    /// Record a probe only if it belongs to the currently installed route
    /// revision.  `false` means the refresh result was stale and was ignored.
    pub fn record_probe_at(
        &self,
        revision: PeerReadinessRevision,
        target: &PeerRouteTarget,
        probe: PeerProbeState,
    ) -> Result<bool, PeerReadinessError> {
        let key = target.key();
        let mut state = self.state.lock().expect("peer readiness mutex poisoned");
        if state.revision != revision {
            return Ok(false);
        }
        let Some(required) = state.routes.get_mut(&key) else {
            return Err(PeerReadinessError::UnknownRoute);
        };
        if !required.target.same_pins(target) {
            return Err(PeerReadinessError::UnknownRoute);
        }
        required.state = probe;
        required.last_probe = (probe == PeerProbeState::Reachable).then(Instant::now);
        required.available_capacity = match probe {
            PeerProbeState::Reachable => Some(1),
            PeerProbeState::CapacityExhausted => Some(0),
            PeerProbeState::Pending | PeerProbeState::Unreachable => None,
        };
        Ok(true)
    }

    /// Return the current route-set revision.
    #[must_use]
    pub fn current_revision(&self) -> PeerReadinessRevision {
        self.state
            .lock()
            .expect("peer readiness mutex poisoned")
            .revision
    }

    /// Publish a bounded route-specific capacity observation.
    ///
    /// Route capacity is independent: updating one route never clears a
    /// capacity failure recorded for another route.
    pub fn set_route_capacity(
        &self,
        target: &PeerRouteTarget,
        available_capacity: usize,
    ) -> Result<(), PeerReadinessError> {
        let revision = self.current_revision();
        self.set_route_capacity_at(revision, target, available_capacity)
            .map(|_| ())
    }

    /// Publish route-specific capacity only for the expected route revision.
    pub fn set_route_capacity_at(
        &self,
        revision: PeerReadinessRevision,
        target: &PeerRouteTarget,
        available_capacity: usize,
    ) -> Result<bool, PeerReadinessError> {
        let key = target.key();
        let mut state = self.state.lock().expect("peer readiness mutex poisoned");
        if state.revision != revision {
            return Ok(false);
        }
        let required_capacity = state.required_capacity;
        let Some(required) = state.routes.get_mut(&key) else {
            return Err(PeerReadinessError::UnknownRoute);
        };
        if !required.target.same_pins(target) {
            return Err(PeerReadinessError::UnknownRoute);
        }
        required.available_capacity = Some(available_capacity);
        if available_capacity < required_capacity {
            required.state = PeerProbeState::CapacityExhausted;
        }
        Ok(true)
    }

    /// Mark a currently required route unavailable after a failed admitted
    /// open.  Unknown routes are ignored because membership may have already
    /// removed them during the same reconciliation pass.
    pub fn mark_route_unreachable(&self, target: &PeerRouteTarget) {
        let key = target.key();
        let mut state = self.state.lock().expect("peer readiness mutex poisoned");
        if let Some(required) = state.routes.get_mut(&key)
            && required.target.matches_route_observation(target)
        {
            required.state = PeerProbeState::Unreachable;
            required.available_capacity = None;
        }
    }

    /// Check whether an authenticated peer certificate belongs to one of the
    /// currently verified route targets.  Probe admission intentionally does
    /// not require the route to have completed its outbound probe: requiring
    /// that would make two relays wait on each other during bootstrap.
    #[must_use]
    pub fn accepts_probe(&self, node_id: &str, spki_sha256: &str) -> bool {
        let state = self.state.lock().expect("peer readiness mutex poisoned");
        state.listener == PeerListenerState::Bound
            && state.routes_known
            && state.routes.values().any(|route| {
                route.target.node_id() == node_id
                    && route
                        .target
                        .approved_spki_sha256()
                        .iter()
                        .any(|pin| pin == spki_sha256)
            })
    }

    /// Return a redacted bounded snapshot.
    #[must_use]
    pub fn snapshot(&self) -> PeerReadinessSnapshot {
        let state = self.state.lock().expect("peer readiness mutex poisoned");
        PeerReadinessSnapshot {
            listener: state.listener,
            routes_known: state.routes_known,
            required_routes: state.routes.len(),
            reachable_routes: state
                .routes
                .values()
                .filter(|route| route.state == PeerProbeState::Reachable)
                .count(),
            capacity_ready_routes: state
                .routes
                .values()
                .filter(|route| {
                    route
                        .available_capacity
                        .is_some_and(|available| available >= state.required_capacity)
                })
                .count(),
            available_capacity: state.available_capacity,
            required_capacity: state.required_capacity,
            revision: state.revision,
        }
    }

    /// Return the redacted probe state for one uniquely identified route.
    ///
    /// A duplicate node identifier is treated as ambiguous and returns
    /// `None`; callers must never infer a route result from an arbitrary
    /// endpoint when the verified route set is malformed.
    #[must_use]
    pub fn route_readiness(&self, node_id: &str) -> Option<PeerRouteReadiness> {
        let state = self.state.lock().expect("peer readiness mutex poisoned");
        let mut matches = state
            .routes
            .values()
            .filter(|route| route.target.node_id() == node_id);
        let route = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some(PeerRouteReadiness {
            node_id: route.target.node_id().to_owned(),
            state: route.state,
        })
    }

    /// Return whether all current bounded peer prerequisites hold.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        let state = self.state.lock().expect("peer readiness mutex poisoned");
        state.listener == PeerListenerState::Bound
            && state.routes_known
            && state.routes.values().all(|route| {
                route.state == PeerProbeState::Reachable
                    && route
                        .last_probe
                        .is_some_and(|last_probe| last_probe.elapsed() <= state.probe_ttl)
                    && route
                        .available_capacity
                        .is_some_and(|available| available >= state.required_capacity)
            })
            && state
                .available_capacity
                .is_some_and(|available| available >= state.required_capacity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(name: &str, pin: &str) -> PeerRouteTarget {
        PeerRouteTarget {
            node_id: name.to_owned(),
            peer_endpoint: format!("10.0.0.{}:8443", name.len()),
            server_name: format!("10.0.0.{}", name.len()),
            approved_spki_sha256: vec![pin.to_owned()],
        }
    }

    #[test]
    fn bootstrap_requires_listener_routes_probes_and_capacity() {
        let readiness = PeerReadiness::new(1).expect("capacity floor");
        let route = target("peer-a", "a");
        readiness
            .replace_required_routes([route.clone()])
            .expect("bounded route set");
        readiness.set_available_capacity(1);
        assert!(!readiness.is_ready(), "unbound listener must fail closed");
        readiness.set_listener_state(PeerListenerState::Bound);
        assert!(!readiness.is_ready(), "unprobed route must fail closed");
        readiness
            .record_probe(&route, PeerProbeState::Reachable)
            .expect("required route");
        assert!(readiness.is_ready());
    }

    #[test]
    fn route_readiness_reports_node_state_without_route_identity_material() {
        let readiness = PeerReadiness::new(1).expect("capacity floor");
        let first = target("peer-a", "a");
        let second = target("peer-b", "b");
        readiness
            .replace_required_routes([first.clone(), second.clone()])
            .expect("bounded route set");
        readiness
            .record_probe(&first, PeerProbeState::Unreachable)
            .expect("first route");
        readiness
            .record_probe(&second, PeerProbeState::Reachable)
            .expect("second route");

        assert_eq!(
            readiness.route_readiness("peer-a"),
            Some(PeerRouteReadiness {
                node_id: "peer-a".to_owned(),
                state: PeerProbeState::Unreachable,
            })
        );
        assert_eq!(
            readiness.route_readiness("peer-b"),
            Some(PeerRouteReadiness {
                node_id: "peer-b".to_owned(),
                state: PeerProbeState::Reachable,
            })
        );
        assert_eq!(readiness.route_readiness("unknown"), None);
    }

    #[test]
    fn route_loss_and_capacity_exhaustion_withdraw_readiness_until_recovery() {
        let readiness = PeerReadiness::new(1).expect("capacity floor");
        let route = target("peer-a", "a");
        readiness
            .replace_required_routes([route.clone()])
            .expect("bounded route set");
        readiness.set_listener_state(PeerListenerState::Bound);
        readiness.set_available_capacity(1);
        readiness
            .record_probe(&route, PeerProbeState::Reachable)
            .expect("required route");
        assert!(readiness.is_ready());

        readiness
            .record_probe(&route, PeerProbeState::CapacityExhausted)
            .expect("required route");
        assert!(!readiness.is_ready());
        readiness.set_available_capacity(0);
        assert!(!readiness.is_ready());

        readiness.set_available_capacity(1);
        readiness
            .record_probe(&route, PeerProbeState::Reachable)
            .expect("fresh probe");
        assert!(readiness.is_ready());
    }

    #[test]
    fn explicit_empty_route_set_is_ready_only_after_installation() {
        let readiness = PeerReadiness::new(1).expect("capacity floor");
        readiness.set_listener_state(PeerListenerState::Bound);
        readiness.set_available_capacity(1);
        assert!(!readiness.is_ready(), "route set is not yet known");
        readiness
            .replace_required_routes([])
            .expect("empty one-node route set");
        assert!(readiness.is_ready());
    }

    #[test]
    fn route_refresh_resets_state_when_signed_pin_set_changes() {
        let readiness = PeerReadiness::new(1).expect("capacity floor");
        let old = target("peer-a", "a");
        let new = target("peer-a", "b");
        readiness
            .replace_required_routes([old.clone()])
            .expect("old route");
        readiness.set_listener_state(PeerListenerState::Bound);
        readiness.set_available_capacity(1);
        readiness
            .record_probe(&old, PeerProbeState::Reachable)
            .expect("old probe");
        assert!(readiness.is_ready());

        readiness
            .replace_required_routes([new.clone()])
            .expect("new route");
        assert!(
            !readiness.is_ready(),
            "key replacement requires a fresh probe"
        );
        readiness
            .record_probe(&new, PeerProbeState::Reachable)
            .expect("new probe");
        assert!(readiness.is_ready());
    }

    #[test]
    fn stale_probe_withdraws_readiness_without_a_refresh_task_tick() {
        let readiness = PeerReadiness::new_with_probe_ttl(1, Duration::from_millis(1))
            .expect("short probe freshness");
        let route = target("peer-a", "a");
        readiness
            .replace_required_routes([route.clone()])
            .expect("bounded route set");
        readiness.set_listener_state(PeerListenerState::Bound);
        readiness.set_available_capacity(1);
        readiness
            .record_probe(&route, PeerProbeState::Reachable)
            .expect("route probe");
        assert!(readiness.is_ready());
        std::thread::sleep(Duration::from_millis(3));
        assert!(
            !readiness.is_ready(),
            "freshness must be monotonic and fail closed"
        );
    }

    #[test]
    fn route_bound_is_capped_without_growing_state() {
        let readiness = PeerReadiness::new(1).expect("capacity floor");
        let routes = (0..=MAX_REQUIRED_PEER_ROUTES)
            .map(|index| target(&format!("peer-{index}"), "a"))
            .collect::<Vec<_>>();
        let error = readiness
            .replace_required_routes(routes)
            .expect_err("route bound");
        assert_eq!(
            error,
            PeerReadinessError::TooManyRoutes {
                observed: MAX_REQUIRED_PEER_ROUTES + 1,
                maximum: MAX_REQUIRED_PEER_ROUTES,
            }
        );
        assert!(!readiness.snapshot().routes_known);
    }

    #[test]
    fn stale_probe_revision_cannot_republish_after_same_target_refresh() {
        let readiness = PeerReadiness::new(1).expect("capacity floor");
        let route = target("peer-a", "a");
        let first = readiness
            .replace_required_routes_with_revision([route.clone()])
            .expect("first route revision");
        readiness.set_listener_state(PeerListenerState::Bound);
        readiness.set_available_capacity(1);
        let second = readiness
            .replace_required_routes_with_revision([route.clone()])
            .expect("second route revision");
        assert!(second > first);
        assert!(
            !readiness
                .record_probe_at(first, &route, PeerProbeState::Reachable)
                .expect("stale result is handled")
        );
        assert!(!readiness.is_ready(), "stale success must not publish");
        assert!(
            readiness
                .record_probe_at(second, &route, PeerProbeState::Reachable)
                .expect("current result is handled")
        );
        assert!(readiness.is_ready());
    }

    #[test]
    fn route_capacity_failures_are_independent() {
        let readiness = PeerReadiness::new(1).expect("capacity floor");
        let first = target("peer-a", "a");
        let second = target("peer-b", "b");
        readiness
            .replace_required_routes([first.clone(), second.clone()])
            .expect("routes");
        readiness.set_listener_state(PeerListenerState::Bound);
        readiness.set_available_capacity(1);
        readiness
            .record_probe(&first, PeerProbeState::Reachable)
            .expect("first route");
        readiness
            .record_probe(&second, PeerProbeState::Reachable)
            .expect("second route");
        assert!(readiness.is_ready());

        readiness
            .record_probe(&second, PeerProbeState::CapacityExhausted)
            .expect("second capacity failure");
        readiness
            .record_probe(&first, PeerProbeState::Reachable)
            .expect("first route remains healthy");
        assert!(
            !readiness.is_ready(),
            "one route capacity failure must gate all"
        );
        assert_eq!(readiness.snapshot().capacity_ready_routes, 1);

        readiness
            .record_probe(&second, PeerProbeState::Reachable)
            .expect("second route recovers");
        assert!(readiness.is_ready());
    }

    #[test]
    fn rotating_pin_set_fences_old_probe_even_when_route_key_is_same() {
        let readiness = PeerReadiness::new(1).expect("capacity floor");
        let old = target("peer-a", "old");
        let new = target("peer-a", "new");
        let old_revision = readiness
            .replace_required_routes_with_revision([old.clone()])
            .expect("old route");
        let new_revision = readiness
            .replace_required_routes_with_revision([new.clone()])
            .expect("rotated route");
        readiness.set_listener_state(PeerListenerState::Bound);
        readiness.set_available_capacity(1);
        assert!(
            !readiness
                .record_probe_at(old_revision, &old, PeerProbeState::Reachable)
                .expect("old result is handled")
        );
        assert!(!readiness.is_ready());
        assert!(
            readiness
                .record_probe_at(new_revision, &new, PeerProbeState::Reachable)
                .expect("new result is handled")
        );
        assert!(readiness.is_ready());
    }

    #[test]
    fn binding_failure_matches_one_pin_inside_signed_overlap_without_accepting_wrong_pin() {
        let readiness = PeerReadiness::new(1).expect("capacity floor");
        let signed = PeerRouteTarget::for_test(
            "peer-a",
            "10.0.0.1:8443",
            "peer-a.internal",
            vec!["old-pin".to_owned(), "next-pin".to_owned()],
        );
        let observed_old = PeerRouteTarget::for_test(
            "peer-a",
            "10.0.0.1:8443",
            "peer-a.internal",
            vec!["old-pin".to_owned()],
        );
        let observed_wrong = PeerRouteTarget::for_test(
            "peer-a",
            "10.0.0.1:8443",
            "peer-a.internal",
            vec!["unapproved-pin".to_owned()],
        );
        readiness
            .replace_required_routes([signed.clone()])
            .expect("signed route");
        readiness.set_listener_state(PeerListenerState::Bound);
        readiness.set_available_capacity(1);
        readiness
            .record_probe(&signed, PeerProbeState::Reachable)
            .expect("signed route probe");
        assert!(readiness.is_ready());

        readiness.mark_route_unreachable(&observed_wrong);
        assert!(readiness.is_ready(), "wrong pin must not mark the route");
        readiness.mark_route_unreachable(&observed_old);
        assert!(
            !readiness.is_ready(),
            "overlap binding must mark route loss"
        );
    }
}
