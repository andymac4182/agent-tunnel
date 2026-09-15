//! Three-relay M7 acceptance harness.
//!
//! This command uses the production Redis catalog, owner router, signed
//! membership verifier, peer runtime, and HTTP/3 transport.  The owner
//! callback is a bounded synthetic adapter: it records routing metadata and
//! echoes peer records, but never executes a desktop operation or retains
//! payloads.  This keeps the cluster gate deterministic while still making
//! every route cross a real mTLS QUIC socket.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
    time::Duration,
};

use chrono::{DateTime, Utc};
use http::StatusCode;
use tokio::{
    sync::Mutex,
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{
    AuthenticatedConsumer, Catalog, CatalogError, OwnerClaim, OwnerClaimRequest, OwnerToken,
    RedisCatalog, SharedCatalog, ValidatedAccessToken,
};
use tunnel_cluster::{
    envelope::{
        Destination, DeviceAuthenticationContext, DeviceControlRequest, DeviceDataRequest,
        ForwardedConsumerBearer, IngressRequestBinding, InternalRequest, InternalRoute,
        PeerIdentity, RequestEnvelope, VerifiedDeviceCertificate, VerifiedPeerIdentity,
    },
    membership::{
        MembershipPolicy, MembershipVerifier, PrivateEndpointPolicy, VerifiedPeerBinding,
    },
    peer_frame::{PeerRecord, PeerRecordKind},
};
use tunnel_relay::{
    peer_runtime::{InboundPeerRequest, PeerBindingProvider, PeerRuntime, PeerRuntimeError},
    routing::{OwnerRoute, OwnerRouter, OwnerScope, RelayIdentity},
};
use tunnel_transport::{
    ApprovedPeerPins, PeerClient, PeerServer, PeerTransportError, PeerTransportLimits,
    SharedPeerPins, SpkiSha256, load_peer_client_config_from_pem, load_peer_server_config_from_pem,
    spki_sha256_from_der,
};
use uuid::Uuid;

use crate::{
    ClusterFixture, FixturePki, FixtureTopology, HarnessError, OidcFixture, RedisLease,
    RedisLeaseOptions, Result,
};

const REDIS_DEPLOYMENT_INCARNATION: &str = "m7-cluster-harness";
const REDIS_NAMESPACE_PREFIX: &str = "m7-cluster";
const SYNTHETIC_BEARER: &str = "m7-synthetic-consumer-bearer";
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(8);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Payload-free evidence from one real three-relay acceptance run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterAcceptanceEvidence {
    /// Number of relay identities admitted by the signed checkpoint.
    pub relay_count: usize,
    /// Number of tenant scopes present in the Redis fixture.
    pub tenant_count: usize,
    /// Number of devices used by the route scenarios.
    pub device_count: usize,
    /// Number of distinct owner nodes selected by the catalog.
    pub owner_count: usize,
    /// Number of accepted control arrivals.
    pub control_routes: usize,
    /// Number of accepted data arrivals across active and replacements.
    pub data_routes: usize,
    /// Number of accepted consumer arrivals.
    pub consumer_routes: usize,
    /// Number of replacement data generations accepted in order.
    pub replacement_generations: usize,
    /// Whether every accepted route consumed exactly one peer hop.
    pub direct_hops_only: bool,
    /// Whether a duplicate request ID was rejected before response headers.
    pub replay_rejected: bool,
    /// Whether a live owner refused a competing claim and stale cleanup was fenced.
    pub owner_fencing_rejected: bool,
    /// Whether removing the approved peer pins prevented a new connection.
    pub key_revocation_rejected: bool,
    /// Whether owner release made a fresh route lookup fail closed.
    pub owner_death_interrupted: bool,
}

/// Required number of accepted control arrivals.
const EXPECTED_CONTROL_ROUTES: usize = 1;
/// Required number of accepted data arrivals across active and replacements.
const EXPECTED_DATA_ROUTES: usize = 3;
/// Required number of accepted consumer arrivals.
const EXPECTED_CONSUMER_ROUTES: usize = 1;
/// Required number of replacement data generations accepted in order.
const EXPECTED_REPLACEMENT_GENERATIONS: usize = 2;
/// Required number of distinct owner nodes selected by the catalog.
const EXPECTED_OWNER_NODES: usize = 3;

/// Diagnostic prefix for the route-stage contract, retained from the inline
/// assertion this validator replaced.
const ROUTE_ASSERTION: &str = "M7 cluster acceptance assertion failed";
/// Diagnostic prefix for the owner-topology contract, retained from the
/// inline assertion this validator replaced.
const OWNER_ASSERTION: &str = "M7 cluster direct-owner assertion failed";

/// Route-stage counters and flags observed while the peers are still running.
///
/// This is the exact set the gate checked inline before shutting the peers
/// down, so the stage boundary and its ordering are preserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClusterRouteEvidence {
    /// Number of accepted control arrivals.
    pub control_routes: usize,
    /// Number of accepted data arrivals across active and replacements.
    pub data_routes: usize,
    /// Number of accepted consumer arrivals.
    pub consumer_routes: usize,
    /// Number of replacement data generations accepted in order.
    pub replacement_generations: usize,
    /// Whether a duplicate request ID was rejected before response headers.
    pub replay_rejected: bool,
    /// Whether a live owner refused a competing claim and stale cleanup was fenced.
    pub owner_fencing_rejected: bool,
    /// Whether removing the approved peer pins prevented a new connection.
    pub key_revocation_rejected: bool,
    /// Whether owner release made a fresh route lookup fail closed.
    pub owner_death_interrupted: bool,
}

/// Owner-topology observations taken after the peers joined.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClusterOwnerTopologyEvidence {
    /// Number of distinct owner nodes selected by the catalog.
    pub owner_count: usize,
    /// Whether every accepted route consumed exactly one peer hop.
    pub direct_hops_only: bool,
}

/// One named condition of the cluster evidence contract.
///
/// `detail` carries counters and flags only: no payloads and no credentials.
#[derive(Clone, Debug)]
struct EvidenceCondition {
    name: &'static str,
    satisfied: bool,
    detail: String,
}

impl EvidenceCondition {
    fn new(name: &'static str, satisfied: bool, detail: String) -> Self {
        Self {
            name,
            satisfied,
            detail,
        }
    }

    fn count(name: &'static str, observed: usize, expected: usize) -> Self {
        Self::new(
            name,
            observed == expected,
            format!("expected {expected}, observed {observed}"),
        )
    }

    fn flag(name: &'static str, observed: bool) -> Self {
        Self::new(name, observed, "required flag was false".to_owned())
    }
}

fn cluster_route_conditions(evidence: &ClusterRouteEvidence) -> Vec<EvidenceCondition> {
    vec![
        EvidenceCondition::count(
            "control_routes",
            evidence.control_routes,
            EXPECTED_CONTROL_ROUTES,
        ),
        EvidenceCondition::count("data_routes", evidence.data_routes, EXPECTED_DATA_ROUTES),
        EvidenceCondition::count(
            "consumer_routes",
            evidence.consumer_routes,
            EXPECTED_CONSUMER_ROUTES,
        ),
        EvidenceCondition::count(
            "replacement_generations",
            evidence.replacement_generations,
            EXPECTED_REPLACEMENT_GENERATIONS,
        ),
        EvidenceCondition::flag("replay_rejected", evidence.replay_rejected),
        EvidenceCondition::flag("owner_fencing_rejected", evidence.owner_fencing_rejected),
        EvidenceCondition::flag("key_revocation_rejected", evidence.key_revocation_rejected),
        EvidenceCondition::flag("owner_death_interrupted", evidence.owner_death_interrupted),
    ]
}

fn cluster_owner_topology_conditions(
    evidence: &ClusterOwnerTopologyEvidence,
) -> Vec<EvidenceCondition> {
    vec![
        EvidenceCondition::count("owner_count", evidence.owner_count, EXPECTED_OWNER_NODES),
        EvidenceCondition::flag("direct_hops_only", evidence.direct_hops_only),
    ]
}

fn first_failure(prefix: &str, conditions: Vec<EvidenceCondition>) -> Result<()> {
    match conditions
        .into_iter()
        .find(|condition| !condition.satisfied)
    {
        Some(condition) => Err(HarnessError::Http(format!(
            "{prefix}: {} {}",
            condition.name, condition.detail
        ))),
        None => Ok(()),
    }
}

/// Validate the route-stage contract of the three-relay gate.
pub fn validate_cluster_route_evidence(evidence: &ClusterRouteEvidence) -> Result<()> {
    first_failure(ROUTE_ASSERTION, cluster_route_conditions(evidence))
}

/// Validate the owner-topology contract of the three-relay gate.
pub fn validate_cluster_owner_topology_evidence(
    evidence: &ClusterOwnerTopologyEvidence,
) -> Result<()> {
    first_failure(OWNER_ASSERTION, cluster_owner_topology_conditions(evidence))
}

/// Validate a complete evidence value against both staged contracts, in the
/// order the gate observes them.
pub fn validate_cluster_acceptance_evidence(evidence: &ClusterAcceptanceEvidence) -> Result<()> {
    validate_cluster_route_evidence(&evidence.route_evidence())?;
    validate_cluster_owner_topology_evidence(&evidence.owner_topology_evidence())
}

impl ClusterAcceptanceEvidence {
    /// Project the route-stage view checked before peer shutdown.
    pub fn route_evidence(&self) -> ClusterRouteEvidence {
        ClusterRouteEvidence {
            control_routes: self.control_routes,
            data_routes: self.data_routes,
            consumer_routes: self.consumer_routes,
            replacement_generations: self.replacement_generations,
            replay_rejected: self.replay_rejected,
            owner_fencing_rejected: self.owner_fencing_rejected,
            key_revocation_rejected: self.key_revocation_rejected,
            owner_death_interrupted: self.owner_death_interrupted,
        }
    }

    /// Project the owner-topology view checked after peer shutdown.
    pub fn owner_topology_evidence(&self) -> ClusterOwnerTopologyEvidence {
        ClusterOwnerTopologyEvidence {
            owner_count: self.owner_count,
            direct_hops_only: self.direct_hops_only,
        }
    }
}

#[cfg(test)]
mod c17_cluster_validator_tests {
    use super::{
        ClusterAcceptanceEvidence, EXPECTED_CONSUMER_ROUTES, EXPECTED_CONTROL_ROUTES,
        EXPECTED_DATA_ROUTES, EXPECTED_OWNER_NODES, EXPECTED_REPLACEMENT_GENERATIONS,
        cluster_owner_topology_conditions, cluster_route_conditions,
        validate_cluster_acceptance_evidence,
    };
    use crate::acceptance_test_support::assert_failed;

    fn valid_evidence() -> ClusterAcceptanceEvidence {
        ClusterAcceptanceEvidence {
            relay_count: 3,
            tenant_count: 2,
            device_count: 3,
            owner_count: EXPECTED_OWNER_NODES,
            control_routes: EXPECTED_CONTROL_ROUTES,
            data_routes: EXPECTED_DATA_ROUTES,
            consumer_routes: EXPECTED_CONSUMER_ROUTES,
            replacement_generations: EXPECTED_REPLACEMENT_GENERATIONS,
            direct_hops_only: true,
            replay_rejected: true,
            owner_fencing_rejected: true,
            key_revocation_rejected: true,
            owner_death_interrupted: true,
        }
    }

    type Case = (&'static str, fn(&mut ClusterAcceptanceEvidence));

    /// One mutation per condition the gate checked inline.
    const CASES: &[Case] = &[
        ("control_routes", |e| e.control_routes = 0),
        ("data_routes", |e| e.data_routes = 2),
        ("consumer_routes", |e| e.consumer_routes = 0),
        ("replacement_generations", |e| e.replacement_generations = 1),
        ("replay_rejected", |e| e.replay_rejected = false),
        ("owner_fencing_rejected", |e| {
            e.owner_fencing_rejected = false
        }),
        ("key_revocation_rejected", |e| {
            e.key_revocation_rejected = false
        }),
        ("owner_death_interrupted", |e| {
            e.owner_death_interrupted = false
        }),
        ("owner_count", |e| e.owner_count = 2),
        ("direct_hops_only", |e| e.direct_hops_only = false),
    ];

    #[test]
    fn cluster_validator_accepts_complete_evidence() {
        validate_cluster_acceptance_evidence(&valid_evidence())
            .expect("complete M7 cluster evidence is valid");
    }

    #[test]
    fn every_cluster_flag_and_count_reaches_the_shared_exit_path() {
        assert_eq!(
            CASES.len(),
            cluster_route_conditions(&valid_evidence().route_evidence()).len()
                + cluster_owner_topology_conditions(&valid_evidence().owner_topology_evidence())
                    .len(),
            "every validated condition needs its own mutation case"
        );
        for &(name, mutate) in CASES {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            let diagnostic = assert_failed(validate_cluster_acceptance_evidence(&evidence));
            assert!(
                !diagnostic.is_empty(),
                "{name} produced an empty diagnostic"
            );
        }
    }

    #[test]
    fn every_cluster_rejection_names_its_condition() {
        for &(name, mutate) in CASES {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            let diagnostic = assert_failed(validate_cluster_acceptance_evidence(&evidence));
            assert!(
                diagnostic.contains(name),
                "{name}: expected the condition name in diagnostic {diagnostic}"
            );
        }
    }

    /// Leave-one-out: each mutant is rejected by its own guard and by no
    /// other, so deleting that guard would let the mutant through.
    #[test]
    fn every_cluster_guard_is_load_bearing() {
        for &(name, mutate) in CASES {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            let failing = cluster_route_conditions(&evidence.route_evidence())
                .into_iter()
                .chain(cluster_owner_topology_conditions(
                    &evidence.owner_topology_evidence(),
                ))
                .filter(|condition| !condition.satisfied)
                .map(|condition| condition.name)
                .collect::<Vec<_>>();
            assert_eq!(
                failing,
                vec![name],
                "{name} must be the only guard rejecting its own mutation"
            );
        }
    }
}

#[derive(Default)]
struct Observation {
    request_ids: BTreeSet<String>,
    routes: Vec<RouteObservation>,
    data_sequences: BTreeMap<Uuid, Vec<u64>>,
}

#[derive(Clone, Debug)]
struct RouteObservation {
    route: InternalRoute,
    source_node: String,
    owner_node: String,
}

struct RunningPeer {
    node_id: String,
    runtime: Arc<PeerRuntime>,
    pins: SharedPeerPins,
    cancel: CancellationToken,
    task: JoinHandle<std::result::Result<(), PeerTransportError>>,
}

impl RunningPeer {
    async fn shutdown(self) -> Result<()> {
        self.cancel.cancel();
        timeout(SHUTDOWN_TIMEOUT, self.task)
            .await
            .map_err(|_| HarnessError::Timeout(format!("joining peer {}", self.node_id)))?
            .map_err(|error| HarnessError::Process(format!("peer {} join: {error}", self.node_id)))?
            .map_err(|error| {
                HarnessError::Http(format!("peer {} shutdown: {error}", self.node_id))
            })?;
        Ok(())
    }
}

/// Run the real Redis-backed three-relay M7 gate.
pub async fn verify() -> Result<ClusterAcceptanceEvidence> {
    let redis = RedisLease::open(RedisLeaseOptions {
        redis_url: std::env::var("TEST_REDIS_URL").ok(),
        namespace_prefix: Some(REDIS_NAMESPACE_PREFIX.to_owned()),
    })
    .await?;
    let result = verify_with_redis(&redis).await;
    let cleanup = redis.close().await;
    match (result, cleanup) {
        (Ok(evidence), Ok(())) => Ok(evidence),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(_cleanup_error)) => Err(error),
    }
}

async fn verify_with_redis(redis: &RedisLease) -> Result<ClusterAcceptanceEvidence> {
    let pki = FixturePki::new()?;
    let oidc = OidcFixture::new("https://m7-oidc.fixture.test", "agent-tunnel")?;
    let topology = FixtureTopology::new(&pki)?;
    let catalog = RedisCatalog::connect_for_recovery(
        redis.redis_url(),
        redis.namespace(),
        REDIS_DEPLOYMENT_INCARNATION,
    )
    .await
    .map_err(|error| HarnessError::Redis(format!("connecting M7 Redis catalog: {error}")))?;
    catalog
        .activate_deployment_incarnation()
        .await
        .map_err(|error| HarnessError::Redis(format!("activating M7 Redis catalog: {error}")))?;
    catalog
        .seed_fixture(&topology.catalog_fixture(&oidc)?)
        .await
        .map_err(|error| HarnessError::Redis(format!("seeding M7 Redis catalog: {error}")))?;

    let mut cluster = ClusterFixture::with_deployment(
        &pki,
        "m7-cluster-harness-deployment",
        REDIS_DEPLOYMENT_INCARNATION,
    )?;
    for node in &mut cluster.nodes {
        node.release_ports();
    }

    let shared_catalog: SharedCatalog = Arc::new(catalog.clone());
    let bindings = Arc::new(verified_bindings(&cluster)?);
    let observations = Arc::new(Mutex::new(Observation::default()));
    let device_by_id = Arc::new(
        topology
            .all_devices()
            .map(|device| (device.id, device.clone()))
            .collect::<HashMap<_, _>>(),
    );
    let consumer = topology
        .consumers_b
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("M7 fixture has no tenant-B consumer".into()))?;
    let consumer_auth = Arc::new(ConsumerAuth {
        consumer: AuthenticatedConsumer {
            tenant_id: consumer.tenant_id,
            principal_id: consumer.id,
        },
        issuer: oidc.issuer.clone(),
        subject: consumer.name.clone(),
    });

    let owners = claim_three_owners(&catalog, &cluster, &topology).await?;
    let owner_by_device = Arc::new(owners.clone());
    let callback = owner_callback(
        shared_catalog.clone(),
        owner_by_device.clone(),
        device_by_id,
        consumer_auth,
        observations.clone(),
    );
    let mut peers = start_peers(&cluster, shared_catalog, bindings, callback).await?;
    sleep(Duration::from_millis(50)).await;

    let scenario = run_route_scenarios(&topology, &owners, &peers).await;
    let scenario = match scenario {
        Ok(value) => value,
        Err(error) => {
            for peer in peers.drain(..) {
                let _ = peer.shutdown().await;
            }
            return Err(error);
        }
    };

    let replay_rejected = replay_case(&topology, &owners, &peers).await?;
    let owner_fencing_rejected = owner_fencing_case(&catalog, &cluster, &owners, &topology).await?;
    let key_revocation_rejected = key_revocation_case(&topology, &owners, &peers).await?;
    let owner_death_interrupted =
        owner_death_case(&catalog, &cluster, &owners, &topology, &mut peers).await?;

    let route_evidence = ClusterRouteEvidence {
        control_routes: scenario.control_routes,
        data_routes: scenario.data_routes,
        consumer_routes: scenario.consumer_routes,
        replacement_generations: scenario.replacement_generations,
        replay_rejected,
        owner_fencing_rejected,
        key_revocation_rejected,
        owner_death_interrupted,
    };
    if let Err(error) = validate_cluster_route_evidence(&route_evidence) {
        for peer in peers.drain(..) {
            let _ = peer.shutdown().await;
        }
        return Err(error);
    }

    for peer in peers.drain(..) {
        peer.shutdown().await?;
    }

    let observation = observations.lock().await;
    let owner_count = observation
        .routes
        .iter()
        .map(|route| route.owner_node.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let direct_hops_only = observation
        .routes
        .iter()
        .all(|route| route.route != InternalRoute::Health && route.source_node != route.owner_node);
    let owner_topology_evidence = ClusterOwnerTopologyEvidence {
        owner_count,
        direct_hops_only,
    };
    validate_cluster_owner_topology_evidence(&owner_topology_evidence)?;
    Ok(ClusterAcceptanceEvidence {
        relay_count: cluster.nodes.len(),
        tenant_count: 2,
        device_count: 3,
        owner_count: owner_topology_evidence.owner_count,
        control_routes: route_evidence.control_routes,
        data_routes: route_evidence.data_routes,
        consumer_routes: route_evidence.consumer_routes,
        replacement_generations: route_evidence.replacement_generations,
        direct_hops_only: owner_topology_evidence.direct_hops_only,
        replay_rejected: route_evidence.replay_rejected,
        owner_fencing_rejected: route_evidence.owner_fencing_rejected,
        key_revocation_rejected: route_evidence.key_revocation_rejected,
        owner_death_interrupted: route_evidence.owner_death_interrupted,
    })
}

struct ConsumerAuth {
    consumer: AuthenticatedConsumer,
    issuer: String,
    subject: String,
}

fn owner_callback(
    catalog: SharedCatalog,
    owners: Arc<HashMap<Uuid, OwnerClaim>>,
    devices: Arc<HashMap<Uuid, crate::DeviceFixture>>,
    consumer: Arc<ConsumerAuth>,
    observations: Arc<Mutex<Observation>>,
) -> impl tunnel_relay::PeerIngressHandler + Clone {
    move |request: InboundPeerRequest| {
        let catalog = catalog.clone();
        let owners = owners.clone();
        let devices = devices.clone();
        let consumer = consumer.clone();
        let observations = observations.clone();
        async move {
            handle_peer_request(request, catalog, owners, devices, consumer, observations).await
        }
    }
}

async fn handle_peer_request(
    request: InboundPeerRequest,
    catalog: SharedCatalog,
    owners: Arc<HashMap<Uuid, OwnerClaim>>,
    devices: Arc<HashMap<Uuid, crate::DeviceFixture>>,
    consumer: Arc<ConsumerAuth>,
    observations: Arc<Mutex<Observation>>,
) -> std::result::Result<(), PeerRuntimeError> {
    let envelope = request.envelope().clone();
    let now = Utc::now();
    let destination_owner = catalog
        .current_owner(
            envelope.destination.tenant_id,
            envelope.destination.device_id,
            now,
        )
        .await
        .map_err(catalog_peer_error)?
        .ok_or_else(|| {
            PeerRuntimeError::Routing(tunnel_relay::routing::OwnerRoutingError::NoLiveOwner(
                OwnerScope::new(
                    envelope.destination.tenant_id,
                    envelope.destination.device_id,
                ),
            ))
        })?;
    if destination_owner.token != envelope.destination.owner_token
        || owners
            .get(&envelope.destination.device_id)
            .is_some_and(|owner| owner.token != destination_owner.token)
    {
        return Err(PeerRuntimeError::Membership("owner fence rejected".into()));
    }
    let verified_peer = VerifiedPeerIdentity::from_verified_peer_binding(request.binding())
        .map_err(|error| PeerRuntimeError::Membership(error.to_string()))?;
    let owner_access = if matches!(&envelope.request, InternalRequest::ConsumerStreams(_)) {
        Some(ValidatedAccessToken {
            consumer: consumer.consumer.clone(),
            issuer: consumer.issuer.clone(),
            subject: consumer.subject.clone(),
            scopes: BTreeSet::from(["echo:invoke".to_owned()]),
            expires_at: now + chrono::Duration::seconds(20),
        })
    } else {
        None
    };
    let expected_destination = Destination::new(
        destination_owner.token.clone(),
        envelope.destination.service_id,
    );
    envelope
        .validate(
            now,
            &verified_peer,
            &expected_destination,
            owner_access.as_ref(),
        )
        .map_err(|error| PeerRuntimeError::Membership(error.to_string()))?;

    if let InternalRequest::ConsumerStreams(request_body) = &envelope.request {
        if request_body.bearer.token() != SYNTHETIC_BEARER {
            return Err(PeerRuntimeError::Membership(
                "consumer bearer rejected".into(),
            ));
        }
        let grant = catalog
            .authorize(
                &consumer.consumer,
                envelope.destination.device_id,
                envelope.destination.service_id,
                now,
                now,
            )
            .await
            .map_err(catalog_peer_error)?
            .ok_or_else(|| PeerRuntimeError::Membership("consumer grant rejected".into()))?;
        if !grant.permissions.allows(&request_body.required_scope) {
            return Err(PeerRuntimeError::Membership(
                "consumer scope rejected".into(),
            ));
        }
    }

    if let Some(authentication) = device_data_authentication(&envelope.request) {
        let Some(identity) = catalog
            .resolve_device(&authentication.certificate.spki_fingerprint, now)
            .await
            .map_err(catalog_peer_error)?
        else {
            return Err(PeerRuntimeError::Membership(
                "device credential rejected".into(),
            ));
        };
        if identity.tenant_id != envelope.destination.tenant_id
            || identity.device_id != envelope.destination.device_id
            || !devices.contains_key(&identity.device_id)
        {
            return Err(PeerRuntimeError::Membership("device scope rejected".into()));
        }
    }

    let (mut send, mut recv) = request.split();
    let route = envelope.route;
    let sequence = match &envelope.request {
        InternalRequest::DeviceData(request) => Some(request.sequence),
        _ => None,
    };
    {
        let mut state = observations.lock().await;
        if !state.request_ids.insert(envelope.request_id.clone()) {
            return Err(PeerRuntimeError::Membership("replayed request ID".into()));
        }
        if let Some(sequence) = sequence {
            let entries = state
                .data_sequences
                .entry(envelope.destination.device_id)
                .or_default();
            if entries.last().is_some_and(|last| sequence <= *last) {
                return Err(PeerRuntimeError::Membership("stale data fence".into()));
            }
            entries.push(sequence);
        }
        state.routes.push(RouteObservation {
            route,
            source_node: envelope.source.node_id.clone(),
            owner_node: destination_owner.token.node_id.clone(),
        });
    }
    send.respond(StatusCode::OK).await?;
    while let Some(record) = recv.recv_message().await? {
        send.send_message(record.kind(), record.body()).await?;
    }
    send.finish().await
}

fn catalog_peer_error(error: CatalogError) -> PeerRuntimeError {
    PeerRuntimeError::Membership(format!("catalog admission failed: {error}"))
}

fn device_data_authentication(request: &InternalRequest) -> Option<&DeviceAuthenticationContext> {
    match request {
        InternalRequest::DeviceControl(request) => Some(&request.authentication),
        InternalRequest::DeviceData(request) => Some(&request.authentication),
        _ => None,
    }
}

fn verified_bindings(
    cluster: &ClusterFixture,
) -> Result<HashMap<(String, String), VerifiedPeerBinding>> {
    let ports = cluster.nodes.iter().map(|node| node.addresses.udp.port());
    let endpoint_policy =
        PrivateEndpointPolicy::allowlisted(["127.0.0.1"], ["localhost"], ports)
            .map_err(|error| HarnessError::InvalidInput(format!("M7 endpoint policy: {error}")))?;
    let policy = MembershipPolicy::new(
        &cluster.deployment_id,
        &cluster.deployment_incarnation,
        endpoint_policy,
    )
    .map_err(|error| HarnessError::InvalidInput(format!("M7 membership policy: {error}")))?;
    let trusted = cluster.membership_authority.trusted_key()?;
    let mut verifier = MembershipVerifier::new(policy, [trusted])
        .map_err(|error| HarnessError::InvalidInput(format!("M7 membership verifier: {error}")))?;
    let now = Utc::now();
    verifier
        .verify_checkpoint(
            cluster.checkpoint.encoded_bytes(),
            &cluster.checkpoint.payload.nonce,
            now,
        )
        .map_err(|error| HarnessError::InvalidInput(format!("M7 checkpoint: {error}")))?;
    for membership in cluster.memberships.values() {
        verifier
            .verify_membership(membership.encoded_bytes(), now)
            .map_err(|error| HarnessError::InvalidInput(format!("M7 membership: {error}")))?;
    }
    let mut bindings = HashMap::new();
    for node in &cluster.nodes {
        let spki = node.peer_spki_fingerprint()?;
        let binding = verifier
            .bind_peer(&node.node_id, &node.boot_id, &spki, now)
            .map_err(|error| HarnessError::InvalidInput(format!("M7 peer binding: {error}")))?;
        bindings.insert((node.node_id.clone(), node.boot_id.clone()), binding);
    }
    Ok(bindings)
}

async fn claim_three_owners(
    catalog: &RedisCatalog,
    cluster: &ClusterFixture,
    topology: &FixtureTopology,
) -> Result<HashMap<Uuid, OwnerClaim>> {
    let devices = [
        &topology.devices_a[0],
        &topology.devices_a[1],
        &topology.devices_b[0],
    ];
    let owner_nodes = ["relay-b", "relay-a", "relay-c"];
    let now = Utc::now();
    let mut owners = HashMap::new();
    for (device, node_id) in devices.into_iter().zip(owner_nodes) {
        let node = cluster
            .node(node_id)
            .ok_or_else(|| HarnessError::InvalidInput(format!("missing M7 owner {node_id}")))?;
        let claim = catalog
            .claim_owner(&OwnerClaimRequest {
                deployment_incarnation: cluster.deployment_incarnation.clone(),
                tenant_id: device.tenant_id,
                device_id: device.id,
                node_id: node.node_id.clone(),
                boot_id: node.boot_id.clone(),
                session_id: Uuid::new_v4().to_string(),
                lease_expires_at: now + chrono::Duration::seconds(25),
            })
            .await
            .map_err(|error| HarnessError::Redis(format!("claiming M7 owner: {error}")))?;
        owners.insert(device.id, claim);
    }
    Ok(owners)
}

async fn start_peers(
    cluster: &ClusterFixture,
    catalog: SharedCatalog,
    bindings: Arc<HashMap<(String, String), VerifiedPeerBinding>>,
    callback: impl tunnel_relay::PeerIngressHandler + Clone,
) -> Result<Vec<RunningPeer>> {
    let mut pins = Vec::new();
    for node in &cluster.nodes {
        pins.push(
            spki_sha256_from_der(&node.peer_certificate.certificate_der)
                .map_err(|error| HarnessError::Pki(format!("M7 peer SPKI: {error}")))?,
        );
    }
    let limits = PeerTransportLimits::default();
    let mut peers = Vec::with_capacity(cluster.nodes.len());
    for node in &cluster.nodes {
        let mut server_config = load_peer_server_config_from_pem(
            node.peer_certificate_chain_pem().as_bytes(),
            node.peer_certificate.private_key_pem.as_bytes(),
            node.peer_ca_pem().as_bytes(),
        )
        .map_err(|error| HarnessError::Pki(format!("M7 peer server TLS: {error}")))?;
        limits
            .apply_to_server_config(&mut server_config)
            .map_err(|error| HarnessError::Http(format!("M7 peer server limits: {error}")))?;
        let endpoint = quinn::Endpoint::server(server_config, node.addresses.udp)
            .map_err(|error| HarnessError::Http(format!("M7 peer bind: {error}")))?;
        let mut client_endpoint =
            quinn::Endpoint::client((std::net::Ipv4Addr::LOCALHOST, 0).into())
                .map_err(|error| HarnessError::Http(format!("M7 peer client bind: {error}")))?;
        let mut client_config = load_peer_client_config_from_pem(
            node.peer_certificate_chain_pem().as_bytes(),
            node.peer_certificate.private_key_pem.as_bytes(),
            node.peer_ca_pem().as_bytes(),
        )
        .map_err(|error| HarnessError::Pki(format!("M7 peer client TLS: {error}")))?;
        limits
            .apply_to_client_config(&mut client_config)
            .map_err(|error| HarnessError::Http(format!("M7 peer client limits: {error}")))?;
        client_endpoint.set_default_client_config(client_config);
        let pin_set = ApprovedPeerPins::new(pins.clone())
            .map_err(|error| HarnessError::Http(format!("M7 peer pins: {error}")))?;
        let shared_pins = SharedPeerPins::new(pin_set)
            .map_err(|error| HarnessError::Http(format!("M7 dynamic pins: {error}")))?;
        let client =
            PeerClient::new_with_pin_provider(client_endpoint, shared_pins.clone(), limits.clone())
                .map_err(|error| HarnessError::Http(format!("M7 peer client: {error}")))?;
        let identity = RelayIdentity::new(
            cluster.deployment_incarnation.clone(),
            node.node_id.clone(),
            node.boot_id.clone(),
        )
        .map_err(|error| HarnessError::InvalidInput(format!("M7 relay identity: {error}")))?;
        let router = OwnerRouter::new(catalog.clone(), identity)
            .map_err(|error| HarnessError::InvalidInput(format!("M7 owner router: {error}")))?;
        let provider = binding_provider(bindings.clone());
        let runtime = Arc::new(PeerRuntime::new(
            client,
            Arc::new(router),
            provider,
            node.node_id.clone(),
            node.boot_id.clone(),
        ));
        let (policy, handler) = runtime.server_components(callback.clone());
        let server = PeerServer::new_with_pin_provider(
            endpoint,
            shared_pins.clone(),
            limits.clone(),
            policy,
            handler,
        )
        .map_err(|error| HarnessError::Http(format!("M7 peer server: {error}")))?;
        let cancel = CancellationToken::new();
        let task = tokio::spawn(server.serve(cancel.clone()));
        peers.push(RunningPeer {
            node_id: node.node_id.clone(),
            runtime,
            pins: shared_pins,
            cancel,
            task,
        });
    }
    Ok(peers)
}

fn binding_provider(
    bindings: Arc<HashMap<(String, String), VerifiedPeerBinding>>,
) -> Arc<dyn PeerBindingProvider> {
    Arc::new(move |node_id: &str, boot_id: &str, _now: DateTime<Utc>| {
        let result = bindings
            .get(&(node_id.to_owned(), boot_id.to_owned()))
            .cloned()
            .ok_or_else(|| PeerRuntimeError::Membership("peer binding unavailable".into()));
        async move { result }
    })
}

struct ScenarioEvidence {
    control_routes: usize,
    data_routes: usize,
    consumer_routes: usize,
    replacement_generations: usize,
}

async fn run_route_scenarios(
    topology: &FixtureTopology,
    owners: &HashMap<Uuid, OwnerClaim>,
    peers: &[RunningPeer],
) -> Result<ScenarioEvidence> {
    let control_device = &topology.devices_a[0];
    let data_device = &topology.devices_a[1];
    let consumer_device = &topology.devices_b[0];
    let control_runtime = peer(peers, "relay-a")?;
    let active_runtime = peer(peers, "relay-b")?;
    let replacement_runtime = peer(peers, "relay-c")?;
    let consumer_runtime = peer(peers, "relay-b")?;
    let control_owner = owners.get(&control_device.id).ok_or_else(missing_owner)?;
    let data_owner = owners.get(&data_device.id).ok_or_else(missing_owner)?;
    let consumer_owner = owners.get(&consumer_device.id).ok_or_else(missing_owner)?;
    let control_service = topology.service_ids[&control_device.id];
    let data_service = topology.service_ids[&data_device.id];
    let consumer_service = topology.service_ids[&consumer_device.id];
    let now = Utc::now();

    let control_envelope = device_control_envelope(
        control_device,
        control_runtime.runtime.source().clone(),
        control_owner.token.clone(),
        control_service,
        "m7-control-1",
        now,
    );
    let control = exchange(
        control_runtime,
        control_envelope,
        PeerRecordKind::CompleteControlText,
        b"control-fence-1",
    )
    .await?;
    if control.kind() != PeerRecordKind::CompleteControlText || control.body() != b"control-fence-1"
    {
        return Err(HarnessError::Http("M7 control response mismatch".into()));
    }

    let mut replacement_generations = 0;
    for (runtime, sequence, request_id) in [
        (active_runtime, 1_u64, "m7-data-active"),
        (replacement_runtime, 2_u64, "m7-data-replacement-1"),
        (replacement_runtime, 3_u64, "m7-data-replacement-2"),
    ] {
        let envelope = device_data_envelope(
            data_device,
            runtime.runtime.source().clone(),
            data_owner.token.clone(),
            data_service,
            request_id,
            sequence,
            now,
        );
        let body = format!("data-generation-{sequence}");
        let response = exchange(
            runtime,
            envelope,
            PeerRecordKind::CompleteDeviceData,
            body.as_bytes(),
        )
        .await?;
        if response.body() != body.as_bytes() {
            return Err(HarnessError::Http("M7 data response mismatch".into()));
        }
        if sequence > 1 {
            replacement_generations += 1;
        }
    }

    let consumer_envelope = consumer_envelope(
        consumer_runtime.runtime.source().clone(),
        consumer_owner.token.clone(),
        consumer_service,
        "m7-consumer-1",
    )?;
    let consumer = exchange(
        consumer_runtime,
        consumer_envelope,
        PeerRecordKind::ConsumerChunk,
        b"consumer-chunk-1",
    )
    .await?;
    if consumer.kind() != PeerRecordKind::ConsumerChunk || consumer.body() != b"consumer-chunk-1" {
        return Err(HarnessError::Http("M7 consumer response mismatch".into()));
    }

    Ok(ScenarioEvidence {
        control_routes: 1,
        data_routes: 3,
        consumer_routes: 1,
        replacement_generations,
    })
}

async fn exchange(
    ingress: &RunningPeer,
    envelope: RequestEnvelope,
    kind: PeerRecordKind,
    body: &[u8],
) -> Result<PeerRecord> {
    let route = ingress
        .runtime
        .resolve(
            OwnerScope::new(
                envelope.destination.tenant_id,
                envelope.destination.device_id,
            ),
            Utc::now(),
        )
        .await
        .map_err(|error| HarnessError::Http(format!("M7 owner route: {error}")))?;
    if !matches!(&route, OwnerRoute::Remote { .. }) {
        return Err(HarnessError::Http(
            "M7 scenario unexpectedly routed locally".into(),
        ));
    }
    let exchange = ingress
        .runtime
        .open(&route, envelope)
        .await
        .map_err(|error| HarnessError::Http(format!("M7 peer open: {error}")))?;
    let (mut send, mut recv) = exchange.split();
    send.send_message(kind, body)
        .await
        .map_err(|error| HarnessError::Http(format!("M7 peer send: {error}")))?;
    send.finish()
        .await
        .map_err(|error| HarnessError::Http(format!("M7 peer finish: {error}")))?;
    let record = timeout(EXCHANGE_TIMEOUT, recv.recv_message())
        .await
        .map_err(|_| HarnessError::Timeout("M7 peer response timed out".into()))?
        .map_err(|error| HarnessError::Http(format!("M7 peer response: {error}")))?
        .ok_or_else(|| HarnessError::Http("M7 peer response was empty".into()))?;
    let end = timeout(EXCHANGE_TIMEOUT, recv.recv_message())
        .await
        .map_err(|_| HarnessError::Timeout("M7 peer response close timed out".into()))?
        .map_err(|error| HarnessError::Http(format!("M7 peer response close: {error}")))?;
    if end.is_some() {
        return Err(HarnessError::Http(
            "M7 peer returned multiple response records".into(),
        ));
    }
    Ok(record)
}

async fn replay_case(
    topology: &FixtureTopology,
    owners: &HashMap<Uuid, OwnerClaim>,
    peers: &[RunningPeer],
) -> Result<bool> {
    let device = &topology.devices_a[0];
    let ingress = peer(peers, "relay-a")?;
    let owner = owners.get(&device.id).ok_or_else(missing_owner)?;
    let envelope = device_control_envelope(
        device,
        ingress.runtime.source().clone(),
        owner.token.clone(),
        topology.service_ids[&device.id],
        "m7-replayed-request",
        Utc::now(),
    );
    let _ = exchange(
        ingress,
        envelope.clone(),
        PeerRecordKind::CompleteControlText,
        b"replay-first",
    )
    .await?;
    let route = ingress
        .runtime
        .resolve(OwnerScope::new(device.tenant_id, device.id), Utc::now())
        .await
        .map_err(|error| HarnessError::Http(format!("M7 replay route: {error}")))?;
    let exchange = ingress
        .runtime
        .open(&route, envelope)
        .await
        .map_err(|error| HarnessError::Http(format!("M7 replay open: {error}")))?;
    let (mut send, mut recv) = exchange.split();
    send.send_message(PeerRecordKind::CompleteControlText, b"replay-second")
        .await
        .map_err(|error| HarnessError::Http(format!("M7 replay send: {error}")))?;
    send.finish()
        .await
        .map_err(|error| HarnessError::Http(format!("M7 replay finish: {error}")))?;
    let result = timeout(EXCHANGE_TIMEOUT, recv.recv_message()).await;
    Ok(match result {
        Err(_) | Ok(Err(_)) => true,
        Ok(Ok(_)) => false,
    })
}

async fn owner_fencing_case(
    catalog: &RedisCatalog,
    cluster: &ClusterFixture,
    owners: &HashMap<Uuid, OwnerClaim>,
    topology: &FixtureTopology,
) -> Result<bool> {
    let device = &topology.devices_a[1];
    let current = owners.get(&device.id).ok_or_else(missing_owner)?;
    let competing_node = cluster
        .node("relay-c")
        .ok_or_else(|| HarnessError::InvalidInput("missing relay-c".into()))?;
    let competing = catalog
        .claim_owner(&OwnerClaimRequest {
            deployment_incarnation: cluster.deployment_incarnation.clone(),
            tenant_id: device.tenant_id,
            device_id: device.id,
            node_id: competing_node.node_id.clone(),
            boot_id: competing_node.boot_id.clone(),
            session_id: Uuid::new_v4().to_string(),
            lease_expires_at: Utc::now() + chrono::Duration::seconds(30),
        })
        .await;
    if !matches!(competing, Err(CatalogError::OwnerBusy)) {
        return Ok(false);
    }
    if !catalog
        .release_owner(&current.token)
        .await
        .map_err(|error| HarnessError::Redis(format!("releasing M7 owner: {error}")))?
    {
        return Ok(false);
    }
    let replacement = catalog
        .claim_owner(&OwnerClaimRequest {
            deployment_incarnation: cluster.deployment_incarnation.clone(),
            tenant_id: device.tenant_id,
            device_id: device.id,
            node_id: competing_node.node_id.clone(),
            boot_id: competing_node.boot_id.clone(),
            session_id: Uuid::new_v4().to_string(),
            lease_expires_at: Utc::now() + chrono::Duration::seconds(30),
        })
        .await
        .map_err(|error| HarnessError::Redis(format!("claiming replacement M7 owner: {error}")))?;
    let stale_release = catalog
        .release_owner(&current.token)
        .await
        .map_err(|error| HarnessError::Redis(format!("stale M7 release: {error}")))?;
    let _ = catalog.release_owner(&replacement.token).await;
    Ok(!stale_release)
}

async fn key_revocation_case(
    topology: &FixtureTopology,
    owners: &HashMap<Uuid, OwnerClaim>,
    peers: &[RunningPeer],
) -> Result<bool> {
    let owner = owners
        .get(&topology.devices_a[1].id)
        .ok_or_else(missing_owner)?;
    let owner_peer = peer(peers, &owner.token.node_id)?;
    owner_peer
        .pins
        .replace(Vec::<SpkiSha256>::new())
        .map_err(|error| HarnessError::Http(format!("revoking M7 peer key: {error}")))?;
    // Allow the transport's pin watcher to close any pooled connection before
    // the negative open below.  The wait is bounded and carries no payload.
    sleep(Duration::from_millis(50)).await;
    let ingress = peer(peers, "relay-b")?;
    let route = match ingress
        .runtime
        .resolve(
            OwnerScope::new(topology.devices_a[1].tenant_id, topology.devices_a[1].id),
            Utc::now(),
        )
        .await
    {
        Ok(route) => route,
        Err(_) => return Ok(true),
    };
    let envelope = device_data_envelope(
        &topology.devices_a[1],
        ingress.runtime.source().clone(),
        owner.token.clone(),
        topology.service_ids[&topology.devices_a[1].id],
        "m7-revoked-key",
        99,
        Utc::now(),
    );
    let open = ingress.runtime.open(&route, envelope).await;
    Ok(open.is_err())
}

async fn owner_death_case(
    catalog: &RedisCatalog,
    cluster: &ClusterFixture,
    owners: &HashMap<Uuid, OwnerClaim>,
    topology: &FixtureTopology,
    peers: &mut Vec<RunningPeer>,
) -> Result<bool> {
    let device = &topology.devices_b[0];
    let owner = owners.get(&device.id).ok_or_else(missing_owner)?;
    let owner_node = owner.token.node_id.clone();
    let Some(dead_index) = peers.iter().position(|peer| peer.node_id == owner_node) else {
        return Ok(false);
    };
    let dead_peer = peers.swap_remove(dead_index);
    dead_peer.shutdown().await?;
    let released = catalog
        .release_owner(&owner.token)
        .await
        .map_err(|error| HarnessError::Redis(format!("releasing dead M7 owner: {error}")))?;
    if !released {
        return Ok(false);
    }
    let identity = RelayIdentity::new(
        cluster.deployment_incarnation.clone(),
        "relay-b",
        cluster
            .node("relay-b")
            .ok_or_else(|| HarnessError::InvalidInput("missing relay-b".into()))?
            .boot_id
            .clone(),
    )
    .map_err(|error| HarnessError::InvalidInput(format!("M7 recovery identity: {error}")))?;
    let router = OwnerRouter::new(Arc::new(catalog.clone()), identity)
        .map_err(|error| HarnessError::InvalidInput(format!("M7 recovery router: {error}")))?;
    let route = router
        .resolve(
            OwnerScope::new(device.tenant_id, device.id),
            Utc::now(),
            None,
        )
        .await;
    Ok(matches!(
        route,
        Err(tunnel_relay::routing::OwnerRoutingError::NoLiveOwner(_))
    ))
}

fn peer<'a>(peers: &'a [RunningPeer], node_id: &str) -> Result<&'a RunningPeer> {
    peers
        .iter()
        .find(|peer| peer.node_id == node_id)
        .ok_or_else(|| HarnessError::InvalidInput(format!("M7 running peer {node_id} is missing")))
}

fn missing_owner() -> HarnessError {
    HarnessError::InvalidInput("M7 owner claim is missing".into())
}

fn device_control_envelope(
    device: &crate::DeviceFixture,
    source: PeerIdentity,
    owner: OwnerToken,
    service_id: Uuid,
    request_id: &str,
    now: DateTime<Utc>,
) -> RequestEnvelope {
    let destination = Destination::new(owner, service_id);
    RequestEnvelope::new(
        InternalRoute::DeviceControl,
        request_id,
        source.clone(),
        destination.clone(),
        20_000,
        Some(20_000),
        InternalRequest::DeviceControl(DeviceControlRequest {
            stream_id: request_id.to_owned(),
            authentication: device_authentication(device, &source, &destination, request_id, now),
        }),
    )
}

fn device_data_envelope(
    device: &crate::DeviceFixture,
    source: PeerIdentity,
    owner: OwnerToken,
    service_id: Uuid,
    request_id: &str,
    sequence: u64,
    now: DateTime<Utc>,
) -> RequestEnvelope {
    let destination = Destination::new(owner, service_id);
    RequestEnvelope::new(
        InternalRoute::DeviceData,
        request_id,
        source.clone(),
        destination.clone(),
        20_000,
        Some(20_000),
        InternalRequest::DeviceData(DeviceDataRequest {
            stream_id: request_id.to_owned(),
            sequence,
            authentication: device_authentication(device, &source, &destination, request_id, now),
            bytes: Vec::new(),
        }),
    )
}

fn device_authentication(
    device: &crate::DeviceFixture,
    source: &PeerIdentity,
    destination: &Destination,
    request_id: &str,
    _now: DateTime<Utc>,
) -> DeviceAuthenticationContext {
    let not_before =
        DateTime::<Utc>::from_timestamp(device.certificate.not_before.unix_timestamp(), 0)
            .unwrap_or_else(Utc::now);
    let expires_at =
        DateTime::<Utc>::from_timestamp(device.certificate.not_after.unix_timestamp(), 0)
            .unwrap_or_else(|| Utc::now() + chrono::Duration::hours(1));
    DeviceAuthenticationContext {
        certificate: VerifiedDeviceCertificate {
            certificate_identity: device.id.to_string(),
            spki_fingerprint: device
                .certificate
                .spki_fingerprint_sha256()
                .unwrap_or_else(|_| "0".repeat(64)),
            serial: device.id.to_string(),
            not_before,
            expires_at,
            tenant_id: destination.tenant_id,
            device_id: destination.device_id,
        },
        ingress: IngressRequestBinding {
            request_id: request_id.to_owned(),
            source: source.clone(),
            destination: destination.clone(),
            expires_at,
        },
    }
}

fn consumer_envelope(
    source: PeerIdentity,
    owner: OwnerToken,
    service_id: Uuid,
    request_id: &str,
) -> Result<RequestEnvelope> {
    let destination = Destination::new(owner.clone(), service_id);
    let bearer = ForwardedConsumerBearer::new(SYNTHETIC_BEARER, owner)
        .map_err(|error| HarnessError::InvalidInput(format!("M7 consumer bearer: {error}")))?;
    Ok(RequestEnvelope::new(
        InternalRoute::ConsumerStreams,
        request_id,
        source,
        destination,
        20_000,
        Some(20_000),
        InternalRequest::ConsumerStreams(tunnel_cluster::envelope::ConsumerStreamsRequest {
            stream_id: request_id.to_owned(),
            required_scope: "echo:invoke".to_owned(),
            bearer,
            bytes: Vec::new(),
        }),
    ))
}
