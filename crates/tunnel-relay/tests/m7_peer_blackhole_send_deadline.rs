//! Real-H3 regression for EC-029 on the peer record send path.
//!
//! The consumer socket path already bounds each physical write, but the peer
//! record send was bounded only by an admission-cancellation token, and the
//! branch with no admission context fell through to an unbounded await whose
//! only backstop was a relative per-chunk idle allowance renewed for every
//! physical write.  This fixture drives that exact branch: the binding
//! provider returns no admission context, and the destination handler accepts
//! the request and then never reads its body, so the peer becomes a blackhole
//! once the connection flow-control window fills.
//!
//! The assertions are the two clauses EC-029 requires of a physical write:
//! the send is bounded by an absolute deadline created once from the record's
//! own stream budget, and the elapsed send cancels and joins its stream
//! rather than leaking a half-open pump.  Before the repair the send stayed
//! parked for the 60-second idle allowance of each chunk and the pump never
//! joined inside the case budget.

use std::{
    collections::{BTreeMap, HashMap},
    future::pending,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use chrono::{Duration as ChronoDuration, Utc};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use tokio::{
    task::JoinHandle,
    time::{Instant, timeout},
};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{Catalog, MemoryCatalog, OwnerClaim, OwnerToken};
use tunnel_cluster::{
    envelope::{
        Destination, HealthRequest, InternalRequest, InternalRoute, PeerIdentity, RequestEnvelope,
    },
    membership::{
        MEMBERSHIP_SCHEMA_VERSION, MembershipCheckpoint, MembershipIssuer, MembershipPolicy,
        MembershipRecord, MembershipVerifier, PrivateEndpointPolicy, RELAY_PEER_ROLE, RelayKey,
        TrustedPublisherKey, VerifiedPeerBinding,
    },
    peer_frame::{PeerRecordKind, RECORD_SEND_BUDGET},
};
use tunnel_relay::{
    InboundPeerRequest, PeerBindingProvider, PeerIngressHandler, PeerRuntime, PeerRuntimeError,
    peer_runtime::{PeerAdmissionCancellationFuture, PeerBindingFuture, PeerIngressHandlerFuture},
    routing::{OwnerRoute, OwnerRouter, RelayIdentity},
};
use tunnel_transport::{
    ApprovedPeerPins, PeerClient, PeerServer, PeerTransportError, PeerTransportLimits,
    load_peer_client_config_from_pem, load_peer_server_config_from_pem, spki_sha256_from_der,
};
use uuid::Uuid;

const DEPLOYMENT_ID: &str = "m7-blackhole-deployment";
const DEPLOYMENT_INCARNATION: &str = "m7-blackhole-incarnation";
const SOURCE_NODE: &str = "m7-blackhole-source";
const SOURCE_BOOT: &str = "m7-blackhole-source-boot";
const DESTINATION_NODE: &str = "m7-blackhole-destination";
const DESTINATION_BOOT: &str = "m7-blackhole-destination-boot";
const SERVER_NAME: &str = "localhost";
const SERVICE_ID: Uuid = Uuid::from_u128(0x5b00_0000_0000_0000_0000_0000_0000_0001);

/// Per-chunk allowance the repaired path must no longer renew.  It is also
/// the QUIC idle timeout, so a test that outlives it is observing the old
/// unbounded behaviour rather than a slow machine.
const IDLE_ALLOWANCE: Duration = Duration::from_secs(60);
/// Transport windows, deliberately small so the blackholed peer stalls the
/// writer after a couple of records instead of megabytes of traffic.
const CHUNK_BYTES: usize = 16 * 1024;
const STREAM_BODY_BYTES: usize = 64 * 1024;
const CONNECTION_BODY_BYTES: usize = 128 * 1024;
/// Body of each charged record pushed at the blackhole.
const RECORD_BODY_BYTES: usize = 60 * 1024;
/// Upper bound on records written before the window is exhausted.
const MAX_RECORDS: usize = 64;
/// The bounded send plus generous scheduling slack, and still far below the
/// per-chunk idle allowance the old path relied on.
const SEND_BUDGET_SLACK: Duration = Duration::from_secs(6);
/// Budget for joining the pump after its send elapsed.
const JOIN_BUDGET: Duration = Duration::from_secs(5);

#[derive(Clone)]
struct BlackholeProvider {
    bindings: Arc<HashMap<(String, String), VerifiedPeerBinding>>,
    admission_lookups: Arc<Mutex<usize>>,
    admission_contexts: Arc<Mutex<usize>>,
}

impl BlackholeProvider {
    fn new(bindings: HashMap<(String, String), VerifiedPeerBinding>) -> Self {
        Self {
            bindings: Arc::new(bindings),
            admission_lookups: Arc::new(Mutex::new(0)),
            admission_contexts: Arc::new(Mutex::new(0)),
        }
    }

    fn admission_lookups(&self) -> usize {
        *self
            .admission_lookups
            .lock()
            .expect("blackhole admission lookup mutex")
    }

    fn admission_contexts(&self) -> usize {
        *self
            .admission_contexts
            .lock()
            .expect("blackhole admission context mutex")
    }
}

impl PeerBindingProvider for BlackholeProvider {
    fn binding<'a>(
        &'a self,
        node_id: &'a str,
        boot_id: &'a str,
        _now: chrono::DateTime<Utc>,
    ) -> PeerBindingFuture<'a> {
        let binding = self
            .bindings
            .get(&(node_id.to_owned(), boot_id.to_owned()))
            .cloned();
        Box::pin(async move {
            binding
                .ok_or_else(|| PeerRuntimeError::Membership("missing blackhole binding".to_owned()))
        })
    }

    fn binding_for_certificate<'a>(
        &'a self,
        node_id: &'a str,
        boot_id: &'a str,
        spki_sha256: &'a str,
        _now: chrono::DateTime<Utc>,
    ) -> PeerBindingFuture<'a> {
        let binding = self
            .bindings
            .get(&(node_id.to_owned(), boot_id.to_owned()))
            .cloned();
        let expected_spki = spki_sha256.to_owned();
        Box::pin(async move {
            let binding = binding.ok_or_else(|| {
                PeerRuntimeError::Membership("missing blackhole binding".to_owned())
            })?;
            if binding.spki_sha256() != expected_spki {
                return Err(PeerRuntimeError::PeerIdentityMismatch);
            }
            Ok(binding)
        })
    }

    /// This provider verifies membership but publishes no invalidation edge,
    /// which is the branch under test: the send has no admission token to
    /// select on and must rely on its own absolute deadline.
    fn admission_cancellation<'a>(
        &'a self,
        node_id: &'a str,
        boot_id: &'a str,
        spki_sha256: &'a str,
        _now: chrono::DateTime<Utc>,
    ) -> PeerAdmissionCancellationFuture<'a> {
        let binding = self
            .bindings
            .get(&(node_id.to_owned(), boot_id.to_owned()))
            .cloned();
        let expected_spki = spki_sha256.to_owned();
        *self
            .admission_lookups
            .lock()
            .expect("blackhole admission lookup mutex") += 1;
        Box::pin(async move {
            let binding = binding.ok_or_else(|| {
                PeerRuntimeError::Membership("missing blackhole binding".to_owned())
            })?;
            if binding.spki_sha256() != expected_spki {
                return Err(PeerRuntimeError::PeerIdentityMismatch);
            }
            Ok(None)
        })
    }

    fn is_ready(&self) -> bool {
        true
    }
}

/// Accepts the request and then never reads its body, so the writer stalls
/// once the connection flow-control window is exhausted.
#[derive(Clone)]
struct BlackholeHandler {
    accepted: Arc<AtomicUsize>,
    accepted_notify: Arc<tokio::sync::Notify>,
}

impl PeerIngressHandler for BlackholeHandler {
    fn handle(&self, request: InboundPeerRequest) -> PeerIngressHandlerFuture {
        let accepted = Arc::clone(&self.accepted);
        let accepted_notify = Arc::clone(&self.accepted_notify);
        Box::pin(async move {
            // Retaining the request without reading it is the blackhole: the
            // stream stays admitted, nothing is consumed, and no response is
            // produced.
            let _request = request;
            accepted.fetch_add(1, Ordering::AcqRel);
            accepted_notify.notify_waiters();
            pending::<()>().await;
            Ok(())
        })
    }
}

struct Leaf {
    certificate_pem: String,
    private_key_pem: String,
    der: Vec<u8>,
}

struct FixturePki {
    ca: Certificate,
    ca_key: KeyPair,
    ca_pem: String,
}

impl FixturePki {
    fn new() -> Self {
        let ca_key = KeyPair::generate().expect("blackhole CA key");
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "blackhole CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = params
            .self_signed(&ca_key)
            .expect("blackhole CA certificate");
        Self {
            ca_pem: ca.pem(),
            ca,
            ca_key,
        }
    }

    fn issue_peer(&self, node_id: &str) -> Leaf {
        let key = KeyPair::generate().expect("blackhole peer key");
        let mut params =
            CertificateParams::new(vec![SERVER_NAME.to_owned()]).expect("blackhole peer params");
        params
            .distinguished_name
            .push(DnType::CommonName, format!("peer/{node_id}"));
        params.subject_alt_names.push(SanType::URI(
            format!("urn:agent-tunnel:peer:{node_id}")
                .try_into()
                .expect("blackhole peer URI SAN"),
        ));
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let certificate = params
            .signed_by(&key, &self.ca, &self.ca_key)
            .expect("blackhole peer certificate");
        Leaf {
            certificate_pem: certificate.pem(),
            private_key_pem: key.serialize_pem(),
            der: certificate.der().to_vec(),
        }
    }

    fn chain(&self, leaf: &Leaf) -> String {
        format!("{}{}", leaf.certificate_pem, self.ca_pem)
    }
}

struct BlackholeFixture {
    source_runtime: Arc<PeerRuntime>,
    destination_runtime: Arc<PeerRuntime>,
    destination_binding: VerifiedPeerBinding,
    provider: BlackholeProvider,
    accepted: Arc<AtomicUsize>,
    accepted_notify: Arc<tokio::sync::Notify>,
    max_stream_permits: usize,
    cancel: CancellationToken,
    server_task: JoinHandle<Result<(), PeerTransportError>>,
}

impl BlackholeFixture {
    fn new() -> Self {
        let pki = FixturePki::new();
        let source_leaf = pki.issue_peer(SOURCE_NODE);
        let destination_leaf = pki.issue_peer(DESTINATION_NODE);
        let source_chain = pki.chain(&source_leaf);
        let destination_chain = pki.chain(&destination_leaf);

        let server_config = load_peer_server_config_from_pem(
            destination_chain.as_bytes(),
            destination_leaf.private_key_pem.as_bytes(),
            pki.ca_pem.as_bytes(),
        )
        .expect("blackhole server TLS");
        let server_endpoint =
            quinn::Endpoint::server(server_config, SocketAddr::from(([127, 0, 0, 1], 0)))
                .expect("blackhole server endpoint");
        let server_address = server_endpoint
            .local_addr()
            .expect("blackhole server address");

        let mut source_endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("blackhole source endpoint");
        source_endpoint.set_default_client_config(
            load_peer_client_config_from_pem(
                source_chain.as_bytes(),
                source_leaf.private_key_pem.as_bytes(),
                pki.ca_pem.as_bytes(),
            )
            .expect("blackhole source TLS"),
        );
        let mut destination_endpoint =
            quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
                .expect("blackhole destination endpoint");
        destination_endpoint.set_default_client_config(
            load_peer_client_config_from_pem(
                destination_chain.as_bytes(),
                destination_leaf.private_key_pem.as_bytes(),
                pki.ca_pem.as_bytes(),
            )
            .expect("blackhole destination TLS"),
        );

        let bindings = verified_bindings(&source_leaf, &destination_leaf, server_address);
        let provider = BlackholeProvider::new(bindings);
        let destination_binding = provider
            .bindings
            .get(&(DESTINATION_NODE.to_owned(), DESTINATION_BOOT.to_owned()))
            .cloned()
            .expect("blackhole destination binding");
        let limits = PeerTransportLimits {
            max_chunk_bytes: CHUNK_BYTES,
            max_stream_body_bytes: STREAM_BODY_BYTES,
            max_connection_body_bytes: CONNECTION_BODY_BYTES,
            max_streams_per_connection: 4,
            idle_timeout: IDLE_ALLOWANCE,
            drain_timeout: Duration::from_secs(2),
            ..PeerTransportLimits::default()
        };
        let max_stream_permits = limits.max_streams_per_connection;
        let source_client = PeerClient::new(
            source_endpoint,
            ApprovedPeerPins::new([
                spki_sha256_from_der(&destination_leaf.der).expect("destination pin")
            ])
            .expect("source pins"),
            limits.clone(),
        )
        .expect("blackhole source client");
        let destination_client = PeerClient::new(
            destination_endpoint,
            ApprovedPeerPins::new([spki_sha256_from_der(&source_leaf.der).expect("source pin")])
                .expect("destination pins"),
            limits.clone(),
        )
        .expect("blackhole destination client");
        let source_runtime = Arc::new(PeerRuntime::new(
            source_client,
            owner_router(SOURCE_NODE, SOURCE_BOOT),
            Arc::new(provider.clone()),
            SOURCE_NODE,
            SOURCE_BOOT,
        ));
        let destination_runtime = Arc::new(PeerRuntime::new(
            destination_client,
            owner_router(DESTINATION_NODE, DESTINATION_BOOT),
            Arc::new(provider.clone()),
            DESTINATION_NODE,
            DESTINATION_BOOT,
        ));
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_notify = Arc::new(tokio::sync::Notify::new());
        let handler = BlackholeHandler {
            accepted: Arc::clone(&accepted),
            accepted_notify: Arc::clone(&accepted_notify),
        };
        let server = PeerServer::new(
            server_endpoint,
            ApprovedPeerPins::new([
                spki_sha256_from_der(&source_leaf.der).expect("source server pin")
            ])
            .expect("server pins"),
            limits,
            PeerRuntime::server_policy(),
            destination_runtime.server_handler(handler),
        )
        .expect("blackhole peer server");
        let cancel = CancellationToken::new();
        let server_task = tokio::spawn(server.serve(cancel.clone()));

        Self {
            source_runtime,
            destination_runtime,
            destination_binding,
            provider,
            accepted,
            accepted_notify,
            max_stream_permits,
            cancel,
            server_task,
        }
    }

    async fn shutdown(self) {
        self.cancel.cancel();
        let _ = timeout(Duration::from_secs(5), self.server_task).await;
        let _ = self.source_runtime.shutdown().await;
        let _ = self.destination_runtime.shutdown().await;
    }
}

fn owner_router(node_id: &str, boot_id: &str) -> Arc<OwnerRouter<dyn Catalog>> {
    let catalog: Arc<dyn Catalog> = Arc::new(MemoryCatalog::new());
    let identity = RelayIdentity::new(DEPLOYMENT_INCARNATION, node_id, boot_id)
        .expect("blackhole relay identity");
    Arc::new(OwnerRouter::new(catalog, identity).expect("blackhole owner router"))
}

fn verified_bindings(
    source: &Leaf,
    destination: &Leaf,
    server_address: SocketAddr,
) -> HashMap<(String, String), VerifiedPeerBinding> {
    let endpoint_policy =
        PrivateEndpointPolicy::allowlisted(["127.0.0.1"], [SERVER_NAME], [server_address.port()])
            .expect("blackhole endpoint policy");
    let policy = MembershipPolicy::new(DEPLOYMENT_ID, DEPLOYMENT_INCARNATION, endpoint_policy)
        .expect("blackhole membership policy");
    let (issuer, _) =
        MembershipIssuer::generate("m7-blackhole-publisher").expect("blackhole membership issuer");
    let trusted = TrustedPublisherKey::new(
        "m7-blackhole-publisher",
        issuer.public_key().expect("blackhole publisher key"),
    )
    .expect("blackhole trusted key");
    let mut verifier = MembershipVerifier::new(policy, [trusted]).expect("blackhole verifier");
    let now = Utc::now();
    let checkpoint = MembershipCheckpoint {
        schema_version: MEMBERSHIP_SCHEMA_VERSION,
        deployment_id: DEPLOYMENT_ID.to_owned(),
        deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
        checkpoint_version: 1,
        nonce: "m7-blackhole-nonce".to_owned(),
        minimum_versions: BTreeMap::from([
            (SOURCE_NODE.to_owned(), 1),
            (DESTINATION_NODE.to_owned(), 1),
        ]),
        issued_at: now - ChronoDuration::seconds(1),
        not_before: now - ChronoDuration::seconds(1),
        expires_at: now + ChronoDuration::seconds(50),
    };
    let checkpoint_bytes = issuer
        .sign_checkpoint_bytes(checkpoint)
        .expect("blackhole checkpoint signature");
    verifier
        .verify_checkpoint(&checkpoint_bytes, "m7-blackhole-nonce", now)
        .expect("blackhole checkpoint verification");

    let mut bindings = HashMap::new();
    for (node_id, boot_id, leaf) in [
        (SOURCE_NODE, SOURCE_BOOT, source),
        (DESTINATION_NODE, DESTINATION_BOOT, destination),
    ] {
        let spki = spki_sha256_from_der(&leaf.der)
            .expect("blackhole leaf SPKI")
            .to_hex();
        let record = MembershipRecord {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            deployment_id: DEPLOYMENT_ID.to_owned(),
            deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
            node_id: node_id.to_owned(),
            record_version: 1,
            roles: vec![RELAY_PEER_ROLE.to_owned()],
            peer_endpoint: server_address.to_string(),
            server_name: SERVER_NAME.to_owned(),
            keys: vec![RelayKey {
                key_id: format!("{node_id}-key"),
                spki_sha256: spki.clone(),
                not_before: now - ChronoDuration::seconds(1),
                expires_at: now + ChronoDuration::seconds(50),
                revoked: false,
            }],
            issued_at: now - ChronoDuration::seconds(1),
            not_before: now - ChronoDuration::seconds(1),
            expires_at: now + ChronoDuration::seconds(50),
        };
        let signed = issuer
            .sign_membership_bytes(record)
            .expect("blackhole membership signature");
        let verified = verifier
            .verify_membership(&signed, now)
            .expect("blackhole membership verification");
        let binding = verified
            .bind_peer(node_id, boot_id, &spki, now)
            .expect("blackhole peer binding");
        bindings.insert((node_id.to_owned(), boot_id.to_owned()), binding);
    }
    bindings
}

fn owner_route(binding: &VerifiedPeerBinding) -> OwnerRoute {
    OwnerRoute::Remote {
        owner: OwnerClaim {
            token: owner_token(),
            lease_expires_at: Utc::now() + ChronoDuration::seconds(50),
        },
        peer: Some(binding.clone()),
    }
}

fn owner_token() -> OwnerToken {
    OwnerToken {
        deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
        tenant_id: Uuid::from_u128(0x5c00_0000_0000_0000_0000_0000_0000_0001),
        device_id: Uuid::from_u128(0x5d00_0000_0000_0000_0000_0000_0000_0001),
        node_id: DESTINATION_NODE.to_owned(),
        boot_id: DESTINATION_BOOT.to_owned(),
        session_id: "m7-blackhole-session".to_owned(),
        epoch: 1,
    }
}

fn health_envelope(request_id: &str) -> RequestEnvelope {
    RequestEnvelope::new(
        InternalRoute::Health,
        request_id,
        PeerIdentity::new(SOURCE_NODE, SOURCE_BOOT),
        Destination::new(owner_token(), SERVICE_ID),
        2_000,
        Some(2_000),
        InternalRequest::Health(HealthRequest {
            check_id: request_id.to_owned(),
        }),
    )
}

/// One bounded outcome of the blackholed pump, reported back to the case.
struct PumpOutcome {
    records_sent: usize,
    blocked_send: Duration,
    error: PeerRuntimeError,
    follow_up: Option<PeerRuntimeError>,
    follow_up_elapsed: Duration,
}

async fn run_case(fixture: &BlackholeFixture) -> Result<(), String> {
    let route = owner_route(&fixture.destination_binding);
    let exchange = fixture
        .source_runtime
        .open(&route, health_envelope("m7-blackhole-open"))
        .await
        .map_err(|error| format!("blackhole stream open failed: {error}"))?;

    // The handler must have taken the request without reading it before the
    // writer starts, so the stall is the peer's refusal to consume rather
    // than an unadmitted stream.
    timeout(Duration::from_secs(5), async {
        loop {
            if fixture.accepted.load(Ordering::Acquire) >= 1 {
                break;
            }
            fixture.accepted_notify.notified().await;
        }
    })
    .await
    .map_err(|_| "blackhole handler never accepted the request".to_owned())?;

    if fixture.provider.admission_lookups() == 0 || fixture.provider.admission_contexts() != 0 {
        return Err(format!(
            "the branch under test is not the no-admission branch: lookups={}, contexts={}",
            fixture.provider.admission_lookups(),
            fixture.provider.admission_contexts(),
        ));
    }

    let (mut send, recv) = exchange.split();
    let body = vec![0x5a_u8; RECORD_BODY_BYTES];

    // The pump runs as its own task so the case can prove it joins after the
    // bounded send elapses.
    let pump: JoinHandle<Result<PumpOutcome, String>> = tokio::spawn(async move {
        for index in 0..MAX_RECORDS {
            let started = Instant::now();
            match send
                .send_message(PeerRecordKind::CompleteDeviceData, &body)
                .await
            {
                Ok(()) => continue,
                Err(error) => {
                    let blocked_send = started.elapsed();
                    // A cancelled stream must refuse further writes promptly
                    // instead of parking on the same blackhole again.
                    let follow_up_started = Instant::now();
                    let follow_up = send
                        .send_message(PeerRecordKind::CompleteDeviceData, &body)
                        .await
                        .err();
                    return Ok(PumpOutcome {
                        records_sent: index,
                        blocked_send,
                        error,
                        follow_up,
                        follow_up_elapsed: follow_up_started.elapsed(),
                    });
                }
            }
        }
        Err(format!(
            "the blackholed peer accepted all {MAX_RECORDS} records without stalling the writer"
        ))
    });

    let outcome = timeout(RECORD_SEND_BUDGET + SEND_BUDGET_SLACK + JOIN_BUDGET, pump)
        .await
        .map_err(|_| {
            format!(
                "the peer record send was not bounded: the pump did not join within {:?}",
                RECORD_SEND_BUDGET + SEND_BUDGET_SLACK + JOIN_BUDGET
            )
        })?
        .map_err(|error| format!("blackhole pump panicked: {error}"))??;

    if outcome.records_sent == 0 {
        return Err("the writer failed before any record reached the wire".to_owned());
    }
    if !matches!(
        outcome.error,
        PeerRuntimeError::Transport(PeerTransportError::Timeout)
    ) {
        return Err(format!(
            "the blocked send was not the typed bounded-write outcome: {:?}",
            outcome.error
        ));
    }
    if outcome.blocked_send > RECORD_SEND_BUDGET + SEND_BUDGET_SLACK {
        return Err(format!(
            "the blocked send took {:?}, beyond the record send budget {RECORD_SEND_BUDGET:?}",
            outcome.blocked_send
        ));
    }
    if outcome.blocked_send >= IDLE_ALLOWANCE {
        return Err(format!(
            "the blocked send waited out the per-chunk idle allowance {IDLE_ALLOWANCE:?}: {:?}",
            outcome.blocked_send
        ));
    }
    // The send must have actually blocked on the blackhole: an instant
    // failure would prove nothing about the deadline.
    if outcome.blocked_send < RECORD_SEND_BUDGET / 2 {
        return Err(format!(
            "the send did not block on the blackholed peer: {:?}",
            outcome.blocked_send
        ));
    }
    match &outcome.follow_up {
        None => {
            return Err(
                "the elapsed send did not cancel the stream: a later write succeeded".to_owned(),
            );
        }
        Some(error) => {
            let message = error.to_string();
            if message.contains("5a5a") || message.contains(&RECORD_BODY_BYTES.to_string()) {
                return Err(format!(
                    "the cancelled-write diagnostic carried body state: {message}"
                ));
            }
        }
    }
    if outcome.follow_up_elapsed > SEND_BUDGET_SLACK {
        return Err(format!(
            "a write after cancellation blocked again for {:?}",
            outcome.follow_up_elapsed
        ));
    }

    // The pump joined above.  Releasing the response half then leaves nothing
    // holding the request stream, so its lease must return to the pool: that
    // is the observable half of "cancels and joins the socket".
    drop(recv);
    let mut pool = fixture.source_runtime.peer_pool_stats().await;
    let joined =
        timeout(JOIN_BUDGET, async {
            loop {
                pool = fixture.source_runtime.peer_pool_stats().await;
                if pool.pooled_connections.iter().all(|connection| {
                    connection.available_stream_permits == fixture.max_stream_permits
                }) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .is_ok();
    if !joined {
        return Err(format!(
            "the cancelled stream was not joined back into the pool: {pool:?}"
        ));
    }

    Ok(())
}

#[tokio::test]
async fn real_h3_blackholed_peer_record_send_is_bounded_cancelled_and_joined() {
    let fixture = BlackholeFixture::new();
    let result = run_case(&fixture).await;
    fixture.shutdown().await;
    result.expect("peer record send deadline regression");
}
