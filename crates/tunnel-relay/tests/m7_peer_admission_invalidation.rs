//! Red real-H3 regression for membership admission cancellation.
//!
//! This is intentionally staged separately from the production repair.  The
//! test compiles after the API-only
//! `PeerBindingProvider::admission_cancellation` seam, then remains
//! behaviorally red until the forwarding loops carry and select on the token.
//! It keeps two POST streams on one pooled peer connection, cancels the
//! destination admission token, and proves that both local exchanges return a
//! typed `PeerRuntimeError::Closed` before the owner callback can dispatch.
//! A third POST from a different authenticated sibling identity then remains
//! usable on the same destination while the affected identity is cancelled.

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
use http::StatusCode;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use tokio::{task::JoinHandle, time::timeout};
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
};
use tunnel_relay::{
    InboundPeerRequest, PeerBindingProvider, PeerIngressHandler, PeerRuntime, PeerRuntimeError,
    membership_runtime::PeerAdmissionCancellation,
    peer_runtime::{PeerAdmissionCancellationFuture, PeerBindingFuture, PeerIngressHandlerFuture},
    routing::{OwnerRoute, OwnerRouter, RelayIdentity},
};
use tunnel_transport::{
    ApprovedPeerPins, PeerClient, PeerServer, PeerTransportError, PeerTransportLimits,
    load_peer_client_config_from_pem, load_peer_server_config_from_pem, spki_sha256_from_der,
};
use uuid::Uuid;

const DEPLOYMENT_ID: &str = "m7-admission-invalidation-deployment";
const DEPLOYMENT_INCARNATION: &str = "m7-admission-invalidation-incarnation";
const SOURCE_NODE: &str = "m7-admission-source";
const SOURCE_BOOT: &str = "m7-admission-source-boot";
const SIBLING_NODE: &str = "m7-admission-sibling";
const SIBLING_BOOT: &str = "m7-admission-sibling-boot";
const DESTINATION_NODE: &str = "m7-admission-destination";
const DESTINATION_BOOT: &str = "m7-admission-destination-boot";
const SERVER_NAME: &str = "localhost";
const SERVICE_ID: Uuid = Uuid::from_u128(0x5a00_0000_0000_0000_0000_0000_0000_0001);
const CASE_TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Clone)]
struct AdmissionProvider {
    bindings: Arc<HashMap<(String, String), VerifiedPeerBinding>>,
    tokens: Arc<Mutex<HashMap<(String, String), CancellationToken>>>,
    lookups: Arc<Mutex<HashMap<(String, String), usize>>>,
}

impl AdmissionProvider {
    fn new(bindings: HashMap<(String, String), VerifiedPeerBinding>) -> Self {
        let tokens = bindings
            .keys()
            .cloned()
            .map(|key| (key, CancellationToken::new()))
            .collect();
        Self {
            bindings: Arc::new(bindings),
            tokens: Arc::new(Mutex::new(tokens)),
            lookups: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn token(&self, node_id: &str, boot_id: &str) -> CancellationToken {
        self.tokens
            .lock()
            .expect("admission token mutex")
            .get(&(node_id.to_owned(), boot_id.to_owned()))
            .cloned()
            .expect("admission token for verified identity")
    }

    fn lookup_count(&self, node_id: &str, boot_id: &str) -> usize {
        self.lookups
            .lock()
            .expect("admission lookup mutex")
            .get(&(node_id.to_owned(), boot_id.to_owned()))
            .copied()
            .unwrap_or(0)
    }

    fn record_lookup(&self, node_id: &str, boot_id: &str) {
        let mut lookups = self.lookups.lock().expect("admission lookup mutex");
        *lookups
            .entry((node_id.to_owned(), boot_id.to_owned()))
            .or_default() += 1;
    }
}

impl PeerBindingProvider for AdmissionProvider {
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
            binding.ok_or_else(|| PeerRuntimeError::Membership("missing probe binding".to_owned()))
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
            let binding = binding
                .ok_or_else(|| PeerRuntimeError::Membership("missing probe binding".to_owned()))?;
            if binding.spki_sha256() != expected_spki {
                return Err(PeerRuntimeError::PeerIdentityMismatch);
            }
            Ok(binding)
        })
    }

    fn admission_cancellation<'a>(
        &'a self,
        node_id: &'a str,
        boot_id: &'a str,
        spki_sha256: &'a str,
        _now: chrono::DateTime<Utc>,
    ) -> PeerAdmissionCancellationFuture<'a> {
        let key = (node_id.to_owned(), boot_id.to_owned());
        let expected_spki = spki_sha256.to_owned();
        let binding = self.bindings.get(&key).cloned();
        let token = self
            .tokens
            .lock()
            .expect("admission token mutex")
            .get(&key)
            .cloned();
        self.record_lookup(node_id, boot_id);
        Box::pin(async move {
            let binding = binding
                .ok_or_else(|| PeerRuntimeError::Membership("missing probe binding".to_owned()))?;
            if binding.spki_sha256() != expected_spki {
                return Err(PeerRuntimeError::PeerIdentityMismatch);
            }
            token
                .map(PeerAdmissionCancellation::from_token)
                .map(Some)
                .ok_or_else(|| PeerRuntimeError::Membership("missing admission token".to_owned()))
        })
    }

    fn is_ready(&self) -> bool {
        true
    }
}

struct DispatchGuard {
    dispatches: Arc<AtomicUsize>,
    dropped_before_dispatch: Arc<AtomicUsize>,
    dropped_notify: Arc<tokio::sync::Notify>,
}

impl Drop for DispatchGuard {
    fn drop(&mut self) {
        if self.dispatches.load(Ordering::Acquire) == 0 {
            self.dropped_before_dispatch.fetch_add(1, Ordering::AcqRel);
            self.dropped_notify.notify_waiters();
        }
    }
}

#[derive(Clone)]
struct AdmissionHandler {
    started: Arc<AtomicUsize>,
    started_notify: Arc<tokio::sync::Notify>,
    dispatches: Arc<AtomicUsize>,
    sibling_dispatches: Arc<AtomicUsize>,
    dropped_before_dispatch: Arc<AtomicUsize>,
    dropped_notify: Arc<tokio::sync::Notify>,
}

impl PeerIngressHandler for AdmissionHandler {
    fn handle(&self, request: InboundPeerRequest) -> PeerIngressHandlerFuture {
        let started = Arc::clone(&self.started);
        let started_notify = Arc::clone(&self.started_notify);
        let dispatches = Arc::clone(&self.dispatches);
        let sibling_dispatches = Arc::clone(&self.sibling_dispatches);
        let dropped_before_dispatch = Arc::clone(&self.dropped_before_dispatch);
        let dropped_notify = Arc::clone(&self.dropped_notify);
        Box::pin(async move {
            if request.envelope().source.node_id == SIBLING_NODE {
                let (mut send, mut recv) = request.split();
                // Consume the request FIN before completing this successful
                // health response. Cancelling the input here would race the
                // caller's finish and test reset semantics instead of sibling
                // survival after another identity is invalidated.
                if let Some(record) = recv.recv_message().await? {
                    return Err(PeerRuntimeError::UnexpectedRecord(record.kind()));
                }
                sibling_dispatches.fetch_add(1, Ordering::AcqRel);
                send.respond(StatusCode::OK).await?;
                send.finish().await?;
                return Ok(());
            }
            // Holding the request in this pending owner callback models an
            // admitted application stream.  PeerRuntimeHandler must drop it
            // when the membership token is cancelled, before dispatch occurs.
            let _request = request;
            let _guard = DispatchGuard {
                dispatches: Arc::clone(&dispatches),
                dropped_before_dispatch,
                dropped_notify,
            };
            started.fetch_add(1, Ordering::AcqRel);
            started_notify.notify_waiters();
            pending::<()>().await;
            dispatches.fetch_add(1, Ordering::AcqRel);
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
        let ca_key = KeyPair::generate().expect("admission CA key");
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "admission CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = params
            .self_signed(&ca_key)
            .expect("admission CA certificate");
        Self {
            ca_pem: ca.pem(),
            ca,
            ca_key,
        }
    }

    fn issue_peer(&self, node_id: &str) -> Leaf {
        let key = KeyPair::generate().expect("admission peer key");
        let mut params =
            CertificateParams::new(vec![SERVER_NAME.to_owned()]).expect("admission peer params");
        params
            .distinguished_name
            .push(DnType::CommonName, format!("peer/{node_id}"));
        params.subject_alt_names.push(SanType::URI(
            format!("urn:agent-tunnel:peer:{node_id}")
                .try_into()
                .expect("admission peer URI SAN"),
        ));
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let certificate = params
            .signed_by(&key, &self.ca, &self.ca_key)
            .expect("admission peer certificate");
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

struct AdmissionFixture {
    source_runtime: Arc<PeerRuntime>,
    sibling_runtime: Arc<PeerRuntime>,
    destination_runtime: Arc<PeerRuntime>,
    destination_binding: VerifiedPeerBinding,
    provider: AdmissionProvider,
    started: Arc<AtomicUsize>,
    started_notify: Arc<tokio::sync::Notify>,
    dispatches: Arc<AtomicUsize>,
    sibling_dispatches: Arc<AtomicUsize>,
    dropped_before_dispatch: Arc<AtomicUsize>,
    dropped_notify: Arc<tokio::sync::Notify>,
    cancel: CancellationToken,
    server_task: JoinHandle<Result<(), PeerTransportError>>,
}

impl AdmissionFixture {
    fn new() -> Self {
        let pki = FixturePki::new();
        let source_leaf = pki.issue_peer(SOURCE_NODE);
        let sibling_leaf = pki.issue_peer(SIBLING_NODE);
        let destination_leaf = pki.issue_peer(DESTINATION_NODE);
        let source_chain = pki.chain(&source_leaf);
        let sibling_chain = pki.chain(&sibling_leaf);
        let destination_chain = pki.chain(&destination_leaf);

        let server_config = load_peer_server_config_from_pem(
            destination_chain.as_bytes(),
            destination_leaf.private_key_pem.as_bytes(),
            pki.ca_pem.as_bytes(),
        )
        .expect("admission server TLS");
        let server_endpoint =
            quinn::Endpoint::server(server_config, SocketAddr::from(([127, 0, 0, 1], 0)))
                .expect("admission server endpoint");
        let server_address = server_endpoint
            .local_addr()
            .expect("admission server address");

        let mut source_endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("admission source endpoint");
        source_endpoint.set_default_client_config(
            load_peer_client_config_from_pem(
                source_chain.as_bytes(),
                source_leaf.private_key_pem.as_bytes(),
                pki.ca_pem.as_bytes(),
            )
            .expect("admission source TLS"),
        );
        let mut sibling_endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("admission sibling endpoint");
        sibling_endpoint.set_default_client_config(
            load_peer_client_config_from_pem(
                sibling_chain.as_bytes(),
                sibling_leaf.private_key_pem.as_bytes(),
                pki.ca_pem.as_bytes(),
            )
            .expect("admission sibling TLS"),
        );
        let mut destination_endpoint =
            quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
                .expect("admission destination endpoint");
        destination_endpoint.set_default_client_config(
            load_peer_client_config_from_pem(
                destination_chain.as_bytes(),
                destination_leaf.private_key_pem.as_bytes(),
                pki.ca_pem.as_bytes(),
            )
            .expect("admission destination TLS"),
        );

        let bindings = verified_bindings(
            &source_leaf,
            &sibling_leaf,
            &destination_leaf,
            server_address,
        );
        let provider = AdmissionProvider::new(bindings);
        let destination_binding = provider
            .bindings
            .get(&(DESTINATION_NODE.to_owned(), DESTINATION_BOOT.to_owned()))
            .cloned()
            .expect("destination binding");
        let limits = PeerTransportLimits {
            max_streams_per_connection: 4,
            stream_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(2),
            drain_timeout: Duration::from_secs(1),
            ..PeerTransportLimits::default()
        };
        let source_client = PeerClient::new(
            source_endpoint,
            ApprovedPeerPins::new([
                spki_sha256_from_der(&destination_leaf.der).expect("destination pin")
            ])
            .expect("source pins"),
            limits.clone(),
        )
        .expect("source client");
        let sibling_client = PeerClient::new(
            sibling_endpoint,
            ApprovedPeerPins::new([
                spki_sha256_from_der(&destination_leaf.der).expect("sibling destination pin")
            ])
            .expect("sibling pins"),
            limits.clone(),
        )
        .expect("sibling client");
        let destination_client = PeerClient::new(
            destination_endpoint,
            ApprovedPeerPins::new([spki_sha256_from_der(&source_leaf.der).expect("source pin")])
                .expect("destination pins"),
            limits.clone(),
        )
        .expect("destination client");
        let source_runtime = Arc::new(PeerRuntime::new(
            source_client.clone(),
            owner_router(SOURCE_NODE, SOURCE_BOOT),
            Arc::new(provider.clone()),
            SOURCE_NODE,
            SOURCE_BOOT,
        ));
        let sibling_runtime = Arc::new(PeerRuntime::new(
            sibling_client,
            owner_router(SIBLING_NODE, SIBLING_BOOT),
            Arc::new(provider.clone()),
            SIBLING_NODE,
            SIBLING_BOOT,
        ));
        let destination_runtime = Arc::new(PeerRuntime::new(
            destination_client,
            owner_router(DESTINATION_NODE, DESTINATION_BOOT),
            Arc::new(provider.clone()),
            DESTINATION_NODE,
            DESTINATION_BOOT,
        ));
        let started = Arc::new(AtomicUsize::new(0));
        let started_notify = Arc::new(tokio::sync::Notify::new());
        let dispatches = Arc::new(AtomicUsize::new(0));
        let sibling_dispatches = Arc::new(AtomicUsize::new(0));
        let dropped_before_dispatch = Arc::new(AtomicUsize::new(0));
        let dropped_notify = Arc::new(tokio::sync::Notify::new());
        let handler = AdmissionHandler {
            started: Arc::clone(&started),
            started_notify: Arc::clone(&started_notify),
            dispatches: Arc::clone(&dispatches),
            sibling_dispatches: Arc::clone(&sibling_dispatches),
            dropped_before_dispatch: Arc::clone(&dropped_before_dispatch),
            dropped_notify: Arc::clone(&dropped_notify),
        };
        let server = PeerServer::new(
            server_endpoint,
            ApprovedPeerPins::new([
                spki_sha256_from_der(&source_leaf.der).expect("source server pin"),
                spki_sha256_from_der(&sibling_leaf.der).expect("sibling server pin"),
            ])
            .expect("server pins"),
            limits,
            PeerRuntime::server_policy(),
            destination_runtime.server_handler(handler),
        )
        .expect("admission peer server");
        let cancel = CancellationToken::new();
        let server_task = tokio::spawn(server.serve(cancel.clone()));

        Self {
            source_runtime,
            sibling_runtime,
            destination_runtime,
            destination_binding,
            provider,
            started,
            started_notify,
            dispatches,
            sibling_dispatches,
            dropped_before_dispatch,
            dropped_notify,
            cancel,
            server_task,
        }
    }

    async fn shutdown(self) {
        self.cancel.cancel();
        let server_result = timeout(Duration::from_secs(3), self.server_task)
            .await
            .expect("admission server shutdown deadline")
            .expect("admission server join");
        assert!(
            server_result.is_ok(),
            "admission server failed: {server_result:?}"
        );
        self.source_runtime
            .shutdown()
            .await
            .expect("source runtime shutdown");
        self.sibling_runtime
            .shutdown()
            .await
            .expect("sibling runtime shutdown");
        self.destination_runtime
            .shutdown()
            .await
            .expect("destination runtime shutdown");
    }
}

fn owner_router(node_id: &str, boot_id: &str) -> Arc<OwnerRouter<dyn Catalog>> {
    let catalog: Arc<dyn Catalog> = Arc::new(MemoryCatalog::new());
    let identity = RelayIdentity::new(DEPLOYMENT_INCARNATION, node_id, boot_id)
        .expect("admission relay identity");
    Arc::new(OwnerRouter::new(catalog, identity).expect("admission owner router"))
}

fn verified_bindings(
    source: &Leaf,
    sibling: &Leaf,
    destination: &Leaf,
    server_address: SocketAddr,
) -> HashMap<(String, String), VerifiedPeerBinding> {
    let endpoint_policy =
        PrivateEndpointPolicy::allowlisted(["127.0.0.1"], [SERVER_NAME], [server_address.port()])
            .expect("admission endpoint policy");
    let policy = MembershipPolicy::new(DEPLOYMENT_ID, DEPLOYMENT_INCARNATION, endpoint_policy)
        .expect("admission membership policy");
    let (issuer, _) =
        MembershipIssuer::generate("m7-admission-publisher").expect("admission membership issuer");
    let trusted = TrustedPublisherKey::new(
        "m7-admission-publisher",
        issuer.public_key().expect("admission publisher key"),
    )
    .expect("admission trusted key");
    let mut verifier = MembershipVerifier::new(policy, [trusted]).expect("admission verifier");
    let now = Utc::now();
    let checkpoint = MembershipCheckpoint {
        schema_version: MEMBERSHIP_SCHEMA_VERSION,
        deployment_id: DEPLOYMENT_ID.to_owned(),
        deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
        checkpoint_version: 1,
        nonce: "m7-admission-nonce".to_owned(),
        minimum_versions: BTreeMap::from([
            (SOURCE_NODE.to_owned(), 1),
            (SIBLING_NODE.to_owned(), 1),
            (DESTINATION_NODE.to_owned(), 1),
        ]),
        issued_at: now - ChronoDuration::seconds(1),
        not_before: now - ChronoDuration::seconds(1),
        expires_at: now + ChronoDuration::seconds(30),
    };
    let checkpoint_bytes = issuer
        .sign_checkpoint_bytes(checkpoint)
        .expect("admission checkpoint signature");
    verifier
        .verify_checkpoint(&checkpoint_bytes, "m7-admission-nonce", now)
        .expect("admission checkpoint verification");

    let mut bindings = HashMap::new();
    for (node_id, boot_id, leaf) in [
        (SOURCE_NODE, SOURCE_BOOT, source),
        (SIBLING_NODE, SIBLING_BOOT, sibling),
        (DESTINATION_NODE, DESTINATION_BOOT, destination),
    ] {
        let spki = spki_sha256_from_der(&leaf.der)
            .expect("admission leaf SPKI")
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
                expires_at: now + ChronoDuration::seconds(30),
                revoked: false,
            }],
            issued_at: now - ChronoDuration::seconds(1),
            not_before: now - ChronoDuration::seconds(1),
            expires_at: now + ChronoDuration::seconds(30),
        };
        let signed = issuer
            .sign_membership_bytes(record)
            .expect("admission membership signature");
        let verified = verifier
            .verify_membership(&signed, now)
            .expect("admission membership verification");
        let binding = verified
            .bind_peer(node_id, boot_id, &spki, now)
            .expect("admission peer binding");
        bindings.insert((node_id.to_owned(), boot_id.to_owned()), binding);
    }
    bindings
}

fn owner_route(binding: &VerifiedPeerBinding) -> OwnerRoute {
    let token = OwnerToken {
        deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
        tenant_id: Uuid::from_u128(0x5100_0000_0000_0000_0000_0000_0000_0001),
        device_id: Uuid::from_u128(0x5200_0000_0000_0000_0000_0000_0000_0001),
        node_id: DESTINATION_NODE.to_owned(),
        boot_id: DESTINATION_BOOT.to_owned(),
        session_id: "m7-admission-session".to_owned(),
        epoch: 1,
    };
    OwnerRoute::Remote {
        owner: OwnerClaim {
            token: token.clone(),
            lease_expires_at: Utc::now() + ChronoDuration::seconds(30),
        },
        peer: Some(binding.clone()),
    }
}

fn health_envelope_for(source_node: &str, source_boot: &str, request_id: &str) -> RequestEnvelope {
    let token = OwnerToken {
        deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
        tenant_id: Uuid::from_u128(0x5100_0000_0000_0000_0000_0000_0000_0001),
        device_id: Uuid::from_u128(0x5200_0000_0000_0000_0000_0000_0000_0001),
        node_id: DESTINATION_NODE.to_owned(),
        boot_id: DESTINATION_BOOT.to_owned(),
        session_id: "m7-admission-session".to_owned(),
        epoch: 1,
    };
    RequestEnvelope::new(
        InternalRoute::Health,
        request_id,
        PeerIdentity::new(source_node, source_boot),
        Destination::new(token, SERVICE_ID),
        2_000,
        Some(2_000),
        InternalRequest::Health(HealthRequest {
            check_id: request_id.to_owned(),
        }),
    )
}

fn health_envelope(request_id: &str) -> RequestEnvelope {
    health_envelope_for(SOURCE_NODE, SOURCE_BOOT, request_id)
}

async fn run_case(fixture: &AdmissionFixture) -> Result<(), String> {
    let route = owner_route(&fixture.destination_binding);
    let first = fixture
        .source_runtime
        .open(&route, health_envelope("m7-admission-first"))
        .await
        .map_err(|error| format!("first pooled stream open failed: {error}"))?;
    let second = fixture
        .source_runtime
        .open(&route, health_envelope("m7-admission-second"))
        .await
        .map_err(|error| format!("second pooled stream open failed: {error}"))?;
    let (_first_send, mut first_recv) = first.split();
    let (_second_send, mut second_recv) = second.split();

    timeout(CASE_TIMEOUT, async {
        loop {
            if fixture.started.load(Ordering::Acquire) >= 2 {
                break;
            }
            fixture.started_notify.notified().await;
        }
    })
    .await
    .map_err(|_| "both same-identity handlers did not reach the bounded gate".to_owned())?;

    let pool = fixture.source_runtime.peer_pool_stats().await;
    if pool.pooled_connections.len() != 1 {
        return Err(format!(
            "same-identity streams did not share one pooled connection: {pool:?}"
        ));
    }

    // Cancel the inbound token first.  The callback is still pending, so a
    // correct server adapter drops both request futures before application
    // dispatch.  This is a separate edge from the local outbound close.
    fixture.provider.token(SOURCE_NODE, SOURCE_BOOT).cancel();
    timeout(CASE_TIMEOUT, async {
        loop {
            if fixture.dropped_before_dispatch.load(Ordering::Acquire) >= 2 {
                break;
            }
            fixture.dropped_notify.notified().await;
        }
    })
    .await
    .map_err(|_| "inbound admission cancellation did not drop both handlers".to_owned())?;

    // A different authenticated source identity remains usable while the
    // source admission token is cancelled.  This is a real peer POST on the
    // same destination, rather than a synthetic counter or a fresh listener.
    let sibling = fixture
        .sibling_runtime
        .open(
            &route,
            health_envelope_for(SIBLING_NODE, SIBLING_BOOT, "m7-admission-sibling"),
        )
        .await
        .map_err(|error| format!("unrelated sibling open failed: {error}"))?;
    let (mut sibling_send, mut sibling_recv) = sibling.split();
    sibling_send
        .finish()
        .await
        .map_err(|error| format!("unrelated sibling request finish failed: {error}"))?;
    let sibling_response = timeout(CASE_TIMEOUT, sibling_recv.accept_response())
        .await
        .map_err(|_| "unrelated sibling response timed out".to_owned())?
        .map_err(|error| format!("unrelated sibling response failed: {error}"))?;
    if sibling_response.status() != StatusCode::OK {
        return Err(format!(
            "unrelated sibling returned {}",
            sibling_response.status()
        ));
    }
    if sibling_recv
        .recv_message()
        .await
        .map_err(|error| format!("unrelated sibling terminal failed: {error}"))?
        .is_some()
        || fixture.sibling_dispatches.load(Ordering::Acquire) != 1
    {
        return Err(
            "unrelated sibling did not complete exactly one application dispatch".to_owned(),
        );
    }

    // The outbound exchange carries the destination token.  Its cancellation
    // is local and therefore must surface as the typed relay close, rather
    // than a generic timeout or a retryable admission result.
    fixture
        .provider
        .token(DESTINATION_NODE, DESTINATION_BOOT)
        .cancel();
    let first_result = timeout(CASE_TIMEOUT, first_recv.accept_response())
        .await
        .map_err(|_| "first exchange did not observe admission cancellation".to_owned())?;
    let second_result = timeout(CASE_TIMEOUT, second_recv.accept_response())
        .await
        .map_err(|_| "second exchange did not observe admission cancellation".to_owned())?;
    if !matches!(first_result, Err(PeerRuntimeError::Closed))
        || !matches!(second_result, Err(PeerRuntimeError::Closed))
    {
        return Err(format!(
            "admission cancellation was not typed Closed: first={first_result:?}, second={second_result:?}"
        ));
    }

    if fixture
        .provider
        .lookup_count(DESTINATION_NODE, DESTINATION_BOOT)
        < 2
        || fixture.provider.lookup_count(SOURCE_NODE, SOURCE_BOOT) < 2
    {
        return Err(
            "admission token was not acquired for both outbound and inbound streams".to_owned(),
        );
    }

    if fixture.dispatches.load(Ordering::Acquire) != 0
        || fixture.dropped_before_dispatch.load(Ordering::Acquire) < 2
    {
        return Err(format!(
            "cancelled streams made application progress: dispatches={}, dropped_before_dispatch={}",
            fixture.dispatches.load(Ordering::Acquire),
            fixture.dropped_before_dispatch.load(Ordering::Acquire),
        ));
    }

    Ok(())
}

#[tokio::test]
async fn real_h3_membership_admission_cancels_pooled_identity_without_dispatch() {
    let fixture = AdmissionFixture::new();
    let result = run_case(&fixture).await;
    fixture.shutdown().await;
    result.expect("membership admission invalidation regression");
}
