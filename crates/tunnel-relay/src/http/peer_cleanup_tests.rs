use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use crate::{
    actor::RelayHandle,
    config::RelayOptions,
    peer_runtime::{
        InboundPeerRequest, PeerIngressHandler, PeerIngressHandlerFuture, PeerRuntime,
        PeerRuntimeError,
    },
    routing::{OwnerRoute, OwnerRouter, RelayIdentity},
};
use bytes::Bytes;
use chrono::{Duration as ChronoDuration, Utc};
use http::Request;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use tokio::{sync::mpsc, time::timeout};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{
    Catalog, CatalogFixture, CredentialRecord, FixtureDevice, GrantSpec,
    MembershipRecord as CatalogMembershipRecord, MemoryCatalog, OidcConfig, OidcVerifier,
    PermissionSet, PrincipalIdentity, ServiceSpec, TenantRecord, UserRecord,
};
use tunnel_cluster::{
    envelope::{
        ConsumerStreamsRequest, Destination, ForwardedConsumerBearer, InternalRequest,
        InternalRoute, PeerIdentity, RequestEnvelope,
    },
    membership::{
        MEMBERSHIP_SCHEMA_VERSION, MembershipCheckpoint, MembershipIssuer, MembershipPolicy,
        MembershipRecord, MembershipVerifier, PrivateEndpointPolicy, RELAY_PEER_ROLE, RelayKey,
        TrustedPublisherKey, VerifiedPeerBinding,
    },
    peer_frame::PeerRecordKind,
};
use tunnel_protocol::{ControlMessage, Hello};
use tunnel_transport::{
    ApprovedPeerPins, PeerClient, PeerDestination, PeerServer, PeerTransportLimits, SpkiSha256,
    load_peer_client_config_from_pem, load_peer_server_config_from_pem, spki_sha256_from_der,
};
use uuid::Uuid;

use super::{peer_ingress_handler, wire};
use crate::actor::{ControlOutbound, DataOutbound};

const DEPLOYMENT_ID: &str = "m7-peer-cleanup-deployment";
const DEPLOYMENT_INCARNATION: &str = "m7-peer-cleanup-incarnation";
const SOURCE_NODE: &str = "m7-peer-cleanup-source";
const SOURCE_BOOT: &str = "m7-peer-cleanup-source-boot";
const DESTINATION_NODE: &str = "m7-peer-cleanup-owner";
const DESTINATION_BOOT: &str = "m7-peer-cleanup-owner-boot";
const MEMBERSHIP_NONCE: &str = "m7-peer-cleanup-membership-nonce";
const ISSUER: &str = "https://peer-cleanup-issuer.example";
const AUDIENCE: &str = "peer-cleanup-audience";
const SUBJECT: &str = "peer-cleanup-consumer";

fn tenant_id() -> Uuid {
    Uuid::from_u128(0x1100_0000_0000_0000_0000_0000_0000_0001)
}

fn user_id() -> Uuid {
    Uuid::from_u128(0x2200_0000_0000_0000_0000_0000_0000_0001)
}

fn device_id() -> Uuid {
    Uuid::from_u128(0x3300_0000_0000_0000_0000_0000_0000_0001)
}

fn service_id() -> Uuid {
    Uuid::from_u128(0x4400_0000_0000_0000_0000_0000_0000_0001)
}

const DEVICE_SPKI: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[derive(Clone)]
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
        let ca_key = KeyPair::generate().expect("peer CA key");
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "M7 peer cleanup CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = params.self_signed(&ca_key).expect("peer CA certificate");
        Self {
            ca_pem: ca.pem(),
            ca,
            ca_key,
        }
    }

    fn issue_peer(&self, node_id: &str) -> Leaf {
        let key = KeyPair::generate().expect("peer leaf key");
        let mut params =
            CertificateParams::new(vec!["localhost".to_owned()]).expect("peer leaf parameters");
        params
            .distinguished_name
            .push(DnType::CommonName, format!("peer/{node_id}"));
        params.subject_alt_names.push(SanType::URI(
            format!("urn:agent-tunnel:peer:{node_id}")
                .try_into()
                .expect("peer URI SAN"),
        ));
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let certificate = params
            .signed_by(&key, &self.ca, &self.ca_key)
            .expect("peer leaf certificate");
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

#[derive(serde::Serialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    exp: usize,
    scope: String,
}

fn oidc_fixture() -> (Arc<OidcVerifier>, String) {
    let (verifier, token, _signer) = oidc_fixture_with_signer();
    (verifier, token)
}

/// Build the verifier and a 60-second consumer token, and keep the signing
/// key so a test can mint a second token with a deliberately short lifetime
/// without re-seeding the verifier.
fn oidc_fixture_with_signer() -> (Arc<OidcVerifier>, String, EncodingKey) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("OIDC signing key");
    let approved = tunnel_catalog::ApprovedJwk::from_ed25519_der("cleanup", key.public_key_raw())
        .expect("OIDC verification key");
    let config =
        OidcConfig::new(ISSUER, [AUDIENCE.to_owned()], vec![approved]).expect("OIDC config");
    let verifier = Arc::new(OidcVerifier::new(config).expect("OIDC verifier"));
    let signer = EncodingKey::from_ed_der(key.serialized_der());
    let token = mint_consumer_token(&signer, 60);
    (verifier, token, signer)
}

/// Mint a consumer bearer token that expires `lifetime_secs` from now.
fn mint_consumer_token(signer: &EncodingKey, lifetime_secs: i64) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("cleanup".to_owned());
    let claims = Claims {
        iss: ISSUER.to_owned(),
        sub: SUBJECT.to_owned(),
        aud: AUDIENCE.to_owned(),
        exp: (Utc::now().timestamp() + lifetime_secs) as usize,
        scope: crate::ECHO_OPERATION.to_owned(),
    };
    encode(&header, &claims, signer).expect("OIDC token")
}

fn catalog_fixture(now: chrono::DateTime<Utc>) -> CatalogFixture {
    CatalogFixture {
        tenants: vec![TenantRecord {
            tenant_id: tenant_id(),
            display_name: "cleanup tenant".to_owned(),
            active: true,
        }],
        users: vec![UserRecord {
            user_id: user_id(),
            display_name: "cleanup consumer".to_owned(),
        }],
        identities: vec![PrincipalIdentity {
            issuer: ISSUER.to_owned(),
            subject: SUBJECT.to_owned(),
            user_id: user_id(),
        }],
        memberships: vec![CatalogMembershipRecord {
            tenant_id: tenant_id(),
            user_id: user_id(),
            role: tunnel_catalog::MembershipRole::Member,
            active: true,
        }],
        devices: vec![FixtureDevice {
            tenant_id: tenant_id(),
            device_id: device_id(),
            owner_user_id: user_id(),
            display_name: "cleanup device".to_owned(),
            active: true,
            last_seen_at: Some(now),
        }],
        credentials: vec![CredentialRecord {
            tenant_id: tenant_id(),
            device_id: device_id(),
            credential_id: Uuid::from_u128(0x5500_0000_0000_0000_0000_0000_0000_0001),
            spki_fingerprint: DEVICE_SPKI.to_owned(),
            serial: Some("cleanup-device".to_owned()),
            not_before: now - ChronoDuration::seconds(1),
            expires_at: now + ChronoDuration::minutes(5),
            revoked_at: None,
            active: true,
        }],
        services: vec![ServiceSpec {
            tenant_id: tenant_id(),
            device_id: device_id(),
            service_id: service_id(),
            service_type: "echo".to_owned(),
            display_name: "Echo".to_owned(),
            capabilities: serde_json::json!({"operations": ["echo:invoke"]}),
            version: 1,
            active: true,
        }],
        grants: vec![GrantSpec {
            tenant_id: tenant_id(),
            principal_id: user_id(),
            device_id: device_id(),
            service_id: service_id(),
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            expires_at: Some(now + ChronoDuration::minutes(5)),
            active: true,
        }],
    }
}

fn encode_peer_record(kind: PeerRecordKind, body: &[u8]) -> Bytes {
    let body_len = u32::try_from(body.len()).expect("peer record body length");
    let mut encoded = Vec::with_capacity(8 + body.len());
    encoded.extend_from_slice(&body_len.to_be_bytes());
    encoded.push(kind.code());
    encoded.extend_from_slice(&[0, 0, 0]);
    encoded.extend_from_slice(body);
    Bytes::from(encoded)
}

fn test_limits() -> PeerTransportLimits {
    PeerTransportLimits::new_with_timeouts(
        64 * 1024,
        256 * 1024,
        1024 * 1024,
        4,
        4,
        4,
        16 * 1024,
        Duration::from_secs(3),
        Duration::from_secs(3),
        Duration::from_secs(2),
        Duration::from_secs(3),
    )
    .expect("bounded peer limits")
}

fn spki(leaf: &Leaf) -> String {
    spki_sha256_from_der(&leaf.der).expect("peer SPKI").to_hex()
}

fn approved_pin(leaf: &Leaf) -> ApprovedPeerPins {
    let pin: SpkiSha256 = spki_sha256_from_der(&leaf.der).expect("peer SPKI");
    ApprovedPeerPins::new([pin]).expect("approved peer pin")
}

fn membership_bindings(
    source: &Leaf,
    destination: &Leaf,
    source_addr: SocketAddr,
    destination_addr: SocketAddr,
) -> (VerifiedPeerBinding, VerifiedPeerBinding) {
    let source_spki = spki(source);
    let destination_spki = spki(destination);
    let endpoint_policy = PrivateEndpointPolicy::allowlisted(
        ["127.0.0.1"],
        ["localhost"],
        [source_addr.port(), destination_addr.port()],
    )
    .expect("endpoint policy");
    let policy = MembershipPolicy::new(DEPLOYMENT_ID, DEPLOYMENT_INCARNATION, endpoint_policy)
        .expect("membership policy");
    let (issuer, _) =
        MembershipIssuer::generate("m7-peer-cleanup-publisher").expect("membership issuer");
    let trusted = TrustedPublisherKey::new(
        "m7-peer-cleanup-publisher",
        issuer.public_key().expect("publisher key"),
    )
    .expect("trusted publisher");
    let mut verifier = MembershipVerifier::new(policy, [trusted]).expect("membership verifier");
    let now = Utc::now();
    let checkpoint = MembershipCheckpoint {
        schema_version: MEMBERSHIP_SCHEMA_VERSION,
        deployment_id: DEPLOYMENT_ID.to_owned(),
        deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
        checkpoint_version: 1,
        nonce: MEMBERSHIP_NONCE.to_owned(),
        minimum_versions: BTreeMap::from([
            (SOURCE_NODE.to_owned(), 1),
            (DESTINATION_NODE.to_owned(), 1),
        ]),
        issued_at: now - ChronoDuration::seconds(1),
        not_before: now - ChronoDuration::seconds(1),
        expires_at: now + ChronoDuration::seconds(30),
    };
    let checkpoint_bytes = issuer
        .sign_checkpoint_bytes(checkpoint)
        .expect("signed checkpoint");
    verifier
        .verify_checkpoint(&checkpoint_bytes, MEMBERSHIP_NONCE, now)
        .expect("verified checkpoint");

    let make_record = |node_id: &str, peer: &Leaf, endpoint: SocketAddr| MembershipRecord {
        schema_version: MEMBERSHIP_SCHEMA_VERSION,
        deployment_id: DEPLOYMENT_ID.to_owned(),
        deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
        node_id: node_id.to_owned(),
        record_version: 1,
        roles: vec![RELAY_PEER_ROLE.to_owned()],
        peer_endpoint: endpoint.to_string(),
        server_name: "localhost".to_owned(),
        keys: vec![RelayKey {
            key_id: format!("{node_id}-key"),
            spki_sha256: spki(peer),
            not_before: now - ChronoDuration::seconds(1),
            expires_at: now + ChronoDuration::seconds(30),
            revoked: false,
        }],
        issued_at: now - ChronoDuration::seconds(1),
        not_before: now - ChronoDuration::seconds(1),
        expires_at: now + ChronoDuration::seconds(30),
    };
    let source_record = issuer
        .sign_membership_bytes(make_record(SOURCE_NODE, source, source_addr))
        .expect("signed source membership");
    let destination_record = issuer
        .sign_membership_bytes(make_record(DESTINATION_NODE, destination, destination_addr))
        .expect("signed destination membership");
    let source_membership = verifier
        .verify_membership(&source_record, now)
        .expect("verified source membership");
    let destination_membership = verifier
        .verify_membership(&destination_record, now)
        .expect("verified destination membership");
    (
        source_membership
            .bind_peer(SOURCE_NODE, SOURCE_BOOT, &source_spki, now)
            .expect("source binding"),
        destination_membership
            .bind_peer(DESTINATION_NODE, DESTINATION_BOOT, &destination_spki, now)
            .expect("destination binding"),
    )
}

struct RecordingHandler<H> {
    inner: H,
    returned_errors: Arc<AtomicUsize>,
}

impl<H> PeerIngressHandler for RecordingHandler<H>
where
    H: PeerIngressHandler,
{
    fn handle(&self, request: InboundPeerRequest) -> PeerIngressHandlerFuture {
        let future = self.inner.handle(request);
        let returned_errors = Arc::clone(&self.returned_errors);
        Box::pin(async move {
            let result = future.await;
            if result.is_err() {
                returned_errors.fetch_add(1, Ordering::AcqRel);
            }
            result
        })
    }
}

async fn drain_queues(
    control_rx: &mut mpsc::Receiver<ControlOutbound>,
    data_rx: &mut mpsc::Receiver<DataOutbound>,
) {
    loop {
        let mut drained = false;
        while let Ok(item) = control_rx.try_recv() {
            drained = true;
            if let ControlOutbound::Text(mut text) = item {
                text.release();
            }
        }
        while let Ok(item) = data_rx.try_recv() {
            drained = true;
            match item {
                DataOutbound::Binary(mut bytes) => bytes.release(),
                DataOutbound::Barrier(done) => {
                    let _ = done.send(());
                }
                DataOutbound::Close => {}
            }
        }
        if !drained {
            break;
        }
        tokio::task::yield_now().await;
    }
}

/// Reply OPENED for one queued consumer OPEN exactly as a real connector
/// would.  Cleanup paths that emit a terminal FIN require an admitted stream;
/// the owner defers the close of an unadmitted OPEN until its outcome.
async fn admit_open(
    handle: &RelayHandle,
    key: &crate::actor::SessionKey,
    open: &tunnel_protocol::Open,
) {
    handle
        .inbound_control(
            key.clone(),
            ControlMessage::Opened(tunnel_protocol::Opened::new(
                format!("{}-opened", open.message_id),
                open.message_id.clone(),
                key.session_id.clone(),
                key.epoch,
                open.stream_id,
                open.operation_id.clone(),
                open.initial_send_window,
                open.initial_receive_window,
            )),
        )
        .await
        .expect("deliver OPENED for the queued OPEN");
}

#[tokio::test]
async fn peer_consumer_error_reclaims_scoped_stream_and_queue_charge() {
    let now = Utc::now();
    let catalog = Arc::new(MemoryCatalog::new());
    catalog
        .seed_fixture(&catalog_fixture(now))
        .await
        .expect("seed cleanup catalog");
    let (oidc, token) = oidc_fixture();
    let mut options = RelayOptions::new(oidc.clone());
    options.node_id = DESTINATION_NODE.to_owned();
    options.boot_id = DESTINATION_BOOT.to_owned();
    options.deployment_incarnation = DEPLOYMENT_INCARNATION.to_owned();
    let handle = RelayHandle::spawn(options, catalog.clone());

    let device = catalog
        .resolve_device(DEVICE_SPKI, Utc::now())
        .await
        .expect("resolve device")
        .expect("device identity");
    let mut hello = Hello::new("peer-cleanup-hello", device_id().to_string(), 1, 0);
    hello.features = vec![
        wire::M1_PROFILE_FEATURE.to_owned(),
        wire::ORDERED_ROTATION_FEATURE.to_owned(),
        "echo".to_owned(),
    ];
    let registration = handle
        .register_forwarded_control(device.clone(), DEVICE_SPKI.to_owned(), hello)
        .await
        .expect("admit M2 control session");
    let key = registration.key.clone();
    let mut control_rx = registration.rx;
    let welcome = match wire::parse_control(registration.welcome.as_bytes()).expect("WELCOME") {
        ControlMessage::Welcome(welcome) => welcome,
        other => panic!("unexpected registration response: {other:?}"),
    };
    let ticket = welcome.attachment_ticket;
    // Owner admission advances the catalog owner epoch.  Resolve the device
    // again before attaching the carrier so the forwarded path proves the
    // same generation fence used by a real data socket.
    let data_device = catalog
        .resolve_device(DEVICE_SPKI, Utc::now())
        .await
        .expect("resolve data device")
        .expect("data device identity");
    let data_registration = handle
        .attach_forwarded_data(data_device, DEVICE_SPKI.to_owned(), ticket)
        .await
        .expect("attach data carrier");
    let mut data_rx = data_registration.rx;

    let owner = catalog
        .current_owner(tenant_id(), device_id(), Utc::now())
        .await
        .expect("read owner")
        .expect("owner claim");

    let pki = FixturePki::new();
    let source_leaf = pki.issue_peer(SOURCE_NODE);
    let destination_leaf = pki.issue_peer(DESTINATION_NODE);
    let destination_chain = pki.chain(&destination_leaf);
    let server_config = load_peer_server_config_from_pem(
        destination_chain.as_bytes(),
        destination_leaf.private_key_pem.as_bytes(),
        pki.ca_pem.as_bytes(),
    )
    .expect("peer server TLS config");
    let server_endpoint =
        quinn::Endpoint::server(server_config, SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("peer server endpoint");
    let destination_addr = server_endpoint.local_addr().expect("server address");
    let mut client_endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("peer client endpoint");
    let source_addr = client_endpoint.local_addr().expect("client address");
    let source_chain = pki.chain(&source_leaf);
    let client_config = load_peer_client_config_from_pem(
        source_chain.as_bytes(),
        source_leaf.private_key_pem.as_bytes(),
        pki.ca_pem.as_bytes(),
    )
    .expect("peer client TLS config");
    client_endpoint.set_default_client_config(client_config);

    let (source_binding, destination_binding) = membership_bindings(
        &source_leaf,
        &destination_leaf,
        source_addr,
        destination_addr,
    );
    let source_binding_for_provider = source_binding.clone();
    let destination_binding_for_provider = destination_binding.clone();
    let provider = move |node_id: &str, boot_id: &str, _now| {
        let result = if node_id == SOURCE_NODE && boot_id == SOURCE_BOOT {
            Ok(source_binding_for_provider.clone())
        } else if node_id == DESTINATION_NODE && boot_id == DESTINATION_BOOT {
            Ok(destination_binding_for_provider.clone())
        } else {
            Err(PeerRuntimeError::Membership(
                "unknown cleanup test peer".to_owned(),
            ))
        };
        async move { result }
    };
    let identity = RelayIdentity::new(DEPLOYMENT_INCARNATION, SOURCE_NODE, SOURCE_BOOT)
        .expect("source relay identity");
    let router: Arc<OwnerRouter<dyn Catalog>> =
        Arc::new(OwnerRouter::new(catalog.clone(), identity).expect("owner router"));
    let limits = test_limits();
    let client = PeerClient::new(
        client_endpoint,
        approved_pin(&destination_leaf),
        limits.clone(),
    )
    .expect("peer client");
    let raw_client = client.clone();
    let runtime = Arc::new(PeerRuntime::new(
        client,
        router,
        Arc::new(provider),
        SOURCE_NODE,
        SOURCE_BOOT,
    ));
    let returned_errors = Arc::new(AtomicUsize::new(0));
    let production_handler = peer_ingress_handler(
        handle.clone(),
        catalog.clone(),
        oidc,
        DESTINATION_NODE.to_owned(),
        DESTINATION_BOOT.to_owned(),
    );
    let server_handler = runtime.server_handler(RecordingHandler {
        inner: production_handler,
        returned_errors: Arc::clone(&returned_errors),
    });
    let server = PeerServer::new(
        server_endpoint,
        approved_pin(&source_leaf),
        limits,
        PeerRuntime::server_policy(),
        server_handler,
    )
    .expect("peer server");
    let server_cancel = CancellationToken::new();
    let server_task = tokio::spawn(server.serve(server_cancel.clone()));

    let route = OwnerRoute::Remote {
        owner: owner.clone(),
        peer: Some(destination_binding),
    };
    let source = PeerIdentity::new(SOURCE_NODE, SOURCE_BOOT);
    let destination = Destination::new(owner.token.clone(), service_id());
    let bearer = ForwardedConsumerBearer::new(token.clone(), owner.token.clone()).expect("bearer");
    let envelope = RequestEnvelope::new(
        InternalRoute::ConsumerStreams,
        "peer-cleanup-request",
        source.clone(),
        destination.clone(),
        1_000,
        Some(1_000),
        InternalRequest::ConsumerStreams(ConsumerStreamsRequest {
            stream_id: "peer-cleanup-stream".to_owned(),
            required_scope: crate::ECHO_OPERATION.to_owned(),
            bearer,
            bytes: Vec::new(),
        }),
    );
    let exchange = runtime
        .open(&route, envelope)
        .await
        .expect("open production peer request");
    let (mut send, mut recv) = exchange.split();
    timeout(Duration::from_secs(3), recv.accept_response())
        .await
        .expect("peer response deadline")
        .expect("peer response headers")
        .status();

    let open = loop {
        let item = timeout(Duration::from_secs(3), control_rx.recv())
            .await
            .expect("OPEN queue deadline")
            .expect("control registration remains live");
        match item {
            ControlOutbound::Text(text) => {
                let (text, mut charge) = text.into_parts();
                let parsed = wire::parse_control(text.as_bytes()).expect("OPEN control");
                charge.release();
                if let ControlMessage::Open(open) = parsed {
                    break open;
                }
            }
            ControlOutbound::Close => {}
        }
    };
    // The connector admits the OPEN.  The cleanup paths below must close an
    // admitted stream through the real terminal FIN path; an unadmitted OPEN
    // is deferred until the owner outcome instead.
    admit_open(&handle, &key, &open).await;

    let mut record = (7_u32).to_be_bytes().to_vec();
    record.extend_from_slice(b"drop-me");
    send.send_message(PeerRecordKind::ConsumerChunk, &record)
        .await
        .expect("send consumer record");
    timeout(Duration::from_secs(3), async {
        loop {
            let snapshot = handle.snapshot().await.expect("snapshot while queued");
            if snapshot.sessions.iter().any(|session| {
                session
                    .streams
                    .iter()
                    .any(|stream| stream.stream_id == open.stream_id && stream.queue_bytes > 0)
            }) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("pending consumer body was charged");

    // Open a second real H3 stream through the transport-level API so the
    // next peer record can be deliberately truncated. The owner handler
    // must return the decoder error and its returned-error cleanup guard must
    // terminalize this stream while the first stream still holds its queued
    // consumer body.
    let raw_bearer = ForwardedConsumerBearer::new(token, owner.token.clone()).expect("raw bearer");
    let raw_envelope = RequestEnvelope::new(
        InternalRoute::ConsumerStreams,
        "peer-cleanup-raw-request",
        source.clone(),
        destination.clone(),
        1_000,
        Some(1_000),
        InternalRequest::ConsumerStreams(ConsumerStreamsRequest {
            stream_id: "peer-cleanup-raw-stream".to_owned(),
            required_scope: crate::ECHO_OPERATION.to_owned(),
            bearer: raw_bearer,
            bytes: Vec::new(),
        }),
    );
    let raw_request = Request::builder()
        .method("POST")
        .uri(format!(
            "https://localhost{}",
            PeerRuntime::path(InternalRoute::ConsumerStreams)
        ))
        .header("content-type", "application/octet-stream")
        .body(())
        .expect("raw peer request");
    let mut raw_stream = raw_client
        .open(
            PeerDestination::new(destination_addr, "localhost"),
            raw_request,
        )
        .await
        .expect("open raw peer request");
    raw_stream
        .send_chunk(encode_peer_record(
            PeerRecordKind::CompleteControlText,
            &raw_envelope.encode().expect("encode raw envelope"),
        ))
        .await
        .expect("send raw envelope");
    let raw_response = timeout(Duration::from_secs(3), raw_stream.recv_response())
        .await
        .expect("raw peer response deadline")
        .expect("raw peer response headers");
    assert!(raw_response.status().is_success());
    let raw_open = loop {
        let item = timeout(Duration::from_secs(3), control_rx.recv())
            .await
            .expect("raw OPEN queue deadline")
            .expect("control registration remains live");
        match item {
            ControlOutbound::Text(text) => {
                let (text, mut charge) = text.into_parts();
                let parsed = wire::parse_control(text.as_bytes()).expect("raw OPEN control");
                charge.release();
                if let ControlMessage::Open(open) = parsed {
                    break open;
                }
            }
            ControlOutbound::Close => {}
        }
    };
    admit_open(&handle, &key, &raw_open).await;
    let returned_errors_before_raw = returned_errors.load(Ordering::Acquire);
    let mut truncated = Vec::with_capacity(8);
    truncated.extend_from_slice(&1_u32.to_be_bytes());
    truncated.extend_from_slice(&[PeerRecordKind::ConsumerChunk.code(), 0, 0, 0]);
    raw_stream
        .send_chunk(Bytes::from(truncated))
        .await
        .expect("send truncated peer record prefix");
    let _ = raw_stream.finish().await;
    timeout(Duration::from_secs(3), async {
        loop {
            if returned_errors.load(Ordering::Acquire) > returned_errors_before_raw {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("raw peer handler returned-error deadline");
    timeout(Duration::from_secs(3), async {
        loop {
            let snapshot = handle.snapshot().await.expect("raw cleanup snapshot");
            let Some(session) = snapshot.sessions.first() else {
                tokio::task::yield_now().await;
                continue;
            };
            let raw_terminal = session
                .streams
                .iter()
                .any(|stream| stream.stream_id == raw_open.stream_id && stream.terminal);
            let first_still_charged = session
                .streams
                .iter()
                .any(|stream| stream.stream_id == open.stream_id && stream.queue_bytes > 0);
            if raw_terminal && first_still_charged {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("raw returned-error cleanup deadline");

    catalog
        .revoke_grant(
            tenant_id(),
            user_id(),
            device_id(),
            service_id(),
            Utc::now(),
        )
        .await
        .expect("revoke grant for returned error");
    let challenge = tunnel_protocol::AuthorizationChallenge::new(
        "peer-cleanup-challenge",
        key.session_id.clone(),
        key.epoch,
        open.stream_id,
        "peer-cleanup-challenge-id",
        "peer-cleanup-nonce",
        open.service_id.clone(),
        open.metadata
            .get("permission_digest")
            .expect("OPEN permission digest")
            .clone(),
        open.metadata
            .get("grant_revision")
            .expect("OPEN grant revision")
            .parse()
            .expect("grant revision"),
    );
    let returned_errors_before_challenge = returned_errors.load(Ordering::Acquire);
    handle
        .inbound_control(
            key.clone(),
            ControlMessage::AuthorizationChallenge(challenge),
        )
        .await
        .expect("deliver authorization challenge");
    timeout(Duration::from_secs(3), async {
        loop {
            if returned_errors.load(Ordering::Acquire) > returned_errors_before_challenge {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("peer handler returned-error deadline");
    timeout(Duration::from_secs(3), async {
        loop {
            drain_queues(&mut control_rx, &mut data_rx).await;
            let snapshot = handle.snapshot().await.expect("cleanup snapshot");
            let clean = snapshot.sessions.len() == 1
                && snapshot.sessions[0].queue_bytes == 0
                && snapshot.sessions[0]
                    .streams
                    .iter()
                    .any(|stream| stream.stream_id == open.stream_id && stream.terminal);
            if clean {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("scoped stream cleanup and queue release deadline");

    let _ = timeout(Duration::from_secs(3), recv.recv_message()).await;
    server_cancel.cancel();
    let server_result = timeout(Duration::from_secs(3), server_task)
        .await
        .expect("peer server shutdown deadline")
        .expect("peer server join");
    assert!(
        server_result.is_ok(),
        "peer server returned {server_result:?}"
    );
    runtime.shutdown().await.expect("peer runtime shutdown");
    handle.shutdown().await.expect("relay shutdown");
}

/// EC-035 device HELLO version negotiation: a device advertising a protocol
/// major this relay does not speak is refused with a typed protocol outcome
/// before any owner lease, session, or dispatch state is created, and there is
/// no silent fallback to the supported generation.
#[tokio::test]
async fn device_hello_unsupported_or_missing_major_is_refused_before_state() {
    let now = Utc::now();
    let catalog = Arc::new(MemoryCatalog::new());
    catalog
        .seed_fixture(&catalog_fixture(now))
        .await
        .expect("seed cleanup catalog");
    let (oidc, _token) = oidc_fixture();
    let mut options = RelayOptions::new(oidc);
    options.node_id = DESTINATION_NODE.to_owned();
    options.boot_id = DESTINATION_BOOT.to_owned();
    options.deployment_incarnation = DEPLOYMENT_INCARNATION.to_owned();
    let handle = RelayHandle::spawn(options, catalog.clone());

    let device = catalog
        .resolve_device(DEVICE_SPKI, Utc::now())
        .await
        .expect("resolve device")
        .expect("device identity");

    // A HELLO from an incompatible protocol generation.  Even with every
    // required feature advertised, the exact major-version check refuses it;
    // there is no fallback branch that downgrades it to the supported major.
    let unsupported_major = u16::from(crate::PROTOCOL_MAJOR) + 1;
    let mut hello = Hello::new(
        "ec035-unsupported-hello",
        device_id().to_string(),
        unsupported_major,
        0,
    );
    hello.features = vec![
        wire::M1_PROFILE_FEATURE.to_owned(),
        wire::ORDERED_ROTATION_FEATURE.to_owned(),
        wire::OWNER_FENCING_FEATURE.to_owned(),
        "echo".to_owned(),
    ];
    let outcome = handle
        .register_forwarded_control(device.clone(), DEVICE_SPKI.to_owned(), hello)
        .await;
    match outcome {
        Err(crate::RelayError::Protocol(_)) => {}
        Err(other) => panic!("expected a typed protocol outcome, got {other:?}"),
        Ok(_) => panic!("an unsupported protocol major must be refused"),
    }

    // No owner lease was taken and no session state was created for the
    // refused device.
    assert!(
        catalog
            .current_owner(tenant_id(), device_id(), Utc::now())
            .await
            .expect("read owner after refusal")
            .is_none(),
        "a refused HELLO must not create an owner lease"
    );
    let snapshot = handle.snapshot().await.expect("snapshot after refusal");
    assert!(
        snapshot
            .sessions
            .iter()
            .all(|session| session.device_id != device_id().to_string()),
        "a refused HELLO must not create a session"
    );
    assert_eq!(
        snapshot.lifetime_application_dispatches, 0,
        "a refused HELLO must not dispatch"
    );

    // A version-0 HELLO (a missing/zero major) is refused the same way.
    let mut zero_major = Hello::new("ec035-zero-hello", device_id().to_string(), 0, 0);
    zero_major.features = vec![
        wire::M1_PROFILE_FEATURE.to_owned(),
        wire::ORDERED_ROTATION_FEATURE.to_owned(),
        wire::OWNER_FENCING_FEATURE.to_owned(),
        "echo".to_owned(),
    ];
    match handle
        .register_forwarded_control(device, DEVICE_SPKI.to_owned(), zero_major)
        .await
    {
        Err(crate::RelayError::Protocol(_)) => {}
        Err(other) => panic!("expected a typed protocol outcome, got {other:?}"),
        Ok(_) => panic!("a zero protocol major must be refused"),
    }

    handle.shutdown().await.expect("relay shutdown");
}

#[cfg(test)]
#[path = "peer_cleanup_h3_tests.rs"]
mod peer_cleanup_h3_tests;
