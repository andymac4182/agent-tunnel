//! Public HTTP/forwarding boundary for the real authenticated H3 GOAWAY path.
//!
//! This is deliberately separate from the transport component fixture.  It
//! installs a production `router_with_peer`, a real `PeerRuntime`, an
//! authoritative in-memory owner/catalog route, and a signed OIDC consumer.
//! The synthetic H3 owner sends one response after admitting the first public
//! request, then sends a wire GOAWAY while that response remains unfinished.
//! A direct bounded open waits for the typed pre-open `GoAway` outcome before
//! the second public request, removing the delivery race from the HTTP
//! assertion.  The second request must return `503 PEER_UNAVAILABLE` with
//! `execution=not_dispatched`; the first request then completes and the owner
//! dispatch counter remains exactly one.
//!
//! This closes only the public forwarding boundary.  It does not claim the
//! full three-relay rotation/I08 row or an actual adapter operation.

use std::{
    cmp::min,
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::body::{Body, to_bytes};
use bytes::{Buf, Bytes};
use chrono::{Duration as ChronoDuration, Utc};
use http::{Method, Request, Response, StatusCode, header};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use tokio::{
    sync::Notify,
    task::JoinHandle,
    time::{Instant, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use tunnel_catalog::{
    Catalog, CatalogFixture, FixtureDevice, GrantSpec, MembershipRecord, MembershipRole,
    MemoryCatalog, OidcConfig, OidcVerifier, PermissionSet, PrincipalIdentity, ServiceSpec,
    TenantRecord, UserRecord,
};
use tunnel_cluster::{
    envelope::{
        ConsumerStreamsRequest, Destination, ForwardedConsumerBearer, InternalRequest,
        InternalRoute, RequestEnvelope, decode_envelope,
    },
    membership::{
        MEMBERSHIP_SCHEMA_VERSION, MembershipCheckpoint, MembershipIssuer, MembershipPolicy,
        MembershipRecord as ClusterMembershipRecord, MembershipVerifier, PrivateEndpointPolicy,
        RELAY_PEER_ROLE, RelayKey, TrustedPublisherKey, VerifiedPeerBinding,
    },
    peer_frame::{ConnectionBudget, PeerRecord, PeerRecordDecoder, PeerRecordKind},
};
use tunnel_relay::{
    PeerRuntime, PeerRuntimeError, Relay, RelayLimits, RelayOptions, router_with_peer,
    routing::{OwnerRouter, OwnerScope, RelayIdentity},
};
use tunnel_transport::{
    ApprovedPeerPins, PeerClient, PeerDestination, PeerTransportError, PeerTransportLimits,
    load_peer_client_config_from_pem, load_peer_server_config_from_pem, spki_sha256_from_der,
};
use uuid::Uuid;

const DEPLOYMENT_ID: &str = "m7-public-goaway-deployment";
const DEPLOYMENT_INCARNATION: &str = "m7-public-goaway-incarnation";
const SOURCE_NODE: &str = "m7-public-goaway-ingress";
const SOURCE_BOOT: &str = "m7-public-goaway-ingress-boot";
const OWNER_NODE: &str = "m7-public-goaway-owner";
const OWNER_BOOT: &str = "m7-public-goaway-owner-boot";
const ISSUER: &str = "https://m7-public-goaway-issuer.example";
const AUDIENCE: &str = "m7-public-goaway-audience";
const SUBJECT: &str = "m7-public-goaway-consumer";
const SERVER_NAME: &str = "localhost";
const CASE_TIMEOUT: Duration = Duration::from_secs(3);
const GOAWAY_DRAIN_QUIET: Duration = Duration::from_millis(100);
const RESPONSE_BODY: &[u8] = b"public-admitted-before-goaway";
const FIRST_REQUEST_BODY: &[u8] = b"first-public-body";
const MAX_FORWARDED_REQUEST_BYTES: usize = 128 * 1024;
const DEVICE_ID: Uuid = Uuid::from_u128(0x3300_0000_0000_0000_0000_0000_0000_0001);
const SERVICE_ID: Uuid = Uuid::from_u128(0x4400_0000_0000_0000_0000_0000_0000_0001);
const TENANT_ID: Uuid = Uuid::from_u128(0x1100_0000_0000_0000_0000_0000_0000_0001);
const USER_ID: Uuid = Uuid::from_u128(0x2200_0000_0000_0000_0000_0000_0000_0001);

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

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
        let ca_key = KeyPair::generate().expect("public GOAWAY CA key");
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "M7 public GOAWAY CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = params
            .self_signed(&ca_key)
            .expect("public GOAWAY CA certificate");
        Self {
            ca_pem: ca.pem(),
            ca,
            ca_key,
        }
    }

    fn issue_peer(&self, node_id: &str) -> Leaf {
        let key = KeyPair::generate().expect("public GOAWAY peer key");
        let mut params =
            CertificateParams::new(vec![SERVER_NAME.to_owned()]).expect("public GOAWAY peer");
        params
            .distinguished_name
            .push(DnType::CommonName, format!("peer/{node_id}"));
        params.subject_alt_names.push(SanType::URI(
            format!("urn:agent-tunnel:peer:{node_id}")
                .try_into()
                .expect("public GOAWAY peer URI SAN"),
        ));
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let certificate = params
            .signed_by(&key, &self.ca, &self.ca_key)
            .expect("public GOAWAY peer certificate");
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
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("public OIDC signing key");
    let approved =
        tunnel_catalog::ApprovedJwk::from_ed25519_der("public-goaway", key.public_key_raw())
            .expect("public OIDC verification key");
    let config =
        OidcConfig::new(ISSUER, [AUDIENCE.to_owned()], vec![approved]).expect("public OIDC config");
    let verifier = Arc::new(OidcVerifier::new(config).expect("public OIDC verifier"));
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("public-goaway".to_owned());
    let claims = Claims {
        iss: ISSUER.to_owned(),
        sub: SUBJECT.to_owned(),
        aud: AUDIENCE.to_owned(),
        exp: (Utc::now().timestamp() + 60) as usize,
        scope: tunnel_relay::ECHO_OPERATION.to_owned(),
    };
    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_ed_der(key.serialized_der()),
    )
    .expect("public OIDC token");
    (verifier, token)
}

fn catalog_fixture(now: chrono::DateTime<Utc>) -> CatalogFixture {
    CatalogFixture {
        tenants: vec![TenantRecord {
            tenant_id: TENANT_ID,
            display_name: "public GOAWAY tenant".to_owned(),
            active: true,
        }],
        users: vec![UserRecord {
            user_id: USER_ID,
            display_name: "public GOAWAY user".to_owned(),
        }],
        identities: vec![PrincipalIdentity {
            issuer: ISSUER.to_owned(),
            subject: SUBJECT.to_owned(),
            user_id: USER_ID,
        }],
        memberships: vec![MembershipRecord {
            tenant_id: TENANT_ID,
            user_id: USER_ID,
            role: MembershipRole::Member,
            active: true,
        }],
        devices: vec![FixtureDevice {
            tenant_id: TENANT_ID,
            device_id: DEVICE_ID,
            owner_user_id: USER_ID,
            display_name: "public GOAWAY device".to_owned(),
            active: true,
            last_seen_at: Some(now),
        }],
        credentials: Vec::new(),
        services: vec![ServiceSpec {
            tenant_id: TENANT_ID,
            device_id: DEVICE_ID,
            service_id: SERVICE_ID,
            service_type: "echo".to_owned(),
            display_name: "Public GOAWAY echo".to_owned(),
            capabilities: serde_json::json!({"operations": [tunnel_relay::ECHO_OPERATION]}),
            version: 1,
            active: true,
        }],
        grants: vec![GrantSpec {
            tenant_id: TENANT_ID,
            principal_id: USER_ID,
            device_id: DEVICE_ID,
            service_id: SERVICE_ID,
            permissions: PermissionSet {
                operations: BTreeSet::from([tunnel_relay::ECHO_OPERATION.to_owned()]),
            },
            constraints: serde_json::json!({}),
            expires_at: Some(now + ChronoDuration::minutes(5)),
            active: true,
        }],
    }
}

fn spki(leaf: &Leaf) -> String {
    spki_sha256_from_der(&leaf.der)
        .expect("public GOAWAY SPKI")
        .to_hex()
}

fn membership_bindings(
    source: &Leaf,
    owner: &Leaf,
    source_addr: SocketAddr,
    owner_addr: SocketAddr,
) -> (VerifiedPeerBinding, VerifiedPeerBinding) {
    let source_spki = spki(source);
    let owner_spki = spki(owner);
    let endpoint_policy = PrivateEndpointPolicy::allowlisted(
        ["127.0.0.1"],
        [SERVER_NAME],
        [source_addr.port(), owner_addr.port()],
    )
    .expect("public endpoint policy");
    let policy = MembershipPolicy::new(DEPLOYMENT_ID, DEPLOYMENT_INCARNATION, endpoint_policy)
        .expect("public membership policy");
    let (issuer, _) =
        MembershipIssuer::generate("public-goaway-publisher").expect("public membership issuer");
    let trusted = TrustedPublisherKey::new(
        "public-goaway-publisher",
        issuer.public_key().expect("public membership key"),
    )
    .expect("public trusted publisher");
    let mut verifier = MembershipVerifier::new(policy, [trusted]).expect("public verifier");
    let now = Utc::now();
    let checkpoint = MembershipCheckpoint {
        schema_version: MEMBERSHIP_SCHEMA_VERSION,
        deployment_id: DEPLOYMENT_ID.to_owned(),
        deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
        checkpoint_version: 1,
        nonce: "public-goaway-nonce".to_owned(),
        minimum_versions: BTreeMap::from([(SOURCE_NODE.to_owned(), 1), (OWNER_NODE.to_owned(), 1)]),
        issued_at: now - ChronoDuration::seconds(1),
        not_before: now - ChronoDuration::seconds(1),
        expires_at: now + ChronoDuration::seconds(30),
    };
    let checkpoint_bytes = issuer
        .sign_checkpoint_bytes(checkpoint)
        .expect("public checkpoint");
    verifier
        .verify_checkpoint(&checkpoint_bytes, "public-goaway-nonce", now)
        .expect("public checkpoint verification");

    let make_record = |node_id: &str, peer: &Leaf, endpoint: SocketAddr| {
        let record = ClusterMembershipRecord {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            deployment_id: DEPLOYMENT_ID.to_owned(),
            deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
            node_id: node_id.to_owned(),
            record_version: 1,
            roles: vec![RELAY_PEER_ROLE.to_owned()],
            peer_endpoint: endpoint.to_string(),
            server_name: SERVER_NAME.to_owned(),
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
        issuer
            .sign_membership_bytes(record)
            .expect("public signed membership")
    };
    let source_membership = verifier
        .verify_membership(&make_record(SOURCE_NODE, source, source_addr), now)
        .expect("public source membership");
    let owner_membership = verifier
        .verify_membership(&make_record(OWNER_NODE, owner, owner_addr), now)
        .expect("public owner membership");
    (
        source_membership
            .bind_peer(SOURCE_NODE, SOURCE_BOOT, &source_spki, now)
            .expect("public source binding"),
        owner_membership
            .bind_peer(OWNER_NODE, OWNER_BOOT, &owner_spki, now)
            .expect("public owner binding"),
    )
}

fn encode_peer_record(kind: PeerRecordKind, body: &[u8]) -> Bytes {
    let body_len = u32::try_from(body.len()).expect("public peer record length");
    let mut encoded = Vec::with_capacity(8 + body.len());
    encoded.extend_from_slice(&body_len.to_be_bytes());
    encoded.extend_from_slice(&[kind.code(), 0, 0, 0]);
    encoded.extend_from_slice(body);
    Bytes::from(encoded)
}

fn response_record(body: &[u8]) -> Bytes {
    let body_len = u32::try_from(body.len()).expect("public response length");
    let mut framed = Vec::with_capacity(4 + body.len());
    framed.extend_from_slice(&body_len.to_be_bytes());
    framed.extend_from_slice(body);
    encode_peer_record(PeerRecordKind::ConsumerChunk, &framed)
}

fn validate_forwarded_request_records(records: &[PeerRecord]) -> TestResult<()> {
    if records.len() != 2 {
        return Err("public owner received an unexpected forwarded record count".into());
    }
    let envelope_record = &records[0];
    if envelope_record.kind() != PeerRecordKind::CompleteControlText {
        return Err("public owner received a non-control envelope record".into());
    }
    let envelope = decode_envelope(envelope_record.body())?;
    if envelope.route != InternalRoute::ConsumerStreams
        || envelope.request.route() != InternalRoute::ConsumerStreams
        || envelope.source.node_id != SOURCE_NODE
        || envelope.source.boot_id != SOURCE_BOOT
    {
        return Err("public owner received an invalid forwarded envelope scope".into());
    }
    let owner = &envelope.destination.owner_token;
    if envelope.destination.tenant_id != TENANT_ID
        || envelope.destination.device_id != DEVICE_ID
        || envelope.destination.service_id != SERVICE_ID
        || owner.deployment_incarnation != DEPLOYMENT_INCARNATION
        || owner.tenant_id != TENANT_ID
        || owner.device_id != DEVICE_ID
        || owner.node_id != OWNER_NODE
        || owner.boot_id != OWNER_BOOT
        || owner.session_id != "public-goaway-owner-session"
        || owner.epoch != 1
    {
        return Err("public owner received an invalid forwarded owner scope".into());
    }
    match &envelope.request {
        InternalRequest::ConsumerStreams(request)
            if request.stream_id == envelope.request_id
                && request.required_scope == tunnel_relay::ECHO_OPERATION
                && request.bytes.is_empty()
                && request.bearer.destination_owner == *owner
                && !request.bearer.token().is_empty() => {}
        _ => return Err("public owner received an invalid consumer envelope".into()),
    }

    let body_record = &records[1];
    if body_record.kind() != PeerRecordKind::ConsumerChunk || body_record.body_len() < 4 {
        return Err("public owner received no framed consumer body".into());
    }
    let framed = body_record.body();
    let declared = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
    if declared > 65_536 || declared.saturating_add(4) != framed.len() {
        return Err("public owner received an invalid consumer body frame".into());
    }
    if framed[4..] != *FIRST_REQUEST_BODY {
        return Err("public owner received an unexpected consumer body".into());
    }
    Ok(())
}

struct GoAwayServer {
    destination: PeerDestination,
    dispatches: Arc<AtomicUsize>,
    post_goaway_resolved: Arc<AtomicUsize>,
    goaway_sent: Arc<Notify>,
    release_response: Arc<Notify>,
    response_drained: Arc<Notify>,
    drain_complete: Arc<Notify>,
    cancel: CancellationToken,
    task: JoinHandle<TestResult>,
}

impl GoAwayServer {
    fn start(pki: &FixturePki, owner: &Leaf) -> Self {
        let server_config = load_peer_server_config_from_pem(
            pki.chain(owner).as_bytes(),
            owner.private_key_pem.as_bytes(),
            pki.ca_pem.as_bytes(),
        )
        .expect("public GOAWAY server TLS");
        let endpoint =
            quinn::Endpoint::server(server_config, SocketAddr::from(([127, 0, 0, 1], 0)))
                .expect("public GOAWAY server endpoint");
        let address = endpoint.local_addr().expect("public GOAWAY server address");
        let dispatches = Arc::new(AtomicUsize::new(0));
        let post_goaway_resolved = Arc::new(AtomicUsize::new(0));
        let goaway_sent = Arc::new(Notify::new());
        let release_response = Arc::new(Notify::new());
        let response_drained = Arc::new(Notify::new());
        let drain_complete = Arc::new(Notify::new());
        let cancel = CancellationToken::new();
        let task = tokio::spawn(serve_one(
            endpoint,
            GoAwaySignals {
                dispatches: Arc::clone(&dispatches),
                post_goaway_resolved: Arc::clone(&post_goaway_resolved),
                goaway_sent: Arc::clone(&goaway_sent),
                release_response: Arc::clone(&release_response),
                response_drained: Arc::clone(&response_drained),
                drain_complete: Arc::clone(&drain_complete),
                cancel: cancel.clone(),
            },
        ));
        Self {
            destination: PeerDestination::new(address, SERVER_NAME),
            dispatches,
            post_goaway_resolved,
            goaway_sent,
            release_response,
            response_drained,
            drain_complete,
            cancel,
            task,
        }
    }

    async fn shutdown(mut self) -> TestResult {
        self.cancel.cancel();
        match timeout(CASE_TIMEOUT, &mut self.task).await {
            Ok(joined) => {
                joined??;
                Ok(())
            }
            Err(_) => {
                self.task.abort();
                let joined = timeout(CASE_TIMEOUT, &mut self.task)
                    .await
                    .map_err(|_| "public GOAWAY server abort join deadline exceeded")?;
                match joined {
                    Ok(Ok(())) => Err("public GOAWAY server exceeded join deadline".into()),
                    Ok(Err(error)) => Err(error),
                    Err(error) if error.is_cancelled() => {
                        Err("public GOAWAY server required forced cancellation".into())
                    }
                    Err(error) => Err(Box::new(error)),
                }
            }
        }
    }
}

impl Drop for GoAwayServer {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

struct GoAwaySignals {
    dispatches: Arc<AtomicUsize>,
    post_goaway_resolved: Arc<AtomicUsize>,
    goaway_sent: Arc<Notify>,
    release_response: Arc<Notify>,
    response_drained: Arc<Notify>,
    drain_complete: Arc<Notify>,
    cancel: CancellationToken,
}

async fn serve_one(endpoint: quinn::Endpoint, signals: GoAwaySignals) -> TestResult {
    let GoAwaySignals {
        dispatches,
        post_goaway_resolved,
        goaway_sent,
        release_response,
        response_drained,
        drain_complete,
        cancel,
    } = signals;
    let incoming = tokio::select! {
        _ = cancel.cancelled() => {
            endpoint.close(quinn::VarInt::from_u32(0), b"public GOAWAY canceled");
            return Ok(())
        }
        incoming = timeout(CASE_TIMEOUT, endpoint.accept()) => incoming?,
    };
    let Some(incoming) = incoming else {
        endpoint.close(quinn::VarInt::from_u32(0), b"public GOAWAY no incoming");
        return Ok(());
    };
    let connection = timeout(CASE_TIMEOUT, incoming).await??;
    let quic = h3_quinn::Connection::new(connection.clone());
    let builder = h3::server::builder();
    let mut h3_connection = timeout(CASE_TIMEOUT, builder.build::<_, Bytes>(quic)).await??;
    let resolver = timeout(CASE_TIMEOUT, h3_connection.accept())
        .await??
        .ok_or("public GOAWAY server ended before request")?;
    let (request, mut stream) = resolver.resolve_request().await?;
    if request.uri().path() != "/internal/v1/streams" {
        return Err(format!(
            "unexpected public forwarding path: {}",
            request.uri().path()
        )
        .into());
    }
    stream
        .send_response(Response::builder().status(StatusCode::OK).body(())?)
        .await?;
    timeout(CASE_TIMEOUT, h3_connection.shutdown(0)).await??;
    goaway_sent.notify_one();

    // The response headers are deliberately sent before the request body is
    // consumed: this is the same admission ordering used by the production
    // peer runtime, and it leaves the first public response unfinished while
    // the wire GOAWAY is observed.  The owner dispatch counter advances only
    // after the complete bounded envelope and ConsumerChunk body have been
    // decoded and checked.
    let connection_budget = ConnectionBudget::new();
    let stream_budget = connection_budget.open_stream()?;
    let mut decoder = PeerRecordDecoder::new(stream_budget.clone());
    let mut records = Vec::new();
    let mut received_bytes = 0usize;
    let body_deadline = Instant::now() + CASE_TIMEOUT;
    loop {
        let chunk = timeout_at(body_deadline, stream.recv_data())
            .await
            .map_err(|_| "public forwarded body deadline exceeded")??;
        let Some(mut chunk) = chunk else { break };
        received_bytes = received_bytes.saturating_add(chunk.remaining());
        if received_bytes > MAX_FORWARDED_REQUEST_BYTES {
            return Err("public forwarded body exceeded bounded validation size".into());
        }
        while chunk.has_remaining() {
            let contiguous = chunk.chunk();
            let length = contiguous.len();
            records.extend(decoder.push(contiguous)?);
            chunk.advance(length);
        }
        if records.len() > 2 {
            return Err("public owner received too many forwarded records".into());
        }
    }
    decoder.finish()?;
    validate_forwarded_request_records(&records)?;
    dispatches.fetch_add(1, Ordering::AcqRel);
    drop(records);
    drop(decoder);
    drop(stream_budget);
    if connection_budget.reserved_bytes() != 0 || connection_budget.active_streams() != 0 {
        return Err("public forwarded validation budget was not reclaimed".into());
    }

    let mut released = false;
    while !released {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = release_response.notified() => released = true,
            result = h3_connection.accept() => match result? {
                Some(resolver) => {
                    post_goaway_resolved.fetch_add(1, Ordering::AcqRel);
                    let (_, mut rejected) = timeout(CASE_TIMEOUT, resolver.resolve_request()).await??;
                    rejected.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
                }
                None => break,
            },
        }
    }
    if !released {
        connection.close(quinn::VarInt::from_u32(0), b"public GOAWAY canceled");
        endpoint.close(quinn::VarInt::from_u32(0), b"public GOAWAY server shutdown");
        return Ok(());
    }

    stream.send_data(response_record(RESPONSE_BODY)).await?;
    stream.finish().await?;

    // Keep the H3 connection alive until the client has actually drained the
    // response body.  Finishing the stream only queues the bytes; closing the
    // QUIC connection immediately after that can race the client's receive
    // path and surface as an unrelated application-close error.
    let drain_deadline = Instant::now() + CASE_TIMEOUT;
    let mut response_was_drained = false;
    let mut accept_finished = false;
    while !response_was_drained {
        if accept_finished {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                result = timeout_at(drain_deadline, response_drained.notified()) => {
                    result.map_err(|_| "public response drain deadline exceeded")?;
                    response_was_drained = true;
                }
            }
            continue;
        }
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = response_drained.notified() => response_was_drained = true,
            result = timeout_at(drain_deadline, h3_connection.accept()) => {
                let result = result
                    .map_err(|_| "public response drain deadline exceeded")??;
                let Some(resolver) = result else {
                    // h3 returns None after GOAWAY once all server-side
                    // request streams are complete. Keep the QUIC owner alive
                    // for the client acknowledgement; repeated accept calls
                    // would only busy-loop on the same graceful state.
                    accept_finished = true;
                    continue;
                };
                post_goaway_resolved.fetch_add(1, Ordering::AcqRel);
                let (_, mut rejected) =
                    timeout_at(drain_deadline, resolver.resolve_request()).await??;
                rejected.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
            }
        }
    }

    // After the client-side drain acknowledgement, retain the same absolute
    // deadline while polling the real H3 accept gate for the bounded quiet
    // interval.  A clean timeout, or an already-drained graceful EOF, is
    // terminal here; an H3 connection error still propagates and is never
    // converted into evidence of a planned GOAWAY.
    let quiet_deadline = min(drain_deadline, Instant::now() + GOAWAY_DRAIN_QUIET);
    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }
        match timeout_at(quiet_deadline, h3_connection.accept()).await {
            Ok(Ok(Some(resolver))) => {
                post_goaway_resolved.fetch_add(1, Ordering::AcqRel);
                let (_, mut rejected) =
                    timeout_at(drain_deadline, resolver.resolve_request()).await??;
                rejected.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
            }
            Ok(Ok(None)) => {
                drain_complete.notify_one();
                break;
            }
            Err(_) => {
                drain_complete.notify_one();
                break;
            }
            Ok(Err(error)) => return Err(error.into()),
        }
    }
    let _ = timeout(CASE_TIMEOUT, h3_connection.shutdown(0)).await;
    connection.close(quinn::VarInt::from_u32(0), b"public GOAWAY cleanup");
    endpoint.close(quinn::VarInt::from_u32(0), b"public GOAWAY server shutdown");
    Ok(())
}

fn make_runtime(
    pki: &FixturePki,
    source: &Leaf,
    owner: &Leaf,
    server: &GoAwayServer,
    catalog: Arc<MemoryCatalog>,
) -> TestResult<Arc<PeerRuntime>> {
    let mut endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let source_config = load_peer_client_config_from_pem(
        pki.chain(source).as_bytes(),
        source.private_key_pem.as_bytes(),
        pki.ca_pem.as_bytes(),
    )?;
    endpoint.set_default_client_config(source_config);
    let pins = ApprovedPeerPins::new([spki_sha256_from_der(&owner.der)?])?;
    let client = PeerClient::new(endpoint, pins, PeerTransportLimits::default())?;
    let identity = RelayIdentity::new(DEPLOYMENT_INCARNATION, SOURCE_NODE, SOURCE_BOOT)?;
    let catalog_shared: Arc<dyn Catalog> = catalog;
    let router: Arc<OwnerRouter<dyn Catalog>> =
        Arc::new(OwnerRouter::new(catalog_shared, identity)?);
    let owner_binding = membership_binding_for_runtime(source, owner, server)?;
    let provider = move |node_id: &str, boot_id: &str, _now| {
        let result = if node_id == OWNER_NODE && boot_id == OWNER_BOOT {
            Ok(owner_binding.clone())
        } else {
            Err(PeerRuntimeError::Membership(
                "public GOAWAY unknown peer".to_owned(),
            ))
        };
        async move { result }
    };
    Ok(Arc::new(PeerRuntime::new(
        client,
        router,
        Arc::new(provider),
        SOURCE_NODE,
        SOURCE_BOOT,
    )))
}

fn membership_binding_for_runtime(
    source: &Leaf,
    owner: &Leaf,
    server: &GoAwayServer,
) -> TestResult<VerifiedPeerBinding> {
    let source_endpoint = SocketAddr::from(([127, 0, 0, 1], 1));
    let (_, owner_binding) =
        membership_bindings(source, owner, source_endpoint, server.destination_addr());
    Ok(owner_binding)
}

impl GoAwayServer {
    fn destination_addr(&self) -> SocketAddr {
        self.destination.address
    }
}

fn public_request(token: &str, body: &'static [u8]) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(format!(
            "/v1/devices/{DEVICE_ID}/services/{SERVICE_ID}/echo"
        ))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(Bytes::from_static(body)))
        .expect("public GOAWAY request")
}

fn direct_probe_envelope(
    runtime: &PeerRuntime,
    route: &tunnel_relay::routing::OwnerRoute,
    token: &str,
    attempt: usize,
) -> RequestEnvelope {
    let owner = route.owner_token().clone();
    let bearer = ForwardedConsumerBearer::new(token.to_owned(), owner.clone())
        .expect("public direct probe bearer");
    let request_id = format!("public-goaway-probe-{attempt}");
    RequestEnvelope::new(
        InternalRoute::ConsumerStreams,
        request_id.clone(),
        runtime.source().clone(),
        Destination::new(owner, SERVICE_ID),
        20_000,
        None,
        InternalRequest::ConsumerStreams(ConsumerStreamsRequest {
            stream_id: request_id,
            required_scope: tunnel_relay::ECHO_OPERATION.to_owned(),
            bearer,
            bytes: Vec::new(),
        }),
    )
}

async fn wait_for_typed_goaway(runtime: &PeerRuntime, token: &str) -> TestResult<()> {
    let deadline = Instant::now() + CASE_TIMEOUT;
    let route = runtime
        .resolve(OwnerScope::new(TENANT_ID, DEVICE_ID), Utc::now())
        .await?;
    for attempt in 1..=32 {
        let result = timeout_at(
            deadline,
            runtime.open(
                &route,
                direct_probe_envelope(runtime, &route, token, attempt),
            ),
        )
        .await
        .map_err(|_| "public GOAWAY typed outcome deadline exceeded")?;
        match result {
            Err(PeerRuntimeError::Transport(PeerTransportError::GoAway)) => return Ok(()),
            Ok(mut exchange) => {
                exchange.cancel();
                if attempt == 32 {
                    return Err("public GOAWAY propagation exceeded bounded attempts".into());
                }
                tokio::task::yield_now().await;
            }
            Err(error) => {
                return Err(format!("unexpected direct GOAWAY probe error: {error}").into());
            }
        }
    }
    Err("public GOAWAY probe loop exhausted".into())
}

#[tokio::test]
async fn public_echo_maps_authenticated_h3_goaway_before_dispatch_without_replay() -> TestResult {
    let pki = FixturePki::new();
    let source = pki.issue_peer(SOURCE_NODE);
    let owner = pki.issue_peer(OWNER_NODE);
    let server = GoAwayServer::start(&pki, &owner);
    let catalog = Arc::new(MemoryCatalog::new());
    catalog.seed_fixture(&catalog_fixture(Utc::now())).await?;
    catalog
        .claim_owner(&tunnel_catalog::OwnerClaimRequest {
            deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
            tenant_id: TENANT_ID,
            device_id: DEVICE_ID,
            node_id: OWNER_NODE.to_owned(),
            boot_id: OWNER_BOOT.to_owned(),
            session_id: "public-goaway-owner-session".to_owned(),
            lease_expires_at: Utc::now() + ChronoDuration::seconds(30),
        })
        .await?;
    let (oidc, token) = oidc_fixture();
    let runtime = make_runtime(&pki, &source, &owner, &server, Arc::clone(&catalog))?;
    let mut options = RelayOptions::new(Arc::clone(&oidc));
    options.node_id = SOURCE_NODE.to_owned();
    options.boot_id = SOURCE_BOOT.to_owned();
    options.deployment_incarnation = DEPLOYMENT_INCARNATION.to_owned();
    let handle = Relay::spawn(options, catalog.clone()).await?;
    let catalog_shared: Arc<dyn Catalog> = catalog.clone();
    let app = router_with_peer(
        handle.clone(),
        catalog_shared,
        oidc,
        RelayLimits::default(),
        Some(Arc::clone(&runtime)),
    );

    let first_app = app.clone();
    let first_token = token.clone();
    let mut first_task = tokio::spawn(async move {
        first_app
            .oneshot(public_request(&first_token, FIRST_REQUEST_BODY))
            .await
            .map_err(|_| "public first request router failure")
    });
    let scenario = async {
        timeout(CASE_TIMEOUT, server.goaway_sent.notified())
            .await
            .map_err(|_| "public H3 GOAWAY was not sent")?;

        wait_for_typed_goaway(&runtime, &token).await?;
        let second = timeout(
            CASE_TIMEOUT,
            app.clone()
                .oneshot(public_request(&token, b"must-not-dispatch")),
        )
        .await
        .map_err(|_| "public GOAWAY rejection deadline exceeded")?
        .map_err(|_| "public GOAWAY router failure")?;
        if second.status() != StatusCode::SERVICE_UNAVAILABLE {
            return Err("public GOAWAY did not map to 503".into());
        }
        if second.headers().get(header::RETRY_AFTER).is_some() {
            return Err("public GOAWAY response unexpectedly requested retry".into());
        }
        let second_body = timeout(CASE_TIMEOUT, to_bytes(second.into_body(), 16 * 1024))
            .await
            .map_err(|_| "public GOAWAY body deadline exceeded")?
            .map_err(|_| "bounded public GOAWAY body failed")?;
        let second_json: serde_json::Value = serde_json::from_slice(&second_body)?;
        if second_json.get("code").and_then(serde_json::Value::as_str) != Some("PEER_UNAVAILABLE") {
            return Err("public GOAWAY response had the wrong failure code".into());
        }
        if second_json
            .get("execution")
            .and_then(serde_json::Value::as_str)
            != Some("not_dispatched")
        {
            return Err("public GOAWAY response was not marked not_dispatched".into());
        }
        if second_json.get("retryable").is_some() || second_json.get("retry_after_ms").is_some() {
            return Err("public GOAWAY response exposed retry metadata".into());
        }

        server.release_response.notify_one();
        let first = timeout(CASE_TIMEOUT, &mut first_task)
            .await
            .map_err(|_| "public admitted response deadline exceeded")?
            .map_err(|_| "public first task join failure")?
            .map_err(|_| "public first request router failure")?;
        if first.status() != StatusCode::OK {
            return Err("public admitted request did not complete successfully".into());
        }
        let first_body = timeout(CASE_TIMEOUT, to_bytes(first.into_body(), 16 * 1024))
            .await
            .map_err(|_| "public admitted body deadline exceeded")?
            .map_err(|_| "bounded public admitted body failed")?;
        if first_body.as_ref() != RESPONSE_BODY {
            return Err("public admitted response body changed after GOAWAY".into());
        }
        server.response_drained.notify_one();
        timeout(CASE_TIMEOUT, server.drain_complete.notified())
            .await
            .map_err(|_| "public H3 response drain did not complete")?;
        if server.dispatches.load(Ordering::Acquire) != 1 {
            return Err("public owner dispatch count was not exactly one".into());
        }
        if server.post_goaway_resolved.load(Ordering::Acquire) != 0 {
            return Err("public owner resolved a request after GOAWAY".into());
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    // Every scenario branch releases and joins the public request before the
    // runtime/server owners are shut down.  A test failure cannot leave a
    // detached Axum future holding the peer stream open.
    server.release_response.notify_one();
    if !first_task.is_finished() && timeout(CASE_TIMEOUT, &mut first_task).await.is_err() {
        first_task.abort();
        let _ = first_task.await;
    }

    let runtime_result = runtime.shutdown().await;
    let handle_result = handle.shutdown().await;
    let server_result = server.shutdown().await;
    scenario?;
    runtime_result.map_err(|error| format!("public runtime cleanup: {error}"))?;
    handle_result.map_err(|error| format!("public relay cleanup: {error}"))?;
    server_result.map_err(|error| format!("public H3 server cleanup: {error}"))?;
    Ok(())
}
