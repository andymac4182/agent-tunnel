//! M7-C06 public liveness/readiness and dispatch gating regression.
//!
//! The fixture uses a signed checkpoint and signed membership record with an
//! in-memory source. It deliberately injects a catalog refresh failure rather
//! than contacting Redis or a checkpoint service. The HTTP requests exercise
//! the production Axum router and keep the health body bounded and redacted.

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use axum::body::Body;
use chrono::Utc;
use http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use tokio::sync::RwLock;
use tower::ServiceExt;
use tunnel_catalog::{MemoryCatalog, SharedCatalog, SignedMembershipRecord};
use tunnel_cluster::membership::{
    MEMBERSHIP_SCHEMA_VERSION, MembershipCheckpoint, MembershipIssuer, MembershipRecord,
    PrivateEndpointPolicy, RELAY_PEER_ROLE, RelayKey, TrustedPublisherKey,
};
use tunnel_relay::{
    CheckpointAuthority, CheckpointAuthorityError, CheckpointRequest, CheckpointResponse,
    MembershipReadiness, MembershipRecordSource, MembershipRuntime, MembershipRuntimeConfig,
    PeerRuntime, Relay, RelayLimits, RelayOptions,
    membership_runtime::{MembershipFuture, MembershipSourceError},
    router_with_peer,
    routing::{OwnerRouter, RelayIdentity},
};
use tunnel_transport::{ApprovedPeerPins, PeerClient, PeerTransportLimits, SpkiSha256};

const DEPLOYMENT_ID: &str = "m7-health-deployment";
const DEPLOYMENT_INCARNATION: &str = "m7-health-incarnation";
const NODE_ID: &str = "relay-health";
const BOOT_ID: &str = "boot-health";
const PUBLISHER_KEY_ID: &str = "publisher-health";
const SPKI_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ECHO_DEVICE: &str = "00000000-0000-0000-0000-000000000001";
const ECHO_SERVICE: &str = "00000000-0000-0000-0000-000000000002";

struct TestCheckpointAuthority {
    issuer: Arc<MembershipIssuer>,
    next_version: AtomicU64,
}

impl CheckpointAuthority for TestCheckpointAuthority {
    fn fetch_checkpoint<'a>(
        &'a self,
        request: CheckpointRequest,
    ) -> MembershipFuture<'a, Result<CheckpointResponse, CheckpointAuthorityError>> {
        Box::pin(async move {
            let now = Utc::now();
            let checkpoint = MembershipCheckpoint {
                schema_version: MEMBERSHIP_SCHEMA_VERSION,
                deployment_id: request.deployment_id,
                deployment_incarnation: request.deployment_incarnation,
                checkpoint_version: self.next_version.fetch_add(1, Ordering::AcqRel),
                nonce: request.nonce,
                minimum_versions: BTreeMap::from([(NODE_ID.to_owned(), 1)]),
                issued_at: now - chrono::Duration::seconds(1),
                not_before: now - chrono::Duration::seconds(1),
                expires_at: now + chrono::Duration::seconds(30),
            };
            let bytes = self
                .issuer
                .sign_checkpoint_bytes(checkpoint)
                .map_err(|_| CheckpointAuthorityError::InvalidResponse)?;
            CheckpointResponse::new(bytes)
        })
    }
}

#[derive(Clone)]
struct TestMembershipSource {
    records: Arc<RwLock<Vec<SignedMembershipRecord>>>,
    fail_reads: Arc<AtomicBool>,
}

impl TestMembershipSource {
    fn new(records: Vec<SignedMembershipRecord>) -> Self {
        Self {
            records: Arc::new(RwLock::new(records)),
            fail_reads: Arc::new(AtomicBool::new(false)),
        }
    }

    async fn replace(&self, records: Vec<SignedMembershipRecord>) {
        *self.records.write().await = records;
    }

    fn set_fail_reads(&self, fail: bool) {
        self.fail_reads.store(fail, Ordering::Release);
    }
}

impl MembershipRecordSource for TestMembershipSource {
    fn read_signed_memberships<'a>(
        &'a self,
    ) -> MembershipFuture<'a, Result<Vec<SignedMembershipRecord>, MembershipSourceError>> {
        Box::pin(async move {
            if self.fail_reads.load(Ordering::Acquire) {
                return Err(MembershipSourceError::Catalog);
            }
            Ok(self.records.read().await.clone())
        })
    }
}

struct RuntimeFixture {
    issuer: Arc<MembershipIssuer>,
    source: TestMembershipSource,
    runtime: Arc<MembershipRuntime>,
}

impl RuntimeFixture {
    async fn ready() -> Self {
        let (issuer, _private_key) =
            MembershipIssuer::generate(PUBLISHER_KEY_ID).expect("synthetic publisher");
        let issuer = Arc::new(issuer);
        let authority = Arc::new(TestCheckpointAuthority {
            issuer: Arc::clone(&issuer),
            next_version: AtomicU64::new(1),
        });
        let source = TestMembershipSource::new(Vec::new());
        let config = MembershipRuntimeConfig::new(
            DEPLOYMENT_ID,
            DEPLOYMENT_INCARNATION,
            NODE_ID,
            BOOT_ID,
            PrivateEndpointPolicy::private_ip_only(),
            Duration::from_secs(60),
            Duration::from_secs(20),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .expect("bounded membership configuration")
        .with_local_spki_sha256(SPKI_SHA256)
        .expect("synthetic local SPKI");
        let trusted_key = TrustedPublisherKey::new(
            PUBLISHER_KEY_ID,
            issuer.public_key().expect("publisher public key"),
        )
        .expect("trusted publisher key");
        let runtime = MembershipRuntime::with_source(
            Arc::new(source.clone()),
            authority,
            config,
            [trusted_key],
        )
        .expect("membership runtime");
        let fixture = Self {
            issuer,
            source,
            runtime,
        };
        fixture.source.replace(vec![fixture.record(1)]).await;
        fixture
            .runtime
            .bootstrap()
            .await
            .expect("signed fixture should become ready");
        assert_eq!(fixture.runtime.readiness(), MembershipReadiness::Ready);
        fixture
    }

    fn record(&self, version: u64) -> SignedMembershipRecord {
        let now = Utc::now();
        let record = MembershipRecord {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            deployment_id: DEPLOYMENT_ID.to_owned(),
            deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
            node_id: NODE_ID.to_owned(),
            record_version: version,
            roles: vec![RELAY_PEER_ROLE.to_owned()],
            peer_endpoint: "10.0.0.1:8443".to_owned(),
            server_name: "10.0.0.1".to_owned(),
            keys: vec![RelayKey {
                key_id: "relay-health-key".to_owned(),
                spki_sha256: SPKI_SHA256.to_owned(),
                not_before: now - chrono::Duration::seconds(1),
                expires_at: now + chrono::Duration::seconds(30),
                revoked: false,
            }],
            issued_at: now - chrono::Duration::seconds(1),
            not_before: now - chrono::Duration::seconds(1),
            expires_at: now + chrono::Duration::seconds(30),
        };
        SignedMembershipRecord {
            version,
            bytes: self
                .issuer
                .sign_membership_bytes(record)
                .expect("signed membership record"),
        }
    }
}

fn peer_runtime(runtime: Arc<MembershipRuntime>, catalog: SharedCatalog) -> Arc<PeerRuntime> {
    let identity =
        RelayIdentity::new(DEPLOYMENT_INCARNATION, NODE_ID, BOOT_ID).expect("relay identity");
    let router: Arc<OwnerRouter<dyn tunnel_catalog::Catalog>> =
        Arc::new(OwnerRouter::new(catalog, identity).expect("owner router"));
    let endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("local synthetic QUIC endpoint");
    let pins = ApprovedPeerPins::new([SpkiSha256::from_bytes([7; 32])]).expect("synthetic pin");
    let client =
        PeerClient::new(endpoint, pins, PeerTransportLimits::default()).expect("peer client");
    Arc::new(PeerRuntime::new(client, router, runtime, NODE_ID, BOOT_ID))
}

fn oidc() -> Arc<tunnel_catalog::OidcVerifier> {
    let key = tunnel_catalog::ApprovedJwk::from_ed25519_der("health-test", &[0; 32])
        .expect("synthetic OIDC key");
    let config = tunnel_catalog::OidcConfig::new(
        "https://issuer.example",
        ["health-audience".to_owned()],
        vec![key],
    )
    .expect("OIDC config");
    Arc::new(tunnel_catalog::OidcVerifier::new(config).expect("OIDC verifier"))
}

async fn response(app: &axum::Router, method: Method, path: &str) -> (StatusCode, Vec<u8>) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .body(Body::empty())
        .expect("health request");
    let response = app.clone().oneshot(request).await.expect("router response");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("bounded response body")
        .to_bytes()
        .to_vec();
    (status, body)
}

async fn valid_upgrade_response(app: &axum::Router, path: &str) -> StatusCode {
    // Router::oneshot has no Hyper OnUpgrade extension. Valid headers reach
    // Axum's 426 extractor rejection when ready; the readiness middleware
    // must produce 503 before extraction when unready.
    let request = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header("upgrade", "websocket")
        .header("connection", "Upgrade")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(Body::empty())
        .expect("valid synthetic upgrade request");
    app.clone()
        .oneshot(request)
        .await
        .expect("router response")
        .status()
}

#[tokio::test]
async fn livez_stays_observable_while_readiness_and_dispatch_fail_closed() {
    let fixture = RuntimeFixture::ready().await;
    let catalog: SharedCatalog = Arc::new(MemoryCatalog::new());
    let oidc = oidc();
    let peer = peer_runtime(Arc::clone(&fixture.runtime), Arc::clone(&catalog));
    let handle = Relay::spawn(RelayOptions::new(Arc::clone(&oidc)), Arc::clone(&catalog))
        .await
        .expect("relay actor");
    let app = router_with_peer(
        handle.clone(),
        Arc::clone(&catalog),
        oidc,
        RelayLimits::default(),
        Some(Arc::clone(&peer)),
    );
    let echo_path = format!("/v1/devices/{ECHO_DEVICE}/services/{ECHO_SERVICE}/echo");

    let (status, body) = response(&app, Method::GET, "/livez").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, br#"{"status":"live"}"#);
    let (status, body) = response(&app, Method::GET, "/readyz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, br#"{"status":"ready"}"#);
    assert_eq!(
        response(&app, Method::POST, &echo_path).await.0,
        StatusCode::UNAUTHORIZED,
        "a ready service dispatch reaches authentication"
    );
    assert_eq!(
        valid_upgrade_response(&app, "/v1/tunnel/control").await,
        StatusCode::UPGRADE_REQUIRED,
        "a ready device request reaches Axum upgrade extraction"
    );

    fixture.source.set_fail_reads(true);
    let error = fixture
        .runtime
        .reconcile_once()
        .await
        .expect_err("catalog refresh failure must make readiness fail closed");
    assert!(matches!(
        error,
        tunnel_relay::MembershipRuntimeError::Source(
            tunnel_relay::membership_runtime::MembershipSourceError::Catalog
        )
    ));
    assert_eq!(
        fixture.runtime.readiness(),
        MembershipReadiness::Unready(
            tunnel_relay::membership_runtime::MembershipUnreadyReason::CatalogUnavailable
        )
    );
    let (status, body) = response(&app, Method::GET, "/livez").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, br#"{"status":"live"}"#);
    let (status, body) = response(&app, Method::GET, "/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, br#"{"status":"unready"}"#);
    assert_eq!(
        response(&app, Method::POST, &echo_path).await.0,
        StatusCode::SERVICE_UNAVAILABLE,
        "unready service dispatch must not reach authentication or the actor"
    );
    assert_eq!(
        valid_upgrade_response(&app, "/v1/tunnel/control").await,
        StatusCode::SERVICE_UNAVAILABLE,
        "unready device dispatch must not upgrade a socket"
    );

    fixture.source.set_fail_reads(false);
    fixture.source.replace(vec![fixture.record(2)]).await;
    fixture
        .runtime
        .reconcile_once()
        .await
        .expect("catalog recovery should restore readiness");
    assert_eq!(fixture.runtime.readiness(), MembershipReadiness::Ready);
    assert_eq!(
        response(&app, Method::GET, "/readyz").await.0,
        StatusCode::OK
    );
    assert_eq!(
        response(&app, Method::POST, &echo_path).await.0,
        StatusCode::UNAUTHORIZED,
        "recovered service dispatch reaches authentication again"
    );

    handle.shutdown().await.expect("relay actor shutdown");
    peer.shutdown().await.expect("peer runtime shutdown");
}
