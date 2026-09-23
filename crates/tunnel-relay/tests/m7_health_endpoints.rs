//! M7-C06 public liveness/readiness and dispatch gating regression.
//!
//! The fixture uses a signed checkpoint and signed membership record with an
//! in-memory source. It deliberately injects a catalog refresh failure rather
//! than contacting Redis or a checkpoint service. The HTTP requests exercise
//! the production Axum router and keep the health body bounded and redacted.
//!
//! The last two tests are the M7-C89 gate: readiness and public admission are
//! asserted **against the transport pin set** that every peer dial reads, not
//! against the other views of readiness that were once its only inputs.

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
    MembershipPeerIdentity, MembershipReadiness, MembershipRecordSource, MembershipRuntime,
    MembershipRuntimeConfig, PeerListenerState, PeerReadiness, PeerRuntime, Relay, RelayLimits,
    RelayOptions,
    membership_runtime::{MembershipFuture, MembershipSourceError},
    router_with_peer,
    routing::{OwnerRouter, RelayIdentity},
};
use tunnel_transport::{
    ApprovedPeerPins, PeerClient, PeerDestination, PeerTransportError, PeerTransportLimits,
    SharedPeerPins, SpkiSha256,
};

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

/// A cluster-shaped peer runtime whose pin set the test holds a handle to.
///
/// Every other readiness input is made to hold: the listener is bound, the
/// verified route set is installed and empty (a one-node deployment, so no
/// probe is owed), and capacity meets the floor. That isolates the one input
/// M7-C89 is about. The client is returned too, so the test can show the
/// same pin set refusing a real dial.
struct PinnedRuntime {
    peer: Arc<PeerRuntime>,
    pins: SharedPeerPins,
    readiness: Arc<PeerReadiness>,
    client: PeerClient,
}

fn pinned_peer_runtime(runtime: Arc<MembershipRuntime>, catalog: SharedCatalog) -> PinnedRuntime {
    let identity =
        RelayIdentity::new(DEPLOYMENT_INCARNATION, NODE_ID, BOOT_ID).expect("relay identity");
    let router: Arc<OwnerRouter<dyn tunnel_catalog::Catalog>> =
        Arc::new(OwnerRouter::new(catalog, identity).expect("owner router"));
    let endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("local synthetic QUIC endpoint");
    let pins = SharedPeerPins::new(
        ApprovedPeerPins::new([local_pin()]).expect("the relay's own synthetic pin"),
    )
    .expect("dynamic pin set");
    let client =
        PeerClient::new_with_pin_provider(endpoint, pins.clone(), PeerTransportLimits::default())
            .expect("peer client");
    let readiness = Arc::new(PeerReadiness::new(1).expect("capacity floor"));
    readiness.set_listener_state(PeerListenerState::Bound);
    readiness
        .replace_required_routes(std::iter::empty())
        .expect("verified one-node route set");
    readiness.set_available_capacity(1);
    let peer = Arc::new(PeerRuntime::new_with_readiness(
        client.clone(),
        router,
        runtime,
        NODE_ID,
        BOOT_ID,
        Arc::clone(&readiness),
    ));
    PinnedRuntime {
        peer,
        pins,
        readiness,
        client,
    }
}

fn local_pin() -> SpkiSha256 {
    let mut bytes = [0_u8; 32];
    for (index, chunk) in SPKI_SHA256.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).expect("ascii digest");
        bytes[index] = u8::from_str_radix(text, 16).expect("hex digest");
    }
    SpkiSha256::from_bytes(bytes)
}

/// The body of a public request refused by the cluster readiness gate. Named
/// so an assertion can tell that refusal apart from any other 503.
fn is_cluster_unready(body: &[u8]) -> bool {
    let body = String::from_utf8_lossy(body);
    body.contains(r#""code":"CLUSTER_UNREADY""#) && body.contains(r#""execution":"not_dispatched""#)
}

/// **The M7-C89 gate.** With every other readiness input satisfied, an empty
/// transport pin set -- the state the membership invalidation callback leaves
/// behind -- must make `/readyz` unready and public admission refuse, through
/// the production router and the real `PeerRuntime::is_ready`, and both must
/// recover when the set is republished.
///
/// It asserts the controls first, because a gate that could not have gone
/// green is not evidence either: with the pins present this relay is ready,
/// which is also the one-node deployment that must NOT be made unready for
/// having no peers.
#[tokio::test]
async fn readiness_and_admission_withdraw_with_the_transport_pin_set() {
    let fixture = RuntimeFixture::ready().await;
    let catalog: SharedCatalog = Arc::new(MemoryCatalog::new());
    let oidc = oidc();
    let pinned = pinned_peer_runtime(Arc::clone(&fixture.runtime), Arc::clone(&catalog));
    let handle = Relay::spawn(RelayOptions::new(Arc::clone(&oidc)), Arc::clone(&catalog))
        .await
        .expect("relay actor");
    let app = router_with_peer(
        handle.clone(),
        Arc::clone(&catalog),
        oidc,
        RelayLimits::default(),
        Some(Arc::clone(&pinned.peer)),
    );
    let echo_path = format!("/v1/devices/{ECHO_DEVICE}/services/{ECHO_SERVICE}/echo");

    // Control: a one-node cluster relay holding only its own key is ready.
    assert!(!pinned.pins.snapshot().is_empty());
    let (status, body) = response(&app, Method::GET, "/readyz").await;
    assert_eq!(
        (status, body.as_slice()),
        (StatusCode::OK, br#"{"status":"ready"}"#.as_slice()),
        "control: a one-node relay with its own pin and no peers must be ready"
    );
    assert_eq!(
        response(&app, Method::POST, &echo_path).await.0,
        StatusCode::UNAUTHORIZED,
        "control: a ready relay's public dispatch reaches authentication"
    );

    // The window: the pin set is emptied and nothing else changes.
    pinned
        .pins
        .replace(std::iter::empty::<SpkiSha256>())
        .expect("empty pin set");
    // The other views of readiness still say ready -- this is exactly the
    // state in which the relay used to report itself ready.
    assert_eq!(fixture.runtime.readiness(), MembershipReadiness::Ready);
    assert!(
        pinned.readiness.is_ready(),
        "precondition: route, listener and capacity readiness are untouched"
    );
    // And the pin set really does make every peer dial impossible: this is
    // the transport's own refusal, not the test's reading of the set.
    let dial = pinned
        .client
        .connect(PeerDestination::new(
            SocketAddr::from(([127, 0, 0, 1], 9)),
            "relay-peer",
        ))
        .await;
    assert!(
        matches!(dial, Err(PeerTransportError::PinsUnavailable)),
        "an empty pin set must refuse the dial before any network I/O"
    );

    let (status, body) = response(&app, Method::GET, "/readyz").await;
    assert_eq!(
        (status, body.as_slice()),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            br#"{"status":"unready"}"#.as_slice()
        ),
        "M7-C89: /readyz reported ready while every peer dial is refused for an empty pin set"
    );
    let (status, body) = response(&app, Method::POST, &echo_path).await;
    assert!(
        status == StatusCode::SERVICE_UNAVAILABLE && is_cluster_unready(&body),
        "M7-C89: public admission accepted work while every peer dial is refused for an \
         empty pin set (status {status}, body {})",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(
        valid_upgrade_response(&app, "/v1/tunnel/control").await,
        StatusCode::SERVICE_UNAVAILABLE,
        "M7-C89: a device upgrade was admitted with an empty pin set"
    );

    // Recovery: republishing the set restores readiness and admission together.
    pinned
        .pins
        .replace([local_pin()])
        .expect("republished pin set");
    assert_eq!(
        response(&app, Method::GET, "/readyz").await.0,
        StatusCode::OK,
        "readiness must recover as soon as the pin set is republished"
    );
    assert_eq!(
        response(&app, Method::POST, &echo_path).await.0,
        StatusCode::UNAUTHORIZED,
        "admission must recover together with readiness"
    );

    handle.shutdown().await.expect("relay actor shutdown");
    pinned.peer.shutdown().await.expect("peer runtime shutdown");
}

/// The M7-C89 mechanism end to end, with the real `MembershipRuntime`
/// dispatching its real invalidation callback.
///
/// The callback installed here applies the serving relay's rule -- publish
/// when `Ready`, empty the set otherwise -- because the rule itself lives in
/// the binary. It is the scenario's trigger, not the property under test.
/// What is asserted is the part that was relayed and is re-derived here:
/// an unready transition with an active admission empties the pin set; the
/// reconcile that returns membership to `Ready` has no admission left to
/// invalidate and so **does not call the callback again**, leaving the set
/// empty with membership `Ready` -- the state `/readyz` used to call ready.
#[tokio::test]
async fn a_membership_recovery_that_leaves_the_pin_set_empty_is_not_ready() {
    let fixture = RuntimeFixture::ready().await;
    let catalog: SharedCatalog = Arc::new(MemoryCatalog::new());
    let pinned = pinned_peer_runtime(Arc::clone(&fixture.runtime), Arc::clone(&catalog));
    let calls = Arc::new(AtomicU64::new(0));
    {
        let membership = Arc::clone(&fixture.runtime);
        let pins = pinned.pins.clone();
        let calls = Arc::clone(&calls);
        fixture
            .runtime
            .set_invalidation_callback(Some(Arc::new(move |_identity, _reason| {
                calls.fetch_add(1, Ordering::AcqRel);
                if matches!(membership.readiness(), MembershipReadiness::Ready) {
                    pins.replace([local_pin()]).expect("republished pins");
                } else {
                    pins.replace(std::iter::empty::<SpkiSha256>())
                        .expect("fail-closed pins");
                }
            })));
    }
    let _admission = fixture
        .runtime
        .admit_peer(MembershipPeerIdentity::new(NODE_ID, BOOT_ID, SPKI_SHA256))
        .expect("an active admission for the invalidation to reach");
    assert!(pinned.peer.is_ready(), "control: ready before the blip");

    // The blip: one malformed catalog record, which the verifier rejects.
    fixture
        .source
        .replace(vec![SignedMembershipRecord {
            version: 2,
            bytes: b"not a signed membership record".to_vec(),
        }])
        .await;
    fixture
        .runtime
        .reconcile_once()
        .await
        .expect_err("a rejected membership record must make membership unready");
    assert_eq!(calls.load(Ordering::Acquire), 1, "the callback fired once");
    assert!(pinned.pins.snapshot().is_empty(), "and emptied the pin set");
    assert!(!pinned.peer.is_ready(), "unready membership is not ready");

    // Recovery: membership is Ready again and no callback runs.
    fixture.source.replace(vec![fixture.record(3)]).await;
    fixture
        .runtime
        .reconcile_once()
        .await
        .expect("membership recovers");
    assert_eq!(fixture.runtime.readiness(), MembershipReadiness::Ready);
    assert_eq!(
        calls.load(Ordering::Acquire),
        1,
        "the recovering reconcile had no admission to invalidate"
    );
    assert!(
        pinned.pins.snapshot().is_empty(),
        "nothing republished the pin set: this is the M7-C89 window"
    );
    assert!(
        pinned.readiness.is_ready(),
        "precondition: route, listener and capacity readiness were never withdrawn"
    );
    assert!(
        !pinned.peer.is_ready(),
        "M7-C89: membership recovered with an empty pin set and the relay reported ready"
    );

    pinned
        .pins
        .replace([local_pin()])
        .expect("the refresh tick's republication");
    assert!(pinned.peer.is_ready(), "ready again once the set is back");
    pinned.peer.shutdown().await.expect("peer runtime shutdown");
}
