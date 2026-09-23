//! Staged EC-019 fixture for live destination boot and owner-lease replacement.
//!
//! This is a standalone follow-up to
//! `m7_live_membership.rs`; it does not duplicate that test's source-key
//! overlap scenario.  The source relay has one stable certificate, while the
//! destination relay is represented by two real mTLS certificates,
//! `DESTINATION_OLD_BOOT` and `DESTINATION_NEW_BOOT`, on two real
//! `PeerServer` endpoints.
//!
//! The signed membership record authorizes the destination node and its
//! certificate/endpoint.  It deliberately has no boot field.  The synthetic
//! catalog's complete owner token (deployment incarnation, node, boot, epoch,
//! and lease) fences the old owner.  The peer listeners are started through
//! the public `Relay::spawn` handle plus real `PeerServer` endpoints.  Each
//! server installs the real `peer_ingress_handler` behind a thin post-result
//! recording wrapper.  The probe is intentionally a control-plane Health
//! request; RPC/adapter lease semantics remain covered by the planned
//! `verify_scope` slice and are out of scope here.

// The harness library is Unix-only (see `src/entry.rs`).
#![cfg(unix)]
#![allow(clippy::too_many_arguments)]

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rcgen::KeyPair;
use tokio::{
    sync::RwLock,
    time::{timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{
    ApprovedJwk, Catalog, CatalogFixture, FixtureDevice, MembershipRecord as CatalogMembership,
    MembershipRole, MemoryCatalog, OidcConfig, OidcVerifier, OwnerClaim, OwnerClaimRequest,
    OwnerToken, TenantRecord, UserRecord,
};
use tunnel_cluster::{
    envelope::{
        Destination, HealthRequest, InternalRequest, InternalRoute, PeerIdentity, RequestEnvelope,
    },
    membership::{
        MEMBERSHIP_SCHEMA_VERSION, MembershipCheckpoint, MembershipIssuer, MembershipRecord,
        PrivateEndpointPolicy, RELAY_PEER_ROLE, RelayKey, TrustedPublisherKey,
    },
};
use tunnel_relay::membership_runtime::MembershipFuture;
use tunnel_relay::peer_runtime::PeerIngressHandlerFuture;
use tunnel_relay::{
    CheckpointAuthority, CheckpointAuthorityError, CheckpointRequest, CheckpointResponse,
    InboundPeerRequest, MembershipPeerIdentity, MembershipReadiness, MembershipRecordSource,
    MembershipRuntime, MembershipRuntimeConfig, MembershipRuntimeHandle, PeerBindingProvider,
    PeerIngressHandler, PeerRuntime, Relay, RelayHandle, RelayOptions,
    routing::{OwnerRoute, OwnerRouter, OwnerScope, RelayIdentity},
};
use tunnel_test_harness::{CertificateMaterial, FixturePki};
use tunnel_transport::{
    PeerClient, PeerServer, PeerTransportLimits, SharedPeerPins, SpkiSha256,
    load_peer_client_config_from_pem, load_peer_server_config_from_pem, spki_sha256_from_der,
};
use uuid::Uuid;

const DEPLOYMENT_ID: &str = "m7-ec019-boot-replacement-deployment";
const DEPLOYMENT_INCARNATION: &str = "m7-ec019-boot-replacement-incarnation";
const SOURCE_NODE: &str = "m7-ec019-source";
const SOURCE_BOOT: &str = "m7-ec019-source-boot";
const DESTINATION_NODE: &str = "m7-ec019-destination";
const DESTINATION_OLD_BOOT: &str = "m7-ec019-destination-old-boot";
const DESTINATION_NEW_BOOT: &str = "m7-ec019-destination-new-boot";
const SIBLING_NODE: &str = "m7-ec019-sibling";
const SIBLING_BOOT: &str = "m7-ec019-sibling-boot";
const PUBLISHER_KEY_ID: &str = "m7-ec019-publisher";
const OIDC_ISSUER: &str = "https://m7-ec019-issuer.example";
const OIDC_AUDIENCE: &str = "m7-ec019-audience";
const TENANT_ID: Uuid = Uuid::from_u128(0x1000_0000_0000_0000_0000_0000_0000_0019);
const DEVICE_ID: Uuid = Uuid::from_u128(0x2000_0000_0000_0000_0000_0000_0000_0019);
const SIBLING_DEVICE_ID: Uuid = Uuid::from_u128(0x2000_0000_0000_0000_0000_0000_0000_0020);
const OWNER_USER_ID: Uuid = Uuid::from_u128(0x3000_0000_0000_0000_0000_0000_0000_0019);
const SERVICE_ID: Uuid = Uuid::from_u128(0x4000_0000_0000_0000_0000_0000_0000_0019);
const RESPONSE_BOUND: Duration = Duration::from_secs(2);
const EXPIRY_BOUND: Duration = Duration::from_secs(3);

#[derive(Clone)]
struct DirectoryState {
    records: Vec<tunnel_catalog::SignedMembershipRecord>,
    minimum_versions: BTreeMap<String, u64>,
}

#[derive(Clone)]
struct SignedDirectory {
    state: Arc<RwLock<DirectoryState>>,
}

impl SignedDirectory {
    fn new(records: Vec<tunnel_catalog::SignedMembershipRecord>) -> Self {
        Self {
            state: Arc::new(RwLock::new(directory_state(records))),
        }
    }

    async fn replace(&self, records: Vec<tunnel_catalog::SignedMembershipRecord>) {
        *self.state.write().await = directory_state(records);
    }

    async fn snapshot(&self) -> DirectoryState {
        self.state.read().await.clone()
    }
}

impl MembershipRecordSource for SignedDirectory {
    fn read_signed_memberships<'a>(
        &'a self,
    ) -> MembershipFuture<
        'a,
        Result<
            Vec<tunnel_catalog::SignedMembershipRecord>,
            tunnel_relay::membership_runtime::MembershipSourceError,
        >,
    > {
        Box::pin(async move { Ok(self.state.read().await.records.clone()) })
    }
}

struct SignedDirectoryAuthority {
    issuer: Arc<MembershipIssuer>,
    directory: SignedDirectory,
    next_checkpoint_version: AtomicU64,
}

impl CheckpointAuthority for SignedDirectoryAuthority {
    fn fetch_checkpoint<'a>(
        &'a self,
        request: CheckpointRequest,
    ) -> MembershipFuture<'a, Result<CheckpointResponse, CheckpointAuthorityError>> {
        Box::pin(async move {
            let directory = self.directory.snapshot().await;
            let now = Utc::now();
            let checkpoint = MembershipCheckpoint {
                schema_version: MEMBERSHIP_SCHEMA_VERSION,
                deployment_id: request.deployment_id,
                deployment_incarnation: request.deployment_incarnation,
                checkpoint_version: self.next_checkpoint_version.fetch_add(1, Ordering::AcqRel),
                nonce: request.nonce,
                minimum_versions: directory.minimum_versions,
                issued_at: now - ChronoDuration::milliseconds(1),
                not_before: now - ChronoDuration::milliseconds(1),
                expires_at: now + ChronoDuration::seconds(30),
            };
            let bytes = self
                .issuer
                .sign_checkpoint_bytes(checkpoint)
                .map_err(|_| CheckpointAuthorityError::InvalidResponse)?;
            CheckpointResponse::new(bytes)
        })
    }
}

struct ReplacementFixture {
    membership: Arc<MembershipRuntime>,
    membership_handle: MembershipRuntimeHandle,
    directory: SignedDirectory,
    issuer: Arc<MembershipIssuer>,
    source_record: tunnel_catalog::SignedMembershipRecord,
    sibling_record: tunnel_catalog::SignedMembershipRecord,
    catalog: Arc<MemoryCatalog>,
    router: Arc<OwnerRouter<dyn Catalog>>,
    source_runtime: Arc<PeerRuntime>,
    source_client: PeerClient,
    old_handle: RelayHandle,
    new_handle: RelayHandle,
    sibling_handle: RelayHandle,
    old_destination_runtime: Arc<PeerRuntime>,
    new_destination_runtime: Arc<PeerRuntime>,
    sibling_runtime: Arc<PeerRuntime>,
    old_accepted: Arc<AtomicUsize>,
    new_accepted: Arc<AtomicUsize>,
    sibling_accepted: Arc<AtomicUsize>,
    old_server_cancel: CancellationToken,
    new_server_cancel: CancellationToken,
    sibling_server_cancel: CancellationToken,
    old_server_task: tokio::task::JoinHandle<Result<(), tunnel_transport::PeerTransportError>>,
    new_server_task: tokio::task::JoinHandle<Result<(), tunnel_transport::PeerTransportError>>,
    sibling_server_task: tokio::task::JoinHandle<Result<(), tunnel_transport::PeerTransportError>>,
    destination_pins: SharedPeerPins,
    destination_new_address: SocketAddr,
    destination_new_pin: SpkiSha256,
    sibling_pin: SpkiSha256,
    destination_old_route: OwnerRoute,
    sibling_route: OwnerRoute,
    destination_scope: OwnerScope,
    old_owner: OwnerClaim,
}

impl ReplacementFixture {
    fn new_destination_address(&self) -> SocketAddr {
        self.destination_new_address
    }

    fn new_destination_pin(&self) -> SpkiSha256 {
        self.destination_new_pin
    }

    fn sibling_pin(&self) -> SpkiSha256 {
        self.sibling_pin
    }
}

impl ReplacementFixture {
    async fn start() -> Self {
        let pki = FixturePki::new().expect("synthetic fixture PKI");
        let source_certificate = pki
            .issue_peer(SOURCE_NODE)
            .expect("source relay certificate");
        let destination_old_certificate = pki
            .issue_peer(DESTINATION_NODE)
            .expect("old destination relay certificate");
        let destination_new_certificate = pki
            .issue_peer(DESTINATION_NODE)
            .expect("new destination relay certificate");
        let sibling_certificate = pki
            .issue_peer(SIBLING_NODE)
            .expect("sibling relay certificate");
        let source_pin = spki(&source_certificate);
        let destination_old_pin = spki(&destination_old_certificate);
        let destination_new_pin = spki(&destination_new_certificate);
        let sibling_pin = spki(&sibling_certificate);

        let limits = test_limits();
        let (source_endpoint, source_address) = client_endpoint(&source_certificate, &pki);
        let (old_server_endpoint, old_server_address) =
            server_endpoint(&destination_old_certificate, &pki);
        let (new_server_endpoint, new_server_address) =
            server_endpoint(&destination_new_certificate, &pki);
        let (sibling_server_endpoint, sibling_server_address) =
            server_endpoint(&sibling_certificate, &pki);

        let (issuer, _issuer_pkcs8) =
            MembershipIssuer::generate(PUBLISHER_KEY_ID).expect("membership issuer");
        let issuer = Arc::new(issuer);
        let now = Utc::now();
        let old_membership_expires = now + ChronoDuration::milliseconds(1_500);
        let source_record = signed_record(
            &issuer,
            SOURCE_NODE,
            1,
            source_address,
            vec![membership_key("source-key", source_pin, now)],
            now,
            now + ChronoDuration::seconds(30),
        );
        let destination_old_record = signed_record(
            &issuer,
            DESTINATION_NODE,
            1,
            old_server_address,
            vec![membership_key_window(
                "destination-old-key",
                destination_old_pin,
                now,
                old_membership_expires,
            )],
            now,
            old_membership_expires,
        );
        let sibling_record = signed_record(
            &issuer,
            SIBLING_NODE,
            1,
            sibling_server_address,
            vec![membership_key("sibling-key", sibling_pin, now)],
            now,
            now + ChronoDuration::seconds(30),
        );
        let directory = SignedDirectory::new(vec![
            source_record.clone(),
            destination_old_record.clone(),
            sibling_record.clone(),
        ]);
        let endpoint_policy = PrivateEndpointPolicy::allowlisted(
            ["127.0.0.1"],
            ["localhost"],
            [
                source_address.port(),
                old_server_address.port(),
                new_server_address.port(),
                sibling_server_address.port(),
            ],
        )
        .expect("private endpoint policy");
        let config = MembershipRuntimeConfig::new(
            DEPLOYMENT_ID,
            DEPLOYMENT_INCARNATION,
            SOURCE_NODE,
            SOURCE_BOOT,
            endpoint_policy,
            Duration::from_secs(60),
            Duration::from_secs(1),
            Duration::from_millis(20),
            Duration::from_secs(1),
            Duration::from_millis(50),
        )
        .expect("membership config")
        .with_local_spki_sha256(source_pin.to_hex())
        .expect("source local SPKI");
        let trusted_publisher = TrustedPublisherKey::new(
            PUBLISHER_KEY_ID,
            issuer.public_key().expect("publisher public key"),
        )
        .expect("trusted publisher");
        let authority = Arc::new(SignedDirectoryAuthority {
            issuer: Arc::clone(&issuer),
            directory: directory.clone(),
            next_checkpoint_version: AtomicU64::new(1),
        });
        let membership = MembershipRuntime::with_source(
            Arc::new(directory.clone()),
            authority,
            config,
            [trusted_publisher],
        )
        .expect("membership runtime");
        let membership_handle = membership.start().await.expect("membership supervisor");
        assert_eq!(membership.snapshot().readiness, MembershipReadiness::Ready);

        let source_pins = SharedPeerPins::empty();
        source_pins.replace([source_pin]).expect("source pin set");
        let destination_pins = SharedPeerPins::empty();
        destination_pins
            .replace([destination_old_pin, sibling_pin])
            .expect("destination pin set");

        let catalog = Arc::new(MemoryCatalog::new());
        let oidc = oidc_fixture();
        catalog
            .seed_fixture(&CatalogFixture {
                tenants: vec![TenantRecord {
                    tenant_id: TENANT_ID,
                    display_name: "EC019 tenant".to_owned(),
                    active: true,
                }],
                users: vec![UserRecord {
                    user_id: OWNER_USER_ID,
                    display_name: "EC019 owner".to_owned(),
                }],
                memberships: vec![CatalogMembership {
                    tenant_id: TENANT_ID,
                    user_id: OWNER_USER_ID,
                    role: MembershipRole::Member,
                    active: true,
                }],
                devices: vec![
                    FixtureDevice {
                        tenant_id: TENANT_ID,
                        device_id: DEVICE_ID,
                        owner_user_id: OWNER_USER_ID,
                        display_name: "EC019 device".to_owned(),
                        active: true,
                        last_seen_at: Some(now),
                    },
                    FixtureDevice {
                        tenant_id: TENANT_ID,
                        device_id: SIBLING_DEVICE_ID,
                        owner_user_id: OWNER_USER_ID,
                        display_name: "EC019 sibling device".to_owned(),
                        active: true,
                        last_seen_at: Some(now),
                    },
                ],
                ..CatalogFixture::default()
            })
            .await
            .expect("catalog fixture");
        let old_owner = catalog
            .claim_owner(&OwnerClaimRequest {
                deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
                tenant_id: TENANT_ID,
                device_id: DEVICE_ID,
                node_id: DESTINATION_NODE.to_owned(),
                boot_id: DESTINATION_OLD_BOOT.to_owned(),
                session_id: "ec019-old-session".to_owned(),
                lease_expires_at: now + ChronoDuration::milliseconds(750),
            })
            .await
            .expect("old owner claim");
        let sibling_scope = OwnerScope::new(TENANT_ID, SIBLING_DEVICE_ID);
        let sibling_owner = seed_sibling_owner(&catalog, sibling_scope).await;

        let source_catalog: Arc<dyn Catalog> = catalog.clone();
        let router = Arc::new(
            OwnerRouter::new(
                source_catalog,
                RelayIdentity::new(DEPLOYMENT_INCARNATION, SOURCE_NODE, SOURCE_BOOT)
                    .expect("source identity"),
            )
            .expect("owner router"),
        );
        let provider: Arc<dyn PeerBindingProvider> = membership.clone();
        let source_client = PeerClient::new_with_pin_provider(
            source_endpoint,
            destination_pins.clone(),
            limits.clone(),
        )
        .expect("source peer client");
        let source_runtime = Arc::new(PeerRuntime::new(
            source_client.clone(),
            Arc::clone(&router),
            Arc::clone(&provider),
            SOURCE_NODE,
            SOURCE_BOOT,
        ));

        let old_destination_runtime = Arc::new(server_runtime(
            &source_certificate,
            &pki,
            Arc::clone(&router),
            Arc::clone(&provider),
            destination_pins.clone(),
            &limits,
            DESTINATION_NODE,
            DESTINATION_OLD_BOOT,
        ));
        let new_destination_runtime = Arc::new(server_runtime(
            &source_certificate,
            &pki,
            Arc::clone(&router),
            Arc::clone(&provider),
            destination_pins.clone(),
            &limits,
            DESTINATION_NODE,
            DESTINATION_NEW_BOOT,
        ));
        let sibling_runtime = Arc::new(server_runtime(
            &source_certificate,
            &pki,
            Arc::clone(&router),
            Arc::clone(&provider),
            destination_pins.clone(),
            &limits,
            SIBLING_NODE,
            SIBLING_BOOT,
        ));

        let destination_scope = OwnerScope::new(TENANT_ID, DEVICE_ID);
        let old_binding = membership
            .verified_peer_binding(&MembershipPeerIdentity::new(
                DESTINATION_NODE,
                DESTINATION_OLD_BOOT,
                destination_old_pin.to_hex(),
            ))
            .expect("old destination binding");
        let sibling_binding = membership
            .verified_peer_binding(&MembershipPeerIdentity::new(
                SIBLING_NODE,
                SIBLING_BOOT,
                sibling_pin.to_hex(),
            ))
            .expect("sibling binding");
        let destination_old_route = router
            .resolve(destination_scope, Utc::now(), Some(&old_binding))
            .await
            .expect("old destination route");
        let sibling_route = router
            .resolve(sibling_scope, Utc::now(), Some(&sibling_binding))
            .await
            .expect("sibling route");
        assert_eq!(destination_old_route.owner_token(), &old_owner.token);
        assert_eq!(sibling_route.owner_token(), &sibling_owner.token);

        // `Relay::spawn` exposes an idle production actor handle while this
        // external fixture still owns the real peer server endpoints.  The
        // production ingress callback performs current owner, node, boot, and
        // lease checks before the wrapper records a successful response.
        let handler_catalog: Arc<dyn Catalog> = catalog.clone();
        let old_handle = spawn_idle_handle(
            DESTINATION_NODE,
            DESTINATION_OLD_BOOT,
            Arc::clone(&catalog),
            Arc::clone(&oidc),
        )
        .await;
        let new_handle = spawn_idle_handle(
            DESTINATION_NODE,
            DESTINATION_NEW_BOOT,
            Arc::clone(&catalog),
            Arc::clone(&oidc),
        )
        .await;
        let sibling_handle = spawn_idle_handle(
            SIBLING_NODE,
            SIBLING_BOOT,
            Arc::clone(&catalog),
            oidc.clone(),
        )
        .await;
        let old_accepted = Arc::new(AtomicUsize::new(0));
        let new_accepted = Arc::new(AtomicUsize::new(0));
        let sibling_accepted = Arc::new(AtomicUsize::new(0));
        let old_production = tunnel_relay::peer_ingress_handler(
            old_handle.clone(),
            Arc::clone(&handler_catalog),
            Arc::clone(&oidc),
            DESTINATION_NODE.to_owned(),
            DESTINATION_OLD_BOOT.to_owned(),
        );
        let new_production = tunnel_relay::peer_ingress_handler(
            new_handle.clone(),
            Arc::clone(&handler_catalog),
            Arc::clone(&oidc),
            DESTINATION_NODE.to_owned(),
            DESTINATION_NEW_BOOT.to_owned(),
        );
        let sibling_production = tunnel_relay::peer_ingress_handler(
            sibling_handle.clone(),
            Arc::clone(&handler_catalog),
            Arc::clone(&oidc),
            SIBLING_NODE.to_owned(),
            SIBLING_BOOT.to_owned(),
        );
        let old_server = old_destination_runtime.server_handler(RecordingHandler {
            inner: old_production,
            successful: Arc::clone(&old_accepted),
        });
        let new_server = new_destination_runtime.server_handler(RecordingHandler {
            inner: new_production,
            successful: Arc::clone(&new_accepted),
        });
        let sibling_server = sibling_runtime.server_handler(RecordingHandler {
            inner: sibling_production,
            successful: Arc::clone(&sibling_accepted),
        });
        let old_server = PeerServer::new_with_pin_provider(
            old_server_endpoint,
            source_pins.clone(),
            limits.clone(),
            PeerRuntime::server_policy(),
            old_server,
        )
        .expect("old peer server");
        let new_server = PeerServer::new_with_pin_provider(
            new_server_endpoint,
            source_pins.clone(),
            limits.clone(),
            PeerRuntime::server_policy(),
            new_server,
        )
        .expect("new peer server");
        let sibling_server = PeerServer::new_with_pin_provider(
            sibling_server_endpoint,
            source_pins,
            limits,
            PeerRuntime::server_policy(),
            sibling_server,
        )
        .expect("sibling peer server");
        let old_server_cancel = CancellationToken::new();
        let new_server_cancel = CancellationToken::new();
        let sibling_server_cancel = CancellationToken::new();
        let old_server_task = tokio::spawn(old_server.serve(old_server_cancel.clone()));
        let new_server_task = tokio::spawn(new_server.serve(new_server_cancel.clone()));
        let sibling_server_task = tokio::spawn(sibling_server.serve(sibling_server_cancel.clone()));

        Self {
            membership,
            membership_handle,
            directory,
            issuer,
            source_record,
            sibling_record,
            catalog,
            router,
            source_runtime,
            source_client,
            old_handle,
            new_handle,
            sibling_handle,
            old_destination_runtime,
            new_destination_runtime,
            sibling_runtime,
            old_accepted,
            new_accepted,
            sibling_accepted,
            old_server_cancel,
            new_server_cancel,
            sibling_server_cancel,
            old_server_task,
            new_server_task,
            sibling_server_task,
            destination_pins,
            destination_new_address: new_server_address,
            destination_new_pin,
            sibling_pin,
            destination_old_route,
            sibling_route,
            destination_scope,
            old_owner,
        }
    }

    async fn shutdown(self) {
        self.membership_handle
            .shutdown()
            .await
            .expect("membership supervisor joins");
        self.old_server_cancel.cancel();
        self.new_server_cancel.cancel();
        self.sibling_server_cancel.cancel();
        for task in [
            self.old_server_task,
            self.new_server_task,
            self.sibling_server_task,
        ] {
            let result = timeout(RESPONSE_BOUND, task)
                .await
                .expect("peer server shutdown deadline")
                .expect("peer server task joins");
            assert!(result.is_ok(), "peer server result: {result:?}");
        }
        self.old_handle
            .shutdown()
            .await
            .expect("old relay actor joins");
        self.new_handle
            .shutdown()
            .await
            .expect("new relay actor joins");
        self.sibling_handle
            .shutdown()
            .await
            .expect("sibling relay actor joins");
        self.source_runtime
            .shutdown()
            .await
            .expect("source runtime joins");
        self.old_destination_runtime
            .shutdown()
            .await
            .expect("old destination runtime joins");
        self.new_destination_runtime
            .shutdown()
            .await
            .expect("new destination runtime joins");
        self.sibling_runtime
            .shutdown()
            .await
            .expect("sibling runtime joins");
    }
}

#[tokio::test]
async fn ec019_live_destination_boot_replacement_fences_pool_and_preserves_sibling() {
    let fixture = ReplacementFixture::start().await;
    let result = exercise_replacement(&fixture).await;
    fixture.shutdown().await;
    result.expect("EC019 live destination boot replacement");
}

async fn exercise_replacement(fixture: &ReplacementFixture) -> Result<(), String> {
    open_health(
        &fixture.source_runtime,
        &fixture.destination_old_route,
        "ec019-old-initial",
    )
    .await?;
    open_health(
        &fixture.source_runtime,
        &fixture.sibling_route,
        "ec019-sibling-initial",
    )
    .await?;
    if fixture.old_accepted.load(Ordering::Acquire) != 1
        || fixture.sibling_accepted.load(Ordering::Acquire) != 1
    {
        return Err(
            "initial old and sibling health probes did not succeed exactly once".to_owned(),
        );
    }

    wait_async(EXPIRY_BOUND, || async {
        Ok(fixture
            .catalog
            .current_owner(TENANT_ID, DEVICE_ID, Utc::now())
            .await
            .map_err(|error| format!("old owner lookup: {error}"))?
            .is_none())
    })
    .await?;
    let old_pin = fixture
        .destination_old_route
        .peer_binding()
        .ok_or_else(|| "old route missing peer binding".to_owned())?
        .spki_sha256()
        .to_owned();
    if fixture
        .membership
        .verified_peer_binding(&MembershipPeerIdentity::new(
            DESTINATION_NODE,
            DESTINATION_OLD_BOOT,
            old_pin.clone(),
        ))
        .is_err()
    {
        return Err("old signed membership expired before owner fencing was exercised".to_owned());
    }

    let stale = open_health(
        &fixture.source_runtime,
        &fixture.destination_old_route,
        "ec019-stale-owner",
    )
    .await;
    if stale.is_ok() {
        return Err("expired old owner route was admitted".to_owned());
    }
    if fixture.old_accepted.load(Ordering::Acquire) != 1 {
        return Err("stale owner request reached the production callback".to_owned());
    }

    wait_async(EXPIRY_BOUND, || async {
        Ok(fixture
            .membership
            .verified_peer_binding(&MembershipPeerIdentity::new(
                DESTINATION_NODE,
                DESTINATION_OLD_BOOT,
                old_pin.clone(),
            ))
            .is_err())
    })
    .await?;

    let now = Utc::now();
    let destination_new_record = signed_record(
        &fixture.issuer,
        DESTINATION_NODE,
        2,
        fixture.new_destination_address(),
        vec![membership_key(
            "destination-new-key",
            fixture.new_destination_pin(),
            now,
        )],
        now - ChronoDuration::milliseconds(1),
        now + ChronoDuration::seconds(30),
    );
    fixture
        .directory
        .replace(vec![
            fixture.source_record.clone(),
            destination_new_record,
            fixture.sibling_record.clone(),
        ])
        .await;
    // Deliberately omit notify_membership_changed: the bounded periodic
    // reconciler proves a lost refresh hint cannot strand replacement trust.
    wait_async(EXPIRY_BOUND, || async {
        let snapshot = fixture.membership.snapshot();
        Ok(matches!(snapshot.readiness, MembershipReadiness::Ready)
            && snapshot
                .memberships
                .iter()
                .any(|entry| entry.node_id == DESTINATION_NODE && entry.record_version == 2))
    })
    .await?;

    let replacement_owner = fixture
        .catalog
        .claim_owner(&OwnerClaimRequest {
            deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
            tenant_id: TENANT_ID,
            device_id: DEVICE_ID,
            node_id: DESTINATION_NODE.to_owned(),
            boot_id: DESTINATION_NEW_BOOT.to_owned(),
            session_id: "ec019-new-session".to_owned(),
            lease_expires_at: Utc::now() + ChronoDuration::seconds(30),
        })
        .await
        .map_err(|error| format!("replacement owner claim: {error}"))?;
    if replacement_owner.token.epoch <= fixture.old_owner.token.epoch {
        return Err("replacement owner did not advance the retained epoch".to_owned());
    }

    let new_pin = fixture.new_destination_pin();
    let new_binding = fixture
        .membership
        .verified_peer_binding(&MembershipPeerIdentity::new(
            DESTINATION_NODE,
            DESTINATION_NEW_BOOT,
            new_pin.to_hex(),
        ))
        .map_err(|error| format!("new destination binding: {error}"))?;
    fixture.router.invalidate(fixture.destination_scope).await;
    let replacement_route = fixture
        .router
        .resolve(fixture.destination_scope, Utc::now(), Some(&new_binding))
        .await
        .map_err(|error| format!("replacement route: {error}"))?;
    if replacement_route.owner_token() != &replacement_owner.token
        || replacement_route.boot_id() != DESTINATION_NEW_BOOT
        || replacement_route.peer_binding().is_none_or(|binding| {
            binding.peer_endpoint() != new_binding.peer_endpoint()
                || binding.server_name() != new_binding.server_name()
        })
    {
        return Err("replacement route lost exact owner boot or endpoint binding".to_owned());
    }

    fixture
        .destination_pins
        .replace([new_pin, fixture.sibling_pin()])
        .map_err(|error| format!("destination pin replacement: {error}"))?;
    let revoked = fixture
        .source_client
        .refresh_pins()
        .await
        .map_err(|error| format!("refresh stale peer pins: {error}"))?;
    if revoked != 1 {
        return Err(format!(
            "expected exactly one old pooled connection revoked, got {revoked}"
        ));
    }
    let stale_after_replacement = open_health(
        &fixture.source_runtime,
        &fixture.destination_old_route,
        "ec019-stale-after-replacement",
    )
    .await;
    if stale_after_replacement.is_ok() || fixture.old_accepted.load(Ordering::Acquire) != 1 {
        return Err("stale old route dispatched after destination replacement".to_owned());
    }

    open_health(
        &fixture.source_runtime,
        &replacement_route,
        "ec019-new-owner",
    )
    .await?;
    if fixture.new_accepted.load(Ordering::Acquire) != 1 {
        return Err("fresh destination boot did not dispatch positively".to_owned());
    }
    open_health(
        &fixture.source_runtime,
        &fixture.sibling_route,
        "ec019-sibling-followup",
    )
    .await?;
    if fixture.sibling_accepted.load(Ordering::Acquire) != 2 {
        return Err("sibling health probe did not survive replacement".to_owned());
    }
    Ok(())
}

async fn open_health(
    runtime: &PeerRuntime,
    route: &OwnerRoute,
    request_id: &str,
) -> Result<(), String> {
    let exchange = runtime
        .open(
            route,
            health_envelope(route.owner_token().clone(), request_id),
        )
        .await
        .map_err(|error| format!("peer open failed: {error}"))?;
    let (mut send, mut recv) = exchange.split();
    send.finish()
        .await
        .map_err(|error| format!("peer health finish failed: {error}"))?;
    timeout(RESPONSE_BOUND, recv.accept_response())
        .await
        .map_err(|_| "peer response headers timed out".to_owned())?
        .map_err(|error| format!("peer response headers failed: {error}"))?;
    Ok(())
}

fn health_envelope(owner: OwnerToken, request_id: &str) -> RequestEnvelope {
    RequestEnvelope::new(
        InternalRoute::Health,
        request_id,
        PeerIdentity::new(SOURCE_NODE, SOURCE_BOOT),
        Destination::new(owner, SERVICE_ID),
        5_000,
        Some(10_000),
        InternalRequest::Health(HealthRequest {
            check_id: request_id.to_owned(),
        }),
    )
}

async fn wait_async<F, Fut>(bound: Duration, mut predicate: F) -> Result<(), String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<bool, String>>,
{
    let deadline = tokio::time::Instant::now() + bound;
    timeout_at(deadline, async move {
        loop {
            if predicate().await? {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| format!("condition did not become true within {bound:?}"))?
}

fn directory_state(records: Vec<tunnel_catalog::SignedMembershipRecord>) -> DirectoryState {
    let minimum_versions = records
        .iter()
        .map(|record| {
            let signed: tunnel_cluster::membership::SignedMembershipRecord =
                serde_json::from_slice(&record.bytes).expect("signed membership envelope");
            (signed.node_id, record.version)
        })
        .collect();
    DirectoryState {
        records,
        minimum_versions,
    }
}

async fn seed_sibling_owner(catalog: &MemoryCatalog, scope: OwnerScope) -> OwnerClaim {
    // `MemoryCatalog` retains the same synthetic device under one scope.  The
    // sibling gets a separate device ID so its owner route is independent.
    assert_eq!(scope, OwnerScope::new(TENANT_ID, SIBLING_DEVICE_ID));
    catalog
        .claim_owner(&OwnerClaimRequest {
            deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
            tenant_id: TENANT_ID,
            device_id: SIBLING_DEVICE_ID,
            node_id: SIBLING_NODE.to_owned(),
            boot_id: SIBLING_BOOT.to_owned(),
            session_id: "ec019-sibling-session".to_owned(),
            lease_expires_at: Utc::now() + ChronoDuration::seconds(30),
        })
        .await
        .expect("sibling owner claim")
}

fn oidc_fixture() -> Arc<OidcVerifier> {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("OIDC signing key");
    let approved = ApprovedJwk::from_ed25519_der("ec019", key.public_key_raw())
        .expect("OIDC verification key");
    let config = OidcConfig::new(OIDC_ISSUER, [OIDC_AUDIENCE.to_owned()], vec![approved])
        .expect("OIDC config");
    Arc::new(OidcVerifier::new(config).expect("OIDC verifier"))
}

struct RecordingHandler<H> {
    inner: H,
    successful: Arc<AtomicUsize>,
}

impl<H> PeerIngressHandler for RecordingHandler<H>
where
    H: PeerIngressHandler,
{
    fn handle(&self, request: InboundPeerRequest) -> PeerIngressHandlerFuture {
        let future = self.inner.handle(request);
        let successful = Arc::clone(&self.successful);
        Box::pin(async move {
            let result = future.await;
            if result.is_ok() {
                successful.fetch_add(1, Ordering::AcqRel);
            }
            result
        })
    }
}

async fn spawn_idle_handle(
    node_id: &str,
    boot_id: &str,
    catalog: Arc<MemoryCatalog>,
    oidc: Arc<OidcVerifier>,
) -> RelayHandle {
    let mut options = RelayOptions::new(oidc);
    options.node_id = node_id.to_owned();
    options.boot_id = boot_id.to_owned();
    options.deployment_incarnation = DEPLOYMENT_INCARNATION.to_owned();
    Relay::spawn(options, catalog)
        .await
        .expect("idle production relay actor")
}

fn signed_record(
    issuer: &MembershipIssuer,
    node_id: &str,
    record_version: u64,
    endpoint: SocketAddr,
    keys: Vec<RelayKey>,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> tunnel_catalog::SignedMembershipRecord {
    let record = MembershipRecord {
        schema_version: MEMBERSHIP_SCHEMA_VERSION,
        deployment_id: DEPLOYMENT_ID.to_owned(),
        deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
        node_id: node_id.to_owned(),
        record_version,
        roles: vec![RELAY_PEER_ROLE.to_owned()],
        peer_endpoint: endpoint.to_string(),
        server_name: "localhost".to_owned(),
        keys,
        issued_at: not_before,
        not_before,
        expires_at,
    };
    tunnel_catalog::SignedMembershipRecord {
        version: record_version,
        bytes: issuer
            .sign_membership_bytes(record)
            .expect("signed synthetic membership record"),
    }
}

fn membership_key(key_id: &str, pin: SpkiSha256, now: DateTime<Utc>) -> RelayKey {
    membership_key_window(
        key_id,
        pin,
        now - ChronoDuration::milliseconds(1),
        now + ChronoDuration::seconds(30),
    )
}

fn membership_key_window(
    key_id: &str,
    pin: SpkiSha256,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> RelayKey {
    RelayKey {
        key_id: key_id.to_owned(),
        spki_sha256: pin.to_hex(),
        not_before,
        expires_at,
        revoked: false,
    }
}

fn server_runtime(
    source_certificate: &CertificateMaterial,
    pki: &FixturePki,
    router: Arc<OwnerRouter<dyn Catalog>>,
    provider: Arc<dyn PeerBindingProvider>,
    destination_pins: SharedPeerPins,
    limits: &PeerTransportLimits,
    node_id: &str,
    boot_id: &str,
) -> PeerRuntime {
    let (endpoint, _) = client_endpoint(source_certificate, pki);
    let client = PeerClient::new_with_pin_provider(endpoint, destination_pins, limits.clone())
        .expect("server runtime client");
    PeerRuntime::new(client, router, provider, node_id, boot_id)
}

fn server_endpoint(
    certificate: &CertificateMaterial,
    pki: &FixturePki,
) -> (quinn::Endpoint, SocketAddr) {
    let chain = certificate_chain(certificate, pki);
    let config = load_peer_server_config_from_pem(
        chain.as_bytes(),
        certificate.private_key_pem.as_bytes(),
        pki.peer_ca.certificate_pem.as_bytes(),
    )
    .expect("peer mTLS server config");
    let endpoint = quinn::Endpoint::server(config, SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("server QUIC endpoint");
    let address = endpoint.local_addr().expect("server address");
    (endpoint, address)
}

fn client_endpoint(
    certificate: &CertificateMaterial,
    pki: &FixturePki,
) -> (quinn::Endpoint, SocketAddr) {
    let chain = certificate_chain(certificate, pki);
    let config = load_peer_client_config_from_pem(
        chain.as_bytes(),
        certificate.private_key_pem.as_bytes(),
        pki.peer_ca.certificate_pem.as_bytes(),
    )
    .expect("peer mTLS client config");
    let mut endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("client QUIC endpoint");
    let address = endpoint.local_addr().expect("client address");
    endpoint.set_default_client_config(config);
    (endpoint, address)
}

fn certificate_chain(certificate: &CertificateMaterial, pki: &FixturePki) -> String {
    format!(
        "{}{}",
        certificate.certificate_pem, pki.peer_ca.certificate_pem
    )
}

fn spki(certificate: &CertificateMaterial) -> SpkiSha256 {
    spki_sha256_from_der(&certificate.certificate_der).expect("peer SPKI")
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
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(1),
    )
    .expect("bounded peer limits")
}
