//! M7-I06 live membership and peer-transport regression coverage.
//!
//! The fixture below keeps the directory and checkpoint authority in memory,
//! but uses the production signed-membership verifier, `PeerRuntime`,
//! `PeerClient`, and `PeerServer` over real loopback QUIC/mTLS/H3 sockets.  A
//! pin update is published only after a successful signed reconciliation; the
//! test therefore exercises the same trust boundary that the production pin
//! coordinator owns without requiring Redis or an external authority.

#![allow(clippy::too_many_arguments)]

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use http::StatusCode;
use tokio::{
    sync::RwLock,
    task::JoinHandle,
    time::{timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{Catalog, MemoryCatalog, OwnerClaim, OwnerToken};
use tunnel_cluster::{
    envelope::{
        Destination, HealthRequest, InternalRequest, InternalRoute,
        PeerIdentity as WirePeerIdentity, RequestEnvelope,
    },
    membership::{
        MEMBERSHIP_SCHEMA_VERSION, MembershipCheckpoint, MembershipIssuer, MembershipRecord,
        PrivateEndpointPolicy, RELAY_PEER_ROLE, RelayKey, TrustedPublisherKey,
    },
    peer_frame::PeerRecordKind,
};
use tunnel_relay::membership_runtime::MembershipFuture;
use tunnel_relay::{
    CheckpointAuthority, CheckpointAuthorityError, CheckpointRequest, CheckpointResponse,
    MembershipPeerIdentity, MembershipReadiness, MembershipRecordSource, MembershipRuntime,
    MembershipRuntimeConfig, MembershipRuntimeHandle, PeerBindingProvider, PeerIngressHandler,
    PeerRuntime, PeerRuntimeError,
    peer_runtime::{InboundPeerRequest, PeerExchangeRecv},
    routing::{OwnerRoute, OwnerRouter, RelayIdentity},
};
use tunnel_test_harness::{CertificateMaterial, FixturePki};
use tunnel_transport::{
    ApprovedPeerPins, PeerClient, PeerServer, PeerTransportError, PeerTransportLimits,
    SharedPeerPins, SpkiSha256, load_peer_client_config_from_pem, load_peer_server_config_from_pem,
    spki_sha256_from_der,
};
use uuid::Uuid;

const DEPLOYMENT_ID: &str = "m7-live-membership-deployment";
const DEPLOYMENT_INCARNATION: &str = "m7-live-membership-incarnation";
const SOURCE_NODE: &str = "m7-live-source";
const OLD_BOOT_ID: &str = "m7-live-old-boot";
const NEW_BOOT_ID: &str = "m7-live-new-boot";
const UNAPPROVED_BOOT_ID: &str = "m7-live-unapproved-boot";
const DESTINATION_NODE: &str = "m7-live-destination";
const DESTINATION_BOOT_ID: &str = "m7-live-destination-boot";
const PUBLISHER_KEY_ID: &str = "m7-live-membership-publisher";
const RECONCILE_BOUND: Duration = Duration::from_secs(2);
const RESPONSE_BOUND: Duration = Duration::from_secs(2);

#[derive(Clone)]
struct DirectoryState {
    records: Vec<tunnel_catalog::SignedMembershipRecord>,
    minimum_versions: BTreeMap<String, u64>,
}

#[derive(Clone)]
struct SignedDirectory {
    state: Arc<RwLock<DirectoryState>>,
    reads: Arc<AtomicUsize>,
}

impl SignedDirectory {
    fn new(records: Vec<tunnel_catalog::SignedMembershipRecord>) -> Self {
        let minimum_versions = records
            .iter()
            .map(|record| (record.version_node_id(), record.version))
            .collect();
        Self {
            state: Arc::new(RwLock::new(DirectoryState {
                records,
                minimum_versions,
            })),
            reads: Arc::new(AtomicUsize::new(0)),
        }
    }

    async fn replace(&self, records: Vec<tunnel_catalog::SignedMembershipRecord>) {
        let minimum_versions = records
            .iter()
            .map(|record| (record.version_node_id(), record.version))
            .collect();
        *self.state.write().await = DirectoryState {
            records,
            minimum_versions,
        };
    }

    async fn snapshot(&self) -> DirectoryState {
        self.state.read().await.clone()
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::Acquire)
    }
}

// The catalog wrapper intentionally exposes only the signed record version and
// bytes.  The node ID used for checkpoint minimums is recovered from the
// signed bytes by the authority fixture when it builds the directory.
trait CatalogRecordNodeId {
    fn version_node_id(&self) -> String;
}

impl CatalogRecordNodeId for tunnel_catalog::SignedMembershipRecord {
    fn version_node_id(&self) -> String {
        let signed: tunnel_cluster::membership::SignedMembershipRecord =
            serde_json::from_slice(&self.bytes).expect("synthetic signed membership envelope");
        signed.node_id
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
        Box::pin(async move {
            self.reads.fetch_add(1, Ordering::AcqRel);
            Ok(self.state.read().await.records.clone())
        })
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

#[derive(Clone)]
struct HoldingHandler {
    accepted: Arc<AtomicUsize>,
    release: CancellationToken,
}

impl PeerIngressHandler for HoldingHandler {
    fn handle(
        &self,
        request: InboundPeerRequest,
    ) -> tunnel_relay::peer_runtime::PeerIngressHandlerFuture {
        let accepted = Arc::clone(&self.accepted);
        let release = self.release.clone();
        Box::pin(async move {
            if request.envelope().route != InternalRoute::Health
                || !matches!(&request.envelope().request, InternalRequest::Health(_))
            {
                return Err(PeerRuntimeError::Closed);
            }
            let (mut send, mut recv) = request.split();
            let Some(record) = recv.recv_message().await? else {
                return Err(PeerRuntimeError::Closed);
            };
            if record.kind() != PeerRecordKind::ConsumerChunk {
                return Err(PeerRuntimeError::Closed);
            }
            accepted.fetch_add(1, Ordering::AcqRel);
            send.respond(StatusCode::OK).await?;
            send.send_message(PeerRecordKind::ConsumerChunk, b"m7-live-accepted")
                .await?;
            // Keep the H3 stream open so a pin update can prove that the old
            // admitted stream is actively closed, rather than merely denying a
            // later dial.
            release.cancelled().await;
            send.finish().await
        })
    }
}

struct LiveFixture {
    membership: Arc<MembershipRuntime>,
    membership_handle: MembershipRuntimeHandle,
    directory: SignedDirectory,
    issuer: Arc<MembershipIssuer>,
    destination_record: tunnel_catalog::SignedMembershipRecord,
    source_pins: SharedPeerPins,
    old_runtime: Arc<PeerRuntime>,
    new_runtime: Arc<PeerRuntime>,
    unapproved_runtime: Arc<PeerRuntime>,
    old_route: OwnerRoute,
    new_route: OwnerRoute,
    old_pin: SpkiSha256,
    new_pin: SpkiSha256,
    unapproved_pin: SpkiSha256,
    source_endpoint: SocketAddr,
    release: CancellationToken,
    server_cancel: CancellationToken,
    server_task: JoinHandle<Result<(), PeerTransportError>>,
    handler: HoldingHandler,
}

impl LiveFixture {
    async fn start() -> Self {
        let pki = FixturePki::new().expect("synthetic fixture PKI");
        let old_certificate = pki
            .issue_peer(SOURCE_NODE)
            .expect("old source peer certificate");
        let new_certificate = pki
            .issue_peer(SOURCE_NODE)
            .expect("new source peer certificate");
        let unapproved_certificate = pki
            .issue_peer(SOURCE_NODE)
            .expect("unapproved source peer certificate");
        let destination_certificate = pki
            .issue_peer(DESTINATION_NODE)
            .expect("destination peer certificate");
        let old_pin = spki(&old_certificate);
        let new_pin = spki(&new_certificate);
        let unapproved_pin = spki(&unapproved_certificate);
        let destination_pin = spki(&destination_certificate);

        let limits = test_limits();
        let destination_chain = certificate_chain(&destination_certificate, &pki);
        let server_config = load_peer_server_config_from_pem(
            destination_chain.as_bytes(),
            destination_certificate.private_key_pem.as_bytes(),
            pki.peer_ca.certificate_pem.as_bytes(),
        )
        .expect("destination mTLS server config");
        let server_endpoint =
            quinn::Endpoint::server(server_config, SocketAddr::from(([127, 0, 0, 1], 0)))
                .expect("destination QUIC endpoint");
        let server_address = server_endpoint.local_addr().expect("server address");

        let (old_endpoint, old_address) = client_endpoint(&old_certificate, &pki);
        let (new_endpoint, new_address) = client_endpoint(&new_certificate, &pki);
        let (unapproved_endpoint, unapproved_address) =
            client_endpoint(&unapproved_certificate, &pki);

        let (issuer, _issuer_pkcs8) =
            MembershipIssuer::generate(PUBLISHER_KEY_ID).expect("membership issuer");
        let issuer = Arc::new(issuer);
        let destination_record = signed_record(
            &issuer,
            DESTINATION_NODE,
            1,
            server_address,
            vec![
                // Keep an approved overlap pin ahead of the certificate the
                // server actually presents.  Outbound routing must use the
                // authenticated certificate-specific binding after the H3
                // handshake, rather than treating the first signed pin as
                // authoritative.
                membership_key(
                    "destination-overlap",
                    SpkiSha256::from_bytes([0; 32]),
                    Utc::now(),
                ),
                membership_key("destination-key", destination_pin, Utc::now()),
            ],
            Utc::now(),
            Utc::now() + ChronoDuration::seconds(30),
        );
        let source_record = signed_record(
            &issuer,
            SOURCE_NODE,
            1,
            old_address,
            vec![
                membership_key("source-old-key", old_pin, Utc::now()),
                membership_key("source-new-key", new_pin, Utc::now()),
            ],
            Utc::now(),
            Utc::now() + ChronoDuration::seconds(30),
        );
        let directory = SignedDirectory::new(vec![source_record, destination_record.clone()]);
        let endpoint_policy = PrivateEndpointPolicy::allowlisted(
            ["127.0.0.1"],
            ["localhost"],
            [
                server_address.port(),
                old_address.port(),
                new_address.port(),
                unapproved_address.port(),
            ],
        )
        .expect("private endpoint policy");
        let config = MembershipRuntimeConfig::new(
            DEPLOYMENT_ID,
            DEPLOYMENT_INCARNATION,
            DESTINATION_NODE,
            DESTINATION_BOOT_ID,
            endpoint_policy,
            Duration::from_secs(60),
            Duration::from_secs(1),
            Duration::from_millis(30),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .expect("bounded membership runtime config")
        .with_local_spki_sha256(destination_pin.to_hex())
        .expect("destination local SPKI");
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
        let initial_snapshot = membership.snapshot();
        assert_eq!(initial_snapshot.readiness, MembershipReadiness::Ready);
        assert_source_keys(&initial_snapshot, old_pin, new_pin);

        let source_pins = SharedPeerPins::empty();
        publish_source_pins(&source_pins, &initial_snapshot, old_pin, new_pin);

        let old_client = PeerClient::new(
            old_endpoint,
            ApprovedPeerPins::new([destination_pin]).expect("destination pin set"),
            limits.clone(),
        )
        .expect("old peer client");
        let new_client = PeerClient::new(
            new_endpoint,
            ApprovedPeerPins::new([destination_pin]).expect("destination pin set"),
            limits.clone(),
        )
        .expect("new peer client");
        let unapproved_client = PeerClient::new(
            unapproved_endpoint,
            ApprovedPeerPins::new([destination_pin]).expect("destination pin set"),
            limits.clone(),
        )
        .expect("unapproved peer client");
        let provider: Arc<dyn PeerBindingProvider> = membership.clone();
        let catalog: Arc<dyn Catalog> = Arc::new(MemoryCatalog::new());
        let old_identity = RelayIdentity::new(DEPLOYMENT_INCARNATION, SOURCE_NODE, OLD_BOOT_ID)
            .expect("old source identity");
        let router: Arc<OwnerRouter<dyn Catalog>> =
            Arc::new(OwnerRouter::new(catalog, old_identity).expect("owner router"));
        let old_runtime = Arc::new(PeerRuntime::new(
            old_client,
            Arc::clone(&router),
            Arc::clone(&provider),
            SOURCE_NODE,
            OLD_BOOT_ID,
        ));
        let new_runtime = Arc::new(PeerRuntime::new(
            new_client,
            Arc::clone(&router),
            Arc::clone(&provider),
            SOURCE_NODE,
            NEW_BOOT_ID,
        ));
        let unapproved_runtime = Arc::new(PeerRuntime::new(
            unapproved_client,
            router,
            provider,
            SOURCE_NODE,
            UNAPPROVED_BOOT_ID,
        ));

        // Exercise the same pre-handshake provider lookup used by
        // `PeerRuntime::resolve`: the signed overlap pin is first, while the
        // destination server presents `destination_pin`.
        let destination_binding = membership
            .binding(DESTINATION_NODE, DESTINATION_BOOT_ID, Utc::now())
            .await
            .expect("destination overlap binding");
        assert_eq!(
            destination_binding.spki_sha256(),
            SpkiSha256::from_bytes([0; 32]).to_hex()
        );
        let owner = OwnerClaim {
            token: OwnerToken {
                deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
                tenant_id: Uuid::from_u128(0x1000_0000_0000_0000_0000_0000_0000_0001),
                device_id: Uuid::from_u128(0x2000_0000_0000_0000_0000_0000_0000_0001),
                node_id: DESTINATION_NODE.to_owned(),
                boot_id: DESTINATION_BOOT_ID.to_owned(),
                session_id: "m7-live-session".to_owned(),
                epoch: 1,
            },
            lease_expires_at: Utc::now() + ChronoDuration::seconds(30),
        };
        let old_route = OwnerRoute::Remote {
            owner: owner.clone(),
            peer: Some(destination_binding.clone()),
        };
        let new_route = OwnerRoute::Remote {
            owner,
            peer: Some(destination_binding),
        };

        let release = CancellationToken::new();
        let handler = HoldingHandler {
            accepted: Arc::new(AtomicUsize::new(0)),
            release: release.clone(),
        };
        let server_handler = old_runtime.server_handler(handler.clone());
        let server = PeerServer::new_with_pin_provider(
            server_endpoint,
            source_pins.clone(),
            limits,
            PeerRuntime::server_policy(),
            server_handler,
        )
        .expect("peer server");
        let server_cancel = CancellationToken::new();
        let server_task = tokio::spawn(server.serve(server_cancel.clone()));

        Self {
            membership,
            membership_handle,
            directory,
            issuer,
            destination_record,
            source_pins,
            old_runtime,
            new_runtime,
            unapproved_runtime,
            old_route,
            new_route,
            old_pin,
            new_pin,
            unapproved_pin,
            source_endpoint: old_address,
            release,
            server_cancel,
            server_task,
            handler,
        }
    }

    async fn shutdown(self) {
        self.release.cancel();
        self.membership_handle
            .shutdown()
            .await
            .expect("membership supervisor joins");
        self.server_cancel.cancel();
        let server_result = timeout(RESPONSE_BOUND, self.server_task)
            .await
            .expect("peer server shutdown deadline")
            .expect("peer server task joins");
        assert!(
            server_result.is_ok(),
            "peer server result: {server_result:?}"
        );
        self.old_runtime
            .shutdown()
            .await
            .expect("old peer client joins");
        self.new_runtime
            .shutdown()
            .await
            .expect("new peer client joins");
        self.unapproved_runtime
            .shutdown()
            .await
            .expect("unapproved peer client joins");
    }
}

#[tokio::test]
async fn m7_signed_membership_rotation_closes_old_h3_and_preserves_new_sibling() {
    let fixture = LiveFixture::start().await;
    let result = exercise_rotation(&fixture).await;
    fixture.shutdown().await;
    result.expect("signed membership live rotation");
}

async fn exercise_rotation(fixture: &LiveFixture) -> Result<(), String> {
    let mut old_stream = open_and_read_ack(
        &fixture.old_runtime,
        &fixture.old_route,
        health_envelope(
            OLD_BOOT_ID,
            fixture.old_route.owner_token().clone(),
            "old-initial",
        ),
    )
    .await?;
    let mut new_stream = open_and_read_ack(
        &fixture.new_runtime,
        &fixture.new_route,
        health_envelope(
            NEW_BOOT_ID,
            fixture.new_route.owner_token().clone(),
            "new-initial",
        ),
    )
    .await?;
    if fixture.handler.accepted.load(Ordering::Acquire) != 2 {
        return Err("old and new overlap clients must both reach the owner".to_owned());
    }
    let unapproved_result = open_and_read_ack(
        &fixture.unapproved_runtime,
        &fixture.old_route,
        health_envelope(
            UNAPPROVED_BOOT_ID,
            fixture.old_route.owner_token().clone(),
            "unapproved-initial",
        ),
    )
    .await;
    if unapproved_result.is_ok() {
        return Err("unapproved source SPKI reached the H3 owner".to_owned());
    }
    if fixture.handler.accepted.load(Ordering::Acquire) != 2 {
        return Err("unapproved source must be rejected before owner dispatch".to_owned());
    }
    let source_snapshot = fixture
        .membership
        .snapshot()
        .memberships
        .into_iter()
        .find(|membership| membership.node_id == SOURCE_NODE)
        .ok_or_else(|| "source snapshot entry missing".to_owned())?;
    if source_snapshot
        .spki_sha256
        .contains(&fixture.unapproved_pin.to_hex())
    {
        return Err("unapproved SPKI appeared in signed source snapshot".to_owned());
    }
    let old_admission = fixture
        .membership
        .admit_peer(MembershipPeerIdentity::new(
            SOURCE_NODE,
            OLD_BOOT_ID,
            fixture.old_pin.to_hex(),
        ))
        .map_err(|error| format!("old overlap admission failed: {error}"))?;

    let reads_before_rotation = fixture.directory.reads();
    let rotation_started = Instant::now();
    let new_record = signed_record(
        fixture.issuer.as_ref(),
        SOURCE_NODE,
        2,
        fixture.source_endpoint,
        vec![membership_key(
            "source-new-key",
            fixture.new_pin,
            Utc::now(),
        )],
        Utc::now(),
        Utc::now() + ChronoDuration::seconds(30),
    );
    fixture
        .directory
        .replace(vec![
            new_record,
            // The destination record remains authoritative and unchanged.
            fixture.destination_record.clone(),
        ])
        .await;
    // Deliberately omit notify_membership_changed: the supervisor's periodic
    // authenticated read is the lost-hint recovery path.
    wait_until(RECONCILE_BOUND, || {
        let snapshot = fixture.membership.snapshot();
        snapshot.generation >= 2
            && matches!(snapshot.readiness, MembershipReadiness::Ready)
            && snapshot
                .memberships
                .iter()
                .find(|membership| membership.node_id == SOURCE_NODE)
                .is_some_and(|membership| {
                    !membership.spki_sha256.contains(&fixture.old_pin.to_hex())
                        && membership.spki_sha256.contains(&fixture.new_pin.to_hex())
                })
    })
    .await?;
    let rotation_elapsed = rotation_started.elapsed();
    if rotation_elapsed > RECONCILE_BOUND || fixture.directory.reads() <= reads_before_rotation {
        return Err(format!(
            "periodic membership rotation exceeded bound or did not read source: {rotation_elapsed:?}"
        ));
    }
    publish_source_pins(
        &fixture.source_pins,
        &fixture.membership.snapshot(),
        fixture.old_pin,
        fixture.new_pin,
    );
    if fixture.source_pins.snapshot().len() != 1
        || !fixture.source_pins.snapshot().contains(fixture.new_pin)
    {
        return Err("signed rotation must publish only the replacement source pin".to_owned());
    }
    if fixture
        .membership
        .verified_peer_binding(&MembershipPeerIdentity::new(
            SOURCE_NODE,
            OLD_BOOT_ID,
            fixture.old_pin.to_hex(),
        ))
        .is_ok()
    {
        return Err("removed old key remained admissible after signed reconciliation".to_owned());
    }
    if !old_admission.is_invalidated() {
        return Err("old active admission was not invalidated by signed key removal".to_owned());
    }

    let old_closed = timeout(RESPONSE_BOUND, old_stream.recv_message()).await;
    if !matches!(old_closed, Ok(Ok(None)) | Ok(Err(_))) {
        return Err(format!(
            "old H3 stream was not closed after pin removal: {old_closed:?}"
        ));
    }
    let mut replacement_stream = open_and_read_ack(
        &fixture.new_runtime,
        &fixture.new_route,
        health_envelope(
            NEW_BOOT_ID,
            fixture.new_route.owner_token().clone(),
            "new-after-rotation",
        ),
    )
    .await?;
    if fixture.handler.accepted.load(Ordering::Acquire) != 3 {
        return Err("new-key sibling did not survive old-key removal".to_owned());
    }
    let new_admission = fixture
        .membership
        .admit_peer(MembershipPeerIdentity::new(
            SOURCE_NODE,
            NEW_BOOT_ID,
            fixture.new_pin.to_hex(),
        ))
        .map_err(|error| format!("new replacement admission failed: {error}"))?;

    // Publish an already-expired, signed revision without a wake hint.  The
    // periodic pass must fail closed and revoke the remaining source pin.
    let expired_record = signed_record(
        fixture.issuer.as_ref(),
        SOURCE_NODE,
        3,
        fixture.source_endpoint,
        vec![membership_key_window(
            "source-new-key",
            fixture.new_pin,
            Utc::now() - ChronoDuration::seconds(2),
            Utc::now() - ChronoDuration::seconds(1),
        )],
        Utc::now() - ChronoDuration::seconds(2),
        Utc::now() - ChronoDuration::seconds(1),
    );
    fixture
        .directory
        .replace(vec![expired_record, fixture.destination_record.clone()])
        .await;
    let expiry_started = Instant::now();
    wait_until(RECONCILE_BOUND, || {
        matches!(
            fixture.membership.readiness(),
            MembershipReadiness::Unready(_)
        )
    })
    .await?;
    let expiry_elapsed = expiry_started.elapsed();
    if expiry_elapsed > RECONCILE_BOUND {
        return Err(format!(
            "expired membership was not withdrawn in bound: {expiry_elapsed:?}"
        ));
    }
    publish_source_pins(
        &fixture.source_pins,
        &fixture.membership.snapshot(),
        fixture.old_pin,
        fixture.new_pin,
    );
    if !fixture.source_pins.snapshot().is_empty() {
        return Err("unready membership must clear all source pins".to_owned());
    }
    if fixture
        .membership
        .verified_peer_binding(&MembershipPeerIdentity::new(
            SOURCE_NODE,
            NEW_BOOT_ID,
            fixture.new_pin.to_hex(),
        ))
        .is_ok()
    {
        return Err("expired source membership still admitted a new-key peer".to_owned());
    }
    if !new_admission.is_invalidated() {
        return Err("new active admission was not invalidated by membership expiry".to_owned());
    }
    let new_closed = timeout(RESPONSE_BOUND, new_stream.recv_message()).await;
    if !matches!(new_closed, Ok(Ok(None)) | Ok(Err(_))) {
        return Err(format!(
            "new H3 stream was not closed on membership expiry: {new_closed:?}"
        ));
    }
    let replacement_closed = timeout(RESPONSE_BOUND, replacement_stream.recv_message()).await;
    if !matches!(replacement_closed, Ok(Ok(None)) | Ok(Err(_))) {
        return Err(format!(
            "replacement H3 stream was not closed on membership expiry: {replacement_closed:?}"
        ));
    }
    Ok(())
}

async fn open_and_read_ack(
    runtime: &Arc<PeerRuntime>,
    route: &OwnerRoute,
    envelope: RequestEnvelope,
) -> Result<PeerExchangeRecv, String> {
    let exchange = runtime
        .open(route, envelope)
        .await
        .map_err(|error| format!("peer open failed: {error}"))?;
    let (mut send, mut recv) = exchange.split();
    send.send_message(PeerRecordKind::ConsumerChunk, b"m7-live-probe")
        .await
        .map_err(|error| format!("peer request body failed: {error}"))?;
    send.finish()
        .await
        .map_err(|error| format!("peer request finish failed: {error}"))?;
    let record = timeout(RESPONSE_BOUND, recv.recv_message())
        .await
        .map_err(|_| "peer response timed out".to_owned())?
        .map_err(|error| format!("peer response failed: {error}"))?
        .ok_or_else(|| "peer response ended before acknowledgement".to_owned())?;
    if record.kind() != PeerRecordKind::ConsumerChunk || record.body() != b"m7-live-accepted" {
        return Err("unexpected live membership acknowledgement".to_owned());
    }
    Ok(recv)
}

fn health_envelope(boot_id: &str, owner: OwnerToken, request_id: &str) -> RequestEnvelope {
    RequestEnvelope::new(
        InternalRoute::Health,
        request_id,
        WirePeerIdentity::new(SOURCE_NODE, boot_id),
        Destination::new(
            owner,
            Uuid::from_u128(0x3000_0000_0000_0000_0000_0000_0000_0001),
        ),
        5_000,
        Some(10_000),
        InternalRequest::Health(HealthRequest {
            check_id: request_id.to_owned(),
        }),
    )
}

async fn wait_until<F>(bound: Duration, mut predicate: F) -> Result<(), String>
where
    F: FnMut() -> bool,
{
    let deadline = tokio::time::Instant::now() + bound;
    timeout_at(deadline, async move {
        loop {
            if predicate() {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| format!("condition did not become true within {bound:?}"))?
}

fn assert_source_keys(
    snapshot: &tunnel_relay::MembershipSnapshot,
    old: SpkiSha256,
    new: SpkiSha256,
) {
    let source = snapshot
        .memberships
        .iter()
        .find(|membership| membership.node_id == SOURCE_NODE)
        .expect("source snapshot entry");
    assert!(source.spki_sha256.contains(&old.to_hex()));
    assert!(source.spki_sha256.contains(&new.to_hex()));
}

fn publish_source_pins(
    pins: &SharedPeerPins,
    snapshot: &tunnel_relay::MembershipSnapshot,
    old: SpkiSha256,
    new: SpkiSha256,
) {
    let source = snapshot
        .memberships
        .iter()
        .find(|membership| membership.node_id == SOURCE_NODE);
    let mut approved = Vec::new();
    if matches!(snapshot.readiness, MembershipReadiness::Ready)
        && let Some(source) = source
    {
        if source.spki_sha256.contains(&old.to_hex()) {
            approved.push(old);
        }
        if source.spki_sha256.contains(&new.to_hex()) {
            approved.push(new);
        }
    }
    pins.replace(approved)
        .expect("bounded source pin publication");
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
        now - ChronoDuration::seconds(1),
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
