//! Configured two-relay dynamic peer SPKI replacement (M7-C06 / M7-I06).
//!
//! Relay A and relay B run as separate `tunnel-relay serve` processes over
//! a Redis TLS forwarder and a live signed checkpoint authority.  Relay A is
//! never restarted.  The signed relay-b record walks old -> old+new -> new
//! while a harness peer client presents the old, the replacement, and a rogue
//! certificate to A's private listener, and an impostor QUIC server with the
//! retired certificate sits at B's endpoint after the overlap ends.  Public
//! canaries enter A and are answered by a device attached to B at the initial
//! and overlap phases.  After the replacement, relay A's readiness recovering
//! is the evidence that A adopted the new pin without restarting; the
//! replacement process's own public admission is deliberately not exercised
//! (see the readiness-convergence limitation in docs/testing.md and the
//! phase 5 comment below), so this gate does not prove a post-replacement
//! public canary.  Every assertion is local to this source build; evidence is
//! payload-free.

use std::{
    collections::BTreeMap,
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use chrono::Utc;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, body::Bytes};
use hyper_util::rt::TokioIo;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use sha2::{Digest, Sha256};
use tokio::time::{sleep, timeout, timeout_at};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{
    Catalog, CatalogError, RedisCatalog, RedisMembershipPublisher, SignedMembershipRecord,
};
use tunnel_client::{
    ConnectConfig, ConnectOptions, CredentialConfig, LimitsConfig, LocalExport, LocalExportKind,
    connect,
};
use tunnel_core::RotationConfig;
use tunnel_test_harness::cluster_fixture::{
    FixturePeerKey, MembershipRecordOptions, RelayNodeFixture, TestMembershipAuthority,
};
use tunnel_test_harness::{
    CertificateMaterial, ClusterFixture, FixturePki, FixtureTopology, HarnessError, ManagedProcess,
    OidcFixture, ProcessSpec, Result,
};
use tunnel_transport::{
    ApprovedPeerPins, PeerClient, PeerDestination, PeerTransportLimits, SpkiSha256,
    load_peer_client_config_from_pem, load_peer_server_config_from_pem,
    load_server_config_from_pem, spki_sha256_from_der,
};
use uuid::Uuid;

#[path = "common/m7_deployment.rs"]
mod common;
use common::{
    CheckpointServer, FixtureFiles, ProcessConfigFixture, RedisTlsProxy, free_tcp_addr,
    health_request, hex_encode, jwks_json, parse_plaintext_upstream, process_diagnostic,
    relay_binary_path, send_sigint, wait_for_exit, wait_for_ports_released, wait_for_ready,
};

macro_rules! bail {
    ($($argument:tt)*) => {
        return Err(HarnessError::Process(format!($($argument)*)))
    };
}

const TEST_DEADLINE: Duration = Duration::from_secs(150);
const CLI_DEADLINE: Duration = Duration::from_secs(20);
const CONNECT_DEADLINE: Duration = Duration::from_secs(20);
const EXCHANGE_DEADLINE: Duration = Duration::from_secs(8);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(8);
const TRANSITION_DEADLINE: Duration = Duration::from_secs(20);
const PEER_PROBE_DEADLINE: Duration = Duration::from_secs(4);
const IMPOSTOR_DEADLINE: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(150);
/// Signed records are re-issued at each phase with this lifetime so the
/// staged walk never depends on a record older than the relay's 60-second
/// bound.
const RECORD_LIFETIME_SECONDS: i64 = 55;
const DEPLOYMENT_ID_PREFIX: &str = "m7-spki-replacement-deployment";
const INCARNATION_PREFIX: &str = "m7-spki-replacement-incarnation";
const CANARY: &str = "m7-spki-replacement-canary";
const PAYLOAD: &[u8] = b"configured-spki-replacement-request-body";

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires TEST_REDIS_URL; run explicitly as the configured dynamic SPKI replacement gate"]
async fn m7_configured_relay_replaces_peer_spki_without_restart() {
    run_spki_replacement_gate()
        .await
        .expect("configured dynamic SPKI replacement gate");
}

#[cfg(unix)]
async fn run_spki_replacement_gate() -> Result<()> {
    let deadline = Instant::now() + TEST_DEADLINE;
    let mut fixture = create_fixture().await?;
    let result = fixture.exercise(deadline).await;
    let cleanup = fixture.cleanup().await;
    match (result, cleanup) {
        (Ok(mut evidence), Ok(())) => {
            // Cleanup joined every relay process, the checkpoint authority,
            // the Redis forwarder and the catalog namespace without error.
            evidence.cleanup_joined = true;
            evidence.validate()?;
            println!("{}", evidence.evidence_line());
            Ok(())
        }
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(HarnessError::Process(format!(
            "configured SPKI replacement gate failed: {primary}; cleanup failed: {cleanup}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnerEvidence {
    node_id: String,
    boot_id: String,
    deployment_incarnation: String,
    tenant_id: Uuid,
    device_id: Uuid,
    session_id: String,
    epoch: u64,
}

/// Outcome of one harness peer connection presented to relay A's private
/// listener.  `Accepted` means the authenticated health stream returned 200;
/// every other outcome carries a bounded, payload-free classification.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PeerProbeOutcome {
    Accepted,
    Rejected(String),
}

impl PeerProbeOutcome {
    fn accepted(&self) -> bool {
        matches!(self, Self::Accepted)
    }
}

/// The typed public outcome observed while the live owner was reachable only
/// across the retired peer certificate.
#[derive(Debug, Clone)]
struct RetiredRouteOutcome {
    status: u16,
    code: String,
    execution: String,
}

#[derive(Debug, Clone, Default)]
struct ImpostorEvidence {
    connections: usize,
    connections_from_relay_a: usize,
    streams_opened: usize,
    closes_without_stream: usize,
}

#[derive(Debug, Clone)]
struct SpkiReplacementEvidence {
    a_pid: u32,
    b_old_pid: u32,
    b_new_pid: u32,
    old_spki_sha256: String,
    replacement_spki_sha256: String,
    rogue_spki_sha256: String,
    initial_owner: OwnerEvidence,
    overlap_owner: OwnerEvidence,
    device_generation_before_overlap: u64,
    device_generation_after_overlap: u64,
    checkpoint_requests_before_overlap: usize,
    checkpoint_requests_after_overlap: usize,
    new_cert_before_record: PeerProbeOutcome,
    old_cert_before_record: PeerProbeOutcome,
    new_cert_during_overlap: PeerProbeOutcome,
    old_cert_during_overlap: PeerProbeOutcome,
    overlap_readiness_samples: usize,
    overlap_readiness_unready_samples: usize,
    a_unready_after_b_old_stopped: bool,
    stale_record_publish_refused: bool,
    old_cert_after_overlap: PeerProbeOutcome,
    new_cert_after_overlap: PeerProbeOutcome,
    a_unready_after_pin_retired: bool,
    retired_owner_released: bool,
    retired_relay_closed_device_session: bool,
    retired_route: RetiredRouteOutcome,
    impostor: ImpostorEvidence,
    a_probe_failure_diagnostic: bool,
    a_ready_after_replacement: bool,
    a_unready_under_unsigned_record: bool,
    rogue_cert_under_unsigned_record: PeerProbeOutcome,
    new_cert_under_unsigned_record: PeerProbeOutcome,
    a_ready_after_recovery: bool,
    rogue_cert_after_recovery: PeerProbeOutcome,
    old_cert_after_recovery: PeerProbeOutcome,
    new_cert_after_recovery: PeerProbeOutcome,
    diagnostics_payload_free: bool,
    cleanup_joined: bool,
}

impl SpkiReplacementEvidence {
    fn validate(&self) -> Result<()> {
        if self.a_pid == 0 || self.b_old_pid == 0 || self.b_new_pid == 0 {
            bail!("evidence omitted a relay process PID");
        }
        if self.b_old_pid == self.b_new_pid {
            bail!("relay B replacement reused the old process");
        }
        let digests = [
            &self.old_spki_sha256,
            &self.replacement_spki_sha256,
            &self.rogue_spki_sha256,
        ];
        if digests.iter().any(|digest| !is_spki_digest(digest))
            || self.old_spki_sha256 == self.replacement_spki_sha256
            || self.replacement_spki_sha256 == self.rogue_spki_sha256
            || self.old_spki_sha256 == self.rogue_spki_sha256
        {
            bail!("SPKI digests do not describe three distinct bounded pins");
        }
        if self.initial_owner != self.overlap_owner {
            bail!("the established owner session changed during the overlap");
        }
        if self.initial_owner.node_id != "relay-b" {
            bail!("owner evidence names the wrong relay node");
        }
        if self.initial_owner.boot_id.is_empty()
            || self.initial_owner.session_id.is_empty()
            || self.initial_owner.epoch == 0
            || self.initial_owner.tenant_id.is_nil()
            || self.initial_owner.device_id.is_nil()
        {
            bail!("the established owner token did not carry an exact identity");
        }
        if self.device_generation_before_overlap == 0
            || self.device_generation_before_overlap != self.device_generation_after_overlap
        {
            bail!("the device session did not survive the overlap on its original generation");
        }
        if self.checkpoint_requests_after_overlap <= self.checkpoint_requests_before_overlap {
            bail!("no signed checkpoint was refreshed while the overlap record was adopted");
        }
        if self.new_cert_before_record.accepted() {
            bail!("relay A accepted the replacement certificate before any signed record");
        }
        if !self.old_cert_before_record.accepted() {
            bail!("relay A rejected the approved old certificate before the overlap");
        }
        if !self.new_cert_during_overlap.accepted() || !self.old_cert_during_overlap.accepted() {
            bail!("relay A did not accept both approved certificates during the overlap");
        }
        if self.overlap_readiness_samples == 0 || self.overlap_readiness_unready_samples != 0 {
            bail!("relay A readiness did not stay ready through the overlap");
        }
        if !self.a_unready_after_b_old_stopped {
            bail!("relay A readiness did not reflect the retired relay B route");
        }
        if !self.stale_record_publish_refused {
            bail!("the catalog accepted a stale signed record");
        }
        if self.old_cert_after_overlap.accepted() {
            bail!("relay A accepted the retired certificate after the overlap ended");
        }
        if !self.new_cert_after_overlap.accepted() {
            bail!("relay A rejected the replacement certificate after the overlap ended");
        }
        if !self.a_unready_after_pin_retired {
            bail!("relay A readiness did not reflect the retired peer pin");
        }
        if !self.retired_owner_released {
            bail!("the relay with the retired certificate kept its owner claim");
        }
        if !self.retired_relay_closed_device_session {
            bail!("the retired relay did not close its device session when its key was retired");
        }
        // The retired peer route can only fail closed: either the peer pin
        // check refused the live owner's certificate, or readiness had already
        // withdrawn that route.  Both are pre-dispatch outcomes, and the echo
        // export means a dispatched body would have returned 200 instead.
        if self.retired_route.status != 503
            || self.retired_route.execution != "not_dispatched"
            || !matches!(
                self.retired_route.code.as_str(),
                "PEER_UNTRUSTED" | "CLUSTER_UNREADY"
            )
        {
            bail!(
                "the retired peer route did not return a typed pre-dispatch failure: status={} code={} execution={}",
                self.retired_route.status,
                self.retired_route.code,
                self.retired_route.execution
            );
        }
        if self.impostor.connections == 0 || self.impostor.connections_from_relay_a == 0 {
            bail!("relay A never dialed the retired-certificate endpoint");
        }
        if self.impostor.streams_opened != 0
            || self.impostor.closes_without_stream != self.impostor.connections_from_relay_a
        {
            bail!("relay A opened a stream toward the retired certificate");
        }
        if !self.a_probe_failure_diagnostic {
            bail!("relay A did not emit the bounded probe failure diagnostic");
        }
        if !self.a_ready_after_replacement {
            bail!("relay A readiness did not recover on the replacement route");
        }
        if !self.a_unready_under_unsigned_record {
            bail!("relay A stayed ready while an unsigned record was published");
        }
        if self.rogue_cert_under_unsigned_record.accepted()
            || self.new_cert_under_unsigned_record.accepted()
        {
            bail!("relay A accepted a certificate while an unsigned record was published");
        }
        if !self.a_ready_after_recovery {
            bail!("relay A readiness did not recover after the signed record was restored");
        }
        if self.rogue_cert_after_recovery.accepted() || self.old_cert_after_recovery.accepted() {
            bail!("relay A accepted a rogue or retired certificate after recovery");
        }
        if !self.new_cert_after_recovery.accepted() {
            bail!("relay A rejected the replacement certificate after recovery");
        }
        if !self.diagnostics_payload_free {
            bail!("relay diagnostics contained credential or payload material");
        }
        if !self.cleanup_joined {
            bail!("fixture cleanup was not joined");
        }
        Ok(())
    }

    fn evidence_line(&self) -> String {
        format!(
            "m7-configured-spki-replacement a_pid={} b_old_pid={} b_new_pid={} old_spki={} replacement_spki={} rogue_spki={} initial_boot={} initial_session={} initial_epoch={} device_generation={} checkpoint_requests={}->{} new_cert_before_record={} old_cert_before_record={} new_cert_during_overlap={} old_cert_during_overlap={} overlap_readiness_samples={} overlap_unready_samples={} a_unready_after_b_old_stopped={} stale_record_publish_refused={} old_cert_after_overlap={} new_cert_after_overlap={} a_unready_after_pin_retired={} retired_owner_released={} retired_relay_closed_device_session={} retired_route_status={} retired_route_code={} retired_route_execution={} impostor_connections={} impostor_from_relay_a={} impostor_streams={} impostor_closes_without_stream={} a_probe_failure_diagnostic={} a_ready_after_replacement={} a_unready_under_unsigned_record={} rogue_cert_under_unsigned_record={} new_cert_under_unsigned_record={} a_ready_after_recovery={} rogue_cert_after_recovery={} old_cert_after_recovery={} new_cert_after_recovery={} diagnostics_payload_free={} cleanup_joined={}",
            self.a_pid,
            self.b_old_pid,
            self.b_new_pid,
            self.old_spki_sha256,
            self.replacement_spki_sha256,
            self.rogue_spki_sha256,
            self.initial_owner.boot_id,
            self.initial_owner.session_id,
            self.initial_owner.epoch,
            self.device_generation_after_overlap,
            self.checkpoint_requests_before_overlap,
            self.checkpoint_requests_after_overlap,
            probe_code(&self.new_cert_before_record),
            probe_code(&self.old_cert_before_record),
            probe_code(&self.new_cert_during_overlap),
            probe_code(&self.old_cert_during_overlap),
            self.overlap_readiness_samples,
            self.overlap_readiness_unready_samples,
            self.a_unready_after_b_old_stopped,
            self.stale_record_publish_refused,
            probe_code(&self.old_cert_after_overlap),
            probe_code(&self.new_cert_after_overlap),
            self.a_unready_after_pin_retired,
            self.retired_owner_released,
            self.retired_relay_closed_device_session,
            self.retired_route.status,
            self.retired_route.code,
            self.retired_route.execution,
            self.impostor.connections,
            self.impostor.connections_from_relay_a,
            self.impostor.streams_opened,
            self.impostor.closes_without_stream,
            self.a_probe_failure_diagnostic,
            self.a_ready_after_replacement,
            self.a_unready_under_unsigned_record,
            probe_code(&self.rogue_cert_under_unsigned_record),
            probe_code(&self.new_cert_under_unsigned_record),
            self.a_ready_after_recovery,
            probe_code(&self.rogue_cert_after_recovery),
            probe_code(&self.old_cert_after_recovery),
            probe_code(&self.new_cert_after_recovery),
            self.diagnostics_payload_free,
            self.cleanup_joined,
        )
    }
}

fn probe_code(outcome: &PeerProbeOutcome) -> String {
    match outcome {
        PeerProbeOutcome::Accepted => "accepted".to_owned(),
        PeerProbeOutcome::Rejected(kind) => format!("rejected:{kind}"),
    }
}

fn is_spki_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct RelayProcessSlot {
    process: ManagedProcess,
    consumer_bind: SocketAddr,
    device_bind: SocketAddr,
    peer_bind: SocketAddr,
    label: &'static str,
}

/// Certificate material presented by the harness peer client.
struct PeerCredential {
    label: &'static str,
    chain_pem: String,
    key_pem: String,
}

struct PartialFixture {
    catalog: Option<RedisCatalog>,
    /// One forwarder per relay: the shared helper bounds concurrent
    /// connections, and each configured relay opens its own catalog lanes.
    redis_proxies: Vec<RedisTlsProxy>,
    checkpoint: Option<CheckpointServer>,
}

impl PartialFixture {
    async fn cleanup(self) -> Result<()> {
        let mut errors = Vec::new();
        if let Some(catalog) = self.catalog
            && let Err(error) = catalog.cleanup_fixture_namespace().await
        {
            errors.push(format!("partial catalog cleanup: {error}"));
        }
        if let Some(checkpoint) = self.checkpoint
            && let Err(error) = checkpoint.shutdown_allow_unused().await
        {
            errors.push(error.to_string());
        }
        for redis in self.redis_proxies {
            if let Err(error) = redis.shutdown_allow_unused().await {
                errors.push(error.to_string());
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(HarnessError::Process(errors.join("; ")))
        }
    }
}

struct SpkiReplacementFixture {
    _files: FixtureFiles,
    catalog: Option<RedisCatalog>,
    redis_proxies: Vec<RedisTlsProxy>,
    checkpoint: Option<CheckpointServer>,
    relay_binary: PathBuf,
    upstream_url: String,
    namespace: String,
    deployment_id: String,
    deployment_incarnation: String,
    signer: Arc<TestMembershipAuthority>,
    rogue_signer: TestMembershipAuthority,
    node_b: RelayNodeFixture,
    device: tunnel_test_harness::DeviceFixture,
    service_id: Uuid,
    client_token: String,
    a_consumer_bind: SocketAddr,
    a_device_bind: SocketAddr,
    a_peer_bind: SocketAddr,
    b_consumer_bind: SocketAddr,
    b_device_bind: SocketAddr,
    b_peer_bind: SocketAddr,
    server_ca_der: Vec<u8>,
    peer_ca_pem: String,
    a_spki: SpkiSha256,
    old_credential: PeerCredential,
    replacement_credential: PeerCredential,
    rogue_credential: PeerCredential,
    old_key: FixturePeerKey,
    replacement_key: FixturePeerKey,
    rogue_key: FixturePeerKey,
    a_config: PathBuf,
    b_old_config: PathBuf,
    b_new_config: PathBuf,
    client_config: ConnectConfig,
    processes: Vec<RelayProcessSlot>,
    client: Option<tunnel_client::ConnectionHandle>,
    diagnostics: Vec<(String, String)>,
}

async fn create_fixture() -> Result<SpkiReplacementFixture> {
    let files = FixtureFiles::new()?;
    let mut partial = PartialFixture {
        catalog: None,
        redis_proxies: Vec::new(),
        checkpoint: None,
    };
    let result = create_fixture_inner(files, &mut partial).await;
    if result.is_err() {
        let _ = partial.cleanup().await;
    }
    result
}

async fn create_fixture_inner(
    files: FixtureFiles,
    partial: &mut PartialFixture,
) -> Result<SpkiReplacementFixture> {
    let relay_binary = relay_binary_path()?;
    let upstream_url = env::var("TEST_REDIS_URL").map_err(|_| HarnessError::MissingRedisUrl {
        env_var: "TEST_REDIS_URL",
        guidance: "configured SPKI replacement requires a disposable plaintext Redis upstream"
            .into(),
    })?;
    let upstream = parse_plaintext_upstream(&upstream_url)?;
    let run_id = Uuid::new_v4().simple().to_string();
    let deployment_id = format!("{DEPLOYMENT_ID_PREFIX}-{run_id}");
    let deployment_incarnation = format!("{INCARNATION_PREFIX}-{run_id}");
    let namespace = format!("m7-spki-replacement-fixture-{run_id}");
    let pki = FixturePki::new()?;
    let oidc = OidcFixture::new(
        format!("https://m7-spki-replacement-oidc-{run_id}.invalid"),
        "agent-tunnel",
    )?;
    let topology = FixtureTopology::new(&pki)?;
    let device = topology
        .devices_a
        .first()
        .cloned()
        .ok_or_else(|| HarnessError::InvalidInput("missing canary device".into()))?;
    let service_id = *topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("missing canary service".into()))?;
    let consumer = topology
        .consumers_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("missing consumer".into()))?;
    let catalog_fixture = topology.catalog_fixture(&oidc)?;

    let mut cluster =
        ClusterFixture::with_deployment(&pki, &deployment_id, &deployment_incarnation)?;
    for node in &mut cluster.nodes {
        node.release_ports();
    }
    let mut nodes = std::mem::take(&mut cluster.nodes).into_iter();
    let mut node_a = None;
    let mut node_b = None;
    for node in nodes.by_ref() {
        match node.node_id.as_str() {
            "relay-a" => node_a = Some(node),
            "relay-b" => node_b = Some(node),
            _ => {}
        }
    }
    let node_a = node_a.ok_or_else(|| HarnessError::InvalidInput("missing relay-a".into()))?;
    let node_b = node_b.ok_or_else(|| HarnessError::InvalidInput("missing relay-b".into()))?;
    let signer = Arc::new(cluster.membership_authority);
    let rogue_signer = TestMembershipAuthority::with_key_id("m7-spki-replacement-rogue-signer")?;
    if rogue_signer.public_key() == signer.public_key() {
        bail!("rogue signer unexpectedly shares the trusted publisher key");
    }

    let a_spki = spki_sha256_from_der(&node_a.peer_certificate.certificate_der)
        .map_err(|error| HarnessError::Pki(format!("relay-a SPKI: {error}")))?;
    let old_spki = node_b.peer_spki_fingerprint()?;
    let replacement_peer = pki.issue_peer("relay-b")?;
    let rogue_peer = pki.issue_peer("relay-b")?;
    let replacement_spki = replacement_peer.spki_fingerprint_sha256()?;
    let rogue_spki = rogue_peer.spki_fingerprint_sha256()?;
    if old_spki == replacement_spki || old_spki == rogue_spki || replacement_spki == rogue_spki {
        bail!("fixture peer certificates did not produce distinct SPKI digests");
    }
    let old_key = FixturePeerKey {
        key_id: "relay-b-peer-old".into(),
        spki_sha256: old_spki,
        not_before: Utc::now(),
        expires_at: Utc::now(),
        revoked: false,
    };
    let replacement_key = FixturePeerKey {
        key_id: "relay-b-peer-replacement".into(),
        spki_sha256: replacement_spki,
        not_before: Utc::now(),
        expires_at: Utc::now(),
        revoked: false,
    };
    let rogue_key = FixturePeerKey {
        key_id: "relay-b-peer-rogue".into(),
        spki_sha256: rogue_spki,
        not_before: Utc::now(),
        expires_at: Utc::now(),
        revoked: false,
    };

    let server_leaf = pki.issue_server("m7-spki-replacement-relay")?;
    let checkpoint_leaf = pki.issue_server("m7-spki-replacement-checkpoint")?;
    let redis_leaf = pki.issue_server("m7-spki-replacement-redis")?;
    let server_chain = format!(
        "{}{}",
        server_leaf.certificate_pem, pki.server_ca.certificate_pem
    );
    let checkpoint_chain = format!(
        "{}{}",
        checkpoint_leaf.certificate_pem, pki.server_ca.certificate_pem
    );
    let redis_chain = format!(
        "{}{}",
        redis_leaf.certificate_pem, pki.server_ca.certificate_pem
    );
    let redis_tls = load_server_config_from_pem(
        redis_chain.as_bytes(),
        redis_leaf.private_key_pem.as_bytes(),
        None,
    )
    .map_err(|error| HarnessError::Pki(format!("building Redis TLS proxy: {error}")))?;
    // Relay A and relay B each get their own configured `rediss://`
    // forwarder so one relay's catalog lanes cannot exhaust the other's
    // bounded connection budget.
    partial
        .redis_proxies
        .push(RedisTlsProxy::bind(upstream, redis_tls.clone()).await?);
    partial
        .redis_proxies
        .push(RedisTlsProxy::bind(upstream, redis_tls).await?);
    let a_redis_url = partial.redis_proxies[0].url();
    let b_redis_url = partial.redis_proxies[1].url();
    let catalog =
        RedisCatalog::connect_for_recovery(&upstream_url, &namespace, &deployment_incarnation)
            .await
            .map_err(|error| HarnessError::Redis(format!("opening catalog: {error}")))?;
    catalog
        .activate_deployment_incarnation()
        .await
        .map_err(|error| HarnessError::Redis(format!("activating catalog: {error}")))?;
    catalog
        .seed_fixture(&catalog_fixture)
        .await
        .map_err(|error| HarnessError::Redis(format!("seeding catalog: {error}")))?;
    partial.catalog = Some(catalog);

    let record_a = sign_record(
        &signer,
        &deployment_id,
        &deployment_incarnation,
        &node_a,
        1,
        {
            let mut key = FixturePeerKey {
                key_id: "relay-a-peer".into(),
                spki_sha256: a_spki.to_hex(),
                not_before: Utc::now(),
                expires_at: Utc::now(),
                revoked: false,
            };
            refresh_key(&mut key);
            vec![key]
        },
    )?;
    let record_b_initial = sign_record(
        &signer,
        &deployment_id,
        &deployment_incarnation,
        &node_b,
        1,
        vec![fresh_key(&old_key)],
    )?;
    publish_membership(&upstream_url, &namespace, "relay-a", &record_a).await?;
    publish_membership(&upstream_url, &namespace, "relay-b", &record_b_initial).await?;

    let checkpoint = CheckpointServer::bind_live(
        load_server_config_from_pem(
            checkpoint_chain.as_bytes(),
            checkpoint_leaf.private_key_pem.as_bytes(),
            None,
        )
        .map_err(|error| HarnessError::Pki(format!("building checkpoint TLS: {error}")))?,
        signer.clone(),
        deployment_id.clone(),
        deployment_incarnation.clone(),
        BTreeMap::from([("relay-a".to_owned(), 1), ("relay-b".to_owned(), 1)]),
    )
    .await?;
    let checkpoint_endpoint = format!(
        "https://localhost:{}/v1/checkpoint",
        checkpoint.address().port()
    );
    partial.checkpoint = Some(checkpoint);

    let signer_trust_path = files.write(
        "membership-trust.json",
        format!(
            "{{\"keys\":[{{\"key_id\":{},\"public_key\":{}}}]}}",
            serde_json::to_string(signer.key_id())?,
            serde_json::to_string(&hex_encode(&signer.public_key()))?,
        )
        .as_bytes(),
    )?;
    let oidc_jwks_path = files.write("oidc-jwks.json", jwks_json(&oidc)?.as_bytes())?;
    let server_chain_path = files.write("relay-cert-chain.pem", server_chain.as_bytes())?;
    let server_key_path = files.write("relay-key.pem", server_leaf.private_key_pem.as_bytes())?;
    let server_ca_path = files.write("server-ca.pem", pki.server_ca.certificate_pem.as_bytes())?;
    let device_ca_path = files.write("device-ca.pem", pki.device_ca.certificate_pem.as_bytes())?;
    let peer_ca_path = files.write("peer-ca.pem", pki.peer_ca.certificate_pem.as_bytes())?;
    let peer_a_chain_path = files.write(
        "relay-a-peer-chain.pem",
        node_a.peer_certificate_chain_pem().as_bytes(),
    )?;
    let peer_a_key_path = files.write(
        "relay-a-peer-key.pem",
        node_a.peer_certificate.private_key_pem.as_bytes(),
    )?;
    let old_credential = credential("relay-b-old", &node_b.peer_certificate, &pki);
    let replacement_credential = credential("relay-b-replacement", &replacement_peer, &pki);
    let rogue_credential = credential("relay-b-rogue", &rogue_peer, &pki);
    let peer_b_old_chain_path = files.write(
        "relay-b-old-peer-chain.pem",
        old_credential.chain_pem.as_bytes(),
    )?;
    let peer_b_old_key_path = files.write(
        "relay-b-old-peer-key.pem",
        old_credential.key_pem.as_bytes(),
    )?;
    let peer_b_new_chain_path = files.write(
        "relay-b-replacement-peer-chain.pem",
        replacement_credential.chain_pem.as_bytes(),
    )?;
    let peer_b_new_key_path = files.write(
        "relay-b-replacement-peer-key.pem",
        replacement_credential.key_pem.as_bytes(),
    )?;
    let state_a = files.state_path()?;
    let state_b = state_a.with_file_name("relay-b-membership-state.json");
    // The replacement boot is a fresh deployment of the same node: it brings
    // its own membership version-state file, exactly as a replaced container
    // or host would.
    let state_b_replacement = state_a.with_file_name("relay-b-replacement-membership-state.json");
    let a_consumer_bind = free_tcp_addr();
    let a_device_bind = distinct_tcp_addr(&[a_consumer_bind]);
    let b_consumer_bind = distinct_tcp_addr(&[a_consumer_bind, a_device_bind]);
    let b_device_bind = distinct_tcp_addr(&[a_consumer_bind, a_device_bind, b_consumer_bind]);
    let a_peer_bind = node_a.addresses.udp;
    let b_peer_bind = node_b.addresses.udp;
    let allowed_peer_ports = [a_peer_bind.port(), b_peer_bind.port()];
    let render = |consumer_bind,
                  device_bind,
                  peer_bind,
                  chain: &Path,
                  key: &Path,
                  state: &Path,
                  node_id,
                  redis_url: &str| {
        let config = ProcessConfigFixture {
            consumer_bind,
            device_bind,
            peer_bind,
            redis_url,
            namespace: &namespace,
            deployment_id: &deployment_id,
            deployment_incarnation: &deployment_incarnation,
            oidc: &oidc,
            oidc_jwks_path: &oidc_jwks_path,
            server_chain_path: &server_chain_path,
            server_key_path: &server_key_path,
            server_ca_path: &server_ca_path,
            device_ca_path: &device_ca_path,
            peer_chain_path: chain,
            peer_key_path: key,
            peer_ca_path: &peer_ca_path,
            signer_trust_path: &signer_trust_path,
            state_path: state,
            checkpoint_endpoint: &checkpoint_endpoint,
            node_id,
        };
        with_fast_refresh(&config.render(), &allowed_peer_ports)
    };
    let a_config = files.write(
        "relay-a.toml",
        render(
            a_consumer_bind,
            a_device_bind,
            a_peer_bind,
            &peer_a_chain_path,
            &peer_a_key_path,
            &state_a,
            "relay-a",
            &a_redis_url,
        )
        .as_bytes(),
    )?;
    let b_old_config = files.write(
        "relay-b-old.toml",
        render(
            b_consumer_bind,
            b_device_bind,
            b_peer_bind,
            &peer_b_old_chain_path,
            &peer_b_old_key_path,
            &state_b,
            "relay-b",
            &b_redis_url,
        )
        .as_bytes(),
    )?;
    let b_new_config = files.write(
        "relay-b-replacement.toml",
        render(
            b_consumer_bind,
            b_device_bind,
            b_peer_bind,
            &peer_b_new_chain_path,
            &peer_b_new_key_path,
            &state_b_replacement,
            "relay-b",
            &b_redis_url,
        )
        .as_bytes(),
    )?;
    initialize_state(&relay_binary, &a_config).await?;
    initialize_state(&relay_binary, &b_old_config).await?;
    initialize_state(&relay_binary, &b_new_config).await?;
    let client_config = write_client_config(
        &files,
        "spki-device",
        device.id,
        service_id,
        b_device_bind,
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &pki.device_ca.certificate_pem,
        &pki.server_ca.certificate_pem,
    )?;
    let client_token = oidc.issue(&consumer.name)?;
    Ok(SpkiReplacementFixture {
        _files: files,
        catalog: partial.catalog.take(),
        redis_proxies: std::mem::take(&mut partial.redis_proxies),
        checkpoint: partial.checkpoint.take(),
        relay_binary,
        upstream_url,
        namespace,
        deployment_id,
        deployment_incarnation,
        signer,
        rogue_signer,
        node_b,
        device,
        service_id,
        client_token,
        a_consumer_bind,
        a_device_bind,
        a_peer_bind,
        b_consumer_bind,
        b_device_bind,
        b_peer_bind,
        server_ca_der: pki.server_ca.certificate_der.clone(),
        peer_ca_pem: pki.peer_ca.certificate_pem.clone(),
        a_spki,
        old_credential,
        replacement_credential,
        rogue_credential,
        old_key,
        replacement_key,
        rogue_key,
        a_config,
        b_old_config,
        b_new_config,
        client_config,
        processes: Vec::new(),
        client: None,
        diagnostics: Vec::new(),
    })
}

fn credential(label: &'static str, leaf: &CertificateMaterial, pki: &FixturePki) -> PeerCredential {
    PeerCredential {
        label,
        chain_pem: format!("{}{}", leaf.certificate_pem, pki.peer_ca.certificate_pem),
        key_pem: leaf.private_key_pem.clone(),
    }
}

fn fresh_key(key: &FixturePeerKey) -> FixturePeerKey {
    let mut key = key.clone();
    refresh_key(&mut key);
    key
}

fn refresh_key(key: &mut FixturePeerKey) {
    let now = Utc::now();
    key.not_before = now - chrono::Duration::seconds(1);
    key.expires_at = now + chrono::Duration::seconds(RECORD_LIFETIME_SECONDS);
}

/// Sign one bounded relay record at the current instant.  Every phase signs
/// its own record so the staged walk is never limited by the age of an
/// earlier record.
fn sign_record(
    signer: &TestMembershipAuthority,
    deployment_id: &str,
    deployment_incarnation: &str,
    node: &RelayNodeFixture,
    record_version: u64,
    keys: Vec<FixturePeerKey>,
) -> Result<SignedMembershipRecord> {
    let now = Utc::now();
    let fixture = signer.sign_membership_with_endpoint_and_keys(
        deployment_id,
        deployment_incarnation,
        node,
        MembershipRecordOptions {
            record_version,
            peer_endpoint: node.addresses.udp,
            keys,
            now,
            expires_at: now + chrono::Duration::seconds(RECORD_LIFETIME_SECONDS),
        },
    )?;
    Ok(fixture.catalog_record())
}

impl SpkiReplacementFixture {
    fn sign_b(&self, version: u64, keys: Vec<FixturePeerKey>) -> Result<SignedMembershipRecord> {
        sign_record(
            &self.signer,
            &self.deployment_id,
            &self.deployment_incarnation,
            &self.node_b,
            version,
            keys.iter().map(fresh_key).collect(),
        )
    }

    fn catalog(&self) -> Result<&RedisCatalog> {
        self.catalog
            .as_ref()
            .ok_or_else(|| HarnessError::Redis("fixture catalog missing".into()))
    }

    fn checkpoint_requests(&self) -> usize {
        self.checkpoint
            .as_ref()
            .map(CheckpointServer::request_count)
            .unwrap_or(0)
    }

    async fn probe_a(&self, credential: &PeerCredential) -> Result<PeerProbeOutcome> {
        probe_relay_peer(
            self.a_peer_bind,
            credential,
            &self.peer_ca_pem,
            self.a_spki,
            PEER_PROBE_DEADLINE,
        )
        .await
    }

    /// Poll relay A's private listener with `credential` until the outcome's
    /// acceptance matches `expected` or the bounded deadline passes.
    async fn wait_for_probe(
        &self,
        credential: &PeerCredential,
        expected: bool,
        phase: &str,
        deadline: Instant,
    ) -> Result<PeerProbeOutcome> {
        let phase_deadline = Instant::now() + TRANSITION_DEADLINE;
        let end = phase_deadline.min(deadline);
        loop {
            let outcome = self.probe_a(credential).await?;
            if outcome.accepted() == expected {
                return Ok(outcome);
            }
            if Instant::now() >= end {
                bail!(
                    "{phase}: relay A did not reach the expected {} outcome for the {} certificate before the bounded deadline (last={})",
                    if expected { "accepted" } else { "rejected" },
                    credential.label,
                    probe_code(&outcome)
                );
            }
            sleep(POLL_INTERVAL).await;
        }
    }

    async fn wait_for_a_readiness(
        &self,
        ready: bool,
        phase: &str,
        deadline: Instant,
    ) -> Result<()> {
        let end = (Instant::now() + TRANSITION_DEADLINE).min(deadline);
        loop {
            let status = health_request(self.a_consumer_bind, &self.server_ca_der, "/readyz")
                .await
                .map(|(status, _)| status);
            let matches = match status {
                Ok(200) => ready,
                Ok(503) => !ready,
                Ok(_) | Err(_) => false,
            };
            if matches {
                return Ok(());
            }
            if Instant::now() >= end {
                bail!(
                    "{phase}: relay A readiness did not become {} before the bounded deadline (last={status:?})",
                    if ready { "ready" } else { "unready" }
                );
            }
            sleep(POLL_INTERVAL).await;
        }
    }

    async fn echo_via_a(&self, phase: &str) -> Result<()> {
        echo_http(EchoProbe {
            consumer_bind: self.a_consumer_bind,
            server_ca_der: &self.server_ca_der,
            token: &self.client_token,
            device_id: self.device.id,
            service_id: self.service_id,
            payload: PAYLOAD,
            canary: CANARY.as_bytes(),
            phase,
        })
        .await
    }

    async fn connect_device(&mut self, phase: &str) -> Result<u64> {
        let mut client = connect_fresh(&self.client_config).await?;
        let session = timeout(CONNECT_DEADLINE, client.wait_ready())
            .await
            .map_err(|_| HarnessError::Timeout(format!("{phase} device readiness")))?
            .map_err(|error| HarnessError::Process(format!("{phase} device readiness: {error}")))?;
        if session.generation == 0 {
            bail!("{phase}: device reported generation zero");
        }
        self.client = Some(client);
        Ok(session.generation)
    }

    /// Stop a device whose control socket the owning relay may already have
    /// closed.  A relay that fails closed on its own retired key terminates
    /// the session, so only that exact transport close is tolerated here.
    async fn stop_closed_device(&mut self, phase: &str) -> Result<bool> {
        let Some(client) = self.client.take() else {
            return Ok(false);
        };
        match client.stop().await {
            Ok(()) => Ok(false),
            Err(error) => {
                let text = error.to_string();
                if text.contains("control read") || text.contains("control socket closed") {
                    Ok(true)
                } else {
                    Err(HarnessError::Process(format!(
                        "{phase} device stop: {error}"
                    )))
                }
            }
        }
    }

    fn device_generation(&self) -> Result<u64> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| HarnessError::Process("device client is not connected".into()))?;
        let status = client.status_snapshot();
        status
            .active_generation
            .filter(|generation| *generation > 0)
            .ok_or_else(|| {
                HarnessError::Process(format!(
                    "device session lost its active generation (phase={})",
                    status.phase
                ))
            })
    }

    /// Wait until the relay whose certificate was retired gives up its owner
    /// claim.  A relay whose own signed key is no longer approved must fail
    /// closed rather than keep serving the device it owns.
    async fn wait_for_owner_released(&self, deadline: Instant) -> Result<bool> {
        let end = (Instant::now() + TRANSITION_DEADLINE).min(deadline);
        loop {
            let owner = self
                .catalog()?
                .current_owner(self.device.tenant_id, self.device.id, Utc::now())
                .await
                .map_err(|error| {
                    HarnessError::Redis(format!("reading retired-route owner: {error}"))
                })?;
            if owner.is_none() {
                return Ok(true);
            }
            if Instant::now() >= end {
                bail!(
                    "the relay whose peer certificate was retired kept its owner claim past the bounded deadline"
                );
            }
            sleep(POLL_INTERVAL).await;
        }
    }

    /// Issue one public consumer request while the only route to the device's
    /// owner crosses the retired peer certificate, and return the exact typed
    /// pre-dispatch outcome.  The device export is an echo, so a dispatched
    /// body would have produced a 200 canary response instead.
    async fn retired_route_outcome(&self) -> Result<RetiredRouteOutcome> {
        let (status, code, execution) = typed_failure_http(EchoProbe {
            consumer_bind: self.a_consumer_bind,
            server_ca_der: &self.server_ca_der,
            token: &self.client_token,
            device_id: self.device.id,
            service_id: self.service_id,
            payload: PAYLOAD,
            canary: CANARY.as_bytes(),
            phase: "spki-retired-route",
        })
        .await?;
        Ok(RetiredRouteOutcome {
            status,
            code,
            execution,
        })
    }

    async fn owner(&self, deadline: Instant) -> Result<OwnerEvidence> {
        wait_for_owner(
            self.catalog()?,
            self.device.tenant_id,
            self.device.id,
            "relay-b",
            &self.deployment_incarnation,
            (Instant::now() + TRANSITION_DEADLINE).min(deadline),
        )
        .await
    }

    async fn start_slot(
        &mut self,
        config: &Path,
        consumer_bind: SocketAddr,
        device_bind: SocketAddr,
        peer_bind: SocketAddr,
        label: &'static str,
    ) -> Result<u32> {
        let process = start_relay(
            &self.relay_binary,
            config,
            consumer_bind,
            device_bind,
            peer_bind,
            &self.server_ca_der,
            label,
        )
        .await?;
        let pid = process
            .id()
            .ok_or_else(|| HarnessError::Process(format!("{label} PID disappeared")))?;
        self.processes.push(RelayProcessSlot {
            process,
            consumer_bind,
            device_bind,
            peer_bind,
            label,
        });
        Ok(pid)
    }

    /// Spawn a relay process without waiting for readiness.  Two configured
    /// relays each require the other's authenticated peer route, so the first
    /// pair must be started before either can converge.
    async fn spawn_slot(
        &mut self,
        config: &Path,
        consumer_bind: SocketAddr,
        device_bind: SocketAddr,
        peer_bind: SocketAddr,
        label: &'static str,
    ) -> Result<u32> {
        let process = ManagedProcess::spawn(
            label,
            ProcessSpec::new(&self.relay_binary)
                .arg("serve")
                .arg("--config")
                .arg(config.display().to_string()),
        )
        .await?;
        let pid = process
            .id()
            .ok_or_else(|| HarnessError::Process(format!("{label} PID disappeared")))?;
        self.processes.push(RelayProcessSlot {
            process,
            consumer_bind,
            device_bind,
            peer_bind,
            label,
        });
        Ok(pid)
    }

    /// Await readiness for two already spawned relays at the same time.
    async fn wait_for_pair_ready(&mut self, first: &str, second: &str) -> Result<()> {
        let first_index = self
            .processes
            .iter()
            .position(|slot| slot.label == first)
            .ok_or_else(|| HarnessError::Process(format!("missing process slot {first}")))?;
        let second_index = self
            .processes
            .iter()
            .position(|slot| slot.label == second)
            .ok_or_else(|| HarnessError::Process(format!("missing process slot {second}")))?;
        if first_index == second_index {
            bail!("readiness pair requires two distinct process slots");
        }
        let (low, high) = if first_index < second_index {
            (first_index, second_index)
        } else {
            (second_index, first_index)
        };
        let (head, tail) = self.processes.split_at_mut(high);
        let low_slot = &mut head[low];
        let high_slot = &mut tail[0];
        let server_ca_der = self.server_ca_der.as_slice();
        let (low_result, high_result) = tokio::join!(
            wait_for_ready(&mut low_slot.process, low_slot.consumer_bind, server_ca_der),
            wait_for_ready(
                &mut high_slot.process,
                high_slot.consumer_bind,
                server_ca_der
            ),
        );
        let mut errors = Vec::new();
        for (slot, result) in [(&*low_slot, low_result), (&*high_slot, high_result)] {
            if let Err(error) = result {
                errors.push(format!(
                    "{} readiness: {error}; {}",
                    slot.label,
                    process_diagnostic(&slot.process)
                ));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(HarnessError::Process(errors.join("; ")))
        }
    }

    async fn stop_slot(&mut self, label: &str) -> Result<()> {
        let index = self
            .processes
            .iter()
            .position(|slot| slot.label == label)
            .ok_or_else(|| HarnessError::Process(format!("missing process slot {label}")))?;
        let slot = self.processes.remove(index);
        self.diagnostics
            .push((slot.label.to_owned(), process_diagnostic(&slot.process)));
        stop_relay(
            slot.process,
            slot.consumer_bind,
            slot.device_bind,
            slot.peer_bind,
            slot.label,
        )
        .await
    }

    fn slot_diagnostic(&self, label: &str) -> Result<String> {
        self.processes
            .iter()
            .find(|slot| slot.label == label)
            .map(|slot| process_diagnostic(&slot.process))
            .ok_or_else(|| HarnessError::Process(format!("missing process slot {label}")))
    }

    async fn exercise(&mut self, deadline: Instant) -> Result<SpkiReplacementEvidence> {
        // Phase 0: both relays reach readiness, the device attaches to B and
        // a public canary through A reaches it over the old certificate.
        let b_old_pid = self
            .spawn_slot(
                &self.b_old_config.clone(),
                self.b_consumer_bind,
                self.b_device_bind,
                self.b_peer_bind,
                "relay-b-old",
            )
            .await?;
        let a_pid = self
            .spawn_slot(
                &self.a_config.clone(),
                self.a_consumer_bind,
                self.a_device_bind,
                self.a_peer_bind,
                "relay-a",
            )
            .await?;
        self.wait_for_pair_ready("relay-a", "relay-b-old").await?;
        self.wait_for_a_readiness(true, "initial", deadline).await?;
        let device_generation_before_overlap = self.connect_device("initial").await?;
        let initial_owner = self.owner(deadline).await?;
        self.echo_via_a("spki-initial").await?;

        // Phase 1: before any signed record names the replacement key, A
        // rejects it at the pin boundary while the approved old key passes.
        let new_cert_before_record = self.probe_a(&self.replacement_credential).await?;
        let old_cert_before_record = self
            .wait_for_probe(&self.old_credential, true, "pre-overlap", deadline)
            .await?;
        let checkpoint_requests_before_overlap = self.checkpoint_requests();

        // Phase 2: the overlap record (old + replacement) is adopted without
        // restarting A; readiness is sampled continuously meanwhile.
        let sampler = ReadinessSampler::start(self.a_consumer_bind, self.server_ca_der.clone());
        let record_b_overlap =
            self.sign_b(2, vec![self.old_key.clone(), self.replacement_key.clone()])?;
        publish_membership(
            &self.upstream_url,
            &self.namespace,
            "relay-b",
            &record_b_overlap,
        )
        .await?;
        let new_cert_during_overlap = self
            .wait_for_probe(&self.replacement_credential, true, "overlap", deadline)
            .await?;
        let old_cert_during_overlap = self.probe_a(&self.old_credential).await?;
        let checkpoint_requests_after_overlap = self.checkpoint_requests();
        let overlap_owner = self.owner(deadline).await?;
        self.echo_via_a("spki-overlap").await?;
        let device_generation_after_overlap = self.device_generation()?;
        let (overlap_readiness_samples, overlap_readiness_unready_samples) = sampler.stop().await?;

        // Phase 3: end the overlap with the replacement-only record while the
        // original relay B process is still serving its now-retired
        // certificate and still owns the live device session.  The retired
        // certificate must stop being accepted and the public route across it
        // must fail closed before any body is dispatched.
        let record_b_replacement = self.sign_b(3, vec![self.replacement_key.clone()])?;
        publish_membership(
            &self.upstream_url,
            &self.namespace,
            "relay-b",
            &record_b_replacement,
        )
        .await?;
        let stale_record_publish_refused = matches!(
            try_publish_membership(
                &self.upstream_url,
                &self.namespace,
                "relay-b",
                &record_b_overlap
            )
            .await,
            Err(CatalogError::Conflict(_))
        );
        // The listener and the outbound pool share one dynamic pin snapshot,
        // so a listener rejection is the exact instant after which A must
        // also refuse to use the retired certificate as a client.
        let old_cert_after_overlap = self
            .wait_for_probe(&self.old_credential, false, "post-overlap", deadline)
            .await?;
        let new_cert_after_overlap = self
            .wait_for_probe(&self.replacement_credential, true, "post-overlap", deadline)
            .await?;
        // A's readiness reflects the pin transition itself: the route to the
        // still-running relay B is withdrawn because its certificate is no
        // longer approved, not because the process died.
        self.wait_for_a_readiness(false, "pin retired", deadline)
            .await?;
        let a_unready_after_pin_retired = true;
        // The retired relay must surrender the device it owns rather than keep
        // serving behind a key the signed record no longer approves.
        let retired_owner_released = self.wait_for_owner_released(deadline).await?;
        let retired_relay_closed_device_session = self.stop_closed_device("overlap").await?;
        self.stop_slot("relay-b-old").await?;
        self.wait_for_a_readiness(false, "relay-b-old stopped", deadline)
            .await?;
        let a_unready_after_b_old_stopped = true;

        // Phase 4: an impostor presenting the retired certificate at B's
        // endpoint.  A dials it for its readiness probe, fails the pin check
        // and never opens a request stream.
        let a_probe_failures_before = count_probe_failures(&self.slot_diagnostic("relay-a")?);
        let impostor = ImpostorServer::start(
            self.b_peer_bind,
            &self.old_credential,
            &self.peer_ca_pem,
            self.a_spki,
        )?;
        let impostor_end = (Instant::now() + IMPOSTOR_DEADLINE).min(deadline);
        loop {
            let snapshot = impostor.snapshot();
            if snapshot.connections_from_relay_a >= 1
                && snapshot.closes_without_stream >= snapshot.connections_from_relay_a
                && count_probe_failures(&self.slot_diagnostic("relay-a")?) > a_probe_failures_before
            {
                break;
            }
            if Instant::now() >= impostor_end {
                let _ = impostor.stop().await;
                bail!(
                    "relay A did not dial and reject the retired-certificate endpoint before the bounded deadline: {snapshot:?}"
                );
            }
            sleep(POLL_INTERVAL).await;
        }
        // With the impostor presenting the retired certificate at relay B's
        // endpoint, a public consumer request must fail closed before any body
        // is dispatched, and the impostor must not receive a request stream
        // for it.
        let streams_before_request = impostor.snapshot().streams_opened;
        let retired_route = self.retired_route_outcome().await?;
        let impostor_evidence = impostor.stop().await?;
        if impostor_evidence.streams_opened != streams_before_request {
            bail!(
                "the public request opened a stream toward the retired certificate: {impostor_evidence:?}"
            );
        }
        let a_probe_failure_diagnostic =
            count_probe_failures(&self.slot_diagnostic("relay-a")?) > a_probe_failures_before;
        wait_for_ports_released(self.b_consumer_bind, self.b_device_bind, self.b_peer_bind).await?;

        // Phase 5: the replacement process with the new certificate takes
        // over B's endpoint; A recovers readiness, the device re-attaches and
        // a public canary crosses the replaced route with exact identities.
        //
        // The replacement process restores relay B's persisted version fence,
        // which already records every record version the retired process
        // accepted.  Re-reading any of those versions would be a typed
        // equal-version conflict by design, so the replacement boot is given
        // fresh higher signed records for both nodes.
        let record_b_boot = self.sign_b(4, vec![self.replacement_key.clone()])?;
        publish_membership(
            &self.upstream_url,
            &self.namespace,
            "relay-b",
            &record_b_boot,
        )
        .await?;
        let b_new_pid = self
            .start_slot(
                &self.b_new_config.clone(),
                self.b_consumer_bind,
                self.b_device_bind,
                self.b_peer_bind,
                "relay-b-replacement",
            )
            .await?;
        self.wait_for_a_readiness(true, "replacement", deadline)
            .await?;
        let a_ready_after_replacement = true;
        // Relay A now uses the replacement certificate for this route without
        // ever having restarted: its readiness recovered only because the
        // authenticated probe to the replacement process passed the new pin.
        // The replacement process's own public admission is deliberately not
        // exercised here; see the readiness-convergence limitation recorded in
        // docs/testing.md.

        // Phase 6: a record signed by an untrusted key names a rogue SPKI.
        // Both relays fail closed; the rogue pin never enters A's trust set.
        let unsigned_record = sign_record(
            &self.rogue_signer,
            &self.deployment_id,
            &self.deployment_incarnation,
            &self.node_b,
            5,
            vec![fresh_key(&self.replacement_key), fresh_key(&self.rogue_key)],
        )?;
        publish_membership(
            &self.upstream_url,
            &self.namespace,
            "relay-b",
            &unsigned_record,
        )
        .await?;
        self.wait_for_a_readiness(false, "unsigned record", deadline)
            .await?;
        let a_unready_under_unsigned_record = true;
        let rogue_cert_under_unsigned_record = self
            .wait_for_probe(&self.rogue_credential, false, "unsigned record", deadline)
            .await?;
        let new_cert_under_unsigned_record = self
            .wait_for_probe(
                &self.replacement_credential,
                false,
                "unsigned record",
                deadline,
            )
            .await?;

        // Phase 7: a trusted record restores the replacement-only key set.
        let record_b_recovery = self.sign_b(6, vec![self.replacement_key.clone()])?;
        publish_membership(
            &self.upstream_url,
            &self.namespace,
            "relay-b",
            &record_b_recovery,
        )
        .await?;
        self.wait_for_a_readiness(true, "recovery", deadline)
            .await?;
        let a_ready_after_recovery = true;
        let new_cert_after_recovery = self
            .wait_for_probe(&self.replacement_credential, true, "recovery", deadline)
            .await?;
        let rogue_cert_after_recovery = self.probe_a(&self.rogue_credential).await?;
        let old_cert_after_recovery = self.probe_a(&self.old_credential).await?;

        let mut diagnostic_failures = Vec::new();
        for (label, diagnostic) in self.diagnostics.iter().cloned().chain(
            self.processes
                .iter()
                .map(|slot| (slot.label.to_owned(), process_diagnostic(&slot.process))),
        ) {
            if let Err(error) = ensure_safe_diagnostic(&diagnostic, &label) {
                diagnostic_failures.push(error.to_string());
            }
        }
        let diagnostics_payload_free = diagnostic_failures.is_empty();
        if !diagnostics_payload_free {
            bail!(
                "configured relay diagnostics were not payload-free: {}",
                diagnostic_failures.join("; ")
            );
        }

        Ok(SpkiReplacementEvidence {
            a_pid,
            b_old_pid,
            b_new_pid,
            old_spki_sha256: self.old_key.spki_sha256.clone(),
            replacement_spki_sha256: self.replacement_key.spki_sha256.clone(),
            rogue_spki_sha256: self.rogue_key.spki_sha256.clone(),
            initial_owner,
            overlap_owner,
            device_generation_before_overlap,
            device_generation_after_overlap,
            checkpoint_requests_before_overlap,
            checkpoint_requests_after_overlap,
            new_cert_before_record,
            old_cert_before_record,
            new_cert_during_overlap,
            old_cert_during_overlap,
            overlap_readiness_samples,
            overlap_readiness_unready_samples,
            a_unready_after_b_old_stopped,
            stale_record_publish_refused,
            old_cert_after_overlap,
            new_cert_after_overlap,
            a_unready_after_pin_retired,
            retired_owner_released,
            retired_relay_closed_device_session,
            retired_route,
            impostor: impostor_evidence,
            a_probe_failure_diagnostic,
            a_ready_after_replacement,
            a_unready_under_unsigned_record,
            rogue_cert_under_unsigned_record,
            new_cert_under_unsigned_record,
            a_ready_after_recovery,
            rogue_cert_after_recovery,
            old_cert_after_recovery,
            new_cert_after_recovery,
            diagnostics_payload_free,
            cleanup_joined: false,
        })
    }

    async fn cleanup(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        if let Some(client) = self.client.take()
            && let Err(error) = client.stop().await
        {
            errors.push(format!("stopping device: {error}"));
        }
        while let Some(slot) = self.processes.pop() {
            let diagnostic = process_diagnostic(&slot.process);
            if let Err(error) = ensure_safe_diagnostic(&diagnostic, slot.label) {
                errors.push(error.to_string());
            }
            if let Err(error) = stop_relay(
                slot.process,
                slot.consumer_bind,
                slot.device_bind,
                slot.peer_bind,
                slot.label,
            )
            .await
            {
                errors.push(error.to_string());
            }
        }
        if let Some(checkpoint) = self.checkpoint.take()
            && let Err(error) = checkpoint.shutdown().await
        {
            errors.push(error.to_string());
        }
        if let Some(catalog) = self.catalog.take()
            && let Err(error) = catalog.cleanup_fixture_namespace().await
        {
            errors.push(format!("catalog cleanup: {error}"));
        }
        for redis in std::mem::take(&mut self.redis_proxies) {
            // Every forwarder must have completed at least one relay TLS
            // handshake: an unused forwarder would mean a relay never used
            // its configured `rediss://` authority.
            if let Err(error) = redis.shutdown().await {
                errors.push(error.to_string());
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(HarnessError::Process(errors.join("; ")))
        }
    }
}

// ---------------------------------------------------------------------------
// Harness peer client: present one certificate to relay A's private listener
// ---------------------------------------------------------------------------

async fn probe_relay_peer(
    relay_peer_bind: SocketAddr,
    credential: &PeerCredential,
    peer_ca_pem: &str,
    relay_spki: SpkiSha256,
    deadline: Duration,
) -> Result<PeerProbeOutcome> {
    let client_config = load_peer_client_config_from_pem(
        credential.chain_pem.as_bytes(),
        credential.key_pem.as_bytes(),
        peer_ca_pem.as_bytes(),
    )
    .map_err(|error| HarnessError::Pki(format!("{} peer client TLS: {error}", credential.label)))?;
    let mut endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    endpoint.set_default_client_config(client_config);
    let pins = ApprovedPeerPins::new([relay_spki])
        .map_err(|error| HarnessError::Pki(format!("relay pin set: {error}")))?;
    let client = PeerClient::new(endpoint.clone(), pins, PeerTransportLimits::default())
        .map_err(|error| HarnessError::Process(format!("peer client: {error}")))?;
    let outcome = timeout(deadline, async {
        let connection = match client
            .connect(PeerDestination::new(relay_peer_bind, "localhost"))
            .await
        {
            Ok(connection) => connection,
            Err(error) => {
                return Ok::<_, HarnessError>(PeerProbeOutcome::Rejected(classify(&error)));
            }
        };
        let request = Request::builder()
            .method("GET")
            .uri("https://localhost/internal/v1/health")
            .body(())
            .map_err(|error| HarnessError::Http(format!("peer health request: {error}")))?;
        let mut stream = match connection.open(request).await {
            Ok(stream) => stream,
            Err(error) => return Ok(PeerProbeOutcome::Rejected(classify(&error))),
        };
        if let Err(error) = stream.finish().await {
            return Ok(PeerProbeOutcome::Rejected(classify(&error)));
        }
        match stream.recv_response().await {
            Ok(response) if response.status().is_success() => Ok(PeerProbeOutcome::Accepted),
            Ok(response) => Ok(PeerProbeOutcome::Rejected(format!(
                "status_{}",
                response.status().as_u16()
            ))),
            Err(error) => Ok(PeerProbeOutcome::Rejected(classify(&error))),
        }
    })
    .await
    .unwrap_or(Ok(PeerProbeOutcome::Rejected("timeout".to_owned())))?;
    client
        .shutdown()
        .await
        .map_err(|error| HarnessError::Process(format!("peer client shutdown: {error}")))?;
    endpoint.close(quinn::VarInt::from_u32(0), b"probe done");
    timeout(Duration::from_secs(2), endpoint.wait_idle())
        .await
        .map_err(|_| HarnessError::Timeout("peer probe endpoint drain".into()))?;
    Ok(outcome)
}

/// Bounded, payload-free classification of a transport error.
fn classify(error: &tunnel_transport::PeerTransportError) -> String {
    use tunnel_transport::PeerTransportError as E;
    match error {
        E::Authentication(_) => "authentication".to_owned(),
        E::Quic(_) => "quic_closed".to_owned(),
        E::H3(_) => "h3_closed".to_owned(),
        E::Timeout => "timeout".to_owned(),
        E::GoAway => "goaway".to_owned(),
        E::Capacity => "capacity".to_owned(),
        E::PolicyRejected => "policy".to_owned(),
        E::Cancelled => "cancelled".to_owned(),
        _ => "transport".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Impostor: a QUIC server at B's endpoint presenting the retired certificate
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ImpostorCounters {
    connections: AtomicUsize,
    connections_from_relay_a: AtomicUsize,
    streams_opened: AtomicUsize,
    closes_without_stream: AtomicUsize,
}

struct ImpostorServer {
    endpoint: quinn::Endpoint,
    counters: Arc<ImpostorCounters>,
    cancellation: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
    connections: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl ImpostorServer {
    fn start(
        bind: SocketAddr,
        credential: &PeerCredential,
        peer_ca_pem: &str,
        relay_a_spki: SpkiSha256,
    ) -> Result<Self> {
        let server_config = load_peer_server_config_from_pem(
            credential.chain_pem.as_bytes(),
            credential.key_pem.as_bytes(),
            peer_ca_pem.as_bytes(),
        )
        .map_err(|error| HarnessError::Pki(format!("impostor server TLS: {error}")))?;
        let endpoint = quinn::Endpoint::server(server_config, bind)?;
        let counters = Arc::new(ImpostorCounters::default());
        let cancellation = CancellationToken::new();
        let connections = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn(run_impostor(
            endpoint.clone(),
            counters.clone(),
            cancellation.clone(),
            relay_a_spki,
            connections.clone(),
        ));
        Ok(Self {
            endpoint,
            counters,
            cancellation,
            task: Some(task),
            connections,
        })
    }

    fn snapshot(&self) -> ImpostorEvidence {
        ImpostorEvidence {
            connections: self.counters.connections.load(Ordering::Acquire),
            connections_from_relay_a: self
                .counters
                .connections_from_relay_a
                .load(Ordering::Acquire),
            streams_opened: self.counters.streams_opened.load(Ordering::Acquire),
            closes_without_stream: self.counters.closes_without_stream.load(Ordering::Acquire),
        }
    }

    async fn stop(mut self) -> Result<ImpostorEvidence> {
        self.cancellation.cancel();
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"impostor stopped");
        if let Some(task) = self.task.take() {
            timeout(Duration::from_secs(3), task)
                .await
                .map_err(|_| HarnessError::Timeout("impostor supervisor join".into()))?
                .map_err(|error| HarnessError::Process(format!("impostor supervisor: {error}")))?;
        }
        let handles = std::mem::take(
            &mut *self
                .connections
                .lock()
                .map_err(|_| HarnessError::Process("impostor connection list poisoned".into()))?,
        );
        for handle in handles {
            timeout(Duration::from_secs(3), handle)
                .await
                .map_err(|_| HarnessError::Timeout("impostor connection join".into()))?
                .map_err(|error| HarnessError::Process(format!("impostor connection: {error}")))?;
        }
        timeout(Duration::from_secs(3), self.endpoint.wait_idle())
            .await
            .map_err(|_| HarnessError::Timeout("impostor endpoint drain".into()))?;
        Ok(self.snapshot())
    }
}

impl Drop for ImpostorServer {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"impostor dropped");
    }
}

async fn run_impostor(
    endpoint: quinn::Endpoint,
    counters: Arc<ImpostorCounters>,
    cancellation: CancellationToken,
    relay_a_spki: SpkiSha256,
    connections: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
) {
    loop {
        let incoming = tokio::select! {
            _ = cancellation.cancelled() => return,
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                None => return,
            },
        };
        let counters = counters.clone();
        let cancellation = cancellation.clone();
        let handle = tokio::spawn(async move {
            let connection = tokio::select! {
                _ = cancellation.cancelled() => return,
                connected = timeout(Duration::from_secs(5), incoming) => match connected {
                    Ok(Ok(connection)) => connection,
                    _ => return,
                },
            };
            counters.connections.fetch_add(1, Ordering::AcqRel);
            let from_relay_a = connection
                .peer_identity()
                .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
                .and_then(|chain| chain.first().cloned())
                .and_then(|leaf| spki_sha256_from_der(leaf.as_ref()).ok())
                .is_some_and(|spki| spki == relay_a_spki);
            if from_relay_a {
                counters
                    .connections_from_relay_a
                    .fetch_add(1, Ordering::AcqRel);
            }
            // A pin-rejecting dialer closes without ever opening a stream.
            tokio::select! {
                _ = cancellation.cancelled() => {}
                stream = connection.accept_bi() => {
                    if stream.is_ok() {
                        counters.streams_opened.fetch_add(1, Ordering::AcqRel);
                    } else {
                        counters.closes_without_stream.fetch_add(1, Ordering::AcqRel);
                    }
                }
                _ = connection.closed() => {
                    counters.closes_without_stream.fetch_add(1, Ordering::AcqRel);
                }
            }
        });
        if let Ok(mut connections) = connections.lock() {
            connections.push(handle);
        }
    }
}

// ---------------------------------------------------------------------------
// Readiness sampler
// ---------------------------------------------------------------------------

struct ReadinessSampler {
    cancellation: CancellationToken,
    task: tokio::task::JoinHandle<(usize, usize)>,
}

impl ReadinessSampler {
    fn start(consumer_bind: SocketAddr, server_ca_der: Vec<u8>) -> Self {
        let cancellation = CancellationToken::new();
        let sampler_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            let mut samples = 0_usize;
            let mut unready = 0_usize;
            loop {
                if sampler_cancellation.is_cancelled() {
                    return (samples, unready);
                }
                let ready = matches!(
                    health_request(consumer_bind, &server_ca_der, "/readyz").await,
                    Ok((200, _))
                );
                samples += 1;
                if !ready {
                    unready += 1;
                }
                tokio::select! {
                    _ = sampler_cancellation.cancelled() => return (samples, unready),
                    _ = sleep(POLL_INTERVAL) => {}
                }
            }
        });
        Self { cancellation, task }
    }

    async fn stop(self) -> Result<(usize, usize)> {
        self.cancellation.cancel();
        timeout(Duration::from_secs(3), self.task)
            .await
            .map_err(|_| HarnessError::Timeout("readiness sampler join".into()))?
            .map_err(|error| HarnessError::Process(format!("readiness sampler: {error}")))
    }
}

// ---------------------------------------------------------------------------
// Catalog and process helpers
// ---------------------------------------------------------------------------

fn count_probe_failures(diagnostic: &str) -> usize {
    diagnostic
        .matches("authenticated peer readiness probe failed")
        .count()
}

fn ensure_safe_diagnostic(diagnostic: &str, label: &str) -> Result<()> {
    let lower = diagnostic.to_ascii_lowercase();
    if lower.contains("private_key") || lower.contains("-----begin") {
        return Err(HarnessError::Process(format!(
            "{label} diagnostic contained credential material"
        )));
    }
    if diagnostic.contains(CANARY)
        || diagnostic.contains(std::str::from_utf8(PAYLOAD).unwrap_or(""))
    {
        return Err(HarnessError::Process(format!(
            "{label} diagnostic contained application payload"
        )));
    }
    Ok(())
}

async fn try_publish_membership(
    upstream_url: &str,
    namespace: &str,
    node_id: &str,
    record: &SignedMembershipRecord,
) -> std::result::Result<(), CatalogError> {
    let publisher = RedisMembershipPublisher::connect(upstream_url, namespace).await?;
    publisher
        .publish_signed_membership_for_node(node_id, record)
        .await
}

async fn publish_membership(
    upstream_url: &str,
    namespace: &str,
    node_id: &str,
    record: &SignedMembershipRecord,
) -> Result<()> {
    try_publish_membership(upstream_url, namespace, node_id, record)
        .await
        .map_err(|error| {
            HarnessError::Redis(format!(
                "publishing {node_id} record v{}: {error}",
                record.version
            ))
        })
}

async fn wait_for_owner(
    catalog: &RedisCatalog,
    tenant_id: Uuid,
    device_id: Uuid,
    expected_node: &str,
    expected_incarnation: &str,
    deadline: Instant,
) -> Result<OwnerEvidence> {
    loop {
        if let Some(claim) = catalog
            .current_owner(tenant_id, device_id, Utc::now())
            .await
            .map_err(|error| HarnessError::Redis(format!("reading owner: {error}")))?
            && claim.token.node_id == expected_node
            && claim.token.deployment_incarnation == expected_incarnation
        {
            return Ok(OwnerEvidence {
                node_id: claim.token.node_id,
                boot_id: claim.token.boot_id,
                deployment_incarnation: claim.token.deployment_incarnation,
                tenant_id: claim.token.tenant_id,
                device_id: claim.token.device_id,
                session_id: claim.token.session_id,
                epoch: claim.token.epoch,
            });
        }
        if Instant::now() >= deadline {
            bail!("owner did not converge to {expected_node} before the bounded deadline");
        }
        sleep(Duration::from_millis(100)).await;
    }
}

fn distinct_tcp_addr(others: &[SocketAddr]) -> SocketAddr {
    loop {
        let address = free_tcp_addr();
        if !others.contains(&address) {
            return address;
        }
    }
}

/// Allow both configured peer ports and shorten the membership refresh so
/// each signed transition is adopted within a bounded wait.  Production
/// defaults are untouched.
fn with_fast_refresh(base: &str, ports: &[u16]) -> String {
    let ports = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    base.lines()
        .map(|line| {
            if line.trim_start().starts_with("allowed_ports =") {
                format!("allowed_ports = [{ports}]")
            } else if line
                .trim_start()
                .starts_with("membership_refresh_seconds =")
            {
                "membership_refresh_seconds = 2".to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

async fn initialize_state(binary: &Path, config: &Path) -> Result<()> {
    let mut process = ManagedProcess::spawn(
        "m7-spki-replacement-initialize",
        ProcessSpec::new(binary)
            .arg("initialize")
            .arg("--config")
            .arg(config.display().to_string()),
    )
    .await?;
    let status = match wait_for_exit(&mut process, CLI_DEADLINE).await {
        Ok(status) => status,
        Err(error) => {
            let diagnostic = process_diagnostic(&process);
            let shutdown = process.shutdown(Duration::from_millis(100)).await;
            return Err(HarnessError::Process(format!(
                "configured process initialize deadline: {error}; {diagnostic}; shutdown={shutdown:?}"
            )));
        }
    };
    let diagnostic = process_diagnostic(&process);
    let _ = process.shutdown(Duration::from_millis(100)).await?;
    if !status.success() {
        return Err(HarnessError::Process(format!(
            "configured process initialize exited {status}; {diagnostic}"
        )));
    }
    Ok(())
}

async fn start_relay(
    binary: &Path,
    config: &Path,
    consumer_bind: SocketAddr,
    device_bind: SocketAddr,
    peer_bind: SocketAddr,
    server_ca_der: &[u8],
    name: &str,
) -> Result<ManagedProcess> {
    let mut process = ManagedProcess::spawn(
        name,
        ProcessSpec::new(binary)
            .arg("serve")
            .arg("--config")
            .arg(config.display().to_string()),
    )
    .await?;
    if let Err(error) = wait_for_ready(&mut process, consumer_bind, server_ca_der).await {
        let diagnostic = process_diagnostic(&process);
        let shutdown = process.shutdown(Duration::from_millis(100)).await;
        let ports = wait_for_ports_released(consumer_bind, device_bind, peer_bind).await;
        return Err(HarnessError::Process(format!(
            "{name} configured process readiness: {error}; {diagnostic}; shutdown={shutdown:?}; ports={ports:?}"
        )));
    }
    if process.id().is_none() {
        let diagnostic = process_diagnostic(&process);
        let shutdown = process.shutdown(Duration::from_millis(100)).await;
        let ports = wait_for_ports_released(consumer_bind, device_bind, peer_bind).await;
        return Err(HarnessError::Process(format!(
            "{name} configured process exited after readiness: {diagnostic}; shutdown={shutdown:?}; ports={ports:?}"
        )));
    }
    Ok(process)
}

async fn stop_relay(
    mut process: ManagedProcess,
    consumer_bind: SocketAddr,
    device_bind: SocketAddr,
    peer_bind: SocketAddr,
    label: &str,
) -> Result<()> {
    // A relay that already failed closed has no PID left to signal.  Join it
    // and still require its listeners to be released.
    if process.try_wait()?.is_some() {
        let joined = process.shutdown(Duration::from_millis(100)).await;
        let ports = wait_for_ports_released(consumer_bind, device_bind, peer_bind).await;
        joined?;
        ports?;
        return Ok(());
    }
    let pid = process
        .id()
        .ok_or_else(|| HarnessError::Process(format!("{label} lost its process ID")))?;
    if let Err(signal_error) = send_sigint(pid) {
        let shutdown = process.shutdown(Duration::from_millis(100)).await;
        let ports = wait_for_ports_released(consumer_bind, device_bind, peer_bind).await;
        return Err(HarnessError::Process(format!(
            "{label} SIGINT failed: {signal_error}; forced_shutdown={shutdown:?}; ports={ports:?}"
        )));
    }
    let status = match wait_for_exit(&mut process, SHUTDOWN_DEADLINE).await {
        Ok(status) => status,
        Err(wait_error) => {
            let diagnostic = process_diagnostic(&process);
            let shutdown = process.shutdown(Duration::from_millis(100)).await;
            let ports = wait_for_ports_released(consumer_bind, device_bind, peer_bind).await;
            return Err(HarnessError::Process(format!(
                "{label} SIGINT wait failed: {wait_error}; {diagnostic}; forced_shutdown={shutdown:?}; ports={ports:?}"
            )));
        }
    };
    let diagnostic = process_diagnostic(&process);
    if !status.success() {
        let shutdown = process.shutdown(Duration::from_millis(100)).await;
        let ports = wait_for_ports_released(consumer_bind, device_bind, peer_bind).await;
        return Err(HarnessError::Process(format!(
            "{label} exited {status} during graceful shutdown; {diagnostic}; shutdown={shutdown:?}; ports={ports:?}"
        )));
    }
    let joined = process.shutdown(Duration::from_millis(100)).await;
    let ports = wait_for_ports_released(consumer_bind, device_bind, peer_bind).await;
    joined?;
    ports?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_client_config(
    files: &FixtureFiles,
    name: &str,
    device_id: Uuid,
    service_id: Uuid,
    device_bind: SocketAddr,
    certificate_pem: &str,
    private_key_pem: &str,
    device_ca_pem: &str,
    server_ca_pem: &str,
) -> Result<ConnectConfig> {
    let certificate_path = files.write(
        &format!("{name}-device-cert.pem"),
        format!("{certificate_pem}{device_ca_pem}").as_bytes(),
    )?;
    let key_path = files.write(
        &format!("{name}-device-key.pem"),
        private_key_pem.as_bytes(),
    )?;
    let server_ca_path = files.write(&format!("{name}-server-ca.pem"), server_ca_pem.as_bytes())?;
    let config = ConnectConfig {
        device_id: device_id.to_string(),
        relay_url: format!("wss://localhost:{}/v1/tunnel/control", device_bind.port()),
        credentials: CredentialConfig {
            client_certificate: certificate_path,
            client_key: key_path,
            server_ca: server_ca_path,
        },
        exports: BTreeMap::from([(
            service_id.to_string(),
            LocalExport {
                kind: LocalExportKind::Echo,
                device_canary: Some(CANARY.to_owned()),
                mcp: None,
                acp: None,
                fs: None,
            },
        )]),
        limits: LimitsConfig::default(),
        rotation: RotationConfig::default(),
    };
    config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("client config: {error}")))?;
    Ok(config)
}

async fn connect_fresh(config: &ConnectConfig) -> Result<tunnel_client::ConnectionHandle> {
    timeout(
        CONNECT_DEADLINE,
        connect(ConnectOptions::new(config.clone())),
    )
    .await
    .map_err(|_| HarnessError::Timeout("device connect deadline".into()))?
    .map_err(|error| HarnessError::Process(format!("device connect: {error}")))
}

// ---------------------------------------------------------------------------
// Public echo canary through relay A
// ---------------------------------------------------------------------------

const ECHO_CONNECTION_CLEANUP_DEADLINE: Duration = Duration::from_secs(2);

struct EchoConnectionGuard {
    task: Option<tokio::task::JoinHandle<()>>,
}

impl EchoConnectionGuard {
    async fn shutdown(mut self, phase: &str) -> Result<()> {
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        task.abort();
        match timeout(ECHO_CONNECTION_CLEANUP_DEADLINE, &mut task).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) if error.is_cancelled() => Ok(()),
            Ok(Err(error)) => Err(HarnessError::Http(format!(
                "{phase} echo connection task join failed: {error}"
            ))),
            Err(_) => Err(HarnessError::Timeout(format!(
                "{phase} echo connection cleanup deadline"
            ))),
        }
    }
}

impl Drop for EchoConnectionGuard {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

struct EchoProbe<'a> {
    consumer_bind: SocketAddr,
    server_ca_der: &'a [u8],
    token: &'a str,
    device_id: Uuid,
    service_id: Uuid,
    payload: &'a [u8],
    canary: &'a [u8],
    phase: &'a str,
}

/// The bounded public error envelope.  Only the typed fields are read.
#[derive(serde::Deserialize)]
struct WireError {
    code: String,
    execution: String,
}

/// Issue the public consumer request and require the exact canary response.
async fn echo_http(probe: EchoProbe<'_>) -> Result<()> {
    let phase = probe.phase.to_owned();
    let canary = probe.canary.to_vec();
    let payload = probe.payload.to_vec();
    let (status, body) = post_echo(probe).await?;
    if status != 200 {
        return Err(HarnessError::Http(format!(
            "{phase} echo returned HTTP {status}: body_len={} body_sha256={}",
            body.len(),
            digest_hex(&body),
        )));
    }
    expect_canary_body(&phase, &body, &canary, &payload)
}

/// The public HTTP adapter strips the internal tunnel record framing, so the
/// configured non-streaming echo export returns the device canary followed by
/// the exact request payload.
fn expect_canary_body(phase: &str, body: &[u8], canary: &[u8], payload: &[u8]) -> Result<()> {
    let mut expected = Vec::with_capacity(canary.len().saturating_add(payload.len()));
    expected.extend_from_slice(canary);
    expected.extend_from_slice(payload);
    if body != expected.as_slice() {
        return Err(HarnessError::Http(format!(
            "{phase} echo canary response mismatch: actual_len={} expected_len={} canary_prefix={} actual_sha256={} expected_sha256={}",
            body.len(),
            expected.len(),
            body.starts_with(canary),
            digest_hex(body),
            digest_hex(&expected),
        )));
    }
    Ok(())
}

/// Issue the same public consumer request and return only its bounded typed
/// failure shape.  No payload or message text crosses this boundary.
async fn typed_failure_http(probe: EchoProbe<'_>) -> Result<(u16, String, String)> {
    let phase = probe.phase.to_owned();
    let (status, body) = post_echo(probe).await?;
    let parsed: WireError = serde_json::from_slice(&body).map_err(|error| {
        HarnessError::Http(format!(
            "{phase} typed failure body was not a bounded error envelope: {error}; body_len={}",
            body.len()
        ))
    })?;
    Ok((status, parsed.code, parsed.execution))
}

async fn post_echo(probe: EchoProbe<'_>) -> Result<(u16, Vec<u8>)> {
    let EchoProbe {
        consumer_bind,
        server_ca_der,
        token,
        device_id,
        service_id,
        payload,
        canary: _,
        phase,
    } = probe;
    let exchange_deadline = tokio::time::Instant::now() + EXCHANGE_DEADLINE;
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(server_ca_der.to_vec()))
        .map_err(|error| HarnessError::Http(format!("{phase} echo root: {error}")))?;
    let client_config =
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| HarnessError::Http(format!("{phase} echo TLS: {error}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let stream = timeout_at(
        exchange_deadline,
        tokio::net::TcpStream::connect(consumer_bind),
    )
    .await
    .map_err(|_| HarnessError::Timeout(format!("{phase} echo TCP connect")))?
    .map_err(|error| HarnessError::Http(format!("{phase} echo TCP connect: {error}")))?;
    let server_name = ServerName::try_from("localhost".to_owned())
        .map_err(|error| HarnessError::Http(format!("{phase} echo server name: {error}")))?;
    let tls = timeout_at(exchange_deadline, connector.connect(server_name, stream))
        .await
        .map_err(|_| HarnessError::Timeout(format!("{phase} echo TLS handshake")))?
        .map_err(|error| HarnessError::Http(format!("{phase} echo TLS handshake: {error}")))?;
    let (mut sender, connection) = timeout_at(
        exchange_deadline,
        hyper::client::conn::http1::handshake(TokioIo::new(tls)),
    )
    .await
    .map_err(|_| HarnessError::Timeout(format!("{phase} echo HTTP handshake")))?
    .map_err(|error| HarnessError::Http(format!("{phase} echo HTTP handshake: {error}")))?;
    let connection_guard = EchoConnectionGuard {
        task: Some(tokio::spawn(async move {
            let _ = connection.await;
        })),
    };
    let result: Result<(u16, Vec<u8>)> = async {
        let path = format!("/v1/devices/{device_id}/services/{service_id}/echo");
        let request = Request::builder()
            .method("POST")
            .uri(format!("https://localhost{path}"))
            .header("host", "localhost")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/octet-stream")
            .body(Full::new(Bytes::copy_from_slice(payload)))
            .map_err(|error| HarnessError::Http(format!("{phase} echo request: {error}")))?;
        let response = timeout_at(exchange_deadline, sender.send_request(request))
            .await
            .map_err(|_| HarnessError::Timeout(format!("{phase} echo request")))?
            .map_err(|error| HarnessError::Http(format!("{phase} echo response: {error}")))?;
        let status = response.status();
        let body = timeout_at(
            exchange_deadline,
            Limited::new(response.into_body(), 256 * 1024).collect(),
        )
        .await
        .map_err(|_| HarnessError::Timeout(format!("{phase} echo body")))?
        .map_err(|error| HarnessError::Http(format!("{phase} echo body: {error}")))?
        .to_bytes();
        Ok((status.as_u16(), body.to_vec()))
    }
    .await;
    let cleanup = connection_guard.shutdown(phase).await;
    match (result, cleanup) {
        (Ok(response), Ok(())) => Ok(response),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(HarnessError::Http(format!(
            "{phase} echo primary failure: {primary}; connection cleanup failure: {cleanup}"
        ))),
    }
}

fn digest_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_encode(digest.as_ref())
}
