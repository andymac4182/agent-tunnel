//! A serving `tunnel-relay serve` process genuinely re-keys its private
//! HTTP/3 peer identity without a restart (task rows M8-C45, M8-C46,
//! M7-C150).
//!
//! Relay A and relay B run as separate processes over a Redis TLS forwarder
//! and a live signed checkpoint authority, exactly as in
//! `m7_deployment_spki_replacement` -- except that relay B is **never
//! replaced**.  B's configuration names a successor certificate under
//! `cluster.peer_tls_next_*`; the operator trigger (`SIGHUP`) stages it; the
//! signed record approving both keys lets B switch new handshakes to it after
//! its convergence hold; and the replacement-only record retires the
//! predecessor.  Throughout, B keeps its process, its boot identity, its owner
//! claim and its device session, stays Ready, and a public canary entering A
//! is answered by the device attached to B.  Every assertion is local to this
//! source build; evidence is payload-free.

// The harness library is Unix-only (see `src/entry.rs`).
#![cfg(unix)]

use std::{
    collections::BTreeMap,
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
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
    load_peer_client_config_from_pem, load_server_config_from_pem, spki_sha256_from_der,
};
use uuid::Uuid;

#[path = "common/m7_deployment.rs"]
mod common;
use common::{
    CheckpointServer, FixtureFiles, ProcessConfigFixture, free_tcp_addr, health_request,
    hex_encode, jwks_json, parse_plaintext_upstream, process_diagnostic, relay_binary_path,
    send_sigint, wait_for_exit, wait_for_ports_released, wait_for_ready,
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
const TRANSITION_DEADLINE: Duration = Duration::from_secs(25);
const PEER_PROBE_DEADLINE: Duration = Duration::from_secs(4);
const POLL_INTERVAL: Duration = Duration::from_millis(150);
const RECORD_LIFETIME_SECONDS: i64 = 55;
/// B's convergence hold: the configuration floor, twice this fixture's 2 s
/// reconcile interval.
const CONVERGENCE_SECONDS: u64 = 4;
const DEPLOYMENT_ID_PREFIX: &str = "m8-relay-rekey-deployment";
const INCARNATION_PREFIX: &str = "m8-relay-rekey-incarnation";
const CANARY: &str = "m8-relay-rekey-canary";
const PAYLOAD: &[u8] = b"relay-rekey-request-body";

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires TEST_REDIS_URL; run explicitly as the live relay re-key process gate"]
async fn m8_serving_relay_rekeys_its_peer_identity_without_restart() {
    let deadline = Instant::now() + TEST_DEADLINE;
    let mut fixture = create_fixture().await.expect("relay re-key fixture");
    let result = fixture.exercise(deadline).await;
    let cleanup = fixture.cleanup().await;
    match (result, cleanup) {
        (Ok(evidence), Ok(())) => {
            println!("{}", evidence.evidence_line());
            evidence.validate().expect("relay re-key evidence");
        }
        (Err(primary), Ok(())) => panic!("relay re-key gate failed: {primary}"),
        (Ok(_), Err(cleanup)) => panic!("relay re-key cleanup failed: {cleanup}"),
        (Err(primary), Err(cleanup)) => {
            panic!("relay re-key gate failed: {primary}; cleanup failed: {cleanup}")
        }
    }
}

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

fn probe_code(outcome: &PeerProbeOutcome) -> String {
    match outcome {
        PeerProbeOutcome::Accepted => "accepted".to_owned(),
        PeerProbeOutcome::Rejected(code) => code.clone(),
    }
}

#[derive(Debug, Clone)]
struct RekeyEvidence {
    b_pid_initial: u32,
    b_pid_final: u32,
    old_spki: String,
    new_spki: String,
    initial_owner: OwnerEvidence,
    final_owner: OwnerEvidence,
    device_generation_initial: u64,
    device_generation_final: u64,
    old_presented_initially: PeerProbeOutcome,
    new_presented_initially: PeerProbeOutcome,
    mismatched_refused: bool,
    new_presented_after_refusal: PeerProbeOutcome,
    staged_logged: bool,
    new_presented_while_staged: PeerProbeOutcome,
    old_presented_while_staged: PeerProbeOutcome,
    new_presented_after_switch: PeerProbeOutcome,
    old_presented_after_switch: PeerProbeOutcome,
    switch_logged: bool,
    retired_logged: bool,
    new_presented_after_retirement: PeerProbeOutcome,
    old_presented_after_retirement: PeerProbeOutcome,
    canary_initial: bool,
    canary_during_overlap: bool,
    canary_after_retirement_attempts: usize,
    b_readiness_samples: usize,
    b_unready_samples: usize,
    a_readiness_samples: usize,
    a_unready_samples: usize,
    diagnostics_payload_free: bool,
}

impl RekeyEvidence {
    fn validate(&self) -> Result<()> {
        if self.b_pid_initial == 0 || self.b_pid_initial != self.b_pid_final {
            bail!("relay B was restarted or lost its PID: the rotation must not restart it");
        }
        if self.old_spki == self.new_spki {
            bail!("the successor did not change the SPKI");
        }
        if self.initial_owner != self.final_owner {
            bail!(
                "the owner claim changed across the rotation: a re-key must not be an owner loss"
            );
        }
        if self.device_generation_initial == 0
            || self.device_generation_initial != self.device_generation_final
        {
            bail!("the device session did not survive the rotation on its original generation");
        }
        if !self.old_presented_initially.accepted() || self.new_presented_initially.accepted() {
            bail!("relay B did not start by presenting only the configured certificate");
        }
        if !self.mismatched_refused || self.new_presented_after_refusal.accepted() {
            bail!("a SIGHUP with a mismatched successor key was not refused cleanly");
        }
        if !self.staged_logged {
            bail!("SIGHUP did not stage the configured successor");
        }
        if self.new_presented_while_staged.accepted() || !self.old_presented_while_staged.accepted()
        {
            bail!("relay B served a staged successor before any record approved it");
        }
        if !self.new_presented_after_switch.accepted() || self.old_presented_after_switch.accepted()
        {
            bail!("relay B did not switch new handshakes to the approved successor");
        }
        if !self.switch_logged || !self.retired_logged {
            bail!("relay B did not log its switch and the predecessor's retirement");
        }
        if !self.new_presented_after_retirement.accepted()
            || self.old_presented_after_retirement.accepted()
        {
            bail!("the retired predecessor was still presented, or the successor was not");
        }
        if !self.canary_initial || !self.canary_during_overlap {
            bail!("the public canary through A did not reach B's device during the rotation");
        }
        if self.canary_after_retirement_attempts == 0 {
            bail!("the public canary through A did not reach B's device after retirement");
        }
        if self.b_readiness_samples == 0 || self.b_unready_samples != 0 {
            bail!(
                "relay B did not stay Ready throughout its own rotation ({} of {} samples unready)",
                self.b_unready_samples,
                self.b_readiness_samples
            );
        }
        if !self.diagnostics_payload_free {
            bail!("relay diagnostics contained credential or payload material");
        }
        Ok(())
    }

    fn evidence_line(&self) -> String {
        format!(
            "m8-relay-rekey-process b_pid={}->{} old_spki={} new_spki={} owner_boot={} owner_epoch={} device_generation={}->{} initial(old={} new={}) mismatched_refused={} after_refusal(new={}) staged_logged={} staged(new={} old={}) switched(new={} old={}) switch_logged={} retired_logged={} retired(new={} old={}) canary(initial={} overlap={} after_retirement_attempts={}) b_ready_samples={} b_unready={} a_ready_samples={} a_unready={} payload_free={}",
            self.b_pid_initial,
            self.b_pid_final,
            self.old_spki,
            self.new_spki,
            self.initial_owner.boot_id,
            self.initial_owner.epoch,
            self.device_generation_initial,
            self.device_generation_final,
            probe_code(&self.old_presented_initially),
            probe_code(&self.new_presented_initially),
            self.mismatched_refused,
            probe_code(&self.new_presented_after_refusal),
            self.staged_logged,
            probe_code(&self.new_presented_while_staged),
            probe_code(&self.old_presented_while_staged),
            probe_code(&self.new_presented_after_switch),
            probe_code(&self.old_presented_after_switch),
            self.switch_logged,
            self.retired_logged,
            probe_code(&self.new_presented_after_retirement),
            probe_code(&self.old_presented_after_retirement),
            self.canary_initial,
            self.canary_during_overlap,
            self.canary_after_retirement_attempts,
            self.b_readiness_samples,
            self.b_unready_samples,
            self.a_readiness_samples,
            self.a_unready_samples,
            self.diagnostics_payload_free,
        )
    }
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
    redis_proxies: Vec<LongLivedRedisTlsProxy>,
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

struct RekeyFixture {
    _files: FixtureFiles,
    catalog: Option<RedisCatalog>,
    redis_proxies: Vec<LongLivedRedisTlsProxy>,
    checkpoint: Option<CheckpointServer>,
    relay_binary: PathBuf,
    upstream_url: String,
    namespace: String,
    deployment_id: String,
    deployment_incarnation: String,
    signer: Arc<TestMembershipAuthority>,
    node_a: RelayNodeFixture,
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
    a_credential: PeerCredential,
    a_key: FixturePeerKey,
    old_spki: SpkiSha256,
    new_spki: SpkiSha256,
    old_key: FixturePeerKey,
    new_key: FixturePeerKey,
    a_config: PathBuf,
    b_config: PathBuf,
    b_next_key_path: PathBuf,
    b_next_key_pem: String,
    client_config: ConnectConfig,
    processes: Vec<RelayProcessSlot>,
    client: Option<tunnel_client::ConnectionHandle>,
    next_a_version: u64,
}

async fn create_fixture() -> Result<RekeyFixture> {
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

fn key(key_id: &str, spki: SpkiSha256) -> FixturePeerKey {
    let mut key = FixturePeerKey {
        key_id: key_id.to_owned(),
        spki_sha256: spki.to_hex(),
        not_before: Utc::now(),
        expires_at: Utc::now(),
        revoked: false,
    };
    refresh_key(&mut key);
    key
}

async fn create_fixture_inner(
    files: FixtureFiles,
    partial: &mut PartialFixture,
) -> Result<RekeyFixture> {
    let relay_binary = relay_binary_path()?;
    let upstream_url = env::var("TEST_REDIS_URL").map_err(|_| HarnessError::MissingRedisUrl {
        env_var: "TEST_REDIS_URL",
        guidance: "the relay re-key process gate requires a disposable plaintext Redis upstream"
            .into(),
    })?;
    let upstream = parse_plaintext_upstream(&upstream_url)?;
    let run_id = Uuid::new_v4().simple().to_string();
    let deployment_id = format!("{DEPLOYMENT_ID_PREFIX}-{run_id}");
    let deployment_incarnation = format!("{INCARNATION_PREFIX}-{run_id}");
    let namespace = format!("m8-relay-rekey-fixture-{run_id}");
    let pki = FixturePki::new()?;
    let oidc = OidcFixture::new(
        format!("https://m8-relay-rekey-oidc-{run_id}.invalid"),
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
    let mut node_a = None;
    let mut node_b = None;
    for node in std::mem::take(&mut cluster.nodes) {
        match node.node_id.as_str() {
            "relay-a" => node_a = Some(node),
            "relay-b" => node_b = Some(node),
            _ => {}
        }
    }
    let node_a = node_a.ok_or_else(|| HarnessError::InvalidInput("missing relay-a".into()))?;
    let node_b = node_b.ok_or_else(|| HarnessError::InvalidInput("missing relay-b".into()))?;
    let signer = Arc::new(cluster.membership_authority);

    let a_spki = spki_sha256_from_der(&node_a.peer_certificate.certificate_der)
        .map_err(|error| HarnessError::Pki(format!("relay-a SPKI: {error}")))?;
    let old_spki = spki_sha256_from_der(&node_b.peer_certificate.certificate_der)
        .map_err(|error| HarnessError::Pki(format!("relay-b SPKI: {error}")))?;
    let successor = pki.issue_peer("relay-b")?;
    let new_spki = spki_sha256_from_der(&successor.certificate_der)
        .map_err(|error| HarnessError::Pki(format!("successor SPKI: {error}")))?;
    if old_spki == new_spki {
        bail!("fixture peer certificates did not produce distinct SPKI digests");
    }
    let a_key = key("relay-a-peer", a_spki);
    let old_key = key("relay-b-peer-0-old", old_spki);
    let new_key = key("relay-b-peer-1-new", new_spki);

    let server_leaf = pki.issue_server("m8-relay-rekey-relay")?;
    let checkpoint_leaf = pki.issue_server("m8-relay-rekey-checkpoint")?;
    let redis_leaf = pki.issue_server("m8-relay-rekey-redis")?;
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
    partial
        .redis_proxies
        .push(LongLivedRedisTlsProxy::bind(upstream, redis_tls.clone()).await?);
    partial
        .redis_proxies
        .push(LongLivedRedisTlsProxy::bind(upstream, redis_tls).await?);
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
        vec![fresh_key(&a_key)],
    )?;
    let record_b = sign_record(
        &signer,
        &deployment_id,
        &deployment_incarnation,
        &node_b,
        1,
        vec![fresh_key(&old_key)],
    )?;
    publish_membership(&upstream_url, &namespace, "relay-a", &record_a).await?;
    publish_membership(&upstream_url, &namespace, "relay-b", &record_b).await?;

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
    let a_credential = credential("relay-a", &node_a.peer_certificate, &pki);
    let peer_a_chain_path =
        files.write("relay-a-peer-chain.pem", a_credential.chain_pem.as_bytes())?;
    let peer_a_key_path = files.write("relay-a-peer-key.pem", a_credential.key_pem.as_bytes())?;
    let old_credential = credential("relay-b-old", &node_b.peer_certificate, &pki);
    let new_credential = credential("relay-b-next", &successor, &pki);
    let peer_b_chain_path = files.write(
        "relay-b-peer-chain.pem",
        old_credential.chain_pem.as_bytes(),
    )?;
    let peer_b_key_path = files.write("relay-b-peer-key.pem", old_credential.key_pem.as_bytes())?;
    let peer_b_next_chain_path = files.write(
        "relay-b-next-peer-chain.pem",
        new_credential.chain_pem.as_bytes(),
    )?;
    // The first SIGHUP meets a key that does not match the successor
    // certificate (relay-a's own key); the gate then writes the right one.
    let peer_b_next_key_path =
        files.write("relay-b-next-peer-key.pem", a_credential.key_pem.as_bytes())?;
    let b_next_key_pem = new_credential.key_pem.clone();
    let state_a = files.state_path()?;
    let state_b = state_a.with_file_name("relay-b-membership-state.json");
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
    // Relay B names its successor identity and a convergence hold at the
    // configuration floor.  Nothing reads the successor until `SIGHUP`.
    let b_rendered = render(
        b_consumer_bind,
        b_device_bind,
        b_peer_bind,
        &peer_b_chain_path,
        &peer_b_key_path,
        &state_b,
        "relay-b",
        &b_redis_url,
    );
    let rekey_lines = format!(
        "checkpoint_timeout_seconds = 2\npeer_tls_next_cert_chain = {}\npeer_tls_next_private_key = {}\npeer_rekey_convergence_seconds = {CONVERGENCE_SECONDS}\n",
        serde_json::to_string(&peer_b_next_chain_path.display().to_string())?,
        serde_json::to_string(&peer_b_next_key_path.display().to_string())?,
    );
    if !b_rendered.contains("checkpoint_timeout_seconds = 2\n") {
        bail!("the rendered relay-b configuration lost its cluster anchor line");
    }
    let b_config = files.write(
        "relay-b.toml",
        b_rendered
            .replacen("checkpoint_timeout_seconds = 2\n", &rekey_lines, 1)
            .as_bytes(),
    )?;
    initialize_state(&relay_binary, &a_config).await?;
    initialize_state(&relay_binary, &b_config).await?;
    let client_config = write_client_config(
        &files,
        "rekey-device",
        device.id,
        service_id,
        b_device_bind,
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &pki.device_ca.certificate_pem,
        &pki.server_ca.certificate_pem,
    )?;
    let client_token = oidc.issue(&consumer.name)?;
    Ok(RekeyFixture {
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
        node_a,
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
        a_credential,
        a_key,
        old_spki,
        new_spki,
        old_key,
        new_key,
        a_config,
        b_config,
        b_next_key_path: peer_b_next_key_path,
        b_next_key_pem,
        client_config,
        processes: Vec::new(),
        client: None,
        next_a_version: 2,
    })
}

impl RekeyFixture {
    async fn publish_b(&self, version: u64, keys: &[&FixturePeerKey]) -> Result<()> {
        let record = sign_record(
            &self.signer,
            &self.deployment_id,
            &self.deployment_incarnation,
            &self.node_b,
            version,
            keys.iter().map(|key| fresh_key(key)).collect(),
        )?;
        publish_membership(&self.upstream_url, &self.namespace, "relay-b", &record).await
    }

    /// Re-issue relay A's record so no phase rests on an aging record.
    async fn refresh_a(&mut self) -> Result<()> {
        let version = self.next_a_version;
        self.next_a_version += 1;
        let record = sign_record(
            &self.signer,
            &self.deployment_id,
            &self.deployment_incarnation,
            &self.node_a,
            version,
            vec![fresh_key(&self.a_key)],
        )?;
        publish_membership(&self.upstream_url, &self.namespace, "relay-a", &record).await
    }

    /// Wait until the checkpoint authority has served `passes` more
    /// reconciliation requests than it had when called.
    async fn wait_reconciles(&self, passes: usize, deadline: Instant) -> Result<()> {
        let count = || {
            self.checkpoint
                .as_ref()
                .map(CheckpointServer::request_count)
                .unwrap_or(0)
        };
        let start = count();
        let end = (Instant::now() + TRANSITION_DEADLINE).min(deadline);
        while count() < start + passes {
            if Instant::now() >= end {
                bail!(
                    "the relays did not reconcile {passes} more times before the bounded deadline"
                );
            }
            sleep(POLL_INTERVAL).await;
        }
        Ok(())
    }

    fn catalog(&self) -> Result<&RedisCatalog> {
        self.catalog
            .as_ref()
            .ok_or_else(|| HarnessError::Redis("fixture catalog missing".into()))
    }

    /// Dial relay B's private listener afresh as relay A, approving only
    /// `pin`: accepted exactly when B's new handshake presents it.
    async fn b_presents(&self, pin: SpkiSha256) -> Result<PeerProbeOutcome> {
        probe_relay_peer(
            self.b_peer_bind,
            &self.a_credential,
            &self.peer_ca_pem,
            pin,
            PEER_PROBE_DEADLINE,
        )
        .await
    }

    async fn wait_b_presents(&self, pin: SpkiSha256, phase: &str, deadline: Instant) -> Result<()> {
        let end = (Instant::now() + TRANSITION_DEADLINE).min(deadline);
        loop {
            let outcome = self.b_presents(pin).await?;
            if outcome.accepted() {
                return Ok(());
            }
            if Instant::now() >= end {
                bail!(
                    "{phase}: relay B did not present the expected identity before the bounded deadline (last={}); {}",
                    probe_code(&outcome),
                    self.slot_diagnostic("relay-b")?
                );
            }
            sleep(POLL_INTERVAL).await;
        }
    }

    /// The warnings and rotation lines a relay logged, last twenty, for a
    /// failure message.  Payload-free: the relay logs identifiers only.
    fn notable(&self, label: &str) -> String {
        let stderr = self
            .processes
            .iter()
            .find(|slot| slot.label == label)
            .map(|slot| String::from_utf8_lossy(&slot.process.stderr()).into_owned())
            .unwrap_or_default();
        let lines: Vec<&str> = stderr
            .lines()
            .filter(|line| {
                line.contains("WARN")
                    || line.contains("ERROR")
                    || line.contains("peer identity")
                    || line.contains("unready")
            })
            .collect();
        lines[lines.len().saturating_sub(20)..].join(" | ")
    }

    fn b_stderr(&self) -> String {
        self.processes
            .iter()
            .find(|slot| slot.label == "relay-b")
            .map(|slot| String::from_utf8_lossy(&slot.process.stderr()).into_owned())
            .unwrap_or_default()
    }

    async fn wait_b_logged(&self, needles: &[&str], phase: &str, deadline: Instant) -> Result<()> {
        let end = (Instant::now() + TRANSITION_DEADLINE).min(deadline);
        loop {
            let stderr = self.b_stderr();
            if stderr
                .lines()
                .any(|line| needles.iter().all(|needle| line.contains(needle)))
            {
                return Ok(());
            }
            if Instant::now() >= end {
                bail!(
                    "{phase}: relay B did not log {needles:?} before the bounded deadline; {}",
                    self.slot_diagnostic("relay-b")?
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

    /// The canary through A, retried while A re-verifies its route to B:
    /// withdrawing a pin closes A's pooled connection, and A's next request
    /// dials afresh.  Returns the attempt that succeeded.
    async fn echo_via_a_until(&self, phase: &str, deadline: Instant) -> Result<usize> {
        let end = (Instant::now() + TRANSITION_DEADLINE).min(deadline);
        let mut attempts = 0;
        loop {
            attempts += 1;
            match self.echo_via_a(phase).await {
                Ok(()) => return Ok(attempts),
                Err(error) if Instant::now() >= end => {
                    let directory = match self.catalog()?.read_signed_memberships().await {
                        Ok(records) => format!("{} records", records.len()),
                        Err(error) => format!("unreadable: {error:?}"),
                    };
                    bail!(
                        "{phase}: the canary never succeeded ({attempts} attempts): {error}; membership directory {directory}; relay-a: {}; relay-b: {}",
                        self.notable("relay-a"),
                        self.notable("relay-b")
                    )
                }
                Err(_) => sleep(POLL_INTERVAL).await,
            }
        }
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

    async fn wait_for_both_ready(&mut self) -> Result<()> {
        let server_ca_der = self.server_ca_der.clone();
        let mut errors = Vec::new();
        let (first, rest) = self
            .processes
            .split_first_mut()
            .ok_or_else(|| HarnessError::Process("no relay processes".into()))?;
        let second = rest
            .first_mut()
            .ok_or_else(|| HarnessError::Process("one relay process missing".into()))?;
        let (first_result, second_result) = tokio::join!(
            wait_for_ready(&mut first.process, first.consumer_bind, &server_ca_der),
            wait_for_ready(&mut second.process, second.consumer_bind, &server_ca_der),
        );
        for (slot, result) in [(&*first, first_result), (&*second, second_result)] {
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

    fn slot_diagnostic(&self, label: &str) -> Result<String> {
        self.processes
            .iter()
            .find(|slot| slot.label == label)
            .map(|slot| process_diagnostic(&slot.process))
            .ok_or_else(|| HarnessError::Process(format!("missing process slot {label}")))
    }

    fn b_pid(&self) -> Result<u32> {
        self.processes
            .iter()
            .find(|slot| slot.label == "relay-b")
            .and_then(|slot| slot.process.id())
            .ok_or_else(|| HarnessError::Process("relay-b is not running".into()))
    }

    async fn exercise(&mut self, deadline: Instant) -> Result<RekeyEvidence> {
        // ---- phase 0: both relays serve; the device attaches to B ---------
        let b_pid_initial = self
            .spawn_slot(
                &self.b_config.clone(),
                self.b_consumer_bind,
                self.b_device_bind,
                self.b_peer_bind,
                "relay-b",
            )
            .await?;
        self.spawn_slot(
            &self.a_config.clone(),
            self.a_consumer_bind,
            self.a_device_bind,
            self.a_peer_bind,
            "relay-a",
        )
        .await?;
        self.wait_for_both_ready().await?;
        let device_generation_initial = self.connect_device("initial").await?;
        let initial_owner = self.owner(deadline).await?;
        self.echo_via_a_until("rekey-initial", deadline).await?;
        let canary_initial = true;
        let old_presented_initially = self.b_presents(self.old_spki).await?;
        let new_presented_initially = self.b_presents(self.new_spki).await?;

        let b_sampler = ReadinessSampler::start(self.b_consumer_bind, self.server_ca_der.clone());
        let a_sampler = ReadinessSampler::start(self.a_consumer_bind, self.server_ca_der.clone());

        // ---- phase 1a: a trigger with a mismatched key is refused --------
        send_sighup(b_pid_initial)?;
        self.wait_b_logged(
            &["peer rekey refused", "does not match its certificate"],
            "mismatched trigger",
            deadline,
        )
        .await?;
        let mismatched_refused = !self.b_stderr().contains("peer identity staged");
        let new_presented_after_refusal = self.b_presents(self.new_spki).await?;

        // ---- phase 1b: the operator fixes the key; the trigger stages -----
        std::fs::write(&self.b_next_key_path, self.b_next_key_pem.as_bytes())?;
        send_sighup(b_pid_initial)?;
        let staged_line = format!("staged_spki_sha256={}", self.new_spki.to_hex());
        self.wait_b_logged(&["peer identity staged", &staged_line], "staged", deadline)
            .await?;
        let staged_logged = true;
        // Until both relays have reconciled at least twice more, an
        // unapproved successor must still not serve.  A condition, not a
        // fixed sleep: the checkpoint authority counts every reconcile.
        self.wait_reconciles(4, deadline).await?;
        let new_presented_while_staged = self.b_presents(self.new_spki).await?;
        let old_presented_while_staged = self.b_presents(self.old_spki).await?;

        // ---- phase 2: the publisher approves both; B switches -------------
        self.refresh_a().await?;
        self.publish_b(2, &[&self.old_key, &self.new_key]).await?;
        self.wait_b_presents(self.new_spki, "switch", deadline)
            .await?;
        let new_presented_after_switch = self.b_presents(self.new_spki).await?;
        let old_presented_after_switch = self.b_presents(self.old_spki).await?;
        self.wait_b_logged(&["peer identity switched"], "switch log", deadline)
            .await?;
        let switch_logged = true;
        self.echo_via_a_until("rekey-overlap", deadline).await?;
        let canary_during_overlap = true;

        // ---- phase 3: the publisher withdraws the predecessor --------------
        self.refresh_a().await?;
        self.publish_b(3, &[&self.new_key]).await?;
        self.wait_b_logged(
            &["previous peer identity retired", "withdrawn"],
            "retirement",
            deadline,
        )
        .await?;
        let retired_logged = true;
        let canary_after_retirement_attempts =
            self.echo_via_a_until("rekey-retired", deadline).await?;
        let new_presented_after_retirement = self.b_presents(self.new_spki).await?;
        let old_presented_after_retirement = self.b_presents(self.old_spki).await?;
        let final_owner = self.owner(deadline).await?;
        let device_generation_final = self.device_generation()?;
        let (b_readiness_samples, b_unready_samples) = b_sampler.stop().await?;
        let (a_readiness_samples, a_unready_samples) = a_sampler.stop().await?;
        let b_pid_final = self.b_pid()?;
        let diagnostics_payload_free = self.processes.iter().all(|slot| {
            ensure_safe_diagnostic(&process_diagnostic(&slot.process), slot.label).is_ok()
        });
        Ok(RekeyEvidence {
            b_pid_initial,
            b_pid_final,
            old_spki: self.old_spki.to_hex(),
            new_spki: self.new_spki.to_hex(),
            initial_owner,
            final_owner,
            device_generation_initial,
            device_generation_final,
            old_presented_initially,
            new_presented_initially,
            mismatched_refused,
            new_presented_after_refusal,
            staged_logged,
            new_presented_while_staged,
            old_presented_while_staged,
            new_presented_after_switch,
            old_presented_after_switch,
            switch_logged,
            retired_logged,
            new_presented_after_retirement,
            old_presented_after_retirement,
            canary_initial,
            canary_during_overlap,
            canary_after_retirement_attempts,
            b_readiness_samples,
            b_unready_samples,
            a_readiness_samples,
            a_unready_samples,
            diagnostics_payload_free,
        })
    }

    async fn cleanup(&mut self) -> Result<()> {
        // Keep each relay's full, payload-free stderr where the operator asked
        // for it, so a failed run can be read rather than guessed at.
        if let Ok(directory) = env::var("M8_REKEY_LOG_DIR") {
            for slot in &self.processes {
                let _ = std::fs::write(
                    Path::new(&directory).join(format!("{}.stderr", slot.label)),
                    slot.process.stderr(),
                );
            }
        }
        let mut errors = Vec::new();
        if let Some(client) = self.client.take()
            && let Err(error) = client.stop().await
        {
            errors.push(format!("stopping device: {error}"));
        }
        while let Some(slot) = self.processes.pop() {
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

fn send_sighup(pid: u32) -> Result<()> {
    let status = std::process::Command::new("/bin/kill")
        .arg("-HUP")
        .arg(pid.to_string())
        .status()
        .map_err(|error| HarnessError::Process(format!("sending SIGHUP: {error}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(HarnessError::Process(format!(
            "sending SIGHUP returned {status}"
        )))
    }
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
                cua: None,
            },
        )]),
        limits: LimitsConfig::default(),
        rotation: RotationConfig::default(),
        reconnect: Default::default(),
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
        // Name the typed envelope's code and execution when the body is one
        // (M7-C111: two 503s were unattributable with only a digest). Only
        // the two typed fields cross; message text and payload never do.
        let typed = serde_json::from_slice::<WireError>(&body).map_or_else(
            |_| "untyped".to_owned(),
            |wire| format!("code={} execution={}", wire.code, wire.execution),
        );
        return Err(HarnessError::Http(format!(
            "{phase} echo returned HTTP {status}: {typed} body_len={} body_sha256={}",
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

// ---------------------------------------------------------------------------
// A Redis TLS forwarder whose connections live as long as the relay keeps them
// ---------------------------------------------------------------------------

/// The shared `RedisTlsProxy` ends every forwarded connection five seconds
/// after it is accepted (`AUXILIARY_CONNECTION_DEADLINE`).  A relay's catalog
/// lanes are long-lived, so behind it every lane breaks with `broken pipe`
/// every few seconds; each failed membership reconcile takes the relay
/// Unready and a failed maintenance identity check closes the device session.
/// That was measured, in this gate, before this forwarder existed: the
/// relays' directory reads failed with `Database(broken pipe)` on one
/// reconcile in two and the device owner was lost.  This gate's phases are
/// longer than `m7_deployment_spki_replacement`'s, so it forwards without a
/// per-connection deadline, bounded by count and joined on shutdown.
struct LongLivedRedisTlsProxy {
    address: SocketAddr,
    handshakes: Arc<std::sync::atomic::AtomicUsize>,
    cancellation: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
}

const LONG_LIVED_PROXY_CONNECTIONS: usize = 64;

impl LongLivedRedisTlsProxy {
    async fn bind(upstream: SocketAddr, server_config: Arc<rustls::ServerConfig>) -> Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let cancellation = CancellationToken::new();
        let handshakes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let task_cancellation = cancellation.clone();
        let task_handshakes = handshakes.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    () = task_cancellation.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        while connections.try_join_next().is_some() {}
                        if connections.len() >= LONG_LIVED_PROXY_CONNECTIONS {
                            drop(stream);
                            continue;
                        }
                        let acceptor = acceptor.clone();
                        let handshakes = task_handshakes.clone();
                        let cancellation = task_cancellation.clone();
                        connections.spawn(async move {
                            let Ok(mut tls) = acceptor.accept(stream).await else { return };
                            handshakes.fetch_add(1, std::sync::atomic::Ordering::Release);
                            let Ok(mut upstream) = tokio::net::TcpStream::connect(upstream).await
                            else {
                                return;
                            };
                            tokio::select! {
                                () = cancellation.cancelled() => {}
                                _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream) => {}
                            }
                        });
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Ok(Self {
            address,
            handshakes,
            cancellation,
            task: Some(task),
        })
    }

    fn url(&self) -> String {
        format!("rediss://localhost:{}/0", self.address.port())
    }

    async fn shutdown(mut self) -> Result<()> {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            timeout(Duration::from_secs(5), task)
                .await
                .map_err(|_| HarnessError::Timeout("Redis TLS forwarder shutdown".into()))?
                .map_err(|error| HarnessError::Proxy(format!("Redis TLS forwarder: {error}")))?;
        }
        if self.handshakes.load(std::sync::atomic::Ordering::Acquire) == 0 {
            return Err(HarnessError::Proxy(
                "relay never completed a Redis TLS handshake".into(),
            ));
        }
        Ok(())
    }

    async fn shutdown_allow_unused(mut self) -> Result<()> {
        self.handshakes
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            let _ = timeout(Duration::from_secs(5), task).await;
        }
        Ok(())
    }
}

impl Drop for LongLivedRedisTlsProxy {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
