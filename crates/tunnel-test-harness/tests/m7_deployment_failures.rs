//! Process-bound M7 bootstrap fault acceptance.
//!
//! Every case uses the configured relay executable and real Redis/checkpoint
//! authorities.  The matrix deliberately stops at the bootstrap boundary:
//! malformed or unavailable trust inputs must produce bounded typed diagnostics,
//! never ready/admitted listeners, and released ports.
//!
//! The matrix covers FP-10's bootstrap prerequisites: local peer identity,
//! signed membership, signed checkpoint authority, Redis authority, and
//! capacity.  Peer reachability has its own process case in
//! `m7_deployment_port_binding.rs`; runtime loss of an authority after a ready
//! start is `m7_deployment_runtime_faults.rs`.

use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use tokio::time::sleep;
use tunnel_catalog::{RedisCatalog, RedisMembershipPublisher};
use tunnel_test_harness::cluster_fixture::TestMembershipAuthority;
use tunnel_test_harness::{
    ClusterFixture, FixturePki, HarnessError, ManagedProcess, OidcFixture, ProcessSpec, Result,
};
use tunnel_transport::load_server_config_from_pem;
use uuid::Uuid;

#[path = "common/m7_deployment.rs"]
mod common;
use common::{
    CheckpointServer, FixtureFiles, ProcessConfigFixture, RedisTlsProxy, free_tcp_addr,
    health_request, hex_encode, jwks_json, parse_plaintext_upstream, process_diagnostic,
    relay_binary_path, wait_for_exit, wait_for_ports_released,
};

const PROCESS_DEADLINE: Duration = Duration::from_secs(8);
const SHUTDOWN_GRACE: Duration = Duration::from_millis(100);

#[tokio::test]
#[ignore = "requires TEST_REDIS_URL and the root-built relay binary"]
async fn m7_configured_relay_bootstrap_fault_matrix() {
    run_fault_matrix().await.expect("M7 bootstrap fault matrix");
}

#[derive(Clone, Copy, Debug)]
enum Fault {
    InvalidMembership,
    MissingMembership,
    ExpiredMembership,
    InvalidCheckpoint,
    MissingCheckpoint,
    ExpiredCheckpoint,
    ConflictingCheckpoint,
    RedisUnavailable,
    WrongLocalPeerCertificateKeyPair,
    /// FP-10 capacity: a relay configured to admit no devices per user is a
    /// partial bootstrap, not a serving gateway.
    ZeroDeviceCapacity,
    /// FP-10 capacity: a queue budget below the documented floor cannot honor
    /// the bounded replay contract.
    InsufficientQueueCapacity,
}

impl Fault {
    const ALL: [Self; 11] = [
        Self::InvalidMembership,
        Self::MissingMembership,
        Self::ExpiredMembership,
        Self::InvalidCheckpoint,
        Self::MissingCheckpoint,
        Self::ExpiredCheckpoint,
        Self::ConflictingCheckpoint,
        Self::RedisUnavailable,
        Self::WrongLocalPeerCertificateKeyPair,
        Self::ZeroDeviceCapacity,
        Self::InsufficientQueueCapacity,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::InvalidMembership => "invalid-membership",
            Self::MissingMembership => "missing-membership",
            Self::ExpiredMembership => "expired-membership",
            Self::InvalidCheckpoint => "invalid-checkpoint",
            Self::MissingCheckpoint => "missing-checkpoint",
            Self::ExpiredCheckpoint => "expired-checkpoint",
            Self::ConflictingCheckpoint => "conflicting-checkpoint",
            Self::RedisUnavailable => "redis-unavailable",
            Self::WrongLocalPeerCertificateKeyPair => "wrong-local-peer-certificate-key-pair",
            Self::ZeroDeviceCapacity => "zero-device-capacity",
            Self::InsufficientQueueCapacity => "insufficient-queue-capacity",
        }
    }

    fn diagnostic_matches(self, lower: &str) -> bool {
        match self {
            Self::InvalidMembership
            | Self::MissingMembership
            | Self::ExpiredMembership
            | Self::ConflictingCheckpoint => {
                // The public readiness surface deliberately redacts the
                // verifier detail. These cases share membership_rejected;
                // each fixture mutation has its own precondition assertion.
                lower.contains("reason=membership_rejected")
                    && lower.contains("category=membership")
            }
            Self::InvalidCheckpoint | Self::MissingCheckpoint => {
                lower.contains("reason=unknown_authority") && lower.contains("category=authority")
            }
            Self::ExpiredCheckpoint => {
                lower.contains("reason=checkpoint_expired") && lower.contains("category=checkpoint")
            }
            Self::RedisUnavailable => {
                // Redis is opened by the executable before the membership
                // runtime exists, so this fault has the redacted typed
                // redis_connection::CatalogConnection diagnostic rather than
                // a membership readiness reason/category.
                lower.contains("redis catalog connection failed")
            }
            Self::WrongLocalPeerCertificateKeyPair => {
                lower.contains("rustls configuration error") && lower.contains("keymismatch")
            }
            // Capacity is validated while the configuration is parsed, so the
            // executable never reaches a listener at all.  The bound itself is
            // named in the typed diagnostic.
            Self::ZeroDeviceCapacity => lower.contains("max_devices_per_user must be 1..=64"),
            Self::InsufficientQueueCapacity => {
                lower.contains("max_queue_bytes must be 256kib..=64mib")
            }
        }
    }

    fn membership_time(self) -> DateTime<Utc> {
        if matches!(self, Self::ExpiredMembership) {
            Utc::now() - ChronoDuration::minutes(5)
        } else {
            Utc::now()
        }
    }

    fn checkpoint_time(self) -> DateTime<Utc> {
        if matches!(self, Self::ExpiredCheckpoint) {
            Utc::now() - ChronoDuration::minutes(5)
        } else {
            Utc::now()
        }
    }

    fn checkpoint_minimum_version(self) -> u64 {
        if matches!(self, Self::ConflictingCheckpoint) {
            2
        } else {
            1
        }
    }

    fn checkpoint_signer_is_trusted(self) -> bool {
        !matches!(self, Self::InvalidCheckpoint)
    }

    fn expects_initialize_success(self) -> bool {
        // initialize parses config and bootstraps only the local membership
        // version fence. It does not read Redis, checkpoint, or peer PEM
        // material; every matrix fault is expected to reach serve.
        match self {
            Self::InvalidMembership
            | Self::MissingMembership
            | Self::ExpiredMembership
            | Self::InvalidCheckpoint
            | Self::MissingCheckpoint
            | Self::ExpiredCheckpoint
            | Self::ConflictingCheckpoint
            | Self::RedisUnavailable
            | Self::WrongLocalPeerCertificateKeyPair => true,
            // Capacity bounds are part of configuration validation, which
            // `initialize` performs before any authority is contacted.
            Self::ZeroDeviceCapacity | Self::InsufficientQueueCapacity => false,
        }
    }
}

struct ProcessFixture {
    _files: FixtureFiles,
    catalog: RedisCatalog,
    redis_proxy: RedisTlsProxy,
    checkpoint_server: CheckpointServer,
    relay_binary: PathBuf,
    config_path: PathBuf,
    consumer_bind: std::net::SocketAddr,
    device_bind: std::net::SocketAddr,
    peer_bind: std::net::SocketAddr,
    server_ca_der: Vec<u8>,
    upstream_url: String,
    relay_redis_url: String,
    namespace: String,
    node_id: String,
    checkpoint_endpoint: String,
    peer_chain_path: PathBuf,
    server_chain_path: PathBuf,
}

#[allow(dead_code)]
#[derive(serde::Deserialize, serde::Serialize)]
struct DirectoryMembershipEnvelope {
    version: String,
    bytes: Vec<u8>,
}

impl ProcessFixture {
    async fn cleanup(self) -> Result<()> {
        let catalog_result = self
            .catalog
            .cleanup_fixture_namespace()
            .await
            .map_err(|error| HarnessError::Redis(format!("cleaning fault fixture: {error}")));
        // Fault cases intentionally permit zero successful requests/handshakes,
        // but supervisors still receive bounded cancellation and join.
        let checkpoint_result = self.checkpoint_server.shutdown_allow_unused().await;
        let redis_result = self.redis_proxy.shutdown_allow_unused().await;
        let mut errors = Vec::new();
        if let Err(error) = catalog_result {
            errors.push(error);
        }
        if let Err(error) = checkpoint_result {
            errors.push(error);
        }
        if let Err(error) = redis_result {
            errors.push(error);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(combine_fault_errors("fault fixture cleanup", errors))
        }
    }
}

async fn cleanup_failed_fixture(fixture: ProcessFixture, primary: HarnessError) -> Result<()> {
    let addresses = (
        fixture.consumer_bind,
        fixture.device_bind,
        fixture.peer_bind,
    );
    let cleanup_result = fixture.cleanup().await;
    let ports_result = wait_for_ports_released(addresses.0, addresses.1, addresses.2).await;
    let mut errors = vec![primary];
    if let Err(error) = cleanup_result {
        errors.push(HarnessError::Process(format!(
            "fault fixture cleanup failed: {error}"
        )));
    }
    if let Err(error) = ports_result {
        errors.push(HarnessError::Process(format!(
            "fault fixture listener ports were not released: {error}"
        )));
    }
    Err(combine_fault_errors("M7 bootstrap fault", errors))
}

fn combine_fault_errors(context: &str, mut errors: Vec<HarnessError>) -> HarnessError {
    debug_assert!(!errors.is_empty());
    if errors.len() == 1 {
        return errors.remove(0);
    }
    let details = errors
        .into_iter()
        .map(|error| error.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    HarnessError::Process(format!("{context}: {details}"))
}

async fn run_fault_matrix() -> Result<()> {
    for fault in Fault::ALL {
        run_fault_case(fault).await?;
    }
    Ok(())
}

async fn run_fault_case(fault: Fault) -> Result<()> {
    let fixture = create_fixture(fault).await?;
    if let Err(error) = apply_fault(&fixture, fault).await {
        return cleanup_failed_fixture(fixture, error).await;
    }

    let initialization = initialize_state(&fixture.relay_binary, &fixture.config_path).await;
    let diagnostic = match initialization {
        Ok(()) if fixture_fault_expects_initialize_success(fault) => {
            let mut process = match ManagedProcess::spawn(
                format!("m7-bootstrap-failure-{}", fault.name()),
                ProcessSpec::new(&fixture.relay_binary)
                    .arg("serve")
                    .arg("--config")
                    .arg(fixture.config_path.display().to_string()),
            )
            .await
            {
                Ok(process) => process,
                Err(error) => return cleanup_failed_fixture(fixture, error).await,
            };

            let (status, bounded) = match wait_for_bootstrap_failure(&mut process, &fixture).await {
                Ok(result) => result,
                Err(error) => {
                    let bounded = process_diagnostic(&process);
                    let shutdown = process.shutdown(SHUTDOWN_GRACE).await;
                    let primary = match shutdown {
                        Ok(shutdown_status) => HarnessError::Process(format!(
                            "{} did not fail within the bounded bootstrap deadline: {error}; {bounded}; relay shutdown status={shutdown_status}",
                            fault.name()
                        )),
                        Err(shutdown_error) => HarnessError::Process(format!(
                            "{} did not fail within the bounded bootstrap deadline: {error}; {bounded}; relay shutdown failed: {shutdown_error}",
                            fault.name()
                        )),
                    };
                    return cleanup_failed_fixture(fixture, primary).await;
                }
            };
            if let Err(error) = process.shutdown(SHUTDOWN_GRACE).await {
                return cleanup_failed_fixture(fixture, error).await;
            }
            if status.success() {
                return cleanup_failed_fixture(
                    fixture,
                    HarnessError::Process(format!(
                        "{} unexpectedly exited successfully; {bounded}",
                        fault.name()
                    )),
                )
                .await;
            }
            bounded
        }
        Ok(()) => {
            return cleanup_failed_fixture(
                fixture,
                HarnessError::Process(format!(
                    "{} unexpectedly left initialize without its declared outcome",
                    fault.name()
                )),
            )
            .await;
        }
        Err(error) if fixture_fault_expects_initialize_success(fault) => {
            return cleanup_failed_fixture(
                fixture,
                HarnessError::Process(format!(
                    "{} failed during initialize although serve-only fault was expected: {error}",
                    fault.name()
                )),
            )
            .await;
        }
        Err(error) => error.to_string(),
    };
    finish_failure(fixture, fault, diagnostic).await
}

fn fixture_fault_expects_initialize_success(fault: Fault) -> bool {
    fault.expects_initialize_success()
}

async fn wait_for_bootstrap_failure(
    process: &mut ManagedProcess,
    fixture: &ProcessFixture,
) -> Result<(std::process::ExitStatus, String)> {
    let deadline = Instant::now() + PROCESS_DEADLINE;
    loop {
        if let Some(status) = process.try_wait()? {
            return Ok((status, process_diagnostic(process)));
        }
        assert_bootstrap_health(fixture).await?;
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "bootstrap fault process remained alive past bounded deadline".into(),
            ));
        }
        sleep(Duration::from_millis(50)).await;
    }
}

async fn assert_bootstrap_health(fixture: &ProcessFixture) -> Result<()> {
    let live = match health_request(fixture.consumer_bind, &fixture.server_ca_der, "/livez").await {
        Ok(response) => response,
        Err(_) => {
            // A process that fails before binding its public listener has no
            // health surface to query. The checks below apply whenever the
            // listener is exposed during the bounded failure window.
            return Ok(());
        }
    };
    if live != (200, br#"{"status":"live"}"#.to_vec()) {
        return Err(HarnessError::Process(format!(
            "bootstrap fault exposed unexpected /livez response: status={}, body={:?}",
            live.0, live.1
        )));
    }
    let ready = health_request(fixture.consumer_bind, &fixture.server_ca_der, "/readyz")
        .await
        .map_err(|error| {
            HarnessError::Process(format!(
                "bootstrap fault exposed /livez but /readyz was unavailable: {error}"
            ))
        })?;
    if ready != (503, br#"{"status":"unready"}"#.to_vec()) {
        return Err(HarnessError::Process(format!(
            "bootstrap fault exposed unexpected /readyz response: status={}, body={:?}",
            ready.0, ready.1
        )));
    }
    Ok(())
}

async fn finish_failure(fixture: ProcessFixture, fault: Fault, diagnostic: String) -> Result<()> {
    let addresses = (
        fixture.consumer_bind,
        fixture.device_bind,
        fixture.peer_bind,
    );
    let ports_before_cleanup = wait_for_ports_released(addresses.0, addresses.1, addresses.2).await;
    let typed_result = assert_bounded_typed_failure(fault, &diagnostic);
    let cleanup_result = fixture.cleanup().await;
    let ports_after_cleanup = wait_for_ports_released(addresses.0, addresses.1, addresses.2).await;
    let mut errors = Vec::new();
    if let Err(error) = ports_before_cleanup {
        errors.push(HarnessError::Process(format!(
            "{} listener ports were not released before fixture cleanup: {error}",
            fault.name()
        )));
    }
    if let Err(error) = typed_result {
        errors.push(error);
    }
    if let Err(error) = cleanup_result {
        errors.push(HarnessError::Process(format!(
            "{} fixture cleanup failed: {error}",
            fault.name()
        )));
    }
    if let Err(error) = ports_after_cleanup {
        errors.push(HarnessError::Process(format!(
            "{} listener ports were not released after fixture cleanup: {error}",
            fault.name()
        )));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(combine_fault_errors(fault.name(), errors))
    }
}

fn assert_bounded_typed_failure(fault: Fault, diagnostic: &str) -> Result<()> {
    if diagnostic.len() > 10_000 {
        return Err(HarnessError::Process(format!(
            "{} diagnostic exceeded the bounded capture: {} bytes",
            fault.name(),
            diagnostic.len()
        )));
    }
    let lower = diagnostic.to_ascii_lowercase();
    if lower.contains("-----begin") || lower.contains("private_key") {
        return Err(HarnessError::Process(format!(
            "{} diagnostic included unbounded credential material: {diagnostic}",
            fault.name()
        )));
    }
    if !fault.diagnostic_matches(&lower) {
        return Err(HarnessError::Process(format!(
            "{} diagnostic was not typed/bounded: {diagnostic}",
            fault.name()
        )));
    }
    Ok(())
}

async fn initialize_state(binary: &Path, config: &Path) -> Result<()> {
    let mut process = ManagedProcess::spawn(
        "m7-bootstrap-failure-initialize",
        ProcessSpec::new(binary)
            .arg("initialize")
            .arg("--config")
            .arg(config.display().to_string()),
    )
    .await?;
    let status = match wait_for_exit(&mut process, PROCESS_DEADLINE).await {
        Ok(status) => status,
        Err(error) => {
            let diagnostic = process_diagnostic(&process);
            let _ = process.shutdown(SHUTDOWN_GRACE).await;
            return Err(HarnessError::Process(format!(
                "initialization deadline: {error}; {diagnostic}"
            )));
        }
    };
    let diagnostic = process_diagnostic(&process);
    let _ = process.shutdown(SHUTDOWN_GRACE).await?;
    if !status.success() {
        return Err(HarnessError::Process(format!(
            "initialization exited {status}; {diagnostic}"
        )));
    }
    Ok(())
}

async fn create_fixture(fault: Fault) -> Result<ProcessFixture> {
    let relay_binary = relay_binary_path()?;
    let upstream_url = env::var("TEST_REDIS_URL").map_err(|_| HarnessError::MissingRedisUrl {
        env_var: "TEST_REDIS_URL",
        guidance: "the process fault matrix requires a disposable plaintext Redis upstream for its local TLS forwarder".into(),
    })?;
    let upstream = parse_plaintext_upstream(&upstream_url)?;

    let run_id = Uuid::new_v4().simple().to_string();
    let deployment_id = format!("m7-fault-deployment-{run_id}");
    let deployment_incarnation = format!("m7-fault-incarnation-{run_id}");
    let namespace = format!("m7-fault-fixture-{run_id}");
    let node_id = "relay-a".to_owned();

    let files = FixtureFiles::new()?;
    let pki = FixturePki::new()?;
    let mut cluster =
        ClusterFixture::with_deployment(&pki, &deployment_id, &deployment_incarnation)?;
    let peer_node = cluster
        .node(&node_id)
        .ok_or_else(|| HarnessError::InvalidInput("fault fixture missing relay-a".into()))?;
    let peer_bind = peer_node.addresses.udp;
    let peer_chain = peer_node.peer_certificate_chain_pem();
    let peer_key = peer_node.peer_certificate.private_key_pem.clone();
    let membership_time = fault.membership_time();
    let membership_fixture = cluster.membership_authority.sign_membership(
        &deployment_id,
        &deployment_incarnation,
        peer_node,
        1,
        membership_time,
    )?;
    let membership = membership_fixture.catalog_record();
    cluster
        .node_mut(&node_id)
        .ok_or_else(|| HarnessError::InvalidInput("fault fixture missing relay-a".into()))?
        .release_ports();
    let signer = Arc::new(cluster.membership_authority);

    let server_leaf = pki.issue_server("m7-fault-relay")?;
    let checkpoint_leaf = pki.issue_server("m7-fault-checkpoint")?;
    let redis_leaf = pki.issue_server("m7-fault-redis")?;
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
    .map_err(|error| HarnessError::Pki(format!("building fault Redis TLS forwarder: {error}")))?;
    let redis_proxy = RedisTlsProxy::bind(upstream, redis_tls).await?;
    let relay_redis_url = redis_proxy.url();

    let catalog =
        RedisCatalog::connect_for_recovery(&upstream_url, &namespace, &deployment_incarnation)
            .await
            .map_err(|error| HarnessError::Redis(format!("opening fault catalog: {error}")))?;
    catalog
        .activate_deployment_incarnation()
        .await
        .map_err(|error| HarnessError::Redis(format!("activating fault catalog: {error}")))?;
    let publisher = RedisMembershipPublisher::connect(&upstream_url, &namespace)
        .await
        .map_err(|error| HarnessError::Redis(format!("opening fault publisher: {error}")))?;
    publisher
        .publish_signed_membership_for_node(&node_id, &membership)
        .await
        .map_err(|error| HarnessError::Redis(format!("publishing fault membership: {error}")))?;
    drop(publisher);

    let checkpoint_signer = if fault.checkpoint_signer_is_trusted() {
        signer.clone()
    } else {
        Arc::new(TestMembershipAuthority::with_key_id(format!(
            "m7-untrusted-checkpoint-{run_id}"
        ))?)
    };
    let checkpoint_server = CheckpointServer::bind_at(
        load_server_config_from_pem(
            checkpoint_chain.as_bytes(),
            checkpoint_leaf.private_key_pem.as_bytes(),
            None,
        )
        .map_err(|error| HarnessError::Pki(format!("building fault checkpoint TLS: {error}")))?,
        checkpoint_signer,
        deployment_id.clone(),
        deployment_incarnation.clone(),
        BTreeMap::from([(node_id.clone(), fault.checkpoint_minimum_version())]),
        fault.checkpoint_time(),
    )
    .await?;

    let oidc = OidcFixture::new("https://m7-fault-oidc.invalid", "agent-tunnel")?;
    let oidc_jwks = jwks_json(&oidc)?;
    let server_chain_path = files.write("relay-cert-chain.pem", server_chain.as_bytes())?;
    let server_key_path = files.write("relay-key.pem", server_leaf.private_key_pem.as_bytes())?;
    let server_ca_path = files.write("server-ca.pem", pki.server_ca.certificate_pem.as_bytes())?;
    let device_ca_path = files.write("device-ca.pem", pki.device_ca.certificate_pem.as_bytes())?;
    let peer_chain_path = files.write("peer-cert-chain.pem", peer_chain.as_bytes())?;
    let peer_key_path = files.write("peer-key.pem", peer_key.as_bytes())?;
    let peer_ca_path = files.write("peer-ca.pem", pki.peer_ca.certificate_pem.as_bytes())?;
    let signer_trust_path = files.write(
        "membership-trust.json",
        format!(
            "{{\"keys\":[{{\"key_id\":{},\"public_key\":{}}}]}}",
            serde_json::to_string(signer.key_id())?,
            serde_json::to_string(&hex_encode(&signer.public_key()))?,
        )
        .as_bytes(),
    )?;
    let oidc_jwks_path = files.write("oidc-jwks.json", oidc_jwks.as_bytes())?;
    let state_path = files.state_path()?;
    let consumer_bind = free_tcp_addr();
    let device_bind = loop {
        let candidate = free_tcp_addr();
        if candidate != consumer_bind {
            break candidate;
        }
    };
    let checkpoint_endpoint = format!(
        "https://localhost:{}/v1/checkpoint",
        checkpoint_server.address().port()
    );
    let config = ProcessConfigFixture {
        consumer_bind,
        device_bind,
        peer_bind,
        redis_url: &relay_redis_url,
        namespace: &namespace,
        deployment_id: &deployment_id,
        deployment_incarnation: &deployment_incarnation,
        oidc: &oidc,
        oidc_jwks_path: &oidc_jwks_path,
        server_chain_path: &server_chain_path,
        server_key_path: &server_key_path,
        server_ca_path: &server_ca_path,
        device_ca_path: &device_ca_path,
        peer_chain_path: &peer_chain_path,
        peer_key_path: &peer_key_path,
        peer_ca_path: &peer_ca_path,
        signer_trust_path: &signer_trust_path,
        state_path: &state_path,
        checkpoint_endpoint: &checkpoint_endpoint,
        node_id: &node_id,
    };
    let config_path = files.write("relay.toml", config.render().as_bytes())?;

    Ok(ProcessFixture {
        _files: files,
        catalog,
        redis_proxy,
        checkpoint_server,
        relay_binary,
        config_path,
        consumer_bind,
        device_bind,
        peer_bind,
        server_ca_der: pki.server_ca.certificate_der.clone(),
        upstream_url,
        relay_redis_url,
        namespace,
        node_id,
        checkpoint_endpoint,
        peer_chain_path,
        server_chain_path,
    })
}

async fn apply_fault(fixture: &ProcessFixture, fault: Fault) -> Result<()> {
    match fault {
        Fault::InvalidMembership => corrupt_membership(fixture).await,
        Fault::MissingMembership => delete_membership(fixture).await,
        Fault::ExpiredMembership
        | Fault::InvalidCheckpoint
        | Fault::ExpiredCheckpoint
        | Fault::ConflictingCheckpoint => Ok(()),
        Fault::MissingCheckpoint => {
            let unused = free_tcp_addr();
            replace_config_value(
                &fixture.config_path,
                &fixture.checkpoint_endpoint,
                &format!("https://localhost:{}/v1/checkpoint", unused.port()),
            )
        }
        Fault::RedisUnavailable => {
            let unused = free_tcp_addr();
            replace_config_value(
                &fixture.config_path,
                &fixture.relay_redis_url,
                &format!("rediss://localhost:{}/0", unused.port()),
            )
        }
        Fault::WrongLocalPeerCertificateKeyPair => {
            let wrong_chain = fs::read(&fixture.server_chain_path)?;
            fs::write(&fixture.peer_chain_path, wrong_chain)?;
            Ok(())
        }
        // The capacity keys belong to the top-level table, so they are
        // inserted immediately before the cluster table rather than appended.
        Fault::ZeroDeviceCapacity => replace_config_value(
            &fixture.config_path,
            "\n\n[cluster]\n",
            "\nmax_devices_per_user = 0\n\n[cluster]\n",
        ),
        Fault::InsufficientQueueCapacity => replace_config_value(
            &fixture.config_path,
            "\n\n[cluster]\n",
            "\nmax_queue_bytes = 1024\n\n[cluster]\n",
        ),
    }
}

fn replace_config_value(path: &Path, from: &str, to: &str) -> Result<()> {
    let contents = fs::read_to_string(path)?;
    if !contents.contains(from) {
        return Err(HarnessError::InvalidInput(format!(
            "fault config did not contain expected value {from}"
        )));
    }
    fs::write(path, contents.replace(from, to))?;
    Ok(())
}

async fn corrupt_membership(fixture: &ProcessFixture) -> Result<()> {
    let key = membership_directory_key(&fixture.namespace);
    let client = redis::Client::open(fixture.upstream_url.as_str())
        .map_err(|error| HarnessError::Redis(format!("opening mutation client: {error}")))?;
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .map_err(|error| HarnessError::Redis(format!("opening mutation connection: {error}")))?;
    let encoded: Vec<u8> = redis::cmd("HGET")
        .arg(&key)
        .arg(&fixture.node_id)
        .query_async(&mut connection)
        .await
        .map_err(|error| HarnessError::Redis(format!("reading membership envelope: {error}")))?;
    if encoded.is_empty() {
        return Err(HarnessError::Redis(
            "invalid-membership precondition failed: directory slot was empty".into(),
        ));
    }
    let mut envelope: DirectoryMembershipEnvelope =
        serde_json::from_slice(&encoded).map_err(|error| {
            HarnessError::Redis(format!(
                "decoding membership directory envelope for signature mutation: {error}"
            ))
        })?;
    let mut record: tunnel_cluster::membership::SignedMembershipRecord =
        serde_json::from_slice(&envelope.bytes).map_err(|error| {
            HarnessError::Redis(format!(
                "decoding signed membership record for signature mutation: {error}"
            ))
        })?;
    // Keep the record structurally and temporally valid, but change a signed
    // field without recomputing the signature. This exercises verification
    // failure rather than malformed JSON handling.
    record.issued_at += ChronoDuration::seconds(1);
    envelope.bytes = serde_json::to_vec(&record)?;
    let replacement = serde_json::to_vec(&envelope)?;
    let updated: i32 = redis::cmd("HSET")
        .arg(&key)
        .arg(&fixture.node_id)
        .arg(replacement)
        .query_async(&mut connection)
        .await
        .map_err(|error| HarnessError::Redis(format!("corrupting membership envelope: {error}")))?;
    if updated != 0 {
        return Err(HarnessError::Redis(format!(
            "invalid-membership precondition failed: HSET returned {updated}, expected an existing directory slot"
        )));
    }
    Ok(())
}

async fn delete_membership(fixture: &ProcessFixture) -> Result<()> {
    let key = membership_directory_key(&fixture.namespace);
    let client = redis::Client::open(fixture.upstream_url.as_str())
        .map_err(|error| HarnessError::Redis(format!("opening mutation client: {error}")))?;
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .map_err(|error| HarnessError::Redis(format!("opening mutation connection: {error}")))?;
    let removed: i32 = redis::cmd("HDEL")
        .arg(&key)
        .arg(&fixture.node_id)
        .query_async(&mut connection)
        .await
        .map_err(|error| HarnessError::Redis(format!("removing membership envelope: {error}")))?;
    if removed != 1 {
        return Err(HarnessError::Redis(format!(
            "missing-membership precondition failed: HDEL removed {removed} fields, expected 1"
        )));
    }
    Ok(())
}

fn membership_directory_key(namespace: &str) -> String {
    format!("tunnel-catalog:{namespace}:membership:operator:directory")
}
