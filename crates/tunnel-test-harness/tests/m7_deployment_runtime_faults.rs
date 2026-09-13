//! Process-bound M7 dependency-loss acceptance.
//!
//! Each ignored case starts the configured relay against a real rediss TLS
//! forwarder and HTTPS checkpoint authority, observes the exact ready baseline,
//! then removes one live dependency.  The process must keep `/livez`
//! observable while `/readyz` becomes the bounded, redacted unready response.
//! The relay is stopped with SIGINT and every socket and Redis fixture namespace
//! is cleaned up before the case returns, including failed probe paths.

use std::{
    collections::BTreeMap,
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::time::timeout;
use tunnel_catalog::{RedisCatalog, RedisMembershipPublisher};
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
    relay_binary_path, send_sigint, wait_for_exit, wait_for_ports_released, wait_for_ready,
};

const TEST_DEADLINE: Duration = Duration::from_secs(60);
const PROCESS_DEADLINE: Duration = Duration::from_secs(8);
const DEPENDENCY_LOSS_DEADLINE: Duration = Duration::from_secs(8);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(8);
const SHUTDOWN_GRACE: Duration = Duration::from_millis(100);
const LIVE_BODY: &[u8] = br#"{"status":"live"}"#;
const UNREADY_BODY: &[u8] = br#"{"status":"unready"}"#;

#[derive(Clone, Copy, Debug)]
enum DependencyLoss {
    RedisTlsProxy,
    CheckpointAuthority,
}

impl DependencyLoss {
    fn name(self) -> &'static str {
        match self {
            Self::RedisTlsProxy => "redis-tls-proxy",
            Self::CheckpointAuthority => "checkpoint-authority",
        }
    }
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires TEST_REDIS_URL and the root-built relay binary"]
async fn m7_configured_relay_loses_redis_tls_proxy_fails_closed() {
    timeout(
        TEST_DEADLINE,
        run_dependency_loss_case(DependencyLoss::RedisTlsProxy),
    )
    .await
    .expect("Redis dependency-loss gate exceeded its bounded deadline")
    .expect("Redis dependency-loss gate");
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires TEST_REDIS_URL and the root-built relay binary"]
async fn m7_configured_relay_loses_checkpoint_authority_fails_closed() {
    timeout(
        TEST_DEADLINE,
        run_dependency_loss_case(DependencyLoss::CheckpointAuthority),
    )
    .await
    .expect("checkpoint dependency-loss gate exceeded its bounded deadline")
    .expect("checkpoint dependency-loss gate");
}

struct PartialFixture {
    catalog: Option<RedisCatalog>,
    redis_proxy: Option<RedisTlsProxy>,
    checkpoint_server: Option<CheckpointServer>,
}

impl PartialFixture {
    fn new() -> Self {
        Self {
            catalog: None,
            redis_proxy: None,
            checkpoint_server: None,
        }
    }

    async fn cleanup(self) -> Result<()> {
        let Self {
            catalog,
            redis_proxy,
            checkpoint_server,
        } = self;
        let catalog_result = match catalog {
            Some(catalog) => catalog
                .cleanup_fixture_namespace()
                .await
                .map_err(|error| HarnessError::Redis(format!("cleaning runtime fixture: {error}"))),
            None => Ok(()),
        };
        let checkpoint_result = match checkpoint_server {
            Some(server) => server.shutdown_allow_unused().await,
            None => Ok(()),
        };
        let redis_result = match redis_proxy {
            Some(proxy) => proxy.shutdown_allow_unused().await,
            None => Ok(()),
        };
        catalog_result?;
        checkpoint_result?;
        redis_result
    }
}

struct RuntimeFixture {
    _files: FixtureFiles,
    catalog: RedisCatalog,
    redis_proxy: Option<RedisTlsProxy>,
    checkpoint_server: Option<CheckpointServer>,
    relay_binary: PathBuf,
    config_path: PathBuf,
    consumer_bind: SocketAddr,
    device_bind: SocketAddr,
    peer_bind: SocketAddr,
    server_ca_der: Vec<u8>,
}

impl RuntimeFixture {
    async fn lose_dependency(&mut self, dependency: DependencyLoss) -> Result<()> {
        // The common one-shot supervisors intentionally expose no restart
        // operation. Each fault case therefore gets a fresh fixture rather
        // than replacing an authority or bypassing its durable version fence.
        match dependency {
            DependencyLoss::RedisTlsProxy => {
                let proxy = self.redis_proxy.take().ok_or_else(|| {
                    HarnessError::InvalidInput("Redis TLS proxy already stopped".into())
                })?;
                proxy.shutdown().await
            }
            DependencyLoss::CheckpointAuthority => {
                let server = self.checkpoint_server.take().ok_or_else(|| {
                    HarnessError::InvalidInput("checkpoint authority already stopped".into())
                })?;
                server.shutdown().await
            }
        }
    }

    async fn cleanup(self) -> Result<()> {
        let Self {
            _files: _,
            catalog,
            redis_proxy,
            checkpoint_server,
            ..
        } = self;
        let catalog_result = catalog
            .cleanup_fixture_namespace()
            .await
            .map_err(|error| HarnessError::Redis(format!("cleaning runtime fixture: {error}")));
        let checkpoint_result = match checkpoint_server {
            Some(server) => server.shutdown_allow_unused().await,
            None => Ok(()),
        };
        let redis_result = match redis_proxy {
            Some(proxy) => proxy.shutdown_allow_unused().await,
            None => Ok(()),
        };
        catalog_result?;
        checkpoint_result?;
        redis_result
    }
}

async fn run_dependency_loss_case(dependency: DependencyLoss) -> Result<()> {
    let mut fixture = create_fixture().await?;
    let result = run_configured_case(&mut fixture, dependency).await;
    let cleanup = fixture.cleanup().await;
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(HarnessError::Process(format!(
            "{} dependency-loss case failed: {error}; fixture cleanup failed: {cleanup_error}",
            dependency.name()
        ))),
    }
}

async fn run_configured_case(
    fixture: &mut RuntimeFixture,
    dependency: DependencyLoss,
) -> Result<()> {
    initialize_state(&fixture.relay_binary, &fixture.config_path).await?;
    let mut process = ManagedProcess::spawn(
        format!("m7-runtime-fault-{}", dependency.name()),
        ProcessSpec::new(&fixture.relay_binary)
            .arg("serve")
            .arg("--config")
            .arg(fixture.config_path.display().to_string()),
    )
    .await?;

    let probe_result = exercise_dependency_loss(&mut process, fixture, dependency).await;
    let shutdown_result = shutdown_process(
        process,
        fixture.consumer_bind,
        fixture.device_bind,
        fixture.peer_bind,
    )
    .await;
    match (probe_result, shutdown_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(shutdown_error)) => Err(HarnessError::Process(format!(
            "{} dependency-loss probe failed: {error}; SIGINT cleanup failed: {shutdown_error}",
            dependency.name()
        ))),
    }
}

async fn exercise_dependency_loss(
    process: &mut ManagedProcess,
    fixture: &mut RuntimeFixture,
    dependency: DependencyLoss,
) -> Result<()> {
    wait_for_ready(process, fixture.consumer_bind, &fixture.server_ca_der).await?;
    expect_health(
        fixture.consumer_bind,
        &fixture.server_ca_der,
        "/livez",
        200,
        LIVE_BODY,
    )
    .await?;
    expect_health(
        fixture.consumer_bind,
        &fixture.server_ca_der,
        "/readyz",
        200,
        br#"{"status":"ready"}"#,
    )
    .await?;

    fixture.lose_dependency(dependency).await?;
    wait_for_unready(process, fixture).await?;
    expect_health(
        fixture.consumer_bind,
        &fixture.server_ca_der,
        "/livez",
        200,
        LIVE_BODY,
    )
    .await?;
    expect_health(
        fixture.consumer_bind,
        &fixture.server_ca_der,
        "/readyz",
        503,
        UNREADY_BODY,
    )
    .await?;

    // The public body is the typed, payload-free diagnostic. Process output
    // is checked only for boundedness and accidental credential material.
    let diagnostic = process_diagnostic(process);
    assert_safe_diagnostic(&diagnostic, dependency)
}

async fn expect_health(
    address: SocketAddr,
    server_ca_der: &[u8],
    path: &'static str,
    expected_status: u16,
    expected_body: &[u8],
) -> Result<()> {
    let (status, body) = health_request(address, server_ca_der, path).await?;
    if status != expected_status || body.as_slice() != expected_body {
        return Err(HarnessError::Process(format!(
            "health {path} returned bounded status/body mismatch: status={status} body_len={}",
            body.len()
        )));
    }
    Ok(())
}

async fn wait_for_unready(process: &mut ManagedProcess, fixture: &RuntimeFixture) -> Result<()> {
    let deadline = Instant::now() + DEPENDENCY_LOSS_DEADLINE;
    loop {
        if let Some(status) = process.try_wait()? {
            return Err(HarnessError::Process(format!(
                "relay exited before dependency loss became unready: {status}"
            )));
        }
        let (live_status, live_body) =
            health_request(fixture.consumer_bind, &fixture.server_ca_der, "/livez").await?;
        if live_status != 200 || live_body.as_slice() != LIVE_BODY {
            return Err(HarnessError::Process(
                "liveness stopped serving during dependency-loss transition".into(),
            ));
        }
        match health_request(fixture.consumer_bind, &fixture.server_ca_der, "/readyz").await {
            Ok((status, body)) if status == 503 && body.as_slice() == UNREADY_BODY => return Ok(()),
            Ok(_) | Err(_) => {}
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "relay readiness did not fail closed after dependency loss".into(),
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn assert_safe_diagnostic(diagnostic: &str, dependency: DependencyLoss) -> Result<()> {
    if diagnostic.len() > 10_000 {
        return Err(HarnessError::Process(format!(
            "{} dependency-loss diagnostic exceeded its bound",
            dependency.name()
        )));
    }
    let lower = diagnostic.to_ascii_lowercase();
    if lower.contains("-----begin")
        || lower.contains("private_key")
        || lower.contains("private key")
        || lower.contains("password")
    {
        return Err(HarnessError::Process(format!(
            "{} dependency-loss diagnostic contained credential material",
            dependency.name()
        )));
    }
    Ok(())
}

async fn shutdown_process(
    mut process: ManagedProcess,
    consumer_bind: SocketAddr,
    device_bind: SocketAddr,
    peer_bind: SocketAddr,
) -> Result<()> {
    let status = if let Some(status) = process.try_wait()? {
        status
    } else {
        let pid = process
            .id()
            .ok_or_else(|| HarnessError::Process("relay PID disappeared before SIGINT".into()))?;
        if let Err(error) = send_sigint(pid) {
            let diagnostic = process_diagnostic(&process);
            let _ = process.shutdown(SHUTDOWN_GRACE).await;
            let _ = wait_for_ports_released(consumer_bind, device_bind, peer_bind).await;
            return Err(HarnessError::Process(format!(
                "relay SIGINT request failed: {error}; {diagnostic}"
            )));
        }
        match wait_for_exit(&mut process, SHUTDOWN_DEADLINE).await {
            Ok(status) => status,
            Err(error) => {
                let diagnostic = process_diagnostic(&process);
                let _ = process.shutdown(SHUTDOWN_GRACE).await;
                let _ = wait_for_ports_released(consumer_bind, device_bind, peer_bind).await;
                return Err(HarnessError::Process(format!(
                    "relay SIGINT shutdown was not bounded: {error}; {diagnostic}"
                )));
            }
        }
    };
    let diagnostic = process_diagnostic(&process);
    let joined_status = process.shutdown(SHUTDOWN_GRACE).await?;
    wait_for_ports_released(consumer_bind, device_bind, peer_bind).await?;
    if !status.success() || !joined_status.success() {
        return Err(HarnessError::Process(format!(
            "relay SIGINT exited unsuccessfully: {status}; {diagnostic}"
        )));
    }
    Ok(())
}

async fn initialize_state(binary: &Path, config: &Path) -> Result<()> {
    let mut process = ManagedProcess::spawn(
        "m7-runtime-fault-initialize",
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
                "runtime-fault initialization deadline: {error}; {diagnostic}"
            )));
        }
    };
    let diagnostic = process_diagnostic(&process);
    let _ = process.shutdown(SHUTDOWN_GRACE).await?;
    if !status.success() {
        return Err(HarnessError::Process(format!(
            "runtime-fault initialization exited {status}; {diagnostic}"
        )));
    }
    Ok(())
}

async fn create_fixture() -> Result<RuntimeFixture> {
    let files = FixtureFiles::new()?;
    let mut partial = PartialFixture::new();
    let result = create_fixture_inner(files, &mut partial).await;
    if result.is_err() {
        let _ = partial.cleanup().await;
    }
    result
}

async fn create_fixture_inner(
    files: FixtureFiles,
    partial: &mut PartialFixture,
) -> Result<RuntimeFixture> {
    let relay_binary = relay_binary_path()?;
    let upstream_url = env::var("TEST_REDIS_URL").map_err(|_| HarnessError::MissingRedisUrl {
        env_var: "TEST_REDIS_URL",
        guidance: "the dependency-loss gate requires a disposable plaintext Redis upstream for its local TLS forwarder".into(),
    })?;
    let upstream = parse_plaintext_upstream(&upstream_url)?;

    let run_id = Uuid::new_v4().simple().to_string();
    let deployment_id = format!("m7-runtime-fault-deployment-{run_id}");
    let deployment_incarnation = format!("m7-runtime-fault-incarnation-{run_id}");
    let namespace = format!("m7-runtime-fault-fixture-{run_id}");
    let node_id = "relay-a".to_owned();

    let pki = FixturePki::new()?;
    let mut cluster =
        ClusterFixture::with_deployment(&pki, &deployment_id, &deployment_incarnation)?;
    let peer_node = cluster.node(&node_id).ok_or_else(|| {
        HarnessError::InvalidInput("runtime fault fixture missing relay-a".into())
    })?;
    let peer_bind = peer_node.addresses.udp;
    let peer_chain = peer_node.peer_certificate_chain_pem();
    let peer_key = peer_node.peer_certificate.private_key_pem.clone();
    let membership = cluster
        .membership(&node_id)
        .ok_or_else(|| HarnessError::InvalidInput("runtime fault membership missing".into()))?
        .catalog_record();
    cluster
        .node_mut(&node_id)
        .ok_or_else(|| HarnessError::InvalidInput("runtime fault fixture missing relay-a".into()))?
        .release_ports();
    let signer = Arc::new(cluster.membership_authority);

    let server_leaf = pki.issue_server("m7-runtime-fault-relay")?;
    let checkpoint_leaf = pki.issue_server("m7-runtime-fault-checkpoint")?;
    let redis_leaf = pki.issue_server("m7-runtime-fault-redis")?;
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
    .map_err(|error| HarnessError::Pki(format!("building runtime Redis TLS forwarder: {error}")))?;
    partial.redis_proxy = Some(RedisTlsProxy::bind(upstream, redis_tls).await?);
    let relay_redis_url = partial
        .redis_proxy
        .as_ref()
        .expect("runtime Redis proxy")
        .url();

    let catalog =
        RedisCatalog::connect_for_recovery(&upstream_url, &namespace, &deployment_incarnation)
            .await
            .map_err(|error| {
                HarnessError::Redis(format!("opening runtime fault catalog: {error}"))
            })?;
    partial.catalog = Some(catalog);
    partial
        .catalog
        .as_ref()
        .expect("runtime fault catalog retained")
        .activate_deployment_incarnation()
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("activating runtime fault catalog: {error}"))
        })?;
    let publisher = RedisMembershipPublisher::connect(&upstream_url, &namespace)
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("opening runtime fault publisher: {error}"))
        })?;
    publisher
        .publish_signed_membership_for_node(&node_id, &membership)
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("publishing runtime fault membership: {error}"))
        })?;
    drop(publisher);

    let checkpoint_server = CheckpointServer::bind(
        load_server_config_from_pem(
            checkpoint_chain.as_bytes(),
            checkpoint_leaf.private_key_pem.as_bytes(),
            None,
        )
        .map_err(|error| HarnessError::Pki(format!("building runtime checkpoint TLS: {error}")))?,
        signer.clone(),
        deployment_id.clone(),
        deployment_incarnation.clone(),
        BTreeMap::from([(node_id.clone(), membership.version)]),
    )
    .await?;
    partial.checkpoint_server = Some(checkpoint_server);

    let oidc = OidcFixture::new(
        format!("https://m7-runtime-fault-oidc-{run_id}.invalid"),
        "agent-tunnel",
    )?;
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
            serde_json::to_string(&hex_encode(&signer.public_key()))?
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
        partial
            .checkpoint_server
            .as_ref()
            .expect("runtime checkpoint server")
            .address()
            .port()
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
    let catalog = partial
        .catalog
        .take()
        .expect("runtime fault catalog retained");

    Ok(RuntimeFixture {
        _files: files,
        catalog,
        redis_proxy: partial.redis_proxy.take(),
        checkpoint_server: partial.checkpoint_server.take(),
        relay_binary,
        config_path,
        consumer_bind,
        device_bind,
        peer_bind,
        server_ca_der: pki.server_ca.certificate_der.clone(),
    })
}
