//! Process-bound M7 peer endpoint and port-binding acceptance.
//!
//! The first case holds the exact approved peer UDP address while the real
//! configured relay starts.  Startup must fail within the bounded process
//! deadline; the relay cannot choose another address.  The second case signs a
//! versioned membership update for a freshly reserved UDP address, publishes
//! the matching checkpoint, and proves that the configured process reaches
//! readiness on that approved address before its joined shutdown and fixture
//! cleanup.

// The harness library is Unix-only (see `src/entry.rs`).
#![cfg(unix)]

use std::{
    collections::BTreeMap,
    env,
    net::{SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use chrono::Utc;
use tunnel_catalog::{RedisCatalog, RedisMembershipPublisher};
use tunnel_test_harness::{
    ClusterFixture, FixturePki, HarnessError, ManagedProcess, OidcFixture, ProcessSpec, Result,
};
use tunnel_transport::load_server_config_from_pem;
use uuid::Uuid;

#[path = "common/m7_deployment.rs"]
mod common;
use common::{
    CheckpointServer, FixtureFiles, ProcessConfigFixture, RedisTlsProxy, free_tcp_addr, hex_encode,
    jwks_json, parse_plaintext_upstream, process_diagnostic, relay_binary_path, send_sigint,
    wait_for_exit, wait_for_ports_released, wait_for_ready,
};

const TEST_DEADLINE: Duration = Duration::from_secs(60);
const PROCESS_DEADLINE: Duration = Duration::from_secs(8);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(8);
const SHUTDOWN_GRACE: Duration = Duration::from_millis(100);
const DIAGNOSTIC_MAX: usize = 16 * 1024;

#[derive(Clone, Copy, Debug)]
enum PortScenario {
    Collision,
    SignedEndpointUpdate,
}

impl PortScenario {
    fn label(self) -> &'static str {
        match self {
            Self::Collision => "port-collision",
            Self::SignedEndpointUpdate => "signed-endpoint-update",
        }
    }
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires TEST_REDIS_URL and the root-built relay binary"]
async fn m7_configured_relay_rejects_occupied_approved_peer_port() {
    tokio::time::timeout(TEST_DEADLINE, run_collision_case())
        .await
        .expect("configured peer port collision exceeded its bounded deadline")
        .expect("configured peer port collision gate");
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires TEST_REDIS_URL and the root-built relay binary"]
async fn m7_configured_relay_accepts_signed_update_for_bound_peer_endpoint() {
    tokio::time::timeout(TEST_DEADLINE, run_signed_endpoint_update_case())
        .await
        .expect("signed peer endpoint update exceeded its bounded deadline")
        .expect("signed peer endpoint update gate");
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
            Some(catalog) => catalog.cleanup_fixture_namespace().await.map_err(|error| {
                HarnessError::Redis(format!("cleaning partial port fixture: {error}"))
            }),
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
            Err(combine_errors(errors))
        }
    }
}

struct ConfiguredFixture {
    _files: FixtureFiles,
    catalog: RedisCatalog,
    redis_proxy: RedisTlsProxy,
    checkpoint_server: CheckpointServer,
    relay_binary: PathBuf,
    config_path: PathBuf,
    consumer_bind: SocketAddr,
    device_bind: SocketAddr,
    peer_bind: SocketAddr,
    server_ca_der: Vec<u8>,
    membership_version: u64,
    /// Kept only until `initialize` starts so the endpoint is selected from an
    /// address that was genuinely bound during signed-record construction.
    pending_peer_reservation: Option<UdpSocket>,
    /// The collision case retains the approved address while the process is
    /// starting.  It is released only after the child has been reaped.
    occupied_peer: Option<UdpSocket>,
}

impl ConfiguredFixture {
    fn release_pending_peer_reservation(&mut self) {
        self.pending_peer_reservation.take();
    }

    fn release_occupied_peer(&mut self) {
        self.occupied_peer.take();
    }

    async fn cleanup(mut self) -> Result<()> {
        self.release_pending_peer_reservation();
        self.release_occupied_peer();
        let ports = wait_for_ports_released(self.consumer_bind, self.device_bind, self.peer_bind);
        let catalog = self
            .catalog
            .cleanup_fixture_namespace()
            .await
            .map_err(|error| HarnessError::Redis(format!("cleaning port fixture: {error}")));
        let checkpoint = self.checkpoint_server.shutdown_allow_unused().await;
        let redis = self.redis_proxy.shutdown_allow_unused().await;
        let ports = ports.await;
        let mut errors = Vec::new();
        if let Err(error) = ports {
            errors.push(HarnessError::Process(format!(
                "configured listener ports were not released: {error}"
            )));
        }
        if let Err(error) = catalog {
            errors.push(error);
        }
        if let Err(error) = checkpoint {
            errors.push(error);
        }
        if let Err(error) = redis {
            errors.push(error);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(combine_errors(errors))
        }
    }
}

async fn run_collision_case() -> Result<()> {
    let mut fixture = create_fixture(PortScenario::Collision).await?;
    let result = run_collision_process(&mut fixture).await;
    // The child is reaped before this is dropped.  Keeping the socket alive
    // until then proves that the process did not silently move to a guessed
    // alternate peer port.
    fixture.release_occupied_peer();
    let cleanup = fixture.cleanup().await;
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(HarnessError::Process(format!(
            "port collision failed: {error}; cleanup failed: {cleanup_error}"
        ))),
    }
}

async fn run_signed_endpoint_update_case() -> Result<()> {
    let mut fixture = create_fixture(PortScenario::SignedEndpointUpdate).await?;
    // The signed record was created while this exact address was reserved.
    // Release immediately before the configured process takes ownership.
    fixture.release_pending_peer_reservation();
    let result = run_ready_process(&mut fixture).await;
    let cleanup = fixture.cleanup().await;
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(HarnessError::Process(format!(
            "signed endpoint update failed: {error}; cleanup failed: {cleanup_error}"
        ))),
    }
}

async fn run_collision_process(fixture: &mut ConfiguredFixture) -> Result<()> {
    if fixture.membership_version != 1 {
        return Err(HarnessError::Process(format!(
            "collision fixture did not use the initial approved membership version: {}",
            fixture.membership_version
        )));
    }
    if UdpSocket::bind(fixture.peer_bind).is_ok() {
        return Err(HarnessError::Process(
            "collision fixture failed to hold the approved peer address".into(),
        ));
    }
    initialize_state(&fixture.relay_binary, &fixture.config_path).await?;
    let mut process = ManagedProcess::spawn(
        format!("m7-{}", PortScenario::Collision.label()),
        ProcessSpec::new(&fixture.relay_binary)
            .arg("serve")
            .arg("--config")
            .arg(fixture.config_path.display().to_string()),
    )
    .await?;
    let status = match wait_for_exit(&mut process, PROCESS_DEADLINE).await {
        Ok(status) => status,
        Err(error) => {
            let diagnostic = process_diagnostic(&process);
            let _ = process.shutdown(SHUTDOWN_GRACE).await;
            return Err(HarnessError::Process(format!(
                "occupied approved peer port did not fail within the bound: {error}; {diagnostic}"
            )));
        }
    };
    let diagnostic = process_diagnostic(&process);
    let joined_status = process.shutdown(SHUTDOWN_GRACE).await?;
    assert_addr_in_use_bind_failure(status, joined_status, &diagnostic)?;
    if UdpSocket::bind(fixture.peer_bind).is_ok() {
        return Err(HarnessError::Process(
            "occupied approved peer address became available before the relay refusal was asserted"
                .into(),
        ));
    }
    Ok(())
}

fn assert_addr_in_use_bind_failure(
    status: std::process::ExitStatus,
    joined_status: std::process::ExitStatus,
    diagnostic: &str,
) -> Result<()> {
    if status.success() || joined_status.success() {
        return Err(HarnessError::Process(format!(
            "relay did not refuse the occupied approved peer listener: {status}"
        )));
    }
    if diagnostic.len() > DIAGNOSTIC_MAX {
        return Err(HarnessError::Process(
            "occupied-peer refusal diagnostic exceeded its bound".into(),
        ));
    }
    let lower = diagnostic.to_ascii_lowercase();
    // serve_cluster propagates quinn::Endpoint::server's I/O error directly
    // through main.  Match the OS category rather than accepting an unrelated
    // membership, TLS, or Redis startup failure.  The errno alternatives keep
    // the check stable on the supported Unix hosts without echoing an address.
    let address_in_use = lower.contains("address already in use")
        || lower.contains("os error 48")
        || lower.contains("os error 98");
    if !address_in_use {
        return Err(HarnessError::Process(format!(
            "occupied approved peer listener lacked an AddrInUse diagnostic: {status}"
        )));
    }
    Ok(())
}

async fn run_ready_process(fixture: &mut ConfiguredFixture) -> Result<()> {
    if fixture.membership_version != 2 {
        return Err(HarnessError::Process(format!(
            "endpoint update fixture did not publish a versioned membership update: {}",
            fixture.membership_version
        )));
    }
    initialize_state(&fixture.relay_binary, &fixture.config_path).await?;
    let mut process = ManagedProcess::spawn(
        format!("m7-{}", PortScenario::SignedEndpointUpdate.label()),
        ProcessSpec::new(&fixture.relay_binary)
            .arg("serve")
            .arg("--config")
            .arg(fixture.config_path.display().to_string()),
    )
    .await?;
    if let Err(error) =
        wait_for_ready(&mut process, fixture.consumer_bind, &fixture.server_ca_der).await
    {
        let diagnostic = process_diagnostic(&process);
        let _ = process.shutdown(SHUTDOWN_GRACE).await;
        return Err(HarnessError::Process(format!(
            "signed endpoint update did not reach readiness: {error}; {diagnostic}"
        )));
    }
    let Some(pid) = process.id() else {
        let diagnostic = process_diagnostic(&process);
        let _ = process.shutdown(SHUTDOWN_GRACE).await;
        return Err(HarnessError::Process(format!(
            "ready relay PID disappeared before SIGINT; {diagnostic}"
        )));
    };
    if let Err(error) = send_sigint(pid) {
        let diagnostic = process_diagnostic(&process);
        let _ = process.shutdown(SHUTDOWN_GRACE).await;
        return Err(HarnessError::Process(format!(
            "signed endpoint update SIGINT request failed: {error}; {diagnostic}"
        )));
    }
    let status = match wait_for_exit(&mut process, SHUTDOWN_DEADLINE).await {
        Ok(status) => status,
        Err(error) => {
            let diagnostic = process_diagnostic(&process);
            let _ = process.shutdown(SHUTDOWN_GRACE).await;
            return Err(HarnessError::Process(format!(
                "signed endpoint update shutdown was not bounded: {error}; {diagnostic}"
            )));
        }
    };
    let diagnostic = process_diagnostic(&process);
    let joined_status = process.shutdown(SHUTDOWN_GRACE).await?;
    if !status.success() || !joined_status.success() {
        return Err(HarnessError::Process(format!(
            "signed endpoint update relay exited unsuccessfully: {status}; {diagnostic}"
        )));
    }
    wait_for_ports_released(
        fixture.consumer_bind,
        fixture.device_bind,
        fixture.peer_bind,
    )
    .await
}

async fn initialize_state(binary: &Path, config: &Path) -> Result<()> {
    let mut process = ManagedProcess::spawn(
        "m7-port-binding-initialize",
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
                "port-binding initialization deadline: {error}; {diagnostic}"
            )));
        }
    };
    let diagnostic = process_diagnostic(&process);
    let _ = process.shutdown(SHUTDOWN_GRACE).await?;
    if !status.success() {
        return Err(HarnessError::Process(format!(
            "port-binding initialization exited {status}; {diagnostic}"
        )));
    }
    Ok(())
}

async fn create_fixture(scenario: PortScenario) -> Result<ConfiguredFixture> {
    let files = FixtureFiles::new()?;
    let mut partial = PartialFixture::new();
    let result = create_fixture_inner(files, scenario, &mut partial).await;
    match result {
        Ok(fixture) => Ok(fixture),
        Err(primary) => match partial.cleanup().await {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(HarnessError::Process(format!(
                "port-binding fixture setup failed: {primary}; partial cleanup failed: {cleanup}"
            ))),
        },
    }
}

async fn create_fixture_inner(
    files: FixtureFiles,
    scenario: PortScenario,
    partial: &mut PartialFixture,
) -> Result<ConfiguredFixture> {
    let relay_binary = relay_binary_path()?;
    let upstream_url = env::var("TEST_REDIS_URL").map_err(|_| HarnessError::MissingRedisUrl {
        env_var: "TEST_REDIS_URL",
        guidance: "the port-binding gate requires a disposable plaintext Redis upstream for its local TLS forwarder".into(),
    })?;
    let upstream = parse_plaintext_upstream(&upstream_url)?;
    let run_id = Uuid::new_v4().simple().to_string();
    let deployment_id = format!("m7-port-binding-deployment-{run_id}");
    let deployment_incarnation = format!("m7-port-binding-incarnation-{run_id}");
    let namespace = format!("m7-port-binding-fixture-{run_id}");
    let node_id = "relay-a".to_owned();

    let pki = FixturePki::new()?;
    let mut cluster =
        ClusterFixture::with_deployment(&pki, &deployment_id, &deployment_incarnation)?;
    let (original_peer_bind, peer_chain, peer_key) = {
        let node = cluster
            .node(&node_id)
            .ok_or_else(|| HarnessError::InvalidInput("port fixture missing relay-a".into()))?;
        (
            node.addresses.udp,
            node.peer_certificate_chain_pem(),
            node.peer_certificate.private_key_pem.clone(),
        )
    };
    let initial_membership = if matches!(scenario, PortScenario::SignedEndpointUpdate) {
        Some(
            cluster
                .membership(&node_id)
                .ok_or_else(|| {
                    HarnessError::InvalidInput("port fixture initial membership missing".into())
                })?
                .catalog_record(),
        )
    } else {
        None
    };

    let (peer_bind, membership, pending_peer_reservation, occupied_peer) = match scenario {
        PortScenario::Collision => {
            let occupied = cluster
                .node_mut(&node_id)
                .ok_or_else(|| HarnessError::InvalidInput("port fixture missing relay-a".into()))?
                .take_udp_socket()?;
            let membership = cluster
                .membership(&node_id)
                .ok_or_else(|| {
                    HarnessError::InvalidInput("port fixture membership missing".into())
                })?
                .catalog_record();
            (original_peer_bind, membership, None, Some(occupied))
        }
        PortScenario::SignedEndpointUpdate => {
            let reservation = UdpSocket::bind("127.0.0.1:0")?;
            let fresh_peer_bind = reservation.local_addr()?;
            let update = {
                let node = cluster.node(&node_id).ok_or_else(|| {
                    HarnessError::InvalidInput("port fixture missing relay-a".into())
                })?;
                cluster.membership_authority.sign_membership_with_endpoint(
                    &deployment_id,
                    &deployment_incarnation,
                    node,
                    2,
                    fresh_peer_bind,
                    Utc::now(),
                )?
            };
            (
                fresh_peer_bind,
                update.catalog_record(),
                Some(reservation),
                None,
            )
        }
    };
    cluster
        .node_mut(&node_id)
        .ok_or_else(|| HarnessError::InvalidInput("port fixture missing relay-a".into()))?
        .release_ports();
    let membership_version = membership.version;
    let signer = Arc::new(cluster.membership_authority);

    let server_leaf = pki.issue_server("m7-port-binding-relay")?;
    let checkpoint_leaf = pki.issue_server("m7-port-binding-checkpoint")?;
    let redis_leaf = pki.issue_server("m7-port-binding-redis")?;
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
    .map_err(|error| HarnessError::Pki(format!("building port-binding Redis TLS: {error}")))?;
    partial.redis_proxy = Some(RedisTlsProxy::bind(upstream, redis_tls).await?);
    let relay_redis_url = partial
        .redis_proxy
        .as_ref()
        .expect("port-binding Redis proxy retained")
        .url();

    let catalog =
        RedisCatalog::connect_for_recovery(&upstream_url, &namespace, &deployment_incarnation)
            .await
            .map_err(|error| {
                HarnessError::Redis(format!("opening port-binding catalog: {error}"))
            })?;
    partial.catalog = Some(catalog);
    partial
        .catalog
        .as_ref()
        .expect("port-binding catalog retained")
        .activate_deployment_incarnation()
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("activating port-binding catalog: {error}"))
        })?;
    common::mark_catalog_provisioned(
        partial
            .catalog
            .as_ref()
            .expect("port-binding catalog retained"),
    )
    .await?;
    let publisher = RedisMembershipPublisher::connect(&upstream_url, &namespace)
        .await
        .map_err(|error| HarnessError::Redis(format!("opening port-binding publisher: {error}")))?;
    if let Some(initial_membership) = initial_membership.as_ref() {
        publisher
            .publish_signed_membership_for_node(&node_id, initial_membership)
            .await
            .map_err(|error| {
                HarnessError::Redis(format!(
                    "publishing initial port-binding membership: {error}"
                ))
            })?;
    }
    publisher
        .publish_signed_membership_for_node(&node_id, &membership)
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("publishing port-binding membership: {error}"))
        })?;
    drop(publisher);

    let checkpoint_server = CheckpointServer::bind(
        load_server_config_from_pem(
            checkpoint_chain.as_bytes(),
            checkpoint_leaf.private_key_pem.as_bytes(),
            None,
        )
        .map_err(|error| {
            HarnessError::Pki(format!("building port-binding checkpoint TLS: {error}"))
        })?,
        signer.clone(),
        deployment_id.clone(),
        deployment_incarnation.clone(),
        BTreeMap::from([(node_id.clone(), membership_version)]),
    )
    .await?;
    partial.checkpoint_server = Some(checkpoint_server);

    let oidc = OidcFixture::new(
        format!("https://m7-port-binding-oidc-{run_id}.invalid"),
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
            .expect("port-binding checkpoint server")
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
        .expect("port-binding catalog retained");
    let checkpoint_server = partial
        .checkpoint_server
        .take()
        .expect("port-binding checkpoint retained");
    let redis_proxy = partial
        .redis_proxy
        .take()
        .expect("port-binding Redis proxy retained");

    Ok(ConfiguredFixture {
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
        membership_version,
        pending_peer_reservation,
        occupied_peer,
    })
}

fn combine_errors(mut errors: Vec<HarnessError>) -> HarnessError {
    debug_assert!(!errors.is_empty());
    if errors.len() == 1 {
        return errors.remove(0);
    }
    HarnessError::Process(
        errors
            .into_iter()
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("; "),
    )
}
