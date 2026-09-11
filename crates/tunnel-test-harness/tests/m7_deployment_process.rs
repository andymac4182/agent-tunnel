//! One-node, process-bound M7 deployment acceptance.
//!
//! This test is intentionally ignored by the ordinary workspace test suite:
//! it needs a real disposable Redis service and the root-built relay binary.
//! The test still exercises the full executable boundary when run explicitly:
//! Redis is reached through a local TLS forwarder, the membership record is
//! published to Redis, the checkpoint is returned by a real HTTPS authority,
//! and health is observed over the relay's consumer TLS listener.  The relay
//! binary may be supplied explicitly or discovered beside the built test.

use std::{collections::BTreeMap, env, net::SocketAddr, path::Path, sync::Arc, time::Duration};

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

const PROCESS_DEADLINE: Duration = Duration::from_secs(8);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(6);

#[derive(Clone, Copy)]
struct ProcessListenerAddresses {
    consumer: SocketAddr,
    device: SocketAddr,
    peer: SocketAddr,
}

struct ProcessCleanupContext {
    addresses: ProcessListenerAddresses,
    require_activity: bool,
    primary: Option<HarnessError>,
}

/// Runs the actual relay executable against one signed local cluster member.
/// The explicit environment contract keeps the test on the root agent's
/// shared target directory instead of discovering a different Cargo binary.
#[tokio::test]
#[ignore = "requires TEST_REDIS_URL; run explicitly as the C06 process gate"]
async fn m7_configured_relay_process_accepts_one_node_cluster() {
    run_configured_relay().await.expect("M7 process acceptance");
}

async fn run_configured_relay() -> Result<()> {
    let relay_binary = relay_binary_path()?;
    let upstream_url = env::var("TEST_REDIS_URL").map_err(|_| HarnessError::MissingRedisUrl {
        env_var: "TEST_REDIS_URL",
        guidance: "the process gate requires a disposable plaintext Redis upstream for its local TLS forwarder".into(),
    })?;
    let upstream = parse_plaintext_upstream(&upstream_url)?;

    let run_id = Uuid::new_v4().simple().to_string();
    let deployment_id = format!("m7-process-deployment-{run_id}");
    let deployment_incarnation = format!("m7-process-incarnation-{run_id}");
    let namespace = format!("m7-process-fixture-{run_id}");
    let node_id = "relay-a".to_owned();

    let files = FixtureFiles::new()?;
    let pki = FixturePki::new()?;
    let mut cluster =
        ClusterFixture::with_deployment(&pki, &deployment_id, &deployment_incarnation)?;
    let node = cluster
        .node(&node_id)
        .ok_or_else(|| HarnessError::InvalidInput("single-node fixture missing relay-a".into()))?;
    let peer_bind = node.addresses.udp;
    let peer_chain = node.peer_certificate_chain_pem();
    let peer_key = node.peer_certificate.private_key_pem.clone();
    let membership = cluster
        .membership(&node_id)
        .ok_or_else(|| HarnessError::InvalidInput("single-node membership missing".into()))?
        .catalog_record();
    cluster
        .node_mut(&node_id)
        .ok_or_else(|| HarnessError::InvalidInput("single-node fixture missing relay-a".into()))?
        .release_ports();
    let signer = Arc::new(cluster.membership_authority);

    let server_leaf = pki.issue_server("m7-process-relay")?;
    let checkpoint_leaf = pki.issue_server("m7-process-checkpoint")?;
    let redis_leaf = pki.issue_server("m7-process-redis")?;
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
    .map_err(|error| HarnessError::Pki(format!("building Redis TLS forwarder: {error}")))?;
    let redis_proxy = RedisTlsProxy::bind(upstream, redis_tls).await?;
    let relay_redis_url = redis_proxy.url();

    let catalog =
        RedisCatalog::connect_for_recovery(&upstream_url, &namespace, &deployment_incarnation)
            .await
            .map_err(|error| {
                HarnessError::Redis(format!("opening disposable Redis catalog: {error}"))
            })?;
    catalog
        .activate_deployment_incarnation()
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("activating disposable Redis catalog: {error}"))
        })?;
    let publisher = RedisMembershipPublisher::connect(&upstream_url, &namespace)
        .await
        .map_err(|error| HarnessError::Redis(format!("opening membership publisher: {error}")))?;
    publisher
        .publish_signed_membership_for_node(&node_id, &membership)
        .await
        .map_err(|error| HarnessError::Redis(format!("publishing signed membership: {error}")))?;
    drop(publisher);

    let minimum_versions = BTreeMap::from([(node_id.clone(), membership.version)]);
    let checkpoint_server = CheckpointServer::bind(
        load_server_config_from_pem(
            checkpoint_chain.as_bytes(),
            checkpoint_leaf.private_key_pem.as_bytes(),
            None,
        )
        .map_err(|error| HarnessError::Pki(format!("building checkpoint TLS: {error}")))?,
        signer.clone(),
        deployment_id.clone(),
        deployment_incarnation.clone(),
        minimum_versions,
    )
    .await?;

    let oidc = OidcFixture::new("https://m7-process-oidc.invalid", "agent-tunnel")?;
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

    let initialization = initialize_state(&relay_binary, &config_path).await;
    let addresses = ProcessListenerAddresses {
        consumer: consumer_bind,
        device: device_bind,
        peer: peer_bind,
    };
    if let Err(error) = initialization {
        return cleanup_process_fixture(
            catalog,
            checkpoint_server,
            redis_proxy,
            ProcessCleanupContext {
                addresses,
                require_activity: false,
                primary: Some(error),
            },
        )
        .await;
    }

    let process_result = serve_and_probe(
        &relay_binary,
        &config_path,
        consumer_bind,
        device_bind,
        peer_bind,
        &pki.server_ca.certificate_der,
    )
    .await;
    cleanup_process_fixture(
        catalog,
        checkpoint_server,
        redis_proxy,
        ProcessCleanupContext {
            addresses,
            require_activity: process_result.is_ok(),
            primary: process_result.err(),
        },
    )
    .await
}

async fn cleanup_process_fixture(
    catalog: RedisCatalog,
    checkpoint_server: CheckpointServer,
    redis_proxy: RedisTlsProxy,
    context: ProcessCleanupContext,
) -> Result<()> {
    let ProcessCleanupContext {
        addresses,
        require_activity,
        primary,
    } = context;
    let ProcessListenerAddresses {
        consumer,
        device,
        peer,
    } = addresses;
    let ports_before_cleanup = wait_for_ports_released(consumer, device, peer).await;
    let catalog_result = catalog
        .cleanup_fixture_namespace()
        .await
        .map_err(|error| HarnessError::Redis(format!("cleaning process fixture: {error}")));
    let checkpoint_result = if require_activity {
        checkpoint_server.shutdown().await
    } else {
        checkpoint_server.shutdown_allow_unused().await
    };
    let redis_result = if require_activity {
        redis_proxy.shutdown().await
    } else {
        redis_proxy.shutdown_allow_unused().await
    };
    let ports_after_cleanup = wait_for_ports_released(consumer, device, peer).await;

    let mut errors = Vec::new();
    if let Some(error) = primary {
        errors.push(error);
    }
    if let Err(error) = ports_before_cleanup {
        errors.push(HarnessError::Process(format!(
            "process fixture listener ports were not released before cleanup: {error}"
        )));
    }
    if let Err(error) = catalog_result {
        errors.push(error);
    }
    if let Err(error) = checkpoint_result {
        errors.push(error);
    }
    if let Err(error) = redis_result {
        errors.push(error);
    }
    if let Err(error) = ports_after_cleanup {
        errors.push(HarnessError::Process(format!(
            "process fixture listener ports were not released after cleanup: {error}"
        )));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(combine_process_errors(errors))
    }
}

fn combine_process_errors(mut errors: Vec<HarnessError>) -> HarnessError {
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

async fn initialize_state(binary: &Path, config: &Path) -> Result<()> {
    let mut process = ManagedProcess::spawn(
        "m7-process-initialize",
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
            let _ = process.shutdown(Duration::from_millis(100)).await;
            return Err(HarnessError::Process(format!(
                "initialization: {error}; {diagnostic}"
            )));
        }
    };
    let diagnostic = process_diagnostic(&process);
    let _ = process.shutdown(Duration::from_millis(100)).await?;
    if !status.success() {
        return Err(HarnessError::Process(format!(
            "initialization exited {status}; {diagnostic}"
        )));
    }
    Ok(())
}

async fn serve_and_probe(
    binary: &Path,
    config: &Path,
    consumer_bind: SocketAddr,
    device_bind: SocketAddr,
    peer_bind: SocketAddr,
    server_ca_der: &[u8],
) -> Result<()> {
    let mut process = ManagedProcess::spawn(
        "m7-process-relay",
        ProcessSpec::new(binary)
            .arg("serve")
            .arg("--config")
            .arg(config.display().to_string()),
    )
    .await?;
    if let Err(error) = wait_for_ready(&mut process, consumer_bind, server_ca_der).await {
        let diagnostic = process_diagnostic(&process);
        let _ = process.shutdown(Duration::from_millis(100)).await;
        return Err(HarnessError::Process(format!(
            "relay readiness: {error}; {diagnostic}"
        )));
    }

    let Some(pid) = process.id() else {
        let diagnostic = process_diagnostic(&process);
        let _ = process.shutdown(Duration::from_millis(100)).await;
        return Err(HarnessError::Process(format!(
            "relay exited before SIGINT; {diagnostic}"
        )));
    };
    if let Err(error) = send_sigint(pid) {
        let diagnostic = process_diagnostic(&process);
        let _ = process.shutdown(Duration::from_millis(100)).await;
        return Err(HarnessError::Process(format!(
            "relay SIGINT request: {error}; {diagnostic}"
        )));
    }
    let status = match wait_for_exit(&mut process, SHUTDOWN_DEADLINE).await {
        Ok(status) => status,
        Err(error) => {
            let diagnostic = process_diagnostic(&process);
            let _ = process.shutdown(Duration::from_millis(100)).await;
            return Err(HarnessError::Process(format!(
                "relay SIGINT shutdown: {error}; {diagnostic}"
            )));
        }
    };
    let diagnostic = process_diagnostic(&process);
    let _ = process.shutdown(Duration::from_millis(100)).await?;
    if !status.success() {
        return Err(HarnessError::Process(format!(
            "relay SIGINT exited {status}; {diagnostic}"
        )));
    }
    wait_for_ports_released(consumer_bind, device_bind, peer_bind).await
}
