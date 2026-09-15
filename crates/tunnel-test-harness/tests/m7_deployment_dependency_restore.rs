#![cfg(unix)]

//! Staged configured-process dependency restoration gate.
//!
//! This is deliberately an ignored integration target.  It runs the
//! root-built relay executable, an authenticated in-process device client,
//! the public TLS echo route, and a Redis TLS forwarder whose listener and
//! certificate stay stable while active Redis connections are severed and
//! then allowed to reconnect.  It proves, for one same-PID relay: readiness
//! withdrawal with liveness intact; the relay's own typed
//! `AUTHORITY_UNAVAILABLE` close of the pre-fault device session, observed
//! both as the client's clean control close and as the relay's structured
//! `owner_check_failed`/`session_closed` diagnostics for that exact session;
//! the typed `CLUSTER_UNREADY` admission boundary; catalog reconnection to
//! the same verified Redis primary with readiness recovery; the fenced stale
//! owner token clearing only by lease expiry; and a fresh authenticated
//! session/echo afterwards.  It does not inject OS writes, does not restart
//! Redis (a changed `run_id` is a separate fail-closed catalog case), and does
//! not claim dynamic peer SPKI replacement.

use std::{
    collections::BTreeMap,
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use chrono::Utc;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, body::Bytes};
use hyper_util::rt::TokioIo;
use tokio::{
    net::{TcpListener as TokioTcpListener, TcpStream},
    sync::watch,
    task::JoinSet,
    time::{sleep, timeout, timeout_at},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{Catalog, RedisCatalog, RedisMembershipPublisher};
use tunnel_client::{
    ClientError, ConnectConfig, ConnectOptions, CredentialConfig, LimitsConfig, LocalExport,
    LocalExportKind, Readiness, SessionInfo, connect,
};
use tunnel_core::RotationConfig;
use tunnel_test_harness::{
    ClusterFixture, FixturePki, FixtureTopology, HarnessError, ManagedProcess, OidcFixture,
    ProcessSpec, Result,
};
use tunnel_transport::load_server_config_from_pem;
use uuid::Uuid;

#[path = "common/m7_deployment.rs"]
mod common;
use common::{
    AUXILIARY_CONNECTION_DEADLINE, AUXILIARY_CONNECTION_LIMIT, AUXILIARY_SHUTDOWN_DEADLINE,
    CheckpointServer, FixtureFiles, ProcessConfigFixture, free_tcp_addr, health_request,
    hex_encode, jwks_json, parse_plaintext_upstream, process_diagnostic, relay_binary_path,
    send_sigint, truncate, wait_for_exit, wait_for_ports_released, wait_for_ready,
};

const PROCESS_DEADLINE: Duration = Duration::from_secs(8);
const DEPENDENCY_DEADLINE: Duration = Duration::from_secs(20);
const CLIENT_DEADLINE: Duration = Duration::from_secs(20);
const ECHO_DEADLINE: Duration = Duration::from_secs(20);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(8);
const SHUTDOWN_GRACE: Duration = Duration::from_millis(100);
/// The relay's default owner lease is 30 seconds; a stale token left by a
/// session closed while Redis was unreachable clears only by that expiry.
const OWNER_LEASE_CLEAR_DEADLINE: Duration = Duration::from_secs(40);
/// Bounded wait for the relay's structured close diagnostics to reach the
/// harness stderr capture after the client observed the close.
const RELAY_EVIDENCE_DEADLINE: Duration = Duration::from_secs(5);
/// The relay logs structured JSON at `info` by default; pin the filter so an
/// inherited `RUST_LOG` cannot hide the typed close evidence.
const RELAY_LOG_FILTER: &str = "info";
/// The relay's closed terminal reason for a failed owner/authority check.
const DEPENDENCY_CLOSE_REASON: &str = "AUTHORITY_UNAVAILABLE";
/// The relay maintenance operations that can observe the injected loss.
const DEPENDENCY_CLOSE_OPERATIONS: &[&str] = &["resolve_device", "renew_owner"];
/// The relay authority-failure categories that a severed or stalled Redis
/// connection produces; any other category is not the injected fault.
const DEPENDENCY_CLOSE_CATEGORIES: &[&str] = &["redis_io", "timeout"];
/// The client's exact typed error for a relay-initiated clean control close.
const CLIENT_CONTROL_CLOSE_SCOPE: &str = "control read";
const CLIENT_CONTROL_CLOSE_DETAIL: &str = "control socket closed";
const CLIENT_CONTROL_CLOSE_REASON: &str = "control read failed";
const LIVE_BODY: &[u8] = br#"{"status":"live"}"#;
const READY_BODY: &[u8] = br#"{"status":"ready"}"#;
const UNREADY_BODY: &[u8] = br#"{"status":"unready"}"#;
const CANARY: &str = "m7-configured-restoration-canary";
const PAYLOAD: &[u8] = b"m7-configured-restoration-echo";

#[tokio::test]
#[ignore = "requires TEST_REDIS_URL and the root-built relay binary"]
async fn m7_configured_relay_restores_redis_and_serves_fresh_authenticated_echo() {
    run_restoration_gate()
        .await
        .expect("configured dependency-restoration gate");
}

struct RestorationFixture {
    _files: FixtureFiles,
    catalog: RedisCatalog,
    proxy: RestorableRedisTlsProxy,
    checkpoint: CheckpointServer,
    relay_binary: PathBuf,
    config_path: PathBuf,
    client_config: ConnectConfig,
    token: String,
    tenant_id: Uuid,
    device_id: Uuid,
    service_id: Uuid,
    consumer_bind: SocketAddr,
    device_bind: SocketAddr,
    peer_bind: SocketAddr,
    server_ca_der: Vec<u8>,
}

struct PartialFixture {
    catalog: Option<RedisCatalog>,
    proxy: Option<RestorableRedisTlsProxy>,
    checkpoint: Option<CheckpointServer>,
}

impl PartialFixture {
    fn new() -> Self {
        Self {
            catalog: None,
            proxy: None,
            checkpoint: None,
        }
    }

    async fn cleanup(self) -> Result<()> {
        let Self {
            catalog,
            proxy,
            checkpoint,
        } = self;
        let catalog_result = match catalog {
            Some(catalog) => catalog.cleanup_fixture_namespace().await.map_err(|error| {
                HarnessError::Redis(format!("restoration catalog cleanup: {error}"))
            }),
            None => Ok(()),
        };
        let checkpoint_result = match checkpoint {
            Some(checkpoint) => checkpoint.shutdown_allow_unused().await,
            None => Ok(()),
        };
        let proxy_result = match proxy {
            Some(proxy) => proxy.shutdown_allow_unused().await,
            None => Ok(()),
        };
        combine_results(catalog_result, checkpoint_result, proxy_result)
    }
}

impl RestorationFixture {
    async fn cleanup(self) -> Result<()> {
        let Self {
            _files: _,
            catalog,
            proxy,
            checkpoint,
            ..
        } = self;
        let catalog_result = catalog
            .cleanup_fixture_namespace()
            .await
            .map_err(|error| HarnessError::Redis(format!("restoration catalog cleanup: {error}")));
        let checkpoint_result = checkpoint.shutdown_allow_unused().await;
        let proxy_result = proxy.shutdown_allow_unused().await;
        combine_results(catalog_result, checkpoint_result, proxy_result)
    }
}

async fn run_restoration_gate() -> Result<()> {
    let fixture = create_fixture().await?;
    let mut process = None;
    let mut client = None;
    let primary = async {
        initialize_state(&fixture.relay_binary, &fixture.config_path).await?;
        process = Some(start_relay(&fixture).await?);
        let relay = process.as_mut().expect("relay process retained");
        let pid_before = relay
            .id()
            .ok_or_else(|| HarnessError::Process("relay PID missing after readiness".into()))?;

        client = Some(connect_fresh(&fixture.client_config).await?);
        let session =
            wait_for_client_ready(client.as_mut().expect("device client retained")).await?;
        expect_echo(&fixture, "before-redis-loss").await?;

        fixture.proxy.set_available(false)?;
        wait_for_unready(relay, &fixture).await?;
        // The relay must itself close the pre-fault device session once its
        // owner/authority maintenance check fails. Observe that close before
        // stopping the handle so a clean cancellation cannot stand in for it.
        let client_close_reason =
            wait_for_dependency_close(client.as_ref().expect("device client retained")).await?;
        let blocked = attempt_echo(&fixture, "while-redis-unready").await?;
        let blocked_boundary = validate_unready_boundary(&blocked)?;

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

        stop_dependency_closed_client(&mut client).await?;
        let relay_close =
            wait_for_relay_dependency_close(relay, &session, fixture.device_id).await?;
        fixture.proxy.set_available(true)?;
        wait_for_ready_after_restore(relay, &fixture).await?;
        // The closed session's owner token could not be released while Redis
        // was unreachable; lease expiry is its documented fencing fallback and
        // a fresh session must not be able to take the slot before then.
        let stale_owner_cleared_ms = wait_for_stale_owner_clear(&fixture, &session).await?;

        // A new authenticated device session is deliberate evidence for a
        // fresh route after restoration. The pre-fault handle is not treated
        // as proof that a control socket survived the dependency fault.
        client = Some(connect_fresh(&fixture.client_config).await?);
        let fresh =
            wait_for_client_ready(client.as_mut().expect("fresh device client retained")).await?;
        if fresh.session_id == session.session_id || fresh.epoch <= session.epoch {
            return Err(HarnessError::Process(format!(
                "post-restore device session did not use a fresh fenced owner: old_epoch={} new_epoch={} same_session={}",
                session.epoch,
                fresh.epoch,
                fresh.session_id == session.session_id
            )));
        }
        expect_echo(&fixture, "after-redis-restore").await?;

        let pid_after = relay
            .id()
            .ok_or_else(|| HarnessError::Process("relay PID missing after recovery".into()))?;
        if pid_before != pid_after {
            return Err(HarnessError::Process(format!(
                "configured Redis restoration changed relay PID: before={pid_before} after={pid_after}"
            )));
        }
        eprintln!(
            "scope=configured_process_redis_restoration same_pid=true live_after_fault=true ready_withdrawn=true ready_restored=true authenticated_echo_before=true blocked_echo_status={} blocked_code={} blocked_execution={} blocked_body_len={} no_premature_dispatch={} dependency_close_reason={} dependency_close_operation={} dependency_close_category={} client_close_reason={:?} client_close_detail={:?} stale_owner_cleared_ms={} fresh_owner_epoch={} authenticated_echo_after=true",
            blocked_boundary.status,
            blocked_boundary.code,
            blocked_boundary.execution,
            blocked_boundary.body_len,
            blocked_boundary.no_premature_dispatch,
            relay_close.reason,
            relay_close.operation,
            relay_close.category,
            client_close_reason,
            CLIENT_CONTROL_CLOSE_DETAIL,
            stale_owner_cleared_ms,
            fresh.epoch,
        );
        Ok::<(), HarnessError>(())
    }
    .await;

    let client_cleanup = stop_client(&mut client).await;
    let process_cleanup = match process.take() {
        Some(process) => {
            shutdown_process(
                process,
                fixture.consumer_bind,
                fixture.device_bind,
                fixture.peer_bind,
            )
            .await
        }
        None => Ok(()),
    };
    let fixture_cleanup = fixture.cleanup().await;
    let process_and_fixture = combine_results(process_cleanup, fixture_cleanup, Ok(()));
    combine_results(primary, client_cleanup, process_and_fixture)
}

async fn create_fixture() -> Result<RestorationFixture> {
    let files = FixtureFiles::new()?;
    let mut partial = PartialFixture::new();
    let result = create_fixture_inner(files, &mut partial).await;
    match result {
        Ok(fixture) => Ok(fixture),
        Err(primary) => match partial.cleanup().await {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(HarnessError::Process(format!(
                "configured restoration fixture setup failed: {primary}; partial cleanup failed: {cleanup}"
            ))),
        },
    }
}

async fn create_fixture_inner(
    files: FixtureFiles,
    partial: &mut PartialFixture,
) -> Result<RestorationFixture> {
    let relay_binary = relay_binary_path()?;
    let upstream_url = env::var("TEST_REDIS_URL").map_err(|_| HarnessError::MissingRedisUrl {
        env_var: "TEST_REDIS_URL",
        guidance: "configured restoration requires TEST_REDIS_URL for disposable catalog seeding"
            .into(),
    })?;
    let upstream = parse_plaintext_upstream(&upstream_url)?;
    let run_id = Uuid::new_v4().simple().to_string();
    let deployment_id = format!("m7-configured-restore-deployment-{run_id}");
    let deployment_incarnation = format!("m7-configured-restore-incarnation-{run_id}");
    let namespace = format!("m7-configured-restore-fixture-{run_id}");
    let node_id = "relay-a".to_owned();

    let pki = FixturePki::new()?;
    let oidc = OidcFixture::new(
        format!("https://m7-configured-restore-oidc-{run_id}.invalid"),
        "agent-tunnel",
    )?;
    let topology = FixtureTopology::new(&pki)?;
    let catalog_fixture = topology.catalog_fixture(&oidc)?;
    let active_device = topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("missing restoration device fixture".into()))?;
    let device_id = active_device.id;
    let service_id = *topology
        .service_ids
        .get(&device_id)
        .ok_or_else(|| HarnessError::InvalidInput("restoration service fixture missing".into()))?;
    let consumer_name = topology
        .consumers_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("missing restoration consumer fixture".into()))?
        .name
        .clone();

    let mut cluster =
        ClusterFixture::with_deployment(&pki, &deployment_id, &deployment_incarnation)?;
    let peer_node = cluster
        .node(&node_id)
        .ok_or_else(|| HarnessError::InvalidInput("restoration relay fixture missing".into()))?;
    let peer_bind = peer_node.addresses.udp;
    let peer_chain = peer_node.peer_certificate_chain_pem();
    let peer_key = peer_node.peer_certificate.private_key_pem.clone();
    let membership = cluster
        .membership(&node_id)
        .ok_or_else(|| HarnessError::InvalidInput("restoration membership missing".into()))?
        .catalog_record();
    cluster
        .node_mut(&node_id)
        .ok_or_else(|| HarnessError::InvalidInput("restoration relay fixture missing".into()))?
        .release_ports();
    let signer = Arc::new(cluster.membership_authority);

    let server_leaf = pki.issue_server("m7-configured-restore-relay")?;
    let checkpoint_leaf = pki.issue_server("m7-configured-restore-checkpoint")?;
    let redis_leaf = pki.issue_server("m7-configured-restore-redis")?;
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
    .map_err(|error| HarnessError::Pki(format!("restoration Redis TLS config: {error}")))?;
    partial.proxy = Some(RestorableRedisTlsProxy::bind(upstream, redis_tls).await?);
    let relay_redis_url = partial
        .proxy
        .as_ref()
        .expect("restorable Redis proxy")
        .url();

    let catalog =
        RedisCatalog::connect_for_recovery(&upstream_url, &namespace, &deployment_incarnation)
            .await
            .map_err(|error| {
                HarnessError::Redis(format!("opening restoration catalog: {error}"))
            })?;
    partial.catalog = Some(catalog);
    let catalog_ref = partial
        .catalog
        .as_ref()
        .expect("restoration catalog retained");
    catalog_ref
        .activate_deployment_incarnation()
        .await
        .map_err(|error| HarnessError::Redis(format!("activating restoration catalog: {error}")))?;
    catalog_ref
        .seed_fixture(&catalog_fixture)
        .await
        .map_err(|error| HarnessError::Redis(format!("seeding restoration catalog: {error}")))?;
    let publisher = RedisMembershipPublisher::connect(&upstream_url, &namespace)
        .await
        .map_err(|error| HarnessError::Redis(format!("opening restoration publisher: {error}")))?;
    publisher
        .publish_signed_membership_for_node(&node_id, &membership)
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("publishing restoration membership: {error}"))
        })?;
    drop(publisher);

    let checkpoint = CheckpointServer::bind(
        load_server_config_from_pem(
            checkpoint_chain.as_bytes(),
            checkpoint_leaf.private_key_pem.as_bytes(),
            None,
        )
        .map_err(|error| {
            HarnessError::Pki(format!("restoration checkpoint TLS config: {error}"))
        })?,
        Arc::clone(&signer),
        deployment_id.clone(),
        deployment_incarnation.clone(),
        BTreeMap::from([(node_id.clone(), membership.version)]),
    )
    .await?;
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
    let peer_chain_path = files.write("peer-cert-chain.pem", peer_chain.as_bytes())?;
    let peer_key_path = files.write("peer-key.pem", peer_key.as_bytes())?;
    let peer_ca_path = files.write("peer-ca.pem", pki.peer_ca.certificate_pem.as_bytes())?;
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
            .checkpoint
            .as_ref()
            .expect("restoration checkpoint")
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
    let client_config = write_client_config(
        &files,
        active_device,
        service_id,
        device_bind,
        &pki.device_ca.certificate_pem,
        &pki.server_ca.certificate_pem,
    )?;
    let token = oidc.issue(&consumer_name)?;

    Ok(RestorationFixture {
        _files: files,
        catalog: partial
            .catalog
            .take()
            .expect("restoration catalog retained"),
        proxy: partial.proxy.take().expect("restoration proxy retained"),
        checkpoint: partial
            .checkpoint
            .take()
            .expect("restoration checkpoint retained"),
        relay_binary,
        config_path,
        client_config,
        token,
        tenant_id: active_device.tenant_id,
        device_id,
        service_id,
        consumer_bind,
        device_bind,
        peer_bind,
        server_ca_der: pki.server_ca.certificate_der.clone(),
    })
}

async fn initialize_state(binary: &Path, config: &Path) -> Result<()> {
    let mut process = ManagedProcess::spawn(
        "m7-configured-restoration-initialize",
        ProcessSpec::new(binary)
            .arg("initialize")
            .arg("--config")
            .arg(config.display().to_string()),
    )
    .await?;
    let status_result = wait_for_exit(&mut process, PROCESS_DEADLINE).await;
    let diagnostic = process_diagnostic(&process);
    let cleanup_result = process.shutdown(SHUTDOWN_GRACE).await;
    let status = match status_result {
        Ok(status) => status,
        Err(error) => {
            return Err(match cleanup_result {
                Ok(cleanup_status) => HarnessError::Process(format!(
                    "restoration initialize wait failed: {error}; cleanup status={cleanup_status}; {diagnostic}"
                )),
                Err(cleanup_error) => HarnessError::Process(format!(
                    "restoration initialize wait failed: {error}; cleanup failed: {cleanup_error}; {diagnostic}"
                )),
            });
        }
    };
    match cleanup_result {
        Ok(cleanup_status) if status.success() && cleanup_status.success() => Ok(()),
        Ok(cleanup_status) => Err(HarnessError::Process(format!(
            "restoration initialize exited {status}; cleanup status={cleanup_status}; {diagnostic}"
        ))),
        Err(cleanup_error) => Err(HarnessError::Process(format!(
            "restoration initialize exited {status}; cleanup failed: {cleanup_error}; {diagnostic}"
        ))),
    }
}

async fn start_relay(fixture: &RestorationFixture) -> Result<ManagedProcess> {
    let mut process = ManagedProcess::spawn(
        "m7-configured-restoration-relay",
        ProcessSpec::new(&fixture.relay_binary)
            .arg("serve")
            .arg("--config")
            .arg(fixture.config_path.display().to_string())
            .env("RUST_LOG", RELAY_LOG_FILTER),
    )
    .await?;
    if let Err(error) =
        wait_for_ready(&mut process, fixture.consumer_bind, &fixture.server_ca_der).await
    {
        let diagnostic = process_diagnostic(&process);
        let cleanup = process.shutdown(SHUTDOWN_GRACE).await;
        return Err(match cleanup {
            Ok(status) => HarnessError::Process(format!(
                "restoration relay readiness: {error}; cleanup status={status}; {diagnostic}"
            )),
            Err(cleanup_error) => HarnessError::Process(format!(
                "restoration relay readiness: {error}; cleanup failed: {cleanup_error}; {diagnostic}"
            )),
        });
    }
    Ok(process)
}

async fn shutdown_process(
    mut process: ManagedProcess,
    consumer_bind: SocketAddr,
    device_bind: SocketAddr,
    peer_bind: SocketAddr,
) -> Result<()> {
    let diagnostic = process_diagnostic(&process);
    let mut failures = Vec::new();
    let observed_status = match process.try_wait() {
        Ok(Some(status)) => Some(status),
        Ok(None) => {
            match process.id() {
                Some(pid) => {
                    if let Err(error) = send_sigint(pid) {
                        failures.push(format!("restoration relay SIGINT: {error}"));
                    }
                }
                None => failures.push("restoration relay PID disappeared".into()),
            }
            match wait_for_exit(&mut process, SHUTDOWN_DEADLINE).await {
                Ok(status) => Some(status),
                Err(error) => {
                    failures.push(format!("restoration relay exit wait: {error}"));
                    None
                }
            }
        }
        Err(error) => {
            failures.push(format!("restoration relay status check: {error}"));
            None
        }
    };
    let joined_status = process.shutdown(SHUTDOWN_GRACE).await;
    match joined_status {
        Ok(status) => {
            if !status.success() {
                failures.push(format!("restoration relay shutdown status: {status}"));
            }
        }
        Err(error) => failures.push(format!("restoration relay cleanup: {error}")),
    }
    if let Some(status) = observed_status
        && !status.success()
    {
        failures.push(format!("restoration relay observed exit status: {status}"));
    }
    if let Err(error) = wait_for_ports_released(consumer_bind, device_bind, peer_bind).await {
        failures.push(format!("restoration relay port cleanup: {error}"));
    }
    if !failures.is_empty() {
        return Err(HarnessError::Process(format!(
            "{}; {diagnostic}",
            failures.join("; ")
        )));
    }
    Ok(())
}

async fn wait_for_unready(
    process: &mut ManagedProcess,
    fixture: &RestorationFixture,
) -> Result<()> {
    let deadline = Instant::now() + DEPENDENCY_DEADLINE;
    loop {
        if let Some(status) = process.try_wait()? {
            return Err(HarnessError::Process(format!(
                "relay exited before Redis readiness withdrawal: {status}"
            )));
        }
        let live = health_request(fixture.consumer_bind, &fixture.server_ca_der, "/livez").await;
        let ready = health_request(fixture.consumer_bind, &fixture.server_ca_der, "/readyz").await;
        if let Ok((status, body)) = live
            && (status != 200 || body.as_slice() != LIVE_BODY)
        {
            return Err(HarnessError::Process(
                "relay liveness failed during Redis withdrawal".into(),
            ));
        }
        if matches!(ready, Ok((503, body)) if body.as_slice() == UNREADY_BODY) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "Redis readiness withdrawal did not converge".into(),
            ));
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_ready_after_restore(
    process: &mut ManagedProcess,
    fixture: &RestorationFixture,
) -> Result<()> {
    let deadline = Instant::now() + DEPENDENCY_DEADLINE;
    loop {
        if let Some(status) = process.try_wait()? {
            return Err(HarnessError::Process(format!(
                "relay exited before Redis readiness recovery: {status}"
            )));
        }
        if let (Ok((live_status, live_body)), Ok((ready_status, ready_body))) = (
            health_request(fixture.consumer_bind, &fixture.server_ca_der, "/livez").await,
            health_request(fixture.consumer_bind, &fixture.server_ca_der, "/readyz").await,
        ) && live_status == 200
            && live_body.as_slice() == LIVE_BODY
            && ready_status == 200
            && ready_body.as_slice() == READY_BODY
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "Redis readiness recovery did not converge".into(),
            ));
        }
        sleep(Duration::from_millis(100)).await;
    }
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
            "health {path} mismatch: status={status} body_len={}",
            body.len()
        )));
    }
    Ok(())
}

async fn connect_fresh(config: &ConnectConfig) -> Result<tunnel_client::ConnectionHandle> {
    timeout(
        CLIENT_DEADLINE,
        connect(ConnectOptions::new(config.clone())),
    )
    .await
    .map_err(|_| HarnessError::Timeout("restoration device connect deadline".into()))?
    .map_err(|error| HarnessError::Process(format!("restoration device connect: {error}")))
}

async fn wait_for_client_ready(
    client: &mut tunnel_client::ConnectionHandle,
) -> Result<SessionInfo> {
    timeout(CLIENT_DEADLINE, client.wait_ready())
        .await
        .map_err(|_| HarnessError::Timeout("restoration device DataReady deadline".into()))?
        .map_err(|error| HarnessError::Process(format!("restoration device DataReady: {error}")))
}

/// Wait for the relay to close the pre-fault device session after Redis
/// loss.  The client reports a relay-initiated control close as
/// `Readiness::Closed` with its typed transport reason; any other terminal
/// reason, or no close before the bounded deadline, fails the gate.
async fn wait_for_dependency_close(client: &tunnel_client::ConnectionHandle) -> Result<String> {
    let mut readiness = client.readiness();
    let deadline = tokio::time::Instant::now() + DEPENDENCY_DEADLINE;
    loop {
        let state = readiness.borrow().clone();
        if let Readiness::Closed { reason } = state {
            if reason != CLIENT_CONTROL_CLOSE_REASON {
                return Err(HarnessError::Process(format!(
                    "pre-fault device session closed with reason {reason:?} instead of the relay control close {CLIENT_CONTROL_CLOSE_REASON:?}"
                )));
            }
            return Ok(reason);
        }
        match timeout_at(deadline, readiness.changed()).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                return Err(HarnessError::Process(
                    "pre-fault device readiness channel ended before the relay closed the session"
                        .into(),
                ));
            }
            Err(_) => {
                return Err(HarnessError::Timeout(
                    "relay did not close the pre-fault device session after Redis loss".into(),
                ));
            }
        }
    }
}

/// Join the pre-fault device supervisor.  Only the exact typed error for a
/// relay-initiated clean control close is accepted here, and only because
/// Redis was deliberately made unavailable first: a clean `Ok` means the
/// relay never closed the session, and any other error is a different fault.
async fn stop_dependency_closed_client(
    client: &mut Option<tunnel_client::ConnectionHandle>,
) -> Result<()> {
    let Some(handle) = client.as_ref() else {
        return Err(HarnessError::Process(
            "pre-fault device handle was missing before its dependency close was joined".into(),
        ));
    };
    match timeout(CLIENT_DEADLINE, handle.stop()).await {
        Ok(Err(ClientError::Transport {
            scope: CLIENT_CONTROL_CLOSE_SCOPE,
            detail,
        })) if detail == CLIENT_CONTROL_CLOSE_DETAIL => {
            let _ = client.take();
            Ok(())
        }
        Ok(Err(ClientError::Transport { scope, detail })) => {
            let _ = client.take();
            Err(HarnessError::Process(format!(
                "pre-fault device stop reported transport scope={scope:?} detail={:?} instead of the relay's clean control close",
                truncate(&detail)
            )))
        }
        Ok(Err(error)) => {
            let _ = client.take();
            Err(HarnessError::Process(format!(
                "pre-fault device stop reported {} ({error}) instead of the relay's clean control close",
                error.code()
            )))
        }
        Ok(Ok(())) => {
            let _ = client.take();
            Err(HarnessError::Process(
                "pre-fault device stop completed cleanly; the relay did not close the session after Redis loss"
                    .into(),
            ))
        }
        Err(_) => Err(HarnessError::Timeout(
            "pre-fault device stop exceeded its bounded deadline; handle retained for cleanup"
                .into(),
        )),
    }
}

/// The relay's typed close evidence for one exact device session.
struct RelayDependencyClose {
    reason: &'static str,
    operation: String,
    category: String,
}

/// Bounded structured fields of one relay JSON log line, or `None` when the
/// line is not a JSON event.
fn relay_log_fields(line: &str) -> Option<serde_json::Map<String, serde_json::Value>> {
    let value: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    let object = value.as_object()?;
    match object.get("fields").and_then(serde_json::Value::as_object) {
        Some(fields) => Some(fields.clone()),
        None => Some(object.clone()),
    }
}

fn field_str<'a>(
    fields: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<&'a str> {
    fields.get(key).and_then(serde_json::Value::as_str)
}

/// Wait for the relay's own structured diagnostics to attribute the close of
/// the exact pre-fault session to a failed authority check.  The relay logs
/// `owner_check_failed` with its closed reason/operation/category vocabulary
/// and then `session_closed`; both must name this session, epoch and device,
/// and the reason must be the authority-loss reason rather than a fence,
/// revocation or protocol close.
async fn wait_for_relay_dependency_close(
    process: &ManagedProcess,
    session: &SessionInfo,
    device_id: Uuid,
) -> Result<RelayDependencyClose> {
    let deadline = Instant::now() + RELAY_EVIDENCE_DEADLINE;
    let device_id = device_id.to_string();
    loop {
        let stderr = process.stderr();
        let stderr = String::from_utf8_lossy(&stderr);
        let mut check_failed: Option<(String, String)> = None;
        let mut closed = false;
        let mut other_reasons = Vec::new();
        for fields in stderr.lines().filter_map(relay_log_fields) {
            if field_str(&fields, "session_id") != Some(session.session_id.as_str())
                || fields.get("epoch").and_then(serde_json::Value::as_u64) != Some(session.epoch)
                || field_str(&fields, "device_id") != Some(device_id.as_str())
            {
                continue;
            }
            let reason = field_str(&fields, "reason").map(str::to_owned);
            match field_str(&fields, "phase") {
                Some("owner_check_failed") => match reason.as_deref() {
                    Some(DEPENDENCY_CLOSE_REASON) => {
                        let operation = field_str(&fields, "authority_operation")
                            .unwrap_or("missing")
                            .to_owned();
                        let category = field_str(&fields, "authority_category")
                            .unwrap_or("missing")
                            .to_owned();
                        check_failed = Some((operation, category));
                    }
                    Some(other) => other_reasons.push(format!("owner_check_failed:{other}")),
                    None => other_reasons.push("owner_check_failed:missing".to_owned()),
                },
                Some("session_closed") => match reason.as_deref() {
                    Some(DEPENDENCY_CLOSE_REASON) => closed = true,
                    Some(other) => other_reasons.push(format!("session_closed:{other}")),
                    None => other_reasons.push("session_closed:missing".to_owned()),
                },
                _ => {}
            }
        }
        if !other_reasons.is_empty() {
            return Err(HarnessError::Process(format!(
                "relay attributed the pre-fault session terminal path to {} instead of {DEPENDENCY_CLOSE_REASON}",
                other_reasons.join(",")
            )));
        }
        let check_failed_seen = check_failed.is_some();
        if let Some((operation, category)) = check_failed
            && closed
        {
            if !DEPENDENCY_CLOSE_OPERATIONS.contains(&operation.as_str()) {
                return Err(HarnessError::Process(format!(
                    "relay authority check failed in unexpected operation {operation}"
                )));
            }
            if !DEPENDENCY_CLOSE_CATEGORIES.contains(&category.as_str()) {
                return Err(HarnessError::Process(format!(
                    "relay authority failure category {category} is not the injected Redis transport loss"
                )));
            }
            return Ok(RelayDependencyClose {
                reason: DEPENDENCY_CLOSE_REASON,
                operation,
                category,
            });
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "relay diagnostics did not record the {DEPENDENCY_CLOSE_REASON} close of the pre-fault session (check_failed={check_failed_seen} session_closed={closed})"
            )));
        }
        sleep(Duration::from_millis(50)).await;
    }
}

/// Wait for the pre-fault session's owner token to disappear from Redis.
/// The relay could not release it while Redis was unreachable, so only lease
/// expiry may clear it; a different live owner would mean an unexpected
/// takeover and fails the gate.
async fn wait_for_stale_owner_clear(
    fixture: &RestorationFixture,
    session: &SessionInfo,
) -> Result<u64> {
    let started = Instant::now();
    let deadline = started + OWNER_LEASE_CLEAR_DEADLINE;
    loop {
        let owner = timeout(
            Duration::from_secs(5),
            fixture
                .catalog
                .current_owner(fixture.tenant_id, fixture.device_id, Utc::now()),
        )
        .await
        .map_err(|_| HarnessError::Timeout("stale owner read exceeded its deadline".into()))?
        .map_err(|error| HarnessError::Redis(format!("reading stale owner token: {error}")))?;
        match owner {
            None => return Ok(started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64),
            Some(owner)
                if owner.token.session_id == session.session_id
                    && owner.token.epoch == session.epoch => {}
            Some(owner) => {
                return Err(HarnessError::Process(format!(
                    "unexpected owner token during restoration: node={} epoch={} expected_stale_epoch={}",
                    owner.token.node_id, owner.token.epoch, session.epoch
                )));
            }
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "stale owner token did not clear within the owner lease bound".into(),
            ));
        }
        sleep(Duration::from_millis(200)).await;
    }
}

async fn stop_client(client: &mut Option<tunnel_client::ConnectionHandle>) -> Result<()> {
    let Some(handle) = client.as_ref() else {
        return Ok(());
    };
    // ConnectionHandle::stop keeps its supervisor JoinHandle in the lifecycle
    // mutex until the await completes. If this outer timeout fires, the
    // handle remains owned by the ConnectionHandle, so the bounded retry below
    // joins the same supervisor rather than retrying an already-taken handle.
    match timeout(CLIENT_DEADLINE, handle.stop()).await {
        Ok(Ok(())) => {
            let _ = client.take();
            Ok(())
        }
        Ok(Err(error)) => {
            let _ = client.take();
            Err(HarnessError::Process(format!(
                "restoration device stop: {error}"
            )))
        }
        Err(_) => match timeout(CLIENT_DEADLINE, handle.stop()).await {
            Ok(Ok(())) => {
                let _ = client.take();
                Err(HarnessError::Timeout(
                    "restoration device stop exceeded its first bounded deadline; retry joined"
                        .into(),
                ))
            }
            Ok(Err(error)) => {
                let _ = client.take();
                Err(HarnessError::Process(format!(
                    "restoration device stop failed after its first bounded deadline: {error}"
                )))
            }
            Err(_) => Err(HarnessError::Timeout(
                "restoration device stop exceeded bounded retry; handle retained for cleanup"
                    .into(),
            )),
        },
    }
}

async fn expect_echo(fixture: &RestorationFixture, phase: &str) -> Result<()> {
    let attempt = attempt_echo(fixture, phase).await?;
    let EchoOutcome::Http { status, body } = attempt else {
        return Err(HarnessError::Http(format!(
            "{phase} authenticated echo ended at transport boundary"
        )));
    };
    let mut expected = Vec::with_capacity(CANARY.len() + PAYLOAD.len());
    expected.extend_from_slice(CANARY.as_bytes());
    expected.extend_from_slice(PAYLOAD);
    if status != 200 || body != expected {
        return Err(HarnessError::Http(format!(
            "{phase} authenticated echo mismatch: status={status} body_len={} typed={}",
            body.len(),
            typed_error_summary(&body)
        )));
    }
    Ok(())
}

/// The closed `code`/`execution` fields of a relay typed error body, when the
/// response is one.  Only those fixed fields are reported; the message and
/// any other content stay out of the diagnostic.
fn typed_error_summary(body: &[u8]) -> String {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return "none".to_owned();
    };
    let code = value
        .get("code")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("missing");
    let execution = value
        .get("execution")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("missing");
    format!("{code}/{execution}")
}

async fn attempt_echo(fixture: &RestorationFixture, phase: &str) -> Result<EchoOutcome> {
    let deadline = tokio::time::Instant::now() + ECHO_DEADLINE;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            fixture.server_ca_der.clone(),
        ))
        .map_err(|error| HarnessError::Http(format!("{phase} echo root: {error}")))?;
    let client_config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|error| HarnessError::Http(format!("{phase} echo TLS: {error}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let stream = timeout_at(deadline, TcpStream::connect(fixture.consumer_bind))
        .await
        .map_err(|_| HarnessError::Timeout(format!("{phase} echo TCP connect")))?
        .map_err(|error| HarnessError::Http(format!("{phase} echo TCP connect: {error}")))?;
    let server_name = rustls::pki_types::ServerName::try_from("localhost".to_owned())
        .map_err(|error| HarnessError::Http(format!("{phase} echo server name: {error}")))?;
    let tls = timeout_at(deadline, connector.connect(server_name, stream))
        .await
        .map_err(|_| HarnessError::Timeout(format!("{phase} echo TLS handshake")))?
        .map_err(|error| HarnessError::Http(format!("{phase} echo TLS handshake: {error}")))?;
    let (mut sender, connection) = timeout_at(
        deadline,
        hyper::client::conn::http1::handshake(TokioIo::new(tls)),
    )
    .await
    .map_err(|_| HarnessError::Timeout(format!("{phase} echo HTTP handshake")))?
    .map_err(|error| HarnessError::Http(format!("{phase} echo HTTP handshake: {error}")))?;
    let path = format!(
        "/v1/devices/{}/services/{}/echo",
        fixture.device_id, fixture.service_id
    );
    let request = Request::builder()
        .method("POST")
        .uri(format!("https://localhost{path}"))
        .header("host", "localhost")
        .header("authorization", format!("Bearer {}", fixture.token))
        .header("content-type", "application/octet-stream")
        .body(Full::new(Bytes::copy_from_slice(PAYLOAD)))
        .map_err(|error| HarnessError::Http(format!("{phase} echo request: {error}")))?;
    // Build every fallible request value before beginning the local Hyper
    // poll. The request and connection futures are selected together under
    // one deadline, so a construction failure or timeout cannot strand an
    // owned connection future.
    let outcome = timeout_at(deadline, async move {
        tokio::select! {
            result = async move {
                let response = match sender.send_request(request).await {
                    Ok(response) => response,
                    Err(_) => return EchoOutcome::Transport,
                };
                let status = response.status().as_u16();
                let body = match Limited::new(response.into_body(), 256 * 1024).collect().await {
                    Ok(body) => body.to_bytes().to_vec(),
                    Err(_) => return EchoOutcome::Transport,
                };
                EchoOutcome::Http { status, body }
            } => result,
            connection_result = connection => {
                let _ = connection_result;
                EchoOutcome::Transport
            }
        }
    })
    .await;
    Ok(outcome.unwrap_or(EchoOutcome::Transport))
}

enum EchoOutcome {
    Http { status: u16, body: Vec<u8> },
    Transport,
}

struct UnreadyBoundaryEvidence {
    status: u16,
    code: &'static str,
    execution: &'static str,
    body_len: usize,
    no_premature_dispatch: bool,
}

fn validate_unready_boundary(outcome: &EchoOutcome) -> Result<UnreadyBoundaryEvidence> {
    let EchoOutcome::Http { status, body } = outcome else {
        return Err(HarnessError::Process(format!(
            "authenticated echo while Redis was unready ended at {}; exact typed readiness gate was not observed",
            echo_outcome_summary(outcome)
        )));
    };
    if *status != 503 {
        return Err(HarnessError::Process(format!(
            "authenticated echo while Redis was unready returned status={status}; exact typed readiness gate requires status=503"
        )));
    }
    if body.len() > 4 * 1024 {
        return Err(HarnessError::Process(format!(
            "authenticated echo readiness error body exceeded bounded diagnostic limit: body_len={}",
            body.len()
        )));
    }
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| {
        HarnessError::Process(format!(
            "authenticated echo readiness error was not bounded JSON: body_len={}",
            body.len()
        ))
    })?;
    let object = value.as_object().ok_or_else(|| {
        HarnessError::Process(format!(
            "authenticated echo readiness error was not a JSON object: body_len={}",
            body.len()
        ))
    })?;
    if object.len() != 3
        || !object.contains_key("code")
        || !object.contains_key("execution")
        || !object.contains_key("message")
    {
        return Err(HarnessError::Process(format!(
            "authenticated echo readiness error had an unexpected redacted shape: body_len={}",
            body.len()
        )));
    }
    let code = object.get("code").and_then(serde_json::Value::as_str);
    let execution = object.get("execution").and_then(serde_json::Value::as_str);
    let message = object.get("message").and_then(serde_json::Value::as_str);
    if code != Some("CLUSTER_UNREADY")
        || execution != Some("not_dispatched")
        || message != Some("cluster readiness unavailable")
    {
        return Err(HarnessError::Process(format!(
            "authenticated echo readiness error was not CLUSTER_UNREADY/not_dispatched: body_len={}",
            body.len()
        )));
    }
    Ok(UnreadyBoundaryEvidence {
        status: *status,
        code: "CLUSTER_UNREADY",
        execution: "not_dispatched",
        body_len: body.len(),
        // This is a claim about the checked public admission boundary, not a
        // generic inference from a non-200 response. `http.rs` emits this
        // exact typed response before body forwarding when the cluster is
        // unready; the source-proof artifact records that boundary.
        no_premature_dispatch: true,
    })
}

fn echo_outcome_summary(outcome: &EchoOutcome) -> String {
    match outcome {
        EchoOutcome::Http { status, body } => {
            format!("http status={status} body_len={}", body.len())
        }
        EchoOutcome::Transport => "transport".into(),
    }
}

fn write_client_config(
    files: &FixtureFiles,
    device: &tunnel_test_harness::DeviceFixture,
    service_id: Uuid,
    device_bind: SocketAddr,
    device_ca_pem: &str,
    server_ca_pem: &str,
) -> Result<ConnectConfig> {
    let certificate_path = files.write(
        "device-cert.pem",
        format!("{}{}", device.certificate.certificate_pem, device_ca_pem).as_bytes(),
    )?;
    let key_path = files.write(
        "device-key.pem",
        device.certificate.private_key_pem.as_bytes(),
    )?;
    let server_ca_path = files.write("device-server-ca.pem", server_ca_pem.as_bytes())?;
    let config = ConnectConfig {
        device_id: device.id.to_string(),
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
            },
        )]),
        limits: LimitsConfig::default(),
        rotation: RotationConfig::default(),
    };
    config.validate().map_err(|error| {
        HarnessError::InvalidInput(format!("restoration client config: {error}"))
    })?;
    Ok(config)
}

struct RestorableRedisTlsProxy {
    address: SocketAddr,
    availability: watch::Sender<bool>,
    cancellation: CancellationToken,
    handshakes: Arc<AtomicUsize>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
}

impl RestorableRedisTlsProxy {
    async fn bind(upstream: SocketAddr, server_config: Arc<rustls::ServerConfig>) -> Result<Self> {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (availability, _) = watch::channel(true);
        let cancellation = CancellationToken::new();
        let handshakes = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(run_restorable_proxy(
            listener,
            upstream,
            TlsAcceptor::from(server_config),
            availability.subscribe(),
            cancellation.clone(),
            handshakes.clone(),
        ));
        sleep(Duration::from_millis(1)).await;
        Ok(Self {
            address,
            availability,
            cancellation,
            handshakes,
            task: Some(task),
        })
    }

    fn url(&self) -> String {
        format!("rediss://localhost:{}/0", self.address.port())
    }

    fn set_available(&self, available: bool) -> Result<()> {
        self.availability
            .send(available)
            .map_err(|_| HarnessError::Proxy("restorable Redis gate has no supervisor".into()))
    }

    async fn shutdown(mut self, require_activity: bool) -> Result<()> {
        self.cancellation.cancel();
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        match timeout(AUXILIARY_SHUTDOWN_DEADLINE, &mut task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => return Err(error),
            Ok(Err(error)) => {
                return Err(HarnessError::Proxy(format!(
                    "restorable Redis supervisor join failed: {error}"
                )));
            }
            Err(_) => {
                task.abort();
                let _ = task.await;
                return Err(HarnessError::Timeout(
                    "restorable Redis supervisor shutdown".into(),
                ));
            }
        }
        if require_activity && self.handshakes.load(Ordering::Acquire) == 0 {
            return Err(HarnessError::Proxy(format!(
                "restorable Redis proxy at {} completed no TLS handshake",
                self.address
            )));
        }
        Ok(())
    }

    async fn shutdown_allow_unused(self) -> Result<()> {
        self.shutdown(false).await
    }
}

impl Drop for RestorableRedisTlsProxy {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn run_restorable_proxy(
    listener: TokioTcpListener,
    upstream: SocketAddr,
    acceptor: TlsAcceptor,
    availability: watch::Receiver<bool>,
    cancellation: CancellationToken,
    handshakes: Arc<AtomicUsize>,
) -> Result<()> {
    let mut connections = JoinSet::new();
    let mut active_connections = 0_usize;
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => {
                connections.abort_all();
                while let Some(joined) = connections.join_next().await {
                    if let Err(error) = joined && !error.is_cancelled() {
                        return Err(HarnessError::Proxy(format!("restorable Redis connection join: {error}")));
                    }
                }
                return Ok(());
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(|error| HarnessError::Proxy(format!("restorable Redis accept: {error}")))?;
                if active_connections >= AUXILIARY_CONNECTION_LIMIT {
                    drop(stream);
                    continue;
                }
                connections.spawn(run_restorable_connection(
                    stream,
                    upstream,
                    acceptor.clone(),
                    availability.clone(),
                    cancellation.clone(),
                    handshakes.clone(),
                ));
                active_connections += 1;
            }
            Some(joined) = connections.join_next(), if active_connections > 0 => {
                active_connections = active_connections.saturating_sub(1);
                if let Err(error) = joined && !error.is_cancelled() {
                    return Err(HarnessError::Proxy(format!("restorable Redis connection join: {error}")));
                }
            }
        }
    }
}

async fn run_restorable_connection(
    stream: TcpStream,
    upstream: SocketAddr,
    acceptor: TlsAcceptor,
    mut availability: watch::Receiver<bool>,
    cancellation: CancellationToken,
    handshakes: Arc<AtomicUsize>,
) {
    let _ = timeout(AUXILIARY_CONNECTION_DEADLINE, async move {
        let mut tls = tokio::select! {
            _ = cancellation.cancelled() => return,
            accepted = acceptor.accept(stream) => match accepted {
                Ok(tls) => tls,
                Err(_) => return,
            },
        };
        handshakes.fetch_add(1, Ordering::Release);
        if !*availability.borrow() {
            return;
        }
        let mut upstream_stream = tokio::select! {
            _ = cancellation.cancelled() => return,
            _ = wait_until_unavailable(&mut availability) => return,
            connected = TcpStream::connect(upstream) => match connected {
                Ok(stream) => stream,
                Err(_) => return,
            },
        };
        tokio::select! {
            _ = cancellation.cancelled() => {}
            _ = wait_until_unavailable(&mut availability) => {}
            _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream_stream) => {}
        }
    })
    .await;
}

async fn wait_until_unavailable(availability: &mut watch::Receiver<bool>) {
    while *availability.borrow() {
        if availability.changed().await.is_err() {
            return;
        }
    }
}

fn combine_results(first: Result<()>, second: Result<()>, third: Result<()>) -> Result<()> {
    let mut errors = Vec::new();
    if let Err(error) = first {
        errors.push(error);
    }
    if let Err(error) = second {
        errors.push(error);
    }
    if let Err(error) = third {
        errors.push(error);
    }
    match errors.len() {
        0 => Ok(()),
        1 => Err(errors.remove(0)),
        _ => Err(HarnessError::Process(
            errors
                .into_iter()
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
                .join("; "),
        )),
    }
}
