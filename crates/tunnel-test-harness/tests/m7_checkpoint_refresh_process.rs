//! Configured-process checkpoint refresh acceptance.
//!
//! This gate uses the real relay executable, Redis catalog and TLS forwarder,
//! while keeping the checkpoint authority in a bounded test-local HTTPS
//! server.  The authority can deliberately return an authentic lower or
//! equal-version checkpoint after a valid refresh so the process boundary is
//! exercised without changing production authority code.
//!
//! The test is ignored by the ordinary workspace suite because it requires
//! TEST_REDIS_URL and the root-built relay binary.

// The harness library is Unix-only (see `src/entry.rs`).
#![cfg(unix)]

use std::{
    collections::BTreeMap,
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use chrono::Utc;
use serde::Deserialize;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener as TokioTcpListener, TcpStream},
    sync::Mutex as AsyncMutex,
    task::JoinSet,
    time::{sleep, timeout},
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{Catalog, RedisCatalog, RedisMembershipPublisher};
use tunnel_cluster::membership::{MembershipPolicy, MembershipVerifier, PrivateEndpointPolicy};
use tunnel_test_harness::{
    ClusterFixture, FixturePki, HarnessError, ManagedProcess, OidcFixture, ProcessSpec, Result,
};
use tunnel_transport::load_server_config_from_pem;
use uuid::Uuid;

#[path = "common/m7_deployment.rs"]
mod common;
use common::{
    AUXILIARY_CONNECTION_DEADLINE, AUXILIARY_CONNECTION_LIMIT, AUXILIARY_SHUTDOWN_DEADLINE,
    FixtureFiles, ProcessConfigFixture, RedisTlsProxy, drain_aborted_connections, free_tcp_addr,
    health_request, hex_encode, join_connection, jwks_json, parse_plaintext_upstream,
    process_diagnostic, read_http_body, relay_binary_path, send_sigint, wait_for_exit,
    wait_for_ports_released, wait_for_ready,
};

const PROCESS_DEADLINE: Duration = Duration::from_secs(8);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(6);
const SCENARIO_DEADLINE: Duration = Duration::from_secs(45);
const CLEANUP_DEADLINE: Duration = Duration::from_secs(12);
const MAX_OBSERVATIONS: usize = 64;

#[derive(Clone, Copy)]
struct ScenarioDeadline {
    end: Instant,
}

impl ScenarioDeadline {
    fn new(duration: Duration) -> Self {
        Self {
            end: Instant::now() + duration,
        }
    }

    fn remaining(self, phase: &str) -> Result<Duration> {
        let remaining = self.end.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HarnessError::Timeout(format!(
                "{phase} exceeded the shared absolute deadline"
            )));
        }
        Ok(remaining)
    }

    fn cap(self, duration: Duration, phase: &str) -> Result<Duration> {
        Ok(self.remaining(phase)?.min(duration))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum RefreshMode {
    Fresh = 0,
    EqualConflict = 1,
    Stale = 2,
}

impl RefreshMode {
    fn from_byte(value: u8) -> Self {
        match value {
            1 => Self::EqualConflict,
            2 => Self::Stale,
            _ => Self::Fresh,
        }
    }
}

#[derive(Clone, Debug)]
struct CheckpointObservation {
    mode: RefreshMode,
    version: u64,
    nonce: String,
    response: Vec<u8>,
}

struct MutableCheckpointState {
    mode: AtomicU8,
    next_version: AtomicU64,
    minimum_versions: Mutex<BTreeMap<String, u64>>,
    observations: Mutex<Vec<CheckpointObservation>>,
    request_gate: AsyncMutex<()>,
}

impl MutableCheckpointState {
    fn new(minimum_versions: BTreeMap<String, u64>) -> Arc<Self> {
        Arc::new(Self {
            mode: AtomicU8::new(RefreshMode::Fresh as u8),
            next_version: AtomicU64::new(0),
            minimum_versions: Mutex::new(minimum_versions),
            observations: Mutex::new(Vec::new()),
            request_gate: AsyncMutex::new(()),
        })
    }

    async fn transition_mode(&self, mode: RefreshMode, deadline: ScenarioDeadline) -> Result<()> {
        let remaining = deadline.remaining("checkpoint mode transition")?;
        let _request_gate = timeout(remaining, self.request_gate.lock())
            .await
            .map_err(|_| {
                HarnessError::Timeout("checkpoint mode transition did not drain requests".into())
            })?;
        self.mode.store(mode as u8, Ordering::Release);
        Ok(())
    }

    fn issue(&self) -> (RefreshMode, u64) {
        let mode = RefreshMode::from_byte(self.mode.load(Ordering::Acquire));
        let current = self.next_version.load(Ordering::Acquire);
        let version = match mode {
            RefreshMode::Fresh => self.next_version.fetch_add(1, Ordering::AcqRel) + 1,
            RefreshMode::EqualConflict => current.max(1),
            RefreshMode::Stale => current.saturating_sub(1).max(1),
        };
        (mode, version)
    }

    fn record(&self, observation: CheckpointObservation) {
        let mut observations = self
            .observations
            .lock()
            .expect("checkpoint observations mutex");
        if observations.len() == MAX_OBSERVATIONS {
            observations.remove(0);
        }
        observations.push(observation);
    }

    fn observations(&self) -> Vec<CheckpointObservation> {
        self.observations
            .lock()
            .expect("checkpoint observations mutex")
            .clone()
    }

    fn latest_fresh(&self) -> Option<CheckpointObservation> {
        self.observations()
            .into_iter()
            .rev()
            .find(|observation| observation.mode == RefreshMode::Fresh)
    }

    fn advance_minimum_version(&self, node_id: &str, version: u64) -> Result<()> {
        if version == 0 {
            return Err(HarnessError::InvalidInput(
                "checkpoint minimum membership version must be non-zero".into(),
            ));
        }
        let mut minimum_versions = self
            .minimum_versions
            .lock()
            .map_err(|_| HarnessError::Process("checkpoint minimum mutex poisoned".into()))?;
        if minimum_versions
            .get(node_id)
            .is_some_and(|current| version < *current)
        {
            return Err(HarnessError::Process(
                "checkpoint minimum membership version would roll back".into(),
            ));
        }
        minimum_versions.insert(node_id.to_owned(), version);
        Ok(())
    }

    fn minimum_versions(&self) -> BTreeMap<String, u64> {
        self.minimum_versions
            .lock()
            .expect("checkpoint minimum mutex")
            .clone()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointRequestWire {
    deployment_id: String,
    deployment_incarnation: String,
    nonce: String,
}

struct MutableCheckpointContext {
    authority: Arc<tunnel_test_harness::cluster_fixture::TestMembershipAuthority>,
    deployment_id: String,
    deployment_incarnation: String,
    state: Arc<MutableCheckpointState>,
}

struct MutableCheckpointServer {
    address: SocketAddr,
    state: Arc<MutableCheckpointState>,
    cancellation: CancellationToken,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
}

impl MutableCheckpointServer {
    async fn bind(
        server_config: Arc<rustls::ServerConfig>,
        authority: Arc<tunnel_test_harness::cluster_fixture::TestMembershipAuthority>,
        deployment_id: String,
        deployment_incarnation: String,
        minimum_versions: BTreeMap<String, u64>,
    ) -> Result<Self> {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let state = MutableCheckpointState::new(minimum_versions);
        let context = Arc::new(MutableCheckpointContext {
            authority,
            deployment_id,
            deployment_incarnation,
            state: Arc::clone(&state),
        });
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(run_mutable_checkpoint_server(
            listener,
            TlsAcceptor::from(server_config),
            context,
            cancellation.clone(),
        ));
        sleep(Duration::from_millis(1)).await;
        Ok(Self {
            address,
            state,
            cancellation,
            task: Some(task),
        })
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn state(&self) -> Arc<MutableCheckpointState> {
        Arc::clone(&self.state)
    }

    async fn shutdown(mut self) -> Result<()> {
        self.cancellation.cancel();
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        match timeout(AUXILIARY_SHUTDOWN_DEADLINE, &mut task).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(error))) => Err(error),
            Ok(Err(error)) => Err(HarnessError::Http(format!(
                "checkpoint refresh authority supervisor join failed: {error}"
            ))),
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err(HarnessError::Timeout(
                    "checkpoint refresh authority shutdown".into(),
                ))
            }
        }
    }
}

impl Drop for MutableCheckpointServer {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn run_mutable_checkpoint_server(
    listener: TokioTcpListener,
    acceptor: TlsAcceptor,
    context: Arc<MutableCheckpointContext>,
    cancellation: CancellationToken,
) -> Result<()> {
    let mut connections = JoinSet::new();
    let mut active_connections = 0_usize;
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => {
                connections.abort_all();
                drain_aborted_connections(&mut connections, "checkpoint refresh authority").await?;
                return Ok(());
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        connections.abort_all();
                        drain_aborted_connections(&mut connections, "checkpoint refresh authority").await?;
                        return Err(HarnessError::Http(format!(
                            "checkpoint refresh authority accept failed: {error}"
                        )));
                    }
                };
                if active_connections >= AUXILIARY_CONNECTION_LIMIT {
                    drop(stream);
                    continue;
                }
                connections.spawn(run_mutable_checkpoint_connection(
                    stream,
                    acceptor.clone(),
                    Arc::clone(&context),
                    cancellation.clone(),
                ));
                active_connections += 1;
            }
            Some(joined) = connections.join_next(), if active_connections > 0 => {
                active_connections -= 1;
                join_connection(joined, "checkpoint refresh authority")?;
            }
        }
    }
}

async fn run_mutable_checkpoint_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    context: Arc<MutableCheckpointContext>,
    cancellation: CancellationToken,
) {
    let _ = timeout(AUXILIARY_CONNECTION_DEADLINE, async move {
        let _request_gate = context.state.request_gate.lock().await;
        let mut tls = tokio::select! {
            _ = cancellation.cancelled() => return,
            accepted = acceptor.accept(stream) => match accepted {
                Ok(tls) => tls,
                Err(_) => return,
            },
        };
        let body = tokio::select! {
            _ = cancellation.cancelled() => return,
            body = read_http_body(&mut tls) => match body {
                Ok(body) => body,
                Err(_) => return,
            },
        };
        let Ok(request) = serde_json::from_slice::<CheckpointRequestWire>(&body) else {
            return;
        };
        if request.deployment_id != context.deployment_id
            || request.deployment_incarnation != context.deployment_incarnation
        {
            return;
        }
        let (mode, version) = context.state.issue();
        let Ok(checkpoint) = context.authority.sign_checkpoint_with_version(
            &context.deployment_id,
            &context.deployment_incarnation,
            version,
            request.nonce.clone(),
            context.state.minimum_versions(),
            Utc::now(),
        ) else {
            return;
        };
        let bytes = checkpoint.encoded_bytes().to_vec();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            bytes.len()
        );
        if tokio::select! {
            _ = cancellation.cancelled() => true,
            result = tls.write_all(response.as_bytes()) => result.is_err(),
        } {
            return;
        }
        if tokio::select! {
            _ = cancellation.cancelled() => true,
            result = tls.write_all(&bytes) => result.is_err(),
        } {
            return;
        }
        context.state.record(CheckpointObservation {
            mode,
            version,
            nonce: request.nonce,
            response: bytes,
        });
        tokio::select! {
            _ = cancellation.cancelled() => {}
            _ = tls.shutdown() => {}
        }
    })
    .await;
}

struct ProcessFixture {
    _files: FixtureFiles,
    catalog: RedisCatalog,
    redis_proxy: RedisTlsProxy,
    checkpoint_server: MutableCheckpointServer,
    checkpoint_state: Arc<MutableCheckpointState>,
    deployment_id: String,
    deployment_incarnation: String,
    trusted_publisher: tunnel_cluster::membership::TrustedPublisherKey,
    local_spki_sha256: String,
    state_path: PathBuf,
    membership_publisher: RedisMembershipPublisher,
    initial_membership: tunnel_catalog::SignedMembershipRecord,
    recovery_membership: tunnel_catalog::SignedMembershipRecord,
    relay_binary: PathBuf,
    config_path: PathBuf,
    consumer_bind: SocketAddr,
    device_bind: SocketAddr,
    peer_bind: SocketAddr,
    server_ca_der: Vec<u8>,
}

impl ProcessFixture {
    async fn cleanup(self, deadline: ScenarioDeadline) -> Result<()> {
        let ProcessFixture {
            _files: _,
            catalog,
            redis_proxy,
            checkpoint_server,
            checkpoint_state: _,
            deployment_id: _,
            deployment_incarnation: _,
            trusted_publisher: _,
            local_spki_sha256: _,
            state_path: _,
            membership_publisher: _,
            initial_membership: _,
            recovery_membership: _,
            relay_binary: _,
            config_path: _,
            consumer_bind,
            device_bind,
            peer_bind,
            server_ca_der: _,
        } = self;
        let ports_before = wait_for_ports_within(
            deadline,
            consumer_bind,
            device_bind,
            peer_bind,
            "ports before cleanup",
        )
        .await;
        let catalog_result = match deadline.remaining("catalog cleanup") {
            Ok(remaining) => match timeout(remaining, catalog.cleanup_fixture_namespace()).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(HarnessError::Redis(format!(
                    "cleaning refresh fixture: {error}"
                ))),
                Err(_) => Err(HarnessError::Timeout("refresh catalog cleanup".into())),
            },
            Err(error) => Err(error),
        };
        let checkpoint_result = match deadline.remaining("checkpoint authority cleanup") {
            Ok(remaining) => match timeout(remaining, checkpoint_server.shutdown()).await {
                Ok(result) => result,
                Err(_) => Err(HarnessError::Timeout(
                    "checkpoint refresh authority cleanup".into(),
                )),
            },
            Err(error) => Err(error),
        };
        let redis_result = match deadline.remaining("Redis TLS proxy cleanup") {
            Ok(remaining) => match timeout(remaining, redis_proxy.shutdown_allow_unused()).await {
                Ok(result) => result,
                Err(_) => Err(HarnessError::Timeout("Redis TLS proxy cleanup".into())),
            },
            Err(error) => Err(error),
        };
        let ports_after = wait_for_ports_within(
            deadline,
            consumer_bind,
            device_bind,
            peer_bind,
            "ports after cleanup",
        )
        .await;
        let mut errors = Vec::new();
        if let Err(error) = ports_before {
            errors.push(HarnessError::Process(format!(
                "refresh fixture listener ports were not released before cleanup: {error}"
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
        if let Err(error) = ports_after {
            errors.push(HarnessError::Process(format!(
                "refresh fixture listener ports were not released after cleanup: {error}"
            )));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(combine_errors(errors))
        }
    }
}

async fn wait_for_ports_within(
    deadline: ScenarioDeadline,
    consumer_bind: SocketAddr,
    device_bind: SocketAddr,
    peer_bind: SocketAddr,
    phase: &str,
) -> Result<()> {
    let remaining = deadline.remaining(phase)?;
    timeout(
        remaining,
        wait_for_ports_released(consumer_bind, device_bind, peer_bind),
    )
    .await
    .map_err(|_| HarnessError::Timeout(format!("{phase} exceeded the cleanup deadline")))?
}

#[tokio::test]
#[ignore = "requires TEST_REDIS_URL; run explicitly as the M7-I03 process gate"]
async fn m7_configured_checkpoint_refresh_accepts_fresh_and_rejects_conflicts() {
    run_checkpoint_refresh()
        .await
        .expect("configured checkpoint refresh gate");
}

async fn run_checkpoint_refresh() -> Result<()> {
    let fixture = create_fixture().await?;
    let scenario = ScenarioDeadline::new(SCENARIO_DEADLINE);
    let mut process = None;
    let primary = async {
        initialize_state(&fixture.relay_binary, &fixture.config_path, scenario).await?;
        process = Some(start_relay(&fixture, scenario, "initial fresh").await?);

        wait_for_fresh_refresh(process.as_mut().expect("relay process"), &fixture, scenario)
            .await?;
        let accepted_before_conflict = fixture
            .checkpoint_state
            .latest_fresh()
            .ok_or_else(|| HarnessError::Process("fresh checkpoint was not observed".into()))?;
        fixture
            .checkpoint_state
            .transition_mode(RefreshMode::EqualConflict, scenario)
            .await?;
        wait_for_unready_checkpoint(
            process.as_mut().expect("relay process"),
            &fixture,
            RefreshMode::EqualConflict,
            "equal-version checkpoint conflict",
            scenario,
        )
        .await?;
        stop_relay_slot(&mut process, &fixture, scenario).await?;
        expect_startup_rejection(
            &fixture,
            "equal-version checkpoint conflict",
            RefreshMode::EqualConflict,
            scenario,
        )
        .await?;

        fixture
            .checkpoint_state
            .transition_mode(RefreshMode::Fresh, scenario)
            .await?;
        publish_recovery_membership(&fixture).await?;
        process = Some(
            start_relay(
                &fixture,
                scenario,
                "fresh recovery after equal-version conflict",
            )
            .await?,
        );
        let accepted_before_rollback = wait_for_fresh_version(
            process.as_mut().expect("relay process"),
            &fixture,
            &accepted_before_conflict,
            "fresh checkpoint recovery",
            scenario,
        )
        .await?;
        if accepted_before_rollback.version <= accepted_before_conflict.version {
            return Err(HarnessError::Process(
                "fresh checkpoint recovery did not advance the version".into(),
            ));
        }
        if fixture.recovery_membership.version <= fixture.initial_membership.version {
            return Err(HarnessError::Process(
                "fresh membership recovery did not advance the record version".into(),
            ));
        }
        let checkpoint_minimum = checkpoint_minimum_version(&accepted_before_rollback, "relay-a")?;
        if checkpoint_minimum < fixture.recovery_membership.version {
            return Err(HarnessError::Process(format!(
                "fresh checkpoint recovery minimum {} did not cover membership version {}",
                checkpoint_minimum, fixture.recovery_membership.version
            )));
        }
        fixture
            .checkpoint_state
            .transition_mode(RefreshMode::Stale, scenario)
            .await?;
        wait_for_unready_checkpoint(
            process.as_mut().expect("relay process"),
            &fixture,
            RefreshMode::Stale,
            "stale checkpoint rollback",
            scenario,
        )
        .await?;
        stop_relay_slot(&mut process, &fixture, scenario).await?;
        expect_startup_rejection(
            &fixture,
            "stale checkpoint rollback",
            RefreshMode::Stale,
            scenario,
        )
        .await?;
        Ok(())
    }
    .await;

    let cleanup_deadline = ScenarioDeadline::new(CLEANUP_DEADLINE);
    let process_cleanup = if let Some(process) = process.take() {
        stop_relay(process, cleanup_deadline).await.err()
    } else {
        None
    };
    let fixture_cleanup = fixture.cleanup(cleanup_deadline).await.err();
    let mut errors = Vec::new();
    if let Err(primary) = primary {
        errors.push(primary);
    }
    if let Some(error) = process_cleanup {
        errors.push(HarnessError::Process(format!(
            "refresh relay cleanup failed: {error}"
        )));
    }
    if let Some(error) = fixture_cleanup {
        errors.push(HarnessError::Process(format!(
            "refresh fixture cleanup failed: {error}"
        )));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(combine_errors(errors))
    }
}

async fn create_fixture() -> Result<ProcessFixture> {
    let relay_binary = relay_binary_path()?;
    let upstream_url = env::var("TEST_REDIS_URL").map_err(|_| HarnessError::MissingRedisUrl {
        env_var: "TEST_REDIS_URL",
        guidance: "the checkpoint refresh process gate requires a disposable plaintext Redis upstream for its local TLS forwarder".into(),
    })?;
    let upstream = parse_plaintext_upstream(&upstream_url)?;
    let run_id = Uuid::new_v4().simple().to_string();
    let deployment_id = format!("m7-refresh-deployment-{run_id}");
    let deployment_incarnation = format!("m7-refresh-incarnation-{run_id}");
    let namespace = format!("m7-refresh-fixture-{run_id}");
    let node_id = "relay-a".to_owned();

    let files = FixtureFiles::new()?;
    let pki = FixturePki::new()?;
    let mut cluster =
        ClusterFixture::with_deployment(&pki, &deployment_id, &deployment_incarnation)?;
    let peer_node = cluster
        .node(&node_id)
        .ok_or_else(|| HarnessError::InvalidInput("refresh fixture missing relay-a".into()))?;
    let peer_bind = peer_node.addresses.udp;
    let peer_chain = peer_node.peer_certificate_chain_pem();
    let peer_key = peer_node.peer_certificate.private_key_pem.clone();
    let local_spki_sha256 = peer_node.peer_spki_fingerprint()?;
    let initial_membership = cluster
        .membership(&node_id)
        .ok_or_else(|| HarnessError::InvalidInput("refresh fixture membership missing".into()))?
        .catalog_record();
    cluster
        .node_mut(&node_id)
        .ok_or_else(|| HarnessError::InvalidInput("refresh fixture missing relay-a".into()))?
        .release_ports();
    let recovery_membership = cluster
        .membership_authority
        .sign_membership(
            &deployment_id,
            &deployment_incarnation,
            cluster.node(&node_id).ok_or_else(|| {
                HarnessError::InvalidInput("refresh fixture missing relay-a".into())
            })?,
            initial_membership.version.saturating_add(1),
            Utc::now(),
        )?
        .catalog_record();

    let signer = Arc::new(cluster.membership_authority);
    let trusted_publisher = signer.trusted_key()?;

    let server_leaf = pki.issue_server("m7-refresh-relay")?;
    let checkpoint_leaf = pki.issue_server("m7-refresh-checkpoint")?;
    let redis_leaf = pki.issue_server("m7-refresh-redis")?;
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
    .map_err(|error| HarnessError::Pki(format!("building refresh Redis TLS: {error}")))?;
    let redis_proxy = RedisTlsProxy::bind(upstream, redis_tls).await?;
    let relay_redis_url = redis_proxy.url();

    let catalog =
        RedisCatalog::connect_for_recovery(&upstream_url, &namespace, &deployment_incarnation)
            .await
            .map_err(|error| HarnessError::Redis(format!("opening refresh catalog: {error}")))?;
    catalog
        .activate_deployment_incarnation()
        .await
        .map_err(|error| HarnessError::Redis(format!("activating refresh catalog: {error}")))?;
    let publisher = RedisMembershipPublisher::connect(&upstream_url, &namespace)
        .await
        .map_err(|error| HarnessError::Redis(format!("opening refresh publisher: {error}")))?;
    publisher
        .publish_signed_membership_for_node(&node_id, &initial_membership)
        .await
        .map_err(|error| HarnessError::Redis(format!("publishing refresh membership: {error}")))?;

    let checkpoint_server = MutableCheckpointServer::bind(
        load_server_config_from_pem(
            checkpoint_chain.as_bytes(),
            checkpoint_leaf.private_key_pem.as_bytes(),
            None,
        )
        .map_err(|error| HarnessError::Pki(format!("building refresh checkpoint TLS: {error}")))?,
        Arc::clone(&signer),
        deployment_id.clone(),
        deployment_incarnation.clone(),
        BTreeMap::from([(node_id.clone(), initial_membership.version)]),
    )
    .await?;
    let checkpoint_state = checkpoint_server.state();

    let oidc = OidcFixture::new("https://m7-refresh-oidc.invalid", "agent-tunnel")?;
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
        checkpoint_state,
        deployment_id,
        deployment_incarnation,
        trusted_publisher,
        local_spki_sha256,
        state_path,
        membership_publisher: publisher,
        initial_membership,
        recovery_membership,
        relay_binary,
        config_path,
        consumer_bind,
        device_bind,
        peer_bind,
        server_ca_der: pki.server_ca.certificate_der.clone(),
    })
}

async fn initialize_state(binary: &Path, config: &Path, deadline: ScenarioDeadline) -> Result<()> {
    let mut process = ManagedProcess::spawn(
        "m7-checkpoint-refresh-initialize",
        ProcessSpec::new(binary)
            .arg("initialize")
            .arg("--config")
            .arg(config.display().to_string()),
    )
    .await?;
    let status = match wait_for_exit(
        &mut process,
        deadline.cap(PROCESS_DEADLINE, "membership initialization")?,
    )
    .await
    {
        Ok(status) => status,
        Err(error) => {
            let diagnostic = process_diagnostic(&process);
            let cleanup = process.shutdown(Duration::from_millis(100)).await;
            let mut errors = vec![HarnessError::Process(format!(
                "refresh membership initialization timed out: {error}; {diagnostic}"
            ))];
            if let Err(diagnostic_error) =
                ensure_safe_diagnostic(&diagnostic, "refresh membership initialization")
            {
                errors.push(diagnostic_error);
            }
            if let Err(cleanup_error) = cleanup {
                errors.push(HarnessError::Process(format!(
                    "refresh membership initialization cleanup failed: {cleanup_error}"
                )));
            }
            return Err(combine_errors(errors));
        }
    };
    let diagnostic = process_diagnostic(&process);
    if let Err(error) = process.shutdown(Duration::from_millis(100)).await {
        return Err(HarnessError::Process(format!(
            "refresh membership initialization cleanup failed: {error}; {diagnostic}"
        )));
    }
    ensure_safe_diagnostic(&diagnostic, "refresh membership initialization")?;
    if !status.success() {
        return Err(HarnessError::Process(format!(
            "refresh membership initialization exited {status}; {diagnostic}"
        )));
    }
    Ok(())
}

async fn publish_recovery_membership(fixture: &ProcessFixture) -> Result<()> {
    if fixture.recovery_membership.version <= fixture.initial_membership.version {
        return Err(HarnessError::Process(
            "recovery membership version did not advance the initial record".into(),
        ));
    }
    fixture
        .membership_publisher
        .publish_signed_membership_for_node("relay-a", &fixture.recovery_membership)
        .await
        .map_err(|error| HarnessError::Redis(format!("publishing recovery membership: {error}")))?;
    fixture
        .checkpoint_state
        .advance_minimum_version("relay-a", fixture.recovery_membership.version)
}

fn checkpoint_minimum_version(observation: &CheckpointObservation, node_id: &str) -> Result<u64> {
    let checkpoint =
        serde_json::from_slice::<tunnel_cluster::membership::SignedMembershipCheckpoint>(
            &observation.response,
        )
        .map_err(|_| {
            HarnessError::Process("fresh checkpoint response was not valid JSON".into())
        })?;
    checkpoint
        .minimum_versions
        .get(node_id)
        .copied()
        .ok_or_else(|| {
            HarnessError::Process(format!(
                "fresh checkpoint omitted minimum version for {node_id}"
            ))
        })
}

/// Replay the configured runtime's first bootstrap checks against the same
/// live catalog and certificate identity. This is failure diagnostics only:
/// it reports typed invariant categories and never prints signed bytes.
async fn fixture_observation_diagnostic(fixture: &ProcessFixture) -> String {
    let observations = fixture.checkpoint_state.observations();
    if observations.is_empty() {
        return "no fresh checkpoint response was recorded".into();
    }
    let sequence = observations
        .iter()
        .map(|observation| format!("{:?}/v{}", observation.mode, observation.version))
        .collect::<Vec<_>>()
        .join(",");
    let endpoint_policy = match PrivateEndpointPolicy::allowlisted(
        ["127.0.0.1"],
        ["localhost"],
        [fixture.peer_bind.port()],
    ) {
        Ok(policy) => policy,
        Err(error) => return format!("fixture endpoint policy rejected: {error}"),
    };
    let policy = match MembershipPolicy::new(
        fixture.deployment_id.clone(),
        fixture.deployment_incarnation.clone(),
        endpoint_policy,
    ) {
        Ok(policy) => policy,
        Err(error) => return format!("fixture membership policy rejected: {error}"),
    };
    let mut verifier = match MembershipVerifier::new(policy, [fixture.trusted_publisher.clone()]) {
        Ok(verifier) => verifier,
        Err(error) => return format!("fixture verifier construction failed: {error}"),
    };
    let records = match fixture.catalog.read_signed_memberships().await {
        Ok(records) => records,
        Err(error) => return format!("live Redis membership read failed: {error}"),
    };
    if records.is_empty() {
        return "live Redis membership read returned no records".into();
    }
    let mut catalog_nodes = std::collections::BTreeSet::new();
    for catalog_record in &records {
        let signed = match serde_json::from_slice::<
            tunnel_cluster::membership::SignedMembershipRecord,
        >(&catalog_record.bytes)
        {
            Ok(signed) => signed,
            Err(_) => return "live Redis membership envelope is not signed-record JSON".into(),
        };
        if signed.record_version != catalog_record.version {
            return format!(
                "live Redis membership envelope version mismatch: catalog={} signed={}",
                catalog_record.version, signed.record_version
            );
        }
        if !catalog_nodes.insert(signed.node_id.clone()) {
            return format!(
                "live Redis membership directory duplicated node {}",
                signed.node_id
            );
        }
    }
    let mut expected_equal_conflicts = 0_usize;
    let mut last_minimum = None;
    let mut last_local_version = None;
    for observation in &observations {
        let now = Utc::now();
        let checkpoint = match verifier.verify_checkpoint(
            &observation.response,
            &observation.nonce,
            now,
        ) {
            Ok(checkpoint) => checkpoint,
            Err(error)
                if observation.mode == RefreshMode::EqualConflict
                    && matches!(
                        error,
                        tunnel_cluster::membership::MembershipError::CheckpointEqualVersionConflict { .. }
                    ) =>
            {
                expected_equal_conflicts += 1;
                continue;
            }
            Err(error) => {
                return format!(
                    "checkpoint sequence failed at mode={:?} version={}: {error}; sequence={sequence}",
                    observation.mode, observation.version
                );
            }
        };
        let minimum = checkpoint
            .checkpoint()
            .minimum_versions
            .get("relay-a")
            .copied();
        let Some(minimum) = minimum else {
            return format!(
                "checkpoint sequence omitted local relay-a at mode={:?} version={}; sequence={sequence}",
                observation.mode, observation.version
            );
        };
        for catalog_record in &records {
            let verified = match verifier.verify_membership(&catalog_record.bytes, now) {
                Ok(verified) => verified,
                Err(error) => {
                    return format!(
                        "membership sequence failed at mode={:?} version={} node-version={}: {error}; sequence={sequence}",
                        observation.mode, observation.version, catalog_record.version
                    );
                }
            };
            let Some(active_key) = verified.active_key(now) else {
                return format!(
                    "live Redis membership {} has no active key at mode={:?} version={}; sequence={sequence}",
                    verified.node_id(),
                    observation.mode,
                    observation.version
                );
            };
            if verified.node_id() == "relay-a"
                && active_key.spki_sha256 != fixture.local_spki_sha256
            {
                return format!(
                    "local peer SPKI mismatch at mode={:?} version={}: membership pin length={} local pin length={}; sequence={sequence}",
                    observation.mode,
                    observation.version,
                    active_key.spki_sha256.len(),
                    fixture.local_spki_sha256.len()
                );
            }
        }
        let Some(local_record) = records.iter().find(|record| {
            serde_json::from_slice::<tunnel_cluster::membership::SignedMembershipRecord>(
                &record.bytes,
            )
            .map(|signed| signed.node_id == "relay-a" && record.version >= minimum)
            .unwrap_or(false)
        }) else {
            return format!(
                "checkpoint local minimum relay-a={} has no matching live catalog record at mode={:?} version={}; sequence={sequence}",
                minimum, observation.mode, observation.version
            );
        };
        last_minimum = Some(minimum);
        last_local_version = Some(local_record.version);
    }
    let persisted_state = match std::fs::read(&fixture.state_path) {
        Ok(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(value) => {
                let state = value.get("state");
                let checkpoint = state
                    .and_then(|state| state.get("checkpoint_version"))
                    .and_then(serde_json::Value::as_u64);
                let node_count = state
                    .and_then(|state| state.get("node_versions"))
                    .and_then(serde_json::Value::as_object)
                    .map_or(0, |object| object.len());
                format!("checkpoint={checkpoint:?} node-count={node_count}")
            }
            Err(_) => "state file is not canonical JSON".into(),
        },
        Err(_) => "state file could not be read".into(),
    };
    format!(
        "sequence checks accepted: sequence={sequence} expected-equal-conflicts={expected_equal_conflicts} records={} relay-a-version={:?} checkpoint-minimum={:?} local-SPKI=match persisted-state={persisted_state}",
        records.len(),
        last_local_version,
        last_minimum
    )
}

async fn start_relay(
    fixture: &ProcessFixture,
    deadline: ScenarioDeadline,
    stage: &str,
) -> Result<ManagedProcess> {
    let mut process = ManagedProcess::spawn(
        format!("m7-checkpoint-refresh-relay-{stage}"),
        ProcessSpec::new(&fixture.relay_binary)
            .arg("serve")
            .arg("--config")
            .arg(fixture.config_path.display().to_string()),
    )
    .await?;
    let readiness_phase = format!("{stage} relay startup readiness");
    let readiness = match timeout(
        deadline.remaining(&readiness_phase)?,
        wait_for_ready(&mut process, fixture.consumer_bind, &fixture.server_ca_der),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "relay startup readiness exceeded the shared scenario deadline".into(),
        )),
    };
    if let Err(error) = readiness {
        tokio::task::yield_now().await;
        let diagnostic = process_diagnostic(&process);
        let cleanup = process.shutdown(Duration::from_millis(100)).await;
        let mut errors = vec![HarnessError::Process(format!(
            "{stage} refresh relay did not become ready: {error}; {diagnostic}"
        ))];
        errors.push(HarnessError::Process(format!(
            "{stage} refresh fixture verifier: {}",
            fixture_observation_diagnostic(fixture).await
        )));
        if let Err(diagnostic_error) = ensure_safe_diagnostic(&diagnostic, stage) {
            errors.push(diagnostic_error);
        }
        if let Err(cleanup_error) = cleanup {
            errors.push(HarnessError::Process(format!(
                "{stage} refresh relay startup cleanup failed: {cleanup_error}"
            )));
        }
        return Err(combine_errors(errors));
    }
    Ok(process)
}

async fn stop_relay_slot(
    slot: &mut Option<ManagedProcess>,
    fixture: &ProcessFixture,
    deadline: ScenarioDeadline,
) -> Result<()> {
    let Some(process) = slot.take() else {
        return Ok(());
    };
    let stop_result = stop_relay(process, deadline).await;
    let ports_result = wait_for_ports_within(
        deadline,
        fixture.consumer_bind,
        fixture.device_bind,
        fixture.peer_bind,
        "relay listener release",
    )
    .await;
    let mut errors = Vec::new();
    if let Err(error) = stop_result {
        errors.push(error);
    }
    if let Err(error) = ports_result {
        errors.push(error);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(combine_errors(errors))
    }
}

async fn stop_relay(mut process: ManagedProcess, deadline: ScenarioDeadline) -> Result<()> {
    let mut errors = Vec::new();
    let mut wait_for_signal = true;
    match process.id() {
        Some(pid) => {
            if let Err(error) = send_sigint(pid) {
                errors.push(error);
                wait_for_signal = false;
            }
        }
        None => {
            errors.push(HarnessError::Process(
                "refresh relay exited before controlled shutdown".into(),
            ));
            wait_for_signal = false;
        }
    }

    if wait_for_signal {
        match deadline.cap(SHUTDOWN_DEADLINE, "relay shutdown") {
            Ok(shutdown_deadline) => match wait_for_exit(&mut process, shutdown_deadline).await {
                Ok(status) if !status.success() => errors.push(HarnessError::Process(format!(
                    "refresh relay did not exit successfully after SIGINT: {status}"
                ))),
                Ok(_) => {}
                Err(error) => errors.push(HarnessError::Process(format!(
                    "refresh relay shutdown timed out: {error}"
                ))),
            },
            Err(error) => errors.push(error),
        }
    }

    // ManagedProcess::shutdown performs a bounded kill when the graceful wait
    // failed, then waits for the child and joins its output drains.  Always
    // execute it and retain its error alongside the primary shutdown error.
    if let Err(error) = process.shutdown(Duration::from_millis(100)).await {
        errors.push(HarnessError::Process(format!(
            "refresh relay kill/reap cleanup failed: {error}"
        )));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(combine_errors(errors))
    }
}

async fn expect_startup_rejection(
    fixture: &ProcessFixture,
    label: &str,
    mode: RefreshMode,
    deadline: ScenarioDeadline,
) -> Result<()> {
    let observations_before_launch = fixture.checkpoint_state.observations().len();
    let mut process = ManagedProcess::spawn(
        format!("m7-checkpoint-refresh-reject-{label}"),
        ProcessSpec::new(&fixture.relay_binary)
            .arg("serve")
            .arg("--config")
            .arg(fixture.config_path.display().to_string()),
    )
    .await?;
    let wait_deadline = deadline.cap(PROCESS_DEADLINE, "startup rejection")?;
    let status = match wait_for_exit(&mut process, wait_deadline).await {
        Ok(status) => status,
        Err(error) => {
            let diagnostic = process_diagnostic(&process);
            let cleanup = process.shutdown(Duration::from_millis(100)).await;
            let mut errors = vec![HarnessError::Process(format!(
                "{label} process did not fail closed at startup: {error}; {diagnostic}"
            ))];
            if let Err(diagnostic_error) = ensure_safe_diagnostic(&diagnostic, label) {
                errors.push(diagnostic_error);
            }
            if let Err(cleanup_error) = cleanup {
                errors.push(HarnessError::Process(format!(
                    "{label} startup rejection cleanup failed: {cleanup_error}"
                )));
            }
            return Err(combine_errors(errors));
        }
    };
    let diagnostic = process_diagnostic(&process);
    if let Err(error) = process.shutdown(Duration::from_millis(100)).await {
        return Err(HarnessError::Process(format!(
            "{label} startup rejection cleanup failed: {error}; {diagnostic}"
        )));
    }
    ensure_safe_diagnostic(&diagnostic, label)?;
    if status.success() {
        return Err(HarnessError::Process(format!(
            "{label} process unexpectedly started successfully; {diagnostic}"
        )));
    }
    if !diagnostic.contains("readiness=unready reason=membership_rejected category=membership") {
        return Err(HarnessError::Process(format!(
            "{label} process did not expose the exact membership rejection reason; {diagnostic}"
        )));
    }
    let observations_after_launch = fixture.checkpoint_state.observations();
    if observations_after_launch.len() <= observations_before_launch
        || !observations_after_launch[observations_before_launch..]
            .iter()
            .any(|observation| observation.mode == mode)
    {
        return Err(HarnessError::Process(format!(
            "{label} process did not issue a new mode-specific authority request"
        )));
    }
    wait_for_ports_within(
        deadline,
        fixture.consumer_bind,
        fixture.device_bind,
        fixture.peer_bind,
        "startup rejection listener release",
    )
    .await?;
    Ok(())
}

async fn wait_for_fresh_refresh(
    process: &mut ManagedProcess,
    fixture: &ProcessFixture,
    deadline: ScenarioDeadline,
) -> Result<()> {
    loop {
        let fresh = fixture
            .checkpoint_state
            .observations()
            .into_iter()
            .filter(|observation| observation.mode == RefreshMode::Fresh)
            .collect::<Vec<_>>();
        if fresh.len() >= 2 {
            let live = health_matches_within(
                deadline,
                fixture.consumer_bind,
                &fixture.server_ca_der,
                "/livez",
                200,
                br#"{"status":"live"}"#,
            )
            .await;
            let ready = health_matches_within(
                deadline,
                fixture.consumer_bind,
                &fixture.server_ca_der,
                "/readyz",
                200,
                br#"{"status":"ready"}"#,
            )
            .await;
            if live && ready {
                if process.try_wait()?.is_some() {
                    let diagnostic = process_diagnostic(process);
                    ensure_safe_diagnostic(&diagnostic, "fresh checkpoint refresh")?;
                    return Err(HarnessError::Process(format!(
                        "relay exited immediately after fresh readiness; {diagnostic}"
                    )));
                }
                assert_fresh_observations(&fresh)?;
                return Ok(());
            }
        }
        if let Some(status) = process.try_wait()? {
            let diagnostic = process_diagnostic(process);
            ensure_safe_diagnostic(&diagnostic, "fresh checkpoint refresh")?;
            return Err(HarnessError::Process(format!(
                "relay exited while waiting for fresh checkpoint refresh: {status}; {diagnostic}"
            )));
        }
        let remaining = deadline.remaining("fresh checkpoint refresh")?;
        sleep(Duration::from_millis(100).min(remaining)).await;
    }
}

async fn wait_for_fresh_version(
    process: &mut ManagedProcess,
    fixture: &ProcessFixture,
    previous: &CheckpointObservation,
    label: &str,
    deadline: ScenarioDeadline,
) -> Result<CheckpointObservation> {
    loop {
        let observations = fixture.checkpoint_state.observations();
        if let Some(observation) = observations.iter().rev().find(|observation| {
            observation.mode == RefreshMode::Fresh
                && observation.version > previous.version
                && observation.nonce != previous.nonce
                && observation.response != previous.response
        }) {
            let ready = health_matches_within(
                deadline,
                fixture.consumer_bind,
                &fixture.server_ca_der,
                "/readyz",
                200,
                br#"{"status":"ready"}"#,
            )
            .await;
            if ready {
                if process.try_wait()?.is_some() {
                    let diagnostic = process_diagnostic(process);
                    ensure_safe_diagnostic(&diagnostic, label)?;
                    return Err(HarnessError::Process(format!(
                        "{label} relay exited immediately after recovery readiness; {diagnostic}"
                    )));
                }
                return Ok(observation.clone());
            }
        }
        if let Some(status) = process.try_wait()? {
            let diagnostic = process_diagnostic(process);
            ensure_safe_diagnostic(&diagnostic, label)?;
            return Err(HarnessError::Process(format!(
                "{label} relay exited before ready recovery: {status}; {diagnostic}"
            )));
        }
        let remaining = deadline.remaining(label)?;
        sleep(Duration::from_millis(100).min(remaining)).await;
    }
}

async fn wait_for_unready_checkpoint(
    process: &mut ManagedProcess,
    fixture: &ProcessFixture,
    mode: RefreshMode,
    label: &str,
    deadline: ScenarioDeadline,
) -> Result<()> {
    loop {
        let observations = fixture.checkpoint_state.observations();
        if let Some(observation) = observations
            .iter()
            .rev()
            .find(|observation| observation.mode == mode)
            && assert_negative_observation(&observations, observation, mode, label)?
        {
            let live = health_matches_within(
                deadline,
                fixture.consumer_bind,
                &fixture.server_ca_der,
                "/livez",
                200,
                br#"{"status":"live"}"#,
            )
            .await;
            let ready = health_matches_within(
                deadline,
                fixture.consumer_bind,
                &fixture.server_ca_der,
                "/readyz",
                503,
                br#"{"status":"unready"}"#,
            )
            .await;
            if live && ready {
                if process.try_wait()?.is_some() {
                    let diagnostic = process_diagnostic(process);
                    ensure_safe_diagnostic(&diagnostic, label)?;
                    return Err(HarnessError::Process(format!(
                        "{label} relay exited after fail-closed readiness; {diagnostic}"
                    )));
                }
                return Ok(());
            }
        }
        if let Some(status) = process.try_wait()? {
            let diagnostic = process_diagnostic(process);
            ensure_safe_diagnostic(&diagnostic, label)?;
            return Err(HarnessError::Process(format!(
                "{label} relay exited instead of serving fail-closed readiness: {status}; {diagnostic}"
            )));
        }
        let remaining = deadline.remaining(label)?;
        sleep(Duration::from_millis(100).min(remaining)).await;
    }
}

async fn health_matches_within(
    deadline: ScenarioDeadline,
    address: SocketAddr,
    server_ca_der: &[u8],
    path: &'static str,
    expected_status: u16,
    expected_body: &[u8],
) -> bool {
    let Ok(remaining) = deadline.remaining("bounded health probe") else {
        return false;
    };
    match timeout(remaining, health_request(address, server_ca_der, path)).await {
        Ok(result) => health_matches(result, expected_status, expected_body),
        Err(_) => false,
    }
}

fn health_matches(
    result: Result<(u16, Vec<u8>)>,
    expected_status: u16,
    expected_body: &[u8],
) -> bool {
    matches!(result, Ok((status, body)) if status == expected_status && body == expected_body)
}

fn assert_negative_observation(
    observations: &[CheckpointObservation],
    observation: &CheckpointObservation,
    mode: RefreshMode,
    label: &str,
) -> Result<bool> {
    let fresh = observations
        .iter()
        .filter(|candidate| candidate.mode == RefreshMode::Fresh)
        .collect::<Vec<_>>();
    let Some(highest_fresh) = fresh.iter().map(|candidate| candidate.version).max() else {
        return Err(HarnessError::Process(format!(
            "{label} had no earlier fresh checkpoint to fence"
        )));
    };
    match mode {
        RefreshMode::EqualConflict => {
            let previous = fresh
                .iter()
                .rev()
                .find(|candidate| candidate.version == observation.version);
            let Some(previous) = previous else {
                return Ok(false);
            };
            if previous.nonce == observation.nonce || previous.response == observation.response {
                return Err(HarnessError::Process(format!(
                    "{label} equal-version response was a replay rather than a signed conflict"
                )));
            }
        }
        RefreshMode::Stale => {
            if observation.version >= highest_fresh {
                return Ok(false);
            }
        }
        RefreshMode::Fresh => {
            return Err(HarnessError::Process(
                "fresh checkpoint cannot be a negative observation".into(),
            ));
        }
    }
    Ok(true)
}

fn assert_fresh_observations(observations: &[CheckpointObservation]) -> Result<()> {
    if observations.len() < 2 {
        return Err(HarnessError::Process(
            "fewer than two fresh checkpoint observations were retained".into(),
        ));
    }
    let first = &observations[0];
    let second = &observations[1];
    if first.version == 0
        || observations
            .windows(2)
            .any(|pair| pair[1].version != pair[0].version + 1)
    {
        return Err(HarnessError::Process(
            "fresh checkpoint versions did not advance monotonically by one".into(),
        ));
    }
    if first.nonce == second.nonce || first.response == second.response {
        return Err(HarnessError::Process(
            "fresh checkpoint refresh did not bind a new nonce and signed response".into(),
        ));
    }
    if first.nonce.is_empty() || second.nonce.is_empty() {
        return Err(HarnessError::Process(
            "fresh checkpoint request nonce was empty".into(),
        ));
    }
    Ok(())
}

fn ensure_safe_diagnostic(diagnostic: &str, label: &str) -> Result<()> {
    let lower = diagnostic.to_ascii_lowercase();
    if lower.contains("private_key") || lower.contains("-----begin") {
        return Err(HarnessError::Process(format!(
            "{label} diagnostic contained credential material"
        )));
    }
    Ok(())
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
