//! M7-C27 public abandoned-upgrade admission gate.
//!
//! This fixture uses a one-shot server-side barrier after owner admission and
//! before Axum constructs the public WebSocket upgrade response. A real TLS
//! client sends the authenticated WSS request, waits for that exact barrier,
//! observes no response bytes, closes the connection, and then releases the
//! handler. The owner snapshot distinguishes the local unclaimed admission
//! from the remote peer admission, and both exact registrations are observed
//! to leave the active set without an application dispatch.
//!
//! This is deliberately narrower than C22 saturation and does not claim the
//! EC-049 request-body preflight sentinel: the tested request is a body-free
//! WebSocket upgrade.

use super::{
    CLEANUP_TIMEOUT, ConsumerStream, ProductionCluster, RunningHarness, SCENARIO_TIMEOUT,
    STARTUP_TIMEOUT, StreamConnectFailure, open_consumer_stream, start_cli_smoke,
};
use crate::acceptance::helpers::write_device_profile;
use crate::{Harness, HarnessError, HarnessOptions, ManagedProcess, OidcTokenOptions, Result};
use chrono::Utc;
use rustls::{ClientConfig, RootCertStore, pki_types::CertificateDer, pki_types::ServerName};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tempfile::{TempDir, tempdir};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Instant, sleep, timeout, timeout_at},
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tunnel_catalog::{Catalog, OwnerToken};
use tunnel_core::RotationConfig;
use tunnel_relay::{
    ConsumerUpgradeBarrier, RelaySessionSnapshot, RelaySnapshot, RelayStreamSnapshot,
};
use uuid::Uuid;

const ABANDONED_ROTATION: RotationConfig = RotationConfig {
    interval_seconds: 300,
    handshake_timeout_seconds: 10,
    overlap_seconds: 30,
};
const PHASE_TIMEOUT: Duration = Duration::from_secs(15);
const CAPACITY_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PRE_CLOSE_READ_TIMEOUT: Duration = Duration::from_millis(150);
const ECHO_SUBPROTOCOL: &str = "agent-tunnel.echo.v1";
const MAX_ERROR_BODY_BYTES: usize = 1024;
const MAX_RETRY_AFTER_MS: u64 = 60_000;
const TARGET_OWNER: &str = "relay-a";
const REMOTE_INGRESS: &str = "relay-c";
const CLI_INGRESS: &str = "relay-b";

/// Payload-free evidence from both public owner-local and remote abandoned
/// upgrade paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicAbandonedUpgradeEvidence {
    pub scope: &'static str,
    pub relay_count: usize,
    pub actual_cli_processes: usize,
    pub owner_local_barrier_reached: bool,
    pub owner_local_barrier_hits: u64,
    pub owner_local_response_bytes_before_close: usize,
    pub owner_local_no_http_101_observed: bool,
    pub owner_local_registration_observed: bool,
    pub owner_local_registration_unclaimed_before_close: bool,
    pub owner_local_registration_reclaimed: bool,
    pub owner_local_application_dispatch_delta: u64,
    pub owner_local_capacity_status: u16,
    pub owner_local_capacity_admission_limit: bool,
    pub owner_local_capacity_not_dispatched: bool,
    pub remote_barrier_reached: bool,
    pub remote_barrier_hits: u64,
    pub remote_response_bytes_before_close: usize,
    pub remote_no_http_101_observed: bool,
    pub remote_registration_observed: bool,
    pub remote_registration_claimed_before_close: bool,
    pub remote_registration_reclaimed: bool,
    pub remote_application_dispatch_delta: u64,
    pub remote_capacity_status: u16,
    pub remote_capacity_admission_limit: bool,
    pub remote_capacity_not_dispatched: bool,
    pub sibling_baseline_echo: bool,
    pub sibling_recovery_echo: bool,
    pub cleanup_joined: bool,
}

/// Validate the exact C27 public abandoned-upgrade contract.
pub fn validate_public_abandoned_upgrade_evidence(
    evidence: &PublicAbandonedUpgradeEvidence,
) -> Result<()> {
    if evidence.scope != "public_abandoned_upgrade_after_owner_admission" {
        return Err(HarnessError::Process(
            "public abandoned-upgrade evidence scope was widened or missing".into(),
        ));
    }
    if evidence.relay_count != 3 || evidence.actual_cli_processes != 2 {
        return Err(HarnessError::Process(format!(
            "public abandoned-upgrade expected three relays and two actual CLI processes, observed relays={} processes={}",
            evidence.relay_count, evidence.actual_cli_processes
        )));
    }
    let required = [
        (
            "owner_local_barrier_reached",
            evidence.owner_local_barrier_reached,
        ),
        (
            "owner_local_no_http_101_observed",
            evidence.owner_local_no_http_101_observed,
        ),
        (
            "owner_local_registration_observed",
            evidence.owner_local_registration_observed,
        ),
        (
            "owner_local_registration_unclaimed_before_close",
            evidence.owner_local_registration_unclaimed_before_close,
        ),
        (
            "owner_local_registration_reclaimed",
            evidence.owner_local_registration_reclaimed,
        ),
        ("remote_barrier_reached", evidence.remote_barrier_reached),
        (
            "remote_no_http_101_observed",
            evidence.remote_no_http_101_observed,
        ),
        (
            "remote_registration_observed",
            evidence.remote_registration_observed,
        ),
        (
            "remote_registration_claimed_before_close",
            evidence.remote_registration_claimed_before_close,
        ),
        (
            "remote_registration_reclaimed",
            evidence.remote_registration_reclaimed,
        ),
        ("sibling_baseline_echo", evidence.sibling_baseline_echo),
        ("sibling_recovery_echo", evidence.sibling_recovery_echo),
        ("cleanup_joined", evidence.cleanup_joined),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "public abandoned-upgrade required gate {name} was false"
        )));
    }
    if evidence.owner_local_barrier_hits != 1 || evidence.remote_barrier_hits != 1 {
        return Err(HarnessError::Process(format!(
            "public abandoned-upgrade barrier hit count was local={} remote={}, expected one each",
            evidence.owner_local_barrier_hits, evidence.remote_barrier_hits
        )));
    }
    if evidence.owner_local_response_bytes_before_close != 0
        || evidence.remote_response_bytes_before_close != 0
    {
        return Err(HarnessError::Process(format!(
            "public abandoned-upgrade client observed pre-close response bytes: local={} remote={}",
            evidence.owner_local_response_bytes_before_close,
            evidence.remote_response_bytes_before_close
        )));
    }
    if evidence.owner_local_application_dispatch_delta != 0
        || evidence.remote_application_dispatch_delta != 0
    {
        return Err(HarnessError::Process(format!(
            "abandoned public upgrade advanced application dispatch: local={} remote={}",
            evidence.owner_local_application_dispatch_delta,
            evidence.remote_application_dispatch_delta
        )));
    }
    for (label, status, code, not_dispatched) in [
        (
            "owner-local",
            evidence.owner_local_capacity_status,
            evidence.owner_local_capacity_admission_limit,
            evidence.owner_local_capacity_not_dispatched,
        ),
        (
            "remote",
            evidence.remote_capacity_status,
            evidence.remote_capacity_admission_limit,
            evidence.remote_capacity_not_dispatched,
        ),
    ] {
        if status != 429 || !code || !not_dispatched {
            return Err(HarnessError::Process(format!(
                "{label} abandoned-upgrade capacity probe was not exact: status={status}, admission_limit={code}, not_dispatched={not_dispatched}"
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CapacityEvidence {
    status: u16,
    admission_limit: bool,
    not_dispatched: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PhaseEvidence {
    barrier_reached: bool,
    barrier_hits: u64,
    response_bytes_before_close: usize,
    no_http_101_observed: bool,
    registration_observed: bool,
    registration_claimed_before_close: bool,
    registration_reclaimed: bool,
    application_dispatch_delta: u64,
    capacity: CapacityEvidence,
}

struct PublicAbandonedResources {
    target_process: Option<ManagedProcess>,
    target_stream: Option<ConsumerStream>,
    sibling_process: Option<ManagedProcess>,
    sibling_stream: Option<ConsumerStream>,
    profiles: Vec<TempDir>,
}

impl PublicAbandonedResources {
    fn new() -> Self {
        Self {
            target_process: None,
            target_stream: None,
            sibling_process: None,
            sibling_stream: None,
            profiles: Vec::new(),
        }
    }

    async fn shutdown(&mut self) -> Result<()> {
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        let mut errors = Vec::new();
        for (label, stream) in [
            ("target consumer stream", &mut self.target_stream),
            ("sibling consumer stream", &mut self.sibling_stream),
        ] {
            if let Some(mut stream) = stream.take() {
                match timeout_at(deadline, stream.close()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => errors.push(format!("{label}: {error}")),
                    Err(_) => errors.push(format!("{label} cleanup timed out")),
                }
            }
        }
        for (label, process) in [
            ("target CLI", &mut self.target_process),
            ("sibling CLI", &mut self.sibling_process),
        ] {
            if let Some(process) = process.take() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let grace = remaining.min(Duration::from_secs(5));
                match process.shutdown(grace).await {
                    Ok(_) => {}
                    Err(error) => errors.push(format!("{label} join: {error}")),
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(HarnessError::Process(format!(
                "public abandoned-upgrade cleanup failed: {}",
                errors.join("; ")
            )))
        }
    }
}

struct ReleaseOnDrop(Arc<ConsumerUpgradeBarrier>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// Run the bounded public owner-local and remote abandoned-upgrade fixture.
pub async fn verify() -> Result<PublicAbandonedUpgradeEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(ABANDONED_ROTATION)
        .shared_device_uuid(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| {
            HarnessError::Timeout("public abandoned-upgrade harness startup timed out".into())
        })??;
    let local_barrier = Arc::new(ConsumerUpgradeBarrier::default());
    let remote_barrier = Arc::new(ConsumerUpgradeBarrier::default());
    let barriers = BTreeMap::from([
        (TARGET_OWNER.to_owned(), Arc::clone(&local_barrier)),
        (REMOTE_INGRESS.to_owned(), Arc::clone(&remote_barrier)),
    ]);
    let mut cluster = match ProductionCluster::start_with_public_upgrade_barriers(
        &mut harness,
        barriers,
        1,
    )
    .await
    {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };
    let mut resources = PublicAbandonedResources::new();
    let scenario = match timeout(
        SCENARIO_TIMEOUT,
        run_inner(
            &mut cluster,
            &harness,
            &mut resources,
            local_barrier,
            remote_barrier,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "public abandoned-upgrade scenario exceeded its bounded deadline".into(),
        )),
    };
    let resource_cleanup = resources.shutdown().await;
    let cluster_cleanup = cluster.shutdown().await;
    let harness_cleanup = harness.shutdown().await;
    match (scenario, resource_cleanup, cluster_cleanup, harness_cleanup) {
        (Ok(mut evidence), Ok(()), Ok(()), Ok(())) => {
            evidence.cleanup_joined = true;
            validate_public_abandoned_upgrade_evidence(&evidence)?;
            Ok(evidence)
        }
        (scenario, resource_cleanup, cluster_cleanup, harness_cleanup) => {
            let mut errors = Vec::new();
            if let Err(error) = scenario {
                errors.push(error.to_string());
            }
            if let Err(error) = resource_cleanup {
                errors.push(format!("resource cleanup: {error}"));
            }
            if let Err(error) = cluster_cleanup {
                errors.push(format!("relay cleanup: {error}"));
            }
            if let Err(error) = harness_cleanup {
                errors.push(format!("Redis cleanup: {error}"));
            }
            Err(HarnessError::Process(errors.join("; ")))
        }
    }
}

async fn run_inner(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    resources: &mut PublicAbandonedResources,
    local_barrier: Arc<ConsumerUpgradeBarrier>,
    remote_barrier: Arc<ConsumerUpgradeBarrier>,
) -> Result<PublicAbandonedUpgradeEvidence> {
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(format!(
            "public abandoned-upgrade expected three relays, observed {}",
            cluster.relays.len()
        )));
    }
    cluster.wait_for_peer_readiness(STARTUP_TIMEOUT).await?;
    let target = harness.topology.devices_a.first().ok_or_else(|| {
        HarnessError::InvalidInput("public abandoned-upgrade target missing".into())
    })?;
    let target_service = *harness
        .topology
        .service_ids
        .get(&target.id)
        .ok_or_else(|| {
            HarnessError::InvalidInput("public abandoned-upgrade target service missing".into())
        })?;
    let sibling = harness.topology.devices_a.get(2).ok_or_else(|| {
        HarnessError::InvalidInput("public abandoned-upgrade sibling missing".into())
    })?;
    let sibling_service = *harness
        .topology
        .service_ids
        .get(&sibling.id)
        .ok_or_else(|| {
            HarnessError::InvalidInput("public abandoned-upgrade sibling service missing".into())
        })?;
    let consumer = harness.topology.consumers_a.first().ok_or_else(|| {
        HarnessError::InvalidInput("public abandoned-upgrade consumer missing".into())
    })?;
    let token = harness.oidc.issue_with(
        &consumer.name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(120),
            ..OidcTokenOptions::default()
        },
    )?;

    let target_profile_dir = tempdir().map_err(HarnessError::Io)?;
    let mut target_profile = write_device_profile(
        target_profile_dir.path(),
        target.id,
        target_service,
        "m7-c27-target",
        cluster.device_fanout.local_addr(),
        &target.certificate.certificate_pem,
        &target.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    target_profile.config.rotation = ABANDONED_ROTATION;
    target_profile
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("target profile: {error}")))?;
    resources.profiles.push(target_profile_dir);

    let sibling_profile_dir = tempdir().map_err(HarnessError::Io)?;
    let mut sibling_profile = write_device_profile(
        sibling_profile_dir.path(),
        sibling.id,
        sibling_service,
        "m7-c27-sibling",
        cluster.device_fanout.local_addr(),
        &sibling.certificate.certificate_pem,
        &sibling.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    sibling_profile.config.rotation = ABANDONED_ROTATION;
    sibling_profile
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("sibling profile: {error}")))?;
    resources.profiles.push(sibling_profile_dir);

    let cli_ingress = cluster.relay(CLI_INGRESS)?.consumer_addr()?;
    let (target_process, target_stream) = start_cli_smoke(
        harness,
        cluster.device_fanout.local_addr(),
        cli_ingress,
        &target_profile,
        &token,
        target.id,
        target_service,
    )
    .await?;
    resources.target_process = Some(target_process);
    resources.target_stream = Some(target_stream);
    resources
        .target_stream
        .as_mut()
        .ok_or_else(|| HarnessError::Process("target stream was not retained".into()))?
        .round_trip(b"m7-c27-target-baseline", b"m7-c27-target")
        .await?;

    let owner = harness
        .production_catalog()?
        .current_owner(target.tenant_id, target.id, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("reading target owner: {error}")))?
        .ok_or_else(|| HarnessError::Process("target owner was not retained".into()))?;
    if owner.token.node_id != TARGET_OWNER {
        return Err(HarnessError::Process(format!(
            "public abandoned-upgrade target owner was {}, expected {TARGET_OWNER}",
            owner.token.node_id
        )));
    }
    let owner_relay = cluster.relay(TARGET_OWNER)?;
    let owner_addr = owner_relay.consumer_addr()?;
    let remote_addr = cluster.relay(REMOTE_INGRESS)?.consumer_addr()?;
    let local_baseline = baseline_stream_state(owner_relay, &owner.token).await?;
    let local = run_abandoned_phase(
        cluster,
        harness,
        target.id,
        target_service,
        &token,
        TARGET_OWNER,
        owner_addr,
        owner_relay,
        local_barrier,
        local_baseline,
        &owner.token,
        false,
        "owner-local",
    )
    .await?;

    // Keep the target CLI on relay-b and establish the sibling on relay-a so
    // relay-c remains an uncontended public ingress for the remote barrier.
    let sibling_ingress = cluster.relay(TARGET_OWNER)?.consumer_addr()?;
    let (sibling_process, sibling_stream) = start_cli_smoke(
        harness,
        cluster.device_fanout.local_addr(),
        sibling_ingress,
        &sibling_profile,
        &token,
        sibling.id,
        sibling_service,
    )
    .await?;
    resources.sibling_process = Some(sibling_process);
    resources.sibling_stream = Some(sibling_stream);
    let sibling_baseline_echo = resources
        .sibling_stream
        .as_mut()
        .ok_or_else(|| HarnessError::Process("sibling stream was not retained".into()))?
        .round_trip(b"m7-c27-sibling-baseline", b"m7-c27-sibling")
        .await
        .is_ok();
    if !sibling_baseline_echo {
        return Err(HarnessError::Http("sibling baseline echo failed".into()));
    }
    let sibling_owner = harness
        .production_catalog()?
        .current_owner(sibling.tenant_id, sibling.id, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("reading sibling owner: {error}")))?
        .ok_or_else(|| HarnessError::Process("sibling owner was not retained".into()))?;
    let sibling_owner_token = sibling_owner.token.clone();
    assert_current_owner(harness, &sibling_owner_token, "sibling baseline").await?;

    let remote_baseline = baseline_stream_state(owner_relay, &owner.token).await?;
    let remote = run_abandoned_phase(
        cluster,
        harness,
        target.id,
        target_service,
        &token,
        REMOTE_INGRESS,
        remote_addr,
        owner_relay,
        remote_barrier,
        remote_baseline,
        &owner.token,
        true,
        "remote",
    )
    .await?;
    let sibling_recovery_echo = resources
        .sibling_stream
        .as_mut()
        .ok_or_else(|| HarnessError::Process("sibling stream disappeared".into()))?
        .round_trip(b"m7-c27-sibling-recovery", b"m7-c27-sibling")
        .await
        .is_ok();
    assert_current_owner(harness, &sibling_owner_token, "sibling recovery").await?;
    let actual_cli_processes = match (
        resources
            .target_process
            .as_ref()
            .and_then(ManagedProcess::id),
        resources
            .sibling_process
            .as_ref()
            .and_then(ManagedProcess::id),
    ) {
        (Some(target_pid), Some(sibling_pid)) if target_pid != sibling_pid => 2,
        pids => {
            return Err(HarnessError::Process(format!(
                "public abandoned-upgrade expected two distinct live CLI PIDs, observed {pids:?}"
            )));
        }
    };

    Ok(PublicAbandonedUpgradeEvidence {
        scope: "public_abandoned_upgrade_after_owner_admission",
        relay_count: cluster.relays.len(),
        actual_cli_processes,
        owner_local_barrier_reached: local.barrier_reached,
        owner_local_barrier_hits: local.barrier_hits,
        owner_local_response_bytes_before_close: local.response_bytes_before_close,
        owner_local_no_http_101_observed: local.no_http_101_observed,
        owner_local_registration_observed: local.registration_observed,
        owner_local_registration_unclaimed_before_close: !local.registration_claimed_before_close,
        owner_local_registration_reclaimed: local.registration_reclaimed,
        owner_local_application_dispatch_delta: local.application_dispatch_delta,
        owner_local_capacity_status: local.capacity.status,
        owner_local_capacity_admission_limit: local.capacity.admission_limit,
        owner_local_capacity_not_dispatched: local.capacity.not_dispatched,
        remote_barrier_reached: remote.barrier_reached,
        remote_barrier_hits: remote.barrier_hits,
        remote_response_bytes_before_close: remote.response_bytes_before_close,
        remote_no_http_101_observed: remote.no_http_101_observed,
        remote_registration_observed: remote.registration_observed,
        remote_registration_claimed_before_close: remote.registration_claimed_before_close,
        remote_registration_reclaimed: remote.registration_reclaimed,
        remote_application_dispatch_delta: remote.application_dispatch_delta,
        remote_capacity_status: remote.capacity.status,
        remote_capacity_admission_limit: remote.capacity.admission_limit,
        remote_capacity_not_dispatched: remote.capacity.not_dispatched,
        sibling_baseline_echo,
        sibling_recovery_echo,
        cleanup_joined: false,
    })
}

struct BaselineStreamState {
    known_streams: std::collections::BTreeSet<StreamIdentity>,
    application_dispatches: u64,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct StreamIdentity {
    stream_id: u64,
    operation_id: String,
}

fn stream_identity(stream: &RelayStreamSnapshot) -> StreamIdentity {
    StreamIdentity {
        stream_id: stream.stream_id,
        operation_id: stream.operation_id.clone(),
    }
}

fn exact_session<'a>(
    snapshot: &'a RelaySnapshot,
    owner: &OwnerToken,
) -> Result<&'a RelaySessionSnapshot> {
    let mut matches = snapshot.sessions.iter().filter(|session| {
        session.tenant_id == owner.tenant_id.to_string()
            && session.device_id == owner.device_id.to_string()
            && session.session_id == owner.session_id
            && session.epoch == owner.epoch
    });
    let session = matches.next().ok_or_else(|| {
        HarnessError::Process(format!(
            "owner session was missing for tenant={} device={} session={} epoch={}",
            owner.tenant_id, owner.device_id, owner.session_id, owner.epoch
        ))
    })?;
    if matches.next().is_some() {
        return Err(HarnessError::Process(format!(
            "owner session identity was ambiguous for tenant={} device={} session={} epoch={}",
            owner.tenant_id, owner.device_id, owner.session_id, owner.epoch
        )));
    }
    Ok(session)
}

fn session_application_dispatches(snapshot: &RelaySnapshot, owner: &OwnerToken) -> Result<u64> {
    Ok(exact_session(snapshot, owner)?
        .streams
        .iter()
        .map(|stream| stream.last_emitted_relay_to_connector)
        .sum())
}

async fn baseline_stream_state(
    relay: &super::ProductionRelay,
    owner: &OwnerToken,
) -> Result<BaselineStreamState> {
    let snapshot = relay.snapshot().await?;
    let session = exact_session(&snapshot, owner)?;
    let known_streams = session.streams.iter().map(stream_identity).collect();
    Ok(BaselineStreamState {
        known_streams,
        application_dispatches: session_application_dispatches(&snapshot, owner)?,
    })
}

#[allow(clippy::too_many_arguments)] // Keep the two fixture phase inputs explicit.
async fn run_abandoned_phase(
    _cluster: &ProductionCluster,
    harness: &RunningHarness,
    device_id: Uuid,
    service_id: Uuid,
    token: &str,
    ingress_node: &str,
    ingress_addr: std::net::SocketAddr,
    owner_relay: &super::ProductionRelay,
    barrier: Arc<ConsumerUpgradeBarrier>,
    baseline: BaselineStreamState,
    owner: &OwnerToken,
    expected_remote_claim: bool,
    label: &'static str,
) -> Result<PhaseEvidence> {
    assert_current_owner(harness, owner, label).await?;
    if !barrier.arm() {
        return Err(HarnessError::Process(format!(
            "{label} public upgrade barrier was already armed"
        )));
    }
    let _release = ReleaseOnDrop(Arc::clone(&barrier));
    let mut client = open_abandoned_upgrade(
        ingress_addr,
        &harness.pki.server_ca.certificate_der,
        token,
        device_id,
        service_id,
    )
    .await?;
    timeout(PHASE_TIMEOUT, barrier.wait_reached())
        .await
        .map_err(|_| HarnessError::Timeout(format!("{label} upgrade barrier was not reached")))?;
    let barrier_reached = barrier.hit_count() == 1;
    let selected =
        wait_for_new_stream(owner_relay, owner, &baseline.known_streams, PHASE_TIMEOUT).await?;
    let registration_observed = selected.is_some();
    let registration_claimed_before_close = selected
        .as_ref()
        .is_some_and(|stream| stream.admission_claimed);
    if registration_claimed_before_close != expected_remote_claim {
        return Err(HarnessError::Process(format!(
            "{label} admission claim state was {}, expected {}",
            registration_claimed_before_close, expected_remote_claim
        )));
    }
    assert_current_owner(harness, owner, label).await?;
    let capacity = capacity_probe(
        ingress_addr,
        &harness.pki.server_ca.certificate_der,
        token,
        device_id,
        service_id,
    )
    .await?;
    let (response_bytes_before_close, read_outcome) = read_before_close(&mut client).await?;
    let no_http_101_observed = matches!(read_outcome, HeldReadOutcome::Pending);
    if !no_http_101_observed {
        return Err(HarnessError::Process(format!(
            "{label} abandoned-upgrade client read was not pending at the held barrier: {read_outcome:?}"
        )));
    }
    drop(client);
    barrier.release();
    let selected = selected.ok_or_else(|| {
        HarnessError::Process(format!(
            "{label} abandoned-upgrade registration disappeared before close"
        ))
    })?;
    let registration_reclaimed = wait_for_stream_reclaimed(
        owner_relay,
        owner,
        &baseline.known_streams,
        &stream_identity(&selected),
        PHASE_TIMEOUT,
    )
    .await?;
    assert_current_owner(harness, owner, label).await?;
    let snapshot = owner_relay.snapshot().await?;
    let application_dispatches = session_application_dispatches(&snapshot, owner)?;
    if application_dispatches < baseline.application_dispatches {
        return Err(HarnessError::Process(format!(
            "{label} owner dispatch counter moved backwards from {} to {}",
            baseline.application_dispatches, application_dispatches
        )));
    }
    let application_dispatch_delta = application_dispatches - baseline.application_dispatches;
    if !registration_observed || !barrier_reached || !registration_reclaimed {
        return Err(HarnessError::Process(format!(
            "{label} abandoned registration phase incomplete: barrier_reached={barrier_reached}, observed={registration_observed}, reclaimed={registration_reclaimed}, ingress={ingress_node}"
        )));
    }
    Ok(PhaseEvidence {
        barrier_reached,
        barrier_hits: barrier.hit_count(),
        response_bytes_before_close,
        no_http_101_observed,
        registration_observed,
        registration_claimed_before_close,
        registration_reclaimed,
        application_dispatch_delta,
        capacity,
    })
}

async fn wait_for_new_stream(
    relay: &super::ProductionRelay,
    owner: &OwnerToken,
    known_streams: &std::collections::BTreeSet<StreamIdentity>,
    budget: Duration,
) -> Result<Option<RelayStreamSnapshot>> {
    let deadline = Instant::now() + budget;
    loop {
        let snapshot = relay.snapshot().await?;
        let session = exact_session(&snapshot, owner)?;
        let candidates = session
            .streams
            .iter()
            .filter(|stream| !known_streams.contains(&stream_identity(stream)))
            .cloned()
            .collect::<Vec<_>>();
        if candidates.len() == 1 {
            if candidates[0].terminal {
                return Err(HarnessError::Process(
                    "public abandoned-upgrade registration became terminal before selection".into(),
                ));
            }
            return Ok(candidates.into_iter().next());
        }
        if candidates.len() > 1 {
            return Err(HarnessError::Process(
                "public abandoned-upgrade barrier created more than one owner registration".into(),
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        sleep(Duration::from_millis(25).min(remaining)).await;
    }
}

async fn wait_for_stream_reclaimed(
    relay: &super::ProductionRelay,
    owner: &OwnerToken,
    known_streams: &std::collections::BTreeSet<StreamIdentity>,
    selected: &StreamIdentity,
    budget: Duration,
) -> Result<bool> {
    let deadline = Instant::now() + budget;
    loop {
        let snapshot = relay.snapshot().await?;
        let session = exact_session(&snapshot, owner)?;
        let unexpected = session
            .streams
            .iter()
            .filter(|stream| !known_streams.contains(&stream_identity(stream)))
            .filter(|stream| stream_identity(stream) != *selected)
            .count();
        if unexpected != 0 {
            return Err(HarnessError::Process(
                "public abandoned-upgrade left an unexpected new stream registration".into(),
            ));
        }
        let retained_selected = session
            .streams
            .iter()
            .any(|stream| stream_identity(stream) == *selected);
        if !retained_selected {
            return Ok(true);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        sleep(Duration::from_millis(25).min(remaining)).await;
    }
}

async fn assert_current_owner(
    harness: &RunningHarness,
    expected: &OwnerToken,
    label: &str,
) -> Result<()> {
    let owner = timeout(
        PHASE_TIMEOUT,
        harness.production_catalog()?.current_owner(
            expected.tenant_id,
            expected.device_id,
            Utc::now(),
        ),
    )
    .await
    .map_err(|_| HarnessError::Timeout(format!("{label} owner lookup timed out")))?
    .map_err(|error| HarnessError::Redis(format!("{label} owner lookup: {error}")))?
    .ok_or_else(|| HarnessError::Process(format!("{label} owner disappeared")))?;
    if owner.token != *expected {
        return Err(HarnessError::Process(format!(
            "{label} owner token changed: expected node={} boot={} session={} epoch={}, observed node={} boot={} session={} epoch={}",
            expected.node_id,
            expected.boot_id,
            expected.session_id,
            expected.epoch,
            owner.token.node_id,
            owner.token.boot_id,
            owner.token.session_id,
            owner.token.epoch,
        )));
    }
    Ok(())
}

async fn capacity_probe(
    consumer_addr: std::net::SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
) -> Result<CapacityEvidence> {
    let result = timeout(
        CAPACITY_PROBE_TIMEOUT,
        open_consumer_stream(consumer_addr, server_ca_der, token, device_id, service_id),
    )
    .await
    .map_err(|_| {
        HarnessError::Timeout("public abandoned-upgrade capacity probe timed out".into())
    })?;
    let (status, body) = match result {
        Ok(mut stream) => match timeout(CAPACITY_PROBE_TIMEOUT, stream.close()).await {
            Ok(Ok(())) => {
                return Err(HarnessError::Process(
                    "public abandoned-upgrade capacity probe unexpectedly upgraded".into(),
                ));
            }
            Ok(Err(error)) => {
                return Err(HarnessError::Http(format!(
                    "public abandoned-upgrade unexpected capacity upgrade cleanup failed: {error}"
                )));
            }
            Err(_) => {
                return Err(HarnessError::Timeout(
                    "public abandoned-upgrade unexpected capacity upgrade cleanup timed out".into(),
                ));
            }
        },
        Err(StreamConnectFailure::Status { status, body }) => (status, body),
        Err(StreamConnectFailure::Harness(error)) => return Err(error),
    };
    if body
        .as_ref()
        .is_some_and(|body| body.len() > MAX_ERROR_BODY_BYTES)
    {
        return Err(HarnessError::Http(
            "public abandoned-upgrade capacity response exceeded its bound".into(),
        ));
    }
    let value = body
        .as_deref()
        .ok_or_else(|| HarnessError::Http("public abandoned-upgrade capacity body missing".into()))
        .and_then(|body| {
            serde_json::from_slice::<serde_json::Value>(body).map_err(|_| {
                HarnessError::Http("public abandoned-upgrade capacity body was not JSON".into())
            })
        })?;
    let admission_limit = value.get("code").and_then(|v| v.as_str()) == Some("ADMISSION_LIMIT");
    let not_dispatched = value.get("execution").and_then(|v| v.as_str()) == Some("not_dispatched");
    let retry_after_bounded = value.get("retry_after_ms").is_none_or(|value| {
        value
            .as_u64()
            .is_some_and(|millis| millis <= MAX_RETRY_AFTER_MS)
    });
    if status != 429 || !admission_limit || !not_dispatched || !retry_after_bounded {
        return Err(HarnessError::Process(format!(
            "public abandoned-upgrade capacity response was not exact: status={status}, admission_limit={admission_limit}, not_dispatched={not_dispatched}, retry_after_bounded={retry_after_bounded}"
        )));
    }
    Ok(CapacityEvidence {
        status,
        admission_limit,
        not_dispatched,
    })
}

async fn open_abandoned_upgrade(
    consumer_addr: std::net::SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
) -> Result<TlsStream<TcpStream>> {
    if token.contains('\r') || token.contains('\n') || token.len() > 4096 {
        return Err(HarnessError::InvalidInput(
            "public abandoned-upgrade token exceeded its header bound".into(),
        ));
    }
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(server_ca_der.to_vec()))
        .map_err(|error| HarnessError::Http(format!("abandoned-upgrade relay CA: {error}")))?;
    let config =
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| HarnessError::Http(format!("abandoned-upgrade TLS config: {error}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let stream = timeout(PHASE_TIMEOUT, TcpStream::connect(consumer_addr))
        .await
        .map_err(|_| HarnessError::Timeout("abandoned-upgrade TCP connect timed out".into()))?
        .map_err(HarnessError::Io)?;
    let server_name = ServerName::try_from("localhost".to_owned())
        .map_err(|error| HarnessError::Http(format!("abandoned-upgrade server name: {error}")))?;
    let mut tls = timeout(PHASE_TIMEOUT, connector.connect(server_name, stream))
        .await
        .map_err(|_| HarnessError::Timeout("abandoned-upgrade TLS connect timed out".into()))?
        .map_err(|error| HarnessError::Http(format!("abandoned-upgrade TLS: {error}")))?;
    let key = generate_key();
    let request = format!(
        "GET /v1/devices/{device_id}/services/{service_id}/stream HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Protocol: {ECHO_SUBPROTOCOL}\r\n\r\n"
    );
    timeout(PHASE_TIMEOUT, tls.write_all(request.as_bytes()))
        .await
        .map_err(|_| HarnessError::Timeout("abandoned-upgrade request write timed out".into()))?
        .map_err(HarnessError::Io)?;
    Ok(tls)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum HeldReadOutcome {
    /// The client read stayed pending for the bounded held-barrier window.
    Pending,
    /// The peer closed before any response bytes were received.
    Eof,
    /// Response bytes escaped before the fixture closed the abandoned request.
    Data,
    /// The transport failed while the held request was being observed.
    Error(String),
}

async fn read_before_close(stream: &mut TlsStream<TcpStream>) -> Result<(usize, HeldReadOutcome)> {
    let mut buffer = [0_u8; 4096];
    match timeout(PRE_CLOSE_READ_TIMEOUT, stream.read(&mut buffer)).await {
        Err(_) => Ok((0, HeldReadOutcome::Pending)),
        Ok(Ok(0)) => Ok((0, HeldReadOutcome::Eof)),
        Ok(Ok(bytes)) => Ok((bytes, HeldReadOutcome::Data)),
        Ok(Err(error)) => Ok((0, HeldReadOutcome::Error(error.to_string()))),
    }
}

#[cfg(test)]
mod tests {
    use super::{PublicAbandonedUpgradeEvidence, validate_public_abandoned_upgrade_evidence};
    use crate::acceptance_test_support::assert_rejected;

    fn valid() -> PublicAbandonedUpgradeEvidence {
        PublicAbandonedUpgradeEvidence {
            scope: "public_abandoned_upgrade_after_owner_admission",
            relay_count: 3,
            actual_cli_processes: 2,
            owner_local_barrier_reached: true,
            owner_local_barrier_hits: 1,
            owner_local_response_bytes_before_close: 0,
            owner_local_no_http_101_observed: true,
            owner_local_registration_observed: true,
            owner_local_registration_unclaimed_before_close: true,
            owner_local_registration_reclaimed: true,
            owner_local_application_dispatch_delta: 0,
            owner_local_capacity_status: 429,
            owner_local_capacity_admission_limit: true,
            owner_local_capacity_not_dispatched: true,
            remote_barrier_reached: true,
            remote_barrier_hits: 1,
            remote_response_bytes_before_close: 0,
            remote_no_http_101_observed: true,
            remote_registration_observed: true,
            remote_registration_claimed_before_close: true,
            remote_registration_reclaimed: true,
            remote_application_dispatch_delta: 0,
            remote_capacity_status: 429,
            remote_capacity_admission_limit: true,
            remote_capacity_not_dispatched: true,
            sibling_baseline_echo: true,
            sibling_recovery_echo: true,
            cleanup_joined: true,
        }
    }

    #[test]
    fn validator_rejects_every_required_negative_or_impossible_field() {
        type Mutator = (&'static str, fn(&mut PublicAbandonedUpgradeEvidence));
        validate_public_abandoned_upgrade_evidence(&valid()).expect("complete evidence is valid");
        let mutators: &[Mutator] = &[
            ("scope", |e| e.scope = "wrong"),
            ("relay_count", |e| e.relay_count = 2),
            ("actual_cli_processes", |e| e.actual_cli_processes = 1),
            ("owner_local_barrier_reached", |e| {
                e.owner_local_barrier_reached = false
            }),
            ("owner_local_barrier_hits", |e| {
                e.owner_local_barrier_hits = 2
            }),
            ("owner_local_response_bytes_before_close", |e| {
                e.owner_local_response_bytes_before_close = 1
            }),
            ("owner_local_no_http_101_observed", |e| {
                e.owner_local_no_http_101_observed = false
            }),
            ("owner_local_registration_observed", |e| {
                e.owner_local_registration_observed = false
            }),
            ("owner_local_registration_unclaimed_before_close", |e| {
                e.owner_local_registration_unclaimed_before_close = false
            }),
            ("owner_local_registration_reclaimed", |e| {
                e.owner_local_registration_reclaimed = false
            }),
            ("owner_local_application_dispatch_delta", |e| {
                e.owner_local_application_dispatch_delta = 1
            }),
            ("owner_local_capacity_status", |e| {
                e.owner_local_capacity_status = 200
            }),
            ("owner_local_capacity_admission_limit", |e| {
                e.owner_local_capacity_admission_limit = false
            }),
            ("owner_local_capacity_not_dispatched", |e| {
                e.owner_local_capacity_not_dispatched = false
            }),
            ("remote_no_http_101_observed", |e| {
                e.remote_no_http_101_observed = false
            }),
            ("sibling_baseline_echo", |e| e.sibling_baseline_echo = false),
            ("sibling_recovery_echo", |e| e.sibling_recovery_echo = false),
            ("remote_barrier_reached", |e| {
                e.remote_barrier_reached = false
            }),
            ("remote_barrier_hits", |e| e.remote_barrier_hits = 2),
            ("remote_response_bytes_before_close", |e| {
                e.remote_response_bytes_before_close = 1
            }),
            ("remote_registration_observed", |e| {
                e.remote_registration_observed = false
            }),
            ("remote_registration_claimed_before_close", |e| {
                e.remote_registration_claimed_before_close = false
            }),
            ("remote_registration_reclaimed", |e| {
                e.remote_registration_reclaimed = false
            }),
            ("remote_application_dispatch_delta", |e| {
                e.remote_application_dispatch_delta = 1
            }),
            ("remote_capacity_status", |e| e.remote_capacity_status = 200),
            ("remote_capacity_admission_limit", |e| {
                e.remote_capacity_admission_limit = false
            }),
            ("remote_capacity_not_dispatched", |e| {
                e.remote_capacity_not_dispatched = false
            }),
            ("cleanup_joined", |e| e.cleanup_joined = false),
        ];
        for &(name, mutate) in mutators {
            let mut evidence = valid();
            mutate(&mut evidence);
            let diagnostic = match name {
                "relay_count" | "actual_cli_processes" => "expected three relays",
                "owner_local_barrier_hits" | "remote_barrier_hits" => "barrier hit count",
                "owner_local_response_bytes_before_close"
                | "remote_response_bytes_before_close" => "pre-close response bytes",
                "owner_local_application_dispatch_delta" | "remote_application_dispatch_delta" => {
                    "advanced application dispatch"
                }
                value if value.contains("capacity_") => "capacity probe was not exact",
                value => value,
            };
            assert_rejected(
                validate_public_abandoned_upgrade_evidence(&evidence),
                diagnostic,
            );
        }
    }
}
