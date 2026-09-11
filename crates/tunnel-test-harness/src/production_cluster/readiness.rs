//! Production M7-C20 peer route reachability and capacity gate.
//!
//! This scenario uses the real in-process relay listeners, Redis membership
//! directory, device connector, and consumer HTTPS route.  The UDP fault is
//! injected only around the signed private endpoint; membership and Redis stay
//! healthy throughout the loss and recovery phases.

use super::{
    LIVEZ_BODY, ProductionCluster, RunningHarness, SCENARIO_TIMEOUT, STARTUP_TIMEOUT,
    UNREADYZ_BODY, assert_public_health_ready, is_partition_admission_response,
    open_consumer_stream, start_cli_smoke, wait_for_public_health_ready,
};
use crate::acceptance::helpers::write_device_profile;
use crate::{Harness, HarnessError, HarnessOptions, ManagedProcess, Result};
use chrono::Utc;
use std::time::{Duration, Instant};
use tempfile::tempdir;
use tokio::time::{sleep, timeout};
use tunnel_relay::{MembershipReadiness, RelaySnapshot};

const TARGET_NODE: &str = "relay-a";
const INGRESS_NODE: &str = "relay-b";
const PEER_LOSS_TIMEOUT: Duration = Duration::from_secs(12);
const PEER_RECOVERY_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const DIAGNOSTIC_TIMEOUT: Duration = Duration::from_millis(500);

/// Evidence from the real production peer-route loss/recovery gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerReadinessEvidence {
    pub relay_count: usize,
    pub membership_ready_relays: usize,
    pub baseline_echo: bool,
    pub public_livez_ok_during_loss: bool,
    pub public_readyz_unready_during_loss: bool,
    pub selected_dispatch_not_advanced: bool,
    pub route_recovered: bool,
    pub public_readyz_ok_after_recovery: bool,
    pub recovery_echo: bool,
    pub elapsed_ms: u64,
}

/// Validate the C20 gate's bounded evidence contract.
pub fn validate_peer_readiness_evidence(evidence: &PeerReadinessEvidence) -> Result<()> {
    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "peer-readiness requires exactly three relays, observed {}",
            evidence.relay_count
        )));
    }
    if evidence.membership_ready_relays != 3 {
        return Err(HarnessError::Process(format!(
            "peer-readiness requires three Ready memberships, observed {}",
            evidence.membership_ready_relays
        )));
    }
    let required = [
        ("baseline_echo", evidence.baseline_echo),
        (
            "public_livez_ok_during_loss",
            evidence.public_livez_ok_during_loss,
        ),
        (
            "public_readyz_unready_during_loss",
            evidence.public_readyz_unready_during_loss,
        ),
        (
            "selected_dispatch_not_advanced",
            evidence.selected_dispatch_not_advanced,
        ),
        ("route_recovered", evidence.route_recovered),
        (
            "public_readyz_ok_after_recovery",
            evidence.public_readyz_ok_after_recovery,
        ),
        ("recovery_echo", evidence.recovery_echo),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "peer-readiness required gate {name} was false"
        )));
    }
    Ok(())
}

/// Run the bounded production C20 gate with full cleanup and joined relay
/// refresh tasks.
pub async fn verify() -> Result<PeerReadinessEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(super::ROTATION)
        .shared_device_uuid(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("peer-readiness harness startup timed out".into()))??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };

    let scenario = match timeout(SCENARIO_TIMEOUT, run(&mut cluster, &harness)).await {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "peer-readiness production scenario exceeded its bounded deadline".into(),
        )),
    };
    let cluster_cleanup = cluster.shutdown().await;
    let harness_cleanup = harness.shutdown().await;
    match (scenario, cluster_cleanup, harness_cleanup) {
        (Ok(evidence), Ok(()), Ok(())) => Ok(evidence),
        (scenario, cluster_cleanup, harness_cleanup) => {
            let mut failure = scenario.err();
            if let Err(error) = cluster_cleanup {
                append_cleanup_failure(&mut failure, "peer-readiness relay cleanup", error);
            }
            if let Err(error) = harness_cleanup {
                append_cleanup_failure(&mut failure, "peer-readiness Redis cleanup", error);
            }
            Err(failure.expect("peer-readiness cleanup failure was not recorded"))
        }
    }
}

fn append_cleanup_failure(slot: &mut Option<HarnessError>, label: &str, error: HarnessError) {
    *slot = Some(match slot.take() {
        Some(primary) => HarnessError::Process(format!("{primary}; {label}: {error}")),
        None => HarnessError::Process(format!("{label}: {error}")),
    });
}

async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
) -> Result<PeerReadinessEvidence> {
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(format!(
            "peer-readiness gate started {} relays, expected three",
            cluster.relays.len()
        )));
    }
    cluster.wait_for_peer_readiness(STARTUP_TIMEOUT).await?;
    let membership_ready_relays = cluster
        .relays
        .iter()
        .filter(|relay| matches!(relay.membership.readiness(), MembershipReadiness::Ready))
        .count();
    if membership_ready_relays != cluster.relays.len() {
        return Err(HarnessError::Process(format!(
            "peer-readiness gate started with {membership_ready_relays}/{} relays Ready",
            cluster.relays.len()
        )));
    }

    let ingress_addr = cluster.relay(INGRESS_NODE)?.consumer_addr()?;
    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("peer-readiness device is missing".into()))?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("peer-readiness service is missing".into()))?;
    let canary = format!("m7-peer-readiness:{}", device.id);
    let profile_directory = tempdir().map_err(HarnessError::Io)?;
    let mut profile = write_device_profile(
        profile_directory.path(),
        device.id,
        service_id,
        &canary,
        cluster.device_fanout.local_addr(),
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile.config.rotation = super::ROTATION;
    profile.config.validate().map_err(|error| {
        HarnessError::InvalidInput(format!("peer-readiness client config: {error}"))
    })?;
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        super::OidcTokenOptions {
            expires_in: Duration::from_secs(90),
            ..super::OidcTokenOptions::default()
        },
    )?;

    let started = Instant::now();
    let (mut owner_process, mut owner_stream) = start_cli_smoke(
        harness,
        cluster.device_fanout.local_addr(),
        ingress_addr,
        &profile,
        &token,
        device.id,
        service_id,
    )
    .await?;
    let owner = cluster
        .catalog
        .current_owner(device.tenant_id, device.id, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("reading peer-readiness owner: {error}")))?
        .ok_or_else(|| HarnessError::Process("peer-readiness owner is missing".into()))?;
    if owner.token.node_id != TARGET_NODE {
        let _ = owner_process.shutdown(Duration::from_secs(2)).await;
        return Err(HarnessError::Process(format!(
            "peer-readiness owner landed on {}, expected {TARGET_NODE}",
            owner.token.node_id
        )));
    }
    owner_stream
        .round_trip(b"peer-readiness-baseline", canary.as_bytes())
        .await
        .map_err(|error| {
            HarnessError::Http(format!(
                "peer-readiness baseline echo failed: {error}; {}",
                peer_readiness_context(cluster)
            ))
        })?;
    owner_stream.close().await?;
    assert_public_health_ready(ingress_addr, &harness.pki.server_ca.certificate_der)
        .await
        .map_err(|error| {
            HarnessError::Http(format!(
                "peer-readiness baseline /readyz failed: {error}; {}",
                peer_readiness_context(cluster)
            ))
        })?;
    let baseline_snapshot = cluster.relay(TARGET_NODE)?.snapshot().await?;
    let baseline_dispatch = super::device_dispatch_counter(&baseline_snapshot, device.id);

    cluster.set_peer_path_drop(TARGET_NODE, true)?;
    let (public_livez_ok_during_loss, public_readyz_unready_during_loss) = wait_for_public_loss(
        cluster,
        ingress_addr,
        &harness.pki.server_ca.certificate_der,
    )
    .await?;
    let membership_still_ready = cluster
        .relays
        .iter()
        .all(|relay| matches!(relay.membership.readiness(), MembershipReadiness::Ready));
    if !membership_still_ready {
        let _ = owner_process.shutdown(Duration::from_secs(2)).await;
        return Err(HarnessError::Process(format!(
            "peer UDP loss unexpectedly changed signed membership readiness; {}",
            peer_readiness_context(cluster)
        )));
    }

    let admission = timeout(
        super::REDIS_PARTITION_OPERATION_TIMEOUT,
        open_consumer_stream(
            ingress_addr,
            &harness.pki.server_ca.certificate_der,
            &token,
            device.id,
            service_id,
        ),
    )
    .await;
    let selected_not_dispatched = match admission {
        Err(_) => {
            let _ = owner_process.shutdown(Duration::from_secs(2)).await;
            return Err(HarnessError::Timeout(
                "peer-readiness loss admission did not fail within its bound".into(),
            ));
        }
        Ok(Err(super::StreamConnectFailure::Status { status, body }))
            if is_partition_admission_response(status, body.as_deref()) =>
        {
            true
        }
        Ok(Err(super::StreamConnectFailure::Status { status, .. })) => {
            let _ = owner_process.shutdown(Duration::from_secs(2)).await;
            return Err(HarnessError::Http(format!(
                "peer-readiness loss returned unexpected HTTP status {status}"
            )));
        }
        Ok(Err(super::StreamConnectFailure::Harness(error))) => {
            let _ = owner_process.shutdown(Duration::from_secs(2)).await;
            return Err(error);
        }
        Ok(Ok(mut stream)) => {
            let _ = stream.close().await;
            let _ = owner_process.shutdown(Duration::from_secs(2)).await;
            return Err(HarnessError::Process(
                "peer-readiness loss admitted a selected owner stream".into(),
            ));
        }
    };
    let after_loss_snapshot = cluster.relay(TARGET_NODE)?.snapshot().await?;
    let selected_dispatch_not_advanced = selected_not_dispatched
        && super::device_dispatch_counter(&after_loss_snapshot, device.id) <= baseline_dispatch;
    if !selected_dispatch_not_advanced {
        let _ = owner_process.shutdown(Duration::from_secs(2)).await;
        return Err(HarnessError::Process(format!(
            "peer-readiness loss advanced selected-owner dispatch; {}",
            peer_readiness_context(cluster)
        )));
    }

    cluster.set_peer_path_drop(TARGET_NODE, false)?;
    cluster
        .wait_for_peer_readiness(PEER_RECOVERY_TIMEOUT)
        .await
        .map_err(|error| {
            HarnessError::Timeout(format!(
                "peer-readiness route recovery failed: {error}; {}",
                peer_readiness_context(cluster)
            ))
        })?;
    wait_for_public_health_ready(ingress_addr, &harness.pki.server_ca.certificate_der)
        .await
        .map_err(|error| {
            HarnessError::Http(format!(
                "peer-readiness recovery /readyz failed: {error}; {}",
                peer_readiness_context(cluster)
            ))
        })?;
    let recovery_deadline = Instant::now() + PEER_RECOVERY_TIMEOUT;
    let recovery_baseline =
        wait_for_stable_owner_snapshot(cluster, device.id, recovery_deadline).await?;
    let mut recovery_stream = wait_for_recovery_stream(
        cluster,
        tunnel_relay::routing::OwnerScope::new(device.tenant_id, device.id),
        ingress_addr,
        &harness.pki.server_ca.certificate_der,
        &token,
        service_id,
        recovery_deadline,
    )
    .await?;
    if let Err(error) = wait_for_remote_consumer_registration(
        cluster,
        device.id,
        &recovery_baseline,
        recovery_deadline,
    )
    .await
    {
        let _ = recovery_stream.close().await;
        let context = recovery_context(cluster, device.tenant_id, device.id).await;
        return Err(HarnessError::Process(format!(
            "peer-readiness recovery owner admission did not converge: {error}; {context}"
        )));
    }
    if let Err(error) = recovery_stream
        .round_trip(b"peer-readiness-recovery", canary.as_bytes())
        .await
    {
        let recovery_after = match cluster.relay(TARGET_NODE) {
            Ok(relay) => bounded_relay_snapshot(relay).await,
            Err(_) => None,
        };
        let context = recovery_failure_context(
            cluster,
            &mut owner_process,
            device.tenant_id,
            device.id,
            Some(&recovery_baseline),
            recovery_after.as_ref(),
            &error,
        )
        .await;
        return Err(HarnessError::Http(format!(
            "peer-readiness recovery echo failed: {error}; {context}"
        )));
    }
    recovery_stream.close().await?;
    let _ = owner_process.shutdown(Duration::from_secs(5)).await;
    cluster
        .wait_for_no_owner(device.tenant_id, device.id)
        .await?;
    super::wait_for_fanout_drained(&cluster.device_fanout, "peer-readiness").await?;

    Ok(PeerReadinessEvidence {
        relay_count: cluster.relays.len(),
        membership_ready_relays,
        baseline_echo: true,
        public_livez_ok_during_loss,
        public_readyz_unready_during_loss,
        selected_dispatch_not_advanced,
        route_recovered: true,
        public_readyz_ok_after_recovery: true,
        recovery_echo: true,
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

async fn wait_for_public_loss(
    cluster: &ProductionCluster,
    ingress_addr: std::net::SocketAddr,
    server_ca_der: &[u8],
) -> Result<(bool, bool)> {
    let deadline = Instant::now() + PEER_LOSS_TIMEOUT;
    loop {
        let live = super::public_health_request(ingress_addr, server_ca_der, "/livez").await;
        let ready = super::public_health_request(ingress_addr, server_ca_der, "/readyz").await;
        let live_ok = live
            .as_ref()
            .is_ok_and(|response| response.status == 200 && response.body.as_slice() == LIVEZ_BODY);
        let ready_unready = ready.as_ref().is_ok_and(|response| {
            response.status == 503 && response.body.as_slice() == UNREADYZ_BODY
        });
        if live_ok && ready_unready && !cluster.relay(INGRESS_NODE)?.peer_runtime.is_ready() {
            return Ok((true, true));
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "peer-readiness loss did not produce livez=200/readyz=503; {}",
                peer_readiness_context(cluster)
            )));
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_recovery_stream(
    cluster: &ProductionCluster,
    owner_scope: tunnel_relay::routing::OwnerScope,
    ingress_addr: std::net::SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    service_id: uuid::Uuid,
    deadline: Instant,
) -> Result<super::ConsumerStream> {
    let tenant_id = owner_scope.tenant_id;
    let device_id = owner_scope.device_id;
    loop {
        match open_consumer_stream(ingress_addr, server_ca_der, token, device_id, service_id).await
        {
            Ok(stream) => return Ok(stream),
            Err(super::StreamConnectFailure::Status { status, body })
                if is_partition_admission_response(status, body.as_deref())
                    && Instant::now() < deadline => {}
            Err(super::StreamConnectFailure::Status { status, .. }) => {
                let context = recovery_context(cluster, tenant_id, device_id).await;
                return Err(HarnessError::Http(format!(
                    "peer-readiness recovery returned unexpected HTTP status {status}; {context}"
                )));
            }
            Err(super::StreamConnectFailure::Harness(error))
                if is_transient_recovery_handshake(&error) && Instant::now() < deadline => {}
            Err(super::StreamConnectFailure::Harness(error)) => {
                let context = recovery_context(cluster, tenant_id, device_id).await;
                return Err(HarnessError::Process(format!(
                    "peer-readiness recovery handshake failed: {error}; {context}"
                )));
            }
        }
        if Instant::now() >= deadline {
            let context = recovery_context(cluster, tenant_id, device_id).await;
            return Err(HarnessError::Timeout(format!(
                "peer-readiness recovery stream exceeded its bounded deadline; {context}"
            )));
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_stable_owner_snapshot(
    cluster: &ProductionCluster,
    device_id: uuid::Uuid,
    deadline: Instant,
) -> Result<RelaySnapshot> {
    loop {
        if let Some(snapshot) = owner_snapshot(cluster).await
            && owner_session_is_stable(&snapshot, device_id)
        {
            return Ok(snapshot);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "peer-readiness owner session did not reach stable active admission state".into(),
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_remote_consumer_registration(
    cluster: &ProductionCluster,
    device_id: uuid::Uuid,
    baseline: &RelaySnapshot,
    deadline: Instant,
) -> Result<()> {
    loop {
        if let Some(snapshot) = owner_snapshot(cluster).await
            && owner_session_is_stable(&snapshot, device_id)
            && has_new_nonterminal_stream(baseline, &snapshot, device_id)
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "peer-readiness remote consumer registration did not converge".into(),
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}

fn owner_session_is_stable(snapshot: &RelaySnapshot, device_id: uuid::Uuid) -> bool {
    snapshot.sessions.iter().any(|session| {
        session.device_id == device_id.to_string()
            && session.phase == "active"
            && session.sockets >= 2
            && session.candidate_generation.is_none()
    })
}

async fn owner_snapshot(cluster: &ProductionCluster) -> Option<RelaySnapshot> {
    match cluster.relay(TARGET_NODE) {
        Ok(relay) => bounded_relay_snapshot(relay).await,
        Err(_) => None,
    }
}

fn has_new_nonterminal_stream(
    baseline: &RelaySnapshot,
    current: &RelaySnapshot,
    device_id: uuid::Uuid,
) -> bool {
    let Some(baseline_session) = baseline
        .sessions
        .iter()
        .find(|session| session.device_id == device_id.to_string())
    else {
        return false;
    };
    current
        .sessions
        .iter()
        .find(|session| session.device_id == device_id.to_string())
        .is_some_and(|session| {
            session.session_id == baseline_session.session_id
                && session.epoch == baseline_session.epoch
                && session.streams.iter().any(|stream| {
                    !stream.terminal
                        && !baseline_session.streams.iter().any(|candidate| {
                            candidate.stream_id == stream.stream_id
                                && candidate.operation_id == stream.operation_id
                        })
                })
        })
}

fn peer_readiness_context(cluster: &ProductionCluster) -> String {
    let relays = cluster
        .relays
        .iter()
        .map(|relay| {
            let membership_ready =
                matches!(relay.membership.readiness(), MembershipReadiness::Ready);
            let peer = relay
                .peer_runtime
                .peer_readiness()
                .map(|readiness| format!("{:?}", readiness.snapshot()))
                .unwrap_or_else(|| "none".to_owned());
            format!(
                "{}(peer_ready={},membership_ready={},snapshot={peer})",
                relay.node_id,
                relay.peer_runtime.is_ready(),
                membership_ready
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("peer_state=[{relays}]")
}

async fn bounded_relay_snapshot(relay: &super::ProductionRelay) -> Option<RelaySnapshot> {
    timeout(DIAGNOSTIC_TIMEOUT, relay.snapshot())
        .await
        .ok()
        .and_then(|result| result.ok())
}

fn redacted_device_session(snapshot: &RelaySnapshot, device_id: uuid::Uuid) -> String {
    let Some(session) = snapshot
        .sessions
        .iter()
        .find(|session| session.device_id == device_id.to_string())
    else {
        return format!(
            "session=missing,dispatches={},stream_dispatches=0",
            snapshot.lifetime_application_dispatches
        );
    };
    let streams = session
        .streams
        .iter()
        .take(4)
        .map(|stream| {
            format!(
                "{{id={},emitted={},acked={},recv={},delivered={},replay_frames={},replay_bytes={},queue_bytes={},terminal={}}}",
                stream.stream_id,
                stream.last_emitted_relay_to_connector,
                stream.peer_acked_relay_to_connector,
                stream.recv_contiguous_connector_to_relay,
                stream.delivered_contiguous_connector_to_relay,
                stream.replay_frames_relay_to_connector,
                stream.replay_bytes_relay_to_connector,
                stream.queue_bytes,
                stream.terminal,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let omitted_streams = session.streams.len().saturating_sub(4);
    let stream_dispatches = session
        .streams
        .iter()
        .map(|stream| stream.last_emitted_relay_to_connector)
        .sum::<u64>();
    format!(
        "session=present,session_id={:?},epoch={},phase={},active_generation={},candidate_generation={:?},sockets={},queue_bytes={},queue_messages={},drain_fences={},drain_proofs={},replay_frames={},replay_bytes={},streams=[{}],omitted_streams={},dispatches={},stream_dispatches={}",
        session.session_id,
        session.epoch,
        session.phase,
        session.active_generation,
        session.candidate_generation,
        session.sockets,
        session.queue_bytes,
        session.queue_messages,
        session.drain_fences,
        session.drain_proofs,
        session.replay_frames,
        session.replay_bytes,
        streams,
        omitted_streams,
        snapshot.lifetime_application_dispatches,
        stream_dispatches,
    )
}

async fn redacted_device_sessions(cluster: &ProductionCluster, device_id: uuid::Uuid) -> String {
    let mut relays = Vec::with_capacity(cluster.relays.len());
    for relay in &cluster.relays {
        let state = match bounded_relay_snapshot(relay).await {
            Some(snapshot) => redacted_device_session(&snapshot, device_id),
            None => "snapshot=unavailable".to_owned(),
        };
        relays.push(format!("{}({state})", relay.node_id));
    }
    format!("relay_sessions=[{}]", relays.join(","))
}

async fn recovery_context(
    cluster: &ProductionCluster,
    tenant_id: uuid::Uuid,
    device_id: uuid::Uuid,
) -> String {
    let owner = match timeout(
        DIAGNOSTIC_TIMEOUT,
        cluster
            .catalog
            .current_owner(tenant_id, device_id, Utc::now()),
    )
    .await
    {
        Ok(Ok(Some(owner))) => owner.token.node_id,
        Ok(Ok(None)) => "none".to_owned(),
        Ok(Err(_)) => "catalog-error".to_owned(),
        Err(_) => "catalog-timeout".to_owned(),
    };
    format!(
        "{},owner={owner},{}",
        peer_readiness_context(cluster),
        redacted_device_sessions(cluster, device_id).await
    )
}

async fn recovery_failure_context(
    cluster: &ProductionCluster,
    owner_process: &mut ManagedProcess,
    tenant_id: uuid::Uuid,
    device_id: uuid::Uuid,
    before: Option<&RelaySnapshot>,
    after: Option<&RelaySnapshot>,
    error: &HarnessError,
) -> String {
    let owner = match timeout(
        DIAGNOSTIC_TIMEOUT,
        cluster
            .catalog
            .current_owner(tenant_id, device_id, Utc::now()),
    )
    .await
    {
        Ok(Ok(Some(owner))) => owner.token.node_id,
        Ok(Ok(None)) => "none".to_owned(),
        Ok(Err(_)) => "catalog-error".to_owned(),
        Err(_) => "catalog-timeout".to_owned(),
    };
    format!(
        "owner={owner},round_trip_stage={},dispatch_stage={},cli_terminal={},{}",
        recovery_echo_stage(error),
        dispatch_stage(before, after, device_id),
        cli_terminal_diagnostic(owner_process).await,
        redacted_device_sessions(cluster, device_id).await,
    )
}

fn dispatch_stage(
    before: Option<&RelaySnapshot>,
    after: Option<&RelaySnapshot>,
    device_id: uuid::Uuid,
) -> String {
    let format_snapshot = |label: &str, snapshot: Option<&RelaySnapshot>| {
        let Some(snapshot) = snapshot else {
            return format!("{label}=unavailable");
        };
        let stream_dispatches = device_stream_dispatches(snapshot, device_id);
        format!(
            "{label}={{lifetime={},device_stream_emitted={stream_dispatches}}}",
            snapshot.lifetime_application_dispatches
        )
    };
    let delta = match (before, after) {
        (Some(before), Some(after)) => format!(
            "lifetime_delta={},device_stream_delta={}",
            after
                .lifetime_application_dispatches
                .saturating_sub(before.lifetime_application_dispatches),
            device_stream_dispatches(after, device_id)
                .saturating_sub(device_stream_dispatches(before, device_id)),
        ),
        _ => "delta=unavailable".to_owned(),
    };
    format!(
        "{}, {}, {delta}",
        format_snapshot("before", before),
        format_snapshot("after", after)
    )
}

fn device_stream_dispatches(snapshot: &RelaySnapshot, device_id: uuid::Uuid) -> u64 {
    snapshot
        .sessions
        .iter()
        .find(|session| session.device_id == device_id.to_string())
        .map(|session| {
            session
                .streams
                .iter()
                .map(|stream| stream.last_emitted_relay_to_connector)
                .sum()
        })
        .unwrap_or_default()
}

fn recovery_echo_stage(error: &HarnessError) -> &'static str {
    match error {
        HarnessError::Http(message) if message.starts_with("sending production echo:") => "send",
        HarnessError::Http(message)
            if message.starts_with("production echo closed before response") =>
        {
            "awaiting_response_close"
        }
        HarnessError::Http(message) if message.starts_with("reading production echo:") => {
            "awaiting_response_read"
        }
        HarnessError::Http(message) if message.starts_with("echo pong:") => "responding_ping",
        HarnessError::Http(message) if message.starts_with("production echo response mismatch") => {
            "validating_response"
        }
        HarnessError::Http(message)
            if message.starts_with("production echo response exceeded")
                || message.starts_with("production echo response declared")
                || message.starts_with("production echo response contained")
                || message.starts_with("production echo response omitted") =>
        {
            "reassembling_response"
        }
        HarnessError::Timeout(_) => "awaiting_response_timeout",
        _ => "other",
    }
}

struct ClientDiagnosticFields {
    code: &'static str,
    retryable: &'static str,
    phase: &'static str,
}

impl ClientDiagnosticFields {
    fn new() -> Self {
        Self {
            code: "missing",
            retryable: "missing",
            phase: "missing",
        }
    }
}

fn collect_client_json_errors(bytes: &[u8], fields: &mut ClientDiagnosticFields) {
    for line in bytes.split(|byte| *byte == b'\n') {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        let error = value.get("error").unwrap_or(&value);
        if let Some(code) = error.get("code").and_then(serde_json::Value::as_str) {
            fields.code = safe_client_code(code);
        }
        if let Some(retryable) = error.get("retryable").and_then(serde_json::Value::as_bool) {
            fields.retryable = if retryable { "true" } else { "false" };
        }
        if let Some(phase) = error.get("phase").and_then(serde_json::Value::as_str) {
            fields.phase = safe_client_phase(phase);
        }
    }
}

fn safe_client_code(code: &str) -> &'static str {
    match code {
        "INVALID_CONFIG" => "INVALID_CONFIG",
        "CREDENTIAL_ERROR" => "CREDENTIAL_ERROR",
        "INVALID_INVOCATION" => "INVALID_INVOCATION",
        "PROTOCOL_ERROR" => "PROTOCOL_ERROR",
        "TRANSPORT_ERROR" => "TRANSPORT_ERROR",
        "OWNER_BUSY" => "OWNER_BUSY",
        "DEADLINE_EXCEEDED" => "DEADLINE_EXCEEDED",
        "AUTHORIZATION_STALE" => "AUTHORIZATION_STALE",
        "RESOURCE_EXHAUSTED" => "RESOURCE_EXHAUSTED",
        "CANCELLED" => "CANCELLED",
        "SUPERVISOR_FAILED" => "SUPERVISOR_FAILED",
        "SESSION_CLOSED" => "SESSION_CLOSED",
        _ => "other",
    }
}

fn safe_client_phase(phase: &str) -> &'static str {
    match phase {
        "connecting" => "connecting",
        "control_open" => "control_open",
        "data_opening" => "data_opening",
        "active" => "active",
        "preparing" => "preparing",
        "quiescing" => "quiescing",
        "draining" => "draining",
        "committing" => "committing",
        "retiring" => "retiring",
        "recovering" => "recovering",
        "stopping" => "stopping",
        "closed" => "closed",
        _ => "other",
    }
}

async fn cli_terminal_diagnostic(process: &mut ManagedProcess) -> String {
    let process_state = match process.try_wait() {
        Ok(Some(status)) => format!(
            "state=exited,success={},exit_code={},signal={}",
            status.success(),
            status
                .code()
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            process_signal(status).map_or_else(|| "none".to_owned(), |signal| signal.to_string())
        ),
        Ok(None) => "state=running".to_owned(),
        Err(_) => "state=unknown".to_owned(),
    };
    tokio::task::yield_now().await;
    let mut fields = ClientDiagnosticFields::new();
    collect_client_json_errors(&process.stdout(), &mut fields);
    collect_client_json_errors(&process.stderr(), &mut fields);
    format!(
        "{process_state},code={},retryable={},phase={}",
        fields.code, fields.retryable, fields.phase
    )
}

#[cfg(unix)]
fn process_signal(status: std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;

    status.signal()
}

#[cfg(not(unix))]
fn process_signal(_status: std::process::ExitStatus) -> Option<i32> {
    None
}

fn is_transient_recovery_handshake(error: &HarnessError) -> bool {
    match error {
        HarnessError::Timeout(message) => message == "consumer handshake timed out",
        HarnessError::Http(message) => message.starts_with("consumer handshake failed:"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClientDiagnosticFields, PeerReadinessEvidence, collect_client_json_errors,
        recovery_echo_stage, validate_peer_readiness_evidence,
    };
    use crate::HarnessError;
    use crate::acceptance_test_support::assert_rejected;

    fn valid_evidence() -> PeerReadinessEvidence {
        PeerReadinessEvidence {
            relay_count: 3,
            membership_ready_relays: 3,
            baseline_echo: true,
            public_livez_ok_during_loss: true,
            public_readyz_unready_during_loss: true,
            selected_dispatch_not_advanced: true,
            route_recovered: true,
            public_readyz_ok_after_recovery: true,
            recovery_echo: true,
            elapsed_ms: 1_000,
        }
    }

    #[test]
    fn validation_rejects_each_required_false_gate() {
        type DisabledGate = (&'static str, fn(&mut PeerReadinessEvidence));
        let fields: [DisabledGate; 7] = [
            ("baseline_echo", |e| e.baseline_echo = false),
            ("public_livez_ok_during_loss", |e| {
                e.public_livez_ok_during_loss = false
            }),
            ("public_readyz_unready_during_loss", |e| {
                e.public_readyz_unready_during_loss = false
            }),
            ("selected_dispatch_not_advanced", |e| {
                e.selected_dispatch_not_advanced = false
            }),
            ("route_recovered", |e| e.route_recovered = false),
            ("public_readyz_ok_after_recovery", |e| {
                e.public_readyz_ok_after_recovery = false
            }),
            ("recovery_echo", |e| e.recovery_echo = false),
        ];
        for (name, disable) in fields {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_rejected(validate_peer_readiness_evidence(&evidence), name);
        }
    }

    #[test]
    fn validation_requires_three_relays_and_three_ready_memberships() {
        let mut evidence = valid_evidence();
        evidence.relay_count = 2;
        assert_rejected(validate_peer_readiness_evidence(&evidence), "three relays");
        let mut evidence = valid_evidence();
        evidence.membership_ready_relays = 2;
        assert_rejected(
            validate_peer_readiness_evidence(&evidence),
            "three Ready memberships",
        );
    }

    #[test]
    fn recovery_diagnostics_keep_only_safe_cli_fields() {
        let mut fields = ClientDiagnosticFields::new();
        collect_client_json_errors(
            br#"{"error":{"code":"SESSION_CLOSED","message":"secret-payload","retryable":true,"phase":"active"}}"#,
            &mut fields,
        );
        assert_eq!(fields.code, "SESSION_CLOSED");
        assert_eq!(fields.retryable, "true");
        assert_eq!(fields.phase, "active");
        assert_ne!(fields.code, "secret-payload");

        collect_client_json_errors(
            br#"{"error":{"code":"SECRET_INTERNAL_CODE","message":"secret-payload","retryable":false}}"#,
            &mut fields,
        );
        assert_eq!(fields.code, "other");
        assert_eq!(fields.retryable, "false");
    }

    #[test]
    fn recovery_echo_stage_classifies_closed_response() {
        let error = HarnessError::Http("production echo closed before response".into());
        assert_eq!(recovery_echo_stage(&error), "awaiting_response_close");
    }

    #[test]
    fn peer_readiness_validator_accepts_complete_evidence() {
        validate_peer_readiness_evidence(&valid_evidence())
            .expect("complete peer-readiness evidence is valid");
    }
}
