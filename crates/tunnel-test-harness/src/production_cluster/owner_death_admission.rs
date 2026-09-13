//! Owner death during control and data admission (EC-023).
//!
//! The i04 fail-closed gate kills a real owner during one un-barriered
//! in-flight consumer request.  This fixture adds the two *separately
//! barriered* death points EC-023 requires: the owner process is killed while
//! a real public request is held at exactly one deterministic seam, once during
//! control admission (the ingress has resolved the owner route but has not yet
//! opened the one-hop peer stream) and once during data attachment (the owner
//! admitted the stream and the ingress is holding before the 101).  In both
//! cases the in-flight request must end with a typed 503 owner-loss outcome and
//! zero application dispatch, no stale owner session may survive, and fresh
//! ownership must be required afterwards.  The data-attachment seam proves the
//! exact `not_dispatched` certainty (the ingress re-reads the owner before the
//! upgrade and never opens the body stream); the control-admission seam is
//! honestly `unknown` (the owner relay is still up, so the peer stream opens and
//! the owner-side rejects mid-admission) with zero dispatch asserted directly.

use super::admission::{PublicStreamProbe, open_public_stream_with_authorization};
use super::{ConsumerStream, ProductionCluster, start_cli_smoke};
use crate::acceptance::helpers::{DeviceProfile, write_device_profile};
use crate::{
    Harness, HarnessError, HarnessOptions, ManagedProcess, OidcTokenOptions, Result, RunningHarness,
};
use chrono::Utc;
use std::time::Duration;
use tokio::time::{Instant, sleep, timeout};
use tunnel_relay::{ConsumerUpgradeBarrier, PeerAdmissionBarrier, PeerAdmissionScope};
use uuid::Uuid;

const INGRESS_NODE: &str = "relay-c";
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(180);
const PHASE_TIMEOUT: Duration = Duration::from_secs(30);
const OWNER_CLEAR_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const CANARY: &[u8] = b"m7-ec023-canary";

/// The typed internal failure codes for an owner-selection failure at the
/// ingress after the owner disappeared.  The fixture never accepts a silent
/// success or a non-503 status; the acceptable execution certainty per seam is
/// decided by `classify_typed_rejection`.
const OWNER_LOSS_CODES: [&str; 4] = [
    "PEER_UNAVAILABLE",
    "PEER_UNTRUSTED",
    "OWNER_CHANGED",
    "OWNER_EXPIRED",
];

/// Payload-free evidence for the owner-death-during-admission race.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ec023OwnerDeathEvidence {
    pub relay_count: usize,
    // ---- Control admission: killed while held before the one-hop peer open ----
    pub control_admission_barrier_hit: bool,
    pub control_owner_killed: bool,
    pub control_typed_outcome: bool,
    pub control_no_upgrade: bool,
    pub control_dispatch_delta: u64,
    pub control_owner_cleared: bool,
    pub control_no_stale_session: bool,
    pub control_owner_identity_required_fresh: bool,
    // ---- Data attachment: killed while held after admission, before the 101 ----
    pub data_attach_barrier_hit: bool,
    pub data_owner_killed: bool,
    pub data_typed_not_dispatched: bool,
    pub data_no_upgrade: bool,
    pub data_dispatch_delta: u64,
    pub data_owner_cleared: bool,
    pub data_no_stale_session: bool,
    pub data_owner_identity_required_fresh: bool,
    // ---- Recovery: a fresh owner and session serve one dispatch ----
    pub fresh_ownership_recovered: bool,
    pub recovery_dispatch_delta: u64,
    pub cleanup_joined: bool,
}

pub fn validate_ec023_owner_death_evidence(evidence: &Ec023OwnerDeathEvidence) -> Result<()> {
    let required = [
        ("three relays", evidence.relay_count == 3),
        (
            "control admission barrier hit",
            evidence.control_admission_barrier_hit,
        ),
        ("control owner killed", evidence.control_owner_killed),
        ("control typed outcome", evidence.control_typed_outcome),
        ("control no upgrade", evidence.control_no_upgrade),
        ("control owner cleared", evidence.control_owner_cleared),
        (
            "control no stale session",
            evidence.control_no_stale_session,
        ),
        (
            "control owner identity required fresh",
            evidence.control_owner_identity_required_fresh,
        ),
        (
            "data attachment barrier hit",
            evidence.data_attach_barrier_hit,
        ),
        ("data owner killed", evidence.data_owner_killed),
        (
            "data typed not_dispatched",
            evidence.data_typed_not_dispatched,
        ),
        ("data no upgrade", evidence.data_no_upgrade),
        ("data owner cleared", evidence.data_owner_cleared),
        ("data no stale session", evidence.data_no_stale_session),
        (
            "data owner identity required fresh",
            evidence.data_owner_identity_required_fresh,
        ),
        (
            "fresh ownership recovered",
            evidence.fresh_ownership_recovered,
        ),
        ("joined cleanup", evidence.cleanup_joined),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "EC-023 owner death gate was false: {name}"
        )));
    }
    if evidence.control_dispatch_delta != 0 {
        return Err(HarnessError::Process(format!(
            "EC-023 control-admission kill dispatched: {}",
            evidence.control_dispatch_delta
        )));
    }
    if evidence.data_dispatch_delta != 0 {
        return Err(HarnessError::Process(format!(
            "EC-023 data-attachment kill dispatched: {}",
            evidence.data_dispatch_delta
        )));
    }
    if evidence.recovery_dispatch_delta != 1 {
        return Err(HarnessError::Process(format!(
            "EC-023 recovery did not dispatch exactly once: {}",
            evidence.recovery_dispatch_delta
        )));
    }
    Ok(())
}

/// Run the real owner-death-during-admission race.
pub async fn verify() -> Result<Ec023OwnerDeathEvidence> {
    // Distinct devices per phase: each connector is a separate owner killed at
    // most once, which avoids the reconnect-timing fragility of repeatedly
    // resurrecting one device identity after a SIGKILL.
    let options = HarnessOptions::from_env()?.rotation(tunnel_core::RotationConfig::default());
    let mut harness = timeout(super::STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("EC-023 harness startup timed out".into()))??;

    let peer_barrier = std::sync::Arc::new(PeerAdmissionBarrier::default());
    let upgrade_barriers: std::collections::BTreeMap<
        String,
        std::sync::Arc<ConsumerUpgradeBarrier>,
    > = ["relay-a", "relay-b", "relay-c"]
        .into_iter()
        .map(|node| {
            (
                node.to_owned(),
                std::sync::Arc::new(ConsumerUpgradeBarrier::default()),
            )
        })
        .collect();
    let run_upgrade_barriers = upgrade_barriers
        .iter()
        .map(|(node, barrier)| (node.clone(), std::sync::Arc::clone(barrier)))
        .collect();

    let mut cluster = match ProductionCluster::start_with_peer_and_upgrade_barriers(
        &mut harness,
        INGRESS_NODE,
        std::sync::Arc::clone(&peer_barrier),
        upgrade_barriers,
        64,
    )
    .await
    {
        Ok(cluster) => cluster,
        Err(primary) => {
            return match harness.shutdown().await {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(HarnessError::Process(format!(
                    "{primary}; EC-023 harness cleanup failed: {cleanup}"
                ))),
            };
        }
    };

    let mut resources = OwnerDeathResources::default();
    let scenario = timeout(
        SCENARIO_TIMEOUT,
        run(
            &mut cluster,
            &harness,
            &peer_barrier,
            &run_upgrade_barriers,
            &mut resources,
        ),
    )
    .await
    .map_err(|_| HarnessError::Timeout("EC-023 owner death race timed out".into()))?;

    let cleanup = resources.cleanup().await;
    let cluster_cleanup = cluster.shutdown().await;
    let harness_cleanup = harness.shutdown().await;

    let (mut evidence, mut failure) = match scenario {
        Ok(evidence) => (Some(evidence), None),
        Err(error) => (None, Some(error)),
    };
    append_cleanup(&mut failure, "EC-023 resources", cleanup);
    append_cleanup(&mut failure, "EC-023 relay cleanup", cluster_cleanup);
    append_cleanup(&mut failure, "EC-023 catalog cleanup", harness_cleanup);
    if let Some(evidence) = evidence.as_mut() {
        evidence.cleanup_joined = failure.is_none();
        if failure.is_none()
            && let Err(error) = validate_ec023_owner_death_evidence(evidence)
        {
            evidence.cleanup_joined = false;
            failure = Some(error);
        }
    }
    match (evidence, failure) {
        (Some(evidence), None) => Ok(evidence),
        (_, Some(error)) => Err(error),
        (None, None) => Err(HarnessError::Process(
            "EC-023 produced no evidence or failure".into(),
        )),
    }
}

/// One live device connector: its process (until killed), its startup consumer
/// stream and the profile/temp dir kept alive for the process's lifetime.
#[derive(Default)]
struct DeviceConnector {
    process: Option<ManagedProcess>,
    stream: Option<ConsumerStream>,
    _profile: Option<DeviceProfile>,
    _profile_dir: Option<tempfile::TempDir>,
}

#[derive(Default)]
struct OwnerDeathResources {
    connectors: Vec<DeviceConnector>,
}

impl OwnerDeathResources {
    async fn cleanup(&mut self) -> Result<()> {
        let mut first = None;
        for mut connector in self.connectors.drain(..) {
            if let Some(mut stream) = connector.stream.take() {
                append_cleanup(&mut first, "EC-023 consumer stream", stream.close().await);
            }
            if let Some(process) = connector.process.take() {
                let result = process
                    .shutdown(Duration::from_secs(5))
                    .await
                    .map(|_| ())
                    .map_err(|error| {
                        HarnessError::Process(format!("EC-023 connector shutdown: {error}"))
                    });
                append_cleanup(&mut first, "EC-023 connector", result);
            }
        }
        match first {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    peer_barrier: &PeerAdmissionBarrier,
    upgrade_barriers: &std::collections::BTreeMap<String, std::sync::Arc<ConsumerUpgradeBarrier>>,
    resources: &mut OwnerDeathResources,
) -> Result<Ec023OwnerDeathEvidence> {
    cluster
        .wait_for_peer_readiness(super::STARTUP_TIMEOUT)
        .await?;

    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(300),
            ..OidcTokenOptions::default()
        },
    )?;
    let authorization = format!("Bearer {token}");
    let server_ca = harness.pki.server_ca.certificate_der.clone();
    let peer_ingress = cluster.relay(INGRESS_NODE)?.consumer_addr()?;

    // Three distinct devices, one per phase.
    let control_device = device_at(harness, 0)?;
    let data_device = device_at(harness, 1)?;
    let recovery_device = device_at(harness, 2)?;

    // ================= Phase 1: control admission =================
    // The peer-admission barrier lives only on the ingress relay, so owner one
    // must not be the ingress; the first device lands its control on relay-a.
    let (owner1, owner1_node, control_idx) =
        start_owner(cluster, harness, resources, &token, control_device).await?;
    if owner1_node == INGRESS_NODE {
        return Err(HarnessError::Process(
            "EC-023 control-phase owner landed on the ingress relay".into(),
        ));
    }
    let service1_path = control_device.service_id.to_string();
    let scope = PeerAdmissionScope::for_owner(&owner1.token, control_device.service_id);
    if !peer_barrier.arm(scope.clone()) {
        return Err(HarnessError::Process(
            "EC-023 peer admission barrier was already armed".into(),
        ));
    }
    let phase1_deadline = Instant::now() + PHASE_TIMEOUT;
    let mut held = Box::pin(open_public_stream_with_authorization(
        peer_ingress,
        &server_ca,
        &authorization,
        control_device.id,
        &service1_path,
        &[],
    ));
    tokio::select! {
        result = &mut held => {
            return Err(early_result_error("EC-023 control-admission", result));
        }
        waited = timeout(remaining(phase1_deadline), peer_barrier.wait_reached()) => {
            waited.map_err(|_| HarnessError::Timeout(
                "EC-023 control-admission barrier was not reached".into(),
            ))?;
        }
    }
    let control_admission_barrier_hit =
        peer_barrier.hit_count() == 1 && peer_barrier.observed_scope() == Some(scope);

    // Kill the owner while the request is pinned at control admission, then let
    // the authoritative Redis owner disappear before releasing the barrier.
    let before = total_dispatch(cluster).await?;
    let control_owner_killed = kill_owner(resources, control_idx).await?;
    cluster
        .wait_for_owner_clear(
            control_device.tenant_id,
            control_device.id,
            OWNER_CLEAR_TIMEOUT,
        )
        .await?;
    let control_owner_cleared =
        owner_absent(cluster, control_device.tenant_id, control_device.id).await?;
    peer_barrier.release();
    let outcome = timeout(remaining(phase1_deadline), &mut held)
        .await
        .map_err(|_| HarnessError::Timeout("EC-023 control-admission result timed out".into()))??;
    let (control_typed_outcome, control_no_upgrade) =
        classify_typed_rejection(outcome, false, "EC-023 control-admission").await?;
    let after = total_dispatch(cluster).await?;
    let control_dispatch_delta = after.saturating_sub(before);
    let control_no_stale_session = no_session_for(cluster, &owner1_node, control_device.id).await?;
    let control_owner_identity_required_fresh = owner_is_fresh_or_absent(
        cluster,
        control_device.tenant_id,
        control_device.id,
        &owner1.token,
    )
    .await?;

    // ================= Phase 2: data attachment =================
    let (owner2, owner2_node, data_idx) =
        start_owner(cluster, harness, resources, &token, data_device).await?;
    // The upgrade seam lives on every relay, so the ingress is chosen as any
    // relay that is not the current owner: the held request then crosses one
    // real peer hop to the owner and is pinned before the 101.
    let data_ingress_node = ["relay-a", "relay-b", "relay-c"]
        .into_iter()
        .find(|node| *node != owner2_node)
        .ok_or_else(|| HarnessError::Process("EC-023 found no non-owner ingress".into()))?;
    let upgrade_barrier = upgrade_barriers.get(data_ingress_node).ok_or_else(|| {
        HarnessError::Process("EC-023 upgrade barrier missing for the data ingress".into())
    })?;
    let data_ingress = cluster.relay(data_ingress_node)?.consumer_addr()?;
    let service2_path = data_device.service_id.to_string();
    if !upgrade_barrier.arm() {
        return Err(HarnessError::Process(
            "EC-023 data attachment barrier was already armed".into(),
        ));
    }
    let phase2_deadline = Instant::now() + PHASE_TIMEOUT;
    let mut held = Box::pin(open_public_stream_with_authorization(
        data_ingress,
        &server_ca,
        &authorization,
        data_device.id,
        &service2_path,
        &[],
    ));
    tokio::select! {
        result = &mut held => {
            return Err(early_result_error("EC-023 data-attachment", result));
        }
        waited = timeout(remaining(phase2_deadline), upgrade_barrier.wait_reached()) => {
            waited.map_err(|_| HarnessError::Timeout(
                "EC-023 data-attachment barrier was not reached".into(),
            ))?;
        }
    }
    let data_attach_barrier_hit = upgrade_barrier.hit_count() == 1;

    let before = total_dispatch(cluster).await?;
    let data_owner_killed = kill_owner(resources, data_idx).await?;
    cluster
        .wait_for_owner_clear(data_device.tenant_id, data_device.id, OWNER_CLEAR_TIMEOUT)
        .await?;
    let data_owner_cleared = owner_absent(cluster, data_device.tenant_id, data_device.id).await?;
    upgrade_barrier.release();
    let outcome = timeout(remaining(phase2_deadline), &mut held)
        .await
        .map_err(|_| HarnessError::Timeout("EC-023 data-attachment result timed out".into()))??;
    let (data_typed_not_dispatched, data_no_upgrade) =
        classify_typed_rejection(outcome, true, "EC-023 data-attachment").await?;
    let after = total_dispatch(cluster).await?;
    let data_dispatch_delta = after.saturating_sub(before);
    let data_no_stale_session = no_session_for(cluster, &owner2_node, data_device.id).await?;
    let data_owner_identity_required_fresh = owner_is_fresh_or_absent(
        cluster,
        data_device.tenant_id,
        data_device.id,
        &owner2.token,
    )
    .await?;

    // ================= Recovery: a fresh owner serves one dispatch =========
    let (_owner3, _owner3_node, recovery_idx) =
        start_owner(cluster, harness, resources, &token, recovery_device).await?;
    let before = total_dispatch(cluster).await?;
    resources.connectors[recovery_idx]
        .stream
        .as_mut()
        .ok_or_else(|| HarnessError::Process("EC-023 recovery stream was lost".into()))?
        .round_trip(&[], CANARY)
        .await
        .map_err(|error| HarnessError::Http(format!("EC-023 recovery echo: {error}")))?;
    let after = total_dispatch(cluster).await?;
    let recovery_dispatch_delta = after.saturating_sub(before);
    let fresh_ownership_recovered = recovery_dispatch_delta == 1;

    Ok(Ec023OwnerDeathEvidence {
        relay_count: cluster.relays.len(),
        control_admission_barrier_hit,
        control_owner_killed,
        control_typed_outcome,
        control_no_upgrade,
        control_dispatch_delta,
        control_owner_cleared,
        control_no_stale_session,
        control_owner_identity_required_fresh,
        data_attach_barrier_hit,
        data_owner_killed,
        data_typed_not_dispatched,
        data_no_upgrade,
        data_dispatch_delta,
        data_owner_cleared,
        data_no_stale_session,
        data_owner_identity_required_fresh,
        fresh_ownership_recovered,
        recovery_dispatch_delta,
        cleanup_joined: false,
    })
}

/// One device's identity and credentials for a phase.
#[derive(Clone, Copy)]
struct PhaseDevice<'a> {
    id: Uuid,
    tenant_id: Uuid,
    service_id: Uuid,
    certificate_pem: &'a str,
    private_key_pem: &'a str,
}

fn device_at(harness: &RunningHarness, index: usize) -> Result<PhaseDevice<'_>> {
    let device =
        harness.topology.devices_a.get(index).ok_or_else(|| {
            HarnessError::InvalidInput(format!("EC-023 device {index} is missing"))
        })?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| {
            HarnessError::InvalidInput(format!("EC-023 service for device {index} is missing"))
        })?;
    Ok(PhaseDevice {
        id: device.id,
        tenant_id: device.tenant_id,
        service_id,
        certificate_pem: &device.certificate.certificate_pem,
        private_key_pem: &device.certificate.private_key_pem,
    })
}

/// Start a real connector for `device` and wait for it to hold a fresh owner
/// lease.  The connector's startup consumer stream is opened through the ingress
/// relay.  Returns the owner claim, its node id, and the connector's index in
/// `resources.connectors` (so a phase can kill exactly this owner later).
async fn start_owner(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    resources: &mut OwnerDeathResources,
    token: &str,
    device: PhaseDevice<'_>,
) -> Result<(tunnel_catalog::OwnerClaim, String, usize)> {
    // A prior held request that raced an owner death may have withdrawn a peer
    // route's readiness (mark_route_unreachable); wait for the signed mesh to
    // recover so the fresh connector's data path can reach a ready owner.
    cluster
        .wait_for_peer_readiness(super::STARTUP_TIMEOUT)
        .await?;
    let profile_dir = tempfile::tempdir().map_err(HarnessError::Io)?;
    let mut profile = write_device_profile(
        profile_dir.path(),
        device.id,
        device.service_id,
        std::str::from_utf8(CANARY).expect("canary is ascii"),
        cluster.device_fanout.local_addr(),
        device.certificate_pem,
        device.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile.config.rotation = tunnel_core::RotationConfig::default();
    profile
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("EC-023 config: {error}")))?;
    let ingress = cluster.relay(INGRESS_NODE)?.consumer_addr()?;
    let (process, stream) = start_cli_smoke(
        harness,
        cluster.device_fanout.local_addr(),
        ingress,
        &profile,
        token,
        device.id,
        device.service_id,
    )
    .await?;
    let index = resources.connectors.len();
    resources.connectors.push(DeviceConnector {
        process: Some(process),
        stream: Some(stream),
        _profile: Some(profile),
        _profile_dir: Some(profile_dir),
    });
    let owner = wait_for_owner(cluster, device.tenant_id, device.id).await?;
    let node = owner.token.node_id.clone();
    Ok((owner, node, index))
}

/// SIGKILL the owner connector at `index`; the owner ends only through lease
/// and control-socket loss, never a clean shutdown.
async fn kill_owner(resources: &mut OwnerDeathResources, index: usize) -> Result<bool> {
    let process = resources
        .connectors
        .get_mut(index)
        .and_then(|connector| connector.process.take())
        .ok_or_else(|| HarnessError::Process("EC-023 owner connector was lost".into()))?;
    let status = process
        .shutdown(Duration::ZERO)
        .await
        .map_err(|error| HarnessError::Process(format!("EC-023 owner kill: {error}")))?;
    Ok(!status.success())
}

async fn wait_for_owner(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
) -> Result<tunnel_catalog::OwnerClaim> {
    let deadline = Instant::now() + super::STARTUP_TIMEOUT;
    loop {
        if let Some(owner) = cluster
            .catalog
            .current_owner(tenant_id, device_id, Utc::now())
            .await
            .map_err(|error| HarnessError::Redis(format!("EC-023 owner lookup: {error}")))?
        {
            return Ok(owner);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "EC-023 owner did not become visible".into(),
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}

/// Classify the held request's terminal outcome as a typed owner-selection
/// rejection with no 101 upgrade.  An accepted upgrade or a 200 is a hard
/// failure: a request held while the owner dies must never be dispatched.
///
/// `strict` requires exact `not_dispatched` execution certainty (the
/// data-attachment seam, where the ingress re-reads the owner before upgrade
/// and never opens the body stream).  Non-strict also accepts `unknown`: at the
/// control-admission seam the owner relay is still up, so the ingress opens the
/// one-hop peer stream and the owner-side rejects mid-admission; the ingress
/// then honestly reports `unknown` rather than claiming `not_dispatched`.  Zero
/// application dispatch is asserted separately by the caller either way.
async fn classify_typed_rejection(
    outcome: PublicStreamProbe,
    strict: bool,
    label: &str,
) -> Result<(bool, bool)> {
    match outcome {
        PublicStreamProbe::Accepted(mut stream) => {
            let _ = stream.close().await;
            Err(HarnessError::Process(format!(
                "{label} upgraded to 101 after the owner died"
            )))
        }
        PublicStreamProbe::Rejected(failure) => {
            let acceptable_execution = if strict {
                failure.execution == Some("not_dispatched")
            } else {
                matches!(failure.execution, Some("not_dispatched") | Some("unknown"))
            };
            let typed = failure.status == 503
                && failure
                    .code
                    .is_some_and(|code| OWNER_LOSS_CODES.contains(&code))
                && acceptable_execution;
            if !typed {
                return Err(HarnessError::Process(format!(
                    "{label} was not a typed owner-loss rejection: status={} code={:?} execution={:?}",
                    failure.status, failure.code, failure.execution
                )));
            }
            Ok((true, true))
        }
    }
}

async fn total_dispatch(cluster: &ProductionCluster) -> Result<u64> {
    let mut total = 0_u64;
    for relay in &cluster.relays {
        let snapshot = relay.snapshot().await?;
        total = total.saturating_add(snapshot.lifetime_application_dispatches);
    }
    Ok(total)
}

async fn owner_absent(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
) -> Result<bool> {
    Ok(cluster
        .catalog
        .current_owner(tenant_id, device_id, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("EC-023 owner absence: {error}")))?
        .is_none())
}

async fn owner_is_fresh_or_absent(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    dead: &tunnel_catalog::OwnerToken,
) -> Result<bool> {
    Ok(cluster
        .catalog
        .current_owner(tenant_id, device_id, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("EC-023 owner freshness: {error}")))?
        .is_none_or(|owner| owner.token != *dead))
}

/// Prove no stale owner session survives for the device on the dead owner's
/// relay: the killed connector's control socket loss removed its session.
async fn no_session_for(
    cluster: &ProductionCluster,
    node_id: &str,
    device_id: Uuid,
) -> Result<bool> {
    let deadline = Instant::now() + OWNER_CLEAR_TIMEOUT;
    loop {
        let snapshot = cluster.relay(node_id)?.snapshot().await?;
        let has_session = snapshot
            .sessions
            .iter()
            .any(|session| session.device_id == device_id.to_string());
        if !has_session {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        sleep(POLL_INTERVAL).await;
    }
}

fn early_result_error(label: &str, result: Result<PublicStreamProbe>) -> HarnessError {
    match result {
        Ok(PublicStreamProbe::Accepted(_)) => {
            HarnessError::Process(format!("{label} upgraded before its barrier"))
        }
        Ok(PublicStreamProbe::Rejected(failure)) => HarnessError::Process(format!(
            "{label} was rejected before its barrier: status={} code={:?} execution={:?}",
            failure.status, failure.code, failure.execution
        )),
        Err(error) => HarnessError::Http(format!("{label} ended before its barrier: {error}")),
    }
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn append_cleanup(slot: &mut Option<HarnessError>, label: &str, result: Result<()>) {
    if let Err(error) = result {
        let combined = match slot.take() {
            Some(primary) => HarnessError::Process(format!("{primary}; {label}: {error}")),
            None => HarnessError::Process(format!("{label}: {error}")),
        };
        *slot = Some(combined);
    }
}

#[cfg(test)]
mod c17_validator_tests {
    use super::*;
    use crate::acceptance_test_support::{assert_failed, assert_rejected};

    fn valid_evidence() -> Ec023OwnerDeathEvidence {
        Ec023OwnerDeathEvidence {
            relay_count: 3,
            control_admission_barrier_hit: true,
            control_owner_killed: true,
            control_typed_outcome: true,
            control_no_upgrade: true,
            control_dispatch_delta: 0,
            control_owner_cleared: true,
            control_no_stale_session: true,
            control_owner_identity_required_fresh: true,
            data_attach_barrier_hit: true,
            data_owner_killed: true,
            data_typed_not_dispatched: true,
            data_no_upgrade: true,
            data_dispatch_delta: 0,
            data_owner_cleared: true,
            data_no_stale_session: true,
            data_owner_identity_required_fresh: true,
            fresh_ownership_recovered: true,
            recovery_dispatch_delta: 1,
            cleanup_joined: true,
        }
    }

    #[test]
    fn ec023_validator_accepts_complete_evidence() {
        assert!(validate_ec023_owner_death_evidence(&valid_evidence()).is_ok());
    }

    #[test]
    fn every_ec023_required_flag_reaches_the_shared_exit_path() {
        type Disable = (&'static str, fn(&mut Ec023OwnerDeathEvidence));
        let flags: [Disable; 16] = [
            ("control_admission_barrier_hit", |e| {
                e.control_admission_barrier_hit = false
            }),
            ("control_owner_killed", |e| e.control_owner_killed = false),
            ("control_typed_outcome", |e| e.control_typed_outcome = false),
            ("control_no_upgrade", |e| e.control_no_upgrade = false),
            ("control_owner_cleared", |e| e.control_owner_cleared = false),
            ("control_no_stale_session", |e| {
                e.control_no_stale_session = false
            }),
            ("control_owner_identity_required_fresh", |e| {
                e.control_owner_identity_required_fresh = false
            }),
            ("data_attach_barrier_hit", |e| {
                e.data_attach_barrier_hit = false
            }),
            ("data_owner_killed", |e| e.data_owner_killed = false),
            ("data_typed_not_dispatched", |e| {
                e.data_typed_not_dispatched = false
            }),
            ("data_no_upgrade", |e| e.data_no_upgrade = false),
            ("data_owner_cleared", |e| e.data_owner_cleared = false),
            ("data_no_stale_session", |e| e.data_no_stale_session = false),
            ("data_owner_identity_required_fresh", |e| {
                e.data_owner_identity_required_fresh = false
            }),
            ("fresh_ownership_recovered", |e| {
                e.fresh_ownership_recovered = false
            }),
            ("cleanup_joined", |e| e.cleanup_joined = false),
        ];
        for (_, disable) in flags {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_failed(validate_ec023_owner_death_evidence(&evidence));
        }
    }

    #[test]
    fn every_ec023_dispatch_delta_reaches_the_shared_exit_path() {
        type Mutate = (&'static str, fn(&mut Ec023OwnerDeathEvidence));
        let counts: [Mutate; 5] = [
            ("relay_count", |e| e.relay_count = 2),
            ("control_dispatch_delta", |e| e.control_dispatch_delta = 1),
            ("data_dispatch_delta", |e| e.data_dispatch_delta = 1),
            ("recovery_dispatch_none", |e| e.recovery_dispatch_delta = 0),
            ("recovery_dispatch_double", |e| {
                e.recovery_dispatch_delta = 2
            }),
        ];
        for (_, mutate) in counts {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(validate_ec023_owner_death_evidence(&evidence), "EC-023");
        }
    }
}
