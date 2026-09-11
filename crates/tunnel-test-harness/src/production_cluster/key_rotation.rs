//! Phase-observed peer-key revocation during a scheduled M2 rotation.
//!
//! The ordinary production flow keeps its broad routing sequence unchanged.
//! This focused gate waits for the real connector and owner actors to publish
//! a pre-commit rotation phase, withdraws one relay's peer pins at that
//! barrier, and then proves either retained same-owner recovery or an
//! explicit fenced-session handoff.

use super::{
    ConsumerStream, ProductionCluster, RunningHarness, connect_failure_to_harness,
    is_expected_revocation_close, is_peer_recovery_response, open_consumer_stream,
    publish_verified_pins, redacted_status, wait_for_fanout_drained,
};
use crate::acceptance::helpers::write_device_profile;
use crate::{ConnectionId, Direction, HarnessError, ProxyConfig, ProxyHandle, Result, TcpProxy};
use chrono::Utc;
use std::time::{Duration, Instant};
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::OwnerClaim;
use tunnel_client::{ConnectOptions, ConnectionHandle, ConnectionStatus, TransportProfile};
use tunnel_transport::SpkiSha256;
use uuid::Uuid;

const PHASE_WAIT_TIMEOUT: Duration = Duration::from_secs(15);
const RECOVERY_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Payload-free evidence from the phase-observed peer-key/rotation gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRotationEvidence {
    /// Number of production relays serving during the gate.
    pub relay_count: usize,
    /// Connector phase at which the pin withdrawal was applied.
    pub rotation_phase: String,
    /// Candidate generation held at the withdrawal barrier.
    pub candidate_generation: u64,
    /// The existing TCP proxy acknowledged a pause on the active data
    /// direction before the candidate barrier was observed.
    pub data_direction_barrier_applied: bool,
    /// The fail-closed pin snapshot was published and observed.
    pub pin_revocation_observed: bool,
    /// The in-flight consumer record received an explicit interruption.
    pub stream_interrupted: bool,
    /// Recovery retained the original owner/session identity and returned one
    /// fresh canary response.
    pub same_owner_recovery: bool,
    /// Recovery required a fresh fenced session with a higher owner epoch.
    pub fresh_session_recovery: bool,
    /// The interrupted record was dispatched at most once before and during
    /// recovery, based on every relay's application-dispatch counters.
    pub duplicate_response_rejected: bool,
    /// The fresh-session branch observed a strictly higher owner epoch.
    pub owner_epoch_advanced: bool,
    /// Maximum simultaneously open device fanout/proxy sockets.
    pub fanout_peak_open: usize,
    /// Wall-clock milliseconds spent in the focused gate.
    pub elapsed_ms: u64,
}

/// Validate the focused gate's bounded outcome contract.
pub fn validate_key_rotation_evidence(evidence: &KeyRotationEvidence) -> Result<()> {
    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "key-rotation expected three relays, observed {}",
            evidence.relay_count
        )));
    }
    let required = [
        (
            "data_direction_barrier_applied",
            evidence.data_direction_barrier_applied,
        ),
        ("pin_revocation_observed", evidence.pin_revocation_observed),
        ("stream_interrupted", evidence.stream_interrupted),
        (
            "duplicate_response_rejected",
            evidence.duplicate_response_rejected,
        ),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "key-rotation required gate {name} was false"
        )));
    }
    if !matches!(
        evidence.rotation_phase.as_str(),
        "preparing" | "quiescing" | "draining"
    ) {
        return Err(HarnessError::Process(format!(
            "key-rotation withdrawal occurred outside a scheduled drain phase: {}",
            evidence.rotation_phase
        )));
    }
    if evidence.candidate_generation == 0 {
        return Err(HarnessError::Process(
            "key-rotation withdrawal did not observe a candidate generation".into(),
        ));
    }
    if evidence.same_owner_recovery == evidence.fresh_session_recovery {
        return Err(HarnessError::Process(
            "key-rotation must report exactly one recovery outcome".into(),
        ));
    }
    if evidence.fresh_session_recovery && !evidence.owner_epoch_advanced {
        return Err(HarnessError::Process(
            "fresh key-rotation recovery did not advance the owner epoch".into(),
        ));
    }
    if evidence.fanout_peak_open > 3 {
        return Err(HarnessError::Process(format!(
            "key-rotation fanout exceeded the bounded three-socket peak: {}",
            evidence.fanout_peak_open
        )));
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct RotationBarrier {
    phase: String,
    candidate_generation: u64,
}

#[derive(Clone, Debug)]
enum RecoveryOutcome {
    SameOwner,
    FreshSession { owner_epoch: u64 },
}

/// Run one real three-relay peer-key revocation while a scheduled rotation is
/// in its pre-commit drain.  The scenario uses status and owner snapshots as
/// phase barriers, revalidates the same candidate after pin withdrawal, and
/// fails closed if the observed phase has already committed.
pub(super) async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
) -> Result<KeyRotationEvidence> {
    let device_proxy =
        TcpProxy::bind(cluster.device_fanout.local_addr(), ProxyConfig::default()).await?;
    let scenario = run_with_proxy(cluster, harness, &device_proxy).await;
    let proxy_cleanup = timeout(super::CLEANUP_TIMEOUT, device_proxy.shutdown()).await;
    let proxy_cleanup = match proxy_cleanup {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "key-rotation device proxy cleanup timed out".into(),
        )),
    };
    match (scenario, proxy_cleanup) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(evidence), Ok(())) => Ok(evidence),
    }
}

async fn run_with_proxy(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    device_proxy: &ProxyHandle,
) -> Result<KeyRotationEvidence> {
    let started = Instant::now();
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(format!(
            "key-rotation gate started {} relays, expected three",
            cluster.relays.len()
        )));
    }
    let ready = cluster
        .relays
        .iter()
        .filter(|relay| {
            matches!(
                relay.membership.readiness(),
                tunnel_relay::MembershipReadiness::Ready
            )
        })
        .count();
    if ready != 3 {
        return Err(HarnessError::Process(format!(
            "key-rotation gate started with {ready}/3 relays Ready"
        )));
    }

    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("key-rotation device is missing".into()))?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("key-rotation service is missing".into()))?;
    let canary = format!("m7-key-rotation:{}", device.id);
    let profile_directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    let mut profile = write_device_profile(
        profile_directory.path(),
        device.id,
        service_id,
        &canary,
        device_proxy.local_addr(),
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile.config.rotation = super::ROTATION;
    profile.config.validate().map_err(|error| {
        HarnessError::InvalidInput(format!("key-rotation client config: {error}"))
    })?;

    let mut client = connect_client(profile.config.clone()).await?;
    let session = timeout(super::STARTUP_TIMEOUT, client.wait_ready())
        .await
        .map_err(|_| HarnessError::Timeout("key-rotation client readiness timed out".into()))?
        .map_err(|error| {
            HarnessError::Process(format!("key-rotation client not ready: {error}"))
        })?;
    let owner_before = cluster
        .catalog
        .current_owner(device.tenant_id, device.id, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("reading key-rotation owner: {error}")))?
        .ok_or_else(|| {
            HarnessError::Process("key-rotation client did not retain an owner".into())
        })?;
    if owner_before.token.node_id != "relay-a" {
        let _ = client.stop().await;
        return Err(HarnessError::Process(format!(
            "key-rotation owner landed on {} instead of relay-a",
            owner_before.token.node_id
        )));
    }
    if owner_before.token.session_id != session.session_id
        || owner_before.token.epoch != session.epoch
        || !cluster
            .relays
            .iter()
            .any(|relay| relay.node_id == owner_before.token.node_id)
    {
        let _ = client.stop().await;
        return Err(HarnessError::Process(
            "key-rotation owner did not match the ready client session".into(),
        ));
    }

    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        crate::OidcTokenOptions {
            expires_in: Duration::from_secs(90),
            ..crate::OidcTokenOptions::default()
        },
    )?;
    // Relay-C is the non-owner ingress in this fixture.  Keeping the ingress
    // fixed makes the pin withdrawal cross the private H3 hop rather than
    // accidentally probing a local consumer route.
    let relay = cluster.relay("relay-c")?;
    let relay_consumer_addr = relay.consumer_addr()?;
    let mut stream = open_consumer_stream(
        relay_consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &token,
        device.id,
        service_id,
    )
    .await
    .map_err(connect_failure_to_harness)?;
    stream
        .round_trip(b"m7-key-rotation-baseline", canary.as_bytes())
        .await?;

    let active_status = client.status_snapshot();
    let active_data_connection = match wait_for_proxy_connection(device_proxy, &active_status).await
    {
        Ok(connection) => connection,
        Err(error) => {
            let _ = client.stop().await;
            return Err(error);
        }
    };
    if let Err(error) = device_proxy
        .pause(Direction::ClientToTarget, active_data_connection)
        .await
    {
        let _ = client.stop().await;
        return Err(error);
    }
    let data_direction_barrier_applied = true;
    let barrier = match wait_for_rotation_barrier(cluster, &client, &owner_before).await {
        Ok(barrier) => barrier,
        Err(error) => {
            resume_data_direction(device_proxy, active_data_connection).await;
            let _ = client.stop().await;
            return Err(error);
        }
    };
    let dispatch_before = match total_application_dispatches(cluster).await {
        Ok(dispatches) => dispatches,
        Err(error) => {
            resume_data_direction(device_proxy, active_data_connection).await;
            let _ = client.stop().await;
            return Err(error);
        }
    };
    let pins_before = relay.pins.snapshot();
    if pins_before.is_empty() {
        resume_data_direction(device_proxy, active_data_connection).await;
        let _ = stream.close().await;
        let _ = client.stop().await;
        return Err(HarnessError::Process(
            "key-rotation gate began with empty relay-C peer pins".into(),
        ));
    }
    if let Err(error) = relay.pins.replace(std::iter::empty::<SpkiSha256>()) {
        resume_data_direction(device_proxy, active_data_connection).await;
        let _ = stream.close().await;
        let _ = client.stop().await;
        return Err(HarnessError::Process(format!(
            "revoking key-rotation pins: {error}"
        )));
    }
    let pins_after = relay.pins.snapshot();
    let pin_revocation_observed =
        pins_after.is_empty() && pins_after.revision() > pins_before.revision();
    if !pin_revocation_observed {
        resume_data_direction(device_proxy, active_data_connection).await;
        let _ = stream.close().await;
        let _ = client.stop().await;
        return Err(HarnessError::Process(
            "key-rotation gate did not observe the fail-closed pin revision".into(),
        ));
    }
    if let Err(error) = confirm_rotation_barrier(cluster, &client, &owner_before, &barrier).await {
        let _ = publish_verified_pins(&relay.membership, &relay.pins);
        resume_data_direction(device_proxy, active_data_connection).await;
        let _ = stream.close().await;
        let _ = client.stop().await;
        return Err(error);
    }

    let interrupted = stream
        .round_trip(
            format!(
                "m7-key-rotation-interrupted:{}",
                barrier.candidate_generation
            )
            .as_bytes(),
            canary.as_bytes(),
        )
        .await;
    let _ = stream.close().await;
    let stream_interrupted = match interrupted {
        Err(error) if is_expected_revocation_close(&error) => true,
        Err(error) => {
            let _ = publish_verified_pins(&relay.membership, &relay.pins);
            resume_data_direction(device_proxy, active_data_connection).await;
            let _ = client.stop().await;
            return Err(HarnessError::Process(format!(
                "key-rotation interrupted stream returned an unexpected outcome: {error}"
            )));
        }
        Ok(()) => {
            let _ = publish_verified_pins(&relay.membership, &relay.pins);
            resume_data_direction(device_proxy, active_data_connection).await;
            let _ = client.stop().await;
            return Err(HarnessError::Process(
                "key-rotation revoked peer unexpectedly returned an echo".into(),
            ));
        }
    };
    // Snapshot every relay after the failed request, then again before and
    // after the recovery canary.  A replay on the original or successor
    // owner therefore cannot hide behind the request-stream close.
    let dispatch_after = match total_application_dispatches(cluster).await {
        Ok(dispatches) => dispatches,
        Err(error) => {
            let _ = publish_verified_pins(&relay.membership, &relay.pins);
            resume_data_direction(device_proxy, active_data_connection).await;
            let _ = client.stop().await;
            return Err(error);
        }
    };
    let mut duplicate_response_rejected = dispatch_after.saturating_sub(dispatch_before) <= 1;
    if !duplicate_response_rejected {
        let _ = publish_verified_pins(&relay.membership, &relay.pins);
        resume_data_direction(device_proxy, active_data_connection).await;
        let _ = client.stop().await;
        return Err(HarnessError::Process(format!(
            "key-rotation interrupted payload dispatched more than once: before={dispatch_before}, after={dispatch_after}"
        )));
    }

    if let Err(error) = publish_verified_pins(&relay.membership, &relay.pins) {
        resume_data_direction(device_proxy, active_data_connection).await;
        let _ = client.stop().await;
        return Err(error);
    }
    resume_data_direction(device_proxy, active_data_connection).await;
    let outcome = wait_for_recovery_outcome(cluster, &client, &owner_before).await?;
    let (
        same_owner_recovery,
        fresh_session_recovery,
        owner_epoch_advanced,
        dispatch_before_recovery_echo,
    ) = match outcome {
        RecoveryOutcome::SameOwner => {
            let dispatch_before_recovery_echo = total_application_dispatches(cluster).await?;
            verify_same_owner_echo(
                cluster,
                harness,
                &token,
                device.id,
                service_id,
                canary.as_bytes(),
                &client,
                &owner_before,
            )
            .await?;
            let dispatch_after_recovery_echo = total_application_dispatches(cluster).await?;
            duplicate_response_rejected &=
                dispatch_after_recovery_echo.saturating_sub(dispatch_before_recovery_echo) <= 1;
            (true, false, false, dispatch_before_recovery_echo)
        }
        RecoveryOutcome::FreshSession { owner_epoch } => {
            let _ = client.stop().await;
            cluster
                .wait_for_no_owner(device.tenant_id, device.id)
                .await?;
            wait_for_fanout_drained(&cluster.device_fanout, "key-rotation predecessor").await?;
            let mut fresh = connect_client(profile.config.clone()).await?;
            let fresh_session = timeout(super::STARTUP_TIMEOUT, fresh.wait_ready())
                .await
                .map_err(|_| {
                    HarnessError::Timeout("key-rotation fresh client readiness timed out".into())
                })?
                .map_err(|error| {
                    HarnessError::Process(format!(
                        "key-rotation fresh client did not become ready: {error}"
                    ))
                })?;
            let fresh_owner = wait_for_fresh_owner(
                cluster,
                device.tenant_id,
                device.id,
                owner_before.token.epoch,
                &fresh_session.session_id,
            )
            .await?;
            let dispatch_before_recovery_echo = total_application_dispatches(cluster).await?;
            verify_fresh_echo(
                cluster,
                harness,
                &token,
                device.id,
                service_id,
                canary.as_bytes(),
            )
            .await?;
            let dispatch_after_recovery_echo = total_application_dispatches(cluster).await?;
            duplicate_response_rejected &=
                dispatch_after_recovery_echo.saturating_sub(dispatch_before_recovery_echo) <= 1;
            timeout(super::STARTUP_TIMEOUT, fresh.stop())
                .await
                .map_err(|_| {
                    HarnessError::Timeout("key-rotation fresh client shutdown timed out".into())
                })?
                .map_err(|error| {
                    HarnessError::Process(format!(
                        "key-rotation fresh client shutdown failed: {error}"
                    ))
                })?;
            (
                false,
                true,
                fresh_owner.token.epoch > owner_epoch,
                dispatch_before_recovery_echo,
            )
        }
    };

    if same_owner_recovery {
        timeout(super::STARTUP_TIMEOUT, client.stop())
            .await
            .map_err(|_| HarnessError::Timeout("key-rotation client shutdown timed out".into()))?
            .map_err(|error| {
                HarnessError::Process(format!("key-rotation client shutdown failed: {error}"))
            })?;
    }
    wait_for_fanout_drained(&cluster.device_fanout, "key-rotation recovery").await?;
    let dispatch_after_cleanup = total_application_dispatches(cluster).await?;
    duplicate_response_rejected &=
        dispatch_after_cleanup.saturating_sub(dispatch_before_recovery_echo) <= 1;
    let proxy_peak_open =
        usize::try_from(device_proxy.diagnostics().peak_active).unwrap_or(usize::MAX);
    let fanout_peak_open = cluster
        .device_fanout
        .diagnostics()
        .peak_open
        .max(proxy_peak_open);
    if !duplicate_response_rejected {
        return Err(HarnessError::Process(
            "key-rotation interrupted record was dispatched more than once across recovery".into(),
        ));
    }

    Ok(KeyRotationEvidence {
        relay_count: cluster.relays.len(),
        rotation_phase: barrier.phase,
        candidate_generation: barrier.candidate_generation,
        data_direction_barrier_applied,
        pin_revocation_observed,
        stream_interrupted,
        same_owner_recovery,
        fresh_session_recovery,
        duplicate_response_rejected,
        owner_epoch_advanced,
        fanout_peak_open,
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

async fn connect_client(config: tunnel_client::ConnectConfig) -> Result<ConnectionHandle> {
    timeout(
        super::STARTUP_TIMEOUT,
        tunnel_client::connect(ConnectOptions {
            config,
            cancellation: CancellationToken::new(),
            profile: TransportProfile::M2,
        }),
    )
    .await
    .map_err(|_| HarnessError::Timeout("key-rotation client startup timed out".into()))?
    .map_err(|error| HarnessError::Process(format!("starting key-rotation client: {error}")))
}

async fn wait_for_proxy_connection(
    proxy: &ProxyHandle,
    status: &ConnectionStatus,
) -> Result<ConnectionId> {
    let source_addr = status.active_local_addr.ok_or_else(|| {
        HarnessError::Process(
            "key-rotation client did not publish an active data socket for the proxy barrier"
                .into(),
        )
    })?;
    let deadline = Instant::now() + PHASE_WAIT_TIMEOUT;
    loop {
        if let Some(connection) = proxy
            .diagnostics()
            .active_connections
            .into_iter()
            .find(|connection| connection.source_addr == source_addr)
        {
            return Ok(connection.id);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "key-rotation proxy did not expose active data socket {source_addr}"
            )));
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn resume_data_direction(proxy: &ProxyHandle, connection: ConnectionId) {
    let _ = proxy.resume(Direction::ClientToTarget, connection).await;
}

async fn wait_for_rotation_barrier(
    cluster: &ProductionCluster,
    client: &ConnectionHandle,
    owner: &OwnerClaim,
) -> Result<RotationBarrier> {
    let deadline = Instant::now() + PHASE_WAIT_TIMEOUT;
    loop {
        let status = client.status_snapshot();
        let phase = matches!(
            status.phase.as_str(),
            "preparing" | "quiescing" | "draining"
        );
        if phase
            && status.session_id.as_deref() == Some(owner.token.session_id.as_str())
            && status.epoch == Some(owner.token.epoch)
            && status.active_local_addr.is_some()
            && let Some(candidate_generation) = status.candidate_generation
        {
            let snapshot = cluster.relay(&owner.token.node_id)?.snapshot().await?;
            if let Some(session) = snapshot
                .sessions
                .iter()
                .find(|session| session.session_id == owner.token.session_id)
                && session.candidate_generation == Some(candidate_generation)
            {
                return Ok(RotationBarrier {
                    phase: status.phase,
                    candidate_generation,
                });
            }
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "key-rotation did not reach a scheduled pre-commit barrier: status={}",
                redacted_status(&status)
            )));
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn confirm_rotation_barrier(
    cluster: &ProductionCluster,
    client: &ConnectionHandle,
    owner: &OwnerClaim,
    barrier: &RotationBarrier,
) -> Result<()> {
    let status = client.status_snapshot();
    if !matches!(
        status.phase.as_str(),
        "preparing" | "quiescing" | "draining"
    ) || status.session_id.as_deref() != Some(owner.token.session_id.as_str())
        || status.epoch != Some(owner.token.epoch)
        || status.candidate_generation != Some(barrier.candidate_generation)
        || status.active_local_addr.is_none()
    {
        return Err(HarnessError::Process(format!(
            "key-rotation pin withdrawal raced past its phase barrier: status={}",
            redacted_status(&status)
        )));
    }
    let snapshot = cluster.relay(&owner.token.node_id)?.snapshot().await?;
    let Some(session) = snapshot
        .sessions
        .iter()
        .find(|session| session.session_id == owner.token.session_id)
    else {
        return Err(HarnessError::Process(
            "key-rotation owner session disappeared at pin withdrawal".into(),
        ));
    };
    if !matches!(
        session.phase.as_str(),
        "preparing" | "quiescing" | "draining"
    ) || session.candidate_generation != Some(barrier.candidate_generation)
    {
        return Err(HarnessError::Process(format!(
            "key-rotation relay phase did not hold at pin withdrawal: phase={}, candidate={:?}",
            session.phase, session.candidate_generation
        )));
    }
    Ok(())
}

async fn total_application_dispatches(cluster: &ProductionCluster) -> Result<u64> {
    let mut total = 0_u64;
    for relay in &cluster.relays {
        total = total.saturating_add(relay.snapshot().await?.lifetime_application_dispatches);
    }
    Ok(total)
}

async fn wait_for_recovery_outcome(
    cluster: &ProductionCluster,
    client: &ConnectionHandle,
    owner_before: &OwnerClaim,
) -> Result<RecoveryOutcome> {
    let deadline = Instant::now() + RECOVERY_WAIT_TIMEOUT;
    loop {
        let status = client.status_snapshot();
        let owner = timeout(
            super::REDIS_PARTITION_OPERATION_TIMEOUT
                .min(deadline.saturating_duration_since(Instant::now())),
            cluster.catalog.current_owner(
                owner_before.token.tenant_id,
                owner_before.token.device_id,
                Utc::now(),
            ),
        )
        .await;
        if let Ok(Ok(Some(owner))) = owner.as_ref()
            && owner.token == owner_before.token
            && status.phase == "active"
            && status.session_id.as_deref() == Some(owner_before.token.session_id.as_str())
            && status.epoch == Some(owner_before.token.epoch)
            && status.active_local_addr.is_some()
            && status.control_local_addr.is_some()
        {
            return Ok(RecoveryOutcome::SameOwner);
        }
        if matches!(status.phase.as_str(), "closed" | "failed") {
            return Ok(RecoveryOutcome::FreshSession {
                owner_epoch: owner_before.token.epoch,
            });
        }
        if let Ok(Ok(Some(owner))) = owner.as_ref()
            && (owner.token.session_id != owner_before.token.session_id
                || owner.token.epoch != owner_before.token.epoch)
        {
            return Ok(RecoveryOutcome::FreshSession {
                owner_epoch: owner_before.token.epoch,
            });
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "key-rotation recovery produced neither retained-owner nor explicit-fresh outcome: status={}",
                redacted_status(&status)
            )));
        }
        sleep(POLL_INTERVAL).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn verify_same_owner_echo(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
    canary: &[u8],
    client: &ConnectionHandle,
    expected_owner: &OwnerClaim,
) -> Result<()> {
    let status = client.status_snapshot();
    if status.phase != "active"
        || status.session_id.as_deref() != Some(expected_owner.token.session_id.as_str())
        || status.epoch != Some(expected_owner.token.epoch)
        || status.control_local_addr.is_none()
        || status.active_local_addr.is_none()
    {
        return Err(HarnessError::Process(format!(
            "key-rotation retained-owner status changed before echo: status={}",
            redacted_status(&status)
        )));
    }
    let current_owner = cluster
        .catalog
        .current_owner(
            expected_owner.token.tenant_id,
            expected_owner.token.device_id,
            Utc::now(),
        )
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("reading retained key-rotation owner: {error}"))
        })?
        .ok_or_else(|| {
            HarnessError::Process(
                "key-rotation retained-owner claim disappeared before echo".into(),
            )
        })?;
    if current_owner.token != expected_owner.token {
        return Err(HarnessError::Process(
            "key-rotation retained-owner echo observed a different owner token".into(),
        ));
    }
    let stream = open_restored_stream(cluster, harness, token, device_id, service_id).await?;
    let mut stream = stream;
    let result = stream.round_trip(b"m7-key-rotation-retained", canary).await;
    let _ = stream.close().await;
    result
}

async fn verify_fresh_echo(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
    canary: &[u8],
) -> Result<()> {
    let stream = open_restored_stream(cluster, harness, token, device_id, service_id).await?;
    let mut stream = stream;
    let result = stream.round_trip(b"m7-key-rotation-fresh", canary).await;
    let _ = stream.close().await;
    result
}

async fn open_restored_stream(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
) -> Result<ConsumerStream> {
    let deadline = Instant::now() + RECOVERY_WAIT_TIMEOUT;
    let consumer_addr = cluster.relay("relay-c")?.consumer_addr()?;
    loop {
        match open_consumer_stream(
            consumer_addr,
            &harness.pki.server_ca.certificate_der,
            token,
            device_id,
            service_id,
        )
        .await
        {
            Ok(stream) => return Ok(stream),
            Err(super::StreamConnectFailure::Status { status, body })
                if is_peer_recovery_response(status, body.as_deref())
                    && Instant::now() < deadline => {}
            Err(super::StreamConnectFailure::Status { status, .. }) => {
                return Err(HarnessError::Http(format!(
                    "key-rotation restored consumer returned HTTP status {status}"
                )));
            }
            Err(super::StreamConnectFailure::Harness(error)) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "key-rotation restored consumer exceeded its bounded retry deadline".into(),
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_fresh_owner(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    predecessor_epoch: u64,
    session_id: &str,
) -> Result<OwnerClaim> {
    let deadline = Instant::now() + RECOVERY_WAIT_TIMEOUT;
    loop {
        if let Ok(Ok(Some(owner))) = timeout(
            super::REDIS_PARTITION_OPERATION_TIMEOUT
                .min(deadline.saturating_duration_since(Instant::now())),
            cluster
                .catalog
                .current_owner(tenant_id, device_id, Utc::now()),
        )
        .await
            && owner.token.epoch > predecessor_epoch
            && owner.token.session_id == session_id
            && cluster
                .relays
                .iter()
                .any(|relay| relay.node_id == owner.token.node_id)
        {
            return Ok(owner);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "key-rotation fresh owner exceeded its bounded deadline".into(),
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyRotationEvidence, validate_key_rotation_evidence};

    fn valid_evidence() -> KeyRotationEvidence {
        KeyRotationEvidence {
            relay_count: 3,
            rotation_phase: "preparing".into(),
            candidate_generation: 2,
            data_direction_barrier_applied: true,
            pin_revocation_observed: true,
            stream_interrupted: true,
            same_owner_recovery: true,
            fresh_session_recovery: false,
            duplicate_response_rejected: true,
            owner_epoch_advanced: false,
            fanout_peak_open: 3,
            elapsed_ms: 1,
        }
    }

    fn assert_rejected(evidence: KeyRotationEvidence, expected: &str) {
        crate::acceptance_test_support::assert_rejected(
            validate_key_rotation_evidence(&evidence),
            expected,
        );
    }

    #[test]
    fn rejects_each_false_required_flag() {
        fn disable_barrier(evidence: &mut KeyRotationEvidence) {
            evidence.data_direction_barrier_applied = false;
        }
        fn disable_revocation(evidence: &mut KeyRotationEvidence) {
            evidence.pin_revocation_observed = false;
        }
        fn disable_interruption(evidence: &mut KeyRotationEvidence) {
            evidence.stream_interrupted = false;
        }
        fn disable_duplicate_rejection(evidence: &mut KeyRotationEvidence) {
            evidence.duplicate_response_rejected = false;
        }

        type GateDisabler = fn(&mut KeyRotationEvidence);
        let gates: [(&str, GateDisabler); 4] = [
            ("data_direction_barrier_applied", disable_barrier),
            ("pin_revocation_observed", disable_revocation),
            ("stream_interrupted", disable_interruption),
            ("duplicate_response_rejected", disable_duplicate_rejection),
        ];
        for (name, disable) in gates {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_rejected(evidence, name);
        }
    }

    #[test]
    fn accepts_same_owner_recovery_evidence() {
        assert!(validate_key_rotation_evidence(&valid_evidence()).is_ok());
    }

    #[test]
    fn rejects_zero_and_non_three_relay_counts() {
        for relay_count in [0, 2, 4] {
            let mut evidence = valid_evidence();
            evidence.relay_count = relay_count;
            assert_rejected(evidence, "expected three relays");
        }
    }

    #[test]
    fn rejects_invalid_phase_and_missing_candidate() {
        let mut invalid_phase = valid_evidence();
        invalid_phase.rotation_phase = "committing".into();
        assert_rejected(invalid_phase, "outside a scheduled drain phase");

        let mut missing_candidate = valid_evidence();
        missing_candidate.candidate_generation = 0;
        assert_rejected(missing_candidate, "candidate generation");
    }

    #[test]
    fn requires_exactly_one_recovery_outcome() {
        let mut both = valid_evidence();
        both.fresh_session_recovery = true;
        assert_rejected(both, "exactly one recovery outcome");

        let mut neither = valid_evidence();
        neither.same_owner_recovery = false;
        assert_rejected(neither, "exactly one recovery outcome");
    }

    #[test]
    fn fresh_recovery_requires_a_strictly_higher_epoch() {
        let mut evidence = valid_evidence();
        evidence.same_owner_recovery = false;
        evidence.fresh_session_recovery = true;
        evidence.owner_epoch_advanced = false;
        assert_rejected(evidence, "advance the owner epoch");
    }

    #[test]
    fn accepts_fresh_session_recovery_with_an_advanced_epoch() {
        let mut evidence = valid_evidence();
        evidence.same_owner_recovery = false;
        evidence.fresh_session_recovery = true;
        evidence.owner_epoch_advanced = true;
        assert!(validate_key_rotation_evidence(&evidence).is_ok());
    }

    #[test]
    fn rejects_excessive_socket_peak() {
        let mut evidence = valid_evidence();
        evidence.fanout_peak_open = 4;
        assert_rejected(evidence, "bounded three-socket peak");
    }
}
