//! Staged deterministic barrier for the credential-expiry/rotation fixture.
//!
//! This file is intentionally unreferenced by the live checkout.  It is a
//! child-module fragment for `production_cluster`.  The helper is based on
//! the real TCP proxy barrier used by `timing_boundaries.rs`: it pauses the
//! connector-to-relay direction of one already identified data connection,
//! sends one bounded record on an admitted consumer stream, and waits until
//! the relay has emitted that record without receiving its ACK.  The relay
//! cannot complete the old-carrier drain while that ACK is held.  Candidate
//! readiness is then revalidated against the same immutable
//! `RotationAttemptIdentity` before the helper returns.
//!
//! The pause is connection-scoped.  The control WebSocket and a sibling
//! tenant's fanout are not paused, so authorization renewal and the positive
//! sibling can continue while this hold is installed.  The caller must retain
//! the returned `RotationBarrierHold` and call `release_until` on every path
//! before shutting down the proxy.  Rust has no asynchronous `Drop`; dropping
//! a hold without releasing it is therefore a fixture failure, even though
//! the proxy has its own bounded fail-closed pause timeout.

use super::{ConsumerStream, ProductionCluster, session_for};
use crate::{
    ConnectionId, Direction, HarnessError, ManagedProcess, ProxyConfig, ProxyHandle, Result,
    TcpProxy,
};
use futures_util::SinkExt;
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::time::{sleep, timeout};
use tokio_tungstenite::tungstenite::Message;
use tunnel_catalog::OwnerToken;
use tunnel_protocol::rotation_control::RotationAttemptIdentity;
use tunnel_relay::RelaySessionSnapshot;

const POLL: Duration = Duration::from_millis(50);
const CONNECTION_TRIAL_TIMEOUT: Duration = Duration::from_secs(2);
const RESUME_RETRY: Duration = Duration::from_millis(100);
const BARRIER_RECORD: &[u8] = b"m7-i06-expiry-rotation-barrier";

/// Evidence that one exact old carrier is physically held behind a proxy
/// pause while one exact candidate is ready but not committed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RotationBarrierEvidence {
    pub attempt: RotationAttemptIdentity,
    pub phase: String,
    pub old_generation: u64,
    pub old_connection_id: String,
    pub old_local_addr: SocketAddr,
    pub candidate_generation: u64,
    pub candidate_connection_id: String,
    pub started_at_ms: u64,
    pub deadline_ms: u64,
    pub paused_proxy_connection: ConnectionId,
    pub pending_stream_id: u64,
    pub pending_operation_id: String,
    pub pending_emitted_before: u64,
    pub pending_emitted_after: u64,
}

/// A connection-scoped old-carrier hold.
///
/// The proxy is borrowed so its owner remains in the expiry fixture's
/// resource set and can be joined after the hold is explicitly released.
pub(super) struct RotationBarrierHold<'proxy> {
    proxy: &'proxy ProxyHandle,
    paused_connection: Option<ConnectionId>,
    evidence: RotationBarrierEvidence,
}

impl<'proxy> RotationBarrierHold<'proxy> {
    pub(super) fn evidence(&self) -> &RotationBarrierEvidence {
        &self.evidence
    }

    /// Revalidate the physical hold immediately before the expiry probe.
    ///
    /// This samples the proxy connection and authoritative relay snapshot.  A
    /// changed attempt, a closed old socket, a sent/accepted commit, or an
    /// ACK for the barrier record is a hard fixture failure; none of those
    /// states may be reported as a held rotation.
    pub(super) async fn assert_held(
        &self,
        cluster: &ProductionCluster,
        owner: &OwnerToken,
        device_id: uuid::Uuid,
        expected_owner_id: &str,
    ) -> Result<()> {
        let Some(paused_connection) = self.paused_connection else {
            return Err(HarnessError::Process(
                "rotation expiry barrier was already released".into(),
            ));
        };
        if !self.proxy.connections().into_iter().any(|active| {
            active.id == paused_connection && active.source_addr == self.evidence.old_local_addr
        }) {
            return Err(HarnessError::Process(
                "rotation expiry barrier lost its paused proxy connection before release".into(),
            ));
        }
        let relay = cluster.relay(&owner.node_id)?;
        let snapshot = relay.snapshot().await?;
        let session = session_for(&snapshot, owner, device_id)?;
        validate_held_snapshot(
            session,
            &self.evidence,
            paused_connection,
            expected_owner_id,
        )
    }

    /// Release the exact paused data direction before the caller's cleanup
    /// deadline.  On an error the connection ID is retained so the caller can
    /// retry the same bounded proxy command; the method is otherwise
    /// idempotent.
    pub(super) async fn release_until(&mut self, deadline: Instant) -> Result<()> {
        let Some(connection) = self.paused_connection else {
            return Ok(());
        };
        loop {
            let error = match self
                .proxy
                .resume(Direction::ClientToTarget, connection)
                .await
            {
                Ok(()) => {
                    self.paused_connection = None;
                    return Ok(());
                }
                Err(error) => error,
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(error);
            }
            sleep(RESUME_RETRY.min(remaining)).await;
        }
    }
}

/// Bind the device-side proxy before the connector profile is written.
/// Tenant A's device profile must use `local_addr()` as its fanout target;
/// tenant B continues to use `cluster.tenant_b_fanout.local_addr()`.
pub(super) async fn bind_device_proxy(cluster: &ProductionCluster) -> Result<ProxyHandle> {
    TcpProxy::bind(cluster.device_fanout.local_addr(), ProxyConfig::default()).await
}

/// Install a deterministic rotation hold before the candidate is observed.
///
/// `barrier_stream` must be an already admitted, long-lived stream whose
/// `stream_id` was obtained from the authoritative relay snapshot.  The
/// short-lived expiry stream must also be admitted and baseline-echoed before
/// this function is called; otherwise the old-route pause would change the
/// admission condition being tested.  The barrier stream is used only to
/// create the bounded emitted-but-unacknowledged record that prevents the
/// old-carrier drain from completing, and must remain alive until
/// `release_until` has succeeded.  Resume retries keep the same connection ID
/// until the caller's cleanup deadline.
///
/// `minimum_remaining_ms` is measured from the relay's monotonic clock when
/// the candidate is observed.  The expiry fixture chooses this from the
/// token/challenge margin (the current 16-second-token plan validates the
/// remaining token duration separately after this call).  The function also
/// checks the exact configured overlap (`expected_overlap_ms`) rather than
/// trusting a local sleep or a generation counter.
#[allow(clippy::too_many_arguments)]
pub(super) async fn install_rotation_barrier<'proxy>(
    cluster: &ProductionCluster,
    owner: &OwnerToken,
    device_id: uuid::Uuid,
    expected_owner_id: &str,
    proxy: &'proxy ProxyHandle,
    process: &ManagedProcess,
    barrier_stream: &mut ConsumerStream,
    barrier_stream_id: u64,
    expected_overlap_ms: u64,
    minimum_remaining_ms: u64,
    deadline: Instant,
) -> Result<RotationBarrierHold<'proxy>> {
    let active = wait_for_active_carrier(
        cluster,
        owner,
        device_id,
        expected_owner_id,
        proxy,
        process,
        barrier_stream_id,
        deadline,
    )
    .await?;

    let mut last_error = None;
    let mut selected_active = None;
    let mut evidence = None;
    for proxy_connection in active.proxy_connections.iter().copied() {
        let candidate_active = ActiveCarrier {
            local_addr: proxy_connection.source_addr,
            proxy_connection: proxy_connection.id,
            ..active.clone()
        };
        if let Err(error) = proxy
            .pause(Direction::ClientToTarget, candidate_active.proxy_connection)
            .await
        {
            last_error = Some(error);
            continue;
        }
        let trial_deadline = deadline.min(Instant::now() + CONNECTION_TRIAL_TIMEOUT);
        let install = async {
            send_barrier_record(barrier_stream, trial_deadline).await?;
            let emitted_after = wait_for_unacknowledged_barrier_record(
                cluster,
                owner,
                device_id,
                &candidate_active,
                trial_deadline,
            )
            .await?;
            wait_for_candidate_barrier(
                cluster,
                owner,
                device_id,
                expected_owner_id,
                &candidate_active,
                emitted_after,
                expected_overlap_ms,
                minimum_remaining_ms,
                deadline,
            )
            .await
        }
        .await;
        match install {
            Ok(found) => {
                selected_active = Some(candidate_active);
                evidence = Some(found);
                break;
            }
            Err(error) => {
                if let Err(cleanup) =
                    resume_connection_until(proxy, candidate_active.proxy_connection, deadline)
                        .await
                {
                    return Err(HarnessError::Process(format!(
                        "rotation barrier candidate failed: {error}; releasing candidate connection also failed: {cleanup}"
                    )));
                }
                last_error = Some(error);
            }
        }
    }
    let (active, evidence) = match (selected_active, evidence) {
        (Some(active), Some(evidence)) => (active, evidence),
        _ => {
            return Err(last_error.unwrap_or_else(|| {
                HarnessError::Process(
                    "rotation barrier found no usable device data connection".into(),
                )
            }));
        }
    };

    // The candidate wait and the return boundary are separate observations.
    // Revalidate once more so a commit that raced the final relay read cannot
    // be mistaken for a held pre-commit attempt.
    let final_revalidation = async {
        let snapshot = cluster.relay(&owner.node_id)?.snapshot().await?;
        let session = session_for(&snapshot, owner, device_id)?;
        validate_held_snapshot(
            session,
            &evidence,
            active.proxy_connection,
            expected_owner_id,
        )
    }
    .await;
    if let Err(primary) = final_revalidation {
        let cleanup = resume_connection_until(proxy, active.proxy_connection, deadline).await;
        return Err(match cleanup {
            Ok(()) => primary,
            Err(cleanup) => HarnessError::Process(format!(
                "rotation barrier final revalidation failed: {primary}; releasing paused data connection also failed: {cleanup}"
            )),
        });
    }
    Ok(RotationBarrierHold {
        proxy,
        paused_connection: Some(active.proxy_connection),
        evidence,
    })
}

async fn resume_connection_until(
    proxy: &ProxyHandle,
    connection: ConnectionId,
    deadline: Instant,
) -> Result<()> {
    loop {
        let error = match proxy.resume(Direction::ClientToTarget, connection).await {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(error);
        }
        sleep(RESUME_RETRY.min(remaining)).await;
    }
}

#[derive(Clone, Debug)]
struct ActiveCarrier {
    generation: u64,
    connection_id: String,
    stream_id: u64,
    operation_id: String,
    emitted_before: u64,
    proxy_connections: Vec<crate::ProxyConnection>,
    local_addr: SocketAddr,
    proxy_connection: ConnectionId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CliRouteStatus {
    session_id: String,
    epoch: u64,
    generation: u64,
    active_connection_id: String,
    active_local_addr: SocketAddr,
    candidate_local_addr: Option<SocketAddr>,
    rotations_completed: u64,
}

fn latest_cli_route_status(process: &ManagedProcess) -> Option<CliRouteStatus> {
    process
        .stdout()
        .split(|byte| *byte == b'\n')
        .rev()
        .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
        .find_map(|event| {
            if event.get("command").and_then(serde_json::Value::as_str) != Some("connect-status")
                || event.get("ok").and_then(serde_json::Value::as_bool) != Some(true)
            {
                return None;
            }
            let result = event.get("result")?;
            let required_string = |name: &str| {
                result
                    .get(name)
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| !value.is_empty())
            };
            Some(CliRouteStatus {
                session_id: required_string("session_id")?.to_owned(),
                epoch: result.get("epoch")?.as_u64()?,
                generation: result.get("generation")?.as_u64()?,
                active_connection_id: required_string("active_connection_id")?.to_owned(),
                active_local_addr: required_string("active_local_addr")?.parse().ok()?,
                candidate_local_addr: result
                    .get("candidate_local_addr")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|value| value.parse().ok()),
                rotations_completed: result.get("rotations_completed")?.as_u64()?,
            })
        })
}

#[allow(clippy::too_many_arguments)]
async fn wait_for_active_carrier(
    cluster: &ProductionCluster,
    owner: &OwnerToken,
    device_id: uuid::Uuid,
    expected_owner_id: &str,
    proxy: &ProxyHandle,
    process: &ManagedProcess,
    stream_id: u64,
    deadline: Instant,
) -> Result<ActiveCarrier> {
    loop {
        let snapshot = cluster.relay(&owner.node_id)?.snapshot().await?;
        let session = session_for(&snapshot, owner, device_id)?;
        if session.phase != "active" {
            sleep_until(deadline, "active rotation carrier").await?;
            continue;
        }
        if let Some(attempt) = session
            .rotation_diagnostics
            .as_ref()
            .and_then(|diagnostics| diagnostics.attempt.as_ref())
            && (attempt.owner_id != expected_owner_id
                || attempt.session_id != owner.session_id
                || attempt.epoch != owner.epoch)
        {
            return Err(HarnessError::Process(
                "active rotation carrier exposed a different owner fence".into(),
            ));
        }
        let Some(stream) = session
            .streams
            .iter()
            .find(|stream| stream.stream_id == stream_id && !stream.terminal)
        else {
            sleep_until(deadline, "active barrier stream").await?;
            continue;
        };
        let Some(cli_status) = latest_cli_route_status(process) else {
            sleep_until(deadline, "CLI active data socket status").await?;
            continue;
        };
        if cli_status.session_id != owner.session_id
            || cli_status.epoch != owner.epoch
            || cli_status.generation != session.active_generation
            || cli_status.active_connection_id != session.active_connection_id
            || cli_status.rotations_completed != session.rotations_completed
            || cli_status.candidate_local_addr.is_some()
        {
            sleep_until(deadline, "CLI/relay active route correlation").await?;
            continue;
        }
        let active_local_addr = cli_status.active_local_addr;
        let proxy_connections = proxy
            .connections()
            .into_iter()
            .filter(|connection| connection.source_addr == active_local_addr)
            .collect::<Vec<_>>();
        if proxy_connections.len() != 1 {
            sleep_until(deadline, "exact active proxy data connection").await?;
            continue;
        }
        let proxy_connection = proxy_connections[0];
        return Ok(ActiveCarrier {
            generation: session.active_generation,
            connection_id: session.active_connection_id.clone(),
            stream_id,
            operation_id: stream.operation_id.clone(),
            emitted_before: stream.last_emitted_relay_to_connector,
            proxy_connections,
            local_addr: active_local_addr,
            proxy_connection: proxy_connection.id,
        });
    }
}

pub(super) async fn wait_for_committed_cli_route(
    cluster: &ProductionCluster,
    process: &ManagedProcess,
    proxy: &ProxyHandle,
    expected_attempt: &RotationAttemptIdentity,
    deadline: Instant,
) -> Result<SocketAddr> {
    let expected_proxy_target = cluster.device_fanout.local_addr();
    if proxy.target_addr() != expected_proxy_target {
        return Err(HarnessError::Process(format!(
            "credential-expiry replacement proxy targets {}, expected device fanout {}",
            proxy.target_addr(),
            expected_proxy_target
        )));
    }
    loop {
        if let Some(status) = latest_cli_route_status(process)
            && status.session_id == expected_attempt.session_id
            && status.epoch == expected_attempt.epoch
            && status.generation == expected_attempt.new_generation
            && status.active_connection_id == expected_attempt.new_connection_id
            && status.candidate_local_addr.is_none()
            && status.rotations_completed > 0
        {
            let matching_connections = proxy
                .connections()
                .into_iter()
                .filter(|connection| connection.source_addr == status.active_local_addr)
                .collect::<Vec<_>>();
            if matching_connections.len() == 1 {
                return Ok(status.active_local_addr);
            }
            if matching_connections.len() > 1 {
                return Err(HarnessError::Process(format!(
                    "credential-expiry committed CLI route mapped to {} open proxy connections",
                    matching_connections.len()
                )));
            }
        }
        sleep_until(deadline, "CLI committed replacement route").await?;
    }
}

async fn send_barrier_record(stream: &mut ConsumerStream, deadline: Instant) -> Result<()> {
    if BARRIER_RECORD.len() > super::super::MAX_RECORD_BYTES {
        return Err(HarnessError::InvalidInput(
            "rotation barrier record exceeded the M2 record bound".into(),
        ));
    }
    let length = u32::try_from(BARRIER_RECORD.len()).map_err(|_| {
        HarnessError::InvalidInput("rotation barrier record length overflow".into())
    })?;
    let mut frame = Vec::with_capacity(BARRIER_RECORD.len() + 4);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(BARRIER_RECORD);
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .min(super::super::EXCHANGE_TIMEOUT);
    if remaining.is_zero() {
        return Err(HarnessError::Timeout(
            "rotation barrier record send deadline elapsed".into(),
        ));
    }
    timeout(remaining, stream.socket.send(Message::Binary(frame.into())))
        .await
        .map_err(|_| HarnessError::Timeout("rotation barrier record send timed out".into()))?
        .map_err(|error| HarnessError::Http(format!("sending rotation barrier record: {error}")))
}

async fn wait_for_unacknowledged_barrier_record(
    cluster: &ProductionCluster,
    owner: &OwnerToken,
    device_id: uuid::Uuid,
    active: &ActiveCarrier,
    deadline: Instant,
) -> Result<u64> {
    loop {
        let snapshot = cluster.relay(&owner.node_id)?.snapshot().await?;
        let session = session_for(&snapshot, owner, device_id)?;
        if session.phase != "active"
            || session.active_generation != active.generation
            || session.active_connection_id != active.connection_id
        {
            return Err(HarnessError::Process(
                "rotation began before its bounded barrier record became unacknowledged".into(),
            ));
        }
        if let Some(stream) = session.streams.iter().find(|stream| {
            stream.stream_id == active.stream_id
                && stream.operation_id == active.operation_id
                && !stream.terminal
        }) && stream.last_emitted_relay_to_connector > active.emitted_before
            && stream.last_emitted_relay_to_connector > stream.peer_acked_relay_to_connector
        {
            return Ok(stream.last_emitted_relay_to_connector);
        }
        sleep_until(deadline, "rotation barrier record").await?;
    }
}

#[allow(clippy::too_many_arguments)]
async fn wait_for_candidate_barrier(
    cluster: &ProductionCluster,
    owner: &OwnerToken,
    device_id: uuid::Uuid,
    expected_owner_id: &str,
    active: &ActiveCarrier,
    pending_emitted_after: u64,
    expected_overlap_ms: u64,
    minimum_remaining_ms: u64,
    deadline: Instant,
) -> Result<RotationBarrierEvidence> {
    loop {
        let snapshot = cluster.relay(&owner.node_id)?.snapshot().await?;
        let session = session_for(&snapshot, owner, device_id)?;
        if let Some(evidence) = candidate_evidence(
            session,
            owner,
            expected_owner_id,
            active,
            pending_emitted_after,
            expected_overlap_ms,
            minimum_remaining_ms,
            snapshot.monotonic_now_ms,
        )? {
            return Ok(evidence);
        }
        sleep_until(deadline, "rotation candidate barrier").await?;
    }
}

#[allow(clippy::too_many_arguments)]
fn candidate_evidence(
    session: &RelaySessionSnapshot,
    owner: &OwnerToken,
    expected_owner_id: &str,
    active: &ActiveCarrier,
    pending_emitted_after: u64,
    expected_overlap_ms: u64,
    minimum_remaining_ms: u64,
    monotonic_now_ms: u64,
) -> Result<Option<RotationBarrierEvidence>> {
    if !matches!(
        session.phase.as_str(),
        "preparing" | "quiescing" | "draining"
    ) || session.active_generation != active.generation
        || session.active_connection_id != active.connection_id
    {
        return Ok(None);
    }
    let Some(diagnostics) = session.rotation_diagnostics.as_ref() else {
        return Ok(None);
    };
    let Some(attempt) = diagnostics.attempt.as_ref() else {
        return Ok(None);
    };
    let Some(candidate_generation) = session.candidate_generation else {
        return Ok(None);
    };
    let Some(candidate_connection_id) = session.candidate_connection_id.as_deref() else {
        return Ok(None);
    };
    let (Some(started_at_ms), Some(deadline_ms)) =
        (session.rotation_started_at_ms, session.rotation_deadline_ms)
    else {
        return Ok(None);
    };
    let observed_overlap_ms = deadline_ms.saturating_sub(started_at_ms);
    if !diagnostics.attempt_active
        || !diagnostics.candidate_ready
        || diagnostics.commit_sent
        || diagnostics.commit_accepted
        || diagnostics
            .old_socket_closed
            .into_iter()
            .any(|closed| closed)
        || attempt.session_id != owner.session_id
        || attempt.epoch != owner.epoch
        || attempt.owner_id != expected_owner_id
        || attempt.old_generation != active.generation
        || attempt.old_connection_id != active.connection_id
        || attempt.new_generation != candidate_generation
        || attempt.new_connection_id != candidate_connection_id
        || candidate_generation != session.candidate_generation.unwrap_or_default()
        || session.candidate_connection_id.as_deref() != Some(candidate_connection_id)
        || observed_overlap_ms != expected_overlap_ms
        || monotonic_now_ms < started_at_ms
        || monotonic_now_ms >= deadline_ms
        || deadline_ms.saturating_sub(monotonic_now_ms) <= minimum_remaining_ms
    {
        return Ok(None);
    }
    let Some(stream) = session.streams.iter().find(|stream| {
        stream.stream_id == active.stream_id && stream.operation_id == active.operation_id
    }) else {
        return Ok(None);
    };
    if stream.terminal
        || stream.last_emitted_relay_to_connector < pending_emitted_after
        || stream.last_emitted_relay_to_connector <= stream.peer_acked_relay_to_connector
    {
        return Ok(None);
    }
    Ok(Some(RotationBarrierEvidence {
        attempt: attempt.clone(),
        phase: session.phase.clone(),
        old_generation: active.generation,
        old_connection_id: active.connection_id.clone(),
        old_local_addr: active.local_addr,
        candidate_generation,
        candidate_connection_id: candidate_connection_id.to_owned(),
        started_at_ms,
        deadline_ms,
        paused_proxy_connection: active.proxy_connection,
        pending_stream_id: active.stream_id,
        pending_operation_id: active.operation_id.clone(),
        pending_emitted_before: active.emitted_before,
        pending_emitted_after,
    }))
}

fn validate_held_snapshot(
    session: &RelaySessionSnapshot,
    evidence: &RotationBarrierEvidence,
    proxy_connection: ConnectionId,
    expected_owner_id: &str,
) -> Result<()> {
    if proxy_connection != evidence.paused_proxy_connection
        || evidence.pending_emitted_after <= evidence.pending_emitted_before
        || !matches!(
            session.phase.as_str(),
            "preparing" | "quiescing" | "draining"
        )
        || session.active_generation != evidence.old_generation
        || session.active_connection_id != evidence.old_connection_id
        || session.sockets < 2
        || session.candidate_generation != Some(evidence.candidate_generation)
        || session.candidate_connection_id.as_deref()
            != Some(evidence.candidate_connection_id.as_str())
    {
        return Err(HarnessError::Process(
            "rotation expiry barrier changed its connector attempt before release".into(),
        ));
    }
    let Some(diagnostics) = session.rotation_diagnostics.as_ref() else {
        return Err(HarnessError::Process(
            "rotation expiry barrier lost relay diagnostics before release".into(),
        ));
    };
    let Some(attempt) = diagnostics.attempt.as_ref() else {
        return Err(HarnessError::Process(
            "rotation expiry barrier lost its attempt identity before release".into(),
        ));
    };
    if !diagnostics.attempt_active
        || diagnostics.commit_sent
        || diagnostics.commit_accepted
        || !diagnostics.candidate_ready
        || diagnostics
            .old_socket_closed
            .into_iter()
            .any(|closed| closed)
        || attempt != &evidence.attempt
        || attempt.owner_id != expected_owner_id
        || session.active_generation != evidence.old_generation
        || session.active_connection_id != evidence.old_connection_id
        || session.candidate_generation != Some(evidence.candidate_generation)
        || session.candidate_connection_id.as_deref()
            != Some(evidence.candidate_connection_id.as_str())
        || session.rotation_started_at_ms != Some(evidence.started_at_ms)
        || session.rotation_deadline_ms != Some(evidence.deadline_ms)
    {
        return Err(HarnessError::Process(
            "rotation expiry barrier no longer held the exact pre-commit attempt".into(),
        ));
    }
    let Some(stream) = session.streams.iter().find(|stream| {
        stream.stream_id == evidence.pending_stream_id
            && stream.operation_id == evidence.pending_operation_id
    }) else {
        return Err(HarnessError::Process(
            "rotation expiry barrier lost its pending stream evidence".into(),
        ));
    };
    if stream.terminal
        || stream.last_emitted_relay_to_connector < evidence.pending_emitted_after
        || stream.last_emitted_relay_to_connector <= stream.peer_acked_relay_to_connector
    {
        return Err(HarnessError::Process(
            "rotation expiry barrier record was acknowledged before explicit release".into(),
        ));
    }
    Ok(())
}

async fn sleep_until(deadline: Instant, label: &str) -> Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(HarnessError::Timeout(format!(
            "rotation expiry barrier did not reach {label} before its bounded deadline"
        )));
    }
    sleep(POLL.min(remaining)).await;
    Ok(())
}
