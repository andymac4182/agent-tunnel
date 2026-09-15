//! Bounded M7-I08 happy path over the real three-relay production fixture.
//!
//! This is deliberately a synthetic adapter mapping: the public consumer
//! stream carries an opaque, checksummed envelope to the existing Echo
//! export.  It does not implement or stand in for a deployed MCP, 9P, ACP,
//! CUA, or other privileged adapter.  The gate is kept separate from the
//! existing library-connector M2 flow so the client exercised here is the
//! actual `tunnel-client` process.

use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use std::{
    fs,
    time::{Duration, Instant},
};
use tempfile::tempdir;
use tokio::time::{sleep, timeout, timeout_at};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use tunnel_protocol::rotation_control::RotationAttemptIdentity;
use tunnel_relay::{RelayRotationSnapshot, RelaySessionSnapshot, RelayStreamSnapshot};
use uuid::Uuid;

use crate::{
    Harness, HarnessError, HarnessOptions, ManagedProcess, ProcessSpec, Result, RunningHarness,
};

use super::{
    CLEANUP_TIMEOUT, ConsumerStream, ProductionCluster, ROTATION, ROTATION_COUNT, SCENARIO_TIMEOUT,
    STARTUP_TIMEOUT,
};

const I08_SCENARIO_TIMEOUT: Duration = Duration::from_secs(120);
const I08_POLL: Duration = Duration::from_millis(50);
const I08_PROCESS_GRACE: Duration = Duration::from_secs(5);
const I08_FANOUT_FORCED_JOIN_GRACE: Duration = Duration::from_secs(2);
const I08_FID: u64 = 0x0049_3038;
const I08_SYNTHETIC_OPERATION: &str = "synthetic.echo.v1";
const I08_MAGIC: &[u8] = b"I08ECHO1";

/// Payload-free evidence for one real CLI session and three scheduled
/// replacement generations.  All IDs are tunnel/runtime correlation values;
/// no fixture field claims to be a deployed privileged adapter identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct I08Evidence {
    pub scope: &'static str,
    pub relay_count: usize,
    pub public_ingress_relay: String,
    pub owner_relay: String,
    pub actual_cli_process: bool,
    pub public_ingress: bool,
    pub control_identity_stable: bool,
    pub session_id: String,
    pub epoch: u64,
    pub stream_id: u64,
    pub tunnel_operation_id: String,
    pub synthetic_fid: u64,
    pub synthetic_operation_id: String,
    pub records_sent: usize,
    pub records_echoed: usize,
    pub checksums_verified: usize,
    pub rotations: Vec<I08RotationEvidence>,
    /// Physical device fanout high-water, including control/data/candidate
    /// sockets accepted by the opaque production fanout proxy.
    pub socket_high_water: usize,
    pub replay_frames: usize,
    pub cleanup_joined: bool,
    pub elapsed_ms: u64,
}

/// One rotation's diagnostic proof.  The relay exposes the live attempt and
/// retains the final bounded proof long enough to observe both old-carrier
/// closure bits after COMPLETE; no payload or adapter event is retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct I08RotationEvidence {
    pub rotation: u64,
    /// Exact authenticated attempt identity retained by the relay latch.
    /// This binds rotation/session/epoch and both physical carriers.
    pub attempt: RotationAttemptIdentity,
    pub active_generation: u64,
    pub active_connection_id: String,
    pub snapshot_id: String,
    pub completed_latch_observed: bool,
    pub relay_fence_digest: String,
    pub connector_fence_digest: String,
    pub relay_fence_sequence: u64,
    pub connector_fence_sequence: u64,
    pub relay_ack_sequence: u64,
    pub connector_ack_sequence: u64,
    pub writer_barrier_flushed: [bool; 2],
    pub candidate_ready: bool,
    pub commit_sent: bool,
    pub commit_accepted: bool,
    pub old_socket_closed: bool,
    /// Relay state-machine socket count sampled alongside this proof.  The
    /// physical bound is validated from `I08Evidence::socket_high_water`.
    pub runtime_socket_high_water: u8,
    pub replay_frames: usize,
}

/// Reject incomplete or widened evidence.  In particular, this validator
/// requires the process, ingress, transient fence/ACK/flush fields, and
/// exact three-rotation count; a narrow library or source-only probe cannot
/// satisfy it.
pub fn validate_i08_evidence(evidence: &I08Evidence) -> Result<()> {
    if evidence.scope != "synthetic_echo_mapping_only" {
        return Err(HarnessError::Process(format!(
            "M7-I08 evidence has unexpected scope {:?}",
            evidence.scope
        )));
    }
    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "M7-I08 expected three production relays, observed {}",
            evidence.relay_count
        )));
    }
    let checks = [
        ("actual_cli_process", evidence.actual_cli_process),
        ("public_ingress", evidence.public_ingress),
        ("control_identity_stable", evidence.control_identity_stable),
        ("cleanup_joined", evidence.cleanup_joined),
    ];
    if let Some((name, _)) = checks.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "M7-I08 evidence is incomplete: {name}"
        )));
    }
    if evidence.session_id.is_empty()
        || evidence.epoch == 0
        || evidence.stream_id == 0
        || evidence.tunnel_operation_id.is_empty()
        || evidence.synthetic_operation_id != I08_SYNTHETIC_OPERATION
        || evidence.synthetic_fid != I08_FID
    {
        return Err(HarnessError::Process(
            "M7-I08 omitted a stable session/stream/operation identity".into(),
        ));
    }
    if evidence.records_sent != ROTATION_COUNT as usize + 1
        || evidence.records_echoed != evidence.records_sent
        || evidence.checksums_verified != evidence.records_sent
    {
        return Err(HarnessError::Process(format!(
            "M7-I08 expected one baseline plus {ROTATION_COUNT} echoed checksummed records, observed sent={} echoed={} checksums={}",
            evidence.records_sent, evidence.records_echoed, evidence.checksums_verified
        )));
    }
    if evidence.rotations.len() != ROTATION_COUNT as usize {
        return Err(HarnessError::Process(format!(
            "M7-I08 expected {ROTATION_COUNT} rotation proofs, observed {}",
            evidence.rotations.len()
        )));
    }
    if evidence.socket_high_water < 2 || evidence.socket_high_water > 3 {
        return Err(HarnessError::Process(format!(
            "M7-I08 socket high-water was outside the bounded 2..=3 shape: {}",
            evidence.socket_high_water
        )));
    }
    if evidence.replay_frames != 0 {
        return Err(HarnessError::Process(format!(
            "M7-I08 observed {} replay frames on the clean synthetic stream",
            evidence.replay_frames
        )));
    }
    let mut previous_generation = 0;
    let mut previous_connection = None;
    for (index, rotation) in evidence.rotations.iter().enumerate() {
        let expected = index as u64 + 1;
        if rotation.rotation != expected
            || rotation.active_generation <= previous_generation
            || previous_connection.as_deref() == Some(rotation.active_connection_id.as_str())
            || rotation.snapshot_id.is_empty()
            || !rotation.completed_latch_observed
            || rotation.relay_fence_digest.is_empty()
            || rotation.connector_fence_digest.is_empty()
            || rotation.relay_fence_sequence != rotation.relay_ack_sequence
            || rotation.connector_fence_sequence != rotation.connector_ack_sequence
            || rotation.attempt.session_id != evidence.session_id
            || rotation.attempt.epoch != evidence.epoch
            || rotation.attempt.owner_id.is_empty()
            || rotation.attempt.rotation_id.is_empty()
            || rotation.attempt.old_generation >= rotation.attempt.new_generation
            || rotation.attempt.new_generation != rotation.active_generation
            || rotation.attempt.new_connection_id != rotation.active_connection_id
            || rotation.attempt.old_connection_id.is_empty()
            || rotation.attempt.old_connection_id == rotation.attempt.new_connection_id
            || (previous_generation != 0 && rotation.attempt.old_generation != previous_generation)
            || previous_connection
                .as_deref()
                .is_some_and(|connection| connection != rotation.attempt.old_connection_id)
        {
            return Err(HarnessError::Process(format!(
                "M7-I08 rotation {expected} did not retain an immutable fence/ACK identity"
            )));
        }
        let flags = [
            (
                "writer_barrier_flushed",
                rotation
                    .writer_barrier_flushed
                    .into_iter()
                    .all(|flushed| flushed),
            ),
            ("candidate_ready", rotation.candidate_ready),
            ("commit_sent", rotation.commit_sent),
            ("commit_accepted", rotation.commit_accepted),
            ("old_socket_closed", rotation.old_socket_closed),
        ];
        if let Some((name, _)) = flags.into_iter().find(|(_, passed)| !passed) {
            return Err(HarnessError::Process(format!(
                "M7-I08 rotation {expected} omitted {name} evidence"
            )));
        }
        if rotation.replay_frames != 0 {
            return Err(HarnessError::Process(format!(
                "M7-I08 rotation {expected} observed {} replay frames",
                rotation.replay_frames
            )));
        }
        previous_generation = rotation.active_generation;
        previous_connection = Some(rotation.active_connection_id.clone());
    }
    Ok(())
}

/// Start the real CLI and open its public consumer stream, with one absolute
/// deadline.  The helper is local to this fixture so cancellation retains
/// ownership of the process until a bounded shutdown/join is attempted.
#[allow(clippy::too_many_arguments)]
async fn start_cli(
    harness: &RunningHarness,
    device_fanout_addr: std::net::SocketAddr,
    consumer_addr: std::net::SocketAddr,
    profile: &crate::acceptance::helpers::DeviceProfile,
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
    deadline: Instant,
) -> Result<(ManagedProcess, ConsumerStream)> {
    if !profile
        .config
        .relay_url
        .contains(&format!(":{}", device_fanout_addr.port()))
    {
        return Err(HarnessError::InvalidInput(
            "I08 CLI profile does not point at the production device fanout".into(),
        ));
    }
    let binary = super::client_binary_path()?;
    let mut process = ManagedProcess::spawn(
        "m7-i08-production-cli",
        ProcessSpec::new(binary)
            .arg("connect")
            .arg("--config")
            .arg(profile.config_path.to_string_lossy().to_string())
            .arg("--json"),
    )
    .await?;
    loop {
        let process_status = match process.try_wait() {
            Ok(status) => status,
            Err(error) => {
                return Err(
                    startup_cleanup_error(process, error, cleanup_deadline(deadline)).await,
                );
            }
        };
        if let Some(status) = process_status {
            return Err(startup_cleanup_error(
                process,
                HarnessError::Process(format!(
                    "I08 CLI exited before public stream admission: {status}"
                )),
                cleanup_deadline(deadline),
            )
            .await);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(startup_cleanup_error(
                process,
                HarnessError::Timeout(
                    "I08 CLI/public stream startup exceeded its absolute deadline".into(),
                ),
                cleanup_deadline(deadline),
            )
            .await);
        }
        match timeout_at(
            tokio::time::Instant::from_std(deadline),
            super::open_consumer_stream(
                consumer_addr,
                &harness.pki.server_ca.certificate_der,
                token,
                device_id,
                service_id,
            ),
        )
        .await
        {
            Ok(Ok(stream)) => return Ok((process, stream)),
            Ok(Err(_)) if Instant::now() < deadline => {
                sleep(I08_POLL).await;
            }
            Ok(Err(error)) => {
                return Err(startup_cleanup_error(
                    process,
                    super::connect_failure_to_harness(error),
                    cleanup_deadline(deadline),
                )
                .await);
            }
            Err(_) => {
                return Err(startup_cleanup_error(
                    process,
                    HarnessError::Timeout("I08 public consumer stream startup timed out".into()),
                    cleanup_deadline(deadline),
                )
                .await);
            }
        }
    }
}

async fn startup_cleanup_error(
    process: ManagedProcess,
    primary: HarnessError,
    deadline: Instant,
) -> HarnessError {
    match shutdown_process(process, deadline).await {
        Ok(()) => primary,
        Err(cleanup) => HarnessError::Process(format!(
            "{primary}; I08 CLI startup cleanup failed: {cleanup}"
        )),
    }
}

async fn shutdown_process(mut process: ManagedProcess, deadline: Instant) -> Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let stop_request = if remaining.is_zero() {
        Err(HarnessError::Timeout(
            "I08 CLI cleanup had no remaining deadline".into(),
        ))
    } else {
        // The CLI owns a normal SIGINT shutdown path. Request it before the
        // bounded generic cleanup so I08 can prove a graceful process exit rather
        // than accepting the forced-kill status as success.
        process.request_stop().await
    };
    let grace = deadline
        .saturating_duration_since(Instant::now())
        .min(I08_PROCESS_GRACE);
    let shutdown = process.shutdown(grace).await.and_then(|status| {
        if status.success() {
            Ok(())
        } else {
            Err(HarnessError::Process(format!(
                "I08 CLI shutdown returned {status}"
            )))
        }
    });
    match (stop_request, shutdown) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(request), Err(shutdown)) => {
            Err(HarnessError::Process(format!("{request}; {shutdown}")))
        }
    }
}

fn cleanup_deadline(scenario_deadline: Instant) -> Instant {
    scenario_deadline.max(Instant::now() + I08_PROCESS_GRACE)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CliStatus {
    session_id: String,
    epoch: u64,
    generation: u64,
    active_connection_id: String,
    rotations_completed: u64,
    control_local_addr: String,
    active_local_addr: String,
}

fn cli_statuses(process: &ManagedProcess) -> Result<Vec<CliStatus>> {
    let mut statuses = Vec::new();
    for line in process.stdout().split(|byte| *byte == b'\n') {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        if value.get("command").and_then(serde_json::Value::as_str) != Some("connect-status") {
            continue;
        }
        if value.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
            return Err(HarnessError::Process(
                "I08 CLI emitted a failed connect-status event".into(),
            ));
        }
        let result = value
            .get("result")
            .ok_or_else(|| HarnessError::Process("I08 CLI status omitted result".into()))?;
        let required = |name: &str| {
            result
                .get(name)
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| HarnessError::Process(format!("I08 CLI status omitted {name}")))
        };
        statuses.push(CliStatus {
            session_id: required("session_id")?,
            epoch: result
                .get("epoch")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| HarnessError::Process("I08 CLI status omitted epoch".into()))?,
            generation: result
                .get("generation")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| HarnessError::Process("I08 CLI status omitted generation".into()))?,
            active_connection_id: required("active_connection_id")?,
            rotations_completed: result
                .get("rotations_completed")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
                    HarnessError::Process("I08 CLI status omitted rotations_completed".into())
                })?,
            control_local_addr: required("control_local_addr")?,
            active_local_addr: required("active_local_addr")?,
        });
    }
    Ok(statuses)
}

async fn wait_for_cli_status(process: &ManagedProcess, deadline: Instant) -> Result<CliStatus> {
    loop {
        if let Some(status) = cli_statuses(process)?.into_iter().last() {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "I08 CLI did not publish a bounded status event".into(),
            ));
        }
        sleep(I08_POLL).await;
    }
}

fn latest_cli_status(process: &ManagedProcess, initial: &CliStatus) -> Result<Option<CliStatus>> {
    let statuses = cli_statuses(process)?;
    for status in &statuses {
        verify_cli_identity(initial, status)?;
    }
    Ok(statuses.into_iter().last())
}

fn verify_cli_identity(initial: &CliStatus, current: &CliStatus) -> Result<()> {
    if current.session_id != initial.session_id
        || current.epoch != initial.epoch
        || current.control_local_addr != initial.control_local_addr
    {
        return Err(HarnessError::Process(
            "I08 CLI control/session identity changed during same-owner rotation".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct RotationAccumulator {
    rotation: u64,
    snapshot_id: Option<String>,
    relay_fence_digest: Option<String>,
    connector_fence_digest: Option<String>,
    relay_fence_sequence: Option<u64>,
    connector_fence_sequence: Option<u64>,
    relay_ack_sequence: Option<u64>,
    connector_ack_sequence: Option<u64>,
    writer_barrier_flushed: [bool; 2],
    candidate_ready: bool,
    commit_sent: bool,
    commit_accepted: bool,
    old_socket_closed: bool,
    completed_latch_observed: bool,
    runtime_socket_high_water: u8,
    replay_frames: usize,
    stream_id: u64,
    attempt: Option<RotationAttemptIdentity>,
}

impl RotationAccumulator {
    fn new(rotation: u64, stream_id: u64) -> Self {
        Self {
            rotation,
            snapshot_id: None,
            relay_fence_digest: None,
            connector_fence_digest: None,
            relay_fence_sequence: None,
            connector_fence_sequence: None,
            relay_ack_sequence: None,
            connector_ack_sequence: None,
            writer_barrier_flushed: [false; 2],
            candidate_ready: false,
            commit_sent: false,
            commit_accepted: false,
            old_socket_closed: false,
            completed_latch_observed: false,
            runtime_socket_high_water: 0,
            replay_frames: 0,
            stream_id,
            attempt: None,
        }
    }

    fn observe(
        &mut self,
        session: &RelaySessionSnapshot,
        diagnostics: &RelayRotationSnapshot,
    ) -> Result<()> {
        self.runtime_socket_high_water = self.runtime_socket_high_water.max(session.sockets);
        self.replay_frames = self.replay_frames.max(session.replay_frames);
        if let (Some(existing), Some(current)) = (&self.attempt, &diagnostics.attempt)
            && existing != current
        {
            return Err(HarnessError::Process(format!(
                "I08 rotation {} changed its immutable attempt identity",
                self.rotation
            )));
        }
        if self.attempt.is_none() {
            self.attempt = diagnostics.attempt.clone();
        }
        if let Some(existing) = self.snapshot_id.as_deref()
            && diagnostics.snapshot_id.as_deref() != Some(existing)
        {
            return Err(HarnessError::Process(format!(
                "I08 rotation {} changed its immutable snapshot id",
                self.rotation
            )));
        }
        if let Some(snapshot_id) = diagnostics.snapshot_id.as_deref()
            && !snapshot_id.is_empty()
        {
            self.snapshot_id = Some(snapshot_id.to_owned());
        }
        self.relay_fence_digest = retain_immutable(
            self.relay_fence_digest.take(),
            diagnostics.relay_fence_digest.clone(),
            self.rotation,
            "relay fence digest",
        )?;
        self.connector_fence_digest = retain_immutable(
            self.connector_fence_digest.take(),
            diagnostics.connector_fence_digest.clone(),
            self.rotation,
            "connector fence digest",
        )?;
        self.relay_fence_sequence = retain_fence_sequence(
            self.relay_fence_sequence,
            &diagnostics.relay_fence_sequences,
            self.stream_id,
            self.rotation,
            "relay",
        )?;
        self.connector_fence_sequence = retain_fence_sequence(
            self.connector_fence_sequence,
            &diagnostics.connector_fence_sequences,
            self.stream_id,
            self.rotation,
            "connector",
        )?;
        self.relay_ack_sequence = retain_ack_sequence(
            self.relay_ack_sequence,
            &diagnostics.relay_ack_sequences,
            self.stream_id,
            self.rotation,
            "relay",
        )?;
        self.connector_ack_sequence = retain_ack_sequence(
            self.connector_ack_sequence,
            &diagnostics.connector_ack_sequences,
            self.stream_id,
            self.rotation,
            "connector",
        )?;
        for (observed, current) in self
            .writer_barrier_flushed
            .iter_mut()
            .zip(diagnostics.writer_barrier_flushed)
        {
            *observed |= current;
        }
        self.candidate_ready |= diagnostics.candidate_ready;
        self.commit_sent |= diagnostics.commit_sent;
        self.commit_accepted |= diagnostics.commit_accepted;
        self.old_socket_closed |= diagnostics
            .old_socket_closed
            .into_iter()
            .all(|closed| closed);
        self.completed_latch_observed |= !diagnostics.attempt_active;
        Ok(())
    }

    fn finish(self, session: &RelaySessionSnapshot) -> Result<I08RotationEvidence> {
        Ok(I08RotationEvidence {
            rotation: self.rotation,
            attempt: self
                .attempt
                .ok_or_else(|| missing_rotation_field(self.rotation, "attempt_identity"))?,
            active_generation: session.active_generation,
            active_connection_id: session.active_connection_id.clone(),
            snapshot_id: self
                .snapshot_id
                .ok_or_else(|| missing_rotation_field(self.rotation, "snapshot_id"))?,
            relay_fence_digest: self
                .relay_fence_digest
                .ok_or_else(|| missing_rotation_field(self.rotation, "relay_fence_digest"))?,
            connector_fence_digest: self
                .connector_fence_digest
                .ok_or_else(|| missing_rotation_field(self.rotation, "connector_fence_digest"))?,
            relay_fence_sequence: self
                .relay_fence_sequence
                .ok_or_else(|| missing_rotation_field(self.rotation, "relay_fence_sequence"))?,
            connector_fence_sequence: self
                .connector_fence_sequence
                .ok_or_else(|| missing_rotation_field(self.rotation, "connector_fence_sequence"))?,
            relay_ack_sequence: self
                .relay_ack_sequence
                .ok_or_else(|| missing_rotation_field(self.rotation, "relay_ack_sequence"))?,
            connector_ack_sequence: self
                .connector_ack_sequence
                .ok_or_else(|| missing_rotation_field(self.rotation, "connector_ack_sequence"))?,
            writer_barrier_flushed: self.writer_barrier_flushed,
            candidate_ready: self.candidate_ready,
            commit_sent: self.commit_sent,
            commit_accepted: self.commit_accepted,
            old_socket_closed: self.old_socket_closed,
            completed_latch_observed: self.completed_latch_observed,
            runtime_socket_high_water: self.runtime_socket_high_water,
            replay_frames: self.replay_frames,
        })
    }
}

fn missing_rotation_field(rotation: u64, field: &str) -> HarnessError {
    HarnessError::Process(format!("I08 rotation {rotation} omitted {field}"))
}

fn retain_immutable(
    previous: Option<String>,
    current: Option<String>,
    rotation: u64,
    label: &str,
) -> Result<Option<String>> {
    match (previous, current) {
        (Some(previous), Some(current)) if previous != current => Err(HarnessError::Process(
            format!("I08 rotation {rotation} changed immutable {label}"),
        )),
        (Some(previous), _) => Ok(Some(previous)),
        (None, current) => Ok(current),
    }
}

fn retain_fence_sequence(
    previous: Option<u64>,
    values: &[(u64, u64)],
    expected_stream_id: u64,
    rotation: u64,
    direction: &str,
) -> Result<Option<u64>> {
    let current = values
        .iter()
        .find_map(|(stream_id, sequence)| (*stream_id == expected_stream_id).then_some(*sequence));
    match (previous, current) {
        (Some(previous), Some(current)) if previous != current => Err(HarnessError::Process(
            format!("I08 rotation {rotation} changed {direction} fence sequence"),
        )),
        (Some(previous), _) => Ok(Some(previous)),
        (None, current) => Ok(current),
    }
}

fn retain_ack_sequence(
    previous: Option<u64>,
    values: &[(u64, u64)],
    expected_stream_id: u64,
    rotation: u64,
    direction: &str,
) -> Result<Option<u64>> {
    let current = values
        .iter()
        .find_map(|(stream_id, sequence)| (*stream_id == expected_stream_id).then_some(*sequence));
    match (previous, current) {
        (Some(previous), Some(current)) if previous != current => Err(HarnessError::Process(
            format!("I08 rotation {rotation} changed {direction} ACK sequence"),
        )),
        (Some(previous), _) => Ok(Some(previous)),
        (None, current) => Ok(current),
    }
}

fn tokio_deadline(deadline: Instant) -> tokio::time::Instant {
    tokio::time::Instant::from_std(deadline)
}

fn ensure_owner_token(
    expected: &tunnel_catalog::OwnerToken,
    observed: &tunnel_catalog::OwnerClaim,
) -> Result<()> {
    if observed.token != *expected {
        return Err(HarnessError::Process(
            "I08 owner token changed during same-owner rotation".into(),
        ));
    }
    Ok(())
}

/// Match the relay's canonical owner-id digest.  The digest commits the full
/// fencing token, including the owner node identity, rather than accepting a
/// caller-selected node label.
fn owner_id_for_token(owner: &tunnel_catalog::OwnerToken) -> Result<String> {
    let canonical = serde_json::to_vec(owner)
        .map_err(|error| HarnessError::Process(format!("I08 owner identity encoding: {error}")))?;
    Ok(Sha256::digest(canonical)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn exactly_one_nonterminal_admitted_stream(
    session: &RelaySessionSnapshot,
) -> Result<Option<&RelayStreamSnapshot>> {
    Ok(exactly_one_nonterminal_stream(session)?.filter(|stream| !stream.authorization_in_flight))
}

fn exactly_one_nonterminal_stream(
    session: &RelaySessionSnapshot,
) -> Result<Option<&RelayStreamSnapshot>> {
    let mut streams = session.streams.iter().filter(|stream| !stream.terminal);
    let Some(stream) = streams.next() else {
        return Ok(None);
    };
    if streams.next().is_some() {
        return Err(HarnessError::Process(
            "I08 expected exactly one nonterminal admitted stream".into(),
        ));
    }
    if stream.authorization_failure_code.is_some() {
        return Err(HarnessError::Process(
            "I08 nonterminal stream carried an admission failure".into(),
        ));
    }
    if stream.operation_id.is_empty() {
        return Ok(None);
    }
    Ok(Some(stream))
}

async fn owner_session(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    expected_session_id: &str,
    expected_epoch: u64,
    deadline: Instant,
) -> Result<RelaySessionSnapshot> {
    loop {
        let snapshot = timeout_at(
            tokio_deadline(deadline),
            cluster.relay("relay-a")?.snapshot(),
        )
        .await
        .map_err(|_| HarnessError::Timeout("I08 owner snapshot exceeded deadline".into()))??;
        if let Some(session) = snapshot.sessions.into_iter().find(|session| {
            session.tenant_id == tenant_id.to_string()
                && session.device_id == device_id.to_string()
                && session.session_id == expected_session_id
                && session.epoch == expected_epoch
        }) {
            return Ok(session);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "I08 owner session did not appear before deadline".into(),
            ));
        }
        sleep(I08_POLL).await;
    }
}

async fn owner_session_with_stream(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    expected_session_id: &str,
    expected_epoch: u64,
    deadline: Instant,
) -> Result<RelaySessionSnapshot> {
    loop {
        let session = owner_session(
            cluster,
            tenant_id,
            device_id,
            expected_session_id,
            expected_epoch,
            deadline,
        )
        .await?;
        if exactly_one_nonterminal_admitted_stream(&session)?.is_some() {
            return Ok(session);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "I08 owner stream did not appear before deadline".into(),
            ));
        }
        sleep(I08_POLL).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn wait_for_rotation(
    cluster: &ProductionCluster,
    process: &ManagedProcess,
    initial_cli: &CliStatus,
    expected_owner: &tunnel_catalog::OwnerToken,
    device_id: Uuid,
    stream_id: u64,
    operation_id: &str,
    previous_generation: u64,
    expected_rotation: u64,
    deadline: Instant,
    // The clean synthetic gate rotates an idle stream and requires zero
    // retained replay.  The partial-response gate rotates with maximum-size
    // responses continuously in flight, where retaining and replaying whole
    // frames onto the replacement carrier is the documented behaviour, so it
    // records the count instead of rejecting it.
    allow_replay_frames: bool,
) -> Result<(RelaySessionSnapshot, I08RotationEvidence, CliStatus)> {
    let mut accumulator = RotationAccumulator::new(expected_rotation, stream_id);
    let mut latest_cli = initial_cli.clone();
    let expected_owner_id = owner_id_for_token(expected_owner)?;
    loop {
        if let Some(status) = latest_cli_status(process, initial_cli)? {
            latest_cli = status;
        }
        let session = owner_session(
            cluster,
            expected_owner.tenant_id,
            device_id,
            &initial_cli.session_id,
            initial_cli.epoch,
            deadline,
        )
        .await?;
        if session.session_id != initial_cli.session_id
            || session.epoch != initial_cli.epoch
            || session.active_generation < previous_generation
        {
            return Err(HarnessError::Process(format!(
                "I08 owner session identity changed at rotation {expected_rotation}"
            )));
        }
        // The already-admitted stream periodically refreshes authorization.
        // Its identity must survive that in-flight catalog read; completion
        // below still waits for the refresh to resolve successfully.
        let stream = exactly_one_nonterminal_stream(&session)?
            .ok_or_else(|| HarnessError::Process("I08 owner stream is not admitted".into()))?;
        let authorization_idle = !stream.authorization_in_flight;
        if stream.stream_id != stream_id {
            return Err(HarnessError::Process(
                "I08 admitted stream identity changed during rotation".into(),
            ));
        }
        if stream.operation_id != operation_id {
            return Err(HarnessError::Process(
                "I08 tunnel operation id changed during rotation".into(),
            ));
        }
        if let Some(diagnostics) = session.rotation_diagnostics.as_ref()
            && (diagnostics.attempt_active || session.rotations_completed >= expected_rotation)
        {
            if let Some(attempt) = diagnostics.attempt.as_ref()
                && attempt.owner_id != expected_owner_id
            {
                return Err(HarnessError::Process(format!(
                    "I08 rotation {expected_rotation} owner_id did not match the expected owner token"
                )));
            }
            accumulator.observe(&session, diagnostics)?;
        }
        if !allow_replay_frames
            && (session.replay_frames != 0 || session.total_replayed_frames != 0)
        {
            return Err(HarnessError::Process(format!(
                "I08 clean rotation {expected_rotation} observed replay frames"
            )));
        }
        let owner = timeout_at(
            tokio_deadline(deadline),
            cluster
                .catalog
                .current_owner(expected_owner.tenant_id, device_id, Utc::now()),
        )
        .await
        .map_err(|_| HarnessError::Timeout("I08 owner lease sample exceeded deadline".into()))?
        .map_err(|error| HarnessError::Redis(format!("I08 owner lease sample: {error}")))?
        .ok_or_else(|| HarnessError::Process("I08 owner lease disappeared".into()))?;
        ensure_owner_token(expected_owner, &owner)?;
        if authorization_idle
            && session.rotations_completed >= expected_rotation
            && session.active_generation > previous_generation
            && session.candidate_generation.is_none()
            && session.phase == "active"
            && latest_cli.rotations_completed >= expected_rotation
            && latest_cli.generation == session.active_generation
            && latest_cli.active_connection_id == session.active_connection_id
            && accumulator.snapshot_id.is_some()
        {
            let attempt = accumulator.attempt.as_ref().ok_or_else(|| {
                HarnessError::Process(format!(
                    "I08 rotation {expected_rotation} omitted its latched attempt identity"
                ))
            })?;
            if attempt.session_id != initial_cli.session_id
                || attempt.epoch != initial_cli.epoch
                || attempt.owner_id != expected_owner_id
                || attempt.old_generation != previous_generation
                || attempt.new_generation != session.active_generation
                || attempt.new_connection_id != session.active_connection_id
                || attempt.old_connection_id == attempt.new_connection_id
            {
                return Err(HarnessError::Process(format!(
                    "I08 rotation {expected_rotation} latched an identity different from the tested carrier"
                )));
            }
            let evidence = accumulator.finish(&session)?;
            return Ok((session, evidence, latest_cli));
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "I08 rotation {expected_rotation} did not commit with explicit status"
            )));
        }
        sleep(I08_POLL).await;
    }
}

struct SyntheticRecord {
    sequence: u64,
    body: Vec<u8>,
}

impl SyntheticRecord {
    fn new(sequence: u64) -> Self {
        Self {
            sequence,
            body: format!("i08-record-{sequence}").into_bytes(),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let operation = I08_SYNTHETIC_OPERATION.as_bytes();
        let mut value = Vec::with_capacity(
            I08_MAGIC.len() + 8 + 1 + operation.len() + 8 + 4 + self.body.len() + 32,
        );
        value.extend_from_slice(I08_MAGIC);
        value.extend_from_slice(&I08_FID.to_be_bytes());
        value.push(operation.len() as u8);
        value.extend_from_slice(operation);
        value.extend_from_slice(&self.sequence.to_be_bytes());
        value.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
        value.extend_from_slice(&self.body);
        let checksum = Sha256::digest(&value);
        value.extend_from_slice(&checksum);
        value
    }

    /// Re-parse the exact bytes sent through the public stream and verify the
    /// opaque envelope's identity, sequence, body and digest.  The consumer
    /// helper also requires the Echo response payload to equal these bytes,
    /// so this check is response-backed without exposing the synthetic body
    /// in public evidence.
    fn verify_encoded(&self, value: &[u8]) -> Result<()> {
        let mut offset = 0usize;
        fn take<'a>(value: &'a [u8], offset: &mut usize, length: usize) -> Option<&'a [u8]> {
            let end = offset.checked_add(length)?;
            let bytes = value.get(*offset..end)?;
            *offset = end;
            Some(bytes)
        }
        if take(value, &mut offset, I08_MAGIC.len()) != Some(I08_MAGIC)
            || take(value, &mut offset, 8)
                .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                .map(u64::from_be_bytes)
                != Some(I08_FID)
        {
            return Err(HarnessError::Process(
                "I08 synthetic envelope identity header mismatch".into(),
            ));
        }
        let operation_len = *take(value, &mut offset, 1)
            .and_then(|bytes| bytes.first())
            .ok_or_else(|| HarnessError::Process("I08 envelope omitted operation length".into()))?
            as usize;
        if take(value, &mut offset, operation_len) != Some(I08_SYNTHETIC_OPERATION.as_bytes()) {
            return Err(HarnessError::Process(
                "I08 synthetic envelope operation mismatch".into(),
            ));
        }
        let sequence = take(value, &mut offset, 8)
            .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
            .map(u64::from_be_bytes)
            .ok_or_else(|| HarnessError::Process("I08 envelope omitted sequence".into()))?;
        if sequence != self.sequence {
            return Err(HarnessError::Process(
                "I08 synthetic envelope sequence mismatch".into(),
            ));
        }
        let body_len = take(value, &mut offset, 4)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(u32::from_be_bytes)
            .and_then(|length| usize::try_from(length).ok())
            .ok_or_else(|| HarnessError::Process("I08 envelope omitted body length".into()))?;
        let body = take(value, &mut offset, body_len).ok_or_else(|| {
            HarnessError::Process("I08 synthetic envelope body was truncated".into())
        })?;
        if body != self.body.as_slice() {
            return Err(HarnessError::Process(
                "I08 synthetic envelope body mismatch".into(),
            ));
        }
        let checksum = take(value, &mut offset, 32).ok_or_else(|| {
            HarnessError::Process("I08 synthetic envelope omitted checksum".into())
        })?;
        if offset != value.len() {
            return Err(HarnessError::Process(
                "I08 synthetic envelope contained trailing bytes".into(),
            ));
        }
        let expected = Sha256::digest(&value[..value.len() - 32]);
        if checksum != &expected[..] {
            return Err(HarnessError::Process(
                "I08 synthetic envelope checksum mismatch".into(),
            ));
        }
        Ok(())
    }
}

async fn round_trip_at(
    stream: &mut ConsumerStream,
    payload: &[u8],
    canary: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>> {
    timeout_at(
        tokio_deadline(deadline),
        stream.round_trip_capture(payload, canary),
    )
    .await
    .map_err(|_| HarnessError::Timeout("I08 echo exchange exceeded its scenario deadline".into()))?
}

async fn drive_scenario(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    deadline: Instant,
) -> Result<I08Evidence> {
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(
            "I08 requires exactly three production relays".into(),
        ));
    }
    let membership_ready = cluster
        .relays
        .iter()
        .filter(|relay| {
            matches!(
                relay.membership.readiness(),
                tunnel_relay::MembershipReadiness::Ready
            )
        })
        .count();
    if membership_ready != 3 {
        return Err(HarnessError::Process(format!(
            "I08 production membership reached {membership_ready}/3 Ready"
        )));
    }
    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("I08 tenant A has no device".into()))?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("I08 device has no echo service".into()))?;
    let canary = format!("m7-i08:{}", device.id);
    let profile_root = tempdir().map_err(HarnessError::Io)?;
    let mut profile = crate::acceptance::helpers::write_device_profile(
        profile_root.path(),
        device.id,
        service_id,
        &canary,
        cluster.device_fanout.local_addr(),
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile.config.rotation = ROTATION;
    profile
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("I08 CLI profile: {error}")))?;
    let mut config_text = fs::read_to_string(&profile.config_path).map_err(HarnessError::Io)?;
    config_text.push_str(&format!(
        "\n[rotation]\ninterval_seconds = {}\nhandshake_timeout_seconds = {}\noverlap_seconds = {}\n",
        ROTATION.interval_seconds, ROTATION.handshake_timeout_seconds, ROTATION.overlap_seconds
    ));
    fs::write(&profile.config_path, config_text).map_err(HarnessError::Io)?;
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        crate::OidcTokenOptions {
            expires_in: Duration::from_secs(90),
            ..crate::OidcTokenOptions::default()
        },
    )?;
    let ingress_relay = "relay-c".to_owned();
    let ingress_addr = cluster.relay(&ingress_relay)?.consumer_addr()?;
    let started = Instant::now();
    let (process, mut stream) = start_cli(
        harness,
        cluster.device_fanout.local_addr(),
        ingress_addr,
        &profile,
        &token,
        device.id,
        service_id,
        deadline,
    )
    .await?;
    let active = async {
        let owner_before = timeout_at(
            tokio_deadline(deadline),
            cluster
                .catalog
                .current_owner(device.tenant_id, device.id, Utc::now()),
        )
        .await
        .map_err(|_| HarnessError::Timeout("I08 initial owner lookup exceeded deadline".into()))?
        .map_err(|error| HarnessError::Redis(format!("I08 initial owner lookup: {error}")))?
        .ok_or_else(|| HarnessError::Process("I08 device has no catalog owner".into()))?;
        if owner_before.token.node_id != "relay-a" {
            return Err(HarnessError::Process(format!(
                "I08 expected relay-a owner, observed {}",
                owner_before.token.node_id
            )));
        }
        let initial_cli = wait_for_cli_status(&process, deadline).await?;
        if initial_cli.session_id != owner_before.token.session_id
            || initial_cli.epoch != owner_before.token.epoch
        {
            return Err(HarnessError::Process(
                "I08 CLI status and catalog owner session/epoch diverged".into(),
            ));
        }
        let mut owner = owner_session_with_stream(
            cluster,
            device.tenant_id,
            device.id,
            &initial_cli.session_id,
            initial_cli.epoch,
            deadline,
        )
        .await?;
        if owner.session_id != initial_cli.session_id || owner.epoch != initial_cli.epoch {
            return Err(HarnessError::Process(
                "I08 owner snapshot and CLI session identity diverged".into(),
            ));
        }
        if initial_cli.rotations_completed != 0
            || owner.phase != "active"
            || owner.candidate_generation.is_some()
            || owner.candidate_connection_id.is_some()
            || owner.rotations_completed != 0
            || owner.active_generation != initial_cli.generation
            || owner.active_connection_id != initial_cli.active_connection_id
        {
            return Err(HarnessError::Process(format!(
                "I08 baseline was not an active no-candidate state (cli_generation={}, owner_generation={}, cli_connection={}, owner_connection={}, cli_rotations={}, owner_rotations={}, phase={})",
                initial_cli.generation,
                owner.active_generation,
                initial_cli.active_connection_id,
                owner.active_connection_id,
                initial_cli.rotations_completed,
                owner.rotations_completed,
                owner.phase,
            )));
        }
        let stream_snapshot = exactly_one_nonterminal_admitted_stream(&owner)?
            .ok_or_else(|| HarnessError::Process("I08 public stream did not attach".into()))?;
        let stream_id = stream_snapshot.stream_id;
        let operation_id = stream_snapshot.operation_id.clone();
        let mut records_sent = 0usize;
        let mut records_echoed = 0usize;
        let mut checksums_verified = 0usize;
        let mut replay_frames = 0usize;
        let record = SyntheticRecord::new(0);
        let wire = record.encode();
        let response = round_trip_at(&mut stream, &wire, canary.as_bytes(), deadline).await?;
        record.verify_encoded(&response)?;
        records_sent += 1;
        records_echoed += 1;
        checksums_verified += 1;
        let mut rotations = Vec::with_capacity(ROTATION_COUNT as usize);
        let mut previous_generation = initial_cli.generation;
        let mut cli_status = initial_cli;
        for rotation in 1..=ROTATION_COUNT {
            let (after, proof, status) = wait_for_rotation(
                cluster,
                &process,
                &cli_status,
                &owner_before.token,
                device.id,
                stream_id,
                &operation_id,
                previous_generation,
                rotation,
                deadline,
                false,
            )
            .await?;
            previous_generation = after.active_generation;
            replay_frames = replay_frames.max(proof.replay_frames);
            let record = SyntheticRecord::new(rotation);
            let wire = record.encode();
            let response = round_trip_at(&mut stream, &wire, canary.as_bytes(), deadline).await?;
            record.verify_encoded(&response)?;
            records_sent += 1;
            records_echoed += 1;
            checksums_verified += 1;
            rotations.push(proof);
            cli_status = status;
            owner = after;
            if owner.session_id != cli_status.session_id
                || owner.epoch != cli_status.epoch
                || owner.streams.iter().any(|stream| {
                    stream.stream_id == stream_id && stream.operation_id != operation_id
                })
            {
                return Err(HarnessError::Process(
                    "I08 stream/session identity changed after rotation".into(),
                ));
            }
        }
        let elapsed = started.elapsed();
        let required = Duration::from_secs(ROTATION.interval_seconds * ROTATION_COUNT);
        if elapsed < required {
            return Err(HarnessError::Process(format!(
                "I08 rotations completed in {:.3}s below the configured {}s schedule",
                elapsed.as_secs_f64(),
                required.as_secs()
            )));
        }
        let final_cli = latest_cli_status(&process, &cli_status)?.ok_or_else(|| {
            HarnessError::Process("I08 CLI omitted its final stable status event".into())
        })?;
        if final_cli.rotations_completed < ROTATION_COUNT
            || final_cli.generation != owner.active_generation
            || final_cli.active_connection_id != owner.active_connection_id
            || final_cli.active_local_addr.is_empty()
        {
            return Err(HarnessError::Process(
                "I08 CLI final status diverged from the owner snapshot".into(),
            ));
        }
        cli_status = final_cli;
        let final_owner = timeout_at(
            tokio_deadline(deadline),
            cluster
                .catalog
                .current_owner(device.tenant_id, device.id, Utc::now()),
        )
        .await
        .map_err(|_| HarnessError::Timeout("I08 final owner lookup exceeded deadline".into()))?
        .map_err(|error| HarnessError::Redis(format!("I08 final owner lookup: {error}")))?
        .ok_or_else(|| HarnessError::Process("I08 owner disappeared after rotations".into()))?;
        ensure_owner_token(&owner_before.token, &final_owner)?;
        let socket_high_water = cluster.device_fanout.diagnostics().peak_open;
        Ok::<I08Evidence, HarnessError>(I08Evidence {
            scope: "synthetic_echo_mapping_only",
            relay_count: cluster.relays.len(),
            public_ingress_relay: ingress_relay.clone(),
            owner_relay: owner_before.token.node_id.clone(),
            actual_cli_process: true,
            public_ingress: true,
            control_identity_stable: cli_status.session_id == owner.session_id
                && cli_status.epoch == owner.epoch
                && !cli_status.control_local_addr.is_empty(),
            session_id: owner.session_id.clone(),
            epoch: owner.epoch,
            stream_id,
            tunnel_operation_id: operation_id,
            synthetic_fid: I08_FID,
            synthetic_operation_id: I08_SYNTHETIC_OPERATION.to_owned(),
            records_sent,
            records_echoed,
            checksums_verified,
            rotations,
            socket_high_water,
            replay_frames,
            cleanup_joined: false,
            elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        })
    }
    .await;
    let cleanup_at = cleanup_deadline(deadline);
    let close_result = timeout_at(tokio_deadline(cleanup_at), stream.close())
        .await
        .map_err(|_| HarnessError::Timeout("I08 consumer stream cleanup exceeded deadline".into()))
        .and_then(|result| result);
    let process_result = shutdown_process(process, cleanup_at).await;
    let mut cleanup_errors = Vec::new();
    if let Err(error) = close_result {
        cleanup_errors.push(format!("consumer cleanup failed: {error}"));
    }
    if let Err(error) = process_result {
        cleanup_errors.push(format!("CLI cleanup failed: {error}"));
    }
    match active {
        Err(error) if cleanup_errors.is_empty() => Err(error),
        Err(error) => Err(HarnessError::Process(format!(
            "{error}; {}",
            cleanup_errors.join("; ")
        ))),
        Ok(_) if !cleanup_errors.is_empty() => {
            Err(HarnessError::Process(cleanup_errors.join("; ")))
        }
        Ok(mut evidence) => {
            evidence.cleanup_joined = true;
            Ok(evidence)
        }
    }
}

/// Shut down every task-bearing production resource while retaining ownership
/// across each bounded join. Wrapping `ProductionCluster::shutdown` in
/// `timeout` would consume the cluster into a future and drop its remaining
/// relay/fanout handles when the timeout fires.
async fn shutdown_cluster_until(mut cluster: ProductionCluster, deadline: Instant) -> Result<()> {
    let tokio_deadline = tokio::time::Instant::from_std(deadline);
    let mut errors = Vec::new();
    if let Err(error) = shutdown_fanout_until(
        &mut cluster.tenant_b_fanout,
        tokio_deadline,
        "tenant-B fanout",
    )
    .await
    {
        errors.push(format!("tenant-B fanout cleanup: {error}"));
    }
    if let Err(error) =
        shutdown_fanout_until(&mut cluster.device_fanout, tokio_deadline, "device fanout").await
    {
        errors.push(format!("device fanout cleanup: {error}"));
    }
    while let Some(relay) = cluster.relays.pop() {
        if let Err(error) = relay.shutdown().await {
            errors.push(format!("relay cleanup: {error}"));
        }
    }
    for (_, mut proxy) in cluster.peer_proxies {
        if let Err(error) = proxy.shutdown().await {
            errors.push(format!("peer proxy cleanup: {error}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(HarnessError::Process(errors.join("; ")))
    }
}

async fn shutdown_fanout_until(
    fanout: &mut crate::FanoutProxyHandle,
    graceful_deadline: tokio::time::Instant,
    label: &str,
) -> Result<()> {
    let graceful = fanout.shutdown_until(graceful_deadline).await;
    let Err(graceful_error) = graceful else {
        return Ok(());
    };
    let forced_deadline = tokio::time::Instant::now() + I08_FANOUT_FORCED_JOIN_GRACE;
    match fanout.shutdown_until(forced_deadline).await {
        Ok(()) => Err(HarnessError::Process(format!(
            "{label} exceeded its graceful shutdown deadline: {graceful_error}; bounded forced join completed"
        ))),
        Err(forced_error) => {
            let final_deadline = tokio::time::Instant::now() + I08_FANOUT_FORCED_JOIN_GRACE;
            match fanout.shutdown_until(final_deadline).await {
                Ok(()) => Err(HarnessError::Process(format!(
                    "{label} graceful shutdown failed: {graceful_error}; bounded forced join failed: {forced_error}; final bounded join completed"
                ))),
                Err(final_error) => Err(HarnessError::Process(format!(
                    "{label} graceful shutdown failed: {graceful_error}; bounded forced join failed: {forced_error}; final bounded join failed: {final_error}"
                ))),
            }
        }
    }
}

/// Start the isolated real-resource fixture and own all cleanup paths.
pub async fn verify() -> Result<I08Evidence> {
    let options = HarnessOptions::from_env()?
        .rotation(ROTATION)
        .shared_device_uuid(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("I08 harness startup timed out".into()))??;
    let mut cluster = match timeout(STARTUP_TIMEOUT, ProductionCluster::start(&mut harness)).await {
        Ok(Ok(cluster)) => cluster,
        Ok(Err(error)) => {
            let cleanup_deadline = Instant::now() + CLEANUP_TIMEOUT;
            return match harness
                .shutdown_until(tokio::time::Instant::from_std(cleanup_deadline))
                .await
            {
                Ok(()) => Err(error),
                Err(cleanup) => Err(HarnessError::Process(format!(
                    "{error}; I08 harness cleanup failed: {cleanup}"
                ))),
            };
        }
        Err(_) => {
            let error = HarnessError::Timeout("I08 production cluster startup timed out".into());
            let cleanup_deadline = Instant::now() + CLEANUP_TIMEOUT;
            return match harness
                .shutdown_until(tokio::time::Instant::from_std(cleanup_deadline))
                .await
            {
                Ok(()) => Err(error),
                Err(cleanup) => Err(HarnessError::Process(format!(
                    "{error}; I08 harness cleanup failed: {cleanup}"
                ))),
            };
        }
    };
    let deadline = Instant::now() + I08_SCENARIO_TIMEOUT.min(SCENARIO_TIMEOUT);
    let scenario = drive_scenario(&mut cluster, &harness, deadline).await;
    let cleanup_deadline = Instant::now() + CLEANUP_TIMEOUT;
    let cluster_cleanup = shutdown_cluster_until(cluster, cleanup_deadline).await;
    let harness_cleanup = harness
        .shutdown_until(tokio::time::Instant::from_std(cleanup_deadline))
        .await;
    let mut cleanup_errors = Vec::new();
    if let Err(error) = cluster_cleanup {
        cleanup_errors.push(format!("relay cleanup failed: {error}"));
    }
    if let Err(error) = harness_cleanup {
        cleanup_errors.push(format!("Redis cleanup failed: {error}"));
    }
    match scenario {
        Err(error) if cleanup_errors.is_empty() => Err(error),
        Err(error) => Err(HarnessError::Process(format!(
            "{error}; {}",
            cleanup_errors.join("; ")
        ))),
        Ok(_) if !cleanup_errors.is_empty() => {
            Err(HarnessError::Process(cleanup_errors.join("; ")))
        }
        Ok(evidence) => {
            validate_i08_evidence(&evidence)?;
            Ok(evidence)
        }
    }
}
// ---------------------------------------------------------------------------
// M7-I08 partial-response rotation.
//
// The row's last clause asked for a rotation committed while a synthetic
// adapter response is only partly delivered, resumed at an exact byte cursor.
// The product deliberately does not resume a record at a byte offset:
//
//   * `tunnel_client::m2_runtime::M2Actor::emit_payload` chunks a response
//     with `output.chunks(MAX_PAYLOAD_LEN)` and hands every chunk to
//     `emit_or_defer`, which reaches the carrier through the synchronous
//     `emit_output_now`.  The connector actor never yields between a
//     response's frames, so a rotation freeze lands before or after a whole
//     response, never inside one.
//   * A frozen actor defers whole `PendingOutput` values into
//     `pending_outputs` with no sequence allocated, and flushes them whole
//     onto the replacement carrier.
//   * The relay's fence is `StreamFence { last_emitted }`, a frame sequence
//     number, and `validate_ack_cursors` admits COMMIT only when the peer's
//     `recv_contiguous` equals that fence exactly.  The retained replay map
//     is keyed by sequence and replays intact frames.
//
// There is no byte-offset-within-record cursor in `DirectionState`,
// `StreamFence`, `DrainProof` or `ReplayRange`, so "resume at byte N of a
// record" is not a state the product can express.  This gate asserts what
// the product does guarantee for a partly delivered response: the largest
// response the product can produce necessarily spans more than one tunnel
// DATA frame, is driven continuously across real committed rotations, and
// reaches the consumer complete, exactly once, with the received prefix
// equal to the source prefix at every observed byte cursor and a checksum
// computed independently of the delivery path.  The resume unit actually
// observed is recorded as a typed label rather than assumed.
// ---------------------------------------------------------------------------

/// Poll interval used while chasing the bounded rotation attempt window.
const I08_PARTIAL_POLL: Duration = Duration::from_millis(2);
/// Bounded number of maximum-size responses driven across one rotation
/// attempt window, so the gate cannot grow unbounded loopback work.
const I08_PARTIAL_BURST_CAP: usize = 192;
/// Byte overhead of the synthetic envelope around its body.
const I08_ENVELOPE_OVERHEAD: usize =
    I08_MAGIC.len() + 8 + 1 + I08_SYNTHETIC_OPERATION.len() + 8 + 4 + 32;
/// Maximum public consumer record this fixture sends.  It matches the relay's
/// `wire::MAX_BODY_BYTES`, so the echoed response is the largest the product
/// can produce and necessarily spans more than one tunnel DATA frame.
const I08_PARTIAL_RECORD_BYTES: usize = tunnel_protocol::MAX_PAYLOAD_LEN;
const I08_PARTIAL_SCENARIO_TIMEOUT: Duration = Duration::from_secs(150);
/// Bounded wait for the rotation overlap window used by the adapter-shutdown
/// clause.
const I08_PARTIAL_OVERLAP_TIMEOUT: Duration = Duration::from_secs(12);
/// Bounded wait for the one probe issued after the adapter shutdown.
const I08_PARTIAL_POST_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
/// The resume unit the connector and relay actually implement.
const I08_RESUME_UNIT: &str = "frame_sequence";

/// Typed outcomes for the single probe issued after the adapter shutdown.
const I08_POST_SHUTDOWN_OUTCOMES: [&str; 3] = [
    "closed_before_response",
    "complete_checksummed_response",
    "no_response_before_deadline",
];

/// Rotation phases that count as the bounded overlap window.
const I08_OVERLAP_PHASES: [&str; 5] = [
    "preparing",
    "quiescing",
    "draining",
    "committing",
    "retiring",
];

/// Payload-free evidence for the partial-response rotation clause.  Every
/// field is a count, a byte offset, a checksum-derived boolean or a typed
/// label; no response body reaches this structure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct I08PartialResponseEvidence {
    pub scope: &'static str,
    pub relay_count: usize,
    pub session_id: String,
    pub epoch: u64,
    pub stream_id: u64,
    pub tunnel_operation_id: String,
    pub synthetic_fid: u64,
    pub synthetic_operation_id: String,
    /// Bytes in one maximum-size synthetic adapter request record.
    pub request_record_bytes: usize,
    /// Bytes in the adapter response the consumer reassembles.
    pub response_record_bytes: usize,
    /// Tunnel DATA frames the response necessarily occupies.
    pub response_frames: usize,
    /// Resume unit the relay and connector implement.  Recorded because the
    /// row asked for a byte cursor and the product resumes on frame sequence
    /// numbers instead.
    pub resume_unit: String,
    /// The product does not resume a partially written record at a byte
    /// offset; a record is emitted whole or retained whole.
    pub byte_cursor_resume_supported: bool,
    pub responses_delivered: usize,
    pub responses_checksum_matched: usize,
    /// Responses the consumer reassembled from more than one transport chunk,
    /// so delivery was observed incrementally rather than atomically.
    pub responses_multi_chunk: usize,
    /// Responses whose request and final chunk bracketed a connector-reported
    /// active-generation change.  Sampled from the CLI's own published status
    /// immediately before the request and between delivered chunks.
    pub responses_bracketing_commit: usize,
    /// Consumer byte offsets at which the connector's new active generation
    /// was first observed while that response was still incomplete.
    pub partial_resume_offsets: Vec<usize>,
    /// Chunks whose received prefix diverged from the source prefix at the
    /// observed byte cursor.  A gap or a duplicated byte lands here.
    pub cursor_gaps: usize,
    /// Bytes received beyond the response's declared length.
    pub duplicated_bytes: u64,
    /// Rotations whose bounded proof showed the relay retaining frames and
    /// replaying them onto the replacement carrier.  This is the mechanism
    /// the product uses in place of a byte-offset resume: whole frames,
    /// keyed by sequence, re-emitted with a rewritten generation.
    pub rotations_retaining_replay: usize,
    pub rotations: Vec<I08RotationEvidence>,
    /// Relay rotation phase observed when the adapter shutdown was requested.
    pub adapter_shutdown_phase: String,
    pub adapter_shutdown_in_overlap: bool,
    pub adapter_shutdown_graceful: bool,
    /// Typed outcome of the one probe issued after the adapter shutdown.
    pub post_shutdown_outcome: String,
    pub socket_high_water: usize,
    pub cleanup_joined: bool,
    pub elapsed_ms: u64,
}

/// Reject incomplete or weakened partial-response evidence.
pub fn validate_i08_partial_response_evidence(evidence: &I08PartialResponseEvidence) -> Result<()> {
    if evidence.scope != "synthetic_echo_mapping_only" {
        return Err(HarnessError::Process(format!(
            "M7-I08 partial evidence has unexpected scope {:?}",
            evidence.scope
        )));
    }
    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "M7-I08 partial expected three production relays, observed {}",
            evidence.relay_count
        )));
    }
    if evidence.session_id.is_empty()
        || evidence.epoch == 0
        || evidence.stream_id == 0
        || evidence.tunnel_operation_id.is_empty()
        || evidence.synthetic_operation_id != I08_SYNTHETIC_OPERATION
        || evidence.synthetic_fid != I08_FID
    {
        return Err(HarnessError::Process(
            "M7-I08 partial omitted a stable session/stream/operation identity".into(),
        ));
    }
    if evidence.request_record_bytes != I08_PARTIAL_RECORD_BYTES {
        return Err(HarnessError::Process(format!(
            "M7-I08 partial expected a {I08_PARTIAL_RECORD_BYTES}-byte maximum record, observed {}",
            evidence.request_record_bytes
        )));
    }
    if evidence.response_record_bytes <= tunnel_protocol::MAX_PAYLOAD_LEN
        || evidence.response_frames < 2
        || evidence
            .response_record_bytes
            .div_ceil(tunnel_protocol::MAX_PAYLOAD_LEN)
            != evidence.response_frames
    {
        return Err(HarnessError::Process(format!(
            "M7-I08 partial response was not a multi-frame response: bytes={} frames={}",
            evidence.response_record_bytes, evidence.response_frames
        )));
    }
    if evidence.resume_unit != I08_RESUME_UNIT || evidence.byte_cursor_resume_supported {
        return Err(HarnessError::Process(format!(
            "M7-I08 partial recorded resume_unit={:?} byte_cursor_resume_supported={} instead of the implemented frame-sequence resume",
            evidence.resume_unit, evidence.byte_cursor_resume_supported
        )));
    }
    if evidence.responses_delivered == 0
        || evidence.responses_checksum_matched != evidence.responses_delivered
    {
        return Err(HarnessError::Process(format!(
            "M7-I08 partial expected every delivered response to match its independent checksum, observed delivered={} matched={}",
            evidence.responses_delivered, evidence.responses_checksum_matched
        )));
    }
    if evidence.responses_multi_chunk == 0 {
        return Err(HarnessError::Process(
            "M7-I08 partial never observed an incrementally delivered response".into(),
        ));
    }
    if evidence.responses_bracketing_commit == 0 {
        return Err(HarnessError::Process(
            "M7-I08 partial never bracketed a committed rotation with a response in flight".into(),
        ));
    }
    // This is the row's clause measured at the consumer: at least one
    // response must have been only partly delivered at the moment the
    // replacement generation became active, and the remainder must then have
    // completed from that exact byte cursor.  The cursor-gap, duplicate and
    // checksum conditions above are what make "resumed at the exact byte
    // cursor" mean something: they fail on a gap, a repeat or a truncation.
    if evidence.partial_resume_offsets.is_empty() {
        return Err(HarnessError::Process(
            "M7-I08 partial never observed a response that was still incomplete when the replacement generation became active".into(),
        ));
    }
    // The consumer reassembles the four-byte length prefix plus the response
    // body, so a legitimate resume cursor lies strictly inside that frame.
    let framed_len = evidence.response_record_bytes.saturating_add(4);
    if let Some(offset) = evidence
        .partial_resume_offsets
        .iter()
        .find(|offset| **offset == 0 || **offset >= framed_len)
    {
        return Err(HarnessError::Process(format!(
            "M7-I08 partial recorded resume offset {offset} outside the partly delivered range"
        )));
    }
    if evidence.cursor_gaps != 0 || evidence.duplicated_bytes != 0 {
        return Err(HarnessError::Process(format!(
            "M7-I08 partial observed cursor_gaps={} duplicated_bytes={}",
            evidence.cursor_gaps, evidence.duplicated_bytes
        )));
    }
    if evidence.rotations.len() != ROTATION_COUNT as usize {
        return Err(HarnessError::Process(format!(
            "M7-I08 partial expected {ROTATION_COUNT} rotation proofs, observed {}",
            evidence.rotations.len()
        )));
    }
    let observed_retaining = evidence
        .rotations
        .iter()
        .filter(|rotation| rotation.replay_frames > 0)
        .count();
    if evidence.rotations_retaining_replay != observed_retaining {
        return Err(HarnessError::Process(format!(
            "M7-I08 partial reported {} rotations retaining replay but its rotation proofs show {observed_retaining}",
            evidence.rotations_retaining_replay
        )));
    }
    let mut previous_generation = 0;
    for (index, rotation) in evidence.rotations.iter().enumerate() {
        let expected = index as u64 + 1;
        if rotation.rotation != expected
            || rotation.active_generation <= previous_generation
            || rotation.snapshot_id.is_empty()
            || !rotation.completed_latch_observed
            || rotation.relay_fence_sequence != rotation.relay_ack_sequence
            || rotation.connector_fence_sequence != rotation.connector_ack_sequence
            || !rotation.candidate_ready
            || !rotation.commit_sent
            || !rotation.commit_accepted
            || !rotation.old_socket_closed
        {
            return Err(HarnessError::Process(format!(
                "M7-I08 partial rotation {expected} did not prove a whole-frame drain to its fence"
            )));
        }
        previous_generation = rotation.active_generation;
    }
    if !evidence.adapter_shutdown_in_overlap
        || !I08_OVERLAP_PHASES.contains(&evidence.adapter_shutdown_phase.as_str())
    {
        return Err(HarnessError::Process(format!(
            "M7-I08 partial adapter shutdown was not requested inside the rotation overlap: phase={:?} in_overlap={}",
            evidence.adapter_shutdown_phase, evidence.adapter_shutdown_in_overlap
        )));
    }
    if !evidence.adapter_shutdown_graceful {
        return Err(HarnessError::Process(
            "M7-I08 partial adapter shutdown did not complete gracefully".into(),
        ));
    }
    if !I08_POST_SHUTDOWN_OUTCOMES.contains(&evidence.post_shutdown_outcome.as_str()) {
        return Err(HarnessError::Process(format!(
            "M7-I08 partial recorded an unclassified post-shutdown outcome {:?}",
            evidence.post_shutdown_outcome
        )));
    }
    if evidence.socket_high_water < 2 || evidence.socket_high_water > 3 {
        return Err(HarnessError::Process(format!(
            "M7-I08 partial socket high-water was outside the bounded 2..=3 shape: {}",
            evidence.socket_high_water
        )));
    }
    if !evidence.cleanup_joined {
        return Err(HarnessError::Process(
            "M7-I08 partial evidence is incomplete: cleanup_joined".into(),
        ));
    }
    Ok(())
}

impl SyntheticRecord {
    /// Build a record whose encoded envelope is exactly `total_bytes` long.
    /// The body is a deterministic sequence-derived pattern so a duplicated,
    /// reordered or truncated delivery cannot compare equal to the source.
    fn sized(sequence: u64, total_bytes: usize) -> Result<Self> {
        let body_len = total_bytes
            .checked_sub(I08_ENVELOPE_OVERHEAD)
            .ok_or_else(|| {
                HarnessError::InvalidInput(
                    "I08 partial record size is below the synthetic envelope overhead".into(),
                )
            })?;
        let body = (0..body_len)
            .map(|index| {
                let index = index as u64;
                (index
                    .wrapping_mul(31)
                    .wrapping_add(sequence.wrapping_mul(1_000_003))
                    % 251) as u8
            })
            .collect();
        Ok(Self { sequence, body })
    }
}

/// One maximum-size response's payload-free delivery record.
#[derive(Clone, Debug, Default)]
struct PartialDelivery {
    chunks: usize,
    cursor_gaps: usize,
    duplicated_bytes: u64,
    resume_offset: Option<usize>,
    bracketed_commit: bool,
    checksum_matched: bool,
}

/// Accumulated payload-free statistics for the burst phase.
#[derive(Clone, Debug, Default)]
struct PartialStats {
    delivered: usize,
    checksum_matched: usize,
    multi_chunk: usize,
    bracketing_commit: usize,
    cursor_gaps: usize,
    duplicated_bytes: u64,
    resume_offsets: Vec<usize>,
}

/// Build the exact response frame the consumer must reassemble for one
/// maximum-size synthetic record, together with its source-derived digest.
fn partial_expected_frame(record: &SyntheticRecord, canary: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    let wire = record.encode();
    if wire.len() != I08_PARTIAL_RECORD_BYTES {
        return Err(HarnessError::InvalidInput(
            "I08 partial record did not encode to the maximum record size".into(),
        ));
    }
    let declared = u32::try_from(canary.len() + wire.len())
        .map_err(|_| HarnessError::InvalidInput("I08 partial response length overflow".into()))?;
    let mut frame = Vec::with_capacity(4 + canary.len() + wire.len());
    frame.extend_from_slice(&declared.to_be_bytes());
    frame.extend_from_slice(canary);
    frame.extend_from_slice(&wire);
    // The digest is taken from the source envelope, never from the bytes the
    // delivery path produced.
    let digest: [u8; 32] = Sha256::digest(&frame).into();
    Ok((frame, digest))
}

/// Send one maximum-size synthetic record and reassemble its response chunk
/// by chunk, checking the received prefix against the source prefix at every
/// observed byte cursor and sampling the connector's published generation
/// between chunks.
async fn partial_round_trip(
    stream: &mut ConsumerStream,
    process: &ManagedProcess,
    initial_cli: &CliStatus,
    request: &[u8],
    expected_frame: &[u8],
    expected_digest: &[u8; 32],
    deadline: Instant,
) -> Result<PartialDelivery> {
    let length = u32::try_from(request.len())
        .map_err(|_| HarnessError::InvalidInput("I08 partial request length overflow".into()))?;
    let mut framed = Vec::with_capacity(request.len() + 4);
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(request);
    let generation_before = latest_cli_status(process, initial_cli)?
        .map_or(initial_cli.generation, |status| status.generation);
    stream
        .socket
        .send(Message::Binary(framed.into()))
        .await
        .map_err(|error| HarnessError::Http(format!("I08 partial request send: {error}")))?;

    let mut delivery = PartialDelivery::default();
    let mut received: Vec<u8> = Vec::with_capacity(expected_frame.len());
    let mut generation_after = generation_before;
    loop {
        if let Some(status) = latest_cli_status(process, initial_cli)? {
            generation_after = status.generation;
            if status.generation > generation_before
                && delivery.resume_offset.is_none()
                && !received.is_empty()
                && received.len() < expected_frame.len()
            {
                // The response was still incomplete at this exact consumer
                // byte cursor when the replacement generation became active.
                delivery.resume_offset = Some(received.len());
            }
        }
        let next = timeout_at(tokio_deadline(deadline), stream.socket.next())
            .await
            .map_err(|_| {
                HarnessError::Timeout("I08 partial response chunk exceeded its deadline".into())
            })?;
        match next {
            Some(Ok(Message::Binary(bytes))) => {
                delivery.chunks += 1;
                received.extend_from_slice(&bytes);
                let compared = received.len().min(expected_frame.len());
                if received[..compared] != expected_frame[..compared] {
                    delivery.cursor_gaps += 1;
                }
                if received.len() > expected_frame.len() {
                    delivery.duplicated_bytes = delivery
                        .duplicated_bytes
                        .saturating_add((received.len() - expected_frame.len()) as u64);
                    break;
                }
                if received.len() == expected_frame.len() {
                    break;
                }
            }
            Some(Ok(Message::Ping(bytes))) => {
                stream
                    .socket
                    .send(Message::Pong(bytes))
                    .await
                    .map_err(|error| HarnessError::Http(format!("I08 partial pong: {error}")))?;
            }
            Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
            Some(Ok(Message::Text(_))) => {
                return Err(HarnessError::Http(
                    "I08 partial response returned text".into(),
                ));
            }
            Some(Ok(Message::Close(_))) | None => {
                return Err(HarnessError::Http(
                    "I08 partial response closed before completion".into(),
                ));
            }
            Some(Err(error)) => {
                return Err(HarnessError::Http(format!(
                    "I08 partial response read: {error}"
                )));
            }
        }
    }
    delivery.checksum_matched = Sha256::digest(&received)[..] == expected_digest[..];
    delivery.bracketed_commit = generation_after > generation_before;
    Ok(delivery)
}

/// Drive maximum-size responses back to back until the rotation under test
/// commits, so a response is in flight across the commit.
#[allow(clippy::too_many_arguments)]
async fn partial_burst(
    stream: &mut ConsumerStream,
    process: &ManagedProcess,
    initial_cli: &CliStatus,
    canary: &[u8],
    base_sequence: u64,
    stats: &mut PartialStats,
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<()> {
    for index in 0..I08_PARTIAL_BURST_CAP {
        if cancel.is_cancelled() {
            return Ok(());
        }
        let record = SyntheticRecord::sized(
            base_sequence.wrapping_add(index as u64),
            I08_PARTIAL_RECORD_BYTES,
        )?;
        let (expected_frame, expected_digest) = partial_expected_frame(&record, canary)?;
        let wire = expected_frame[4 + canary.len()..].to_vec();
        let delivery = partial_round_trip(
            stream,
            process,
            initial_cli,
            &wire,
            &expected_frame,
            &expected_digest,
            deadline,
        )
        .await?;
        stats.delivered += 1;
        if delivery.checksum_matched {
            stats.checksum_matched += 1;
        }
        if delivery.chunks > 1 {
            stats.multi_chunk += 1;
        }
        if delivery.bracketed_commit {
            stats.bracketing_commit += 1;
        }
        if let Some(offset) = delivery.resume_offset {
            stats.resume_offsets.push(offset);
        }
        stats.cursor_gaps += delivery.cursor_gaps;
        stats.duplicated_bytes = stats
            .duplicated_bytes
            .saturating_add(delivery.duplicated_bytes);
        // Re-parse the synthetic envelope the consumer had to reassemble so a
        // delivery that matched the frame prefix but not the envelope fails.
        record.verify_encoded(&wire)?;
    }
    Ok(())
}

/// Wait for the relay to enter the bounded rotation overlap window.
async fn wait_for_overlap_phase(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    session_id: &str,
    epoch: u64,
    deadline: Instant,
) -> Result<String> {
    loop {
        let session =
            owner_session(cluster, tenant_id, device_id, session_id, epoch, deadline).await?;
        if I08_OVERLAP_PHASES.contains(&session.phase.as_str()) {
            return Ok(session.phase);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "I08 partial did not observe a rotation overlap window before its deadline".into(),
            ));
        }
        sleep(I08_PARTIAL_POLL).await;
    }
}

/// Issue one bounded probe after the adapter shutdown and classify the
/// outcome into the closed vocabulary.  A partly delivered response must
/// never be accepted as a complete one.
async fn classify_post_shutdown_probe(
    stream: &mut ConsumerStream,
    canary: &[u8],
    deadline: Instant,
) -> Result<String> {
    let record = SyntheticRecord::sized(u64::MAX, I08_PARTIAL_RECORD_BYTES)?;
    let (expected_frame, expected_digest) = partial_expected_frame(&record, canary)?;
    let wire = expected_frame[4 + canary.len()..].to_vec();
    let length = u32::try_from(wire.len())
        .map_err(|_| HarnessError::InvalidInput("I08 partial probe length overflow".into()))?;
    let mut framed = Vec::with_capacity(wire.len() + 4);
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(&wire);
    if stream
        .socket
        .send(Message::Binary(framed.into()))
        .await
        .is_err()
    {
        return Ok("closed_before_response".to_owned());
    }
    let mut received: Vec<u8> = Vec::new();
    loop {
        let next = match timeout_at(tokio_deadline(deadline), stream.socket.next()).await {
            Ok(next) => next,
            Err(_) => return Ok("no_response_before_deadline".to_owned()),
        };
        match next {
            Some(Ok(Message::Binary(bytes))) => {
                received.extend_from_slice(&bytes);
                let compared = received.len().min(expected_frame.len());
                if received[..compared] != expected_frame[..compared] {
                    return Err(HarnessError::Process(
                        "I08 partial post-shutdown probe delivered bytes that diverged from the source prefix".into(),
                    ));
                }
                if received.len() >= expected_frame.len() {
                    if received.len() != expected_frame.len()
                        || Sha256::digest(&received)[..] != expected_digest[..]
                    {
                        return Err(HarnessError::Process(
                            "I08 partial post-shutdown probe delivered a response that failed its independent checksum".into(),
                        ));
                    }
                    return Ok("complete_checksummed_response".to_owned());
                }
            }
            Some(Ok(Message::Ping(bytes))) => {
                if stream.socket.send(Message::Pong(bytes)).await.is_err() {
                    return Ok("closed_before_response".to_owned());
                }
            }
            Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
            Some(Ok(Message::Text(_))) => {
                return Err(HarnessError::Http(
                    "I08 partial post-shutdown probe returned text".into(),
                ));
            }
            Some(Ok(Message::Close(_))) | None | Some(Err(_)) => {
                if !received.is_empty() && received.len() < expected_frame.len() {
                    // A partly delivered response is reported as a close, not
                    // as a completed adapter response.
                    return Ok("closed_before_response".to_owned());
                }
                return Ok("closed_before_response".to_owned());
            }
        }
    }
}

/// Wait until the relay has started a rotation attempt for this session, so
/// the burst covers the window that contains the commit rather than an
/// arbitrary slice of the interval.
async fn wait_for_rotation_attempt(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    session_id: &str,
    epoch: u64,
    expected_rotation: u64,
    deadline: Instant,
) -> Result<()> {
    loop {
        let session =
            owner_session(cluster, tenant_id, device_id, session_id, epoch, deadline).await?;
        let attempt_active = session
            .rotation_diagnostics
            .as_ref()
            .is_some_and(|diagnostics| diagnostics.attempt_active);
        if attempt_active
            || session.candidate_generation.is_some()
            || session.phase != "active"
            || session.rotations_completed >= expected_rotation
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "I08 partial rotation {expected_rotation} attempt did not start before its deadline"
            )));
        }
        sleep(I08_PARTIAL_POLL).await;
    }
}

async fn drive_partial_scenario(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    deadline: Instant,
) -> Result<I08PartialResponseEvidence> {
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(
            "I08 partial requires exactly three production relays".into(),
        ));
    }
    let device =
        harness.topology.devices_a.first().ok_or_else(|| {
            HarnessError::InvalidInput("I08 partial tenant A has no device".into())
        })?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| {
            HarnessError::InvalidInput("I08 partial device has no echo service".into())
        })?;
    let canary = format!("m7-i08:{}", device.id);
    let profile_root = tempdir().map_err(HarnessError::Io)?;
    let mut profile = crate::acceptance::helpers::write_device_profile(
        profile_root.path(),
        device.id,
        service_id,
        &canary,
        cluster.device_fanout.local_addr(),
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile.config.rotation = ROTATION;
    profile
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("I08 partial CLI profile: {error}")))?;
    let mut config_text = fs::read_to_string(&profile.config_path).map_err(HarnessError::Io)?;
    config_text.push_str(&format!(
        "\n[rotation]\ninterval_seconds = {}\nhandshake_timeout_seconds = {}\noverlap_seconds = {}\n",
        ROTATION.interval_seconds, ROTATION.handshake_timeout_seconds, ROTATION.overlap_seconds
    ));
    fs::write(&profile.config_path, config_text).map_err(HarnessError::Io)?;
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        crate::OidcTokenOptions {
            expires_in: Duration::from_secs(120),
            ..crate::OidcTokenOptions::default()
        },
    )?;
    let ingress_addr = cluster.relay("relay-c")?.consumer_addr()?;
    let started = Instant::now();
    let (mut process, mut stream) = start_cli(
        harness,
        cluster.device_fanout.local_addr(),
        ingress_addr,
        &profile,
        &token,
        device.id,
        service_id,
        deadline,
    )
    .await?;

    let active = async {
        let owner_before = timeout_at(
            tokio_deadline(deadline),
            cluster
                .catalog
                .current_owner(device.tenant_id, device.id, Utc::now()),
        )
        .await
        .map_err(|_| {
            HarnessError::Timeout("I08 partial initial owner lookup exceeded deadline".into())
        })?
        .map_err(|error| HarnessError::Redis(format!("I08 partial initial owner lookup: {error}")))?
        .ok_or_else(|| HarnessError::Process("I08 partial device has no catalog owner".into()))?;
        let initial_cli = wait_for_cli_status(&process, deadline).await?;
        let owner = owner_session_with_stream(
            cluster,
            device.tenant_id,
            device.id,
            &initial_cli.session_id,
            initial_cli.epoch,
            deadline,
        )
        .await?;
        let stream_snapshot =
            exactly_one_nonterminal_admitted_stream(&owner)?.ok_or_else(|| {
                HarnessError::Process("I08 partial public stream did not attach".into())
            })?;
        let stream_id = stream_snapshot.stream_id;
        let operation_id = stream_snapshot.operation_id.clone();

        let mut stats = PartialStats::default();
        // Baseline: one maximum-size multi-frame response before any rotation.
        let baseline = SyntheticRecord::sized(0, I08_PARTIAL_RECORD_BYTES)?;
        let (baseline_frame, baseline_digest) =
            partial_expected_frame(&baseline, canary.as_bytes())?;
        let baseline_wire = baseline_frame[4 + canary.len()..].to_vec();
        let baseline_delivery = partial_round_trip(
            &mut stream,
            &process,
            &initial_cli,
            &baseline_wire,
            &baseline_frame,
            &baseline_digest,
            deadline,
        )
        .await?;
        if !baseline_delivery.checksum_matched
            || baseline_delivery.cursor_gaps != 0
            || baseline_delivery.duplicated_bytes != 0
        {
            return Err(HarnessError::Process(
                "I08 partial baseline maximum-size response failed its independent checksum".into(),
            ));
        }
        stats.delivered += 1;
        stats.checksum_matched += 1;
        if baseline_delivery.chunks > 1 {
            stats.multi_chunk += 1;
        }

        let mut rotations = Vec::with_capacity(ROTATION_COUNT as usize);
        let mut previous_generation = initial_cli.generation;
        let mut cli_status = initial_cli.clone();
        for rotation in 1..=ROTATION_COUNT {
            wait_for_rotation_attempt(
                cluster,
                device.tenant_id,
                device.id,
                &cli_status.session_id,
                cli_status.epoch,
                rotation,
                deadline,
            )
            .await?;
            let cancel = CancellationToken::new();
            let rotation_cancel = cancel.clone();
            let rotation_future = async {
                let outcome = wait_for_rotation(
                    cluster,
                    &process,
                    &cli_status,
                    &owner_before.token,
                    device.id,
                    stream_id,
                    &operation_id,
                    previous_generation,
                    rotation,
                    deadline,
                    true,
                )
                .await;
                rotation_cancel.cancel();
                outcome
            };
            let burst_future = partial_burst(
                &mut stream,
                &process,
                &cli_status,
                canary.as_bytes(),
                rotation.wrapping_mul(I08_PARTIAL_BURST_CAP as u64) + 1,
                &mut stats,
                &cancel,
                deadline,
            );
            let (rotation_outcome, burst_outcome) = tokio::join!(rotation_future, burst_future);
            burst_outcome?;
            let (after, proof, status) = rotation_outcome?;
            previous_generation = after.active_generation;
            cli_status = status;
            rotations.push(proof);
        }

        // Adapter shutdown inside the rotation overlap window.
        let overlap_deadline = (Instant::now() + I08_PARTIAL_OVERLAP_TIMEOUT).min(deadline);
        let adapter_shutdown_phase = wait_for_overlap_phase(
            cluster,
            device.tenant_id,
            device.id,
            &cli_status.session_id,
            cli_status.epoch,
            overlap_deadline,
        )
        .await?;
        process.request_stop().await?;
        let probe_deadline = (Instant::now() + I08_PARTIAL_POST_SHUTDOWN_TIMEOUT).min(deadline);
        let post_shutdown_outcome =
            classify_post_shutdown_probe(&mut stream, canary.as_bytes(), probe_deadline).await?;

        let elapsed = started.elapsed();
        let required = Duration::from_secs(ROTATION.interval_seconds * ROTATION_COUNT);
        if elapsed < required {
            return Err(HarnessError::Process(format!(
                "I08 partial rotations completed in {:.3}s below the configured {}s schedule",
                elapsed.as_secs_f64(),
                required.as_secs()
            )));
        }
        let socket_high_water = cluster.device_fanout.diagnostics().peak_open;
        let response_record_bytes = canary.len() + I08_PARTIAL_RECORD_BYTES;
        Ok::<I08PartialResponseEvidence, HarnessError>(I08PartialResponseEvidence {
            scope: "synthetic_echo_mapping_only",
            relay_count: cluster.relays.len(),
            session_id: cli_status.session_id.clone(),
            epoch: cli_status.epoch,
            stream_id,
            tunnel_operation_id: operation_id,
            synthetic_fid: I08_FID,
            synthetic_operation_id: I08_SYNTHETIC_OPERATION.to_owned(),
            request_record_bytes: I08_PARTIAL_RECORD_BYTES,
            response_record_bytes,
            response_frames: response_record_bytes.div_ceil(tunnel_protocol::MAX_PAYLOAD_LEN),
            resume_unit: I08_RESUME_UNIT.to_owned(),
            byte_cursor_resume_supported: false,
            responses_delivered: stats.delivered,
            responses_checksum_matched: stats.checksum_matched,
            responses_multi_chunk: stats.multi_chunk,
            responses_bracketing_commit: stats.bracketing_commit,
            partial_resume_offsets: stats.resume_offsets.clone(),
            cursor_gaps: stats.cursor_gaps,
            duplicated_bytes: stats.duplicated_bytes,
            rotations_retaining_replay: rotations
                .iter()
                .filter(|rotation| rotation.replay_frames > 0)
                .count(),
            rotations,
            adapter_shutdown_phase,
            adapter_shutdown_in_overlap: true,
            adapter_shutdown_graceful: false,
            post_shutdown_outcome,
            socket_high_water,
            cleanup_joined: false,
            elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        })
    }
    .await;

    let cleanup_at = cleanup_deadline(deadline);
    let close_result = timeout_at(tokio_deadline(cleanup_at), stream.close())
        .await
        .map_err(|_| HarnessError::Timeout("I08 partial consumer cleanup exceeded deadline".into()))
        .and_then(|result| result);
    let process_result = shutdown_process(process, cleanup_at).await;
    let graceful = process_result.is_ok();
    let mut cleanup_errors = Vec::new();
    if let Err(error) = close_result {
        cleanup_errors.push(format!("consumer cleanup failed: {error}"));
    }
    if let Err(error) = process_result {
        cleanup_errors.push(format!("CLI cleanup failed: {error}"));
    }
    match active {
        Err(error) if cleanup_errors.is_empty() => Err(error),
        Err(error) => Err(HarnessError::Process(format!(
            "{error}; {}",
            cleanup_errors.join("; ")
        ))),
        Ok(_) if !cleanup_errors.is_empty() => {
            Err(HarnessError::Process(cleanup_errors.join("; ")))
        }
        Ok(mut evidence) => {
            evidence.cleanup_joined = true;
            evidence.adapter_shutdown_graceful = graceful;
            Ok(evidence)
        }
    }
}

/// Start the isolated real-resource fixture and own all cleanup paths.
pub async fn verify_partial_response_rotation() -> Result<I08PartialResponseEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(ROTATION)
        .shared_device_uuid(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("I08 partial harness startup timed out".into()))??;
    let mut cluster = match timeout(STARTUP_TIMEOUT, ProductionCluster::start(&mut harness)).await {
        Ok(Ok(cluster)) => cluster,
        Ok(Err(error)) => {
            let cleanup_at = Instant::now() + CLEANUP_TIMEOUT;
            return match harness
                .shutdown_until(tokio::time::Instant::from_std(cleanup_at))
                .await
            {
                Ok(()) => Err(error),
                Err(cleanup) => Err(HarnessError::Process(format!(
                    "{error}; I08 partial harness cleanup failed: {cleanup}"
                ))),
            };
        }
        Err(_) => {
            let error =
                HarnessError::Timeout("I08 partial production cluster startup timed out".into());
            let cleanup_at = Instant::now() + CLEANUP_TIMEOUT;
            return match harness
                .shutdown_until(tokio::time::Instant::from_std(cleanup_at))
                .await
            {
                Ok(()) => Err(error),
                Err(cleanup) => Err(HarnessError::Process(format!(
                    "{error}; I08 partial harness cleanup failed: {cleanup}"
                ))),
            };
        }
    };
    let deadline = Instant::now() + I08_PARTIAL_SCENARIO_TIMEOUT.min(SCENARIO_TIMEOUT);
    let scenario = drive_partial_scenario(&mut cluster, &harness, deadline).await;
    let cleanup_at = Instant::now() + CLEANUP_TIMEOUT;
    let cluster_cleanup = shutdown_cluster_until(cluster, cleanup_at).await;
    let harness_cleanup = harness
        .shutdown_until(tokio::time::Instant::from_std(cleanup_at))
        .await;
    let mut cleanup_errors = Vec::new();
    if let Err(error) = cluster_cleanup {
        cleanup_errors.push(format!("relay cleanup failed: {error}"));
    }
    if let Err(error) = harness_cleanup {
        cleanup_errors.push(format!("Redis cleanup failed: {error}"));
    }
    match scenario {
        Err(error) if cleanup_errors.is_empty() => Err(error),
        Err(error) => Err(HarnessError::Process(format!(
            "{error}; {}",
            cleanup_errors.join("; ")
        ))),
        Ok(_) if !cleanup_errors.is_empty() => {
            Err(HarnessError::Process(cleanup_errors.join("; ")))
        }
        Ok(evidence) => {
            validate_i08_partial_response_evidence(&evidence)?;
            Ok(evidence)
        }
    }
}

#[cfg(test)]
mod envelope_and_evidence_tests {
    use super::*;
    use crate::acceptance_test_support::assert_rejected;

    type CountMutation = (&'static str, fn(&mut I08Evidence));

    fn valid_evidence() -> I08Evidence {
        let rotations = (1..=ROTATION_COUNT)
            .map(|rotation| {
                let old_connection_id = if rotation == 1 {
                    "connection-0".to_owned()
                } else {
                    format!("connection-{}", rotation)
                };
                let new_connection_id = format!("connection-{}", rotation + 1);
                I08RotationEvidence {
                    rotation,
                    attempt: RotationAttemptIdentity::new(
                        "session",
                        1,
                        "owner",
                        format!("rotation-{rotation}"),
                        rotation,
                        rotation + 1,
                        old_connection_id,
                        new_connection_id.clone(),
                    ),
                    active_generation: rotation + 1,
                    active_connection_id: new_connection_id,
                    snapshot_id: format!("snapshot-{rotation}"),
                    completed_latch_observed: true,
                    relay_fence_digest: format!("relay-fence-{rotation}"),
                    connector_fence_digest: format!("connector-fence-{rotation}"),
                    relay_fence_sequence: rotation,
                    connector_fence_sequence: rotation,
                    relay_ack_sequence: rotation,
                    connector_ack_sequence: rotation,
                    writer_barrier_flushed: [true, true],
                    candidate_ready: true,
                    commit_sent: true,
                    commit_accepted: true,
                    old_socket_closed: true,
                    runtime_socket_high_water: 2,
                    replay_frames: 0,
                }
            })
            .collect();
        I08Evidence {
            scope: "synthetic_echo_mapping_only",
            relay_count: 3,
            public_ingress_relay: "relay-c".to_owned(),
            owner_relay: "relay-a".to_owned(),
            actual_cli_process: true,
            public_ingress: true,
            control_identity_stable: true,
            session_id: "session".to_owned(),
            epoch: 1,
            stream_id: 1,
            tunnel_operation_id: "operation".to_owned(),
            synthetic_fid: I08_FID,
            synthetic_operation_id: I08_SYNTHETIC_OPERATION.to_owned(),
            records_sent: ROTATION_COUNT as usize + 1,
            records_echoed: ROTATION_COUNT as usize + 1,
            checksums_verified: ROTATION_COUNT as usize + 1,
            rotations,
            socket_high_water: 2,
            replay_frames: 0,
            cleanup_joined: true,
            elapsed_ms: 1,
        }
    }

    #[test]
    fn i08_synthetic_envelope_round_trips_the_returned_bytes() {
        let record = SyntheticRecord::new(0);
        let encoded = record.encode();
        record
            .verify_encoded(&encoded)
            .expect("encoded synthetic envelope should parse exactly");
    }

    #[test]
    fn i08_synthetic_envelope_rejects_checksum_and_body_corruption() {
        let record = SyntheticRecord::new(1);
        let mut checksum_corrupt = record.encode();
        let last = checksum_corrupt
            .len()
            .checked_sub(1)
            .expect("encoded envelope has a checksum");
        checksum_corrupt[last] ^= 0x01;
        assert!(record.verify_encoded(&checksum_corrupt).is_err());

        let mut body_corrupt = record.encode();
        let body_offset = I08_MAGIC.len() + 8 + 1 + I08_SYNTHETIC_OPERATION.len() + 8 + 4;
        body_corrupt[body_offset] ^= 0x01;
        assert!(record.verify_encoded(&body_corrupt).is_err());
    }

    #[test]
    fn i08_synthetic_envelope_rejects_truncated_length_and_checksum() {
        let record = SyntheticRecord::new(2);
        let encoded = record.encode();
        let body_length_end = I08_MAGIC.len() + 8 + 1 + I08_SYNTHETIC_OPERATION.len() + 8 + 4;
        let mut truncated_length = encoded.clone();
        truncated_length.truncate(body_length_end - 1);
        assert!(record.verify_encoded(&truncated_length).is_err());

        let mut truncated_checksum = encoded;
        truncated_checksum.pop();
        assert!(record.verify_encoded(&truncated_checksum).is_err());
    }

    #[test]
    fn i08_synthetic_envelope_rejects_identity_sequence_and_operation_changes() {
        let record = SyntheticRecord::new(3);
        let encoded = record.encode();
        let operation_offset = I08_MAGIC.len() + 8 + 1;
        let sequence_offset = operation_offset + I08_SYNTHETIC_OPERATION.len();

        let mut wrong_fid = encoded.clone();
        wrong_fid[I08_MAGIC.len()] ^= 0x01;
        assert!(record.verify_encoded(&wrong_fid).is_err());

        let mut wrong_operation = encoded.clone();
        wrong_operation[operation_offset] ^= 0x01;
        assert!(record.verify_encoded(&wrong_operation).is_err());

        let mut wrong_sequence = encoded;
        wrong_sequence[sequence_offset + 7] ^= 0x01;
        assert!(record.verify_encoded(&wrong_sequence).is_err());
    }

    #[test]
    fn i08_synthetic_envelope_rejects_trailing_bytes() {
        let record = SyntheticRecord::new(4);
        let mut encoded = record.encode();
        encoded.push(0);
        assert!(record.verify_encoded(&encoded).is_err());
    }

    #[test]
    fn i08_evidence_rejects_missing_attempt_closure_or_exact_fence_ack() {
        let mut missing_attempt = valid_evidence();
        missing_attempt.rotations[0].attempt.rotation_id.clear();
        assert_rejected(validate_i08_evidence(&missing_attempt), "M7-I08");

        let mut missing_closure = valid_evidence();
        missing_closure.rotations[1].completed_latch_observed = false;
        assert_rejected(validate_i08_evidence(&missing_closure), "M7-I08");

        let mut mismatched_ack = valid_evidence();
        mismatched_ack.rotations[2].connector_ack_sequence += 1;
        assert_rejected(validate_i08_evidence(&mismatched_ack), "M7-I08");
    }

    #[test]
    fn every_i08_flag_and_count_reaches_the_shared_exit_path() {
        type Disable = (&'static str, fn(&mut I08Evidence));
        let top_level: [Disable; 4] = [
            ("actual_cli_process", |e| e.actual_cli_process = false),
            ("public_ingress", |e| e.public_ingress = false),
            ("control_identity_stable", |e| {
                e.control_identity_stable = false
            }),
            ("cleanup_joined", |e| e.cleanup_joined = false),
        ];
        for (name, disable) in top_level {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_rejected(validate_i08_evidence(&evidence), name);
        }

        type RotationDisable = (&'static str, fn(&mut I08RotationEvidence));
        let rotation_flags: [RotationDisable; 8] = [
            ("completed_latch_observed", |r| {
                r.completed_latch_observed = false
            }),
            ("writer_barrier_flushed", |r| {
                r.writer_barrier_flushed[0] = false
            }),
            ("candidate_ready", |r| r.candidate_ready = false),
            ("commit_sent", |r| r.commit_sent = false),
            ("commit_accepted", |r| r.commit_accepted = false),
            ("old_socket_closed", |r| r.old_socket_closed = false),
            ("rotation_replay_frames", |r| r.replay_frames = 1),
            ("relay_fence_digest", |r| r.relay_fence_digest.clear()),
        ];
        for (_, disable) in rotation_flags {
            let mut evidence = valid_evidence();
            disable(&mut evidence.rotations[0]);
            assert_rejected(validate_i08_evidence(&evidence), "M7-I08");
        }

        let mut missing_epoch = valid_evidence();
        missing_epoch.epoch = 0;
        assert_rejected(validate_i08_evidence(&missing_epoch), "M7-I08");

        let mut missing_rotation = valid_evidence();
        missing_rotation.rotations[0].rotation = 0;
        assert_rejected(validate_i08_evidence(&missing_rotation), "M7-I08");

        let mut missing_generation = valid_evidence();
        missing_generation.rotations[0].active_generation = 0;
        assert_rejected(validate_i08_evidence(&missing_generation), "M7-I08");

        let mut missing_attempt_generation = valid_evidence();
        missing_attempt_generation.rotations[0]
            .attempt
            .old_generation = missing_attempt_generation.rotations[0]
            .attempt
            .new_generation;
        assert_rejected(validate_i08_evidence(&missing_attempt_generation), "M7-I08");

        let mut missing_fence_sequence = valid_evidence();
        missing_fence_sequence.rotations[0].relay_fence_sequence = 0;
        assert_rejected(validate_i08_evidence(&missing_fence_sequence), "M7-I08");

        let count_cases: [CountMutation; 7] = [
            ("relay_count", |e: &mut I08Evidence| e.relay_count = 2),
            ("records_sent", |e: &mut I08Evidence| e.records_sent = 0),
            ("records_echoed", |e: &mut I08Evidence| e.records_echoed = 0),
            ("checksums_verified", |e: &mut I08Evidence| {
                e.checksums_verified = 0
            }),
            ("rotations", |e: &mut I08Evidence| e.rotations.truncate(1)),
            ("socket_high_water", |e: &mut I08Evidence| {
                e.socket_high_water = 1
            }),
            ("replay_frames", |e: &mut I08Evidence| e.replay_frames = 1),
        ];
        for (name, mutate) in count_cases {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(validate_i08_evidence(&evidence), "M7-I08");
            let _ = name;
        }
    }

    #[test]
    fn i08_refresh_keeps_stream_identity_while_ready_waits_for_completion() {
        let session = RelaySessionSnapshot {
            streams: vec![RelayStreamSnapshot {
                stream_id: 7,
                operation_id: "operation".to_owned(),
                authorization_in_flight: true,
                authorization_started_at_ms: Some(10),
                authorization_deadline_ms: Some(100),
                authorization_admission_deadline_ms: Some(9),
                ..Default::default()
            }],
            ..Default::default()
        };

        let observed = exactly_one_nonterminal_stream(&session)
            .expect("refresh snapshot should be structurally valid")
            .expect("refresh must retain the nonterminal stream");
        assert_eq!(observed.stream_id, 7);
        assert_eq!(observed.operation_id, "operation");
        assert!(observed.authorization_in_flight);
        assert!(
            exactly_one_nonterminal_admitted_stream(&session)
                .expect("refresh snapshot should be structurally valid")
                .is_none()
        );

        let mut completed = session;
        completed.streams[0].authorization_in_flight = false;
        let admitted = exactly_one_nonterminal_admitted_stream(&completed)
            .expect("completed refresh snapshot should be structurally valid")
            .expect("completed refresh should expose the same admitted stream");
        assert_eq!(admitted.stream_id, 7);
        assert_eq!(admitted.operation_id, "operation");
    }

    fn valid_partial_evidence() -> I08PartialResponseEvidence {
        let rotations = (1..=ROTATION_COUNT)
            .map(|rotation| {
                let old_connection_id = if rotation == 1 {
                    "connection-0".to_owned()
                } else {
                    format!("connection-{rotation}")
                };
                let new_connection_id = format!("connection-{}", rotation + 1);
                I08RotationEvidence {
                    rotation,
                    attempt: RotationAttemptIdentity::new(
                        "session",
                        1,
                        "owner",
                        format!("rotation-{rotation}"),
                        rotation,
                        rotation + 1,
                        old_connection_id,
                        new_connection_id.clone(),
                    ),
                    active_generation: rotation + 1,
                    active_connection_id: new_connection_id,
                    snapshot_id: format!("snapshot-{rotation}"),
                    completed_latch_observed: true,
                    relay_fence_digest: format!("relay-fence-{rotation}"),
                    connector_fence_digest: format!("connector-fence-{rotation}"),
                    relay_fence_sequence: rotation,
                    connector_fence_sequence: rotation,
                    relay_ack_sequence: rotation,
                    connector_ack_sequence: rotation,
                    writer_barrier_flushed: [true, true],
                    candidate_ready: true,
                    commit_sent: true,
                    commit_accepted: true,
                    old_socket_closed: true,
                    runtime_socket_high_water: 2,
                    replay_frames: 0,
                }
            })
            .collect();
        let response_record_bytes = 43 + I08_PARTIAL_RECORD_BYTES;
        I08PartialResponseEvidence {
            scope: "synthetic_echo_mapping_only",
            relay_count: 3,
            session_id: "session".to_owned(),
            epoch: 1,
            stream_id: 1,
            tunnel_operation_id: "operation".to_owned(),
            synthetic_fid: I08_FID,
            synthetic_operation_id: I08_SYNTHETIC_OPERATION.to_owned(),
            request_record_bytes: I08_PARTIAL_RECORD_BYTES,
            response_record_bytes,
            response_frames: response_record_bytes.div_ceil(tunnel_protocol::MAX_PAYLOAD_LEN),
            resume_unit: I08_RESUME_UNIT.to_owned(),
            byte_cursor_resume_supported: false,
            responses_delivered: 64,
            responses_checksum_matched: 64,
            responses_multi_chunk: 64,
            responses_bracketing_commit: 3,
            partial_resume_offsets: vec![tunnel_protocol::MAX_PAYLOAD_LEN; 3],
            cursor_gaps: 0,
            duplicated_bytes: 0,
            rotations_retaining_replay: 0,
            rotations,
            adapter_shutdown_phase: "draining".to_owned(),
            adapter_shutdown_in_overlap: true,
            adapter_shutdown_graceful: true,
            post_shutdown_outcome: "closed_before_response".to_owned(),
            socket_high_water: 3,
            cleanup_joined: true,
            elapsed_ms: 12_000,
        }
    }

    #[test]
    fn i08_partial_validator_accepts_complete_evidence() {
        validate_i08_partial_response_evidence(&valid_partial_evidence())
            .expect("complete I08 partial evidence is valid");
        // A recorded mid-response resume offset is an observation, not a
        // failure: only its shape is enforced.
        let mut observed = valid_partial_evidence();
        observed.partial_resume_offsets = vec![1, observed.response_record_bytes - 1];
        validate_i08_partial_response_evidence(&observed)
            .expect("in-range resume offsets stay valid evidence");
    }

    #[test]
    fn i08_partial_record_encodes_to_the_maximum_record_size() {
        let record = SyntheticRecord::sized(7, I08_PARTIAL_RECORD_BYTES)
            .expect("maximum record size is above the envelope overhead");
        let wire = record.encode();
        assert_eq!(wire.len(), I08_PARTIAL_RECORD_BYTES);
        record
            .verify_encoded(&wire)
            .expect("the sized envelope re-parses");
        // The echoed response is canary + record, so it must exceed one
        // tunnel DATA frame.
        const { assert!(1 + I08_PARTIAL_RECORD_BYTES > tunnel_protocol::MAX_PAYLOAD_LEN) };
        assert!(SyntheticRecord::sized(7, I08_ENVELOPE_OVERHEAD - 1).is_err());
        // A different sequence must produce a different body, so a response
        // delivered for the wrong request cannot compare equal.
        let other = SyntheticRecord::sized(8, I08_PARTIAL_RECORD_BYTES)
            .expect("maximum record size is above the envelope overhead");
        assert_ne!(other.encode(), wire);
        assert!(record.verify_encoded(&other.encode()).is_err());
    }

    #[test]
    fn every_i08_partial_condition_names_its_rejection() {
        use crate::acceptance_test_support::assert_failed;

        const IDENTITY: &str = "stable session/stream/operation identity";
        const MULTI_FRAME: &str = "was not a multi-frame response";
        const RESUME: &str = "instead of the implemented frame-sequence resume";
        const CHECKSUM: &str = "match its independent checksum";
        const DRAIN: &str = "did not prove a whole-frame drain to its fence";
        const OVERLAP: &str = "was not requested inside the rotation overlap";
        type Case = (
            &'static str,
            &'static str,
            fn(&mut I08PartialResponseEvidence),
        );
        let cases: &[Case] = &[
            ("scope", "unexpected scope", |e| e.scope = "widened_scope"),
            ("relay_count", "three production relays", |e| {
                e.relay_count = 2
            }),
            ("session_id_empty", IDENTITY, |e| e.session_id.clear()),
            ("stream_id_zero", IDENTITY, |e| e.stream_id = 0),
            ("operation_id_empty", IDENTITY, |e| {
                e.tunnel_operation_id.clear()
            }),
            ("synthetic_fid", IDENTITY, |e| e.synthetic_fid = I08_FID + 1),
            ("request_below_maximum", "maximum record", |e| {
                e.request_record_bytes -= 1
            }),
            ("response_fits_one_frame", MULTI_FRAME, |e| {
                e.response_record_bytes = tunnel_protocol::MAX_PAYLOAD_LEN;
                e.response_frames = 1;
            }),
            ("response_frame_count_inconsistent", MULTI_FRAME, |e| {
                e.response_frames = 3
            }),
            ("resume_unit_claims_byte_offset", RESUME, |e| {
                e.resume_unit = "byte_offset".to_owned()
            }),
            ("byte_cursor_resume_claimed", RESUME, |e| {
                e.byte_cursor_resume_supported = true
            }),
            ("no_responses", CHECKSUM, |e| {
                e.responses_delivered = 0;
                e.responses_checksum_matched = 0;
            }),
            ("checksum_mismatch", CHECKSUM, |e| {
                e.responses_checksum_matched -= 1
            }),
            (
                "never_incremental",
                "never observed an incrementally delivered response",
                |e| e.responses_multi_chunk = 0,
            ),
            (
                "never_bracketed_a_commit",
                "never bracketed a committed rotation",
                |e| e.responses_bracketing_commit = 0,
            ),
            (
                "never_partly_delivered_at_the_commit",
                "still incomplete when the replacement generation became active",
                |e| e.partial_resume_offsets.clear(),
            ),
            (
                "resume_offset_at_zero",
                "outside the partly delivered range",
                |e| e.partial_resume_offsets = vec![0],
            ),
            (
                "resume_offset_past_response",
                "outside the partly delivered range",
                |e| e.partial_resume_offsets = vec![e.response_record_bytes + 4],
            ),
            ("cursor_gap", "cursor_gaps=1", |e| e.cursor_gaps = 1),
            ("duplicated_bytes", "duplicated_bytes=4", |e| {
                e.duplicated_bytes = 4
            }),
            ("missing_rotation_proof", "rotation proofs", |e| {
                e.rotations.pop();
            }),
            (
                "retained_replay_count_overstated",
                "rotations retaining replay but its rotation proofs show",
                |e| e.rotations_retaining_replay += 1,
            ),
            (
                "retained_replay_count_understated",
                "rotations retaining replay but its rotation proofs show",
                |e| e.rotations[0].replay_frames = 2,
            ),
            ("relay_ack_below_fence", DRAIN, |e| {
                e.rotations[1].relay_ack_sequence += 1
            }),
            ("connector_ack_below_fence", DRAIN, |e| {
                e.rotations[2].connector_ack_sequence += 1
            }),
            ("generation_not_monotonic", DRAIN, |e| {
                e.rotations[1].active_generation = e.rotations[0].active_generation
            }),
            ("commit_not_accepted", DRAIN, |e| {
                e.rotations[0].commit_accepted = false
            }),
            ("old_socket_left_open", DRAIN, |e| {
                e.rotations[2].old_socket_closed = false
            }),
            ("shutdown_outside_overlap", OVERLAP, |e| {
                e.adapter_shutdown_phase = "active".to_owned()
            }),
            ("shutdown_overlap_not_claimed", OVERLAP, |e| {
                e.adapter_shutdown_in_overlap = false
            }),
            (
                "shutdown_not_graceful",
                "did not complete gracefully",
                |e| e.adapter_shutdown_graceful = false,
            ),
            (
                "unclassified_post_shutdown_outcome",
                "unclassified post-shutdown outcome",
                |e| e.post_shutdown_outcome = "something_else".to_owned(),
            ),
            (
                "socket_high_water_over_bound",
                "outside the bounded 2..=3 shape",
                |e| e.socket_high_water = 4,
            ),
            ("cleanup_not_joined", "cleanup_joined", |e| {
                e.cleanup_joined = false
            }),
        ];
        for &(name, fragment, mutate) in cases {
            let mut evidence = valid_partial_evidence();
            mutate(&mut evidence);
            let diagnostic = assert_failed(validate_i08_partial_response_evidence(&evidence));
            assert!(
                diagnostic.contains(fragment),
                "{name}: expected {fragment:?} in diagnostic {diagnostic}"
            );
        }
    }

    #[test]
    fn i08_validator_accepts_complete_evidence() {
        validate_i08_evidence(&valid_evidence()).expect("complete I08 evidence is valid");
    }

    #[test]
    fn every_i08_identity_bound_and_rotation_chain_condition_names_its_rejection() {
        use crate::acceptance_test_support::assert_failed;

        const IDENTITY: &str = "stable session/stream/operation identity";
        const CHAIN: &str = "immutable fence/ACK identity";
        type Case = (&'static str, &'static str, fn(&mut I08Evidence));
        let cases: &[Case] = &[
            ("scope", "unexpected scope", |e| e.scope = "widened_scope"),
            ("session_id_empty", IDENTITY, |e| e.session_id.clear()),
            ("stream_id_zero", IDENTITY, |e| e.stream_id = 0),
            ("tunnel_operation_id_empty", IDENTITY, |e| {
                e.tunnel_operation_id.clear()
            }),
            ("synthetic_operation_id", IDENTITY, |e| {
                e.synthetic_operation_id = "synthetic.other.v1".to_owned()
            }),
            ("synthetic_fid", IDENTITY, |e| e.synthetic_fid = I08_FID + 1),
            (
                "records_echoed_mismatch",
                "echoed checksummed records",
                |e| e.records_echoed += 1,
            ),
            (
                "checksums_verified_mismatch",
                "echoed checksummed records",
                |e| e.checksums_verified += 1,
            ),
            ("rotations_extra_proof", "rotation proofs", |e| {
                let extra = e.rotations[2].clone();
                e.rotations.push(extra);
            }),
            (
                "socket_high_water_over_bound",
                "outside the bounded 2..=3 shape",
                |e| e.socket_high_water = 4,
            ),
            ("rotation_snapshot_id_empty", CHAIN, |e| {
                e.rotations[0].snapshot_id.clear()
            }),
            ("rotation_connector_fence_digest_empty", CHAIN, |e| {
                e.rotations[1].connector_fence_digest.clear()
            }),
            ("rotation_relay_ack_mismatch", CHAIN, |e| {
                e.rotations[1].relay_ack_sequence += 1
            }),
            ("rotation_connector_fence_sequence_mismatch", CHAIN, |e| {
                e.rotations[2].connector_fence_sequence += 1
            }),
            ("attempt_session_mismatch", CHAIN, |e| {
                e.rotations[0].attempt.session_id = "other-session".to_owned()
            }),
            ("attempt_epoch_mismatch", CHAIN, |e| {
                e.rotations[0].attempt.epoch += 1
            }),
            ("attempt_owner_id_empty", CHAIN, |e| {
                e.rotations[0].attempt.owner_id.clear()
            }),
            ("attempt_new_generation_mismatch", CHAIN, |e| {
                e.rotations[0].attempt.new_generation += 1
            }),
            ("attempt_new_connection_mismatch", CHAIN, |e| {
                e.rotations[0].attempt.new_connection_id = "connection-other".to_owned()
            }),
            ("attempt_old_connection_empty", CHAIN, |e| {
                e.rotations[0].attempt.old_connection_id.clear()
            }),
            ("attempt_old_equals_new_connection", CHAIN, |e| {
                let new_connection_id = e.rotations[0].attempt.new_connection_id.clone();
                e.rotations[0].attempt.old_connection_id = new_connection_id;
            }),
            ("active_connection_reused", CHAIN, |e| {
                let previous = e.rotations[0].active_connection_id.clone();
                e.rotations[1].attempt.new_connection_id = previous.clone();
                e.rotations[1].active_connection_id = previous;
            }),
            ("active_generation_not_monotonic", CHAIN, |e| {
                let previous = e.rotations[0].active_generation;
                e.rotations[1].attempt.new_generation = previous;
                e.rotations[1].active_generation = previous;
            }),
            ("generation_chain_break", CHAIN, |e| {
                e.rotations[1].attempt.old_generation = 1
            }),
            ("connection_chain_break", CHAIN, |e| {
                e.rotations[1].attempt.old_connection_id = "connection-stale".to_owned()
            }),
            (
                "later_rotation_second_writer_barrier",
                "omitted writer_barrier_flushed",
                |e| e.rotations[2].writer_barrier_flushed[1] = false,
            ),
            (
                "later_rotation_candidate_ready",
                "omitted candidate_ready",
                |e| e.rotations[2].candidate_ready = false,
            ),
            (
                "later_rotation_replay_frames",
                "observed 1 replay frames",
                |e| e.rotations[2].replay_frames = 1,
            ),
        ];
        for &(name, fragment, mutate) in cases {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            let diagnostic = assert_failed(validate_i08_evidence(&evidence));
            assert!(
                diagnostic.contains(fragment),
                "{name}: expected {fragment:?} in diagnostic {diagnostic}"
            );
        }
    }
}
