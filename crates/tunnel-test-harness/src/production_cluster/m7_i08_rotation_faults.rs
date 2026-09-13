//! M7-I08/EC057/IN09 planned-retirement and active-carrier fault fixture.
//!
//! The fixture uses one real three-relay cluster and one real `tunnel-client`
//! process.  The first two scheduled generations prove the planned successor
//! path (including the relay's immutable fence/close latch) while the same
//! process remains ready.  It then shuts down the exact relay selected for
//! the active data carrier and observes either same-session retained recovery
//! or the client's typed terminal diagnostic.  The status stream also exposes
//! the existing bounded in-session recovery attempt/timestamp/reset metadata;
//! there is deliberately no whole-session reconnect assertion because M2 has
//! no automatic control reconnect.
//! GOAWAY is a separate scope and is reported as such rather than inferred
//! from this active-carrier fault.

use chrono::Utc;
use std::{
    fs,
    net::SocketAddr,
    time::{Duration, Instant},
};
use tempfile::tempdir;
use tokio::time::{sleep, timeout_at};
use tunnel_protocol::rotation::recovery_retry_delay_ms;
use tunnel_relay::{RelaySessionSnapshot, RelaySnapshot};
use uuid::Uuid;

use crate::{
    FanoutProxyDiagnostics, Harness, HarnessError, HarnessOptions, ManagedProcess,
    OidcTokenOptions, Result, RunningHarness,
};

use super::{
    CLEANUP_TIMEOUT, ConsumerStream, ProductionCluster, ROTATION, SCENARIO_TIMEOUT,
    STARTUP_TIMEOUT, start_cli_smoke,
};

const PLANNED_ROTATION_COUNT: u64 = 2;
pub(super) const POLL: Duration = Duration::from_millis(50);
pub(super) const PROCESS_GRACE: Duration = Duration::from_secs(5);
const FAULT_RECOVERY_TIMEOUT: Duration = Duration::from_secs(35);

/// Payload-free evidence for the planned and unexpected active-carrier paths.
/// The identifiers are the authenticated tunnel/runtime correlation values;
/// no application payload or credential is retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct I08RotationFaultEvidence {
    pub scope: &'static str,
    pub relay_count: usize,
    pub actual_cli_process: bool,
    pub planned_retirement_verified: bool,
    pub planned_rotations: u64,
    pub planned_fence_acknowledged: bool,
    pub planned_old_carrier_closed: bool,
    pub planned_process_stayed_alive: bool,
    pub planned_no_whole_session_retry: bool,
    /// Planned retirement must leave the retained-recovery metadata empty;
    /// planned rotation is not a failed carrier attempt.
    pub planned_recovery_diagnostics_clean: bool,
    pub session_id: String,
    pub epoch: u64,
    pub stream_id: u64,
    pub tunnel_operation_id: String,
    pub planned_generation: u64,
    pub planned_connection_id: String,
    pub unexpected_fault_relay: String,
    pub unexpected_fault_route_index: u64,
    pub unexpected_fault_generation: u64,
    pub unexpected_fault_connection_id: String,
    pub unexpected_active_carrier_closed: bool,
    /// The control route stayed on relay-a while the selected data route died.
    /// Without this correlation a session disappearance could be a control
    /// failure rather than evidence about the active data carrier.
    pub control_route_remained_open: bool,
    pub unexpected_outcome: &'static str,
    pub unexpected_failure_code: Option<&'static str>,
    pub unexpected_failure_retryable: Option<bool>,
    pub unexpected_failure_trigger: Option<&'static str>,
    /// A same-session active result is only recovery evidence when its exact
    /// successor attempt is bound to the carrier that faulted.
    pub unexpected_recovery_successor_verified: bool,
    /// The recovery successor also needs the relay/connector fence and close
    /// acknowledgements that make the result safe to treat as a planned path.
    pub unexpected_recovery_fence_acknowledged: bool,
    /// Bounded in-session recovery metadata emitted by the real CLI after
    /// the active carrier fault.  The values contain attempt/identity and
    /// actor-clock policy-deadline metadata only; application payloads are
    /// never retained.
    pub unexpected_recovery_attempts: Vec<u64>,
    /// Actor-clock starts/deadlines observed for each status event.  These
    /// are policy-linked timestamps, not a copied retry-delay table.
    pub unexpected_recovery_attempt_starts_ms: Vec<u64>,
    pub unexpected_recovery_attempt_deadlines_ms: Vec<u64>,
    /// One immutable episode cap observed across every retry status.
    pub unexpected_recovery_episode_deadline_ms: Option<u64>,
    /// Exact connector closure rosters observed for each recovery attempt.
    /// Later retries attest only their newly released candidate; older IDs
    /// remain local fences and are not repeated on the bounded wire record.
    pub unexpected_recovery_closed_connection_ids: Vec<Vec<String>>,
    /// Candidate identity proposed by each observed attempt, used to bind the
    /// next attempt's closure roster to the candidate that actually failed.
    pub unexpected_recovery_successor_connection_ids: Vec<Option<String>>,
    pub unexpected_recovery_reset_reason: Option<&'static str>,
    pub unexpected_recovery_old_generation: Option<u64>,
    pub unexpected_recovery_old_connection_id: Option<String>,
    pub unexpected_recovery_successor_generation: Option<u64>,
    pub unexpected_recovery_successor_connection_id: Option<String>,
    /// A retained carrier recovery keeps the authenticated session process;
    /// a terminal data fault must not silently spawn a replacement session.
    pub unexpected_no_whole_session_retry: bool,
    pub same_session_recovered: bool,
    pub recovered_generation: Option<u64>,
    pub recovered_connection_id: Option<String>,
    pub control_socket_stable: bool,
    pub stream_identity_stable: bool,
    pub post_fault_owner_snapshot_observed: bool,
    pub post_fault_session_terminal_observed: bool,
    pub post_fault_live_session_absent: bool,
    pub post_fault_stream_state_observed: bool,
    pub post_fault_catalog_owner_released: bool,
    pub control_route_observed_after_fault: bool,
    pub control_route_open_after_observation: bool,
    pub pre_fault_dispatch_count: u64,
    pub post_fault_dispatch_count: u64,
    pub post_fault_dispatch_delta: u64,
    pub ordered_records: usize,
    /// M2 intentionally has no automatic control/session reconnect policy.
    pub goaway_tested: bool,
    pub goaway_is_separate_scope: bool,
    pub cleanup_joined: bool,
    pub elapsed_ms: u64,
}

/// Validate that a run proved both sides of the scope without treating a
/// generic process exit or a planned retirement as an unexpected fault.
pub fn validate_i08_rotation_fault_evidence(evidence: &I08RotationFaultEvidence) -> Result<()> {
    if evidence.scope != "planned_retirement_and_active_carrier_fault" {
        return Err(HarnessError::Process(format!(
            "M7-I08 rotation fault evidence has unexpected scope {:?}",
            evidence.scope
        )));
    }
    if evidence.relay_count != 3 || !evidence.actual_cli_process {
        return Err(HarnessError::Process(
            "M7-I08 rotation fault fixture did not use three relays and a real CLI".into(),
        ));
    }
    let required = [
        (
            "planned_retirement_verified",
            evidence.planned_retirement_verified,
        ),
        (
            "planned_fence_acknowledged",
            evidence.planned_fence_acknowledged,
        ),
        (
            "planned_old_carrier_closed",
            evidence.planned_old_carrier_closed,
        ),
        (
            "planned_process_stayed_alive",
            evidence.planned_process_stayed_alive,
        ),
        (
            "planned_no_whole_session_retry",
            evidence.planned_no_whole_session_retry,
        ),
        (
            "planned_recovery_diagnostics_clean",
            evidence.planned_recovery_diagnostics_clean,
        ),
        (
            "unexpected_active_carrier_closed",
            evidence.unexpected_active_carrier_closed,
        ),
        (
            "control_route_remained_open",
            evidence.control_route_remained_open,
        ),
        ("control_socket_stable", evidence.control_socket_stable),
        (
            "post_fault_owner_snapshot_observed",
            evidence.post_fault_owner_snapshot_observed,
        ),
        (
            "post_fault_stream_state_observed",
            evidence.post_fault_stream_state_observed,
        ),
        (
            "control_route_observed_after_fault",
            evidence.control_route_observed_after_fault,
        ),
        (
            "goaway_is_separate_scope",
            evidence.goaway_is_separate_scope,
        ),
        ("cleanup_joined", evidence.cleanup_joined),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, value)| !value) {
        return Err(HarnessError::Process(format!(
            "M7-I08 rotation fault evidence is incomplete: {name}"
        )));
    }
    if evidence.goaway_tested {
        return Err(HarnessError::Process(
            "M7-I08 rotation fault fixture must keep GOAWAY as a separate case".into(),
        ));
    }
    if evidence.planned_rotations != PLANNED_ROTATION_COUNT
        || evidence.session_id.is_empty()
        || evidence.epoch == 0
        || evidence.stream_id == 0
        || evidence.tunnel_operation_id.is_empty()
        || evidence.planned_generation <= 1
        || evidence.planned_connection_id.is_empty()
        || evidence.unexpected_fault_relay.is_empty()
        || evidence.unexpected_fault_route_index != 3
        || evidence.unexpected_fault_generation == 0
        || evidence.unexpected_fault_connection_id.is_empty()
        || evidence.unexpected_fault_generation != evidence.planned_generation
        || evidence.unexpected_fault_connection_id != evidence.planned_connection_id
        || evidence.pre_fault_dispatch_count == 0
        || evidence.ordered_records < PLANNED_ROTATION_COUNT as usize + 1
        || evidence.unexpected_recovery_attempts.len() > 3
        || evidence.unexpected_recovery_attempt_starts_ms.len()
            != evidence.unexpected_recovery_attempts.len()
        || evidence.unexpected_recovery_attempt_deadlines_ms.len()
            != evidence.unexpected_recovery_attempts.len()
        || evidence.unexpected_recovery_closed_connection_ids.len()
            != evidence.unexpected_recovery_attempts.len()
        || evidence.unexpected_recovery_successor_connection_ids.len()
            != evidence.unexpected_recovery_attempts.len()
        || (!evidence.unexpected_recovery_attempts.is_empty()
            && evidence.unexpected_recovery_episode_deadline_ms.is_none())
        || !evidence.unexpected_no_whole_session_retry
    {
        return Err(HarnessError::Process(
            "M7-I08 rotation fault evidence omitted a stable identity or ordered record".into(),
        ));
    }
    if evidence
        .unexpected_recovery_attempts
        .windows(2)
        .any(|window| window[0] >= window[1])
    {
        return Err(HarnessError::Process(
            "unexpected carrier recovery attempt observations were not monotonic".into(),
        ));
    }
    if evidence
        .unexpected_recovery_attempt_starts_ms
        .windows(2)
        .zip(evidence.unexpected_recovery_attempt_deadlines_ms.windows(2))
        .any(|(starts, deadlines)| {
            starts[0] >= starts[1] || deadlines[0] <= starts[0] || deadlines[1] <= starts[1]
        })
    {
        return Err(HarnessError::Process(
            "unexpected carrier recovery attempt timestamps were not monotonic and bounded".into(),
        ));
    }
    if let Some(episode_deadline_ms) = evidence.unexpected_recovery_episode_deadline_ms
        && evidence
            .unexpected_recovery_attempt_deadlines_ms
            .iter()
            .any(|attempt_deadline_ms| *attempt_deadline_ms > episode_deadline_ms)
    {
        return Err(HarnessError::Process(
            "unexpected carrier recovery attempt exceeded its immutable episode deadline".into(),
        ));
    }
    if evidence
        .unexpected_recovery_attempt_starts_ms
        .iter()
        .zip(&evidence.unexpected_recovery_attempt_deadlines_ms)
        .any(|(started, deadline)| deadline <= started)
    {
        return Err(HarnessError::Process(
            "unexpected carrier recovery reported an invalid attempt deadline".into(),
        ));
    }
    for ((attempts, starts), deadlines) in evidence
        .unexpected_recovery_attempts
        .windows(2)
        .zip(evidence.unexpected_recovery_attempt_starts_ms.windows(2))
        .zip(evidence.unexpected_recovery_attempt_deadlines_ms.windows(2))
    {
        // A watch stream may skip an intermediate attempt.  Sum the shared
        // protocol delays for every completed attempt represented by the
        // observed number gap, so coalescing cannot hide an early retry.
        let Some(required_delay_ms) =
            (attempts[0]..attempts[1]).try_fold(0_u64, |total, completed_attempt| {
                total.checked_add(recovery_retry_delay_ms(completed_attempt)?)
            })
        else {
            return Err(HarnessError::Process(
                "unexpected carrier recovery used an out-of-range retry attempt".into(),
            ));
        };
        if starts[1].saturating_sub(starts[0]) < required_delay_ms {
            return Err(HarnessError::Process(
                "recovery retry started before its protocol backoff elapsed".into(),
            ));
        }
        // Only require the preceding attempt's deadline for an actually
        // adjacent observation; each observed attempt is still checked
        // against its own deadline.
        if attempts[1] == attempts[0].saturating_add(1) && starts[1] > deadlines[0] {
            return Err(HarnessError::Process(
                "adjacent recovery attempt started after its predecessor deadline".into(),
            ));
        }
    }
    if !evidence.unexpected_recovery_attempts.is_empty()
        && (evidence.unexpected_recovery_old_generation
            != Some(evidence.unexpected_fault_generation)
            || evidence.unexpected_recovery_old_connection_id.as_deref()
                != Some(evidence.unexpected_fault_connection_id.as_str()))
    {
        return Err(HarnessError::Process(
            "unexpected carrier recovery omitted the exact faulted-carrier identity".into(),
        ));
    }
    if !evidence.unexpected_recovery_attempts.is_empty() {
        if !evidence.unexpected_recovery_closed_connection_ids[0]
            .iter()
            .any(|connection_id| connection_id == &evidence.unexpected_fault_connection_id)
        {
            return Err(HarnessError::Process(
                "first recovery closure roster omitted the faulted active carrier".into(),
            ));
        }
        for index in 1..evidence.unexpected_recovery_attempts.len() {
            if evidence.unexpected_recovery_attempts[index]
                != evidence.unexpected_recovery_attempts[index - 1].saturating_add(1)
            {
                // A coalesced watch stream may omit the intermediate
                // candidate identity. The direct relay regression covers
                // every attempt; process evidence retains only the bounded
                // roster and IDs actually observed.
                continue;
            }
            let Some(previous_successor) =
                evidence.unexpected_recovery_successor_connection_ids[index - 1].as_ref()
            else {
                return Err(HarnessError::Process(
                    "recovery attempt omitted the candidate identity needed to bind its retry"
                        .into(),
                ));
            };
            if evidence.unexpected_recovery_closed_connection_ids[index]
                != vec![previous_successor.clone()]
            {
                return Err(HarnessError::Process(
                    "recovery retry closure roster was not bound to the preceding failed candidate"
                        .into(),
                ));
            }
        }
    }
    match evidence.unexpected_outcome {
        "recovered_same_session" => {
            if !evidence.same_session_recovered
                || evidence.unexpected_recovery_attempts.is_empty()
                || evidence.recovered_generation.unwrap_or_default() <= evidence.planned_generation
                || evidence.unexpected_failure_code.is_some()
                || !evidence.stream_identity_stable
                || evidence.unexpected_failure_retryable.is_some()
                || evidence.unexpected_failure_trigger.is_some()
                || !evidence.unexpected_recovery_successor_verified
                || !evidence.unexpected_recovery_fence_acknowledged
                || evidence.unexpected_recovery_reset_reason != Some("fenced_successor_activated")
                || evidence.unexpected_recovery_successor_generation
                    != evidence.recovered_generation
                || evidence
                    .unexpected_recovery_successor_connection_id
                    .as_deref()
                    != evidence.recovered_connection_id.as_deref()
                || evidence
                    .recovered_connection_id
                    .as_deref()
                    .is_none_or(str::is_empty)
                || !evidence.post_fault_owner_snapshot_observed
                || evidence.post_fault_session_terminal_observed
                || evidence.post_fault_live_session_absent
                || !evidence.post_fault_stream_state_observed
                || evidence.post_fault_catalog_owner_released
                || !evidence.control_route_open_after_observation
            {
                return Err(HarnessError::Process(
                    "same-session recovery evidence was incomplete or mixed with failure".into(),
                ));
            }
            if evidence.post_fault_dispatch_delta != 1
                || evidence.post_fault_dispatch_count
                    != evidence.pre_fault_dispatch_count.saturating_add(1)
            {
                return Err(HarnessError::Process(
                    "same-session recovery dispatched a missing or duplicate post-fault record"
                        .into(),
                ));
            }
        }
        "typed_terminal_failure" => {
            if evidence.unexpected_recovery_reset_reason.is_some()
                || evidence.unexpected_recovery_successor_generation.is_some()
                || evidence
                    .unexpected_recovery_successor_connection_id
                    .is_some()
                || evidence.recovered_generation.is_some()
                || evidence.recovered_connection_id.is_some()
            {
                return Err(HarnessError::Process(
                    "terminal carrier failure claimed a fenced-successor reset".into(),
                ));
            }
            let Some(code) = evidence.unexpected_failure_code else {
                return Err(HarnessError::Process(
                    "unexpected close omitted its typed terminal code".into(),
                ));
            };
            if !matches!(
                code,
                "SESSION_CLOSED"
                    | "TRANSPORT_ERROR"
                    | "SUPERVISOR_FAILED"
                    | "DEADLINE_EXCEEDED"
                    | "OUTCOME_UNKNOWN"
            ) {
                return Err(HarnessError::Process(
                    "unexpected close used an unapproved terminal code".into(),
                ));
            }
            if evidence.unexpected_failure_retryable.is_none() {
                return Err(HarnessError::Process(
                    "unexpected close omitted its retryability policy".into(),
                ));
            }
            if evidence.unexpected_failure_trigger.is_none() {
                return Err(HarnessError::Process(
                    "unexpected close omitted its active-data recovery trigger".into(),
                ));
            }
            if !evidence.post_fault_owner_snapshot_observed
                || !evidence.post_fault_session_terminal_observed
                || !evidence.post_fault_live_session_absent
                || !evidence.post_fault_stream_state_observed
                || !evidence.post_fault_catalog_owner_released
            {
                return Err(HarnessError::Process(
                    "terminal failure lacked an actual post-fault owner/session/stream observation"
                        .into(),
                ));
            }
            if evidence.post_fault_dispatch_delta != 0
                || evidence.post_fault_dispatch_count != evidence.pre_fault_dispatch_count
            {
                return Err(HarnessError::Process(
                    "terminal failure evidence showed a post-fault dispatch or replay".into(),
                ));
            }
        }
        _ => {
            return Err(HarnessError::Process(
                "unexpected close outcome was not a typed recovery/failure".into(),
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub(super) struct CliStatus {
    pub(super) phase: String,
    pub(super) session_id: String,
    pub(super) epoch: u64,
    pub(super) generation: u64,
    pub(super) active_connection_id: String,
    pub(super) rotations_completed: u64,
    pub(super) control_local_addr: String,
    pub(super) recovery_attempt: Option<u64>,
    pub(super) recovery_attempt_started_at_ms: Option<u64>,
    pub(super) recovery_attempt_deadline_ms: Option<u64>,
    pub(super) recovery_episode_deadline_ms: Option<u64>,
    pub(super) recovery_closed_connection_ids: Vec<String>,
    pub(super) recovery_reset_reason: Option<&'static str>,
    pub(super) recovery_old_generation: Option<u64>,
    pub(super) recovery_old_connection_id: Option<String>,
    pub(super) recovery_successor_generation: Option<u64>,
    pub(super) recovery_successor_connection_id: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub(super) struct RecoveryStatusEvidence {
    pub(super) attempts: Vec<u64>,
    pub(super) attempt_starts_ms: Vec<u64>,
    pub(super) attempt_deadlines_ms: Vec<u64>,
    pub(super) episode_deadline_ms: Option<u64>,
    pub(super) closed_connection_ids: Vec<Vec<String>>,
    pub(super) successor_connection_ids: Vec<Option<String>>,
    pub(super) reset_reason: Option<&'static str>,
    pub(super) old_generation: Option<u64>,
    pub(super) old_connection_id: Option<String>,
    pub(super) successor_generation: Option<u64>,
    pub(super) successor_connection_id: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct CliFailure {
    pub(super) code: &'static str,
    pub(super) retryable: Option<bool>,
    pub(super) trigger: Option<&'static str>,
}

fn optional_u64(result: &serde_json::Value, name: &str) -> Result<Option<u64>> {
    let value = result.get(name).ok_or_else(|| {
        HarnessError::Process(format!("I08 rotation fault status omitted {name}"))
    })?;
    if value.is_null() {
        Ok(None)
    } else {
        value.as_u64().map(Some).ok_or_else(|| {
            HarnessError::Process(format!(
                "I08 rotation fault status used a non-number {name}"
            ))
        })
    }
}

fn optional_nonempty_string(result: &serde_json::Value, name: &str) -> Result<Option<String>> {
    let value = result.get(name).ok_or_else(|| {
        HarnessError::Process(format!("I08 rotation fault status omitted {name}"))
    })?;
    if value.is_null() {
        return Ok(None);
    }
    value
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .map(Some)
        .ok_or_else(|| {
            HarnessError::Process(format!(
                "I08 rotation fault status used an empty/non-string {name}"
            ))
        })
}

fn required_string_vec(result: &serde_json::Value, name: &str) -> Result<Vec<String>> {
    let values = result
        .get(name)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            HarnessError::Process(format!("I08 rotation fault status omitted {name}"))
        })?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| {
                    HarnessError::Process(format!(
                        "I08 rotation fault status used an empty/non-string entry in {name}"
                    ))
                })
        })
        .collect()
}

fn parse_statuses(process: &ManagedProcess) -> Result<Vec<CliStatus>> {
    parse_statuses_from(process, 0)
}

pub(super) fn parse_statuses_from(
    process: &ManagedProcess,
    stdout_offset: usize,
) -> Result<Vec<CliStatus>> {
    let mut statuses = Vec::new();
    let stdout = process.stdout();
    let output = stdout.get(stdout_offset..).ok_or_else(|| {
        HarnessError::Process("I08 rotation fault status offset exceeded CLI output".into())
    })?;
    for line in output.split(|byte| *byte == b'\n') {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        if value.get("command").and_then(serde_json::Value::as_str) != Some("connect-status") {
            continue;
        }
        if value.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
            return Err(HarnessError::Process(
                "I08 rotation fault CLI emitted a failed status event".into(),
            ));
        }
        let result = value.get("result").ok_or_else(|| {
            HarnessError::Process("I08 rotation fault status omitted result".into())
        })?;
        let required = |name: &str| {
            result
                .get(name)
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| {
                    HarnessError::Process(format!("I08 rotation fault status omitted {name}"))
                })
        };
        statuses.push(CliStatus {
            phase: result
                .get("phase")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| {
                    HarnessError::Process("I08 rotation fault status omitted phase".into())
                })?,
            session_id: required("session_id")?,
            epoch: result
                .get("epoch")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
                    HarnessError::Process("I08 rotation fault status omitted epoch".into())
                })?,
            generation: result
                .get("generation")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
                    HarnessError::Process("I08 rotation fault status omitted generation".into())
                })?,
            active_connection_id: required("active_connection_id")?,
            rotations_completed: result
                .get("rotations_completed")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
                    HarnessError::Process(
                        "I08 rotation fault status omitted rotations_completed".into(),
                    )
                })?,
            control_local_addr: required("control_local_addr")?,
            recovery_attempt: optional_u64(result, "recovery_attempt")?,
            recovery_attempt_started_at_ms: optional_u64(result, "recovery_attempt_started_at_ms")?,
            recovery_attempt_deadline_ms: optional_u64(result, "recovery_attempt_deadline_ms")?,
            recovery_episode_deadline_ms: optional_u64(result, "recovery_episode_deadline_ms")?,
            recovery_closed_connection_ids: required_string_vec(
                result,
                "recovery_closed_connection_ids",
            )?,
            recovery_reset_reason: match optional_nonempty_string(result, "recovery_reset_reason")?
            {
                None => None,
                Some(reason) if reason == "fenced_successor_activated" => {
                    Some("fenced_successor_activated")
                }
                Some(_) => {
                    return Err(HarnessError::Process(
                        "I08 rotation fault status used an unknown recovery reset reason".into(),
                    ));
                }
            },
            recovery_old_generation: optional_u64(result, "recovery_old_generation")?,
            recovery_old_connection_id: optional_nonempty_string(
                result,
                "recovery_old_connection_id",
            )?,
            recovery_successor_generation: optional_u64(result, "recovery_successor_generation")?,
            recovery_successor_connection_id: optional_nonempty_string(
                result,
                "recovery_successor_connection_id",
            )?,
        });
    }
    Ok(statuses)
}

pub(super) fn assert_recovery_metadata_clear(status: &CliStatus, stage: &str) -> Result<()> {
    if status.recovery_attempt.is_some()
        || status.recovery_attempt_started_at_ms.is_some()
        || status.recovery_attempt_deadline_ms.is_some()
        || status.recovery_episode_deadline_ms.is_some()
        || !status.recovery_closed_connection_ids.is_empty()
        || status.recovery_reset_reason.is_some()
        || status.recovery_old_generation.is_some()
        || status.recovery_old_connection_id.is_some()
        || status.recovery_successor_generation.is_some()
        || status.recovery_successor_connection_id.is_some()
    {
        return Err(HarnessError::Process(format!(
            "I08 {stage} planned status unexpectedly carried retained-recovery metadata"
        )));
    }
    Ok(())
}

pub(super) fn collect_recovery_status_evidence(
    process: &ManagedProcess,
    stdout_offset: usize,
    previous: &CliStatus,
) -> Result<RecoveryStatusEvidence> {
    let statuses = parse_statuses_from(process, stdout_offset)?;
    let mut evidence = RecoveryStatusEvidence::default();
    let mut last_attempt = None;
    for status in statuses {
        if status.session_id != previous.session_id
            || status.epoch != previous.epoch
            || status.control_local_addr != previous.control_local_addr
        {
            return Err(HarnessError::Process(
                "I08 recovery status changed authenticated session/control identity".into(),
            ));
        }
        if status.recovery_closed_connection_ids.len() > 2
            || status
                .recovery_closed_connection_ids
                .windows(2)
                .any(|window| window[0] >= window[1])
        {
            return Err(HarnessError::Process(
                "I08 recovery closure roster was not sorted or exceeded the physical bound".into(),
            ));
        }
        match status.recovery_episode_deadline_ms {
            Some(deadline_ms) => match evidence.episode_deadline_ms {
                None => evidence.episode_deadline_ms = Some(deadline_ms),
                Some(previous_deadline_ms) if previous_deadline_ms != deadline_ms => {
                    return Err(HarnessError::Process(
                        "I08 recovery episode deadline changed across retry status".into(),
                    ));
                }
                Some(_) => {}
            },
            None if status.recovery_attempt.is_some() => {
                return Err(HarnessError::Process(
                    "I08 recovery attempt omitted its immutable episode deadline".into(),
                ));
            }
            None => {}
        }
        if let Some(attempt) = status.recovery_attempt {
            if !(1..=3).contains(&attempt)
                || status.recovery_old_generation != Some(previous.generation)
                || status.recovery_old_connection_id.as_deref()
                    != Some(previous.active_connection_id.as_str())
                || status.recovery_successor_generation.is_none()
                || status.recovery_successor_connection_id.is_none()
                || status.recovery_attempt_started_at_ms.is_none()
                || status.recovery_attempt_deadline_ms.is_none()
            {
                return Err(HarnessError::Process(
                    "I08 recovery attempt status omitted exact identity/timing metadata".into(),
                ));
            }
            // Terminal recovery has no reset marker, so retain the exact
            // authenticated old-carrier anchor from the first attempt too.
            // Later statuses must keep the same anchor; otherwise a runtime
            // identity loss remains a hard evidence failure.
            match (
                evidence.old_generation,
                evidence.old_connection_id.as_deref(),
            ) {
                (None, None) => {
                    evidence.old_generation = status.recovery_old_generation;
                    evidence.old_connection_id = status.recovery_old_connection_id.clone();
                }
                (Some(old_generation), Some(old_connection_id))
                    if Some(old_generation) == status.recovery_old_generation
                        && Some(old_connection_id)
                            == status.recovery_old_connection_id.as_deref() => {}
                _ => {
                    return Err(HarnessError::Process(
                        "I08 recovery attempt changed its authenticated old-carrier identity"
                            .into(),
                    ));
                }
            }
            let started_at_ms = status
                .recovery_attempt_started_at_ms
                .expect("checked above");
            let deadline_ms = status.recovery_attempt_deadline_ms.expect("checked above");
            if deadline_ms <= started_at_ms {
                return Err(HarnessError::Process(format!(
                    "I08 recovery attempt {attempt} reported a deadline at/before its start"
                )));
            }
            if status
                .recovery_episode_deadline_ms
                .is_some_and(|episode_deadline_ms| deadline_ms > episode_deadline_ms)
            {
                return Err(HarnessError::Process(
                    "I08 recovery attempt exceeded its immutable episode deadline".into(),
                ));
            }
            if let Some(reason) = status.recovery_reset_reason {
                if reason != "fenced_successor_activated" {
                    return Err(HarnessError::Process(
                        "I08 recovery reset used an unknown closed reason".into(),
                    ));
                }
                evidence.reset_reason = Some(reason);
                evidence.old_generation = status.recovery_old_generation;
                evidence.old_connection_id = status.recovery_old_connection_id.clone();
                evidence.successor_generation = status.recovery_successor_generation;
                evidence.successor_connection_id = status.recovery_successor_connection_id.clone();
            }
            if last_attempt != Some(attempt) {
                if let Some(previous_attempt) = last_attempt
                    && attempt <= previous_attempt
                {
                    return Err(HarnessError::Process(
                        "I08 recovery attempt sequence regressed or duplicated".into(),
                    ));
                }
                evidence.attempts.push(attempt);
                evidence.attempt_starts_ms.push(started_at_ms);
                evidence.attempt_deadlines_ms.push(deadline_ms);
                evidence
                    .closed_connection_ids
                    .push(status.recovery_closed_connection_ids.clone());
                evidence
                    .successor_connection_ids
                    .push(status.recovery_successor_connection_id.clone());
                last_attempt = Some(attempt);
            }
        } else {
            if status.recovery_attempt_started_at_ms.is_some()
                || status.recovery_attempt_deadline_ms.is_some()
                || !status.recovery_closed_connection_ids.is_empty()
            {
                return Err(HarnessError::Process(
                    "I08 recovery status reported attempt timing without an attempt".into(),
                ));
            }
            let identity_present = status.recovery_old_generation.is_some()
                || status.recovery_old_connection_id.is_some()
                || status.recovery_successor_generation.is_some()
                || status.recovery_successor_connection_id.is_some();
            match status.recovery_reset_reason {
                None if identity_present => {
                    return Err(HarnessError::Process(
                        "I08 recovery status carried identity without a reset reason".into(),
                    ));
                }
                None => {}
                Some("fenced_successor_activated") => {
                    if !identity_present
                        || status.recovery_old_generation != Some(previous.generation)
                        || status.recovery_old_connection_id.as_deref()
                            != Some(previous.active_connection_id.as_str())
                        || status.recovery_successor_generation.is_none()
                        || status.recovery_successor_connection_id.is_none()
                    {
                        return Err(HarnessError::Process(
                            "I08 fenced-successor reset omitted exact carrier identity".into(),
                        ));
                    }
                    evidence.reset_reason = status.recovery_reset_reason;
                    evidence.old_generation = status.recovery_old_generation;
                    evidence.old_connection_id = status.recovery_old_connection_id;
                    evidence.successor_generation = status.recovery_successor_generation;
                    evidence.successor_connection_id = status.recovery_successor_connection_id;
                }
                Some(_) => unreachable!("unknown reset reasons are rejected by the parser"),
            }
        }
    }
    Ok(evidence)
}

fn parse_recovery_trigger(message: &str, expected_generation: u64) -> Option<&'static str> {
    let mut trigger = None;
    let mut role = None;
    let mut generation = None;
    for field in message.split("; ") {
        if let Some(value) = field.strip_prefix("recovery_trigger=") {
            trigger = Some(value);
        } else if let Some(value) = field.strip_prefix("recovery_role=") {
            role = Some(value);
        } else if let Some(value) = field.strip_prefix("recovery_generation=") {
            generation = value.parse::<u64>().ok();
        }
    }
    if role != Some("active") || generation != Some(expected_generation) {
        return None;
    }
    match trigger {
        Some("data_reader_closed") => Some("data_reader_closed"),
        Some("data_writer_closed") => Some("data_writer_closed"),
        Some("data_writer_failed") => Some("data_writer_failed"),
        _ => None,
    }
}

pub(super) fn parse_failure_since(
    process: &ManagedProcess,
    stdout_offset: usize,
    expected_generation: u64,
) -> Option<CliFailure> {
    let stdout = process.stdout();
    let output = stdout.get(stdout_offset..)?;
    for line in output.split(|byte| *byte == b'\n') {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        if value.get("command").and_then(serde_json::Value::as_str) != Some("connect")
            || value.get("ok").and_then(serde_json::Value::as_bool) != Some(false)
        {
            continue;
        }
        let Some(error) = value.get("error") else {
            continue;
        };
        let code = match error.get("code").and_then(serde_json::Value::as_str) {
            Some("SESSION_CLOSED") => "SESSION_CLOSED",
            Some("TRANSPORT_ERROR") => "TRANSPORT_ERROR",
            Some("SUPERVISOR_FAILED") => "SUPERVISOR_FAILED",
            Some("DEADLINE_EXCEEDED") => "DEADLINE_EXCEEDED",
            Some("OUTCOME_UNKNOWN") => "OUTCOME_UNKNOWN",
            _ => continue,
        };
        let message = error
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let trigger = parse_recovery_trigger(message, expected_generation);
        if trigger.is_none() {
            continue;
        }
        return Some(CliFailure {
            code,
            retryable: error.get("retryable").and_then(serde_json::Value::as_bool),
            trigger,
        });
    }
    None
}

pub(super) async fn wait_for_status(
    process: &mut ManagedProcess,
    deadline: Instant,
) -> Result<CliStatus> {
    loop {
        if let Some(status) = parse_statuses(process)?.into_iter().last() {
            return Ok(status);
        }
        if let Some(exit) = process.try_wait()? {
            return Err(HarnessError::Process(format!(
                "I08 rotation fault CLI exited before readiness: {exit}"
            )));
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "I08 rotation fault CLI did not publish status before its deadline".into(),
            ));
        }
        sleep(POLL).await;
    }
}

pub(super) fn latest_status(
    process: &ManagedProcess,
    initial: &CliStatus,
) -> Result<Option<CliStatus>> {
    let statuses = parse_statuses(process)?;
    for status in &statuses {
        if status.session_id != initial.session_id
            || status.epoch != initial.epoch
            || status.control_local_addr != initial.control_local_addr
        {
            return Err(HarnessError::Process(
                "I08 rotation fault changed control/session identity".into(),
            ));
        }
    }
    Ok(statuses.into_iter().last())
}

pub(super) fn session_for_status(
    snapshot: RelaySnapshot,
    status: &CliStatus,
    device_id: Uuid,
) -> Result<RelaySessionSnapshot> {
    snapshot
        .sessions
        .into_iter()
        .find(|session| {
            session.device_id == device_id.to_string()
                && session.session_id == status.session_id
                && session.epoch == status.epoch
        })
        .ok_or_else(|| {
            HarnessError::Process("I08 rotation fault owner snapshot lost the CLI session".into())
        })
}

pub(super) async fn relay_snapshot_until(
    cluster: &ProductionCluster,
    node_id: &str,
    deadline: Instant,
) -> Result<RelaySnapshot> {
    let relay = cluster.relay(node_id)?;
    timeout_at(tokio::time::Instant::from_std(deadline), relay.snapshot())
        .await
        .map_err(|_| {
            HarnessError::Timeout(format!(
                "I08 relay {node_id} snapshot exceeded its absolute deadline"
            ))
        })?
        .map_err(|error| HarnessError::Process(format!("I08 relay {node_id} snapshot: {error}")))
}

async fn wait_for_planned_rotation(
    cluster: &ProductionCluster,
    process: &mut ManagedProcess,
    initial: &CliStatus,
    device_id: Uuid,
    previous: &CliStatus,
    expected: u64,
    deadline: Instant,
) -> Result<(CliStatus, RelaySessionSnapshot)> {
    loop {
        if let Some(status) = latest_status(process, initial)?
            && status.rotations_completed >= expected
            && status.generation > previous.generation
            && status.active_connection_id != previous.active_connection_id
        {
            let snapshot = relay_snapshot_until(cluster, "relay-a", deadline).await?;
            let session = session_for_status(snapshot, &status, device_id)?;
            if session.phase != "active"
                || session.candidate_generation.is_some()
                || session.rotations_completed < expected
                || session.active_generation != status.generation
                || session.active_connection_id != status.active_connection_id
                || session.sockets > 2
            {
                return Err(HarnessError::Process(format!(
                    "planned rotation {expected} was not committed: phase={},generation={},candidate={:?},sockets={}",
                    session.phase,
                    session.active_generation,
                    session.candidate_generation,
                    session.sockets
                )));
            }
            let diagnostics = session.rotation_diagnostics.as_ref().ok_or_else(|| {
                HarnessError::Process(format!(
                    "planned rotation {expected} omitted its bounded fence diagnostics"
                ))
            })?;
            let Some(attempt) = diagnostics.attempt.as_ref() else {
                return Err(HarnessError::Process(format!(
                    "planned rotation {expected} omitted its immutable attempt identity"
                )));
            };
            if attempt.session_id != status.session_id
                || attempt.epoch != status.epoch
                || attempt.old_generation != previous.generation
                || attempt.new_generation != status.generation
                || attempt.new_connection_id != status.active_connection_id
                || !diagnostics.commit_accepted
                || !diagnostics.commit_sent
                || !diagnostics.candidate_ready
                || !diagnostics
                    .writer_barrier_flushed
                    .into_iter()
                    .all(|flushed| flushed)
                || !diagnostics
                    .old_socket_closed
                    .into_iter()
                    .all(|closed| closed)
                || diagnostics.relay_ack_sequences.is_empty()
                || diagnostics.connector_ack_sequences.is_empty()
            {
                return Err(HarnessError::Process(format!(
                    "planned rotation {expected} omitted a successor/fence/close acknowledgement"
                )));
            }
            return Ok((status, session));
        }
        if let Some(exit) = process.try_wait()? {
            return Err(HarnessError::Process(format!(
                "CLI exited during planned rotation {expected}: {exit}"
            )));
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "planned rotation {expected} exceeded its absolute deadline"
            )));
        }
        sleep(POLL).await;
    }
}

enum UnexpectedResult {
    Recovered {
        status: Box<CliStatus>,
        session: Box<RelaySessionSnapshot>,
        recovery: RecoveryStatusEvidence,
        process_pid_same: bool,
    },
    Failed {
        failure: CliFailure,
        recovery: RecoveryStatusEvidence,
        process_pid_same: bool,
    },
}

#[allow(clippy::too_many_arguments)] // Independent identity and fault-boundary inputs.
async fn wait_for_unexpected_close(
    cluster: &ProductionCluster,
    process: &mut ManagedProcess,
    initial: &CliStatus,
    device_id: Uuid,
    previous: &CliStatus,
    fault_stdout_offset: usize,
    process_pid: Option<u32>,
    deadline: Instant,
) -> Result<UnexpectedResult> {
    loop {
        let process_pid_same = process.id() == process_pid;
        if let Some(status) = latest_status(process, initial)?
            && status.generation > previous.generation
            && status.active_connection_id != previous.active_connection_id
        {
            let snapshot = relay_snapshot_until(cluster, "relay-a", deadline).await?;
            let session = session_for_status(snapshot, &status, device_id)?;
            if session.phase == "active"
                && session.candidate_generation.is_none()
                && session.active_generation == status.generation
                && session.active_connection_id == status.active_connection_id
            {
                let recovery =
                    collect_recovery_status_evidence(process, fault_stdout_offset, previous)?;
                return Ok(UnexpectedResult::Recovered {
                    status: Box::new(status),
                    session: Box::new(session),
                    recovery,
                    process_pid_same,
                });
            }
        }
        if let Some(exit) = process.try_wait()? {
            if exit.success() {
                return Err(HarnessError::Process(
                    "unexpected active-carrier close ended the CLI successfully without recovery or typed failure".into(),
                ));
            }
            let failure = parse_failure_since(process, fault_stdout_offset, previous.generation)
                .ok_or_else(|| {
                    HarnessError::Process(
                        "unexpected active-carrier close ended without a typed CLI diagnostic"
                            .into(),
                    )
                })?;
            let recovery =
                collect_recovery_status_evidence(process, fault_stdout_offset, previous)?;
            return Ok(UnexpectedResult::Failed {
                failure,
                recovery,
                process_pid_same,
            });
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "unexpected active-carrier recovery/failure exceeded its bounded deadline".into(),
            ));
        }
        sleep(POLL).await;
    }
}

fn require_unexpected_successor_fence(
    session: &RelaySessionSnapshot,
    previous: &CliStatus,
    status: &CliStatus,
    recovery: &RecoveryStatusEvidence,
) -> Result<()> {
    // A successful active-carrier recovery clears the relay's pure rotation
    // attempt before returning the session to `active`; the relay snapshot
    // therefore intentionally has no `rotation_diagnostics` at this point.
    // The client's typed fenced-successor status is the retained activation
    // proof. It is combined with the relay's live session/generation sample
    // and the bounded attempt rosters collected from the same post-fault
    // status stream.
    if session.phase != "active"
        || session.candidate_generation.is_some()
        || session.candidate_connection_id.is_some()
        || session.active_generation != status.generation
        || session.active_connection_id != status.active_connection_id
    {
        return Err(HarnessError::Process(
            "unexpected active-carrier recovery successor was not live at the exact reported identity"
                .into(),
        ));
    }
    if recovery.attempts.is_empty()
        || status.recovery_attempt != recovery.attempts.last().copied()
        || recovery.reset_reason != Some("fenced_successor_activated")
        || recovery.old_generation != Some(previous.generation)
        || recovery.old_connection_id.as_deref() != Some(previous.active_connection_id.as_str())
        || recovery.successor_generation != Some(status.generation)
        || recovery.successor_connection_id.as_deref() != Some(status.active_connection_id.as_str())
        || status.recovery_reset_reason != Some("fenced_successor_activated")
        || status.recovery_old_generation != Some(previous.generation)
        || status.recovery_old_connection_id.as_deref()
            != Some(previous.active_connection_id.as_str())
        || status.recovery_successor_generation != Some(status.generation)
        || status.recovery_successor_connection_id.as_deref()
            != Some(status.active_connection_id.as_str())
    {
        return Err(HarnessError::Process(
            "unexpected active-carrier recovery omitted the exact fenced-successor activation identity"
                .into(),
        ));
    }
    let first_closed = recovery.closed_connection_ids.first().ok_or_else(|| {
        HarnessError::Process(
            "unexpected active-carrier recovery omitted its first closure roster".into(),
        )
    })?;
    if !first_closed
        .iter()
        .any(|connection_id| connection_id == &previous.active_connection_id)
    {
        return Err(HarnessError::Process(
            "unexpected active-carrier recovery closure roster omitted the faulted carrier".into(),
        ));
    }
    if recovery
        .successor_connection_ids
        .last()
        .and_then(|connection_id| connection_id.as_deref())
        != Some(status.active_connection_id.as_str())
    {
        return Err(HarnessError::Process(
            "unexpected active-carrier recovery status did not retain the authenticated successor connection"
                .into(),
        ));
    }
    Ok(())
}

const CONTROL_ROUTE_INDEX: u64 = 0;
const INITIAL_DATA_ROUTE_INDEX: u64 = 1;
const FIRST_REPLACEMENT_ROUTE_INDEX: u64 = 2;
const SECOND_REPLACEMENT_ROUTE_INDEX: u64 = 3;

/// Correlate the fanout's deterministic route identity with the authenticated
/// owner snapshot taken at the same committed generation.  Fanout diagnostics
/// intentionally expose only an index and target; the generation/connection
/// sample is the relay-side binding for that exact open route.
struct RouteCorrelation<'a> {
    diagnostics: &'a FanoutProxyDiagnostics,
    stage: &'a str,
    expected_accepted: u64,
    control_target: SocketAddr,
    data_index: u64,
    data_target: SocketAddr,
    closed_indices: &'a [u64],
    status: &'a CliStatus,
    session: &'a RelaySessionSnapshot,
    stream_id: u64,
}

fn assert_route_correlation(correlation: RouteCorrelation<'_>) -> Result<()> {
    let RouteCorrelation {
        diagnostics,
        stage,
        expected_accepted,
        control_target,
        data_index,
        data_target,
        closed_indices,
        status,
        session,
        stream_id,
    } = correlation;
    if status.phase != "active"
        || status.generation != session.active_generation
        || status.active_connection_id != session.active_connection_id
    {
        return Err(HarnessError::Process(format!(
            "I08 {stage} route sample was not bound to the active generation/connection"
        )));
    }
    if diagnostics.accepted != expected_accepted {
        return Err(HarnessError::Process(format!(
            "I08 {stage} expected fanout accept index {} after route transitions, observed {}",
            expected_accepted.saturating_sub(1),
            diagnostics.accepted
        )));
    }
    if diagnostics.open.len() != 2
        || !diagnostics
            .open
            .iter()
            .any(|route| route.index == CONTROL_ROUTE_INDEX && route.target == control_target)
        || !diagnostics
            .open
            .iter()
            .any(|route| route.index == data_index && route.target == data_target)
        || diagnostics.open.iter().any(|route| {
            !((route.index == CONTROL_ROUTE_INDEX && route.target == control_target)
                || (route.index == data_index && route.target == data_target))
        })
    {
        return Err(HarnessError::Process(format!(
            "I08 {stage} fanout open routes did not match control index {CONTROL_ROUTE_INDEX} and data index {data_index}"
        )));
    }
    if closed_indices.iter().any(|expected| {
        !diagnostics
            .closed
            .iter()
            .any(|route| route.index == *expected)
    }) {
        return Err(HarnessError::Process(format!(
            "I08 {stage} fanout closed-route tail omitted a prior data carrier"
        )));
    }
    if !session
        .streams
        .iter()
        .any(|stream| stream.stream_id == stream_id && !stream.terminal)
    {
        return Err(HarnessError::Process(format!(
            "I08 {stage} route sample was not bound to the active logical stream"
        )));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct PostFaultObservation {
    owner_snapshot_observed: bool,
    session_terminal_observed: bool,
    live_session_absent: bool,
    stream_state_observed: bool,
    catalog_owner_released: bool,
    control_route_observed_after_fault: bool,
    control_route_open_after_observation: bool,
    dispatch_count: u64,
    dispatch_delta: u64,
}

struct TerminalObservationContext<'a> {
    cluster: &'a ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    expected: &'a CliStatus,
    expected_owner: &'a tunnel_catalog::OwnerToken,
    pre_fault_dispatch_count: u64,
    control_route_was_open_at_data_close: bool,
    control_target: SocketAddr,
    deadline: Instant,
}

async fn wait_for_terminal_observation(
    context: TerminalObservationContext<'_>,
) -> Result<PostFaultObservation> {
    let TerminalObservationContext {
        cluster,
        tenant_id,
        device_id,
        expected,
        expected_owner,
        pre_fault_dispatch_count,
        control_route_was_open_at_data_close,
        control_target,
        deadline,
    } = context;
    loop {
        let snapshot = relay_snapshot_until(cluster, "relay-a", deadline).await?;
        let live_session = snapshot.sessions.iter().find(|session| {
            session.tenant_id == tenant_id.to_string()
                && session.device_id == device_id.to_string()
                && session.session_id == expected.session_id
                && session.epoch == expected.epoch
        });
        let terminal_event = snapshot.session_terminal_events.iter().rev().find(|event| {
            event.tenant_id == tenant_id.to_string()
                && event.device_id == device_id.to_string()
                && event.session_id == expected.session_id
                && event.epoch == expected.epoch
                && event.active_generation == expected.generation
                && event.active_connection_id == expected.active_connection_id
        });
        let live_session_absent = live_session.is_none();
        let stream_state_observed = terminal_event.is_some() && live_session_absent;
        let control_route_open_after_observation = cluster
            .device_fanout
            .diagnostics()
            .open
            .iter()
            .any(|route| route.index == CONTROL_ROUTE_INDEX && route.target == control_target);
        let owner = timeout_at(
            tokio::time::Instant::from_std(deadline),
            cluster
                .catalog
                .current_owner(tenant_id, device_id, Utc::now()),
        )
        .await
        .map_err(|_| {
            HarnessError::Timeout("I08 terminal catalog-owner sample exceeded its deadline".into())
        })?
        .map_err(|error| HarnessError::Redis(format!("I08 terminal owner sample: {error}")))?;
        let catalog_owner_released = owner
            .as_ref()
            .is_none_or(|claim| claim.token != *expected_owner);
        if snapshot.lifetime_application_dispatches < pre_fault_dispatch_count {
            return Err(HarnessError::Process(
                "I08 terminal dispatch counter regressed after the carrier fault".into(),
            ));
        }
        if terminal_event.is_some() && stream_state_observed && catalog_owner_released {
            let dispatch_count = snapshot.lifetime_application_dispatches;
            return Ok(PostFaultObservation {
                owner_snapshot_observed: true,
                session_terminal_observed: true,
                live_session_absent,
                stream_state_observed,
                catalog_owner_released,
                control_route_observed_after_fault: control_route_was_open_at_data_close,
                control_route_open_after_observation,
                dispatch_count,
                dispatch_delta: dispatch_count.saturating_sub(pre_fault_dispatch_count),
            });
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "I08 terminal owner/session/stream observation exceeded its deadline".into(),
            ));
        }
        sleep(POLL).await;
    }
}

pub(super) async fn send_record(
    stream: &mut ConsumerStream,
    sequence: u64,
    canary: &[u8],
    deadline: Instant,
) -> Result<()> {
    let payload = format!("m7-i08-fault-record-{sequence}").into_bytes();
    timeout_at(
        tokio::time::Instant::from_std(deadline),
        stream.round_trip(&payload, canary),
    )
    .await
    .map_err(|_| {
        HarnessError::Timeout("I08 rotation fault record exceeded its deadline".into())
    })??;
    Ok(())
}

pub(super) async fn shutdown_cli(mut process: ManagedProcess, deadline: Instant) -> Result<()> {
    let stop = process.request_stop().await;
    // ManagedProcess::shutdown owns the child and output-drain handles.  Do
    // not cancel its consuming future at the shared deadline: that would
    // drop the handles before the child and drain joins are observed.  Its
    // internal grace/forced-reap bounds keep this wait finite; retain a
    // shared-deadline error after the owned shutdown completes.
    let shutdown = process.shutdown(PROCESS_GRACE).await.map(|_| ());
    let shutdown = if Instant::now() > deadline {
        match shutdown {
            Ok(()) => Err(HarnessError::Timeout(
                "I08 rotation fault CLI cleanup exceeded its deadline after joining the child"
                    .into(),
            )),
            Err(error) => Err(HarnessError::Process(format!(
                "{error}; I08 rotation fault CLI cleanup exceeded its deadline"
            ))),
        }
    } else {
        shutdown
    };
    match (stop, shutdown) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(stop), Err(shutdown)) => Err(HarnessError::Process(format!("{stop}; {shutdown}"))),
    }
}

async fn shutdown_node_until(
    cluster: &mut ProductionCluster,
    node_id: &str,
    deadline: Instant,
) -> Result<()> {
    cluster
        .shutdown_node_until(node_id, tokio::time::Instant::from_std(deadline))
        .await
}

pub(super) async fn shutdown_cluster(cluster: ProductionCluster, deadline: Instant) -> Result<()> {
    cluster
        .shutdown_until(tokio::time::Instant::from_std(deadline))
        .await
}

async fn run_scenario(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    deadline: Instant,
    cleanup_deadline: Instant,
) -> Result<I08RotationFaultEvidence> {
    let started = Instant::now();
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(
            "I08 rotation fault fixture requires exactly three relays".into(),
        ));
    }
    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("I08 rotation fault has no device".into()))?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("I08 rotation fault has no service".into()))?;
    let canary = format!("m7-i08-fault:{}", device.id);
    let profile_root = tempdir().map_err(HarnessError::Io)?;
    let mut profile = super::write_device_profile(
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
    profile.config.validate().map_err(|error| {
        HarnessError::InvalidInput(format!("I08 rotation fault profile: {error}"))
    })?;
    let mut config_text = fs::read_to_string(&profile.config_path).map_err(HarnessError::Io)?;
    config_text.push_str(&format!(
        "\n[rotation]\ninterval_seconds = {}\nhandshake_timeout_seconds = {}\noverlap_seconds = {}\n",
        ROTATION.interval_seconds, ROTATION.handshake_timeout_seconds, ROTATION.overlap_seconds
    ));
    fs::write(&profile.config_path, config_text).map_err(HarnessError::Io)?;
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(120),
            ..OidcTokenOptions::default()
        },
    )?;
    let ingress_addr = cluster.relay("relay-c")?.consumer_addr()?;
    let (mut process, mut stream) = start_cli_smoke(
        harness,
        cluster.device_fanout.local_addr(),
        ingress_addr,
        &profile,
        &token,
        device.id,
        service_id,
    )
    .await?;
    let process_pid = process.id();
    let scenario: Result<I08RotationFaultEvidence> = async {
        let initial = wait_for_status(&mut process, deadline).await?;
        if initial.phase != "active"
            || initial.rotations_completed != 0
            || initial.generation == 0
            || initial.active_connection_id.is_empty()
        {
            return Err(HarnessError::Process(
                "I08 rotation fault did not start from an active zero-rotation status".into(),
            ));
        }
        assert_recovery_metadata_clear(&initial, "initial")?;
        let owner = timeout_at(
            tokio::time::Instant::from_std(deadline),
            cluster
                .catalog
                .current_owner(device.tenant_id, device.id, Utc::now()),
        )
        .await
        .map_err(|_| HarnessError::Timeout("I08 rotation fault owner lookup timed out".into()))?
        .map_err(|error| HarnessError::Redis(format!("I08 rotation fault owner lookup: {error}")))?
        .ok_or_else(|| HarnessError::Process("I08 rotation fault owner disappeared".into()))?;
        if owner.token.node_id != "relay-a"
            || owner.token.tenant_id != device.tenant_id
            || owner.token.device_id != device.id
            || owner.token.session_id != initial.session_id
            || owner.token.epoch != initial.epoch
        {
            return Err(HarnessError::Process(
                "I08 rotation fault did not start with the relay-a owner/session".into(),
            ));
        }
        let expected_owner = owner.token.clone();
        let relay_a_addr = cluster
            .relay("relay-a")?
            .running
            .as_ref()
            .ok_or_else(|| {
                HarnessError::Process(
                    "relay-a listener disappeared before the initial route sample".into(),
                )
            })?
            .device_addr;
        let relay_b_addr = cluster
            .relay("relay-b")?
            .running
            .as_ref()
            .ok_or_else(|| {
                HarnessError::Process(
                    "relay-b listener disappeared before the initial route sample".into(),
                )
            })?
            .device_addr;
        let relay_c_addr = cluster
            .relay("relay-c")?
            .running
            .as_ref()
            .ok_or_else(|| {
                HarnessError::Process(
                    "relay-c listener disappeared before the initial route sample".into(),
                )
            })?
            .device_addr;
        let mut owner_session = loop {
            let snapshot = relay_snapshot_until(cluster, "relay-a", deadline).await?;
            if let Ok(session) = session_for_status(snapshot, &initial, device.id)
                && session
                    .streams
                    .iter()
                    .filter(|stream| !stream.terminal)
                    .count()
                    == 1
            {
                break session;
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "I08 rotation fault stream admission exceeded its deadline".into(),
                ));
            }
            sleep(POLL).await;
        };
        if owner_session.phase != "active"
            || owner_session.candidate_generation.is_some()
            || owner_session.candidate_connection_id.is_some()
            || owner_session.rotations_completed != 0
            || owner_session.active_generation != initial.generation
            || owner_session.active_connection_id != initial.active_connection_id
        {
            return Err(HarnessError::Process(
                "I08 rotation fault owner snapshot was not an active zero-rotation baseline"
                    .into(),
            ));
        }
        let stream_snapshot = owner_session
            .streams
            .iter()
            .find(|stream| !stream.terminal)
            .ok_or_else(|| {
                HarnessError::Process("I08 rotation fault stream was not admitted".into())
            })?;
        let stream_id = stream_snapshot.stream_id;
        let operation_id = stream_snapshot.operation_id.clone();
        assert_route_correlation(RouteCorrelation {
            diagnostics: &cluster.device_fanout.diagnostics(),
            stage: "initial",
            expected_accepted: 2,
            control_target: relay_a_addr,
            data_index: INITIAL_DATA_ROUTE_INDEX,
            data_target: relay_b_addr,
            closed_indices: &[],
            status: &initial,
            session: &owner_session,
            stream_id,
        })?;
        send_record(&mut stream, 0, canary.as_bytes(), deadline).await?;
        let mut records_completed = 1_u64;
        let mut previous = initial.clone();
        let mut planned_fence_acknowledged = true;
        let mut planned_old_carrier_closed = true;
        let mut planned_recovery_metadata_samples = 0_u64;
        for expected in 1..=PLANNED_ROTATION_COUNT {
            let (status, session) = wait_for_planned_rotation(
                cluster, &mut process, &initial, device.id, &previous, expected, deadline,
            )
            .await?;
            assert_recovery_metadata_clear(&status, &format!("planned rotation {expected}"))?;
            planned_recovery_metadata_samples = planned_recovery_metadata_samples.saturating_add(1);
            let owner_after = timeout_at(
                tokio::time::Instant::from_std(deadline),
                cluster
                    .catalog
                    .current_owner(device.tenant_id, device.id, Utc::now()),
            )
            .await
            .map_err(|_| {
                HarnessError::Timeout(format!(
                    "I08 rotation {expected} catalog-owner sample exceeded its deadline"
                ))
            })?
            .map_err(|error| {
                HarnessError::Redis(format!("I08 rotation {expected} owner sample: {error}"))
            })?
            .ok_or_else(|| {
                HarnessError::Process(format!(
                    "I08 rotation {expected} catalog owner disappeared"
                ))
            })?;
            if owner_after.token != expected_owner {
                return Err(HarnessError::Process(format!(
                    "I08 rotation {expected} changed the catalog owner token"
                )));
            }
            let (data_index, data_target, closed_indices) = match expected {
                1 => (FIRST_REPLACEMENT_ROUTE_INDEX, relay_c_addr, vec![INITIAL_DATA_ROUTE_INDEX]),
                2 => (
                    SECOND_REPLACEMENT_ROUTE_INDEX,
                    relay_b_addr,
                    vec![INITIAL_DATA_ROUTE_INDEX, FIRST_REPLACEMENT_ROUTE_INDEX],
                ),
                _ => {
                    return Err(HarnessError::InvalidInput(format!(
                        "I08 unsupported planned rotation index {expected}"
                    )));
                }
            };
            assert_route_correlation(RouteCorrelation {
                diagnostics: &cluster.device_fanout.diagnostics(),
                stage: &format!("planned rotation {expected}"),
                expected_accepted: expected + 2,
                control_target: relay_a_addr,
                data_index,
                data_target,
                closed_indices: &closed_indices,
                status: &status,
                session: &session,
                stream_id,
            })?;
            let diagnostics = session.rotation_diagnostics.as_ref().ok_or_else(|| {
                HarnessError::Process("planned rotation diagnostics disappeared".into())
            })?;
            planned_fence_acknowledged &= diagnostics.commit_accepted
                && diagnostics
                    .relay_ack_sequences
                    .iter()
                    .any(|(id, _)| *id == stream_id)
                && diagnostics
                    .connector_ack_sequences
                    .iter()
                    .any(|(id, _)| *id == stream_id);
            planned_old_carrier_closed &= diagnostics
                .old_socket_closed
                .into_iter()
                .all(|closed| closed);
            let stream_after = session
                .streams
                .iter()
                .find(|stream| stream.stream_id == stream_id && !stream.terminal)
                .ok_or_else(|| {
                    HarnessError::Process("planned rotation lost the admitted stream".into())
                })?;
            if stream_after.operation_id != operation_id {
                return Err(HarnessError::Process(
                    "planned rotation changed the tunnel operation identity".into(),
                ));
            }
            send_record(&mut stream, expected, canary.as_bytes(), deadline).await?;
            records_completed = records_completed.saturating_add(1);
            owner_session = session;
            previous = status;
        }
        let planned_process_stayed_alive = process.try_wait()?.is_none();
        if !planned_process_stayed_alive {
            return Err(HarnessError::Process(
                "CLI exited after a planned carrier retirement".into(),
            ));
        }
        let planned_process_pid_same = process.id() == process_pid;
        let planned_generation = previous.generation;
        let planned_connection_id = previous.active_connection_id.clone();
        let before_fault = cluster.device_fanout.diagnostics();
        assert_route_correlation(RouteCorrelation {
            diagnostics: &before_fault,
            stage: "pre-fault",
            expected_accepted: 4,
            control_target: relay_a_addr,
            data_index: SECOND_REPLACEMENT_ROUTE_INDEX,
            data_target: relay_b_addr,
            closed_indices: &[INITIAL_DATA_ROUTE_INDEX, FIRST_REPLACEMENT_ROUTE_INDEX],
            status: &previous,
            session: &owner_session,
            stream_id,
        })?;
        let active_route = before_fault
            .open
            .iter()
            .find(|route| {
                route.index == SECOND_REPLACEMENT_ROUTE_INDEX && route.target == relay_b_addr
            })
            .copied()
            .ok_or_else(|| {
                HarnessError::Process(
                    "I08 pre-fault snapshot omitted active data route index 3".into(),
                )
            })?;
        let control_route = before_fault
            .open
            .iter()
            .find(|route| route.index == CONTROL_ROUTE_INDEX && route.target == relay_a_addr)
            .copied()
            .ok_or_else(|| {
                HarnessError::Process(
                    "I08 pre-fault snapshot omitted control route index 0".into(),
                )
            })?;
        let pre_fault_snapshot = relay_snapshot_until(cluster, "relay-a", deadline).await?;
        let pre_fault_session = session_for_status(pre_fault_snapshot.clone(), &previous, device.id)?;
        if pre_fault_session.phase != "active"
            || pre_fault_session.candidate_generation.is_some()
            || pre_fault_session.candidate_connection_id.is_some()
            || pre_fault_session.active_generation != previous.generation
            || pre_fault_session.active_connection_id != previous.active_connection_id
            || !pre_fault_session.streams.iter().any(|stream| {
                stream.stream_id == stream_id
                    && !stream.terminal
                    && stream.operation_id == operation_id
            })
        {
            return Err(HarnessError::Process(
                "I08 pre-fault owner snapshot did not match the active route baseline".into(),
            ));
        }
        let pre_fault_dispatch_count = pre_fault_snapshot.lifetime_application_dispatches;
        // Capture the log boundary before starting the fault: the CLI may
        // observe the data loss while relay shutdown is still joining tasks.
        // Exact active generation and carrier identity fence these records.
        let fault_stdout_offset = process.stdout().len();
        shutdown_node_until(cluster, "relay-b", deadline).await?;
        let (unexpected_active_carrier_closed, control_route_remained_open) = loop {
            let diagnostics = cluster.device_fanout.diagnostics();
            let data_closed = diagnostics
                .closed
                .iter()
                .any(|route| route.index == active_route.index)
                && !diagnostics
                    .open
                    .iter()
                    .any(|route| route.index == active_route.index);
            let control_open = diagnostics.open.iter().any(|route| {
                route.index == control_route.index && route.target == relay_a_addr
            });
            if !data_closed && !control_open {
                return Err(HarnessError::Process(
                    "control route closed before the selected active data route; fault is ambiguous".into(),
                ));
            }
            if data_closed {
                if !control_open {
                    return Err(HarnessError::Process(
                        "selected active data route closed without an open control route; fault is ambiguous".into(),
                    ));
                }
                break (true, control_open);
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "active-carrier relay shutdown was not observed by the fanout".into(),
                ));
            }
            sleep(POLL).await;
        };
        let unexpected = wait_for_unexpected_close(
            cluster,
            &mut process,
            &initial,
            device.id,
            &previous,
            fault_stdout_offset,
            process_pid,
            deadline.min(Instant::now() + FAULT_RECOVERY_TIMEOUT),
        )
        .await?;
        let (
            outcome,
            failure_code,
            failure_retryable,
            failure_trigger,
            unexpected_recovery_successor_verified,
            unexpected_recovery_fence_acknowledged,
            same_session_recovered,
            recovered_generation,
            post_fault,
            control_socket_stable,
            stream_identity_stable,
            ordered_records,
            recovery_status,
            unexpected_no_whole_session_retry,
        ) = match unexpected {
            UnexpectedResult::Recovered {
                status,
                session,
                recovery,
                process_pid_same,
            } => {
                let status = *status;
                let session = *session;
                if status.session_id != initial.session_id
                    || status.epoch != initial.epoch
                    || status.control_local_addr != initial.control_local_addr
                    || session.session_id != initial.session_id
                    || session.epoch != initial.epoch
                    || session.streams.iter().any(|stream| {
                        stream.stream_id == stream_id && stream.operation_id != operation_id
                    })
                {
                    return Err(HarnessError::Process(
                        "unexpected active-carrier recovery changed the control/stream identity"
                            .into(),
                    ));
                }
                send_record(
                    &mut stream,
                    PLANNED_ROTATION_COUNT + 1,
                    canary.as_bytes(),
                    deadline,
                )
                .await?;
                records_completed = records_completed.saturating_add(1);
                let post_fault_snapshot =
                    relay_snapshot_until(cluster, "relay-a", deadline).await?;
                let post_fault_session =
                    session_for_status(post_fault_snapshot.clone(), &status, device.id)?;
                if post_fault_session.phase != "active"
                    || post_fault_session.candidate_generation.is_some()
                    || !post_fault_session.streams.iter().any(|stream| {
                        stream.stream_id == stream_id
                            && !stream.terminal
                            && stream.operation_id == operation_id
                    })
                {
                    return Err(HarnessError::Process(
                        "I08 recovered post-fault snapshot did not retain the stream identity"
                            .into(),
                    ));
                }
                require_unexpected_successor_fence(
                    &post_fault_session,
                    &previous,
                    &status,
                    &recovery,
                )?;
                let post_fault_owner = timeout_at(
                    tokio::time::Instant::from_std(deadline),
                    cluster
                        .catalog
                        .current_owner(device.tenant_id, device.id, Utc::now()),
                )
                .await
                .map_err(|_| {
                    HarnessError::Timeout(
                        "I08 recovered post-fault owner sample exceeded its deadline".into(),
                    )
                })?
                .map_err(|error| {
                    HarnessError::Redis(format!("I08 recovered post-fault owner: {error}"))
                })?
                .ok_or_else(|| {
                    HarnessError::Process(
                        "I08 recovered post-fault catalog owner disappeared".into(),
                    )
                })?;
                if post_fault_owner.token != expected_owner
                    || post_fault_snapshot.lifetime_application_dispatches != records_completed
                {
                    return Err(HarnessError::Process(
                        "I08 recovered post-fault owner/counter observation diverged".into(),
                    ));
                }
                let post_fault = PostFaultObservation {
                    owner_snapshot_observed: true,
                    session_terminal_observed: false,
                    live_session_absent: false,
                    stream_state_observed: true,
                    catalog_owner_released: false,
                    control_route_observed_after_fault: control_route_remained_open,
                    control_route_open_after_observation: cluster
                        .device_fanout
                        .diagnostics()
                        .open
                        .iter()
                        .any(|route| {
                            route.index == CONTROL_ROUTE_INDEX && route.target == relay_a_addr
                        }),
                    dispatch_count: post_fault_snapshot.lifetime_application_dispatches,
                    dispatch_delta: post_fault_snapshot
                        .lifetime_application_dispatches
                        .saturating_sub(pre_fault_dispatch_count),
                };
                let control_socket_stable = status.control_local_addr == initial.control_local_addr
                    && status.phase == "active"
                    && post_fault.control_route_open_after_observation;
                (
                    "recovered_same_session",
                    None,
                    None,
                    None,
                    true,
                    true,
                    true,
                    Some(status.generation),
                    post_fault,
                    control_socket_stable,
                    true,
                    usize::try_from(records_completed).unwrap_or(usize::MAX),
                    recovery,
                    process_pid_same,
                )
            }
            UnexpectedResult::Failed {
                failure,
                recovery,
                process_pid_same,
            } => {
                let post_fault = wait_for_terminal_observation(TerminalObservationContext {
                    cluster,
                    tenant_id: device.tenant_id,
                    device_id: device.id,
                    expected: &previous,
                    expected_owner: &expected_owner,
                    pre_fault_dispatch_count,
                    control_route_was_open_at_data_close: control_route_remained_open,
                    control_target: relay_a_addr,
                    deadline,
                })
                .await?;
                let control_socket_stable = control_route_remained_open
                    && post_fault.control_route_observed_after_fault;
                (
                    "typed_terminal_failure",
                    Some(failure.code),
                    failure.retryable,
                    failure.trigger,
                    false,
                    false,
                    false,
                    None,
                    post_fault,
                    control_socket_stable,
                    false,
                    usize::try_from(records_completed).unwrap_or(usize::MAX),
                    recovery,
                    process_pid_same,
                )
            }
        };
        let RecoveryStatusEvidence {
            attempts: unexpected_recovery_attempts,
            attempt_starts_ms: unexpected_recovery_attempt_starts_ms,
            attempt_deadlines_ms: unexpected_recovery_attempt_deadlines_ms,
            episode_deadline_ms: unexpected_recovery_episode_deadline_ms,
            closed_connection_ids: unexpected_recovery_closed_connection_ids,
            successor_connection_ids: unexpected_recovery_successor_connection_ids,
            reset_reason: unexpected_recovery_reset_reason,
            old_generation: unexpected_recovery_old_generation,
            old_connection_id: unexpected_recovery_old_connection_id,
            successor_generation: unexpected_recovery_successor_generation,
            successor_connection_id: unexpected_recovery_successor_connection_id,
        } = recovery_status;
        let recovered_connection_id = if same_session_recovered {
            unexpected_recovery_successor_connection_id.clone()
        } else {
            None
        };
        Ok(I08RotationFaultEvidence {
            scope: "planned_retirement_and_active_carrier_fault",
            relay_count: 3,
            actual_cli_process: process_pid.is_some(),
            planned_retirement_verified: true,
            planned_rotations: PLANNED_ROTATION_COUNT,
            planned_fence_acknowledged,
            planned_old_carrier_closed,
            planned_process_stayed_alive,
            planned_no_whole_session_retry: planned_process_pid_same,
            planned_recovery_diagnostics_clean: planned_recovery_metadata_samples
                == PLANNED_ROTATION_COUNT,
            session_id: initial.session_id.clone(),
            epoch: initial.epoch,
            stream_id,
            tunnel_operation_id: operation_id,
            planned_generation,
            planned_connection_id,
            unexpected_fault_relay: "relay-b".into(),
            unexpected_fault_route_index: active_route.index,
            unexpected_fault_generation: previous.generation,
            unexpected_fault_connection_id: previous.active_connection_id.clone(),
            unexpected_active_carrier_closed,
            control_route_remained_open,
            unexpected_outcome: outcome,
            unexpected_failure_code: failure_code,
            unexpected_failure_retryable: failure_retryable,
            unexpected_failure_trigger: failure_trigger,
            unexpected_recovery_successor_verified,
            unexpected_recovery_fence_acknowledged,
            unexpected_recovery_attempts,
            unexpected_recovery_attempt_starts_ms,
            unexpected_recovery_attempt_deadlines_ms,
            unexpected_recovery_episode_deadline_ms,
            unexpected_recovery_closed_connection_ids,
            unexpected_recovery_successor_connection_ids,
            unexpected_recovery_reset_reason,
            unexpected_recovery_old_generation,
            unexpected_recovery_old_connection_id,
            unexpected_recovery_successor_generation,
            unexpected_recovery_successor_connection_id,
            unexpected_no_whole_session_retry,
            same_session_recovered,
            recovered_generation,
            recovered_connection_id,
            control_socket_stable,
            stream_identity_stable,
            post_fault_owner_snapshot_observed: post_fault.owner_snapshot_observed,
            post_fault_session_terminal_observed: post_fault.session_terminal_observed,
            post_fault_live_session_absent: post_fault.live_session_absent,
            post_fault_stream_state_observed: post_fault.stream_state_observed,
            post_fault_catalog_owner_released: post_fault.catalog_owner_released,
            control_route_observed_after_fault: post_fault.control_route_observed_after_fault,
            control_route_open_after_observation: post_fault.control_route_open_after_observation,
            pre_fault_dispatch_count,
            post_fault_dispatch_count: post_fault.dispatch_count,
            post_fault_dispatch_delta: post_fault.dispatch_delta,
            ordered_records,
            goaway_tested: false,
            goaway_is_separate_scope: true,
            cleanup_joined: false,
            elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
    .await;
    let stream_cleanup = timeout_at(
        tokio::time::Instant::from_std(cleanup_deadline),
        stream.close(),
    )
    .await
    .map_err(|_| HarnessError::Timeout("I08 rotation fault stream cleanup timed out".into()))
    .and_then(|result| result);
    let process_cleanup = shutdown_cli(process, cleanup_deadline).await;
    let mut cleanup_errors = Vec::new();
    if let Err(error) = stream_cleanup {
        cleanup_errors.push(format!("consumer cleanup failed: {error}"));
    }
    if let Err(error) = process_cleanup {
        cleanup_errors.push(format!("CLI cleanup failed: {error}"));
    }
    match scenario {
        Err(error) if cleanup_errors.is_empty() => Err(error),
        Err(error) => Err(HarnessError::Process(format!(
            "{error}; {}",
            cleanup_errors.join("; ")
        ))),
        Ok(mut evidence) if cleanup_errors.is_empty() => {
            evidence.cleanup_joined = true;
            Ok(evidence)
        }
        Ok(_) => Err(HarnessError::Process(cleanup_errors.join("; "))),
    }
}

/// Run the bounded real-process M7-I08 planned/unexpected carrier fixture.
pub async fn verify() -> Result<I08RotationFaultEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(ROTATION)
        .shared_device_uuid(true);
    let startup_deadline = Instant::now() + STARTUP_TIMEOUT;
    let startup_cleanup_deadline = startup_deadline + CLEANUP_TIMEOUT;
    let mut harness_start = Box::pin(Harness::start(options));
    let mut harness = match timeout_at(
        tokio::time::Instant::from_std(startup_deadline),
        &mut harness_start,
    )
    .await
    {
        Ok(Ok(harness)) => harness,
        Ok(Err(error)) => {
            return Err(error);
        }
        Err(_) => {
            // First try the shared cleanup window, but never cancel the
            // constructor at its end.  Harness::start can still own partially
            // created processes and output drains; dropping it here would
            // detach those resources before their own cleanup path runs.
            let (completion, cleanup_budget_exceeded) = match timeout_at(
                tokio::time::Instant::from_std(startup_cleanup_deadline),
                &mut harness_start,
            )
            .await
            {
                Ok(completion) => (completion, false),
                Err(_) => {
                    // There is no safe hard cancellation point once the
                    // cleanup budget expires.  Await the still-owned future
                    // to completion, then clean any returned harness.  This
                    // preserves ownership and join ordering, but means the
                    // wall-clock budget is diagnostic rather than a strict
                    // upper bound if the constructor itself never resolves.
                    (harness_start.as_mut().await, true)
                }
            };
            let timeout_message = if cleanup_budget_exceeded {
                "I08 rotation fault harness startup timed out; startup future completed after the shared cleanup deadline"
            } else {
                "I08 rotation fault harness startup timed out"
            };
            return match completion {
                Ok(harness) => {
                    let cleanup = harness
                        .shutdown_until(tokio::time::Instant::from_std(startup_cleanup_deadline))
                        .await;
                    match cleanup {
                        Ok(()) => Err(HarnessError::Timeout(timeout_message.into())),
                        Err(cleanup) => Err(HarnessError::Process(format!(
                            "{timeout_message}; late harness cleanup: {cleanup}"
                        ))),
                    }
                }
                Err(error) => Err(HarnessError::Process(format!(
                    "{timeout_message}; startup cleanup: {error}"
                ))),
            };
        }
    };
    let mut cluster = {
        let mut start = Box::pin(ProductionCluster::start(&mut harness));
        let result = match timeout_at(tokio::time::Instant::from_std(startup_deadline), &mut start)
            .await
        {
            Ok(result) => result,
            Err(_) => {
                // First give the constructor the shared cleanup window.  If
                // that expires, retain and await the pinned future instead
                // of dropping it: ProductionCluster::start may still own
                // relay, proxy, or membership handles whose cleanup must be
                // joined before the harness is shut down.  This preserves
                // ownership, but an unresolving constructor can exceed the
                // wall-clock budget; the budget is therefore diagnostic, not
                // a cancellation guarantee.
                let (result, cleanup_budget_exceeded) = match timeout_at(
                    tokio::time::Instant::from_std(startup_cleanup_deadline),
                    &mut start,
                )
                .await
                {
                    Ok(result) => (result, false),
                    Err(_) => (start.as_mut().await, true),
                };
                drop(start);
                let timeout_message = if cleanup_budget_exceeded {
                    "I08 rotation fault production cluster startup timed out; startup future completed after the shared cleanup deadline"
                } else {
                    "I08 rotation fault production cluster startup timed out"
                };
                return match result {
                    Ok(cluster) => {
                        let cleanup = shutdown_cluster(cluster, startup_cleanup_deadline).await;
                        let error = match cleanup {
                            Ok(()) => HarnessError::Timeout(timeout_message.into()),
                            Err(cleanup) => HarnessError::Process(format!(
                                "{timeout_message}; startup cluster cleanup: {cleanup}"
                            )),
                        };
                        let harness_cleanup = harness
                            .shutdown_until(tokio::time::Instant::from_std(
                                startup_cleanup_deadline,
                            ))
                            .await;
                        match harness_cleanup {
                            Ok(()) => Err(error),
                            Err(cleanup) => Err(HarnessError::Process(format!(
                                "{error}; harness cleanup: {cleanup}"
                            ))),
                        }
                    }
                    Err(error) => {
                        let harness_cleanup = harness
                            .shutdown_until(tokio::time::Instant::from_std(
                                startup_cleanup_deadline,
                            ))
                            .await;
                        match harness_cleanup {
                            Ok(()) => Err(HarnessError::Process(format!(
                                "{timeout_message}; startup cleanup: {error}"
                            ))),
                            Err(cleanup) => Err(HarnessError::Process(format!(
                                "{timeout_message}; startup cleanup: {error}; harness cleanup: {cleanup}"
                            ))),
                        }
                    }
                };
            }
        };
        drop(start);
        match result {
            Ok(cluster) => cluster,
            Err(error) => {
                let harness_cleanup = harness
                    .shutdown_until(tokio::time::Instant::from_std(startup_cleanup_deadline))
                    .await;
                return match harness_cleanup {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(HarnessError::Process(format!(
                        "{error}; harness cleanup: {cleanup}"
                    ))),
                };
            }
        }
    };
    let deadline = Instant::now() + SCENARIO_TIMEOUT.min(Duration::from_secs(150));
    let cleanup_deadline = deadline + CLEANUP_TIMEOUT;
    let scenario = run_scenario(&mut cluster, &harness, deadline, cleanup_deadline).await;
    let cluster_cleanup = shutdown_cluster(cluster, cleanup_deadline).await;
    let harness_cleanup = harness
        .shutdown_until(tokio::time::Instant::from_std(cleanup_deadline))
        .await;
    let mut cleanup_errors = Vec::new();
    if let Err(error) = cluster_cleanup {
        cleanup_errors.push(format!("cluster cleanup: {error}"));
    }
    if let Err(error) = harness_cleanup {
        cleanup_errors.push(format!("harness cleanup: {error}"));
    }
    match scenario {
        Err(error) if cleanup_errors.is_empty() => Err(error),
        Err(error) => Err(HarnessError::Process(format!(
            "{error}; {}",
            cleanup_errors.join("; ")
        ))),
        Ok(evidence) if cleanup_errors.is_empty() => {
            validate_i08_rotation_fault_evidence(&evidence)?;
            Ok(evidence)
        }
        Ok(_) => Err(HarnessError::Process(cleanup_errors.join("; "))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        I08RotationFaultEvidence, parse_recovery_trigger, validate_i08_rotation_fault_evidence,
    };

    #[test]
    fn recovery_trigger_requires_exact_active_generation_metadata() {
        let message = "retained recovery failed; recovery_trigger=data_writer_failed; recovery_role=active; recovery_generation=3";
        assert_eq!(
            parse_recovery_trigger(message, 3),
            Some("data_writer_failed")
        );
        assert_eq!(parse_recovery_trigger(message, 2), None);
        assert_eq!(
            parse_recovery_trigger(
                "retained recovery failed; detail=data_writer_failed; recovery_role=active; recovery_generation=3",
                3,
            ),
            None
        );
        assert_eq!(
            parse_recovery_trigger(
                "retained recovery failed; recovery_trigger=data_writer_failed; recovery_role=candidate; recovery_generation=3",
                3,
            ),
            None
        );
    }

    fn evidence(outcome: &'static str) -> I08RotationFaultEvidence {
        let control_route_remained_open = true;
        I08RotationFaultEvidence {
            scope: "planned_retirement_and_active_carrier_fault",
            relay_count: 3,
            actual_cli_process: true,
            planned_retirement_verified: true,
            planned_rotations: 2,
            planned_fence_acknowledged: true,
            planned_old_carrier_closed: true,
            planned_process_stayed_alive: true,
            planned_no_whole_session_retry: true,
            planned_recovery_diagnostics_clean: true,
            session_id: "session".into(),
            epoch: 1,
            stream_id: 7,
            tunnel_operation_id: "operation".into(),
            planned_generation: 3,
            planned_connection_id: "connection-3".into(),
            unexpected_fault_relay: "relay-b".into(),
            unexpected_fault_route_index: 3,
            unexpected_fault_generation: 3,
            unexpected_fault_connection_id: "connection-3".into(),
            unexpected_active_carrier_closed: true,
            control_route_remained_open,
            unexpected_outcome: outcome,
            unexpected_failure_code: (outcome == "typed_terminal_failure")
                .then_some("TRANSPORT_ERROR"),
            unexpected_failure_retryable: (outcome == "typed_terminal_failure").then_some(false),
            unexpected_failure_trigger: (outcome == "typed_terminal_failure")
                .then_some("data_reader_closed"),
            unexpected_recovery_successor_verified: outcome == "recovered_same_session",
            unexpected_recovery_fence_acknowledged: outcome == "recovered_same_session",
            unexpected_recovery_attempts: vec![1],
            unexpected_recovery_attempt_starts_ms: vec![1_000],
            unexpected_recovery_attempt_deadlines_ms: vec![3_000],
            unexpected_recovery_episode_deadline_ms: Some(4_000),
            unexpected_recovery_closed_connection_ids: vec![vec!["connection-3".into()]],
            unexpected_recovery_successor_connection_ids: vec![Some("connection-4".into())],
            unexpected_recovery_reset_reason: (outcome == "recovered_same_session")
                .then_some("fenced_successor_activated"),
            unexpected_recovery_old_generation: Some(3),
            unexpected_recovery_old_connection_id: Some("connection-3".into()),
            unexpected_recovery_successor_generation: (outcome == "recovered_same_session")
                .then_some(4),
            unexpected_recovery_successor_connection_id: (outcome == "recovered_same_session")
                .then_some("connection-4".into()),
            unexpected_no_whole_session_retry: true,
            same_session_recovered: outcome == "recovered_same_session",
            recovered_generation: (outcome == "recovered_same_session").then_some(4),
            recovered_connection_id: (outcome == "recovered_same_session")
                .then_some("connection-4".into()),
            control_socket_stable: true,
            stream_identity_stable: true,
            post_fault_owner_snapshot_observed: true,
            post_fault_session_terminal_observed: outcome == "typed_terminal_failure",
            post_fault_live_session_absent: outcome == "typed_terminal_failure",
            post_fault_stream_state_observed: true,
            post_fault_catalog_owner_released: outcome == "typed_terminal_failure",
            control_route_observed_after_fault: control_route_remained_open,
            control_route_open_after_observation: outcome == "recovered_same_session",
            pre_fault_dispatch_count: 3,
            post_fault_dispatch_count: if outcome == "recovered_same_session" {
                4
            } else {
                3
            },
            post_fault_dispatch_delta: if outcome == "recovered_same_session" {
                1
            } else {
                0
            },
            ordered_records: if outcome == "recovered_same_session" {
                4
            } else {
                3
            },
            goaway_tested: false,
            goaway_is_separate_scope: true,
            cleanup_joined: true,
            elapsed_ms: 1,
        }
    }

    #[test]
    fn validates_recovered_same_session_fault() {
        validate_i08_rotation_fault_evidence(&evidence("recovered_same_session"))
            .expect("evidence");
    }

    #[test]
    fn validates_typed_failure_fault() {
        validate_i08_rotation_fault_evidence(&evidence("typed_terminal_failure"))
            .expect("evidence");
    }

    #[test]
    fn rejects_goaway_claim() {
        let mut value = evidence("recovered_same_session");
        value.goaway_tested = true;
        assert!(validate_i08_rotation_fault_evidence(&value).is_err());
    }

    #[test]
    fn rejects_active_data_close_without_control_route() {
        let mut value = evidence("recovered_same_session");
        value.control_route_remained_open = false;
        assert!(validate_i08_rotation_fault_evidence(&value).is_err());
    }

    #[test]
    fn rejects_recovery_with_terminal_retryability_metadata() {
        let mut value = evidence("recovered_same_session");
        value.unexpected_failure_retryable = Some(true);
        assert!(validate_i08_rotation_fault_evidence(&value).is_err());
    }

    #[test]
    fn rejects_recovery_without_successor_fence_evidence() {
        let mut value = evidence("recovered_same_session");
        value.unexpected_recovery_successor_verified = false;
        assert!(validate_i08_rotation_fault_evidence(&value).is_err());
        value = evidence("recovered_same_session");
        value.unexpected_recovery_fence_acknowledged = false;
        assert!(validate_i08_rotation_fault_evidence(&value).is_err());
    }

    #[test]
    fn rejects_typed_failure_without_retryability_policy() {
        let mut value = evidence("typed_terminal_failure");
        value.unexpected_failure_retryable = None;
        assert!(validate_i08_rotation_fault_evidence(&value).is_err());
    }

    #[test]
    fn rejects_terminal_failure_without_data_trigger() {
        let mut value = evidence("typed_terminal_failure");
        value.unexpected_failure_trigger = None;
        assert!(validate_i08_rotation_fault_evidence(&value).is_err());
    }

    #[test]
    fn rejects_terminal_failure_without_post_fault_observation() {
        let mut value = evidence("typed_terminal_failure");
        value.post_fault_session_terminal_observed = false;
        assert!(validate_i08_rotation_fault_evidence(&value).is_err());
    }

    #[test]
    fn rejects_terminal_failure_without_live_session_absence() {
        let mut value = evidence("typed_terminal_failure");
        value.post_fault_live_session_absent = false;
        assert!(validate_i08_rotation_fault_evidence(&value).is_err());
    }

    #[test]
    fn rejects_terminal_failure_when_post_fault_dispatch_delta_is_nonzero() {
        let mut value = evidence("typed_terminal_failure");
        value.post_fault_dispatch_count = 4;
        value.post_fault_dispatch_delta = 1;
        assert!(validate_i08_rotation_fault_evidence(&value).is_err());
    }

    #[test]
    fn rejects_wrong_active_route_correlation() {
        let mut value = evidence("recovered_same_session");
        value.unexpected_fault_route_index = 2;
        assert!(validate_i08_rotation_fault_evidence(&value).is_err());
    }

    #[test]
    fn rejects_reset_without_exact_successor_identity() {
        let mut value = evidence("recovered_same_session");
        value.unexpected_recovery_successor_connection_id = Some("other".into());
        assert!(validate_i08_rotation_fault_evidence(&value).is_err());
        value = evidence("recovered_same_session");
        value.unexpected_recovery_reset_reason = None;
        assert!(validate_i08_rotation_fault_evidence(&value).is_err());
    }

    #[test]
    fn rejects_planned_rotation_recovery_metadata() {
        let mut value = evidence("recovered_same_session");
        value.planned_recovery_diagnostics_clean = false;
        assert!(validate_i08_rotation_fault_evidence(&value).is_err());
    }

    #[test]
    fn accepts_coalesced_attempt_observations_with_real_deadline_spacing() {
        let mut value = evidence("typed_terminal_failure");
        // A status watch can coalesce an intermediate attempt.  The observed
        // attempt numbers need only increase.  The validator still sums the
        // shared 100 ms and 200 ms policy gaps for the omitted attempt.
        value.unexpected_recovery_attempts = vec![1, 3];
        value.unexpected_recovery_attempt_starts_ms = vec![1_000, 1_301];
        value.unexpected_recovery_attempt_deadlines_ms = vec![3_000, 3_250];
        value.unexpected_recovery_closed_connection_ids =
            vec![vec!["connection-3".into()], vec!["connection-4".into()]];
        value.unexpected_recovery_successor_connection_ids =
            vec![Some("connection-4".into()), Some("connection-5".into())];
        validate_i08_rotation_fault_evidence(&value).expect("coalesced timing evidence");
    }

    #[test]
    fn rejects_retry_before_shared_protocol_backoff() {
        let mut value = evidence("typed_terminal_failure");
        value.unexpected_recovery_attempts = vec![1, 2];
        value.unexpected_recovery_attempt_starts_ms = vec![1_000, 1_099];
        value.unexpected_recovery_attempt_deadlines_ms = vec![3_000, 3_250];
        value.unexpected_recovery_closed_connection_ids =
            vec![vec!["connection-3".into()], vec!["connection-4".into()]];
        value.unexpected_recovery_successor_connection_ids =
            vec![Some("connection-4".into()), Some("connection-5".into())];
        assert!(validate_i08_rotation_fault_evidence(&value).is_err());
    }

    #[test]
    fn rejects_retry_closure_roster_not_bound_to_failed_candidate() {
        let mut value = evidence("typed_terminal_failure");
        value.unexpected_recovery_attempts = vec![1, 2];
        value.unexpected_recovery_attempt_starts_ms = vec![1_000, 1_100];
        value.unexpected_recovery_attempt_deadlines_ms = vec![3_000, 3_250];
        value.unexpected_recovery_closed_connection_ids = vec![
            vec!["connection-3".into()],
            vec!["unrelated-connection".into()],
        ];
        value.unexpected_recovery_successor_connection_ids =
            vec![Some("connection-4".into()), Some("connection-5".into())];
        assert!(validate_i08_rotation_fault_evidence(&value).is_err());
    }

    #[test]
    fn accepts_both_bounded_followup_retry_gaps() {
        let mut value = evidence("typed_terminal_failure");
        value.unexpected_recovery_attempts = vec![1, 2, 3];
        value.unexpected_recovery_attempt_starts_ms = vec![1_000, 1_100, 1_300];
        value.unexpected_recovery_attempt_deadlines_ms = vec![3_000, 3_100, 3_300];
        value.unexpected_recovery_closed_connection_ids = vec![
            vec!["connection-3".into()],
            vec!["connection-4".into()],
            vec!["connection-5".into()],
        ];
        value.unexpected_recovery_successor_connection_ids = vec![
            Some("connection-4".into()),
            Some("connection-5".into()),
            Some("connection-6".into()),
        ];
        validate_i08_rotation_fault_evidence(&value).expect("both retry gaps");
        value.unexpected_recovery_attempt_starts_ms[2] = 1_299;
        assert!(validate_i08_rotation_fault_evidence(&value).is_err());
    }

    #[test]
    fn rejects_attempt_spacing_after_the_previous_deadline() {
        let mut value = evidence("typed_terminal_failure");
        value.unexpected_recovery_attempts = vec![1, 2];
        value.unexpected_recovery_attempt_starts_ms = vec![1_000, 3_001];
        value.unexpected_recovery_attempt_deadlines_ms = vec![3_000, 3_250];
        value.unexpected_recovery_closed_connection_ids =
            vec![vec!["connection-3".into()], vec!["connection-4".into()]];
        value.unexpected_recovery_successor_connection_ids =
            vec![Some("connection-4".into()), Some("connection-5".into())];
        assert!(validate_i08_rotation_fault_evidence(&value).is_err());
    }

    #[test]
    fn permits_typed_terminal_without_a_recovery_status_event() {
        let mut value = evidence("typed_terminal_failure");
        value.unexpected_recovery_attempts.clear();
        value.unexpected_recovery_attempt_starts_ms.clear();
        value.unexpected_recovery_attempt_deadlines_ms.clear();
        value.unexpected_recovery_closed_connection_ids.clear();
        value.unexpected_recovery_successor_connection_ids.clear();
        value.unexpected_recovery_old_generation = None;
        value.unexpected_recovery_old_connection_id = None;
        validate_i08_rotation_fault_evidence(&value)
            .expect("terminal evidence does not require a watch event");
    }

    fn with_recovery_attempts(
        evidence: &mut I08RotationFaultEvidence,
        attempts: &[u64],
        starts_ms: &[u64],
        deadlines_ms: &[u64],
    ) {
        evidence.unexpected_recovery_attempts = attempts.to_vec();
        evidence.unexpected_recovery_attempt_starts_ms = starts_ms.to_vec();
        evidence.unexpected_recovery_attempt_deadlines_ms = deadlines_ms.to_vec();
        evidence.unexpected_recovery_closed_connection_ids = (0..attempts.len())
            .map(|index| vec![format!("connection-{}", index + 3)])
            .collect();
        evidence.unexpected_recovery_successor_connection_ids = (0..attempts.len())
            .map(|index| Some(format!("connection-{}", index + 4)))
            .collect();
    }

    #[test]
    fn every_rotation_fault_condition_names_its_rejection_on_the_shared_exit_path() {
        use crate::acceptance_test_support::assert_failed;

        const RECOVERED: &str = "recovered_same_session";
        const TERMINAL: &str = "typed_terminal_failure";
        const IDENTITY: &str = "omitted a stable identity or ordered record";
        const RECOVERED_INCOMPLETE: &str =
            "same-session recovery evidence was incomplete or mixed with failure";
        const TERMINAL_RESET: &str = "claimed a fenced-successor reset";
        const TERMINAL_OBSERVATION: &str =
            "lacked an actual post-fault owner/session/stream observation";
        type Case = (
            &'static str,
            &'static str,
            &'static str,
            fn(&mut I08RotationFaultEvidence),
        );
        let cases: &[Case] = &[
            ("scope", RECOVERED, "unexpected scope", |e| {
                e.scope = "widened_scope"
            }),
            (
                "relay_count",
                RECOVERED,
                "three relays and a real CLI",
                |e| e.relay_count = 2,
            ),
            (
                "actual_cli_process",
                RECOVERED,
                "three relays and a real CLI",
                |e| e.actual_cli_process = false,
            ),
            (
                "planned_retirement_verified",
                RECOVERED,
                "incomplete: planned_retirement_verified",
                |e| e.planned_retirement_verified = false,
            ),
            (
                "planned_fence_acknowledged",
                RECOVERED,
                "incomplete: planned_fence_acknowledged",
                |e| e.planned_fence_acknowledged = false,
            ),
            (
                "planned_old_carrier_closed",
                RECOVERED,
                "incomplete: planned_old_carrier_closed",
                |e| e.planned_old_carrier_closed = false,
            ),
            (
                "planned_process_stayed_alive",
                RECOVERED,
                "incomplete: planned_process_stayed_alive",
                |e| e.planned_process_stayed_alive = false,
            ),
            (
                "planned_no_whole_session_retry",
                RECOVERED,
                "incomplete: planned_no_whole_session_retry",
                |e| e.planned_no_whole_session_retry = false,
            ),
            (
                "planned_recovery_diagnostics_clean",
                RECOVERED,
                "incomplete: planned_recovery_diagnostics_clean",
                |e| e.planned_recovery_diagnostics_clean = false,
            ),
            (
                "unexpected_active_carrier_closed",
                RECOVERED,
                "incomplete: unexpected_active_carrier_closed",
                |e| e.unexpected_active_carrier_closed = false,
            ),
            (
                "control_route_remained_open",
                RECOVERED,
                "incomplete: control_route_remained_open",
                |e| e.control_route_remained_open = false,
            ),
            (
                "control_socket_stable",
                RECOVERED,
                "incomplete: control_socket_stable",
                |e| e.control_socket_stable = false,
            ),
            (
                "post_fault_owner_snapshot_observed",
                RECOVERED,
                "incomplete: post_fault_owner_snapshot_observed",
                |e| e.post_fault_owner_snapshot_observed = false,
            ),
            (
                "post_fault_stream_state_observed",
                RECOVERED,
                "incomplete: post_fault_stream_state_observed",
                |e| e.post_fault_stream_state_observed = false,
            ),
            (
                "control_route_observed_after_fault",
                RECOVERED,
                "incomplete: control_route_observed_after_fault",
                |e| e.control_route_observed_after_fault = false,
            ),
            (
                "goaway_is_separate_scope",
                RECOVERED,
                "incomplete: goaway_is_separate_scope",
                |e| e.goaway_is_separate_scope = false,
            ),
            (
                "cleanup_joined",
                RECOVERED,
                "incomplete: cleanup_joined",
                |e| e.cleanup_joined = false,
            ),
            (
                "goaway_tested",
                RECOVERED,
                "GOAWAY as a separate case",
                |e| e.goaway_tested = true,
            ),
            ("planned_rotations", RECOVERED, IDENTITY, |e| {
                e.planned_rotations = 1
            }),
            ("session_id", RECOVERED, IDENTITY, |e| e.session_id.clear()),
            ("epoch", RECOVERED, IDENTITY, |e| e.epoch = 0),
            ("stream_id", RECOVERED, IDENTITY, |e| e.stream_id = 0),
            ("tunnel_operation_id", RECOVERED, IDENTITY, |e| {
                e.tunnel_operation_id.clear()
            }),
            ("planned_generation", RECOVERED, IDENTITY, |e| {
                e.planned_generation = 1
            }),
            ("planned_connection_id", RECOVERED, IDENTITY, |e| {
                e.planned_connection_id.clear()
            }),
            ("unexpected_fault_relay", RECOVERED, IDENTITY, |e| {
                e.unexpected_fault_relay.clear()
            }),
            ("unexpected_fault_route_index", RECOVERED, IDENTITY, |e| {
                e.unexpected_fault_route_index = 2
            }),
            (
                "unexpected_fault_generation_zero",
                RECOVERED,
                IDENTITY,
                |e| e.unexpected_fault_generation = 0,
            ),
            (
                "unexpected_fault_generation_mismatch",
                RECOVERED,
                IDENTITY,
                |e| e.unexpected_fault_generation = 4,
            ),
            (
                "unexpected_fault_connection_id_empty",
                RECOVERED,
                IDENTITY,
                |e| e.unexpected_fault_connection_id.clear(),
            ),
            (
                "unexpected_fault_connection_id_mismatch",
                RECOVERED,
                IDENTITY,
                |e| e.unexpected_fault_connection_id = "connection-9".into(),
            ),
            ("pre_fault_dispatch_count", RECOVERED, IDENTITY, |e| {
                e.pre_fault_dispatch_count = 0
            }),
            ("ordered_records", RECOVERED, IDENTITY, |e| {
                e.ordered_records = 2
            }),
            ("recovery_attempts_over_bound", TERMINAL, IDENTITY, |e| {
                with_recovery_attempts(
                    e,
                    &[1, 2, 3, 4],
                    &[1_000, 1_100, 1_300, 1_400],
                    &[3_000, 3_100, 3_300, 3_400],
                )
            }),
            ("recovery_attempt_starts_len", RECOVERED, IDENTITY, |e| {
                e.unexpected_recovery_attempt_starts_ms.push(1_100)
            }),
            ("recovery_attempt_deadlines_len", RECOVERED, IDENTITY, |e| {
                e.unexpected_recovery_attempt_deadlines_ms.push(3_100)
            }),
            ("recovery_closed_rosters_len", RECOVERED, IDENTITY, |e| {
                e.unexpected_recovery_closed_connection_ids.push(Vec::new())
            }),
            ("recovery_successor_ids_len", RECOVERED, IDENTITY, |e| {
                e.unexpected_recovery_successor_connection_ids.push(None)
            }),
            (
                "recovery_episode_deadline_missing",
                RECOVERED,
                IDENTITY,
                |e| e.unexpected_recovery_episode_deadline_ms = None,
            ),
            (
                "unexpected_no_whole_session_retry",
                RECOVERED,
                IDENTITY,
                |e| e.unexpected_no_whole_session_retry = false,
            ),
            (
                "recovery_attempts_not_monotonic",
                TERMINAL,
                "attempt observations were not monotonic",
                |e| with_recovery_attempts(e, &[2, 1], &[1_000, 1_100], &[3_000, 3_250]),
            ),
            (
                "recovery_starts_not_monotonic",
                TERMINAL,
                "timestamps were not monotonic and bounded",
                |e| with_recovery_attempts(e, &[1, 2], &[1_100, 1_000], &[3_000, 3_250]),
            ),
            (
                "recovery_deadline_before_start",
                TERMINAL,
                "timestamps were not monotonic and bounded",
                |e| with_recovery_attempts(e, &[1, 2], &[1_000, 1_100], &[900, 3_250]),
            ),
            (
                "recovery_attempt_exceeds_episode_deadline",
                TERMINAL,
                "exceeded its immutable episode deadline",
                |e| with_recovery_attempts(e, &[1], &[1_000], &[4_001]),
            ),
            (
                "recovery_attempt_deadline_not_after_start",
                TERMINAL,
                "invalid attempt deadline",
                |e| with_recovery_attempts(e, &[1], &[1_000], &[1_000]),
            ),
            (
                "recovery_retry_attempt_out_of_range",
                TERMINAL,
                "out-of-range retry attempt",
                |e| with_recovery_attempts(e, &[3, 4], &[1_000, 2_000], &[3_000, 3_500]),
            ),
            (
                "recovery_retry_before_backoff",
                TERMINAL,
                "before its protocol backoff elapsed",
                |e| with_recovery_attempts(e, &[1, 2], &[1_000, 1_099], &[3_000, 3_250]),
            ),
            (
                "recovery_adjacent_attempt_after_predecessor_deadline",
                TERMINAL,
                "after its predecessor deadline",
                |e| with_recovery_attempts(e, &[1, 2], &[1_000, 3_001], &[3_000, 3_250]),
            ),
            (
                "recovery_old_generation_mismatch",
                RECOVERED,
                "exact faulted-carrier identity",
                |e| e.unexpected_recovery_old_generation = Some(2),
            ),
            (
                "recovery_old_connection_mismatch",
                RECOVERED,
                "exact faulted-carrier identity",
                |e| e.unexpected_recovery_old_connection_id = Some("connection-2".into()),
            ),
            (
                "first_roster_omits_faulted_carrier",
                RECOVERED,
                "first recovery closure roster omitted",
                |e| {
                    e.unexpected_recovery_closed_connection_ids =
                        vec![vec!["connection-other".into()]]
                },
            ),
            (
                "retry_without_previous_successor_identity",
                TERMINAL,
                "omitted the candidate identity",
                |e| {
                    with_recovery_attempts(e, &[1, 2], &[1_000, 1_100], &[3_000, 3_250]);
                    e.unexpected_recovery_successor_connection_ids[0] = None;
                },
            ),
            (
                "retry_roster_not_bound_to_failed_candidate",
                TERMINAL,
                "not bound to the preceding failed candidate",
                |e| {
                    with_recovery_attempts(e, &[1, 2], &[1_000, 1_100], &[3_000, 3_250]);
                    e.unexpected_recovery_closed_connection_ids[1] =
                        vec!["unrelated-connection".into()];
                },
            ),
            (
                "recovered_same_session_false",
                RECOVERED,
                RECOVERED_INCOMPLETE,
                |e| e.same_session_recovered = false,
            ),
            (
                "recovered_without_recovery_attempts",
                RECOVERED,
                RECOVERED_INCOMPLETE,
                |e| with_recovery_attempts(e, &[], &[], &[]),
            ),
            (
                "recovered_generation_not_higher",
                RECOVERED,
                RECOVERED_INCOMPLETE,
                |e| {
                    e.recovered_generation = Some(3);
                    e.unexpected_recovery_successor_generation = Some(3);
                },
            ),
            (
                "recovered_generation_missing",
                RECOVERED,
                RECOVERED_INCOMPLETE,
                |e| e.recovered_generation = None,
            ),
            (
                "recovered_with_failure_code",
                RECOVERED,
                RECOVERED_INCOMPLETE,
                |e| e.unexpected_failure_code = Some("TRANSPORT_ERROR"),
            ),
            (
                "recovered_stream_identity_unstable",
                RECOVERED,
                RECOVERED_INCOMPLETE,
                |e| e.stream_identity_stable = false,
            ),
            (
                "recovered_with_failure_trigger",
                RECOVERED,
                RECOVERED_INCOMPLETE,
                |e| e.unexpected_failure_trigger = Some("data_reader_closed"),
            ),
            (
                "recovered_reset_reason_wrong",
                RECOVERED,
                RECOVERED_INCOMPLETE,
                |e| e.unexpected_recovery_reset_reason = Some("other_reason"),
            ),
            (
                "recovered_successor_generation_mismatch",
                RECOVERED,
                RECOVERED_INCOMPLETE,
                |e| e.unexpected_recovery_successor_generation = Some(5),
            ),
            (
                "recovered_connection_id_empty",
                RECOVERED,
                RECOVERED_INCOMPLETE,
                |e| {
                    e.recovered_connection_id = Some(String::new());
                    e.unexpected_recovery_successor_connection_id = Some(String::new());
                },
            ),
            (
                "recovered_session_terminal_observed",
                RECOVERED,
                RECOVERED_INCOMPLETE,
                |e| e.post_fault_session_terminal_observed = true,
            ),
            (
                "recovered_live_session_absent",
                RECOVERED,
                RECOVERED_INCOMPLETE,
                |e| e.post_fault_live_session_absent = true,
            ),
            (
                "recovered_catalog_owner_released",
                RECOVERED,
                RECOVERED_INCOMPLETE,
                |e| e.post_fault_catalog_owner_released = true,
            ),
            (
                "recovered_control_route_closed_after_observation",
                RECOVERED,
                RECOVERED_INCOMPLETE,
                |e| e.control_route_open_after_observation = false,
            ),
            (
                "recovered_dispatch_delta_not_one",
                RECOVERED,
                "missing or duplicate post-fault record",
                |e| {
                    e.post_fault_dispatch_delta = 2;
                    e.post_fault_dispatch_count = 5;
                },
            ),
            (
                "recovered_dispatch_count_mismatch",
                RECOVERED,
                "missing or duplicate post-fault record",
                |e| e.post_fault_dispatch_count = 5,
            ),
            (
                "terminal_claims_reset_reason",
                TERMINAL,
                TERMINAL_RESET,
                |e| e.unexpected_recovery_reset_reason = Some("fenced_successor_activated"),
            ),
            (
                "terminal_claims_successor_generation",
                TERMINAL,
                TERMINAL_RESET,
                |e| e.unexpected_recovery_successor_generation = Some(4),
            ),
            (
                "terminal_claims_successor_connection",
                TERMINAL,
                TERMINAL_RESET,
                |e| e.unexpected_recovery_successor_connection_id = Some("connection-4".into()),
            ),
            (
                "terminal_claims_recovered_generation",
                TERMINAL,
                TERMINAL_RESET,
                |e| e.recovered_generation = Some(4),
            ),
            (
                "terminal_claims_recovered_connection",
                TERMINAL,
                TERMINAL_RESET,
                |e| e.recovered_connection_id = Some("connection-4".into()),
            ),
            (
                "terminal_missing_code",
                TERMINAL,
                "omitted its typed terminal code",
                |e| e.unexpected_failure_code = None,
            ),
            (
                "terminal_unapproved_code",
                TERMINAL,
                "unapproved terminal code",
                |e| e.unexpected_failure_code = Some("SOMETHING_ELSE"),
            ),
            (
                "terminal_missing_retryability",
                TERMINAL,
                "omitted its retryability policy",
                |e| e.unexpected_failure_retryable = None,
            ),
            (
                "terminal_missing_trigger",
                TERMINAL,
                "omitted its active-data recovery trigger",
                |e| e.unexpected_failure_trigger = None,
            ),
            (
                "terminal_missing_session_terminal_observation",
                TERMINAL,
                TERMINAL_OBSERVATION,
                |e| e.post_fault_session_terminal_observed = false,
            ),
            (
                "terminal_missing_live_session_absence",
                TERMINAL,
                TERMINAL_OBSERVATION,
                |e| e.post_fault_live_session_absent = false,
            ),
            (
                "terminal_missing_catalog_owner_release",
                TERMINAL,
                TERMINAL_OBSERVATION,
                |e| e.post_fault_catalog_owner_released = false,
            ),
            (
                "terminal_post_fault_dispatch",
                TERMINAL,
                "post-fault dispatch or replay",
                |e| {
                    e.post_fault_dispatch_delta = 1;
                    e.post_fault_dispatch_count = 4;
                },
            ),
            (
                "terminal_post_fault_count_mismatch",
                TERMINAL,
                "post-fault dispatch or replay",
                |e| e.post_fault_dispatch_count = 4,
            ),
            (
                "unknown_outcome",
                RECOVERED,
                "not a typed recovery/failure",
                |e| e.unexpected_outcome = "something_else",
            ),
        ];
        for &(name, outcome, fragment, mutate) in cases {
            let mut value = evidence(outcome);
            mutate(&mut value);
            let diagnostic = assert_failed(validate_i08_rotation_fault_evidence(&value));
            assert!(
                diagnostic.contains(fragment),
                "{name}: expected {fragment:?} in diagnostic {diagnostic}"
            );
        }
    }
}
