//! M7-I08/EC-057/EC-058/IN-09/OG-01 retained-recovery attempt fixture.
//!
//! One real three-relay cluster and one real `tunnel-client` process per
//! episode.  The fixture cuts the CLI's active data carrier at the opaque TCP
//! fanout and then deliberately fails each recovery attachment: every armed
//! candidate route forwards the client's handshake and attachment request to
//! the selected relay (so the owner actually attaches the recovery candidate
//! and issues DATA_READY) while the fixture withholds the response bytes and
//! closes the route only after the owner snapshot proves the attachment.
//! The owner therefore observes a real candidate transport loss for every
//! attempt, which is the retry path the protocol specifies (100 ms before
//! attempt 2, 200 ms before attempt 3, one immutable episode deadline).
//!
//! Two episodes are proved on fresh clusters:
//! * `exhausted_after_three_attempts`: attempts 1..3 all fail, the owner
//!   ends the session with the typed `RECOVERY_CANDIDATE_FAILED` reason and
//!   the CLI reports a typed terminal diagnostic that keeps the original
//!   data-carrier trigger and the attempt number; no fourth carrier, no
//!   whole-session reconnect, no post-fault dispatch, cursors never rewind.
//! * `second_attempt_recovered`: attempt 1 fails, attempt 2 attaches through
//!   a different relay and the same session/stream identities resume with a
//!   fenced-successor reset and exactly one post-fault record dispatched.

use chrono::Utc;
use std::{
    fs,
    net::SocketAddr,
    time::{Duration, Instant},
};
use tempfile::tempdir;
use tokio::time::{sleep, timeout_at};
use tunnel_core::RotationConfig;
use tunnel_protocol::rotation::recovery_retry_delay_ms;
use tunnel_relay::{RelaySessionSnapshot, RelaySnapshot};
use uuid::Uuid;

use crate::{
    FanoutRouteFault, Harness, HarnessError, HarnessOptions, ManagedProcess, OidcTokenOptions,
    Result, RunningHarness,
};

use super::{
    CLEANUP_TIMEOUT, ProductionCluster, STARTUP_TIMEOUT,
    m7_i08_rotation_faults::{
        CliStatus, POLL, RecoveryStatusEvidence, assert_recovery_metadata_clear,
        collect_recovery_status_evidence, latest_status, parse_statuses_from, relay_snapshot_until,
        send_record, session_for_status, shutdown_cli, shutdown_cluster, wait_for_status,
    },
    start_cli_smoke,
};

/// A long scheduled interval keeps the planned rotation timer out of the
/// bounded recovery episode; the handshake/overlap budgets stay the M7
/// accelerated values so the candidate deadlines remain real.
const EPISODE_ROTATION: RotationConfig = RotationConfig {
    interval_seconds: 60,
    handshake_timeout_seconds: 2,
    overlap_seconds: 5,
};
const EPISODE_TIMEOUT: Duration = Duration::from_secs(90);
/// Bound for one recovery episode: the protocol's absolute 30-second episode
/// deadline plus the CLI exit and owner cleanup observation.
const EPISODE_OUTCOME_TIMEOUT: Duration = Duration::from_secs(40);
/// Quiet window after the terminal outcome in which no further carrier may be
/// accepted by the fanout (no reconnect storm, no whole-session retry).
const RECONNECT_QUIET_WINDOW: Duration = Duration::from_millis(1_500);
const MAX_RECOVERY_ATTEMPTS: u64 = 3;
/// TLS 1.3 mutual handshake over the opaque fanout: burst one is the client
/// `ClientHello`; the relay answers with its handshake flight; burst two is
/// the client `Finished` coalesced with the WebSocket upgrade request.  The
/// relay accepts that upgrade and registers (attaches) the recovery candidate
/// before it writes the HTTP 101 response, so withholding every relay->client
/// byte from burst two onward keeps the owner's attachment while the client
/// never completes its data-socket handshake.  The candidate therefore can
/// never reach recovery activation, which is the deterministic candidate loss
/// the retry path consumes.
const ATTACHMENT_CLIENT_BURST: u32 = 2;
const CONTROL_ROUTE_INDEX: u64 = 0;
const INITIAL_DATA_ROUTE_INDEX: u64 = 1;
const OWNER_NODE: &str = "relay-a";
const INGRESS_NODE: &str = "relay-c";
const SOCKET_BOUND: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EpisodeMode {
    /// Fail every attempt (1..=3) and require the typed exhaustion outcome.
    Exhaust,
    /// Fail attempt 1 only and require attempt 2 to recover the session.
    RetrySucceeds,
}

impl EpisodeMode {
    const fn scope(self) -> &'static str {
        match self {
            Self::Exhaust => "exhausted_after_three_attempts",
            Self::RetrySucceeds => "second_attempt_recovered",
        }
    }

    const fn failed_attempts(self) -> u64 {
        match self {
            Self::Exhaust => MAX_RECOVERY_ATTEMPTS,
            Self::RetrySucceeds => 1,
        }
    }
}

/// Owner-side retained sequence cursors for the admitted stream at one
/// observation point.  Values are sequence counters only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CursorSample {
    pub label: &'static str,
    pub last_emitted_relay_to_connector: u64,
    pub peer_acked_relay_to_connector: u64,
    pub recv_contiguous_connector_to_relay: u64,
    pub delivered_contiguous_connector_to_relay: u64,
}

impl CursorSample {
    fn never_rewound_from(&self, previous: &CursorSample) -> bool {
        self.last_emitted_relay_to_connector >= previous.last_emitted_relay_to_connector
            && self.peer_acked_relay_to_connector >= previous.peer_acked_relay_to_connector
            && self.recv_contiguous_connector_to_relay
                >= previous.recv_contiguous_connector_to_relay
            && self.delivered_contiguous_connector_to_relay
                >= previous.delivered_contiguous_connector_to_relay
    }
}

/// Per-attempt owner/fixture observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptObservation {
    pub attempt: u64,
    pub candidate_route_index: u64,
    pub candidate_relay: String,
    pub candidate_generation: u64,
    pub candidate_connection_id: String,
    /// The owner reserved the candidate socket (recovery phase, two sockets)
    /// at the exact candidate identity before the fixture closed the route.
    pub attached_at_owner: bool,
    pub owner_sockets_at_attach: u8,
    pub owner_recovery_reason: Option<String>,
    /// The fanout withheld every response byte after the client's
    /// attachment burst, so the loss is fixture-controlled.
    pub held_by_fixture: bool,
    pub client_bursts_at_close: u32,
    pub closed_by_fixture: bool,
    /// The owner released the candidate (socket count back to one) after
    /// the fixture close, proving it observed the loss for this attempt.
    pub owner_released_candidate: bool,
}

/// Payload-free evidence for one recovery episode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryEpisodeEvidence {
    pub scope: &'static str,
    pub relay_count: usize,
    pub actual_cli_process: bool,
    pub owner_relay: &'static str,
    pub ingress_relay: &'static str,
    pub session_id: String,
    pub epoch: u64,
    pub stream_id: u64,
    pub tunnel_operation_id: String,
    pub fault_route_index: u64,
    pub fault_relay: String,
    pub fault_generation: u64,
    pub fault_connection_id: String,
    pub active_carrier_closed: bool,
    pub control_route_remained_open: bool,
    /// Bounded in-session recovery metadata from the CLI status stream.
    pub attempts: Vec<u64>,
    pub attempt_starts_ms: Vec<u64>,
    pub attempt_deadlines_ms: Vec<u64>,
    pub episode_deadline_ms: Option<u64>,
    pub closed_connection_ids: Vec<Vec<String>>,
    pub successor_connection_ids: Vec<Option<String>>,
    pub old_generation: Option<u64>,
    pub old_connection_id: Option<String>,
    pub failed_attempts: Vec<AttemptObservation>,
    pub cursor_samples: Vec<CursorSample>,
    pub cursors_never_rewound: bool,
    pub outcome: &'static str,
    pub failure_code: Option<&'static str>,
    pub failure_retryable: Option<bool>,
    pub failure_trigger: Option<&'static str>,
    pub failure_generation: Option<u64>,
    pub failure_attempt: Option<u64>,
    pub owner_terminal_reason: Option<String>,
    pub live_session_absent: bool,
    pub catalog_owner_released: bool,
    pub reset_reason: Option<&'static str>,
    pub recovered_generation: Option<u64>,
    pub recovered_connection_id: Option<String>,
    pub recovered_route_index: Option<u64>,
    pub recovered_relay: Option<String>,
    pub pre_fault_dispatch_count: u64,
    pub post_fault_dispatch_count: u64,
    pub post_fault_dispatch_delta: u64,
    pub ordered_records: u64,
    pub fanout_accepted_total: u64,
    pub fanout_accepted_after_quiet_window: u64,
    pub fanout_peak_open: usize,
    pub owner_socket_high_water: u8,
    pub cli_pid_stable: bool,
    pub cli_exit_success: Option<bool>,
    pub control_socket_stable: bool,
    pub cleanup_joined: bool,
    pub elapsed_ms: u64,
}

impl RecoveryEpisodeEvidence {
    /// One-line payload-free summary for the gate log.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "scope={} relays={} cli={} owner={} ingress={} session={} epoch={} stream={} operation={} fault_route={} fault_relay={} fault_generation={} fault_connection={} fault_closed={} control_route_open={} attempts={:?} attempt_starts_ms={:?} attempt_deadlines_ms={:?} episode_deadline_ms={:?} closed_rosters={:?} candidate_routes={:?} candidate_relays={:?} attached_at_owner={:?} held={:?} closed_by_fixture={:?} owner_released={:?} cursor_samples={} cursors_never_rewound={} outcome={} failure_code={:?} failure_retryable={:?} failure_trigger={:?} failure_generation={:?} failure_attempt={:?} owner_terminal_reason={:?} live_session_absent={} owner_released_catalog={} reset_reason={:?} recovered_generation={:?} recovered_route={:?} recovered_relay={:?} pre_dispatch={} post_dispatch={} dispatch_delta={} ordered_records={} fanout_accepted={} fanout_accepted_after_quiet={} fanout_peak_open={} owner_socket_high_water={} pid_stable={} cli_exit_success={:?} control_stable={} cleanup_joined={} elapsed_ms={}",
            self.scope,
            self.relay_count,
            self.actual_cli_process,
            self.owner_relay,
            self.ingress_relay,
            self.session_id,
            self.epoch,
            self.stream_id,
            self.tunnel_operation_id,
            self.fault_route_index,
            self.fault_relay,
            self.fault_generation,
            self.fault_connection_id,
            self.active_carrier_closed,
            self.control_route_remained_open,
            self.attempts,
            self.attempt_starts_ms,
            self.attempt_deadlines_ms,
            self.episode_deadline_ms,
            self.closed_connection_ids,
            self.failed_attempts
                .iter()
                .map(|attempt| attempt.candidate_route_index)
                .collect::<Vec<_>>(),
            self.failed_attempts
                .iter()
                .map(|attempt| attempt.candidate_relay.as_str())
                .collect::<Vec<_>>(),
            self.failed_attempts
                .iter()
                .map(|attempt| attempt.attached_at_owner)
                .collect::<Vec<_>>(),
            self.failed_attempts
                .iter()
                .map(|attempt| attempt.held_by_fixture)
                .collect::<Vec<_>>(),
            self.failed_attempts
                .iter()
                .map(|attempt| attempt.closed_by_fixture)
                .collect::<Vec<_>>(),
            self.failed_attempts
                .iter()
                .map(|attempt| attempt.owner_released_candidate)
                .collect::<Vec<_>>(),
            self.cursor_samples.len(),
            self.cursors_never_rewound,
            self.outcome,
            self.failure_code,
            self.failure_retryable,
            self.failure_trigger,
            self.failure_generation,
            self.failure_attempt,
            self.owner_terminal_reason,
            self.live_session_absent,
            self.catalog_owner_released,
            self.reset_reason,
            self.recovered_generation,
            self.recovered_route_index,
            self.recovered_relay,
            self.pre_fault_dispatch_count,
            self.post_fault_dispatch_count,
            self.post_fault_dispatch_delta,
            self.ordered_records,
            self.fanout_accepted_total,
            self.fanout_accepted_after_quiet_window,
            self.fanout_peak_open,
            self.owner_socket_high_water,
            self.cli_pid_stable,
            self.cli_exit_success,
            self.control_socket_stable,
            self.cleanup_joined,
            self.elapsed_ms,
        )
    }
}

/// Evidence for both episodes of the gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct I08RecoveryAttemptEvidence {
    pub exhaustion: RecoveryEpisodeEvidence,
    pub retry_success: RecoveryEpisodeEvidence,
    pub cleanup_joined: bool,
    pub elapsed_ms: u64,
}

fn incomplete(name: &str) -> HarnessError {
    HarnessError::Process(format!(
        "M7-I08 recovery attempt evidence is incomplete: {name}"
    ))
}

/// Strict validation shared by both episodes, then the per-scope outcome.
pub fn validate_recovery_episode_evidence(evidence: &RecoveryEpisodeEvidence) -> Result<()> {
    let mode = match evidence.scope {
        "exhausted_after_three_attempts" => EpisodeMode::Exhaust,
        "second_attempt_recovered" => EpisodeMode::RetrySucceeds,
        other => {
            return Err(HarnessError::Process(format!(
                "M7-I08 recovery attempt evidence has unexpected scope {other:?}"
            )));
        }
    };
    if evidence.relay_count != 3 || !evidence.actual_cli_process {
        return Err(incomplete("three relays and a real CLI"));
    }
    if evidence.owner_relay != OWNER_NODE || evidence.ingress_relay != INGRESS_NODE {
        return Err(incomplete("owner/ingress relay roles"));
    }
    let required = [
        ("active_carrier_closed", evidence.active_carrier_closed),
        (
            "control_route_remained_open",
            evidence.control_route_remained_open,
        ),
        ("cursors_never_rewound", evidence.cursors_never_rewound),
        ("cli_pid_stable", evidence.cli_pid_stable),
        ("control_socket_stable", evidence.control_socket_stable),
        ("cleanup_joined", evidence.cleanup_joined),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, value)| !value) {
        return Err(incomplete(name));
    }
    if evidence.session_id.is_empty()
        || evidence.epoch == 0
        || evidence.stream_id == 0
        || evidence.tunnel_operation_id.is_empty()
        || evidence.fault_route_index != INITIAL_DATA_ROUTE_INDEX
        || evidence.fault_relay.is_empty()
        || evidence.fault_generation == 0
        || evidence.fault_connection_id.is_empty()
        || evidence.pre_fault_dispatch_count == 0
        || evidence.ordered_records == 0
    {
        return Err(incomplete("stable session/stream/fault identity"));
    }
    let failed = mode.failed_attempts();
    let expected_attempts = match mode {
        EpisodeMode::Exhaust => (1..=MAX_RECOVERY_ATTEMPTS).collect::<Vec<_>>(),
        EpisodeMode::RetrySucceeds => vec![1, 2],
    };
    if evidence.attempts != expected_attempts {
        return Err(HarnessError::Process(format!(
            "M7-I08 recovery attempts {:?} did not match the required {:?}",
            evidence.attempts, expected_attempts
        )));
    }
    let count = evidence.attempts.len();
    if evidence.attempt_starts_ms.len() != count
        || evidence.attempt_deadlines_ms.len() != count
        || evidence.closed_connection_ids.len() != count
        || evidence.successor_connection_ids.len() != count
        || evidence
            .successor_connection_ids
            .iter()
            .any(Option::is_none)
    {
        return Err(incomplete("per-attempt status metadata"));
    }
    let Some(episode_deadline_ms) = evidence.episode_deadline_ms else {
        return Err(incomplete("immutable episode deadline"));
    };
    // EC-058: one absolute episode deadline; every attempt deadline stays
    // inside it, starts are strictly monotonic, no attempt restarts the
    // clock (a later attempt never has a later deadline than the episode
    // and never an earlier deadline than its predecessor's start).
    let first_start = evidence.attempt_starts_ms[0];
    if episode_deadline_ms <= first_start
        || episode_deadline_ms.saturating_sub(first_start)
            > tunnel_protocol::rotation::MAX_RECOVERY_TIMEOUT_MS
    {
        return Err(HarnessError::Process(
            "M7-I08 recovery episode deadline was not one bounded absolute budget".into(),
        ));
    }
    for index in 0..count {
        let start = evidence.attempt_starts_ms[index];
        let deadline = evidence.attempt_deadlines_ms[index];
        if deadline <= start || deadline > episode_deadline_ms {
            return Err(HarnessError::Process(format!(
                "M7-I08 recovery attempt {} deadline was outside its episode budget",
                evidence.attempts[index]
            )));
        }
        if index > 0 {
            let previous_start = evidence.attempt_starts_ms[index - 1];
            let previous_deadline = evidence.attempt_deadlines_ms[index - 1];
            if start <= previous_start || deadline < previous_deadline || start > previous_deadline
            {
                return Err(HarnessError::Process(
                    "M7-I08 recovery attempt deadlines restarted or regressed".into(),
                ));
            }
            let Some(required_gap) = recovery_retry_delay_ms(evidence.attempts[index - 1]) else {
                return Err(HarnessError::Process(
                    "M7-I08 recovery attempt exceeded the protocol retry table".into(),
                ));
            };
            if start.saturating_sub(previous_start) < required_gap {
                return Err(HarnessError::Process(
                    "M7-I08 recovery retry started before its protocol backoff elapsed".into(),
                ));
            }
        }
    }
    if evidence.old_generation != Some(evidence.fault_generation)
        || evidence.old_connection_id.as_deref() != Some(evidence.fault_connection_id.as_str())
    {
        return Err(incomplete("exact faulted-carrier anchor"));
    }
    if !evidence.closed_connection_ids[0]
        .iter()
        .any(|connection_id| connection_id == &evidence.fault_connection_id)
    {
        return Err(HarnessError::Process(
            "M7-I08 first recovery closure roster omitted the faulted active carrier".into(),
        ));
    }
    for index in 1..count {
        let previous_successor = evidence.successor_connection_ids[index - 1]
            .clone()
            .ok_or_else(|| incomplete("previous candidate identity"))?;
        if evidence.closed_connection_ids[index] != vec![previous_successor] {
            return Err(HarnessError::Process(
                "M7-I08 recovery retry closure roster was not bound to the failed candidate".into(),
            ));
        }
    }
    // Every failed attempt must be a fixture-controlled loss of an actually
    // attached candidate on the exact fanout route, observed by the owner.
    if evidence.failed_attempts.len() != usize::try_from(failed).unwrap_or(usize::MAX) {
        return Err(incomplete("failed attempt observations"));
    }
    for (index, observation) in evidence.failed_attempts.iter().enumerate() {
        let attempt = evidence.attempts[index];
        let expected_route = INITIAL_DATA_ROUTE_INDEX + attempt;
        if observation.attempt != attempt
            || observation.candidate_route_index != expected_route
            || observation.candidate_relay.is_empty()
            || observation.candidate_relay == OWNER_NODE
            || observation.candidate_generation <= evidence.fault_generation
            || Some(observation.candidate_connection_id.as_str())
                != evidence.successor_connection_ids[index].as_deref()
            || !observation.attached_at_owner
            || observation.owner_sockets_at_attach != 2
            || !observation.held_by_fixture
            || observation.client_bursts_at_close < ATTACHMENT_CLIENT_BURST
            || !observation.closed_by_fixture
            || !observation.owner_released_candidate
        {
            return Err(HarnessError::Process(format!(
                "M7-I08 recovery attempt {attempt} was not a fixture-controlled loss of an attached candidate"
            )));
        }
        let expected_reason = if attempt == 1 {
            "old_transport_lost"
        } else {
            "candidate_transport_lost"
        };
        if observation.owner_recovery_reason.as_deref() != Some(expected_reason) {
            return Err(HarnessError::Process(format!(
                "M7-I08 recovery attempt {attempt} owner reason was not {expected_reason}"
            )));
        }
        if index > 0
            && observation.candidate_generation
                <= evidence.failed_attempts[index - 1].candidate_generation
        {
            return Err(HarnessError::Process(
                "M7-I08 recovery candidate generations were not monotonic".into(),
            ));
        }
    }
    if evidence.cursor_samples.len() < 2
        || evidence
            .cursor_samples
            .windows(2)
            .any(|window| !window[1].never_rewound_from(&window[0]))
    {
        return Err(HarnessError::Process(
            "M7-I08 retained cursors rewound or were not sampled across the episode".into(),
        ));
    }
    if evidence.fanout_peak_open > usize::from(SOCKET_BOUND)
        || evidence.owner_socket_high_water > SOCKET_BOUND
        || evidence.owner_socket_high_water == 0
    {
        return Err(HarnessError::Process(
            "M7-I08 recovery exceeded the control-plus-two-data socket bound".into(),
        ));
    }
    // Control(0) + initial data(1) + one carrier per attempt: nothing else.
    let expected_accepted = 2 + count as u64;
    if evidence.fanout_accepted_total != expected_accepted
        || evidence.fanout_accepted_after_quiet_window != expected_accepted
    {
        return Err(HarnessError::Process(format!(
            "M7-I08 fanout accepted {} carriers ({} after the quiet window); expected exactly {expected_accepted}",
            evidence.fanout_accepted_total, evidence.fanout_accepted_after_quiet_window
        )));
    }
    match mode {
        EpisodeMode::Exhaust => {
            // Itemize the terminal requirements so a mismatch names the exact
            // field rather than collapsing into one opaque rejection.
            let terminal = [
                ("outcome", evidence.outcome == "typed_terminal_failure"),
                // The owner ends the exhausted episode by closing the
                // authenticated control socket with RECOVERY_CANDIDATE_FAILED,
                // so the connector's terminal result is its typed retained
                // recovery transport failure.  `parse_terminal_failure` has
                // already required the closed diagnostic shape around this
                // code, so accepting only TRANSPORT_ERROR stays exact.
                (
                    "failure_code",
                    evidence.failure_code == Some("TRANSPORT_ERROR"),
                ),
                (
                    "failure_retryable",
                    evidence.failure_retryable == Some(true),
                ),
                (
                    "failure_trigger",
                    matches!(
                        evidence.failure_trigger,
                        Some("data_reader_closed" | "data_writer_closed" | "data_writer_failed")
                    ),
                ),
                (
                    "failure_generation",
                    evidence.failure_generation == Some(evidence.fault_generation),
                ),
                (
                    "failure_attempt",
                    evidence.failure_attempt == Some(MAX_RECOVERY_ATTEMPTS),
                ),
                (
                    "owner_terminal_reason",
                    evidence.owner_terminal_reason.as_deref() == Some("RECOVERY_CANDIDATE_FAILED"),
                ),
                ("live_session_absent", evidence.live_session_absent),
                ("catalog_owner_released", evidence.catalog_owner_released),
                ("no_reset_reason", evidence.reset_reason.is_none()),
                (
                    "no_recovered_identity",
                    evidence.recovered_generation.is_none()
                        && evidence.recovered_connection_id.is_none()
                        && evidence.recovered_route_index.is_none()
                        && evidence.recovered_relay.is_none(),
                ),
                ("cli_exit_failed", evidence.cli_exit_success == Some(false)),
            ];
            if let Some((name, false)) = terminal.into_iter().find(|(_, value)| !value) {
                return Err(HarnessError::Process(format!(
                    "M7-I08 exhaustion did not end in the typed terminal failure after attempt 3: {name} (code={:?} retryable={:?} trigger={:?} generation={:?} attempt={:?} owner_reason={:?} exit_success={:?})",
                    evidence.failure_code,
                    evidence.failure_retryable,
                    evidence.failure_trigger,
                    evidence.failure_generation,
                    evidence.failure_attempt,
                    evidence.owner_terminal_reason,
                    evidence.cli_exit_success,
                )));
            }
            if evidence.post_fault_dispatch_delta != 0
                || evidence.post_fault_dispatch_count != evidence.pre_fault_dispatch_count
                || evidence.ordered_records != evidence.pre_fault_dispatch_count
            {
                return Err(HarnessError::Process(
                    "M7-I08 exhaustion replayed or dispatched an ambiguous effect".into(),
                ));
            }
        }
        EpisodeMode::RetrySucceeds => {
            let Some(recovered_generation) = evidence.recovered_generation else {
                return Err(incomplete("recovered generation"));
            };
            let Some(last_failed) = evidence.failed_attempts.last() else {
                return Err(incomplete("failed attempt one"));
            };
            if evidence.outcome != "recovered_same_session"
                || evidence.failure_code.is_some()
                || evidence.failure_retryable.is_some()
                || evidence.failure_trigger.is_some()
                || evidence.failure_generation.is_some()
                || evidence.failure_attempt.is_some()
                || evidence.owner_terminal_reason.is_some()
                || evidence.live_session_absent
                || evidence.catalog_owner_released
                || evidence.reset_reason != Some("fenced_successor_activated")
                || recovered_generation <= last_failed.candidate_generation
                || evidence.recovered_connection_id.as_deref()
                    != evidence.successor_connection_ids[1].as_deref()
                || evidence.recovered_route_index != Some(INITIAL_DATA_ROUTE_INDEX + 2)
                || evidence
                    .recovered_relay
                    .as_deref()
                    .is_none_or(|relay| relay.is_empty() || relay == OWNER_NODE)
                || evidence.cli_exit_success.is_some()
            {
                return Err(HarnessError::Process(
                    "M7-I08 second-attempt recovery evidence was incomplete or mixed with failure"
                        .into(),
                ));
            }
            if evidence.post_fault_dispatch_delta != 1
                || evidence.post_fault_dispatch_count
                    != evidence.pre_fault_dispatch_count.saturating_add(1)
                || evidence.ordered_records != evidence.post_fault_dispatch_count
            {
                return Err(HarnessError::Process(
                    "M7-I08 second-attempt recovery dispatched a missing or duplicate record"
                        .into(),
                ));
            }
        }
    }
    Ok(())
}

/// Validate both episodes and their pairing.
pub fn validate_i08_recovery_attempt_evidence(evidence: &I08RecoveryAttemptEvidence) -> Result<()> {
    validate_recovery_episode_evidence(&evidence.exhaustion)?;
    validate_recovery_episode_evidence(&evidence.retry_success)?;
    if evidence.exhaustion.scope != "exhausted_after_three_attempts"
        || evidence.retry_success.scope != "second_attempt_recovered"
    {
        return Err(incomplete("both episode scopes"));
    }
    if !evidence.cleanup_joined {
        return Err(incomplete("cleanup_joined"));
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct TerminalFailure {
    code: &'static str,
    retryable: Option<bool>,
    trigger: &'static str,
    generation: u64,
    attempt: u64,
}

/// Parse the CLI's typed terminal diagnostic emitted after the fault.  The
/// message must be the closed retained-recovery diagnostic that names the
/// original data-carrier trigger, the active role, the faulted generation
/// and the attempt number; any other failure line is not accepted.
fn parse_terminal_failure(
    process: &ManagedProcess,
    stdout_offset: usize,
) -> Option<TerminalFailure> {
    const PREFIX: &str =
        "retained recovery failed: control socket closed during retained recovery; ";
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
        let error = value.get("error")?;
        let code = match error.get("code").and_then(serde_json::Value::as_str) {
            Some("SESSION_CLOSED") => "SESSION_CLOSED",
            Some("TRANSPORT_ERROR") => "TRANSPORT_ERROR",
            _ => return None,
        };
        let message = error
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let metadata = message.strip_prefix(PREFIX)?;
        let mut trigger = None;
        let mut role = None;
        let mut generation = None;
        let mut attempt = None;
        for field in metadata.split("; ") {
            if let Some(value) = field.strip_prefix("recovery_trigger=") {
                trigger = match value {
                    "data_reader_closed" => Some("data_reader_closed"),
                    "data_writer_closed" => Some("data_writer_closed"),
                    "data_writer_failed" => Some("data_writer_failed"),
                    _ => return None,
                };
            } else if let Some(value) = field.strip_prefix("recovery_role=") {
                role = Some(value);
            } else if let Some(value) = field.strip_prefix("recovery_generation=") {
                generation = value.parse::<u64>().ok();
            } else if let Some(value) = field.strip_prefix("recovery_attempt=") {
                attempt = value.parse::<u64>().ok();
            } else {
                return None;
            }
        }
        if role != Some("active") {
            return None;
        }
        return Some(TerminalFailure {
            code,
            retryable: error.get("retryable").and_then(serde_json::Value::as_bool),
            trigger: trigger?,
            generation: generation?,
            attempt: attempt?,
        });
    }
    None
}

/// Bounded, payload-free description of the CLI's last typed diagnostic and
/// status identity for a failed scenario.
fn cli_context(process: &ManagedProcess) -> String {
    let stdout = process.stdout();
    let mut first_error = None;
    let mut last_error = None;
    let mut last_status = None;
    for line in stdout.split(|byte| *byte == b'\n') {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        match value.get("command").and_then(serde_json::Value::as_str) {
            Some("connect")
                if value.get("ok").and_then(serde_json::Value::as_bool) == Some(false) =>
            {
                let error = value.get("error");
                let described = format!(
                    "code={:?} message={:?}",
                    error
                        .and_then(|error| error.get("code"))
                        .and_then(serde_json::Value::as_str),
                    error
                        .and_then(|error| error.get("message"))
                        .and_then(serde_json::Value::as_str),
                );
                // The first failure is the root cause; later lines are often
                // only the supervisor noticing that the actor already ended.
                if first_error.is_none() {
                    first_error = Some(described.clone());
                }
                last_error = Some(described);
            }
            Some("connect-status") => {
                let result = value.get("result");
                last_status = Some(format!(
                    "phase={:?} generation={:?} recovery_attempt={:?} reset={:?}",
                    result
                        .and_then(|result| result.get("phase"))
                        .and_then(serde_json::Value::as_str),
                    result
                        .and_then(|result| result.get("generation"))
                        .and_then(serde_json::Value::as_u64),
                    result
                        .and_then(|result| result.get("recovery_attempt"))
                        .and_then(serde_json::Value::as_u64),
                    result
                        .and_then(|result| result.get("recovery_reset_reason"))
                        .and_then(serde_json::Value::as_str),
                ));
            }
            _ => {}
        }
    }
    format!(
        "cli_first_error=[{}] cli_last_error=[{}] cli_last_status=[{}] cli_stderr_bytes={}",
        first_error.unwrap_or_else(|| "none".to_owned()),
        last_error.unwrap_or_else(|| "none".to_owned()),
        last_status.unwrap_or_else(|| "none".to_owned()),
        process.stderr().len(),
    )
}

fn cursor_sample(
    label: &'static str,
    session: &RelaySessionSnapshot,
    stream_id: u64,
) -> Result<CursorSample> {
    let stream = session
        .streams
        .iter()
        .find(|stream| stream.stream_id == stream_id)
        .ok_or_else(|| {
            HarnessError::Process(format!(
                "M7-I08 owner snapshot lost the admitted stream at {label}"
            ))
        })?;
    Ok(CursorSample {
        label,
        last_emitted_relay_to_connector: stream.last_emitted_relay_to_connector,
        peer_acked_relay_to_connector: stream.peer_acked_relay_to_connector,
        recv_contiguous_connector_to_relay: stream.recv_contiguous_connector_to_relay,
        delivered_contiguous_connector_to_relay: stream.delivered_contiguous_connector_to_relay,
    })
}

fn relay_device_addr(cluster: &ProductionCluster, node_id: &str) -> Result<SocketAddr> {
    cluster
        .relay(node_id)?
        .running
        .as_ref()
        .map(|running| running.device_addr)
        .ok_or_else(|| {
            HarnessError::Process(format!("{node_id} listener disappeared during the episode"))
        })
}

fn relay_name_for_target(cluster: &ProductionCluster, target: SocketAddr) -> Result<String> {
    for relay in &cluster.relays {
        if relay
            .running
            .as_ref()
            .is_some_and(|running| running.device_addr == target)
        {
            return Ok(relay.node_id.clone());
        }
    }
    Err(HarnessError::Process(
        "fanout route target did not match any running relay device listener".into(),
    ))
}

async fn current_owner_token(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    deadline: Instant,
) -> Result<Option<tunnel_catalog::OwnerToken>> {
    let owner = timeout_at(
        tokio::time::Instant::from_std(deadline),
        cluster
            .catalog
            .current_owner(tenant_id, device_id, Utc::now()),
    )
    .await
    .map_err(|_| HarnessError::Timeout("M7-I08 catalog owner sample exceeded its deadline".into()))?
    .map_err(|error| HarnessError::Redis(format!("M7-I08 catalog owner sample: {error}")))?;
    Ok(owner.map(|claim| claim.token))
}

/// Wait for the CLI status stream to report the given recovery attempt with
/// a successor identity, returning that status.
async fn wait_for_attempt_status(
    process: &mut ManagedProcess,
    stdout_offset: usize,
    attempt: u64,
    deadline: Instant,
) -> Result<CliStatus> {
    loop {
        if let Some(status) = parse_statuses_from(process, stdout_offset)?
            .into_iter()
            .rfind(|status| status.recovery_attempt == Some(attempt))
            && status.recovery_successor_connection_id.is_some()
        {
            return Ok(status);
        }
        if let Some(exit) = process.try_wait()? {
            return Err(HarnessError::Process(format!(
                "CLI exited before recovery attempt {attempt} was reported: {exit}"
            )));
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "recovery attempt {attempt} was not reported before its deadline"
            )));
        }
        sleep(POLL).await;
    }
}

struct AttachedCandidate {
    session: RelaySessionSnapshot,
    snapshot: RelaySnapshot,
}

/// Wait until the owner has physically reserved the exact recovery candidate
/// (recovering phase, control plus one allocated candidate socket).
async fn wait_for_owner_candidate_attach(
    cluster: &ProductionCluster,
    status: &CliStatus,
    device_id: Uuid,
    candidate_connection_id: &str,
    candidate_generation: u64,
    deadline: Instant,
) -> Result<AttachedCandidate> {
    loop {
        let snapshot = relay_snapshot_until(cluster, OWNER_NODE, deadline).await?;
        let session = match session_for_status(snapshot.clone(), status, device_id) {
            Ok(session) => session,
            Err(_) => {
                let reason = snapshot
                    .session_terminal_events
                    .iter()
                    .rev()
                    .find(|event| {
                        event.session_id == status.session_id && event.epoch == status.epoch
                    })
                    .map(|event| event.reason);
                return Err(HarnessError::Process(format!(
                    "owner closed the session before recovery candidate generation {candidate_generation} attached: terminal_reason={reason:?}"
                )));
            }
        };
        if session.phase == "recovering"
            && session.candidate_connection_id.as_deref() == Some(candidate_connection_id)
            && session.candidate_generation == Some(candidate_generation)
            && session.sockets == 2
        {
            return Ok(AttachedCandidate { session, snapshot });
        }
        if session.phase != "recovering" && session.phase != "active" {
            return Err(HarnessError::Process(format!(
                "owner left recovery through phase {:?} before the candidate attached",
                session.phase
            )));
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "owner did not reserve the recovery candidate before its deadline".into(),
            ));
        }
        sleep(Duration::from_millis(10)).await;
    }
}

/// Wait until the owner has released the closed candidate: the session is
/// either still recovering with only the control socket allocated, closed,
/// or already on a later candidate identity.
async fn wait_for_owner_candidate_release(
    cluster: &ProductionCluster,
    status: &CliStatus,
    device_id: Uuid,
    candidate_connection_id: &str,
    deadline: Instant,
) -> Result<bool> {
    loop {
        let snapshot = relay_snapshot_until(cluster, OWNER_NODE, deadline).await?;
        let Ok(session) = session_for_status(snapshot, status, device_id) else {
            return Ok(true);
        };
        let released = session.candidate_connection_id.as_deref() != Some(candidate_connection_id)
            || (session.phase == "recovering" && session.sockets == 1);
        if released {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        sleep(Duration::from_millis(10)).await;
    }
}

struct EpisodeContext<'a> {
    cluster: &'a mut ProductionCluster,
    harness: &'a RunningHarness,
    mode: EpisodeMode,
    deadline: Instant,
    cleanup_deadline: Instant,
}

async fn run_episode(context: EpisodeContext<'_>) -> Result<RecoveryEpisodeEvidence> {
    let EpisodeContext {
        cluster,
        harness,
        mode,
        deadline,
        cleanup_deadline,
    } = context;
    let started = Instant::now();
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(
            "M7-I08 recovery attempt fixture requires exactly three relays".into(),
        ));
    }
    let device = harness.topology.devices_a.first().ok_or_else(|| {
        HarnessError::InvalidInput("M7-I08 recovery attempt has no device".into())
    })?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| {
            HarnessError::InvalidInput("M7-I08 recovery attempt has no service".into())
        })?;
    let canary = format!("m7-i08-recovery:{}:{}", mode.scope(), device.id);
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
    profile.config.rotation = EPISODE_ROTATION;
    profile.config.validate().map_err(|error| {
        HarnessError::InvalidInput(format!("M7-I08 recovery attempt profile: {error}"))
    })?;
    let mut config_text = fs::read_to_string(&profile.config_path).map_err(HarnessError::Io)?;
    config_text.push_str(&format!(
        "\n[rotation]\ninterval_seconds = {}\nhandshake_timeout_seconds = {}\noverlap_seconds = {}\n",
        EPISODE_ROTATION.interval_seconds,
        EPISODE_ROTATION.handshake_timeout_seconds,
        EPISODE_ROTATION.overlap_seconds
    ));
    fs::write(&profile.config_path, config_text).map_err(HarnessError::Io)?;
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(180),
            ..OidcTokenOptions::default()
        },
    )?;
    // Arm every deliberately failed candidate before the CLI can dial: the
    // fanout accept order is control(0), initial data(1), then one route per
    // recovery attempt.
    for attempt in 1..=mode.failed_attempts() {
        cluster.device_fanout.set_route_fault(
            INITIAL_DATA_ROUTE_INDEX + attempt,
            FanoutRouteFault::HoldTargetToClientAfterClientFlight(ATTACHMENT_CLIENT_BURST),
        )?;
    }
    let ingress_addr = cluster.relay(INGRESS_NODE)?.consumer_addr()?;
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
    let scenario: Result<RecoveryEpisodeEvidence> = async {
        let initial = wait_for_status(&mut process, deadline).await?;
        if initial.phase != "active"
            || initial.rotations_completed != 0
            || initial.generation == 0
            || initial.active_connection_id.is_empty()
        {
            return Err(HarnessError::Process(
                "M7-I08 recovery attempt did not start from an active zero-rotation status".into(),
            ));
        }
        assert_recovery_metadata_clear(&initial, "initial")?;
        let expected_owner = current_owner_token(cluster, device.tenant_id, device.id, deadline)
            .await?
            .ok_or_else(|| HarnessError::Process("M7-I08 owner claim is missing".into()))?;
        if expected_owner.node_id != OWNER_NODE
            || expected_owner.tenant_id != device.tenant_id
            || expected_owner.device_id != device.id
            || expected_owner.session_id != initial.session_id
            || expected_owner.epoch != initial.epoch
        {
            return Err(HarnessError::Process(
                "M7-I08 recovery attempt did not start with the relay-a owner/session".into(),
            ));
        }
        let owner_addr = relay_device_addr(cluster, OWNER_NODE)?;
        let mut owner_session = loop {
            let snapshot = relay_snapshot_until(cluster, OWNER_NODE, deadline).await?;
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
                    "M7-I08 recovery attempt stream admission exceeded its deadline".into(),
                ));
            }
            sleep(POLL).await;
        };
        if owner_session.phase != "active"
            || owner_session.candidate_generation.is_some()
            || owner_session.active_generation != initial.generation
            || owner_session.active_connection_id != initial.active_connection_id
        {
            return Err(HarnessError::Process(
                "M7-I08 owner snapshot was not an active zero-rotation baseline".into(),
            ));
        }
        let stream_snapshot = owner_session
            .streams
            .iter()
            .find(|stream| !stream.terminal)
            .ok_or_else(|| HarnessError::Process("M7-I08 stream was not admitted".into()))?;
        let stream_id = stream_snapshot.stream_id;
        let operation_id = stream_snapshot.operation_id.clone();
        let initial_routes = cluster.device_fanout.diagnostics();
        let control_route = initial_routes
            .open
            .iter()
            .find(|route| route.index == CONTROL_ROUTE_INDEX && route.target == owner_addr)
            .copied()
            .ok_or_else(|| {
                HarnessError::Process("M7-I08 control route did not select the owner".into())
            })?;
        let data_route = initial_routes
            .open
            .iter()
            .find(|route| route.index == INITIAL_DATA_ROUTE_INDEX)
            .copied()
            .ok_or_else(|| {
                HarnessError::Process("M7-I08 initial data route was not open".into())
            })?;
        if initial_routes.accepted != 2 || initial_routes.open.len() != 2 {
            return Err(HarnessError::Process(
                "M7-I08 fanout did not hold exactly the control and initial data routes".into(),
            ));
        }
        let fault_relay = relay_name_for_target(cluster, data_route.target)?;
        if fault_relay == OWNER_NODE {
            return Err(HarnessError::Process(
                "M7-I08 initial data route unexpectedly selected the owner".into(),
            ));
        }
        send_record(&mut stream, 0, canary.as_bytes(), deadline).await?;
        let mut ordered_records = 1_u64;
        let pre_fault_snapshot = relay_snapshot_until(cluster, OWNER_NODE, deadline).await?;
        owner_session = session_for_status(pre_fault_snapshot.clone(), &initial, device.id)?;
        let pre_fault_dispatch_count = pre_fault_snapshot.lifetime_application_dispatches;
        if pre_fault_dispatch_count != ordered_records {
            return Err(HarnessError::Process(
                "M7-I08 pre-fault dispatch counter did not match the ordered record".into(),
            ));
        }
        let mut cursor_samples = vec![cursor_sample("pre_fault", &owner_session, stream_id)?];
        let mut owner_socket_high_water = owner_session.sockets;

        // Fault: cut the active data carrier at the fanout while the control
        // route to the owner stays open.
        let fault_stdout_offset = process.stdout().len();
        if !cluster.device_fanout.close_route(INITIAL_DATA_ROUTE_INDEX)? {
            return Err(HarnessError::Process(
                "M7-I08 active data route was not open at the fault".into(),
            ));
        }
        let outcome_deadline = deadline.min(Instant::now() + EPISODE_OUTCOME_TIMEOUT);
        let (active_carrier_closed, control_route_remained_open) = loop {
            let diagnostics = cluster.device_fanout.diagnostics();
            let data_closed = !diagnostics
                .open
                .iter()
                .any(|route| route.index == INITIAL_DATA_ROUTE_INDEX)
                && diagnostics
                    .closed
                    .iter()
                    .any(|route| route.index == INITIAL_DATA_ROUTE_INDEX);
            let control_open = diagnostics
                .open
                .iter()
                .any(|route| route.index == control_route.index && route.target == owner_addr);
            if data_closed {
                if !control_open {
                    return Err(HarnessError::Process(
                        "M7-I08 control route closed with the data fault; fault is ambiguous".into(),
                    ));
                }
                break (true, true);
            }
            if Instant::now() >= outcome_deadline {
                return Err(HarnessError::Timeout(
                    "M7-I08 fanout did not close the active data route".into(),
                ));
            }
            sleep(POLL).await;
        };

        // Fail each armed attempt only after the owner attached it.
        let mut failed_attempts = Vec::new();
        // Every attempt is observed while the original CLI process is still
        // live, so a replacement process would be visible as a changed pid
        // at the exact point the retry is running.
        let mut attempt_pids_stable = true;
        for attempt in 1..=mode.failed_attempts() {
            let status =
                wait_for_attempt_status(&mut process, fault_stdout_offset, attempt, outcome_deadline)
                    .await?;
            attempt_pids_stable &= process.id() == process_pid;
            let candidate_connection_id = status
                .recovery_successor_connection_id
                .clone()
                .ok_or_else(|| HarnessError::Process("attempt status lost its successor".into()))?;
            let candidate_generation = status.recovery_successor_generation.ok_or_else(|| {
                HarnessError::Process("attempt status lost its successor generation".into())
            })?;
            let attached = wait_for_owner_candidate_attach(
                cluster,
                &status,
                device.id,
                &candidate_connection_id,
                candidate_generation,
                outcome_deadline,
            )
            .await?;
            owner_socket_high_water = owner_socket_high_water.max(attached.session.sockets);
            cursor_samples.push(cursor_sample(
                match attempt {
                    1 => "attempt_1_attached",
                    2 => "attempt_2_attached",
                    _ => "attempt_3_attached",
                },
                &attached.session,
                stream_id,
            )?);
            if attached.snapshot.lifetime_application_dispatches != pre_fault_dispatch_count {
                return Err(HarnessError::Process(
                    "M7-I08 owner dispatched while recovering".into(),
                ));
            }
            let route_index = INITIAL_DATA_ROUTE_INDEX + attempt;
            let route = cluster
                .device_fanout
                .diagnostics()
                .open
                .iter()
                .find(|route| route.index == route_index)
                .copied()
                .ok_or_else(|| {
                    HarnessError::Process(format!(
                        "M7-I08 candidate route {route_index} was not open at attachment"
                    ))
                })?;
            let flow = cluster.device_fanout.route_flow(route_index).ok_or_else(|| {
                HarnessError::Process(format!("M7-I08 candidate route {route_index} has no flow"))
            })?;
            if !flow.held {
                return Err(HarnessError::Process(format!(
                    "M7-I08 candidate route {route_index} attached without the fixture hold"
                )));
            }
            if !cluster.device_fanout.close_route(route_index)? {
                return Err(HarnessError::Process(format!(
                    "M7-I08 candidate route {route_index} was not open to close"
                )));
            }
            let owner_released_candidate = wait_for_owner_candidate_release(
                cluster,
                &status,
                device.id,
                &candidate_connection_id,
                outcome_deadline,
            )
            .await?;
            let flow_after = cluster
                .device_fanout
                .route_flow(route_index)
                .unwrap_or(flow);
            failed_attempts.push(AttemptObservation {
                attempt,
                candidate_route_index: route_index,
                candidate_relay: relay_name_for_target(cluster, route.target)?,
                candidate_generation,
                candidate_connection_id,
                attached_at_owner: attached.session.sockets == 2
                    && attached.session.phase == "recovering",
                owner_sockets_at_attach: attached.session.sockets,
                owner_recovery_reason: attached
                    .session
                    .rotation_recovery_reason
                    .map(str::to_owned),
                held_by_fixture: flow.held,
                client_bursts_at_close: flow.client_bursts,
                closed_by_fixture: flow_after.closed_by_fixture,
                owner_released_candidate,
            });
        }

        // Outcome.
        let mut failure_code = None;
        let mut failure_retryable = None;
        let mut failure_trigger = None;
        let mut failure_generation = None;
        let mut failure_attempt = None;
        let mut owner_terminal_reason = None;
        let mut live_session_absent = false;
        let mut catalog_owner_released = false;
        let mut recovered_generation = None;
        let mut recovered_connection_id = None;
        let mut recovered_route_index = None;
        let mut recovered_relay = None;
        let mut cli_exit_success = None;
        let outcome;
        let recovery: RecoveryStatusEvidence;
        let post_fault_dispatch_count;
        let control_socket_stable;
        match mode {
            EpisodeMode::Exhaust => {
                let exit = loop {
                    if let Some(exit) = process.try_wait()? {
                        break exit;
                    }
                    if Instant::now() >= outcome_deadline {
                        return Err(HarnessError::Timeout(
                            "CLI did not exit with a typed diagnostic after the third failed attempt"
                                .into(),
                        ));
                    }
                    sleep(POLL).await;
                };
                cli_exit_success = Some(exit.success());
                if exit.success() {
                    return Err(HarnessError::Process(
                        "CLI exited successfully after an exhausted recovery episode".into(),
                    ));
                }
                let failure =
                    parse_terminal_failure(&process, fault_stdout_offset).ok_or_else(|| {
                        HarnessError::Process(
                            "CLI ended the exhausted episode without the typed retained-recovery diagnostic"
                                .into(),
                        )
                    })?;
                failure_code = Some(failure.code);
                failure_retryable = failure.retryable;
                failure_trigger = Some(failure.trigger);
                failure_generation = Some(failure.generation);
                failure_attempt = Some(failure.attempt);
                recovery = collect_recovery_status_evidence(&process, fault_stdout_offset, &initial)?;
                // Owner-side terminal observation.
                let (snapshot, reason) = loop {
                    let snapshot = relay_snapshot_until(cluster, OWNER_NODE, outcome_deadline).await?;
                    let live = snapshot.sessions.iter().any(|session| {
                        session.device_id == device.id.to_string()
                            && session.session_id == initial.session_id
                            && session.epoch == initial.epoch
                    });
                    let terminal = snapshot
                        .session_terminal_events
                        .iter()
                        .rev()
                        .find(|event| {
                            event.device_id == device.id.to_string()
                                && event.session_id == initial.session_id
                                && event.epoch == initial.epoch
                                && event.active_generation == initial.generation
                                && event.active_connection_id == initial.active_connection_id
                        })
                        .map(|event| event.reason.to_owned());
                    let owner = current_owner_token(cluster, device.tenant_id, device.id, outcome_deadline)
                        .await?;
                    let released = owner.as_ref().is_none_or(|token| *token != expected_owner);
                    if let Some(reason) = terminal
                        && !live
                        && released
                    {
                        live_session_absent = true;
                        catalog_owner_released = true;
                        break (snapshot, reason);
                    }
                    if Instant::now() >= outcome_deadline {
                        return Err(HarnessError::Timeout(
                            "owner did not record the exhausted session terminal event".into(),
                        ));
                    }
                    sleep(POLL).await;
                };
                owner_terminal_reason = Some(reason);
                post_fault_dispatch_count = snapshot.lifetime_application_dispatches;
                outcome = "typed_terminal_failure";
                // The control route to the owner stayed open until the owner
                // itself ended the session; it must be closed now and no
                // further carrier may be accepted (no reconnect storm).
                control_socket_stable = control_route_remained_open
                    && recovery
                        .attempts
                        .iter()
                        .all(|attempt| (1..=MAX_RECOVERY_ATTEMPTS).contains(attempt));
            }
            EpisodeMode::RetrySucceeds => {
                let recovered = loop {
                    if let Some(status) = latest_status(&process, &initial)?
                        && status.generation > initial.generation
                        && status.active_connection_id != initial.active_connection_id
                        && status.recovery_reset_reason == Some("fenced_successor_activated")
                    {
                        let snapshot = relay_snapshot_until(cluster, OWNER_NODE, outcome_deadline).await?;
                        let session = session_for_status(snapshot, &status, device.id)?;
                        if session.phase == "active"
                            && session.candidate_generation.is_none()
                            && session.active_generation == status.generation
                            && session.active_connection_id == status.active_connection_id
                        {
                            break (status, session);
                        }
                    }
                    if let Some(exit) = process.try_wait()? {
                        return Err(HarnessError::Process(format!(
                            "CLI exited instead of recovering on attempt 2: {exit}"
                        )));
                    }
                    if Instant::now() >= outcome_deadline {
                        return Err(HarnessError::Timeout(
                            "second recovery attempt did not activate before its deadline".into(),
                        ));
                    }
                    sleep(POLL).await;
                };
                let (status, session) = recovered;
                if status.session_id != initial.session_id
                    || status.epoch != initial.epoch
                    || status.control_local_addr != initial.control_local_addr
                    || status.recovery_attempt != Some(2)
                    || !session.streams.iter().any(|stream| {
                        stream.stream_id == stream_id
                            && !stream.terminal
                            && stream.operation_id == operation_id
                    })
                {
                    return Err(HarnessError::Process(
                        "second-attempt recovery changed the control/stream identity".into(),
                    ));
                }
                recovery = collect_recovery_status_evidence(&process, fault_stdout_offset, &initial)?;
                cursor_samples.push(cursor_sample("recovered", &session, stream_id)?);
                owner_socket_high_water = owner_socket_high_water.max(session.sockets);
                recovered_generation = Some(status.generation);
                recovered_connection_id = Some(status.active_connection_id.clone());
                let route_index = INITIAL_DATA_ROUTE_INDEX + 2;
                let route = cluster
                    .device_fanout
                    .diagnostics()
                    .open
                    .iter()
                    .find(|route| route.index == route_index)
                    .copied()
                    .ok_or_else(|| {
                        HarnessError::Process("recovered carrier route is not open".into())
                    })?;
                recovered_route_index = Some(route.index);
                recovered_relay = Some(relay_name_for_target(cluster, route.target)?);
                send_record(&mut stream, 1, canary.as_bytes(), outcome_deadline).await?;
                ordered_records = ordered_records.saturating_add(1);
                let post_snapshot = relay_snapshot_until(cluster, OWNER_NODE, outcome_deadline).await?;
                let post_session = session_for_status(post_snapshot.clone(), &status, device.id)?;
                cursor_samples.push(cursor_sample("post_record", &post_session, stream_id)?);
                let owner = current_owner_token(cluster, device.tenant_id, device.id, outcome_deadline)
                    .await?;
                if owner.as_ref() != Some(&expected_owner) {
                    return Err(HarnessError::Process(
                        "second-attempt recovery changed the catalog owner".into(),
                    ));
                }
                post_fault_dispatch_count = post_snapshot.lifetime_application_dispatches;
                outcome = "recovered_same_session";
                control_socket_stable = control_route_remained_open
                    && status.phase == "active"
                    && cluster.device_fanout.diagnostics().open.iter().any(|route| {
                        route.index == CONTROL_ROUTE_INDEX && route.target == owner_addr
                    });
                if process.try_wait()?.is_some() {
                    return Err(HarnessError::Process(
                        "CLI exited after the second-attempt recovery".into(),
                    ));
                }
            }
        }
        // No reconnect storm: the fanout must not accept any carrier beyond
        // the initial pair and one per attempt, even after a quiet window.
        let fanout_after_outcome = cluster.device_fanout.diagnostics();
        sleep(RECONNECT_QUIET_WINDOW).await;
        let fanout_after_quiet = cluster.device_fanout.diagnostics();
        let cursors_never_rewound = cursor_samples
            .windows(2)
            .all(|window| window[1].never_rewound_from(&window[0]));
        // No whole-session retry: the authenticated CLI process is never
        // replaced by a second one.  A reaped child reports no pid, which is
        // the expected end state of the exhaustion episode, so absence is
        // accepted here while a *different* pid is not.  Each attempt above
        // additionally required the original live pid.
        let cli_pid_stable =
            attempt_pids_stable && process.id().is_none_or(|pid| Some(pid) == process_pid);
        Ok(RecoveryEpisodeEvidence {
            scope: mode.scope(),
            relay_count: 3,
            actual_cli_process: process_pid.is_some(),
            owner_relay: OWNER_NODE,
            ingress_relay: INGRESS_NODE,
            session_id: initial.session_id.clone(),
            epoch: initial.epoch,
            stream_id,
            tunnel_operation_id: operation_id,
            fault_route_index: INITIAL_DATA_ROUTE_INDEX,
            fault_relay,
            fault_generation: initial.generation,
            fault_connection_id: initial.active_connection_id.clone(),
            active_carrier_closed,
            control_route_remained_open,
            attempts: recovery.attempts,
            attempt_starts_ms: recovery.attempt_starts_ms,
            attempt_deadlines_ms: recovery.attempt_deadlines_ms,
            episode_deadline_ms: recovery.episode_deadline_ms,
            closed_connection_ids: recovery.closed_connection_ids,
            successor_connection_ids: recovery.successor_connection_ids,
            old_generation: recovery.old_generation,
            old_connection_id: recovery.old_connection_id,
            failed_attempts,
            cursor_samples,
            cursors_never_rewound,
            outcome,
            failure_code,
            failure_retryable,
            failure_trigger,
            failure_generation,
            failure_attempt,
            owner_terminal_reason,
            live_session_absent,
            catalog_owner_released,
            reset_reason: recovery.reset_reason,
            recovered_generation,
            recovered_connection_id,
            recovered_route_index,
            recovered_relay,
            pre_fault_dispatch_count,
            post_fault_dispatch_count,
            post_fault_dispatch_delta: post_fault_dispatch_count
                .saturating_sub(pre_fault_dispatch_count),
            ordered_records,
            fanout_accepted_total: fanout_after_outcome.accepted,
            fanout_accepted_after_quiet_window: fanout_after_quiet.accepted,
            fanout_peak_open: fanout_after_quiet.peak_open,
            owner_socket_high_water,
            cli_pid_stable,
            cli_exit_success,
            control_socket_stable,
            cleanup_joined: false,
            elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
    .await;
    // Payload-free CLI context for a failed scenario: the last typed
    // diagnostic code/message and the last published status identity.
    let scenario = scenario
        .map_err(|error| HarnessError::Process(format!("{error}; {}", cli_context(&process))));
    let stream_cleanup = timeout_at(
        tokio::time::Instant::from_std(cleanup_deadline),
        stream.close(),
    )
    .await
    .map_err(|_| HarnessError::Timeout("M7-I08 recovery attempt stream cleanup timed out".into()))
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

/// Start a fresh harness and production cluster for one episode.  Startup
/// futures are never dropped at their deadline: a partially constructed
/// harness or cluster can still own processes and sockets whose cleanup must
/// be joined, so a late completion is awaited and then cleaned.
async fn start_fresh_cluster(label: &str) -> Result<(RunningHarness, ProductionCluster)> {
    let options = HarnessOptions::from_env()?
        .rotation(EPISODE_ROTATION)
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
        Ok(Err(error)) => return Err(error),
        Err(_) => {
            let completion = match timeout_at(
                tokio::time::Instant::from_std(startup_cleanup_deadline),
                &mut harness_start,
            )
            .await
            {
                Ok(completion) => completion,
                Err(_) => harness_start.as_mut().await,
            };
            let message = format!("{label} harness startup timed out");
            return match completion {
                Ok(harness) => {
                    match harness
                        .shutdown_until(tokio::time::Instant::from_std(startup_cleanup_deadline))
                        .await
                    {
                        Ok(()) => Err(HarnessError::Timeout(message)),
                        Err(cleanup) => Err(HarnessError::Process(format!(
                            "{message}; late harness cleanup: {cleanup}"
                        ))),
                    }
                }
                Err(error) => Err(HarnessError::Process(format!(
                    "{message}; startup cleanup: {error}"
                ))),
            };
        }
    };
    let mut cluster_start = Box::pin(ProductionCluster::start(&mut harness));
    let result = match timeout_at(
        tokio::time::Instant::from_std(startup_deadline),
        &mut cluster_start,
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            let result = match timeout_at(
                tokio::time::Instant::from_std(startup_cleanup_deadline),
                &mut cluster_start,
            )
            .await
            {
                Ok(result) => result,
                Err(_) => cluster_start.as_mut().await,
            };
            drop(cluster_start);
            let message = format!("{label} production cluster startup timed out");
            let cluster_error = match result {
                Ok(cluster) => match shutdown_cluster(cluster, startup_cleanup_deadline).await {
                    Ok(()) => HarnessError::Timeout(message),
                    Err(cleanup) => HarnessError::Process(format!(
                        "{message}; startup cluster cleanup: {cleanup}"
                    )),
                },
                Err(error) => HarnessError::Process(format!("{message}; startup cleanup: {error}")),
            };
            return match harness
                .shutdown_until(tokio::time::Instant::from_std(startup_cleanup_deadline))
                .await
            {
                Ok(()) => Err(cluster_error),
                Err(cleanup) => Err(HarnessError::Process(format!(
                    "{cluster_error}; harness cleanup: {cleanup}"
                ))),
            };
        }
    };
    drop(cluster_start);
    match result {
        Ok(cluster) => Ok((harness, cluster)),
        Err(error) => {
            match harness
                .shutdown_until(tokio::time::Instant::from_std(startup_cleanup_deadline))
                .await
            {
                Ok(()) => Err(error),
                Err(cleanup) => Err(HarnessError::Process(format!(
                    "{error}; harness cleanup: {cleanup}"
                ))),
            }
        }
    }
}

async fn run_episode_on_fresh_cluster(mode: EpisodeMode) -> Result<RecoveryEpisodeEvidence> {
    let (harness, mut cluster) = start_fresh_cluster(mode.scope()).await?;
    let deadline = Instant::now() + EPISODE_TIMEOUT;
    let cleanup_deadline = deadline + CLEANUP_TIMEOUT;
    let episode = run_episode(EpisodeContext {
        cluster: &mut cluster,
        harness: &harness,
        mode,
        deadline,
        cleanup_deadline,
    })
    .await;
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
    match episode {
        Err(error) if cleanup_errors.is_empty() => Err(error),
        Err(error) => Err(HarnessError::Process(format!(
            "{error}; {}",
            cleanup_errors.join("; ")
        ))),
        Ok(evidence) if cleanup_errors.is_empty() => {
            validate_recovery_episode_evidence(&evidence)?;
            Ok(evidence)
        }
        Ok(_) => Err(HarnessError::Process(cleanup_errors.join("; "))),
    }
}

/// Run both bounded real-process recovery episodes on fresh clusters.
pub async fn verify() -> Result<I08RecoveryAttemptEvidence> {
    let started = Instant::now();
    let exhaustion = run_episode_on_fresh_cluster(EpisodeMode::Exhaust).await?;
    let retry_success = run_episode_on_fresh_cluster(EpisodeMode::RetrySucceeds).await?;
    let evidence = I08RecoveryAttemptEvidence {
        cleanup_joined: exhaustion.cleanup_joined && retry_success.cleanup_joined,
        exhaustion,
        retry_success,
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    };
    validate_i08_recovery_attempt_evidence(&evidence)?;
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::{
        AttemptObservation, CursorSample, I08RecoveryAttemptEvidence, RecoveryEpisodeEvidence,
        validate_i08_recovery_attempt_evidence, validate_recovery_episode_evidence,
    };
    use crate::HarnessError;

    fn cursor(label: &'static str, value: u64) -> CursorSample {
        CursorSample {
            label,
            last_emitted_relay_to_connector: value,
            peer_acked_relay_to_connector: value,
            recv_contiguous_connector_to_relay: value,
            delivered_contiguous_connector_to_relay: value,
        }
    }

    fn observation(attempt: u64) -> AttemptObservation {
        AttemptObservation {
            attempt,
            candidate_route_index: 1 + attempt,
            candidate_relay: if attempt % 2 == 1 {
                "relay-c"
            } else {
                "relay-b"
            }
            .to_owned(),
            candidate_generation: 1 + attempt,
            candidate_connection_id: format!("candidate-{attempt}"),
            attached_at_owner: true,
            owner_sockets_at_attach: 2,
            owner_recovery_reason: Some(
                if attempt == 1 {
                    "old_transport_lost"
                } else {
                    "candidate_transport_lost"
                }
                .to_owned(),
            ),
            held_by_fixture: true,
            client_bursts_at_close: 3,
            closed_by_fixture: true,
            owner_released_candidate: true,
        }
    }

    fn exhaustion() -> RecoveryEpisodeEvidence {
        RecoveryEpisodeEvidence {
            scope: "exhausted_after_three_attempts",
            relay_count: 3,
            actual_cli_process: true,
            owner_relay: "relay-a",
            ingress_relay: "relay-c",
            session_id: "session".into(),
            epoch: 1,
            stream_id: 7,
            tunnel_operation_id: "operation".into(),
            fault_route_index: 1,
            fault_relay: "relay-b".into(),
            fault_generation: 1,
            fault_connection_id: "active-1".into(),
            active_carrier_closed: true,
            control_route_remained_open: true,
            attempts: vec![1, 2, 3],
            attempt_starts_ms: vec![1_000, 1_150, 1_400],
            attempt_deadlines_ms: vec![31_000, 31_000, 31_000],
            episode_deadline_ms: Some(31_000),
            closed_connection_ids: vec![
                vec!["active-1".into()],
                vec!["candidate-1".into()],
                vec!["candidate-2".into()],
            ],
            successor_connection_ids: vec![
                Some("candidate-1".into()),
                Some("candidate-2".into()),
                Some("candidate-3".into()),
            ],
            old_generation: Some(1),
            old_connection_id: Some("active-1".into()),
            failed_attempts: vec![observation(1), observation(2), observation(3)],
            cursor_samples: vec![
                cursor("pre_fault", 1),
                cursor("attempt_1_attached", 1),
                cursor("attempt_2_attached", 1),
                cursor("attempt_3_attached", 1),
            ],
            cursors_never_rewound: true,
            outcome: "typed_terminal_failure",
            failure_code: Some("TRANSPORT_ERROR"),
            failure_retryable: Some(true),
            failure_trigger: Some("data_reader_closed"),
            failure_generation: Some(1),
            failure_attempt: Some(3),
            owner_terminal_reason: Some("RECOVERY_CANDIDATE_FAILED".into()),
            live_session_absent: true,
            catalog_owner_released: true,
            reset_reason: None,
            recovered_generation: None,
            recovered_connection_id: None,
            recovered_route_index: None,
            recovered_relay: None,
            pre_fault_dispatch_count: 1,
            post_fault_dispatch_count: 1,
            post_fault_dispatch_delta: 0,
            ordered_records: 1,
            fanout_accepted_total: 5,
            fanout_accepted_after_quiet_window: 5,
            fanout_peak_open: 2,
            owner_socket_high_water: 2,
            cli_pid_stable: true,
            cli_exit_success: Some(false),
            control_socket_stable: true,
            cleanup_joined: true,
            elapsed_ms: 4_000,
        }
    }

    fn retry_success() -> RecoveryEpisodeEvidence {
        RecoveryEpisodeEvidence {
            scope: "second_attempt_recovered",
            attempts: vec![1, 2],
            attempt_starts_ms: vec![1_000, 1_150],
            attempt_deadlines_ms: vec![31_000, 31_000],
            closed_connection_ids: vec![vec!["active-1".into()], vec!["candidate-1".into()]],
            successor_connection_ids: vec![Some("candidate-1".into()), Some("candidate-2".into())],
            failed_attempts: vec![observation(1)],
            cursor_samples: vec![
                cursor("pre_fault", 1),
                cursor("attempt_1_attached", 1),
                cursor("recovered", 1),
                cursor("post_record", 2),
            ],
            outcome: "recovered_same_session",
            failure_code: None,
            failure_retryable: None,
            failure_trigger: None,
            failure_generation: None,
            failure_attempt: None,
            owner_terminal_reason: None,
            live_session_absent: false,
            catalog_owner_released: false,
            reset_reason: Some("fenced_successor_activated"),
            recovered_generation: Some(3),
            recovered_connection_id: Some("candidate-2".into()),
            recovered_route_index: Some(3),
            recovered_relay: Some("relay-b".into()),
            post_fault_dispatch_count: 2,
            post_fault_dispatch_delta: 1,
            ordered_records: 2,
            fanout_accepted_total: 4,
            fanout_accepted_after_quiet_window: 4,
            cli_exit_success: None,
            ..exhaustion()
        }
    }

    fn rejects(evidence: RecoveryEpisodeEvidence, needle: &str) {
        match validate_recovery_episode_evidence(&evidence) {
            Err(HarnessError::Process(message)) => {
                assert!(message.contains(needle), "unexpected rejection: {message}");
            }
            other => panic!("expected rejection containing {needle:?}, got {other:?}"),
        }
    }

    #[test]
    fn accepts_both_episodes() {
        validate_recovery_episode_evidence(&exhaustion()).expect("exhaustion");
        validate_recovery_episode_evidence(&retry_success()).expect("retry success");
        let evidence = I08RecoveryAttemptEvidence {
            exhaustion: exhaustion(),
            retry_success: retry_success(),
            cleanup_joined: true,
            elapsed_ms: 9_000,
        };
        validate_i08_recovery_attempt_evidence(&evidence).expect("pair");
        let swapped = I08RecoveryAttemptEvidence {
            exhaustion: retry_success(),
            retry_success: exhaustion(),
            cleanup_joined: true,
            elapsed_ms: 9_000,
        };
        assert!(validate_i08_recovery_attempt_evidence(&swapped).is_err());
    }

    #[test]
    fn rejects_fewer_than_three_attempts_for_exhaustion() {
        let mut evidence = exhaustion();
        evidence.attempts = vec![1, 2];
        evidence.attempt_starts_ms.truncate(2);
        evidence.attempt_deadlines_ms.truncate(2);
        evidence.closed_connection_ids.truncate(2);
        evidence.successor_connection_ids.truncate(2);
        evidence.failed_attempts.truncate(2);
        rejects(evidence, "did not match the required [1, 2, 3]");
    }

    #[test]
    fn rejects_restarted_or_regressed_deadlines() {
        let mut evidence = exhaustion();
        evidence.attempt_deadlines_ms = vec![31_000, 30_000, 31_000];
        rejects(evidence, "restarted or regressed");
        let mut evidence = exhaustion();
        evidence.attempt_deadlines_ms = vec![31_000, 31_000, 31_500];
        rejects(evidence, "outside its episode budget");
        let mut evidence = exhaustion();
        evidence.episode_deadline_ms = Some(40_000);
        evidence.attempt_deadlines_ms = vec![40_000, 40_000, 40_000];
        rejects(evidence, "one bounded absolute budget");
    }

    #[test]
    fn rejects_retry_before_protocol_backoff() {
        let mut evidence = exhaustion();
        evidence.attempt_starts_ms = vec![1_000, 1_050, 1_400];
        rejects(evidence, "before its protocol backoff");
    }

    #[test]
    fn rejects_untyped_or_wrong_terminal_failure() {
        let mut evidence = exhaustion();
        evidence.failure_attempt = Some(2);
        rejects(evidence, "failure_attempt");
        let mut evidence = exhaustion();
        evidence.failure_code = Some("SESSION_CLOSED");
        rejects(evidence, "failure_code");
        let mut evidence = exhaustion();
        evidence.failure_retryable = Some(false);
        rejects(evidence, "failure_retryable");
        let mut evidence = exhaustion();
        evidence.cli_exit_success = Some(true);
        rejects(evidence, "cli_exit_failed");
        let mut evidence = exhaustion();
        evidence.owner_terminal_reason = Some("ROTATION_DEADLINE_EXPIRED".into());
        rejects(evidence, "owner_terminal_reason");
        let mut evidence = exhaustion();
        evidence.failure_trigger = None;
        rejects(evidence, "failure_trigger");
    }

    #[test]
    fn rejects_reconnect_storm_and_socket_bound_breaches() {
        let mut evidence = exhaustion();
        evidence.fanout_accepted_after_quiet_window = 6;
        rejects(evidence, "expected exactly 5");
        let mut evidence = exhaustion();
        evidence.fanout_peak_open = 4;
        rejects(evidence, "socket bound");
        let mut evidence = exhaustion();
        evidence.owner_socket_high_water = 4;
        rejects(evidence, "socket bound");
    }

    #[test]
    fn rejects_rewound_cursors_and_ambiguous_replay() {
        let mut evidence = exhaustion();
        evidence.cursor_samples[2] = cursor("attempt_2_attached", 0);
        rejects(evidence, "cursors rewound");
        let mut evidence = exhaustion();
        evidence.post_fault_dispatch_count = 2;
        evidence.post_fault_dispatch_delta = 1;
        rejects(evidence, "ambiguous effect");
    }

    #[test]
    fn rejects_attempt_that_was_not_an_attached_fixture_loss() {
        let mut evidence = exhaustion();
        evidence.failed_attempts[1].attached_at_owner = false;
        rejects(evidence, "attempt 2 was not a fixture-controlled loss");
        let mut evidence = exhaustion();
        evidence.failed_attempts[2].held_by_fixture = false;
        rejects(evidence, "attempt 3 was not a fixture-controlled loss");
        let mut evidence = exhaustion();
        evidence.failed_attempts[0].owner_recovery_reason = Some("deadline".into());
        rejects(evidence, "owner reason was not old_transport_lost");
        let mut evidence = exhaustion();
        evidence.closed_connection_ids[2] = vec!["candidate-1".into()];
        rejects(evidence, "not bound to the failed candidate");
    }

    #[test]
    fn rejects_retry_success_without_exact_successor_or_record() {
        let mut evidence = retry_success();
        evidence.recovered_connection_id = Some("candidate-1".into());
        rejects(evidence, "incomplete or mixed with failure");
        let mut evidence = retry_success();
        evidence.recovered_relay = Some("relay-a".into());
        rejects(evidence, "incomplete or mixed with failure");
        let mut evidence = retry_success();
        evidence.post_fault_dispatch_count = 3;
        evidence.post_fault_dispatch_delta = 2;
        evidence.ordered_records = 3;
        rejects(evidence, "missing or duplicate record");
        let mut evidence = retry_success();
        evidence.reset_reason = None;
        rejects(evidence, "incomplete or mixed with failure");
    }
}
