//! OG-08 bounded multi-fault chaos classification gate.
//!
//! One real three-relay production cluster (relays connected to Redis through
//! an opaque TCP proxy so Redis can be paused) is driven through a fixed
//! schedule of chaos rounds ([`CHAOS_SCHEDULE`], eight rounds) that repeat
//! owner kill, CLI process pause, peer UDP loss and a full Redis pause, all
//! built from existing fault injectors rather than new mechanisms.  No round
//! is terminal: a full Redis pause drives every relay's membership runtime
//! Unready, and the round waits for it to return to `Ready` on its own before
//! recycling the owner session and echoing, so post-pause recovery is
//! observed rather than assumed.
//!
//! * `OwnerKill`  — the owning `tunnel-client` process is abruptly `SIGKILL`ed
//!   (`send_managed_process_signal`) and the admitted consumer stream must close
//!   fail-closed while the owner lease is released.
//! * `CliPause`   — the owning `tunnel-client` process is `SIGSTOP`ed past its
//!   challenge lease (`ProcessPauseGuard`); its consumer probe must fail closed,
//!   then it is `SIGCONT`ed.
//! * `PeerLoss`   — one non-owner relay's signed private peer path is
//!   black-holed (`set_peer_path_drop`); admission through it must fail closed
//!   before the route is restored and readiness recovers.
//! * `RedisPause` — every proxied Redis socket is paused (`ProxyHandle`);
//!   admission during the pause must fail closed before the proxy resumes.
//!
//! Every observed close and interruption is mapped into the closed vocabulary
//! the diagnostics already use ([`InterruptionClass`]).  Unknown outcomes are
//! preserved as [`InterruptionClass::OutcomeUnknown`] rather than discarded, and
//! any interruption that maps to no vocabulary bucket is recorded as
//! unclassified.  A `tunnel-client` that exits before readiness on the
//! establish path is classified too, from the CLI's own typed exit-code
//! vocabulary, instead of surfacing as an opaque harness error.
//!
//! Every round then recycles the owner session (join predecessor, start a
//! fresh one).  The fixture records the exact instant of every accepted
//! device-fanout socket, so the enforced reconnect metric is the most
//! *client-attributed* accepts inside any real one-second window: the
//! fixture's own recycle sockets are bracketed out (they are bounded
//! separately), and a burst can no longer be averaged away across a whole
//! round.  Release is blocked (validation fails) on any unclassified
//! interruption, a client reconnect burst above the documented ceiling, an
//! untyped pre-readiness CLI exit, an unrepeated or unrecovered Redis pause,
//! or a missing recovery.

use chrono::Utc;
use std::time::{Duration, Instant};
use tempfile::{TempDir, tempdir};
use tokio::time::{sleep, timeout};
use tunnel_core::RotationConfig;
use uuid::Uuid;

use crate::acceptance::helpers::{DeviceProfile, write_device_profile};
use crate::{
    Harness, HarnessError, HarnessOptions, ManagedProcess, OidcTokenOptions, ProxyConfig, Result,
    RunningHarness, TcpProxy,
};

use super::{
    ConsumerStream, PROCESS_PAUSE_MIN_DURATION, ProcessPauseGuard, ProcessPauseProbeOutcome,
    ProductionCluster, ProxyHandle, REDIS_PARTITION_AUTHORIZATION_WAIT,
    REDIS_PARTITION_OPERATION_TIMEOUT, STARTUP_TIMEOUT, StreamConnectFailure,
    is_expected_revocation_close, is_partition_admission_response, is_peer_recovery_response,
    open_consumer_stream, redis_target_address, send_managed_process_signal, start_cli_smoke,
    wait_for_fanout_drained,
};

/// The fixed chaos schedule.  Every fault type is repeated, the full Redis
/// pause included, and **no round is terminal**.
///
/// Pausing *all* proxied Redis sockets drives each relay's membership runtime
/// Unready, because its signed checkpoint cannot be refreshed against an
/// unreachable catalog.  That state is **not** latched: the supervisor keeps
/// reconciling on its interval and restores `Ready` from a single successful
/// pass.  Each Redis round therefore waits for every relay's membership
/// runtime to return to `Ready` on its own, asserts it, and then reuses the
/// cluster -- recycling the owner session and echoing on it -- so post-pause
/// recovery is observed at the *session* level rather than assumed.
///
/// Why that assertion is deterministic rather than positional.  The relay's
/// trust deadline is
/// `min(checkpoint_expiry, record.expires_at, peer_key.expires_at)`.  The
/// checkpoint is minted fresh for every reconcile request, but this fixture
/// signed each relay's membership record and peer key exactly **once**, at
/// bootstrap, with `record_version = 1`, and never re-signed or republished
/// them.  Their `expires_at` was therefore an absolute wall-clock deadline
/// measured from cluster startup, not a sliding window: at the 60-second
/// record lifetime, membership trust lapsed partway through this scenario no
/// matter what the schedule did.  A Redis round placed early
/// re-armed; the same round placed late could not, because there was no valid
/// record left to re-arm *to*.  That, not any latch and not the relay's own
/// `membership_record_lifetime_seconds` (which is pinned at the product
/// maximum of 60 and is a separate quantity), is what made the observation
/// position-dependent and unassertable.
///
/// A longer record is not available to buy: the relay's verifier caps a record
/// at the product maximum of 60 seconds, and a fixture record signed past that
/// cap is refused outright, so the cluster never reaches Ready at all.  The
/// fixture therefore keeps *issuing* records instead, on the interval named by
/// `MEMBERSHIP_RESIGN_INTERVAL`, which is what a real control plane does and
/// which widens nothing the relay will accept.  Membership trust then cannot
/// lapse mid-run and a Redis round re-arms from its own reconcile loop
/// wherever it sits.  Both Redis rounds below are followed by further rounds,
/// so cluster *reuse* after a full outage is proved by the rounds that come
/// after them and not merely by the last one passing.
const CHAOS_SCHEDULE: [Fault; 8] = [
    Fault::PeerLoss,
    Fault::CliPause,
    Fault::RedisPause,
    Fault::OwnerKill,
    Fault::PeerLoss,
    Fault::CliPause,
    Fault::RedisPause,
    Fault::OwnerKill,
];
const CHAOS_ROUNDS: usize = CHAOS_SCHEDULE.len();
/// Whole-scenario wall-clock bound.  Cleanup joins are still owned by the
/// scenario itself; this is the outer safety net.
const CHAOS_SCENARIO_DEADLINE: Duration = Duration::from_secs(420);
/// A slow rotation keeps a bounded chaos round from rotating its data carrier,
/// so the only device-fanout reconnects are the deliberate per-round recycles.
const CHAOS_ROTATION: RotationConfig = RotationConfig {
    interval_seconds: 30,
    handshake_timeout_seconds: 2,
    overlap_seconds: 5,
};
/// Consumer ingress for the persistent owner session's admitted stream.
const OWNER_INGRESS_NODE: &str = "relay-c";
/// Maximum concurrent open device fanout sockets tolerated.  Each session is
/// joined and the fanout drained before the next is started, so at most a
/// transient handful overlap.
const CHAOS_SOCKET_BOUND: usize = 4;
/// Documented reconnect ceiling: device-fanout sockets accepted per second
/// within any one round, scaled by 1000 so the evidence stays an exact
/// integer.  A recycle is two sockets over several seconds, and under load a
/// bounded recovery retry can add a few more quickly (observed peaks near
/// 6-7/second); a genuine client reconnect storm re-dials many dozens to
/// hundreds of times per second, far above this ceiling.
const RECONNECT_RATE_THRESHOLD_MILLI: u64 = 12_000;
/// Second-scale reconnect window.  The OG-08 clause is about reconnects at
/// *second scale*, so the gate measures the largest number of CLI-attributed
/// device-fanout accepts that fall inside any one-second window, computed from
/// exact accept instants.  A per-round average cannot see a burst: ten
/// reconnects inside a ten-second round average to one per second.
const RECONNECT_WINDOW: Duration = Duration::from_secs(1);
/// Ceiling for CLI-attributed device-fanout accepts inside any one-second
/// window.  The fixture's own recycle sockets are excluded from this count
/// (see `fixture_windows` in `run_chaos`), so this measures client reconnects
/// only.  A healthy run re-dials nothing outside the deliberate recycles; a
/// genuine reconnect storm re-dials many times inside one second.
const MAX_CLI_RECONNECTS_PER_WINDOW: usize = 4;
/// Bound on the fixture's own sockets for one deliberate recycle (join the
/// predecessor, start a fresh CLI).  Excluding recycle sockets from the
/// client-attributed metric would hide a storm *during* establishment, so the
/// excluded population is bounded in its own right.
const MAX_RECYCLE_SOCKETS_PER_ROUND: u64 = 6;
/// Budget for observing whether every relay's membership runtime returns to
/// `Ready` after a full Redis outage ends.  The supervisor reconciles on the
/// fixture's one-second interval and each pass is itself bounded, so this
/// covers many reconcile attempts.
///
/// This is now **asserted**, not merely recorded: with membership trust no
/// longer lapsing mid-run (see [`CHAOS_SCHEDULE`]) a re-arm needs one
/// successful reconcile pass, which is a small multiple of the reconcile
/// interval.  The budget is nonetheless generous, because the old 10-second
/// budget was itself too short to see the ~28-second re-arm that the expired
/// fixture record used to force, and a budget that cannot observe the recovery
/// it asserts would be its own source of flakiness.
const MEMBERSHIP_OBSERVE_BUDGET: Duration = Duration::from_secs(45);
/// Minimum number of full Redis pause rounds.  The OG-08 clause asks for the
/// Redis fault to be *repeated* with observed recovery, so a schedule that
/// quietly fell back to a single terminal Redis round fails validation rather
/// than passing with weaker evidence.
const MIN_REDIS_PAUSE_ROUNDS: usize = 2;
/// Preserved-unknown ceiling: a bounded chaos run may legitimately time a probe
/// out once, but a run that is mostly ambiguous is not evidence.
const MAX_UNKNOWN_OUTCOMES: usize = 2;
const ROUND_POLL: Duration = Duration::from_millis(50);
const OWNER_RELEASE_TIMEOUT: Duration = Duration::from_secs(20);
/// Budget for a relay to release the owner lease on its own after an abrupt
/// owner kill (control-close detection plus compare-and-release).
const OWNER_KILL_OBSERVE_BUDGET: Duration = Duration::from_secs(12);
const PEER_RECOVERY_TIMEOUT: Duration = Duration::from_secs(15);
const RECOVERY_ECHO_TIMEOUT: Duration = Duration::from_secs(20);
const POSTKILL_CLOSE_TIMEOUT: Duration = Duration::from_secs(20);
/// Bounded recovery-establishment retries: a fresh CLI can transiently fail to
/// route immediately after a fault before it succeeds.
const MAX_ESTABLISH_ATTEMPTS: usize = 3;
const ESTABLISH_RETRY_DELAY: Duration = Duration::from_secs(1);

/// The closed classification vocabulary for an observed close or interruption.
/// Every chaos round maps its outcome onto exactly one of these buckets;
/// `OutcomeUnknown` preserves a legitimately ambiguous result, and a result
/// that maps to none of them is recorded as unclassified and blocks release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptionClass {
    /// A bounded fail-closed transport/application close of an admitted stream
    /// (a consumer close, transport error, or the expected revocation close).
    BoundedClose,
    /// New admission failed closed with a typed authorization/cluster-unready
    /// response (401/503 with the documented codes).
    AdmissionUnavailable,
    /// New admission failed closed with a typed peer-unavailable/no-owner
    /// response (`PEER_UNTRUSTED` / `PEER_UNAVAILABLE`, not dispatched).
    PeerUnavailable,
    /// The owner lease was released after an abrupt owner loss.
    OwnerReleased,
    /// A preserved unknown outcome: a bounded probe timed out or could not be
    /// sent.  It is retained, not discarded, and not treated as a success.
    OutcomeUnknown,
    /// A managed `tunnel-client` exited before it reached readiness, carrying
    /// one of the CLI's own typed exit codes.  This is a real interruption of
    /// the recovery path, so it is given a class and recorded as evidence
    /// rather than surfacing as an opaque harness error or being silently
    /// rerun.
    ClientExitBeforeReady,
    /// The observation matched no vocabulary bucket (e.g. an unexpected echo or
    /// HTTP status).  Any occurrence blocks release.
    Unclassified,
}

impl InterruptionClass {
    const fn label(self) -> &'static str {
        match self {
            Self::BoundedClose => "bounded_close",
            Self::AdmissionUnavailable => "admission_unavailable",
            Self::PeerUnavailable => "peer_unavailable",
            Self::OwnerReleased => "owner_released",
            Self::OutcomeUnknown => "outcome_unknown",
            Self::ClientExitBeforeReady => "client_exit_before_ready",
            Self::Unclassified => "unclassified",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    RedisPause,
    PeerLoss,
    CliPause,
    OwnerKill,
}

impl Fault {
    /// Fixed label for diagnostics; never caller or payload data.
    const fn label(self) -> &'static str {
        match self {
            Self::RedisPause => "redis_pause",
            Self::PeerLoss => "peer_loss",
            Self::CliPause => "cli_pause",
            Self::OwnerKill => "owner_kill",
        }
    }
}

/// Payload-free evidence from one bounded chaos run.  All fields are counters,
/// bounds and booleans; no application payload or credential is retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChaosEvidence {
    pub relay_count: usize,
    pub rounds: usize,
    pub owner_kill_rounds: usize,
    pub cli_pause_rounds: usize,
    pub peer_loss_rounds: usize,
    pub redis_pause_rounds: usize,
    /// Rounds whose interruption mapped to a concrete (non-unknown) class.
    pub classified_interruptions: usize,
    /// Rounds whose outcome matched no vocabulary bucket.  Must be zero.
    pub unclassified_interruptions: usize,
    /// Preserved `OutcomeUnknown` rounds.  Retained, bounded, never a success.
    pub unknown_outcomes_preserved: usize,
    /// Preserved unknowns that came from a peer-loss round.
    ///
    /// Recorded because the ceiling alone says only "not too many".  A
    /// blackholed peer path is the one fault in this schedule whose outcome is
    /// legitimately unknown: the relay forwards toward the owner and then
    /// loses the path, so whether the request was dispatched genuinely cannot
    /// be determined, and it says so with a typed `execution=unknown`.  Every
    /// other fault in the schedule has a determinate answer, so an unknown
    /// arising anywhere else is a gap in the vocabulary rather than an
    /// honest ambiguity, and the validator rejects it even while the ceiling
    /// would still accept the count.
    pub peer_loss_unknown_outcomes: usize,
    pub class_bounded_close: usize,
    pub class_admission_unavailable: usize,
    pub class_peer_unavailable: usize,
    pub class_owner_released: usize,
    /// Pre-readiness CLI exits that carried a typed CLI exit code.
    pub class_client_exit_before_ready: usize,
    /// Total device-fanout sockets accepted across all rounds (reconnects),
    /// client reconnects and fixture recycles together.
    pub reconnect_sockets_total: u64,
    /// Peak per-round reconnect rate (sockets/second) scaled by 1000.  This is
    /// a whole-round average and is retained only for continuity; the
    /// second-scale clause is enforced on `max_cli_reconnects_per_window`.
    pub max_reconnect_rate_milli: u64,
    /// Documented reconnect ceiling used by [`validate_chaos_evidence`].
    pub reconnect_rate_threshold_milli: u64,
    /// Device-fanout accepts attributed to the client: inside the measured
    /// span and outside every fixture-owned recycle bracket.
    pub cli_reconnect_sockets: u64,
    /// Device-fanout accepts owned by the fixture's deliberate per-round
    /// session recycles, excluded from the client-attributed metric.
    pub fixture_recycle_sockets: u64,
    /// Largest fixture recycle, in sockets, of any single round.
    pub max_recycle_sockets_round: u64,
    /// Enforced second-scale metric: the most CLI-attributed device-fanout
    /// accepts inside any one `reconnect_window_ms` window.
    pub max_cli_reconnects_per_window: usize,
    /// Width of that window in milliseconds.
    pub reconnect_window_ms: u64,
    /// Documented ceiling for `max_cli_reconnects_per_window`.
    pub max_cli_reconnects_allowed: usize,
    /// Accept instants evicted by the fixture's bounded ring.  Non-zero means
    /// the window measurement undercounted, so it is not evidence.
    pub accept_instants_dropped: u64,
    /// Pre-readiness CLI exits observed on the establish path.
    pub client_exit_before_ready: usize,
    /// Those that carried a typed CLI exit code and were classified.
    pub client_exit_classified: usize,
    /// Whether every relay's membership runtime returned to `Ready` on its own
    /// within the observation budget after the full Redis outage.
    ///
    /// Asserted, not merely recorded, and true only if *every* Redis round
    /// re-armed.  Membership trust no longer lapses mid-run, so the re-arm no
    /// longer depends on the round's position in the schedule.  See
    /// [`CHAOS_SCHEDULE`].
    pub redis_membership_recovery_observed: bool,
    /// Number of Redis rounds that observed every relay return to `Ready`
    /// within the budget.  Must equal `redis_pause_rounds`, so a schedule that
    /// silently stopped repeating the Redis fault cannot pass.
    pub redis_recovery_rounds: usize,
    /// Highest concurrent open device-fanout socket count observed.
    pub fanout_peak_open: usize,
    /// A fresh consumer echo succeeded after every single round.
    pub recovered_after_each_round: bool,
    /// The final post-run consumer echo succeeded.
    pub final_recovery_echo: bool,
    pub cleanup_joined: bool,
    pub elapsed_ms: u64,
}

/// The complete closed classification vocabulary, in a stable order.
const CLASS_VOCABULARY: [InterruptionClass; 7] = [
    InterruptionClass::BoundedClose,
    InterruptionClass::AdmissionUnavailable,
    InterruptionClass::PeerUnavailable,
    InterruptionClass::OwnerReleased,
    InterruptionClass::OutcomeUnknown,
    InterruptionClass::ClientExitBeforeReady,
    InterruptionClass::Unclassified,
];

/// The `tunnel-client` CLI's exit codes are a closed, documented vocabulary
/// (`crates/tunnel-client/src/main.rs`, `CliError::exit_code`): 1 other,
/// 2 invocation/config, 3 credential, 4 transport or supervisor-absent,
/// 5 deadline exceeded, 6 outcome unknown.  A pre-readiness exit carrying one
/// of those codes is a classified interruption.  Anything else — a signal death
/// with no exit code, or a success exit that should not have happened before
/// readiness — matches no bucket and blocks release.
const CLIENT_EXIT_CODES: [i32; 6] = [1, 2, 3, 4, 5, 6];

/// Map a pre-readiness CLI exit onto the closed vocabulary.
fn classify_client_exit(code: Option<i32>) -> InterruptionClass {
    match code {
        Some(code) if CLIENT_EXIT_CODES.contains(&code) => InterruptionClass::ClientExitBeforeReady,
        _ => InterruptionClass::Unclassified,
    }
}

/// Accept instants attributable to the client: inside the measured span and
/// outside every fixture-owned recycle bracket.
fn cli_accept_instants(
    accepts: &[Instant],
    from: Instant,
    to: Instant,
    fixture_windows: &[(Instant, Instant)],
) -> Vec<Instant> {
    accepts
        .iter()
        .copied()
        .filter(|at| *at >= from && *at <= to)
        .filter(|at| {
            !fixture_windows
                .iter()
                .any(|(start, end)| at >= start && at <= end)
        })
        .collect()
}

/// Largest number of instants falling inside any `window`-long span.  The
/// input must be sorted ascending, which the accept ring already guarantees.
fn max_instants_in_window(sorted: &[Instant], window: Duration) -> usize {
    let mut peak = 0;
    for (index, start) in sorted.iter().enumerate() {
        let count = sorted[index..]
            .iter()
            .take_while(|at| at.duration_since(*start) < window)
            .count();
        peak = peak.max(count);
    }
    peak
}

impl ChaosEvidence {
    #[must_use]
    pub fn summary(&self) -> String {
        let vocabulary = CLASS_VOCABULARY
            .iter()
            .map(|class| class.label())
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "relays={} rounds={} owner_kill={} cli_pause={} peer_loss={} redis_pause={} \
classified={} unclassified={} unknown_preserved={} unknown_from_peer_loss={} \
bounded_close={} admission_unavailable={} \
peer_unavailable={} owner_released={} client_exit_class={} reconnect_sockets={} \
max_reconnect_rate_milli={} reconnect_threshold_milli={} cli_reconnect_sockets={} \
fixture_recycle_sockets={} max_recycle_sockets_round={} max_cli_reconnects_per_window={} \
reconnect_window_ms={} max_cli_reconnects_allowed={} accept_instants_dropped={} \
client_exit_before_ready={} client_exit_classified={} redis_membership_recovery={} \
redis_recovery_rounds={} fanout_peak_open={} recovered_each_round={} final_recovery={} \
cleanup_joined={} elapsed_ms={} vocabulary={}",
            self.relay_count,
            self.rounds,
            self.owner_kill_rounds,
            self.cli_pause_rounds,
            self.peer_loss_rounds,
            self.redis_pause_rounds,
            self.classified_interruptions,
            self.unclassified_interruptions,
            self.unknown_outcomes_preserved,
            self.peer_loss_unknown_outcomes,
            self.class_bounded_close,
            self.class_admission_unavailable,
            self.class_peer_unavailable,
            self.class_owner_released,
            self.class_client_exit_before_ready,
            self.reconnect_sockets_total,
            self.max_reconnect_rate_milli,
            self.reconnect_rate_threshold_milli,
            self.cli_reconnect_sockets,
            self.fixture_recycle_sockets,
            self.max_recycle_sockets_round,
            self.max_cli_reconnects_per_window,
            self.reconnect_window_ms,
            self.max_cli_reconnects_allowed,
            self.accept_instants_dropped,
            self.client_exit_before_ready,
            self.client_exit_classified,
            self.redis_membership_recovery_observed,
            self.redis_recovery_rounds,
            self.fanout_peak_open,
            self.recovered_after_each_round,
            self.final_recovery_echo,
            self.cleanup_joined,
            self.elapsed_ms,
            vocabulary,
        )
    }
}

fn reject(reason: &str) -> HarnessError {
    HarnessError::Process(format!("M7 chaos returned incomplete evidence: {reason}"))
}

/// Strict OG-08 validator.  Release is blocked on any unclassified
/// interruption, any reconnect rate above the documented threshold, an unmet
/// per-fault coverage requirement, or a missing recovery.
pub fn validate_chaos_evidence(evidence: &ChaosEvidence) -> Result<()> {
    if evidence.relay_count != 3 {
        return Err(reject("relay_count_is_three"));
    }
    if evidence.rounds != CHAOS_ROUNDS {
        return Err(reject("round_count_matches_schedule"));
    }
    let fault_rounds = evidence.owner_kill_rounds
        + evidence.cli_pause_rounds
        + evidence.peer_loss_rounds
        + evidence.redis_pause_rounds;
    if fault_rounds != evidence.rounds {
        return Err(reject("fault_round_tally_matches_rounds"));
    }
    if evidence.owner_kill_rounds == 0
        || evidence.cli_pause_rounds == 0
        || evidence.peer_loss_rounds == 0
        || evidence.redis_pause_rounds == 0
    {
        return Err(reject("each_fault_type_exercised"));
    }
    // OG-08 requires the Redis fault to be *repeated* with recovery observed
    // after it, not exercised once as a terminal round.
    if evidence.redis_pause_rounds < MIN_REDIS_PAUSE_ROUNDS {
        return Err(reject("redis_pause_repeated"));
    }
    // Every Redis round must have observed the re-arm, not just one of them.
    if evidence.redis_recovery_rounds != evidence.redis_pause_rounds {
        return Err(reject("redis_recovery_observed_each_round"));
    }
    if !evidence.redis_membership_recovery_observed {
        return Err(reject("redis_membership_recovery_observed"));
    }
    if evidence.unclassified_interruptions != 0 {
        return Err(reject("no_unclassified_interruption"));
    }
    if evidence.classified_interruptions + evidence.unknown_outcomes_preserved != evidence.rounds {
        return Err(reject("every_round_classified_or_preserved_unknown"));
    }
    let class_total = evidence.class_bounded_close
        + evidence.class_admission_unavailable
        + evidence.class_peer_unavailable
        + evidence.class_owner_released
        + evidence.class_client_exit_before_ready;
    if class_total != evidence.classified_interruptions {
        return Err(reject("class_tally_matches_classified"));
    }
    if evidence.unknown_outcomes_preserved > MAX_UNKNOWN_OUTCOMES {
        return Err(reject("unknown_outcomes_within_bound"));
    }
    // Every preserved unknown must be attributable to a peer-loss round.  This
    // is what the ceiling cannot say: a run sitting at the ceiling is fine when
    // both unknowns are the two blackholed peer paths, and is a finding when
    // one of them came from a fault whose outcome should have been determinate.
    if evidence.peer_loss_unknown_outcomes != evidence.unknown_outcomes_preserved {
        return Err(reject("unknown_outcomes_attributed_to_peer_loss"));
    }
    if evidence.peer_loss_unknown_outcomes > evidence.peer_loss_rounds {
        return Err(reject("peer_loss_unknowns_within_peer_loss_rounds"));
    }
    if evidence.reconnect_rate_threshold_milli != RECONNECT_RATE_THRESHOLD_MILLI {
        return Err(reject("documented_reconnect_threshold"));
    }
    if evidence.max_reconnect_rate_milli > evidence.reconnect_rate_threshold_milli {
        return Err(reject("reconnect_rate_within_threshold"));
    }
    // Second-scale clause: the enforced reconnect metric is a real one-second
    // window over client-attributed accepts, not a whole-round average.
    if evidence.reconnect_window_ms != RECONNECT_WINDOW.as_millis() as u64 {
        return Err(reject("documented_reconnect_window"));
    }
    if evidence.max_cli_reconnects_allowed != MAX_CLI_RECONNECTS_PER_WINDOW {
        return Err(reject("documented_cli_reconnect_ceiling"));
    }
    if evidence.accept_instants_dropped != 0 {
        return Err(reject("accept_instants_not_evicted"));
    }
    if evidence.max_cli_reconnects_per_window > evidence.max_cli_reconnects_allowed {
        return Err(reject("cli_reconnect_window_within_ceiling"));
    }
    // The excluded (fixture) population is bounded in its own right, so
    // excluding it cannot hide a storm during establishment.
    if evidence.max_recycle_sockets_round > MAX_RECYCLE_SOCKETS_PER_ROUND {
        return Err(reject("recycle_sockets_within_bound"));
    }
    if evidence.cli_reconnect_sockets + evidence.fixture_recycle_sockets
        != evidence.reconnect_sockets_total
    {
        return Err(reject("reconnect_attribution_totals_match"));
    }
    // Every pre-readiness CLI exit must carry a typed CLI exit code.
    if evidence.client_exit_classified != evidence.client_exit_before_ready {
        return Err(reject("client_exit_before_ready_classified"));
    }
    if evidence.fanout_peak_open > CHAOS_SOCKET_BOUND {
        return Err(reject("fanout_peak_within_bound"));
    }
    if !evidence.recovered_after_each_round {
        return Err(reject("recovered_after_each_round"));
    }
    if !evidence.final_recovery_echo {
        return Err(reject("final_recovery_echo"));
    }
    if !evidence.cleanup_joined {
        return Err(reject("cleanup_joined"));
    }
    Ok(())
}

/// A live owner CLI session: the real `tunnel-client` process plus its admitted
/// consumer stream to the owning relay's ingress.
struct Session {
    process: ManagedProcess,
    stream: ConsumerStream,
}

struct ChaosContext<'a> {
    cluster: &'a mut ProductionCluster,
    harness: &'a RunningHarness,
    redis_proxy: &'a ProxyHandle,
    profile: &'a DeviceProfile,
    device_id: Uuid,
    tenant_id: Uuid,
    service_id: Uuid,
    canary: Vec<u8>,
    /// Pre-readiness CLI exits seen on the establish path, and how many of
    /// those carried a typed CLI exit code.
    client_exit_before_ready: usize,
    client_exit_classified: usize,
    /// Whether every relay's membership runtime returned to `Ready` on its own
    /// after the full Redis outage ended.
    redis_membership_recovery_observed: bool,
    /// How many Redis rounds observed that re-arm.
    redis_recovery_rounds: usize,
}

/// Bounded chaos gate entrypoint.
pub async fn verify() -> Result<ChaosEvidence> {
    let base_options = HarnessOptions::from_env()?;
    let upstream_url =
        base_options
            .redis_url
            .clone()
            .ok_or_else(|| HarnessError::MissingRedisUrl {
                env_var: "TEST_REDIS_URL",
                guidance: "The chaos gate requires TEST_REDIS_URL for its opaque Redis proxy."
                    .to_owned(),
            })?;
    let target = redis_target_address(&upstream_url)?;
    let redis_proxy = TcpProxy::bind(target, ProxyConfig::default()).await?;
    let proxy_url = format!("redis://{}", redis_proxy.local_addr());
    let options = base_options
        .redis_url(proxy_url)
        .namespace_prefix("m7-chaos")
        .rotation(CHAOS_ROTATION);
    let mut harness = match timeout(STARTUP_TIMEOUT, Harness::start(options)).await {
        Ok(Ok(harness)) => harness,
        Ok(Err(error)) => {
            let _ = redis_proxy.shutdown().await;
            return Err(error);
        }
        Err(_) => {
            let _ = redis_proxy.shutdown().await;
            return Err(HarnessError::Timeout(
                "chaos harness startup timed out".into(),
            ));
        }
    };
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            let _ = redis_proxy.shutdown().await;
            return Err(error);
        }
    };
    // This scenario runs longer than one membership record's maximum lifetime,
    // so the fixture has to keep issuing fresh records; see [`CHAOS_SCHEDULE`]
    // for what depended on that and why a longer record is not available.
    if let Err(error) = cluster.start_membership_resigning().await {
        let _ = cluster.shutdown().await;
        let _ = harness.shutdown().await;
        let _ = redis_proxy.shutdown().await;
        return Err(error);
    }

    let scenario = match timeout(
        CHAOS_SCENARIO_DEADLINE,
        run_chaos(&mut cluster, &harness, &redis_proxy),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "chaos scenario exceeded its bounded deadline".into(),
        )),
    };

    // Always resume the proxy so catalog namespace cleanup stays authoritative.
    let resume = redis_proxy.resume_all().await;
    let mut cleanup_errors = Vec::new();
    if let Err(error) = resume {
        cleanup_errors.push(format!("Redis proxy resume: {error}"));
    }
    if let Err(error) = cluster.shutdown().await {
        cleanup_errors.push(format!("relay cleanup: {error}"));
    }
    if let Err(error) = harness.shutdown().await {
        cleanup_errors.push(format!("catalog cleanup: {error}"));
    }
    if let Err(error) = redis_proxy.shutdown().await {
        cleanup_errors.push(format!("Redis proxy cleanup: {error}"));
    }

    match (scenario, cleanup_errors.is_empty()) {
        (Err(error), true) => Err(error),
        (Err(error), false) => Err(HarnessError::Process(format!(
            "{error}; {}",
            cleanup_errors.join("; ")
        ))),
        (Ok(mut evidence), true) => {
            evidence.cleanup_joined = true;
            validate_chaos_evidence(&evidence)?;
            Ok(evidence)
        }
        (Ok(_), false) => Err(HarnessError::Process(cleanup_errors.join("; "))),
    }
}

async fn run_chaos(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    redis_proxy: &ProxyHandle,
) -> Result<ChaosEvidence> {
    let started = Instant::now();
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(format!(
            "chaos gate started {} relays, expected three",
            cluster.relays.len()
        )));
    }

    let device =
        harness.topology.devices_a.first().ok_or_else(|| {
            HarnessError::InvalidInput("chaos gate has no tenant-A device".into())
        })?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("chaos device has no echo service".into()))?;
    let canary = format!("m7-chaos:{}", device.id).into_bytes();
    let profile_directory: TempDir = tempdir().map_err(HarnessError::Io)?;
    let mut profile = write_device_profile(
        profile_directory.path(),
        device.id,
        service_id,
        &String::from_utf8_lossy(&canary),
        cluster.device_fanout.local_addr(),
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile.config.rotation = CHAOS_ROTATION;
    profile
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("chaos client config: {error}")))?;

    let mut context = ChaosContext {
        cluster,
        harness,
        redis_proxy,
        profile: &profile,
        device_id: device.id,
        tenant_id: device.tenant_id,
        service_id,
        canary,
        client_exit_before_ready: 0,
        client_exit_classified: 0,
        redis_membership_recovery_observed: false,
        redis_recovery_rounds: 0,
    };

    let mut evidence = ChaosEvidence {
        relay_count: 3,
        rounds: 0,
        owner_kill_rounds: 0,
        cli_pause_rounds: 0,
        peer_loss_rounds: 0,
        redis_pause_rounds: 0,
        classified_interruptions: 0,
        unclassified_interruptions: 0,
        unknown_outcomes_preserved: 0,
        peer_loss_unknown_outcomes: 0,
        class_bounded_close: 0,
        class_admission_unavailable: 0,
        class_peer_unavailable: 0,
        class_owner_released: 0,
        class_client_exit_before_ready: 0,
        reconnect_sockets_total: 0,
        max_reconnect_rate_milli: 0,
        reconnect_rate_threshold_milli: RECONNECT_RATE_THRESHOLD_MILLI,
        cli_reconnect_sockets: 0,
        fixture_recycle_sockets: 0,
        max_recycle_sockets_round: 0,
        max_cli_reconnects_per_window: 0,
        reconnect_window_ms: RECONNECT_WINDOW.as_millis() as u64,
        max_cli_reconnects_allowed: MAX_CLI_RECONNECTS_PER_WINDOW,
        accept_instants_dropped: 0,
        client_exit_before_ready: 0,
        client_exit_classified: 0,
        redis_membership_recovery_observed: false,
        redis_recovery_rounds: 0,
        fanout_peak_open: 0,
        recovered_after_each_round: true,
        final_recovery_echo: false,
        cleanup_joined: false,
        elapsed_ms: 0,
    };

    // A live owner session is the precondition of every round.  Its baseline
    // echo confirms the cluster admits before any fault is injected.
    let mut session = establish_session_retrying(&mut context).await?;
    hard_recovery_echo(&mut context, &mut session).await?;

    // Reconnect attribution starts once the baseline session is live, so the
    // fixture's own baseline establishment is never counted as a reconnect.
    let measure_from = Instant::now();
    // Half-open brackets around the fixture's deliberate session recycles.
    // Accepts inside them are fixture churn, not client reconnects.
    let mut fixture_windows: Vec<(Instant, Instant)> = Vec::new();
    let mut recovered_each_round = true;
    for &fault in CHAOS_SCHEDULE.iter() {
        let round_started = Instant::now();
        let accepted_before = context.cluster.device_fanout.diagnostics().accepted;

        let class = match fault {
            Fault::RedisPause => run_redis_pause(&mut context).await?,
            Fault::PeerLoss => run_peer_loss(&mut context).await?,
            Fault::CliPause => run_cli_pause(&mut session).await?,
            Fault::OwnerKill => run_owner_kill(&mut context, &mut session).await?,
        };
        if class == InterruptionClass::Unclassified {
            // Attribute the event to its exact round and fault so a single
            // unreproducible occurrence can still be investigated from the
            // log alone.  The per-classifier warnings name the typed shape.
            tracing::warn!(
                round = evidence.rounds + 1,
                fault = fault.label(),
                stage = "chaos_round_unclassified",
                "chaos round produced an interruption the closed vocabulary does not explain"
            );
        }
        tally_class(&mut evidence, class);
        if class == InterruptionClass::OutcomeUnknown && fault == Fault::PeerLoss {
            evidence.peer_loss_unknown_outcomes += 1;
        }
        match fault {
            Fault::RedisPause => evidence.redis_pause_rounds += 1,
            Fault::PeerLoss => evidence.peer_loss_rounds += 1,
            Fault::CliPause => evidence.cli_pause_rounds += 1,
            Fault::OwnerKill => evidence.owner_kill_rounds += 1,
        }
        evidence.rounds += 1;

        // Recovery policy is now uniform: every fault disturbs the live
        // session, so every round recycles it and echoes on the fresh one.
        // The recycle is the fixture's own churn, so it is bracketed out of
        // the client-attributed reconnect metric.  RedisPause has already
        // asserted its membership re-arm and re-published peer pins inside
        // `run_redis_pause`, so the cluster is routable again here.
        let recycle_from = Instant::now();
        session = recycle_session(&mut context, session).await?;
        fixture_windows.push((recycle_from, Instant::now()));
        record_recovery(
            &mut evidence,
            &mut recovered_each_round,
            soft_recovery_echo(&mut context, &mut session).await?,
        );

        let accepted_after = context.cluster.device_fanout.diagnostics().accepted;
        let round_ms = u64::try_from(round_started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let delta = accepted_after.saturating_sub(accepted_before);
        let rate_milli = delta
            .saturating_mul(1_000_000)
            .checked_div(round_ms)
            .unwrap_or_else(|| delta.saturating_mul(1_000_000));
        evidence.max_reconnect_rate_milli = evidence.max_reconnect_rate_milli.max(rate_milli);
    }
    evidence.recovered_after_each_round = recovered_each_round;

    // Second-scale reconnect measurement.  The fixture records the exact
    // instant of every accepted device-fanout socket, so the rate is a real
    // one-second window over client-attributed accepts rather than a count
    // divided by a whole round.
    let measure_to = Instant::now();
    let diagnostics = context.cluster.device_fanout.diagnostics();
    evidence.accept_instants_dropped = diagnostics.dropped_accepts;
    let in_span: Vec<Instant> = diagnostics
        .recent_accepts
        .iter()
        .copied()
        .filter(|at| *at >= measure_from && *at <= measure_to)
        .collect();
    let cli_accepts = cli_accept_instants(
        &diagnostics.recent_accepts,
        measure_from,
        measure_to,
        &fixture_windows,
    );
    evidence.reconnect_sockets_total = in_span.len() as u64;
    evidence.cli_reconnect_sockets = cli_accepts.len() as u64;
    evidence.fixture_recycle_sockets = evidence
        .reconnect_sockets_total
        .saturating_sub(evidence.cli_reconnect_sockets);
    evidence.max_recycle_sockets_round = fixture_windows
        .iter()
        .map(|(start, end)| {
            in_span
                .iter()
                .filter(|at| *at >= start && *at <= end)
                .count() as u64
        })
        .max()
        .unwrap_or(0);
    evidence.max_cli_reconnects_per_window = max_instants_in_window(&cli_accepts, RECONNECT_WINDOW);
    evidence.client_exit_before_ready = context.client_exit_before_ready;
    evidence.client_exit_classified = context.client_exit_classified;
    evidence.redis_membership_recovery_observed = context.redis_membership_recovery_observed;
    evidence.redis_recovery_rounds = context.redis_recovery_rounds;

    teardown_session(&mut context, session).await?;
    evidence.fanout_peak_open = context.cluster.device_fanout.diagnostics().peak_open;
    evidence.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(evidence)
}

/// Record one round's recovery echo: the most recent success is the run's
/// recovery evidence, and any failure also fails the per-round invariant.
fn record_recovery(evidence: &mut ChaosEvidence, recovered_each_round: &mut bool, recovered: bool) {
    if recovered {
        evidence.final_recovery_echo = true;
    } else {
        *recovered_each_round = false;
        evidence.final_recovery_echo = false;
    }
}

fn tally_class(evidence: &mut ChaosEvidence, class: InterruptionClass) {
    match class {
        InterruptionClass::Unclassified => evidence.unclassified_interruptions += 1,
        InterruptionClass::OutcomeUnknown => evidence.unknown_outcomes_preserved += 1,
        InterruptionClass::BoundedClose => {
            evidence.classified_interruptions += 1;
            evidence.class_bounded_close += 1;
        }
        InterruptionClass::AdmissionUnavailable => {
            evidence.classified_interruptions += 1;
            evidence.class_admission_unavailable += 1;
        }
        InterruptionClass::PeerUnavailable => {
            evidence.classified_interruptions += 1;
            evidence.class_peer_unavailable += 1;
        }
        InterruptionClass::OwnerReleased => {
            evidence.classified_interruptions += 1;
            evidence.class_owner_released += 1;
        }
        InterruptionClass::ClientExitBeforeReady => {
            evidence.classified_interruptions += 1;
            evidence.class_client_exit_before_ready += 1;
        }
    }
}

fn issue_token(harness: &RunningHarness) -> Result<String> {
    harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(90),
            ..OidcTokenOptions::default()
        },
    )
}

/// Establish a fresh owner session, retrying a bounded number of times.
///
/// Immediately after a fault (a Redis pause resume, a restored peer path, an
/// owner kill) a fresh `tunnel-client` can hit a transient transport error and
/// exit before it is routed.  That is a normal chaos condition for the
/// *recovery* path (distinct from the deliberately injected fault), so a
/// bounded retry is allowed here; a persistent failure still aborts.
async fn establish_session_retrying(context: &mut ChaosContext<'_>) -> Result<Session> {
    let mut last_error: Option<HarnessError> = None;
    for attempt in 0..MAX_ESTABLISH_ATTEMPTS {
        // Clear any partial claim left by a previous failed attempt so the next
        // CLI starts from a clean owner slot.
        ensure_owner_released(context).await?;
        match establish_session(context).await {
            Ok(session) => return Ok(session),
            Err(error) => {
                // A CLI that exits before readiness is a real interruption of
                // the recovery path.  Give it a class from the CLI's own typed
                // exit-code vocabulary and record it as evidence, instead of
                // letting it surface as an opaque harness error or vanish into
                // a silent rerun.  An exit carrying no typed code is
                // unclassified and blocks release.
                if let HarnessError::CliExitedBeforeReady {
                    code,
                    diagnostic_code,
                    ..
                } = &error
                {
                    let class = classify_client_exit(*code);
                    context.client_exit_before_ready += 1;
                    if class == InterruptionClass::ClientExitBeforeReady {
                        context.client_exit_classified += 1;
                    }
                    let fanout = context.cluster.device_fanout.diagnostics();
                    tracing::warn!(
                        attempt = attempt + 1,
                        exit_code = ?code,
                        diagnostic_code = ?diagnostic_code,
                        class = class.label(),
                        fanout_open = fanout.open_count(),
                        fanout_accepted = fanout.accepted,
                        fanout_closed = fanout.closed_count,
                        fanout_peak = fanout.peak_open,
                        stage = "chaos_client_exit_before_ready",
                        "owner CLI exited before readiness on the establish path"
                    );
                }
                last_error = Some(error);
                if attempt + 1 < MAX_ESTABLISH_ATTEMPTS {
                    sleep(ESTABLISH_RETRY_DELAY).await;
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        HarnessError::Process("chaos session establishment failed without a recorded error".into())
    }))
}

/// Start a fresh owner CLI and its admitted consumer stream, asserting
/// authoritative Redis ownership.  No echo here; the caller decides whether the
/// recovery echo is a hard precondition or a soft (recorded) observation.
async fn establish_session(context: &mut ChaosContext<'_>) -> Result<Session> {
    let consumer_addr = context.cluster.relay(OWNER_INGRESS_NODE)?.consumer_addr()?;
    let token = issue_token(context.harness)?;
    let (process, mut stream) = start_cli_smoke(
        context.harness,
        context.cluster.device_fanout.local_addr(),
        consumer_addr,
        context.profile,
        &token,
        context.device_id,
        context.service_id,
    )
    .await?;
    let owner = context
        .cluster
        .catalog
        .current_owner(context.tenant_id, context.device_id, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("reading chaos owner: {error}")))?;
    if owner.is_none() {
        let _ = stream.close().await;
        let _ = process.shutdown(Duration::from_secs(5)).await;
        return Err(HarnessError::Process(
            "chaos CLI did not claim an owner".into(),
        ));
    }
    Ok(Session { process, stream })
}

/// Join a live session's process and stream, then wait for the owner to clear
/// and the device fanout to drain so the next session claims a fresh epoch.
async fn teardown_session(context: &mut ChaosContext<'_>, mut session: Session) -> Result<()> {
    let _ = session.stream.close().await;
    session
        .process
        .shutdown(Duration::from_secs(5))
        .await
        .map_err(|error| HarnessError::Process(format!("joining chaos CLI: {error}")))?;
    ensure_owner_released(context).await?;
    wait_for_fanout_drained(&context.cluster.device_fanout, "chaos teardown").await?;
    Ok(())
}

/// Tear down the old session and establish a fresh one.
async fn recycle_session(context: &mut ChaosContext<'_>, old: Session) -> Result<Session> {
    teardown_session(context, old).await?;
    establish_session_retrying(context).await
}

/// A recovery echo whose failure aborts the run (used only for the baseline).
async fn hard_recovery_echo(context: &mut ChaosContext<'_>, session: &mut Session) -> Result<()> {
    match soft_recovery_echo(context, session).await? {
        true => Ok(()),
        false => Err(HarnessError::Process(
            "chaos baseline owner did not echo".into(),
        )),
    }
}

/// A recovery echo whose failure is recorded (returned false) rather than fatal,
/// so a genuine recovery gap is captured as evidence.
async fn soft_recovery_echo(context: &mut ChaosContext<'_>, session: &mut Session) -> Result<bool> {
    let canary = context.canary.clone();
    let echo = timeout(
        RECOVERY_ECHO_TIMEOUT,
        session.stream.round_trip(b"m7-chaos-recovery", &canary),
    )
    .await;
    match echo {
        Ok(Ok(())) => Ok(true),
        Ok(Err(_)) => Ok(false),
        Err(_) => Ok(false),
    }
}

/// Observe whether the relay releases the owner lease on its own within
/// `budget` after an abrupt owner loss.  This never force-releases: it is the
/// evidence source for the `owner_released` classification, so it must reflect
/// the relay's own behavior.
async fn observe_owner_released(context: &ChaosContext<'_>, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        let owner = timeout(
            REDIS_PARTITION_OPERATION_TIMEOUT,
            context
                .cluster
                .catalog
                .current_owner(context.tenant_id, context.device_id, Utc::now()),
        )
        .await;
        if let Ok(Ok(None)) = owner {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(ROUND_POLL).await;
    }
}

/// Ensure the device owner is cleared before a fresh session claims a new
/// epoch.  A Redis pause can orphan the lease (the relay could not run its
/// compare-and-release while Redis was unreachable, so it fell back to lease
/// expiry); this cleanup actively releases this device's own orphaned lease
/// rather than waiting out the natural expiry.  It is bounded and idempotent.
async fn ensure_owner_released(context: &ChaosContext<'_>) -> Result<()> {
    let deadline = Instant::now() + OWNER_RELEASE_TIMEOUT;
    loop {
        let owner = timeout(
            REDIS_PARTITION_OPERATION_TIMEOUT,
            context
                .cluster
                .catalog
                .current_owner(context.tenant_id, context.device_id, Utc::now()),
        )
        .await;
        match owner {
            Ok(Ok(None)) => return Ok(()),
            Ok(Ok(Some(record))) => {
                // Release this device's own lease (compare-and-release on the
                // exact token) so the next session starts clean.
                let _ = timeout(
                    REDIS_PARTITION_OPERATION_TIMEOUT,
                    context.cluster.catalog.release_owner(&record.token),
                )
                .await;
            }
            Ok(Err(_)) | Err(_) => {}
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "chaos owner lease was not released before its bound".into(),
            ));
        }
        sleep(ROUND_POLL).await;
    }
}

/// RedisPause round: pause every proxied Redis socket, prove
/// admission fails closed with a typed authorization/cluster-unready response,
/// then resume and **wait for every relay's membership runtime to return to
/// `Ready`**.
///
/// The full outage drives each membership runtime Unready because its signed
/// checkpoint cannot be refreshed against an unreachable catalog.  That state
/// is not latched: the supervisor keeps reconciling on its interval and
/// restores `Ready` from the current pass alone once a strictly-newer signed
/// checkpoint and a catalog snapshot land together.  Waiting for that here
/// turns the re-arm into an asserted observation instead of an assumption.
///
/// The cluster is then reused: the caller recycles the owner session and
/// echoes on it, and further rounds follow, so recovery after a full Redis
/// outage is proved at the session level and not only at the membership level.
async fn run_redis_pause(context: &mut ChaosContext<'_>) -> Result<InterruptionClass> {
    let ingress = context.cluster.relay(OWNER_INGRESS_NODE)?.consumer_addr()?;
    context.redis_proxy.pause_all().await?;
    let probe = async {
        sleep(REDIS_PARTITION_AUTHORIZATION_WAIT).await;
        let token = issue_token(context.harness)?;
        let admission = timeout(
            REDIS_PARTITION_OPERATION_TIMEOUT,
            open_consumer_stream(
                ingress,
                &context.harness.pki.server_ca.certificate_der,
                &token,
                context.device_id,
                context.service_id,
            ),
        )
        .await;
        Ok::<InterruptionClass, HarnessError>(classify_admission(admission))
    }
    .await;
    let resume = context.redis_proxy.resume_all().await;
    match (probe, resume) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(class), Ok(())) => {
            // Observed and never forced: whether every relay's membership
            // runtime re-arms to `Ready` by its own reconcile loop after the
            // outage.  This is now asserted, because membership trust no
            // longer lapses mid-run and the re-arm is position-independent.
            let recovered = context
                .cluster
                .observe_membership_readiness(MEMBERSHIP_OBSERVE_BUDGET)
                .await;
            tracing::info!(
                recovered,
                stage = "chaos_redis_membership_recovery",
                "observed whether membership re-armed after the full Redis outage"
            );
            if !recovered {
                return Err(HarnessError::Timeout(
                    "chaos redis round: membership did not return to Ready after the outage".into(),
                ));
            }
            // Every Redis round must re-arm, not just the first, so the
            // evidence records the conjunction rather than the last round.
            context.redis_membership_recovery_observed = true;
            context.redis_recovery_rounds += 1;

            // The fixture publishes peer pins from the membership
            // *invalidation* callback only, which is edge-triggered: the
            // outage emptied each relay's pin set and nothing re-publishes it
            // when the runtime returns to `Ready`.  That gap is in the
            // fixture's wiring, not the membership runtime and not the
            // protocol, so re-publish explicitly before the cluster is reused
            // -- exactly as the key-revocation probe does after it
            // deliberately revokes pins.
            context.cluster.republish_peer_pins()?;
            context
                .cluster
                .wait_for_peer_readiness(PEER_RECOVERY_TIMEOUT)
                .await?;
            Ok(class)
        }
    }
}

/// PeerLoss round: black-hole the owner relay's signed peer inbound path and
/// probe admission through a different (non-owner) relay, the same injection
/// the dedicated `verify-m7-peer-readiness` gate proves recovers.  The non-owner
/// relay can no longer reach the owner over the private peer network, so
/// admission fails closed.  The path is then restored and peer readiness
/// awaited; the round's recycle re-establishes the owner session (peer UDP loss
/// does not affect the Redis-backed membership, so the cluster stays routable).
async fn run_peer_loss(context: &mut ChaosContext<'_>) -> Result<InterruptionClass> {
    let owner = context
        .cluster
        .catalog
        .current_owner(context.tenant_id, context.device_id, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("reading chaos peer-loss owner: {error}")))?
        .ok_or_else(|| HarnessError::Process("chaos peer-loss round has no owner".into()))?;
    let owner_node = owner.token.node_id;
    // Probe through a relay that does not own the device, so reaching the owner
    // genuinely requires the (now black-holed) owner peer inbound path.
    let ingress_node = context
        .cluster
        .relays
        .iter()
        .map(|relay| relay.node_id.clone())
        .find(|node| node != &owner_node)
        .ok_or_else(|| {
            HarnessError::Process("chaos peer-loss found no non-owner ingress relay".into())
        })?;
    let ingress = context.cluster.relay(&ingress_node)?.consumer_addr()?;

    context.cluster.set_peer_path_drop(&owner_node, true)?;
    let token = issue_token(context.harness)?;
    let admission = timeout(
        REDIS_PARTITION_OPERATION_TIMEOUT,
        open_consumer_stream(
            ingress,
            &context.harness.pki.server_ca.certificate_der,
            &token,
            context.device_id,
            context.service_id,
        ),
    )
    .await;
    let class = classify_admission(admission);
    context.cluster.set_peer_path_drop(&owner_node, false)?;
    context
        .cluster
        .wait_for_peer_readiness(PEER_RECOVERY_TIMEOUT)
        .await?;
    Ok(class)
}

/// CliPause round: SIGSTOP the owner CLI past its challenge lease, prove the
/// consumer probe fails closed, then SIGCONT and join.
async fn run_cli_pause(session: &mut Session) -> Result<InterruptionClass> {
    let mut guard = ProcessPauseGuard::new(&session.process)?;
    let pause_started = Instant::now();
    let pause_result = guard.pause(&mut session.process);
    let probe = match pause_result {
        Ok(()) => {
            let remaining = PROCESS_PAUSE_MIN_DURATION.saturating_sub(pause_started.elapsed());
            if !remaining.is_zero() {
                sleep(remaining).await;
            }
            let probe = session
                .stream
                .probe_after_pause(b"m7-chaos-pause-stale")
                .await;
            Ok(classify_probe(probe))
        }
        Err(error) => Err(error),
    };
    let resume = guard.resume(&mut session.process);
    match (probe, resume) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(HarnessError::Process(format!(
            "resuming chaos CLI: {error}"
        ))),
        (Ok(class), Ok(())) => Ok(class),
    }
}

/// OwnerKill round: abruptly SIGKILL the owner CLI, prove the admitted consumer
/// stream closes fail-closed and the owner lease is released.
async fn run_owner_kill(
    context: &mut ChaosContext<'_>,
    session: &mut Session,
) -> Result<InterruptionClass> {
    send_managed_process_signal(&mut session.process, "-KILL")?;
    let probe = timeout(
        POSTKILL_CLOSE_TIMEOUT,
        session
            .stream
            .round_trip(b"m7-chaos-postkill", &context.canary),
    )
    .await;
    let stream_class = match probe {
        Ok(Ok(())) => InterruptionClass::Unclassified, // a killed owner must not echo
        Ok(Err(error)) if is_expected_revocation_close(&error) => InterruptionClass::BoundedClose,
        // Any other error after the kill (protocol error, unexpected status,
        // harness I/O failure) is an abnormal close the vocabulary does not
        // explain.  It must surface as unclassified and fail the gate rather
        // than be folded into the bounded-close bucket.
        Ok(Err(error)) => {
            tracing::warn!(
                error = %error,
                stage = "chaos_owner_kill_unexplained_close",
                "owner kill produced a close outside the expected revocation vocabulary"
            );
            InterruptionClass::Unclassified
        }
        Err(_) => InterruptionClass::OutcomeUnknown,
    };
    if stream_class == InterruptionClass::Unclassified {
        return Ok(InterruptionClass::Unclassified);
    }
    // Observe whether the relay releases the owner lease on its own after the
    // abrupt control loss; do not force it here, so the classification reflects
    // the relay's real behavior.  The teardown that follows this round still
    // guarantees the lease is cleared before the next session.
    let released = observe_owner_released(context, OWNER_KILL_OBSERVE_BUDGET).await;
    if released {
        Ok(InterruptionClass::OwnerReleased)
    } else {
        Ok(stream_class)
    }
}

/// Map an admission attempt onto the closed vocabulary.
fn classify_admission(
    admission: std::result::Result<
        std::result::Result<ConsumerStream, StreamConnectFailure>,
        tokio::time::error::Elapsed,
    >,
) -> InterruptionClass {
    match admission {
        Err(_) => InterruptionClass::OutcomeUnknown,
        Ok(Ok(stream)) => {
            tracing::warn!(
                stage = "chaos_admission_succeeded_under_fault",
                "chaos admission succeeded while the authority was paused"
            );
            // Admission unexpectedly succeeded during a fault: unclassified.
            drop(stream);
            InterruptionClass::Unclassified
        }
        Ok(Err(StreamConnectFailure::Status { status, body })) => {
            if is_partition_admission_response(status, body.as_deref()) {
                InterruptionClass::AdmissionUnavailable
            } else if is_peer_recovery_response(status, body.as_deref()) {
                InterruptionClass::PeerUnavailable
            } else if is_peer_unknown_outcome_response(status, body.as_deref()) {
                // The relay forwarded toward the owner and then lost the peer
                // path, so whether the request was dispatched is genuinely
                // unknown and it says so (`execution: "unknown"`).  That is a
                // typed, explicitly preserved unknown outcome, not an
                // unexplained close: a blackholed peer route produces it
                // whenever the transport fails after the request was written.
                InterruptionClass::OutcomeUnknown
            } else {
                // Record the exact typed shape that the closed vocabulary
                // does not explain.  Only the status and the allowlisted
                // `code`/`execution` labels are copied; no body bytes.
                let parsed = body
                    .as_deref()
                    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(bytes).ok());
                tracing::warn!(
                    status,
                    code = parsed
                        .as_ref()
                        .and_then(|value| value.get("code"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("absent"),
                    execution = parsed
                        .as_ref()
                        .and_then(|value| value.get("execution"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("absent"),
                    body_parsed = parsed.is_some(),
                    stage = "chaos_admission_unexplained_status",
                    "chaos admission produced a typed response outside the closed vocabulary"
                );
                InterruptionClass::Unclassified
            }
        }
        Ok(Err(StreamConnectFailure::Harness(_))) => InterruptionClass::OutcomeUnknown,
    }
}

/// Map a paused-process probe outcome onto the closed vocabulary.
/// A typed peer failure whose dispatch outcome the relay reports as unknown.
///
/// `is_peer_recovery_response` deliberately requires `not_dispatched`, because
/// the gates that use it prove no side effect occurred.  Here the unknown
/// variant is equally valid evidence: it is the documented outcome when the
/// peer transport fails after the request may already have reached the owner.
fn is_peer_unknown_outcome_response(status: u16, body: Option<&[u8]>) -> bool {
    if status != 503 {
        return false;
    }
    let Some(body) = body else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    let code = value.get("code").and_then(serde_json::Value::as_str);
    let execution = value.get("execution").and_then(serde_json::Value::as_str);
    matches!(
        code,
        Some("PEER_UNAVAILABLE") | Some("PEER_UNTRUSTED") | Some("CLUSTER_UNREADY")
    ) && execution == Some("unknown")
}

fn classify_probe(probe: ProcessPauseProbeOutcome) -> InterruptionClass {
    if probe.is_fail_closed() {
        InterruptionClass::BoundedClose
    } else if matches!(
        probe,
        ProcessPauseProbeOutcome::TimedOut | ProcessPauseProbeOutcome::SendFailed
    ) {
        InterruptionClass::OutcomeUnknown
    } else {
        tracing::warn!(
            outcome = ?probe,
            stage = "chaos_probe_unexplained_outcome",
            "chaos pause probe produced an outcome outside the closed vocabulary"
        );
        // EchoAfterSend / ProtocolAfterSend: a paused owner must not echo.
        InterruptionClass::Unclassified
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CHAOS_ROUNDS, ChaosEvidence, InterruptionClass, MAX_CLI_RECONNECTS_PER_WINDOW,
        MAX_RECYCLE_SOCKETS_PER_ROUND, MAX_UNKNOWN_OUTCOMES, RECONNECT_RATE_THRESHOLD_MILLI,
        RECONNECT_WINDOW, classify_client_exit, max_instants_in_window, validate_chaos_evidence,
    };
    use crate::acceptance_test_support::assert_failed;
    use std::time::{Duration, Instant};

    #[test]
    fn a_typed_unknown_peer_outcome_is_preserved_not_unclassified() {
        use super::is_peer_unknown_outcome_response;
        // Exactly the shape the relay returns when the peer transport fails
        // after the request may have been written (http.rs owner-forwarding
        // failure mapping): the outcome is unknown and typed.
        for code in ["PEER_UNAVAILABLE", "PEER_UNTRUSTED", "CLUSTER_UNREADY"] {
            let body = format!(
                r#"{{"code":"{code}","execution":"unknown","message":"owner forwarding did not complete"}}"#
            );
            assert!(
                is_peer_unknown_outcome_response(503, Some(body.as_bytes())),
                "{code}/unknown must be a preserved unknown outcome"
            );
        }
        // Everything else stays outside this bucket: a not-dispatched peer
        // failure is a concrete class, a different status is not a peer
        // failure, and an absent or unparsable body proves nothing.
        let not_dispatched = br#"{"code":"PEER_UNAVAILABLE","execution":"not_dispatched"}"#;
        assert!(!is_peer_unknown_outcome_response(503, Some(not_dispatched)));
        assert!(!is_peer_unknown_outcome_response(
            500,
            Some(br#"{"code":"PEER_UNAVAILABLE","execution":"unknown"}"#)
        ));
        assert!(!is_peer_unknown_outcome_response(
            503,
            Some(br#"{"code":"UNAUTHORIZED","execution":"unknown"}"#)
        ));
        assert!(!is_peer_unknown_outcome_response(503, Some(b"not json")));
        assert!(!is_peer_unknown_outcome_response(503, None));
    }

    fn valid_evidence() -> ChaosEvidence {
        // Schedule: peer-loss x2 -> peer_unavailable, redis-pause x2 ->
        // admission_unavailable, cli-pause x2 -> bounded_close, owner-kill x2
        // -> owner_released.  Eight classified rounds.
        ChaosEvidence {
            relay_count: 3,
            rounds: CHAOS_ROUNDS,
            owner_kill_rounds: 2,
            cli_pause_rounds: 2,
            peer_loss_rounds: 2,
            redis_pause_rounds: 2,
            classified_interruptions: 8,
            unclassified_interruptions: 0,
            unknown_outcomes_preserved: 0,
            peer_loss_unknown_outcomes: 0,
            class_bounded_close: 2,
            class_admission_unavailable: 2,
            class_peer_unavailable: 2,
            class_owner_released: 2,
            class_client_exit_before_ready: 0,
            reconnect_sockets_total: 12,
            max_reconnect_rate_milli: 600,
            reconnect_rate_threshold_milli: RECONNECT_RATE_THRESHOLD_MILLI,
            cli_reconnect_sockets: 0,
            fixture_recycle_sockets: 12,
            max_recycle_sockets_round: 2,
            max_cli_reconnects_per_window: 0,
            reconnect_window_ms: RECONNECT_WINDOW.as_millis() as u64,
            max_cli_reconnects_allowed: MAX_CLI_RECONNECTS_PER_WINDOW,
            accept_instants_dropped: 0,
            client_exit_before_ready: 0,
            client_exit_classified: 0,
            redis_membership_recovery_observed: true,
            redis_recovery_rounds: 2,
            fanout_peak_open: 3,
            recovered_after_each_round: true,
            final_recovery_echo: true,
            cleanup_joined: true,
            elapsed_ms: 120_000,
        }
    }

    #[test]
    fn label_covers_every_class() {
        for class in [
            InterruptionClass::BoundedClose,
            InterruptionClass::AdmissionUnavailable,
            InterruptionClass::PeerUnavailable,
            InterruptionClass::OwnerReleased,
            InterruptionClass::OutcomeUnknown,
            InterruptionClass::ClientExitBeforeReady,
            InterruptionClass::Unclassified,
        ] {
            assert!(!class.label().is_empty());
        }
    }

    #[test]
    fn complete_chaos_evidence_passes() {
        assert!(validate_chaos_evidence(&valid_evidence()).is_ok());
        // One preserved unknown outcome (converted from one classified round) is
        // still accepted: seven classified plus one preserved unknown is eight,
        // which is the round count of the current schedule.
        let mut with_unknown = valid_evidence();
        with_unknown.classified_interruptions = 7;
        with_unknown.class_owner_released = 1;
        with_unknown.unknown_outcomes_preserved = 1;
        with_unknown.peer_loss_unknown_outcomes = 1;
        assert!(validate_chaos_evidence(&with_unknown).is_ok());
    }

    #[test]
    fn a_pre_readiness_cli_exit_is_classified_only_for_typed_exit_codes() {
        // The CLI's documented exit codes are a closed vocabulary.
        for code in [1, 2, 3, 4, 5, 6] {
            assert_eq!(
                classify_client_exit(Some(code)),
                InterruptionClass::ClientExitBeforeReady,
                "exit code {code} is a typed CLI diagnostic"
            );
        }
        // A signal death carries no exit code, and a success exit before
        // readiness is not a diagnostic at all.  Neither is classified.
        assert_eq!(classify_client_exit(None), InterruptionClass::Unclassified);
        assert_eq!(
            classify_client_exit(Some(0)),
            InterruptionClass::Unclassified
        );
        assert_eq!(
            classify_client_exit(Some(7)),
            InterruptionClass::Unclassified
        );
    }

    #[test]
    fn the_reconnect_metric_sees_a_burst_a_round_average_would_hide() {
        let base = Instant::now();
        // Ten reconnects inside one second, then silence: exactly the shape the
        // old whole-round average scored as 1/s and passed.
        let burst: Vec<Instant> = (0..10)
            .map(|index| base + Duration::from_millis(index * 50))
            .collect();
        assert_eq!(max_instants_in_window(&burst, RECONNECT_WINDOW), 10);
        assert!(
            max_instants_in_window(&burst, RECONNECT_WINDOW) > MAX_CLI_RECONNECTS_PER_WINDOW,
            "a ten-reconnect burst must exceed the ceiling"
        );
        // The same ten spread evenly over ten seconds stay within the window.
        let spread: Vec<Instant> = (0..10)
            .map(|index| base + Duration::from_millis(index * 1_000))
            .collect();
        assert_eq!(max_instants_in_window(&spread, RECONNECT_WINDOW), 1);
        assert_eq!(max_instants_in_window(&[], RECONNECT_WINDOW), 0);
    }

    #[test]
    fn every_chaos_condition_names_its_rejection() {
        type Case = (&'static str, &'static str, fn(&mut ChaosEvidence));
        let cases: &[Case] = &[
            ("relay_count", "relay_count_is_three", |e| e.relay_count = 2),
            ("rounds", "round_count_matches_schedule", |e| {
                e.rounds = CHAOS_ROUNDS - 1
            }),
            ("fault_tally", "fault_round_tally_matches_rounds", |e| {
                e.owner_kill_rounds = 1
            }),
            ("owner_kill_missing", "each_fault_type_exercised", |e| {
                // Keep the round tally and class totals consistent while zeroing
                // one fault type (move owner-kill's rounds into redis-pause).
                e.owner_kill_rounds = 0;
                e.redis_pause_rounds = 4;
                e.class_owner_released = 0;
                e.class_admission_unavailable = 4;
            }),
            // An unknown that did not come from a blackholed peer path is a
            // gap in the vocabulary, even while the ceiling still accepts the
            // count.
            (
                "unknown_from_another_fault",
                "unknown_outcomes_attributed_to_peer_loss",
                |e| {
                    e.classified_interruptions -= 1;
                    e.class_bounded_close -= 1;
                    e.unknown_outcomes_preserved += 1;
                },
            ),
            // More unknowns than there were peer-loss rounds to explain them.
            (
                "unknowns_exceed_peer_loss_rounds",
                "peer_loss_unknowns_within_peer_loss_rounds",
                |e| {
                    // One peer-loss round, but two unknowns claimed for it:
                    // the round tally and every earlier guard still agree, so
                    // only this rule can catch the over-attribution.
                    e.peer_loss_rounds = 1;
                    e.cli_pause_rounds = 3;
                    e.class_peer_unavailable = 0;
                    e.classified_interruptions = 6;
                    e.unknown_outcomes_preserved = 2;
                    e.peer_loss_unknown_outcomes = 2;
                },
            ),
            // The Redis fault must be repeated, not exercised once.
            ("redis_single_round", "redis_pause_repeated", |e| {
                e.redis_pause_rounds = 1;
                e.cli_pause_rounds = 3;
                e.class_admission_unavailable = 1;
                e.class_bounded_close = 3;
                e.redis_recovery_rounds = 1;
            }),
            // Recovery must be observed after every Redis round.
            (
                "redis_recovery_partial",
                "redis_recovery_observed_each_round",
                |e| e.redis_recovery_rounds = 1,
            ),
            (
                "redis_recovery_absent",
                "redis_membership_recovery_observed",
                |e| e.redis_membership_recovery_observed = false,
            ),
            ("cli_pause_missing", "each_fault_type_exercised", |e| {
                e.cli_pause_rounds = 0;
                e.peer_loss_rounds = 4;
                e.class_bounded_close = 0;
                e.class_peer_unavailable = 4;
            }),
            ("unclassified", "no_unclassified_interruption", |e| {
                e.unclassified_interruptions = 1;
                e.classified_interruptions = 6;
                e.class_owner_released = 1;
            }),
            ("class_sum", "class_tally_matches_classified", |e| {
                e.class_bounded_close = 3
            }),
            ("unknown_over_bound", "unknown_outcomes_within_bound", |e| {
                let excess = MAX_UNKNOWN_OUTCOMES + 1;
                e.unknown_outcomes_preserved = excess;
                e.peer_loss_unknown_outcomes = excess;
                e.classified_interruptions = CHAOS_ROUNDS - excess;
                e.class_bounded_close = 0;
                e.class_peer_unavailable = 0;
                e.class_owner_released = 0;
                e.class_admission_unavailable = CHAOS_ROUNDS - excess;
            }),
            // Second-scale reconnect clause.
            ("window_constant", "documented_reconnect_window", |e| {
                e.reconnect_window_ms = RECONNECT_WINDOW.as_millis() as u64 + 1
            }),
            (
                "cli_ceiling_constant",
                "documented_cli_reconnect_ceiling",
                |e| e.max_cli_reconnects_allowed = MAX_CLI_RECONNECTS_PER_WINDOW + 1,
            ),
            ("accepts_evicted", "accept_instants_not_evicted", |e| {
                e.accept_instants_dropped = 1
            }),
            (
                "cli_reconnect_burst",
                "cli_reconnect_window_within_ceiling",
                |e| e.max_cli_reconnects_per_window = MAX_CLI_RECONNECTS_PER_WINDOW + 1,
            ),
            ("recycle_unbounded", "recycle_sockets_within_bound", |e| {
                e.max_recycle_sockets_round = MAX_RECYCLE_SOCKETS_PER_ROUND + 1
            }),
            (
                "attribution_mismatch",
                "reconnect_attribution_totals_match",
                |e| e.cli_reconnect_sockets = 1,
            ),
            // Pre-readiness CLI exit clause.
            (
                "client_exit_untyped",
                "client_exit_before_ready_classified",
                |e| {
                    e.client_exit_before_ready = 1;
                    e.client_exit_classified = 0;
                },
            ),
            (
                "threshold_constant",
                "documented_reconnect_threshold",
                |e| e.reconnect_rate_threshold_milli = RECONNECT_RATE_THRESHOLD_MILLI + 1,
            ),
            ("reconnect_rate", "reconnect_rate_within_threshold", |e| {
                e.max_reconnect_rate_milli = RECONNECT_RATE_THRESHOLD_MILLI + 1
            }),
            ("socket_peak", "fanout_peak_within_bound", |e| {
                e.fanout_peak_open = 5
            }),
            ("recovered_each", "recovered_after_each_round", |e| {
                e.recovered_after_each_round = false
            }),
            ("final_recovery", "final_recovery_echo", |e| {
                e.final_recovery_echo = false
            }),
            ("cleanup", "cleanup_joined", |e| e.cleanup_joined = false),
        ];
        for &(name, fragment, mutate) in cases {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            let diagnostic = assert_failed(validate_chaos_evidence(&evidence));
            assert!(
                diagnostic.contains(fragment),
                "{name}: expected {fragment:?} in diagnostic {diagnostic}"
            );
        }
    }
}
