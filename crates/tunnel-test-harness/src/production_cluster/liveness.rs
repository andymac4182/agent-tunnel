//! IN-10 / OG-05 heartbeat, liveness and bounded-shutdown evidence.
//!
//! The matrix rows require the receipt-driven M7 acceptance runs to record
//! heartbeat/liveness and shutdown evidence from the exact source-matched
//! CLI and relay, not only gateway tests.  Everything in this module is
//! observed from signals the product already produces:
//!
//! * **Heartbeat.** The only periodic authority round trip that exists end to
//!   end is the relay actor's owner-lease renewal.  Every live device session
//!   re-writes its Redis owner lease on a cadence derived from the configured
//!   `RelayOptions::owner_lease`, so sampling `Catalog::current_owner` and
//!   watching `lease_expires_at` advance counts real heartbeats without any
//!   product change and without any payload or credential.  The protocol's
//!   `PING`/`PONG` pair is *not* used: both the relay actor and the client
//!   answer an inbound `PING`, but nothing in the product ever emits one, and
//!   the `WELCOME` heartbeat interval/timeout fields are advertised but not
//!   driven.  Asserting on `PING`/`PONG` would have required adding a product
//!   heartbeat purely so a test could watch it.
//! * **Liveness vs readiness.** `tunnel_relay::health` serves `/livez` from
//!   process state only and `/readyz` from the cluster peer runtime, and the
//!   documented rule is that liveness may stay up while readiness fails
//!   closed.  The gate observes both states on one relay across the existing
//!   owner-death phase.
//! * **Shutdown.** The real CLI is interrupted and its join is *measured*,
//!   not flagged, and the measured duration is asserted against a bound taken
//!   from the fixture's own rotation policy.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tunnel_catalog::SharedCatalog;
use uuid::Uuid;

use super::{PRODUCTION_OWNER_LEASE, ROTATION};
use crate::{HarnessError, ManagedProcess, Result};

/// Poll spacing for the owner-lease sampler.  It only has to be far below
/// the renewal cadence so no renewal is missed; it asserts nothing itself.
const HEARTBEAT_SAMPLE_INTERVAL: Duration = Duration::from_millis(200);

/// Minimum owner-lease renewals the run must actually observe.  Counting is
/// the point: a session that merely stayed up produces zero of these.
const MINIMUM_HEARTBEAT_ROUND_TRIPS: usize = 3;

/// Minimum number of measured renewal intervals whose spacing is checked
/// against the configured window.
const MINIMUM_HEARTBEAT_INTERVALS: usize = 2;

/// Minimum number of measured renewal intervals that must come from one and
/// the same owner token, so at least one live session is seen heartbeating
/// repeatedly rather than several sessions each heartbeating once.
const MINIMUM_HEARTBEAT_RUN_INTERVALS: usize = 2;

/// Lower bound on one observed heartbeat interval.
///
/// Source: `tunnel_relay`'s actor maintenance round marks a session's owner
/// lease due for renewal when `last_lease_renewal.elapsed() >= owner_lease /
/// 3`, so two consecutive renewals of the same owner token can never be
/// closer together than a third of the configured lease.
#[must_use]
pub(super) const fn heartbeat_minimum_interval() -> Duration {
    Duration::from_millis(owner_lease_ms() / 3)
}

/// The configured production owner lease, in milliseconds.
#[must_use]
pub(super) const fn owner_lease_ms() -> u64 {
    PRODUCTION_OWNER_LEASE.as_secs() * 1_000
}

/// Upper bound on one observed heartbeat interval.
///
/// Source: the same configured `RelayOptions::owner_lease`.  A renewal that
/// landed later than the lease itself would have let the lease expire and
/// fenced the owner, so the whole lease is the outside edge of the window.
#[must_use]
pub(super) const fn heartbeat_maximum_interval() -> Duration {
    PRODUCTION_OWNER_LEASE
}

/// Bound on the real CLI's interrupted shutdown join.
///
/// Source: the fixture's configured rotation policy (`super::ROTATION`) — one
/// complete replacement cycle, `interval + handshake_timeout + overlap`.  A
/// connector stop must not outlast the longest scheduled control/data
/// replacement the very same configuration permits.  Changing `ROTATION`
/// moves this bound with it; nothing here is a hand-picked duration.
pub(super) const CLI_SHUTDOWN_JOIN_BOUND: Duration = Duration::from_secs(
    ROTATION.interval_seconds + ROTATION.handshake_timeout_seconds + ROTATION.overlap_seconds,
);

/// Payload-free heartbeat, liveness and shutdown evidence from one run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionLivenessEvidence {
    /// The configured owner lease every bound below is derived from.
    pub owner_lease_ms: u64,
    /// Lower edge of the permitted heartbeat window (`owner_lease / 3`).
    pub heartbeat_minimum_interval_ms: u64,
    /// Upper edge of the permitted heartbeat window (`owner_lease`).
    pub heartbeat_maximum_interval_ms: u64,
    /// Distinct owner tokens whose lease was sampled.
    pub heartbeat_owner_tokens: usize,
    /// Owner-lease renewals actually observed, counted.
    pub heartbeat_round_trips: usize,
    /// Consecutive-renewal intervals measured across all owner tokens.
    pub heartbeat_intervals: usize,
    /// Longest run of consecutive renewals within one owner token.
    pub longest_heartbeat_run_intervals: usize,
    /// Shortest observed interval, in milliseconds.
    pub observed_minimum_interval_ms: u64,
    /// Longest observed interval, in milliseconds.
    pub observed_maximum_interval_ms: u64,
    /// Every observed interval fell inside the configured window.
    pub heartbeat_intervals_within_bounds: bool,
    /// Bounded `/livez` probes issued against the production relay.
    pub livez_probes: usize,
    /// `/livez` probes that returned the redacted live envelope.
    pub livez_live: usize,
    /// Bounded `/readyz` probes issued against the production relay.
    pub readyz_probes: usize,
    /// `/readyz` probes that returned the redacted ready envelope.
    pub readyz_ready: usize,
    /// `/readyz` probes that failed closed with the redacted unready
    /// envelope.
    pub readyz_unready: usize,
    /// One relay served the live envelope while the same relay's readiness
    /// had gone false: liveness and readiness are distinguishable states, not
    /// one flag behind two paths.
    pub liveness_up_while_readiness_false: bool,
    /// The bound the measured CLI join is asserted against.
    pub cli_shutdown_join_bound_ms: u64,
    /// The measured CLI join, in milliseconds.
    pub cli_shutdown_join_ms: u64,
    /// The measured join landed inside the bound.
    pub cli_shutdown_joined_within_bound: bool,
    /// The interrupted CLI exited through its own stop path rather than
    /// being force-killed once the bound expired.
    pub cli_shutdown_graceful_exit: bool,
    /// The stopped CLI released its Redis owner.
    pub cli_shutdown_owner_released: bool,
}

/// Validate the mandatory IN-10/OG-05 heartbeat, liveness and shutdown
/// contract.  Every branch names the field it rejected.
pub fn validate_production_liveness_evidence(evidence: &ProductionLivenessEvidence) -> Result<()> {
    if evidence.owner_lease_ms == 0 {
        return Err(HarnessError::Process(
            "production liveness evidence owner_lease_ms was zero, so no heartbeat bound exists"
                .into(),
        ));
    }
    let expected_minimum = evidence.owner_lease_ms / 3;
    if evidence.heartbeat_minimum_interval_ms != expected_minimum
        || evidence.heartbeat_maximum_interval_ms != evidence.owner_lease_ms
    {
        return Err(HarnessError::Process(format!(
            "production liveness heartbeat window [{}, {}] ms is not derived from owner_lease_ms={}",
            evidence.heartbeat_minimum_interval_ms,
            evidence.heartbeat_maximum_interval_ms,
            evidence.owner_lease_ms
        )));
    }
    if evidence.heartbeat_round_trips < MINIMUM_HEARTBEAT_ROUND_TRIPS {
        return Err(HarnessError::Process(format!(
            "production liveness heartbeat_round_trips={} is below the required {MINIMUM_HEARTBEAT_ROUND_TRIPS} counted owner-lease renewals",
            evidence.heartbeat_round_trips
        )));
    }
    if evidence.heartbeat_intervals < MINIMUM_HEARTBEAT_INTERVALS {
        return Err(HarnessError::Process(format!(
            "production liveness heartbeat_intervals={} is below the required {MINIMUM_HEARTBEAT_INTERVALS} measured renewal intervals",
            evidence.heartbeat_intervals
        )));
    }
    if evidence.longest_heartbeat_run_intervals < MINIMUM_HEARTBEAT_RUN_INTERVALS {
        return Err(HarnessError::Process(format!(
            "production liveness longest_heartbeat_run_intervals={} is below the required {MINIMUM_HEARTBEAT_RUN_INTERVALS}: no single owner token was seen renewing repeatedly",
            evidence.longest_heartbeat_run_intervals
        )));
    }
    if evidence.longest_heartbeat_run_intervals > evidence.heartbeat_intervals
        || evidence.heartbeat_intervals != evidence.heartbeat_round_trips
    {
        return Err(HarnessError::Process(format!(
            "production liveness heartbeat accounting is inconsistent: round_trips={} intervals={} longest_run={}",
            evidence.heartbeat_round_trips,
            evidence.heartbeat_intervals,
            evidence.longest_heartbeat_run_intervals
        )));
    }
    if evidence.heartbeat_owner_tokens == 0 {
        return Err(HarnessError::Process(
            "production liveness heartbeat_owner_tokens was zero, so no owner lease was sampled"
                .into(),
        ));
    }
    if !evidence.heartbeat_intervals_within_bounds {
        return Err(HarnessError::Process(
            "production liveness heartbeat_intervals_within_bounds was false".into(),
        ));
    }
    if evidence.observed_minimum_interval_ms < evidence.heartbeat_minimum_interval_ms
        || evidence.observed_maximum_interval_ms > evidence.heartbeat_maximum_interval_ms
    {
        return Err(HarnessError::Process(format!(
            "production liveness observed heartbeat interval range [{}, {}] ms escaped the configured window [{}, {}] ms",
            evidence.observed_minimum_interval_ms,
            evidence.observed_maximum_interval_ms,
            evidence.heartbeat_minimum_interval_ms,
            evidence.heartbeat_maximum_interval_ms
        )));
    }
    if evidence.livez_probes == 0 || evidence.livez_live != evidence.livez_probes {
        return Err(HarnessError::Process(format!(
            "production liveness livez_live={} did not account for every one of {} livez_probes",
            evidence.livez_live, evidence.livez_probes
        )));
    }
    if evidence.readyz_probes == 0 {
        return Err(HarnessError::Process(
            "production liveness readyz_probes was zero".into(),
        ));
    }
    if evidence.readyz_ready == 0 {
        return Err(HarnessError::Process(
            "production liveness readyz_ready was zero, so a permanently unready relay would pass"
                .into(),
        ));
    }
    if evidence.readyz_unready == 0 {
        return Err(HarnessError::Process(
            "production liveness readyz_unready was zero, so readiness never failed closed".into(),
        ));
    }
    if evidence.readyz_ready + evidence.readyz_unready != evidence.readyz_probes {
        return Err(HarnessError::Process(format!(
            "production liveness readyz_probes={} does not equal readyz_ready={} plus readyz_unready={}",
            evidence.readyz_probes, evidence.readyz_ready, evidence.readyz_unready
        )));
    }
    if !evidence.liveness_up_while_readiness_false {
        return Err(HarnessError::Process(
            "production liveness liveness_up_while_readiness_false was false: liveness and readiness were never distinguished".into(),
        ));
    }
    if evidence.cli_shutdown_join_bound_ms == 0 {
        return Err(HarnessError::Process(
            "production liveness cli_shutdown_join_bound_ms was zero, so the join is unbounded"
                .into(),
        ));
    }
    if !evidence.cli_shutdown_graceful_exit {
        return Err(HarnessError::Process(
            "production liveness cli_shutdown_graceful_exit was false: the CLI was force-killed rather than joined".into(),
        ));
    }
    if evidence.cli_shutdown_join_ms > evidence.cli_shutdown_join_bound_ms
        || !evidence.cli_shutdown_joined_within_bound
    {
        return Err(HarnessError::Process(format!(
            "production liveness cli_shutdown_join_ms={} exceeded its bound {} ms",
            evidence.cli_shutdown_join_ms, evidence.cli_shutdown_join_bound_ms
        )));
    }
    if !evidence.cli_shutdown_owner_released {
        return Err(HarnessError::Process(
            "production liveness cli_shutdown_owner_released was false: the stopped CLI left its owner behind".into(),
        ));
    }
    Ok(())
}

/// One Redis owner scope the heartbeat sampler watches.
#[derive(Clone, Copy, Debug)]
pub(super) struct HeartbeatScope {
    pub tenant_id: Uuid,
    pub device_id: Uuid,
}

/// Aggregated, payload-free heartbeat samples.
#[derive(Clone, Debug, Default)]
pub(super) struct HeartbeatSamples {
    pub owner_tokens: usize,
    pub round_trips: usize,
    pub intervals_ms: Vec<u64>,
    pub longest_run_intervals: usize,
}

impl HeartbeatSamples {
    pub(super) fn within_bounds(&self) -> bool {
        let minimum = heartbeat_minimum_interval().as_millis() as u64;
        let maximum = heartbeat_maximum_interval().as_millis() as u64;
        !self.intervals_ms.is_empty()
            && self
                .intervals_ms
                .iter()
                .all(|interval| *interval >= minimum && *interval <= maximum)
    }

    pub(super) fn minimum_interval_ms(&self) -> u64 {
        self.intervals_ms.iter().copied().min().unwrap_or(0)
    }

    pub(super) fn maximum_interval_ms(&self) -> u64 {
        self.intervals_ms.iter().copied().max().unwrap_or(u64::MAX)
    }
}

#[derive(Clone, Debug)]
struct OwnerLeaseTrack {
    last_lease_expires_at: DateTime<Utc>,
    intervals_ms: Vec<u64>,
}

/// A background sampler that counts owner-lease renewals for the given
/// scopes until it is joined.
pub(super) struct OwnerLeaseHeartbeat {
    cancel: CancellationToken,
    task: Option<JoinHandle<HeartbeatSamples>>,
}

impl OwnerLeaseHeartbeat {
    pub(super) fn start(catalog: SharedCatalog, scopes: Vec<HeartbeatScope>) -> Self {
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task = tokio::spawn(async move {
            let mut tracks: BTreeMap<(Uuid, String, u64), OwnerLeaseTrack> = BTreeMap::new();
            loop {
                for scope in &scopes {
                    // A read failure is never evidence on its own: the gate's
                    // minimum renewal counts fail the run if sampling could
                    // not observe the authority.
                    if let Ok(Some(claim)) = catalog
                        .current_owner(scope.tenant_id, scope.device_id, Utc::now())
                        .await
                    {
                        record_owner_claim(&mut tracks, &claim);
                    }
                }
                tokio::select! {
                    () = task_cancel.cancelled() => break,
                    () = tokio::time::sleep(HEARTBEAT_SAMPLE_INTERVAL) => {}
                }
            }
            aggregate(&tracks)
        });
        Self {
            cancel,
            task: Some(task),
        }
    }

    pub(super) async fn join(mut self) -> Result<HeartbeatSamples> {
        self.cancel.cancel();
        let task = self.task.take().ok_or_else(|| {
            HarnessError::Process("the owner-lease heartbeat sampler was already joined".into())
        })?;
        task.await.map_err(|error| {
            HarnessError::Process(format!(
                "joining the owner-lease heartbeat sampler: {error}"
            ))
        })
    }
}

impl Drop for OwnerLeaseHeartbeat {
    fn drop(&mut self) {
        // A scenario that fails before the sampler is joined must not leave a
        // background Redis poller running behind it.
        self.cancel.cancel();
    }
}

fn record_owner_claim(
    tracks: &mut BTreeMap<(Uuid, String, u64), OwnerLeaseTrack>,
    claim: &tunnel_catalog::OwnerClaim,
) {
    let key = (
        claim.token.device_id,
        claim.token.session_id.clone(),
        claim.token.epoch,
    );
    match tracks.get_mut(&key) {
        None => {
            tracks.insert(
                key,
                OwnerLeaseTrack {
                    last_lease_expires_at: claim.lease_expires_at,
                    intervals_ms: Vec::new(),
                },
            );
        }
        Some(track) => {
            if claim.lease_expires_at > track.last_lease_expires_at {
                let advanced = claim.lease_expires_at - track.last_lease_expires_at;
                if let Ok(milliseconds) = u64::try_from(advanced.num_milliseconds()) {
                    track.intervals_ms.push(milliseconds);
                }
                track.last_lease_expires_at = claim.lease_expires_at;
            }
        }
    }
}

fn aggregate(tracks: &BTreeMap<(Uuid, String, u64), OwnerLeaseTrack>) -> HeartbeatSamples {
    let mut samples = HeartbeatSamples {
        owner_tokens: tracks.len(),
        ..HeartbeatSamples::default()
    };
    for track in tracks.values() {
        // Every observed lease advance is one renewal round trip, and each
        // one carries exactly one measured interval from the previous lease
        // value, so the two counts agree by construction.
        samples.round_trips += track.intervals_ms.len();
        samples.longest_run_intervals = samples.longest_run_intervals.max(track.intervals_ms.len());
        samples.intervals_ms.extend(track.intervals_ms.iter());
    }
    samples
}

/// The measured outcome of interrupting and joining the real CLI.
#[derive(Clone, Copy, Debug)]
pub(super) struct CliShutdownJoin {
    pub join_ms: u64,
    pub within_bound: bool,
    pub graceful_exit: bool,
}

/// Interrupt the real `tunnel-client` CLI and *measure* its join.
///
/// `ManagedProcess::shutdown` force-kills once the supplied budget expires,
/// so a connector that ignored the interrupt shows up as both an over-bound
/// duration and a non-success exit status.  Nothing here weakens the
/// existing checks: it replaces a hard-coded `true` with a measurement.
pub(super) async fn join_cli_after_interrupt(
    mut process: ManagedProcess,
) -> Result<CliShutdownJoin> {
    // SIGINT and, since M6-C23, SIGTERM both take the connector CLI's own
    // orderly stop path; SIGINT is kept here so this measurement is
    // unchanged from the one its evidence records.
    super::send_managed_process_signal(&mut process, "-INT")?;
    let started = Instant::now();
    let status = process
        .shutdown(CLI_SHUTDOWN_JOIN_BOUND)
        .await
        .map_err(|error| {
            HarnessError::Process(format!("joining the interrupted production CLI: {error}"))
        })?;
    let elapsed = started.elapsed();
    Ok(CliShutdownJoin {
        join_ms: elapsed.as_millis() as u64,
        within_bound: elapsed <= CLI_SHUTDOWN_JOIN_BOUND,
        graceful_exit: status.success(),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        MINIMUM_HEARTBEAT_INTERVALS, MINIMUM_HEARTBEAT_ROUND_TRIPS,
        MINIMUM_HEARTBEAT_RUN_INTERVALS, ProductionLivenessEvidence, heartbeat_maximum_interval,
        heartbeat_minimum_interval, owner_lease_ms, validate_production_liveness_evidence,
    };
    use crate::acceptance_test_support::assert_rejected;

    fn valid_evidence() -> ProductionLivenessEvidence {
        let lease = owner_lease_ms();
        let minimum = heartbeat_minimum_interval().as_millis() as u64;
        let maximum = heartbeat_maximum_interval().as_millis() as u64;
        ProductionLivenessEvidence {
            owner_lease_ms: lease,
            heartbeat_minimum_interval_ms: minimum,
            heartbeat_maximum_interval_ms: maximum,
            heartbeat_owner_tokens: 2,
            heartbeat_round_trips: MINIMUM_HEARTBEAT_ROUND_TRIPS,
            heartbeat_intervals: MINIMUM_HEARTBEAT_ROUND_TRIPS,
            longest_heartbeat_run_intervals: MINIMUM_HEARTBEAT_RUN_INTERVALS,
            observed_minimum_interval_ms: minimum + 25,
            observed_maximum_interval_ms: minimum + 75,
            heartbeat_intervals_within_bounds: true,
            livez_probes: 4,
            livez_live: 4,
            readyz_probes: 4,
            readyz_ready: 3,
            readyz_unready: 1,
            liveness_up_while_readiness_false: true,
            cli_shutdown_join_bound_ms: super::CLI_SHUTDOWN_JOIN_BOUND.as_millis() as u64,
            cli_shutdown_join_ms: 120,
            cli_shutdown_joined_within_bound: true,
            cli_shutdown_graceful_exit: true,
            cli_shutdown_owner_released: true,
        }
    }

    #[test]
    fn complete_liveness_evidence_is_accepted() {
        validate_production_liveness_evidence(&valid_evidence())
            .expect("complete IN-10/OG-05 liveness evidence must pass");
    }

    /// Every new assertion needs a red control: each mutation below stands
    /// for a real production failure the row would otherwise hide, and the
    /// bounded diagnostic must name the exact field that rejected it.
    #[test]
    fn every_liveness_rejection_names_its_condition() {
        type Case = (
            &'static str,
            &'static str,
            fn(&mut ProductionLivenessEvidence),
        );
        let cases: &[Case] = &[
            // The bound was not derived from the configured lease at all.
            ("owner_lease_ms", "owner_lease_ms was zero", |e| {
                e.owner_lease_ms = 0
            }),
            // A hand-picked window instead of `owner_lease / 3`.
            (
                "heartbeat_minimum_interval_ms",
                "is not derived from owner_lease_ms",
                |e| e.heartbeat_minimum_interval_ms += 1,
            ),
            (
                "heartbeat_maximum_interval_ms",
                "is not derived from owner_lease_ms",
                |e| e.heartbeat_maximum_interval_ms += 1,
            ),
            // The session stayed up but never actually heartbeat.
            (
                "heartbeat_round_trips",
                "counted owner-lease renewals",
                |e| e.heartbeat_round_trips = MINIMUM_HEARTBEAT_ROUND_TRIPS - 1,
            ),
            // Renewals were counted but never timed.
            ("heartbeat_intervals", "measured renewal intervals", |e| {
                e.heartbeat_intervals = MINIMUM_HEARTBEAT_INTERVALS - 1
            }),
            // Every interval came from a different owner token, so no single
            // session was ever seen renewing repeatedly.
            (
                "longest_heartbeat_run_intervals",
                "no single owner token was seen renewing repeatedly",
                |e| e.longest_heartbeat_run_intervals = MINIMUM_HEARTBEAT_RUN_INTERVALS - 1,
            ),
            // Renewals counted without a matching timed interval.
            (
                "heartbeat accounting",
                "heartbeat accounting is inconsistent",
                |e| e.heartbeat_intervals += 1,
            ),
            // No owner lease was sampled at all.
            (
                "heartbeat_owner_tokens",
                "heartbeat_owner_tokens was zero",
                |e| e.heartbeat_owner_tokens = 0,
            ),
            (
                "heartbeat_intervals_within_bounds",
                "heartbeat_intervals_within_bounds was false",
                |e| e.heartbeat_intervals_within_bounds = false,
            ),
            // A renewal faster than the configured renewal point: the
            // relay would be hammering the authority.
            (
                "observed_minimum_interval_ms",
                "escaped the configured window",
                |e| e.observed_minimum_interval_ms = e.heartbeat_minimum_interval_ms - 1,
            ),
            // A renewal slower than the lease: the owner would have been
            // fenced instead of renewed.
            (
                "observed_maximum_interval_ms",
                "escaped the configured window",
                |e| e.observed_maximum_interval_ms = e.heartbeat_maximum_interval_ms + 1,
            ),
            // Liveness was never probed, or stopped answering.
            ("livez_probes", "livez_probes", |e| e.livez_probes = 0),
            ("livez_live", "livez_probes", |e| e.livez_live -= 1),
            ("readyz_probes", "readyz_probes was zero", |e| {
                e.readyz_probes = 0;
                e.readyz_ready = 0;
                e.readyz_unready = 0;
            }),
            // Readiness was never observed ready, so a relay wedged unready
            // would satisfy the split.
            ("readyz_ready", "readyz_ready was zero", |e| {
                e.readyz_ready = 0;
                e.readyz_probes = e.readyz_unready;
            }),
            // Readiness never failed closed, so the two endpoints were never
            // actually distinguished.
            ("readyz_unready", "readyz_unready was zero", |e| {
                e.readyz_unready = 0;
                e.readyz_probes = e.readyz_ready;
            }),
            ("readyz_probes total", "does not equal readyz_ready", |e| {
                e.readyz_probes += 1
            }),
            (
                "liveness_up_while_readiness_false",
                "were never distinguished",
                |e| e.liveness_up_while_readiness_false = false,
            ),
            // An unbounded join.
            (
                "cli_shutdown_join_bound_ms",
                "cli_shutdown_join_bound_ms was zero",
                |e| e.cli_shutdown_join_bound_ms = 0,
            ),
            // The CLI ignored the interrupt and was force-killed.
            (
                "cli_shutdown_graceful_exit",
                "force-killed rather than joined",
                |e| e.cli_shutdown_graceful_exit = false,
            ),
            // The measured join outran its bound.
            ("cli_shutdown_join_ms", "exceeded its bound", |e| {
                e.cli_shutdown_join_ms = e.cli_shutdown_join_bound_ms + 1
            }),
            // The boolean claimed success while the measurement did not.
            (
                "cli_shutdown_joined_within_bound",
                "exceeded its bound",
                |e| e.cli_shutdown_joined_within_bound = false,
            ),
            // The stopped CLI abandoned its Redis owner.
            (
                "cli_shutdown_owner_released",
                "left its owner behind",
                |e| e.cli_shutdown_owner_released = false,
            ),
        ];
        for (name, expected, mutate) in cases {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(validate_production_liveness_evidence(&evidence), expected);
            assert!(!name.is_empty());
        }
    }
}
