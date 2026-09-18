//! Convergence from the bounded membership refresh alone when the
//! process-local invalidation hint is dropped.
//!
//! There is no Pub/Sub in this codebase: membership distribution is poll-only
//! with a bounded refresh, so the "missed hint" of EC-019/EC-048/EC-056 is the
//! process-local invalidation callback installed through
//! `MembershipRuntime::set_invalidation_callback`.  This fixture replaces that
//! callback on every relay with one that publishes nothing while armed, so the
//! only remaining path to convergence is the membership reconcile pass itself.
//!
//! Investigation note recorded with M7-C54: pin publication is not the
//! admission set.  `MembershipRuntime::reconcile_once_inner` swaps the verified
//! candidate into live state, and `admit_peer` binds against that verifier, so
//! a rotated-out key is refused by the reconcile pass with no callback and no
//! pin republication involved.  This gate therefore needs no product change; it
//! only removes the eager hint and measures what the refresh alone achieves.
//!
//! The drop is window-wide rather than identity-filtered on purpose.  Pin
//! publication at both install sites is all-or-nothing over the whole verified
//! snapshot, so a hint delivered for any other identity would republish the
//! rotated identity's pins too and silently defeat the drop.  The evidence
//! records that the rotated identity's own hints were dropped and that no
//! publication at all ran inside the window.
//!
//! Two arms are proven, because they prove different things:
//!
//! 1. The overlap is honoured for the rotated identity.  A stream established
//!    while both the old and the incoming key are approved keeps delivering,
//!    and is torn down only once the old key leaves the verifier.  This
//!    exercises `revalidate_active` rather than avoiding it.
//! 2. There is no collateral damage.  A stream on a different, non-rotated
//!    identity survives the whole sequence and keeps dispatching.
//!
//! Convergence is asserted against the configured membership refresh bound,
//! which is the contract.  The reconcile tick is an implementation detail and
//! is only recorded, never asserted, so the gate documents reality without
//! pinning its assertion to a value the product is free to change.

use super::{
    ConsumerStream, ProductionCluster, ProductionRelay, connect_failure_to_harness,
    finish_scenario_with_cleanup, open_consumer_stream, publish_verified_pins,
};
use crate::acceptance::helpers::write_device_profile;
use crate::cluster_fixture::{
    FixturePeerKey, M7_MEMBERSHIP_LIFETIME, MembershipRecordOptions, SignedMembershipFixture,
};
use crate::{Harness, HarnessError, HarnessOptions, OidcTokenOptions, Result, RunningHarness};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tempfile::{TempDir, tempdir};
use tokio::time::{sleep, timeout, timeout_at};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{OwnerToken, RedisMembershipPublisher};
use tunnel_client::{ConnectOptions, ConnectionHandle, TransportProfile};
use tunnel_relay::{MembershipReadiness, RelaySnapshot};

/// The identity whose peer key is rotated out.
pub(super) const TARGET_NODE: &str = "relay-a";
/// The ingress that holds the pooled peer stream to the rotated identity.
const AFFECTED_INGRESS: &str = "relay-c";
/// The ingress used by the unaffected sibling route.
const SIBLING_INGRESS: &str = "relay-b";
/// The owner of the unaffected sibling route.
const SIBLING_OWNER: &str = "relay-c";

/// The configured `cluster.membership_refresh_seconds` of the production
/// fixture.  This is the contractual bound the gate asserts against.
const MEMBERSHIP_REFRESH_BOUND: Duration = Duration::from_secs(20);
/// The configured `cluster.membership_reconcile_seconds` of the production
/// fixture.  Recorded as observed context only; never asserted against, and
/// deliberately not confused with the one-second peer readiness probe loop,
/// which does not drive membership reconciliation.
const RECONCILE_TICK: Duration = Duration::from_secs(1);
/// Budget for the pre-withdrawal steps, which are not the measured window.
const SETUP_BOUND: Duration = Duration::from_secs(20);
/// Budget for the owner-fence warmup admission.
const OWNER_FENCE_READY_BOUND: Duration = Duration::from_secs(5);
/// Budget for the post-withdrawal teardown of the established stream, measured
/// from the observed convergence instant rather than from the withdrawal.
const TEARDOWN_BOUND: Duration = Duration::from_secs(10);
/// Budget for re-approval after the measured window has closed.
const RECOVERY_BOUND: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(50);

/// A 64-hex SPKI that no fixture certificate presents.  It stands in for the
/// incoming key of a staged rotation: approved alongside the real key during
/// the overlap, and the only approved key after the withdrawal.
pub(super) const INCOMING_SPKI: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";

/// The typed public outcome observed for the withdrawn key's fresh admission.
///
/// The ingress relay's own membership is untouched by this rotation, so it
/// answers about the peer rather than about itself: a withdrawn peer key is
/// attributed as `PEER_UNTRUSTED`.  The neighbouring typed codes are named so a
/// behaviour change surfaces as a precise diagnostic instead of "untyped".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WithdrawnAdmissionOutcome {
    /// HTTP 503 `PEER_UNTRUSTED` with `execution=not_dispatched`.  The only
    /// outcome this gate accepts: it names the withdrawn key as the cause.
    PeerUntrusted,
    /// HTTP 503 `CLUSTER_UNREADY` with `execution=not_dispatched`.  Typed, but
    /// attributes the refusal to the ingress rather than to the peer key.
    ClusterUnready,
    /// HTTP 503 `PEER_UNAVAILABLE` with `execution=not_dispatched`.  Typed, but
    /// reads as a transient reachability fault rather than a trust withdrawal.
    PeerUnavailable,
    /// Any other response, including a successful upgrade.  Never valid.
    Untyped,
}

/// Payload-free evidence from the real three-relay hint-drop gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipHintDropEvidence {
    pub relay_count: usize,
    /// Signed record version approving both the old and the incoming key.
    pub overlap_record_version: u64,
    /// Signed record version approving only the incoming key.
    pub withdrawal_record_version: u64,
    /// Invalidation hints for the rotated identity that the fixture dropped.
    pub target_hints_dropped: u64,
    /// Invalidation hints for every other identity dropped inside the window.
    pub other_hints_dropped: u64,
    /// Pin publications that ran inside the drop window.  Must be zero, or the
    /// hint was not actually dropped and the gate proves nothing.
    pub publications_during_drop_window: u64,
    /// Every relay's verifier carried both keys for the rotated identity.
    pub overlap_both_keys_converged: bool,
    /// The stream established on the old key kept delivering during overlap.
    pub overlap_stream_survived: bool,
    /// The old key left the observing relay's verifier from the refresh alone.
    pub withdrawn_key_left_verifier: bool,
    /// That same established stream was torn down after the withdrawal.
    pub overlap_stream_interrupted_after_withdrawal: bool,
    /// The owner's application dispatch counter did not move across the
    /// withdrawal, the teardown, or the refused admission.
    pub target_dispatch_unchanged: bool,
    /// A fresh admission presenting the withdrawn key was refused.
    pub withdrawn_key_admission_refused: bool,
    /// The typed public outcome of that refusal.
    pub withdrawn_admission_outcome: WithdrawnAdmissionOutcome,
    /// The non-rotated identity's stream survived the whole sequence.
    pub sibling_stream_survived: bool,
    /// That sibling route kept dispatching application work.
    pub sibling_dispatch_advanced: bool,
    /// The contractual bound the convergence assertion is made against.
    pub membership_refresh_bound_ms: u64,
    /// The configured reconcile tick.  Context only; never asserted against.
    pub reconcile_tick_ms: u64,
    /// Observed convergence, from the withdrawal being durable in Redis to the
    /// old key being absent from the observing relay's verifier.
    pub observed_convergence_ms: u64,
    /// Observed refusal, measured from the same withdrawal instant.
    pub observed_refusal_ms: u64,
    pub recovery_record_version: u64,
    pub recovery_echo: bool,
    pub fanout_peak_open: usize,
    pub elapsed_ms: u64,
}

/// Validate every required hint-drop observation.
pub fn validate_membership_hint_drop_evidence(evidence: &MembershipHintDropEvidence) -> Result<()> {
    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "hint-drop relay_count expected three relays, observed {}",
            evidence.relay_count
        )));
    }
    let required = [
        (
            "overlap_both_keys_converged",
            evidence.overlap_both_keys_converged,
        ),
        ("overlap_stream_survived", evidence.overlap_stream_survived),
        (
            "withdrawn_key_left_verifier",
            evidence.withdrawn_key_left_verifier,
        ),
        (
            "overlap_stream_interrupted_after_withdrawal",
            evidence.overlap_stream_interrupted_after_withdrawal,
        ),
        (
            "target_dispatch_unchanged",
            evidence.target_dispatch_unchanged,
        ),
        (
            "withdrawn_key_admission_refused",
            evidence.withdrawn_key_admission_refused,
        ),
        ("sibling_stream_survived", evidence.sibling_stream_survived),
        (
            "sibling_dispatch_advanced",
            evidence.sibling_dispatch_advanced,
        ),
        ("recovery_echo", evidence.recovery_echo),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "hint-drop required gate {name} was false"
        )));
    }

    // Without a dropped hint for the rotated identity the run degenerates into
    // the ordinary invalidation path and proves nothing about the refresh.
    if evidence.target_hints_dropped == 0 {
        return Err(HarnessError::Process(
            "hint-drop target_hints_dropped was zero: no invalidation hint for the rotated identity was ever dropped".into(),
        ));
    }
    // Pin publication is all-or-nothing over the verified snapshot, so a single
    // publication inside the window would have republished the rotated
    // identity's pins and defeated the drop.
    if evidence.publications_during_drop_window != 0 {
        return Err(HarnessError::Process(format!(
            "hint-drop publications_during_drop_window was {}: pins were republished while the hint was dropped",
            evidence.publications_during_drop_window
        )));
    }

    if evidence.overlap_record_version == 0
        || evidence.withdrawal_record_version <= evidence.overlap_record_version
        || evidence.recovery_record_version <= evidence.withdrawal_record_version
    {
        return Err(HarnessError::Process(format!(
            "hint-drop record versions did not advance (overlap_record_version {}, withdrawal_record_version {}, recovery_record_version {})",
            evidence.overlap_record_version,
            evidence.withdrawal_record_version,
            evidence.recovery_record_version
        )));
    }

    // The refusal must name the withdrawn key as its cause.  A typed answer
    // that blames the ingress or a transient reachability fault would not prove
    // the rotation was what refused the admission.
    if evidence.withdrawn_admission_outcome != WithdrawnAdmissionOutcome::PeerUntrusted {
        return Err(HarnessError::Process(format!(
            "hint-drop withdrawn_admission_outcome was {:?}, not the PEER_UNTRUSTED no-dispatch refusal",
            evidence.withdrawn_admission_outcome
        )));
    }

    // The contract is the bounded membership refresh.  Assert against it, not
    // against the reconcile tick, which the recorded context exposes instead.
    if evidence.membership_refresh_bound_ms != MEMBERSHIP_REFRESH_BOUND.as_millis() as u64 {
        return Err(HarnessError::Process(format!(
            "hint-drop membership_refresh_bound_ms was {}, not the configured membership refresh",
            evidence.membership_refresh_bound_ms
        )));
    }
    if evidence.reconcile_tick_ms != RECONCILE_TICK.as_millis() as u64 {
        return Err(HarnessError::Process(format!(
            "hint-drop reconcile_tick_ms was {}, which does not match the fixture",
            evidence.reconcile_tick_ms
        )));
    }
    if evidence.observed_convergence_ms > evidence.membership_refresh_bound_ms {
        return Err(HarnessError::Process(format!(
            "hint-drop observed_convergence_ms was {}, beyond the {} ms membership refresh bound",
            evidence.observed_convergence_ms, evidence.membership_refresh_bound_ms
        )));
    }
    if evidence.observed_refusal_ms > evidence.membership_refresh_bound_ms {
        return Err(HarnessError::Process(format!(
            "hint-drop observed_refusal_ms was {}, beyond the {} ms membership refresh bound",
            evidence.observed_refusal_ms, evidence.membership_refresh_bound_ms
        )));
    }
    // The refusal is a consequence of convergence and can never precede it.
    if evidence.observed_refusal_ms < evidence.observed_convergence_ms {
        return Err(HarnessError::Process(format!(
            "hint-drop observed the refusal at {} ms, before_convergence at {} ms",
            evidence.observed_refusal_ms, evidence.observed_convergence_ms
        )));
    }

    if evidence.fanout_peak_open > 3 {
        return Err(HarnessError::Process(format!(
            "hint-drop fanout_peak_open exceeded the three-socket bound: {}",
            evidence.fanout_peak_open
        )));
    }
    Ok(())
}

#[cfg(test)]
mod c17_validator_tests {
    use super::{
        MEMBERSHIP_REFRESH_BOUND, MembershipHintDropEvidence, WithdrawnAdmissionOutcome,
        validate_membership_hint_drop_evidence,
    };
    use crate::acceptance_test_support::assert_rejected;

    fn valid_evidence() -> MembershipHintDropEvidence {
        MembershipHintDropEvidence {
            relay_count: 3,
            overlap_record_version: 2,
            withdrawal_record_version: 3,
            target_hints_dropped: 1,
            other_hints_dropped: 0,
            publications_during_drop_window: 0,
            overlap_both_keys_converged: true,
            overlap_stream_survived: true,
            withdrawn_key_left_verifier: true,
            overlap_stream_interrupted_after_withdrawal: true,
            target_dispatch_unchanged: true,
            withdrawn_key_admission_refused: true,
            withdrawn_admission_outcome: WithdrawnAdmissionOutcome::PeerUntrusted,
            sibling_stream_survived: true,
            sibling_dispatch_advanced: true,
            membership_refresh_bound_ms: MEMBERSHIP_REFRESH_BOUND.as_millis() as u64,
            reconcile_tick_ms: 1_000,
            observed_convergence_ms: 1_200,
            observed_refusal_ms: 1_400,
            recovery_record_version: 4,
            recovery_echo: true,
            fanout_peak_open: 3,
            elapsed_ms: 1,
        }
    }

    #[test]
    fn every_hint_drop_flag_and_bound_reaches_the_shared_exit_path() {
        type Disable = (&'static str, fn(&mut MembershipHintDropEvidence));
        let flags: [Disable; 9] = [
            ("overlap_both_keys_converged", |e| {
                e.overlap_both_keys_converged = false
            }),
            ("overlap_stream_survived", |e| {
                e.overlap_stream_survived = false
            }),
            ("withdrawn_key_left_verifier", |e| {
                e.withdrawn_key_left_verifier = false
            }),
            ("overlap_stream_interrupted_after_withdrawal", |e| {
                e.overlap_stream_interrupted_after_withdrawal = false
            }),
            ("target_dispatch_unchanged", |e| {
                e.target_dispatch_unchanged = false
            }),
            ("withdrawn_key_admission_refused", |e| {
                e.withdrawn_key_admission_refused = false
            }),
            ("sibling_stream_survived", |e| {
                e.sibling_stream_survived = false
            }),
            ("sibling_dispatch_advanced", |e| {
                e.sibling_dispatch_advanced = false
            }),
            ("recovery_echo", |e| e.recovery_echo = false),
        ];
        for (name, disable) in flags {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_rejected(validate_membership_hint_drop_evidence(&evidence), name);
        }

        type Mutate = (&'static str, fn(&mut MembershipHintDropEvidence));
        let bounds: [Mutate; 12] = [
            ("relay_count", |e: &mut MembershipHintDropEvidence| {
                e.relay_count = 2
            }),
            (
                "target_hints_dropped",
                |e: &mut MembershipHintDropEvidence| e.target_hints_dropped = 0,
            ),
            (
                "publications_during_drop_window",
                |e: &mut MembershipHintDropEvidence| e.publications_during_drop_window = 1,
            ),
            (
                "overlap_record_version",
                |e: &mut MembershipHintDropEvidence| e.overlap_record_version = 0,
            ),
            (
                "withdrawal_record_version",
                |e: &mut MembershipHintDropEvidence| e.withdrawal_record_version = 2,
            ),
            (
                "recovery_record_version",
                |e: &mut MembershipHintDropEvidence| e.recovery_record_version = 3,
            ),
            (
                "withdrawn_admission_outcome",
                |e: &mut MembershipHintDropEvidence| {
                    e.withdrawn_admission_outcome = WithdrawnAdmissionOutcome::Untyped
                },
            ),
            (
                "membership_refresh_bound_ms",
                |e: &mut MembershipHintDropEvidence| e.membership_refresh_bound_ms = 1_000,
            ),
            ("reconcile_tick_ms", |e: &mut MembershipHintDropEvidence| {
                e.reconcile_tick_ms = 20_000
            }),
            (
                "observed_convergence_ms",
                |e: &mut MembershipHintDropEvidence| e.observed_convergence_ms = 20_001,
            ),
            (
                "observed_refusal_ms",
                |e: &mut MembershipHintDropEvidence| e.observed_refusal_ms = 20_001,
            ),
            (
                "before_convergence",
                |e: &mut MembershipHintDropEvidence| e.observed_refusal_ms = 1_199,
            ),
        ];
        for (name, mutate) in bounds {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(validate_membership_hint_drop_evidence(&evidence), name);
        }

        // The fanout ceiling shares the same exit path.
        let mut evidence = valid_evidence();
        evidence.fanout_peak_open = 4;
        assert_rejected(
            validate_membership_hint_drop_evidence(&evidence),
            "fanout_peak_open",
        );
    }

    #[test]
    fn hint_drop_validator_accepts_complete_evidence() {
        validate_membership_hint_drop_evidence(&valid_evidence())
            .expect("complete hint-drop evidence is valid");
    }

    #[test]
    fn hint_drop_validator_rejects_every_outcome_but_peer_untrusted() {
        // A typed answer is not enough: one that blames the ingress or a
        // transient reachability fault does not attribute the refusal to the
        // withdrawn key, so the gate would not prove what it claims.
        for outcome in [
            WithdrawnAdmissionOutcome::ClusterUnready,
            WithdrawnAdmissionOutcome::PeerUnavailable,
            WithdrawnAdmissionOutcome::Untyped,
        ] {
            let mut evidence = valid_evidence();
            evidence.withdrawn_admission_outcome = outcome;
            assert_rejected(
                validate_membership_hint_drop_evidence(&evidence),
                "withdrawn_admission_outcome",
            );
        }
    }
}

/// Counters for the process-local invalidation hint this fixture suppresses.
#[derive(Debug, Default)]
struct HintDropFilter {
    armed: AtomicBool,
    target_dropped: AtomicU64,
    other_dropped: AtomicU64,
    published_in_window: AtomicU64,
}

impl HintDropFilter {
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    fn disarm(&self) {
        self.armed.store(false, Ordering::SeqCst);
    }

    /// Return true when the hint must be dropped instead of republishing pins.
    fn should_drop(&self, node_id: &str) -> bool {
        if !self.armed.load(Ordering::SeqCst) {
            return false;
        }
        if node_id == TARGET_NODE {
            self.target_dropped.fetch_add(1, Ordering::SeqCst);
        } else {
            self.other_dropped.fetch_add(1, Ordering::SeqCst);
        }
        true
    }

    fn record_publication(&self) {
        if self.armed.load(Ordering::SeqCst) {
            self.published_in_window.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// Replace the fixture's pin-publishing invalidation callback with one that
/// publishes nothing while armed.  This is the whole injection: no product code
/// changes, and the runtime keeps dispatching hints exactly as before.
fn install_hint_drop_callback(relay: &ProductionRelay, filter: &Arc<HintDropFilter>) {
    let membership = Arc::clone(&relay.membership);
    let pins = relay.pins.clone();
    let filter = Arc::clone(filter);
    relay
        .membership
        .set_invalidation_callback(Some(Arc::new(move |identity, _reason| {
            if filter.should_drop(&identity.node_id) {
                return;
            }
            filter.record_publication();
            if let Err(error) = publish_verified_pins(&membership, &pins) {
                tracing::warn!(?error, "hint-drop pin publication failed closed");
                let _ = pins.replace(std::iter::empty::<tunnel_transport::SpkiSha256>());
            }
        })));
}

/// Run the bounded real Redis-backed membership hint-drop fixture.
pub async fn verify() -> Result<MembershipHintDropEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(super::ROTATION)
        .shared_device_uuid(true);
    let startup_deadline = Instant::now() + super::STARTUP_TIMEOUT;
    let startup_cleanup_deadline = startup_deadline + super::CLEANUP_TIMEOUT;
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
            // Keep the constructor pinned until it yields ownership; it can
            // still own Redis/proxy resources after the first budget expires.
            let (completion, cleanup_budget_exceeded) = match timeout_at(
                tokio::time::Instant::from_std(startup_cleanup_deadline),
                &mut harness_start,
            )
            .await
            {
                Ok(completion) => (completion, false),
                Err(_) => (harness_start.as_mut().await, true),
            };
            let timeout_message = if cleanup_budget_exceeded {
                "hint-drop harness startup timed out; startup future completed after the shared cleanup deadline"
            } else {
                "hint-drop harness startup timed out"
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
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let cleanup_deadline = tokio::time::Instant::now() + super::CLEANUP_TIMEOUT;
            return match harness.shutdown_until(cleanup_deadline).await {
                Ok(()) => Err(error),
                Err(cleanup) => Err(HarnessError::Process(format!(
                    "{error}; hint-drop startup cleanup: {cleanup}"
                ))),
            };
        }
    };

    let scenario = run(&mut cluster, &harness).await;
    let cleanup_deadline = tokio::time::Instant::now() + super::CLEANUP_TIMEOUT;
    let cluster_cleanup = cluster.shutdown_until(cleanup_deadline).await;
    let harness_cleanup = harness.shutdown_until(cleanup_deadline).await;
    let mut cleanup_errors = Vec::new();
    if let Err(error) = cluster_cleanup {
        cleanup_errors.push(format!("relay cleanup: {error}"));
    }
    if let Err(error) = harness_cleanup {
        cleanup_errors.push(format!("catalog cleanup: {error}"));
    }
    finish_scenario_with_cleanup(scenario, cleanup_errors)
}

struct ScenarioResources {
    profile_a: TempDir,
    profile_b: TempDir,
    client_a: Option<ConnectionHandle>,
    client_b: Option<ConnectionHandle>,
    stream_a: Option<ConsumerStream>,
    stream_b: Option<ConsumerStream>,
}

impl ScenarioResources {
    fn new(profile_a: TempDir, profile_b: TempDir) -> Self {
        Self {
            profile_a,
            profile_b,
            client_a: None,
            client_b: None,
            stream_a: None,
            stream_b: None,
        }
    }

    async fn cleanup(&mut self, deadline: Instant) -> Vec<String> {
        let mut errors = Vec::new();
        if let Some(stream) = self.stream_a.as_mut()
            && let Err(error) = stream.close().await
        {
            errors.push(format!("rotated stream cleanup: {error}"));
        }
        if let Some(stream) = self.stream_b.as_mut()
            && let Err(error) = stream.close().await
        {
            errors.push(format!("sibling stream cleanup: {error}"));
        }
        if let Some(client) = self.client_a.take()
            && let Err(error) = stop_client(&client, "rotated client", deadline).await
        {
            errors.push(error.to_string());
        }
        if let Some(client) = self.client_b.take()
            && let Err(error) = stop_client(&client, "sibling client", deadline).await
        {
            errors.push(error.to_string());
        }
        if Instant::now() > deadline {
            errors.push("hint-drop client cleanup exceeded its shared deadline".into());
        }
        errors
    }
}

async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
) -> Result<MembershipHintDropEvidence> {
    let profile_a_directory = tempdir().map_err(HarnessError::Io)?;
    let profile_b_directory = tempdir().map_err(HarnessError::Io)?;
    let mut resources = ScenarioResources::new(profile_a_directory, profile_b_directory);
    let scenario = run_inner(cluster, harness, &mut resources).await;
    let cleanup_deadline = Instant::now() + super::CLEANUP_TIMEOUT;
    let cleanup_errors = resources.cleanup(cleanup_deadline).await;
    finish_scenario_with_cleanup(scenario, cleanup_errors)
}

#[allow(clippy::too_many_lines)]
async fn run_inner(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    resources: &mut ScenarioResources,
) -> Result<MembershipHintDropEvidence> {
    let started = Instant::now();
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(format!(
            "hint-drop started {} relays, expected three",
            cluster.relays.len()
        )));
    }

    let device_a =
        harness.topology.devices_a.first().ok_or_else(|| {
            HarnessError::InvalidInput("hint-drop tenant A device is missing".into())
        })?;
    let device_b =
        harness.topology.devices_b.first().ok_or_else(|| {
            HarnessError::InvalidInput("hint-drop tenant B device is missing".into())
        })?;
    let service_a = *harness
        .topology
        .service_ids
        .get(&device_a.id)
        .ok_or_else(|| {
            HarnessError::InvalidInput("hint-drop tenant A service is missing".into())
        })?;
    let service_b = *harness
        .topology
        .service_ids
        .get(&device_b.id)
        .ok_or_else(|| {
            HarnessError::InvalidInput("hint-drop tenant B service is missing".into())
        })?;

    let target_owner_device = cluster
        .relay(TARGET_NODE)?
        .running
        .as_ref()
        .ok_or_else(|| {
            HarnessError::Process("hint-drop target owner has no device listener".into())
        })?
        .device_addr;
    let sibling_owner_device = cluster
        .relay(SIBLING_OWNER)?
        .running
        .as_ref()
        .ok_or_else(|| {
            HarnessError::Process("hint-drop sibling owner has no device listener".into())
        })?
        .device_addr;
    let target_owner_ingress = cluster.relay(TARGET_NODE)?.consumer_addr()?;
    let sibling_owner_ingress = cluster.relay(SIBLING_OWNER)?.consumer_addr()?;
    let affected_ingress = cluster.relay(AFFECTED_INGRESS)?.consumer_addr()?;
    let sibling_ingress = cluster.relay(SIBLING_INGRESS)?.consumer_addr()?;

    // Install the hint-dropping callback on every relay before any membership
    // change, so no publication path is left behind for the measured window.
    let filter = Arc::new(HintDropFilter::default());
    for relay in &cluster.relays {
        install_hint_drop_callback(relay, &filter);
    }

    // Pin each connector's control and data sockets to its committed owner.
    // The shared fanout intentionally rotates accepted sockets across relays,
    // which would create unrelated peer admissions inside the measured window.
    let mut profile_a = write_device_profile(
        resources.profile_a.path(),
        device_a.id,
        service_a,
        "m7-hint-drop-a",
        target_owner_device,
        &device_a.certificate.certificate_pem,
        &device_a.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile_a.config.rotation = super::ROTATION;
    profile_a
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("hint-drop A config: {error}")))?;
    let mut profile_b = write_device_profile(
        resources.profile_b.path(),
        device_b.id,
        service_b,
        "m7-hint-drop-b",
        sibling_owner_device,
        &device_b.certificate.certificate_pem,
        &device_b.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile_b.config.rotation = super::ROTATION;
    profile_b
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("hint-drop B config: {error}")))?;
    resources.client_a = Some(connect_client(profile_a.config.clone()).await?);
    wait_ready(
        resources.client_a.as_mut().expect("client A installed"),
        "rotated client",
    )
    .await?;
    resources.client_b = Some(connect_client(profile_b.config.clone()).await?);
    wait_ready(
        resources.client_b.as_mut().expect("client B installed"),
        "sibling client",
    )
    .await?;

    let owner_a = cluster
        .catalog
        .current_owner(device_a.tenant_id, device_a.id, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("reading rotated owner: {error}")))?
        .ok_or_else(|| HarnessError::Process("rotated device did not claim an owner".into()))?;
    if owner_a.token.node_id != TARGET_NODE {
        return Err(HarnessError::Process(format!(
            "rotated owner landed on {} instead of {TARGET_NODE}",
            owner_a.token.node_id
        )));
    }
    let owner_b = cluster
        .catalog
        .current_owner(device_b.tenant_id, device_b.id, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("reading sibling owner: {error}")))?
        .ok_or_else(|| HarnessError::Process("sibling device did not claim an owner".into()))?;
    if owner_b.token.node_id != SIBLING_OWNER {
        return Err(HarnessError::Process(format!(
            "sibling owner landed on {} instead of {SIBLING_OWNER}",
            owner_b.token.node_id
        )));
    }

    let token_a = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(180),
            ..OidcTokenOptions::default()
        },
    )?;
    let token_b = harness.oidc.issue_with(
        &harness.topology.consumers_b[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(180),
            ..OidcTokenOptions::default()
        },
    )?;

    // The relay admits a public stream only once its owner-fence/data-carrier
    // gate is complete.  Use the server's own retry metadata as the bounded
    // barrier so a startup race is never mistaken for a rotation result.
    wait_for_owner_admission(
        cluster,
        TARGET_NODE,
        target_owner_ingress,
        &harness.pki.server_ca.certificate_der,
        &token_a,
        device_a.id,
        service_a,
        "rotated owner",
    )
    .await?;
    wait_for_owner_admission(
        cluster,
        SIBLING_OWNER,
        sibling_owner_ingress,
        &harness.pki.server_ca.certificate_der,
        &token_b,
        device_b.id,
        service_b,
        "sibling owner",
    )
    .await?;

    let old_spki = target_peer_spki(cluster)?;

    // ---- Arm 1, part one: enter the overlap -----------------------------
    // v2 approves the old key and the incoming key together.  The hint is not
    // yet dropped here: reaching the overlap is setup, not the measurement.
    let overlap_now = Utc::now();
    let overlap_record = sign_target_record(cluster, overlap_now, 2, &[&old_spki, INCOMING_SPKI])?;
    publish_membership(harness, &overlap_record).await?;
    cluster
        .fixture
        .memberships
        .insert(TARGET_NODE.to_owned(), overlap_record.clone());
    wait_for_record_version(cluster, 2).await?;
    cluster.wait_for_peer_readiness(SETUP_BOUND).await?;

    // The overlap must be observable in every relay's verifier, or "survives
    // the overlap" is an unproven claim about a window that never opened.
    let overlap_both_keys_converged =
        wait_for_target_keys(cluster, 2, &[&old_spki, INCOMING_SPKI], SETUP_BOUND).await?;
    if !overlap_both_keys_converged {
        return Err(HarnessError::Process(
            "hint-drop overlap record did not place both keys in every relay's verifier".into(),
        ));
    }

    // Establish the stream on the old key, through the remote ingress, so the
    // pooled peer admission that `revalidate_active` later re-binds is real.
    resources.stream_a = Some(
        open_baseline_consumer_stream(
            cluster,
            AFFECTED_INGRESS,
            affected_ingress,
            &harness.pki.server_ca.certificate_der,
            &token_a,
            device_a.id,
            service_a,
            "rotated baseline",
        )
        .await?,
    );
    resources
        .stream_a
        .as_mut()
        .expect("rotated stream installed")
        .round_trip(b"overlap-open-a", b"m7-hint-drop-a")
        .await?;
    resources.stream_b = Some(
        open_baseline_consumer_stream(
            cluster,
            SIBLING_INGRESS,
            sibling_ingress,
            &harness.pki.server_ca.certificate_der,
            &token_b,
            device_b.id,
            service_b,
            "sibling baseline",
        )
        .await?,
    );
    resources
        .stream_b
        .as_mut()
        .expect("sibling stream installed")
        .round_trip(b"overlap-open-b", b"m7-hint-drop-b")
        .await?;

    // A second exchange with both keys still approved is the overlap proof:
    // the established stream keeps delivering while the rotation is staged.
    resources
        .stream_a
        .as_mut()
        .expect("rotated stream installed")
        .round_trip(b"overlap-hold-a", b"m7-hint-drop-a")
        .await?;
    let overlap_stream_survived =
        wait_for_target_keys(cluster, 2, &[&old_spki, INCOMING_SPKI], Duration::ZERO).await?;
    if !overlap_stream_survived {
        return Err(HarnessError::Process(
            "hint-drop overlap ended before the established stream completed its exchange".into(),
        ));
    }

    let target_before = cluster.relay(TARGET_NODE)?.snapshot().await?;
    let sibling_before = cluster.relay(SIBLING_OWNER)?.snapshot().await?;
    let sibling_cursor_before =
        owner_session_cursor(&sibling_before, &owner_b.token).ok_or_else(|| {
            HarnessError::Process(
                "hint-drop sibling owner session was not present before the withdrawal".into(),
            )
        })?;
    let target_dispatch_baseline = target_before.lifetime_application_dispatches;

    // ---- Arm 1, part two: withdraw the old key with the hint dropped ----
    filter.arm();
    let withdrawal_now = Utc::now();
    let withdrawal_record = sign_target_record(cluster, withdrawal_now, 3, &[INCOMING_SPKI])?;
    publish_membership(harness, &withdrawal_record).await?;
    // Time convergence from the instant the withdrawal is durable in Redis,
    // which is the earliest instant any refresh could observe it.
    wait_for_catalog_record(cluster, &withdrawal_record).await?;
    let withdrawal_observed = Instant::now();

    // Convergence from the bounded refresh alone: the old key must leave the
    // observing relay's verifier with no invalidation hint and no pin
    // republication.  The bound is the contractual membership refresh.
    let withdrawn_key_left_verifier = wait_for_key_absent(
        cluster,
        AFFECTED_INGRESS,
        3,
        &old_spki,
        MEMBERSHIP_REFRESH_BOUND,
    )
    .await?;
    let observed_convergence_ms =
        u64::try_from(withdrawal_observed.elapsed().as_millis()).unwrap_or(u64::MAX);
    if !withdrawn_key_left_verifier {
        return Err(HarnessError::Timeout(format!(
            "hint-drop withdrawn key was still in the {AFFECTED_INGRESS} verifier after the {} ms membership refresh bound",
            MEMBERSHIP_REFRESH_BOUND.as_millis()
        )));
    }

    // The established stream on the old key must now be torn down.  This is
    // `revalidate_active` re-binding the pooled admission against the newly
    // reconciled verifier, not a pin-watcher close: pins were never republished.
    let teardown_outcome = resources
        .stream_a
        .as_mut()
        .expect("rotated stream installed")
        .probe_after_pause(b"after-withdrawal-a")
        .await;
    if !teardown_outcome.is_fail_closed() {
        return Err(HarnessError::Process(format!(
            "hint-drop rotated stream did not produce a bounded post-send close/error after the withdrawal: {teardown_outcome:?}"
        )));
    }
    let overlap_stream_interrupted_after_withdrawal =
        wait_for_owner_stream_retired(cluster, TARGET_NODE, &owner_a.token, TEARDOWN_BOUND).await?;
    if !overlap_stream_interrupted_after_withdrawal {
        return Err(HarnessError::Timeout(
            "hint-drop rotated owner session still reported a live stream after the withdrawal"
                .into(),
        ));
    }

    // A fresh admission presenting the withdrawn key must be refused with a
    // typed no-dispatch outcome, and must not dispatch application work.
    let dispatch_before_refusal = cluster
        .relay(TARGET_NODE)?
        .snapshot()
        .await?
        .lifetime_application_dispatches;
    let peer_faults_before_refusal = cluster.peer_fault_stages().await?;
    let (withdrawn_admission_outcome, withdrawn_admission_detail) = match open_consumer_stream(
        affected_ingress,
        &harness.pki.server_ca.certificate_der,
        &token_a,
        device_a.id,
        service_a,
    )
    .await
    {
        Err(super::StreamConnectFailure::Status { status, body }) => (
            classify_withdrawn_admission(status, body.as_deref()),
            format!(
                "status={status},{}",
                super::redacted_admission_failure(body.as_deref())
            ),
        ),
        Err(super::StreamConnectFailure::Harness(error)) => return Err(error),
        Ok(mut stream) => {
            let _ = stream.close().await;
            (
                WithdrawnAdmissionOutcome::Untyped,
                "upgrade succeeded".to_owned(),
            )
        }
    };
    let observed_refusal_ms =
        u64::try_from(withdrawal_observed.elapsed().as_millis()).unwrap_or(u64::MAX);
    let withdrawn_key_admission_refused =
        withdrawn_admission_outcome == WithdrawnAdmissionOutcome::PeerUntrusted;
    if !withdrawn_key_admission_refused {
        return Err(HarnessError::Process(format!(
            "hint-drop withdrawn key admission did not return the PEER_UNTRUSTED 503 not_dispatched refusal: {withdrawn_admission_detail}"
        )));
    }
    // IN-05: the withdrawn key is refused inside the pooled peer connect, at
    // the handshake boundary -- the mTLS peer still answers, but the SPKI it
    // presents is no longer an approved membership key, so the binding recheck
    // that follows the handshake fails while the observer is still at
    // `pool_connect`.  This is the gate's own fault, so the tuple must carry
    // the scope of the admission it just refused.
    let peer_faults_after_refusal = cluster.peer_fault_stages().await?;
    let withdrawn_pool_connect_fault = super::require_peer_fault_stage(
        "hint-drop withdrawn-key admission",
        &peer_faults_before_refusal,
        &peer_faults_after_refusal,
        "ingress",
        "pool_connect",
        "membership",
        super::PeerFaultCorrelation {
            tenant_id: device_a.tenant_id,
            device_id: device_a.id,
            owner_node_id: Some(TARGET_NODE),
            owner_epoch: Some(owner_a.token.epoch),
            service_id: Some(service_a),
            require_request_identity: true,
        },
    )?;
    if withdrawn_pool_connect_fault.node_id != AFFECTED_INGRESS {
        return Err(HarnessError::Process(format!(
            "hint-drop pool_connect fault was recorded by {} rather than the affected ingress {AFFECTED_INGRESS}",
            withdrawn_pool_connect_fault.node_id
        )));
    }
    let dispatch_after_refusal = cluster
        .relay(TARGET_NODE)?
        .snapshot()
        .await?
        .lifetime_application_dispatches;
    if dispatch_before_refusal != dispatch_after_refusal {
        return Err(HarnessError::Process(
            "hint-drop withdrawn key admission advanced the owner dispatch counter".into(),
        ));
    }
    let target_dispatch_unchanged = dispatch_after_refusal == target_dispatch_baseline
        && super::wait_for_unchanged_application_dispatch(
            cluster.relay(TARGET_NODE)?,
            target_dispatch_baseline,
        )
        .await
        .is_ok();
    if !target_dispatch_unchanged {
        return Err(HarnessError::Process(format!(
            "hint-drop rotated owner dispatch moved from {target_dispatch_baseline} to {dispatch_after_refusal}"
        )));
    }

    // ---- Arm 2: no collateral damage on the non-rotated identity --------
    resources
        .stream_b
        .as_mut()
        .expect("sibling stream installed")
        .round_trip(b"after-withdrawal-b", b"m7-hint-drop-b")
        .await?;
    let sibling_after = cluster.relay(SIBLING_OWNER)?.snapshot().await?;
    let sibling_stream_survived =
        sibling_owner_stream_advanced(&sibling_after, &owner_b.token, &sibling_cursor_before);
    let sibling_dispatch_advanced = sibling_after.lifetime_application_dispatches
        > sibling_before.lifetime_application_dispatches;
    if !sibling_stream_survived || !sibling_dispatch_advanced {
        return Err(HarnessError::Process(
            "hint-drop sibling owner session or dispatch did not advance across the withdrawal"
                .into(),
        ));
    }

    // Capture the drop counters before the window closes.
    let target_hints_dropped = filter.target_dropped.load(Ordering::SeqCst);
    let other_hints_dropped = filter.other_dropped.load(Ordering::SeqCst);
    let publications_during_drop_window = filter.published_in_window.load(Ordering::SeqCst);

    // ---- Recovery: re-approve the real key and prove the fixture is live --
    filter.disarm();
    let recovery_now = Utc::now();
    let recovery_record = sign_target_record(cluster, recovery_now, 4, &[&old_spki])?;
    let recovery_record_version = recovery_record.payload.record_version;
    publish_membership(harness, &recovery_record).await?;
    wait_for_record_version(cluster, recovery_record_version).await?;
    for relay in &cluster.relays {
        wait_until_membership_ready(&relay.membership, RECOVERY_BOUND).await?;
        publish_verified_pins(&relay.membership, &relay.pins)?;
    }
    cluster.wait_for_peer_readiness(RECOVERY_BOUND).await?;
    cluster
        .fixture
        .memberships
        .insert(TARGET_NODE.to_owned(), recovery_record);
    if let Some(mut withdrawn_stream) = resources.stream_a.take() {
        let _ = withdrawn_stream.close().await;
    }
    resources.stream_a = Some(
        open_consumer_stream(
            affected_ingress,
            &harness.pki.server_ca.certificate_der,
            &token_a,
            device_a.id,
            service_a,
        )
        .await
        .map_err(connect_failure_to_harness)?,
    );
    resources
        .stream_a
        .as_mut()
        .expect("recovery stream installed")
        .round_trip(b"after-recovery-a", b"m7-hint-drop-a")
        .await?;

    Ok(MembershipHintDropEvidence {
        relay_count: cluster.relays.len(),
        overlap_record_version: 2,
        withdrawal_record_version: 3,
        target_hints_dropped,
        other_hints_dropped,
        publications_during_drop_window,
        overlap_both_keys_converged,
        overlap_stream_survived,
        withdrawn_key_left_verifier,
        overlap_stream_interrupted_after_withdrawal,
        target_dispatch_unchanged,
        withdrawn_key_admission_refused,
        withdrawn_admission_outcome,
        sibling_stream_survived,
        sibling_dispatch_advanced,
        membership_refresh_bound_ms: MEMBERSHIP_REFRESH_BOUND.as_millis() as u64,
        reconcile_tick_ms: RECONCILE_TICK.as_millis() as u64,
        observed_convergence_ms,
        observed_refusal_ms,
        recovery_record_version,
        recovery_echo: true,
        fanout_peak_open: cluster.device_fanout.diagnostics().peak_open,
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

fn classify_withdrawn_admission(status: u16, body: Option<&[u8]>) -> WithdrawnAdmissionOutcome {
    if status != 503 {
        return WithdrawnAdmissionOutcome::Untyped;
    }
    let Some(body) = body else {
        return WithdrawnAdmissionOutcome::Untyped;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return WithdrawnAdmissionOutcome::Untyped;
    };
    if value.get("execution").and_then(serde_json::Value::as_str) != Some("not_dispatched") {
        return WithdrawnAdmissionOutcome::Untyped;
    }
    match value.get("code").and_then(serde_json::Value::as_str) {
        Some("PEER_UNTRUSTED") => WithdrawnAdmissionOutcome::PeerUntrusted,
        Some("CLUSTER_UNREADY") => WithdrawnAdmissionOutcome::ClusterUnready,
        Some("PEER_UNAVAILABLE") => WithdrawnAdmissionOutcome::PeerUnavailable,
        _ => WithdrawnAdmissionOutcome::Untyped,
    }
}

pub(super) fn target_peer_spki(cluster: &ProductionCluster) -> Result<String> {
    cluster
        .fixture
        .nodes
        .iter()
        .find(|node| node.node_id == TARGET_NODE)
        .ok_or_else(|| HarnessError::InvalidInput("hint-drop target node is missing".into()))?
        .peer_spki_fingerprint()
}

/// Sign a target record approving exactly `spkis`, each valid for the full
/// fixture lifetime.  Nothing here expires inside the run: the only reason a
/// key stops being approved is that a later record no longer lists it.
fn sign_target_record(
    cluster: &ProductionCluster,
    now: DateTime<Utc>,
    record_version: u64,
    spkis: &[&str],
) -> Result<SignedMembershipFixture> {
    let node = cluster
        .fixture
        .nodes
        .iter()
        .find(|node| node.node_id == TARGET_NODE)
        .ok_or_else(|| HarnessError::InvalidInput("hint-drop target node is missing".into()))?;
    let peer_endpoint = cluster
        .peer_proxies
        .get(TARGET_NODE)
        .ok_or_else(|| HarnessError::InvalidInput("hint-drop target proxy is missing".into()))?
        .address();
    let keys = spkis
        .iter()
        .enumerate()
        .map(|(index, spki)| FixturePeerKey {
            key_id: format!("relay-a-peer-v{record_version}-{index}"),
            spki_sha256: (*spki).to_owned(),
            not_before: now,
            expires_at: now + M7_MEMBERSHIP_LIFETIME,
            revoked: false,
        })
        .collect();
    cluster
        .checkpoint_authority
        .issuer
        .sign_membership_with_endpoint_and_keys(
            &cluster.fixture.deployment_id,
            &cluster.fixture.deployment_incarnation,
            node,
            MembershipRecordOptions {
                record_version,
                peer_endpoint,
                keys,
                now,
                expires_at: now + M7_MEMBERSHIP_LIFETIME,
            },
        )
}

async fn publish_membership(
    harness: &RunningHarness,
    record: &SignedMembershipFixture,
) -> Result<()> {
    let publisher =
        RedisMembershipPublisher::connect(harness.redis.redis_url(), harness.redis.namespace())
            .await
            .map_err(|error| {
                HarnessError::Redis(format!("connecting hint-drop publisher: {error}"))
            })?;
    publisher
        .publish_signed_membership_for_node(TARGET_NODE, &record.catalog_record())
        .await
        .map_err(|error| HarnessError::Redis(format!("publishing hint-drop record: {error}")))
}

/// Wait until the exact signed bytes are readable from Redis.  This is the
/// earliest instant any relay's refresh could observe the withdrawal, and it
/// is where the convergence measurement starts.
async fn wait_for_catalog_record(
    cluster: &ProductionCluster,
    record: &SignedMembershipFixture,
) -> Result<()> {
    let deadline = Instant::now() + SETUP_BOUND;
    loop {
        let observed = cluster
            .catalog
            .read_signed_memberships()
            .await
            .map_err(|error| HarnessError::Redis(format!("reading hint-drop record: {error}")))?;
        if observed.iter().any(|entry| {
            entry.version == record.payload.record_version && entry.bytes == record.encoded_bytes()
        }) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "hint-drop record version {} did not become readable from Redis",
                record.payload.record_version
            )));
        }
        sleep(POLL).await;
    }
}

async fn wait_for_record_version(cluster: &ProductionCluster, version: u64) -> Result<()> {
    let deadline = Instant::now() + SETUP_BOUND;
    loop {
        let applied = cluster.relays.iter().all(|relay| {
            relay
                .membership
                .snapshot()
                .memberships
                .iter()
                .any(|record| record.node_id == TARGET_NODE && record.record_version >= version)
        });
        if applied {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "hint-drop signed record version {version} did not reach all relays"
            )));
        }
        sleep(POLL).await;
    }
}

/// Wait until every relay's verifier carries exactly `spkis` for the target at
/// `version`.  A zero budget makes this a single immediate observation.
async fn wait_for_target_keys(
    cluster: &ProductionCluster,
    version: u64,
    spkis: &[&str],
    budget: Duration,
) -> Result<bool> {
    let deadline = Instant::now() + budget;
    loop {
        let converged = cluster.relays.iter().all(|relay| {
            relay
                .membership
                .snapshot()
                .memberships
                .iter()
                .any(|record| {
                    record.node_id == TARGET_NODE
                        && record.record_version == version
                        && record.spki_sha256.len() == spkis.len()
                        && spkis
                            .iter()
                            .all(|spki| record.spki_sha256.iter().any(|held| held == spki))
                })
        });
        if converged {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        sleep(POLL).await;
    }
}

/// Wait until one relay's verifier has advanced to `version` for the target and
/// no longer holds `spki`.  This reads the same verified state `admit_peer`
/// binds against, so it is the convergence the refusal is a consequence of.
async fn wait_for_key_absent(
    cluster: &ProductionCluster,
    observer: &str,
    version: u64,
    spki: &str,
    budget: Duration,
) -> Result<bool> {
    let deadline = Instant::now() + budget;
    loop {
        let converged = cluster
            .relay(observer)?
            .membership
            .snapshot()
            .memberships
            .iter()
            .any(|record| {
                record.node_id == TARGET_NODE
                    && record.record_version >= version
                    && !record.spki_sha256.iter().any(|held| held == spki)
            });
        if converged {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        sleep(POLL).await;
    }
}

/// Wait until the owner no longer reports a live stream for this session, which
/// is the owner-side view of the pooled admission being re-bound and dropped.
async fn wait_for_owner_stream_retired(
    cluster: &ProductionCluster,
    owner_node: &str,
    owner: &OwnerToken,
    budget: Duration,
) -> Result<bool> {
    let deadline = Instant::now() + budget;
    loop {
        let snapshot = cluster.relay(owner_node)?.snapshot().await?;
        let live = snapshot
            .sessions
            .iter()
            .filter(|session| {
                session.tenant_id == owner.tenant_id.to_string()
                    && session.device_id == owner.device_id.to_string()
                    && session.session_id == owner.session_id
                    && session.epoch == owner.epoch
            })
            .any(|session| session.streams.iter().any(|stream| !stream.terminal));
        if !live {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        sleep(POLL).await;
    }
}

async fn wait_until_membership_ready(
    membership: &tunnel_relay::MembershipRuntime,
    budget: Duration,
) -> Result<()> {
    let deadline = Instant::now() + budget;
    loop {
        if matches!(membership.readiness(), MembershipReadiness::Ready) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "hint-drop reapproved membership did not become Ready".into(),
            ));
        }
        sleep(POLL).await;
    }
}

#[derive(Clone, Debug)]
struct OwnerSessionCursor {
    tenant_id: String,
    device_id: String,
    session_id: String,
    epoch: u64,
    active_generation: u64,
    active_connection_id: String,
    rotations_completed: u64,
    total_replayed_frames: u64,
    stream_id: u64,
    operation_id: String,
    last_emitted: u64,
    delivered: u64,
    terminal: bool,
}

fn owner_session_cursor(
    snapshot: &RelaySnapshot,
    owner: &OwnerToken,
) -> Option<OwnerSessionCursor> {
    owner_session_cursor_for(snapshot, owner, None)
}

fn owner_session_cursor_for(
    snapshot: &RelaySnapshot,
    owner: &OwnerToken,
    expected_stream: Option<(u64, &str)>,
) -> Option<OwnerSessionCursor> {
    snapshot
        .sessions
        .iter()
        .find(|session| {
            session.tenant_id == owner.tenant_id.to_string()
                && session.device_id == owner.device_id.to_string()
                && session.session_id == owner.session_id
                && session.epoch == owner.epoch
        })
        .and_then(|session| {
            // The consumer handle does not expose the relay-assigned stream ID.
            // Establish the logical target from the one nonterminal stream
            // present after the baseline exchange, and reject an ambiguous
            // snapshot rather than selecting an arbitrary stream.
            let stream = match expected_stream {
                Some((stream_id, operation_id)) => session.streams.iter().find(|stream| {
                    stream.stream_id == stream_id && stream.operation_id == operation_id
                })?,
                None => {
                    let mut candidates = session.streams.iter().filter(|stream| !stream.terminal);
                    let stream = candidates.next()?;
                    if candidates.next().is_some() {
                        return None;
                    }
                    stream
                }
            };
            Some(OwnerSessionCursor {
                tenant_id: session.tenant_id.clone(),
                device_id: session.device_id.clone(),
                session_id: session.session_id.clone(),
                epoch: session.epoch,
                active_generation: session.active_generation,
                active_connection_id: session.active_connection_id.clone(),
                rotations_completed: session.rotations_completed,
                total_replayed_frames: session.total_replayed_frames,
                stream_id: stream.stream_id,
                operation_id: stream.operation_id.clone(),
                last_emitted: stream.last_emitted_relay_to_connector,
                delivered: stream.delivered_contiguous_connector_to_relay,
                terminal: stream.terminal,
            })
        })
}

fn verified_carrier_transition(before: &OwnerSessionCursor, after: &OwnerSessionCursor) -> bool {
    if before.active_generation == after.active_generation
        && before.active_connection_id == after.active_connection_id
    {
        return true;
    }
    // A new physical carrier is accepted only when the relay reports one or
    // more clean, scheduled rotation commits.  A connection replacement with no
    // completed rotation cannot be used to hide a logical stream identity
    // change.
    let generation_delta = after
        .active_generation
        .saturating_sub(before.active_generation);
    let rotation_delta = after
        .rotations_completed
        .saturating_sub(before.rotations_completed);
    generation_delta > 0
        && rotation_delta > 0
        && generation_delta == rotation_delta
        && after.total_replayed_frames == before.total_replayed_frames
}

fn sibling_owner_stream_advanced(
    snapshot: &RelaySnapshot,
    owner: &OwnerToken,
    before: &OwnerSessionCursor,
) -> bool {
    let Some(after) = owner_session_cursor_for(
        snapshot,
        owner,
        Some((before.stream_id, &before.operation_id)),
    ) else {
        return false;
    };
    if after.tenant_id != before.tenant_id
        || after.device_id != before.device_id
        || after.session_id != before.session_id
        || after.epoch != before.epoch
        || !verified_carrier_transition(before, &after)
        || after.stream_id != before.stream_id
        || after.operation_id != before.operation_id
    {
        return false;
    }
    !after.terminal
        && (after.last_emitted > before.last_emitted || after.delivered > before.delivered)
}

#[allow(clippy::too_many_arguments)]
async fn wait_for_owner_admission(
    cluster: &ProductionCluster,
    ingress_node: &str,
    consumer_addr: std::net::SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: uuid::Uuid,
    service_id: uuid::Uuid,
    label: &str,
) -> Result<()> {
    let deadline = Instant::now() + OWNER_FENCE_READY_BOUND;
    loop {
        let admission = tokio::time::timeout_at(
            deadline.into(),
            open_consumer_stream(consumer_addr, server_ca_der, token, device_id, service_id),
        )
        .await
        .map_err(|_| {
            HarnessError::Timeout(format!(
                "hint-drop {label} owner-fence admission deadline exceeded"
            ))
        })?;
        match admission {
            Ok(mut stream) => {
                tokio::time::timeout_at(deadline.into(), stream.close())
                    .await
                    .map_err(|_| {
                        HarnessError::Timeout(format!(
                            "hint-drop {label} owner-fence probe close deadline exceeded"
                        ))
                    })?
                    .map_err(|error| {
                        HarnessError::Http(format!(
                            "hint-drop {label} owner-fence probe cleanup failed: {error}"
                        ))
                    })?;
                return Ok(());
            }
            Err(super::StreamConnectFailure::Status { status, body })
                if is_retryable_owner_not_ready(status, body.as_deref()) =>
            {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let Some(retry_after_ms) = retry_after_ms(body.as_deref()) else {
                    return Err(hint_drop_consumer_failure(
                        cluster,
                        ingress_node,
                        label,
                        super::StreamConnectFailure::Status { status, body },
                    ));
                };
                let delay = Duration::from_millis(retry_after_ms.min(1_000));
                if remaining.is_zero() || delay >= remaining {
                    return Err(HarnessError::Timeout(format!(
                        "hint-drop {label} owner-fence admission did not become ready within {} ms (status={status}); {}",
                        OWNER_FENCE_READY_BOUND.as_millis(),
                        ingress_readiness_context(cluster, ingress_node)
                    )));
                }
                sleep(delay).await;
            }
            Err(error) => {
                return Err(hint_drop_consumer_failure(
                    cluster,
                    ingress_node,
                    label,
                    error,
                ));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn open_baseline_consumer_stream(
    cluster: &ProductionCluster,
    ingress_node: &str,
    consumer_addr: std::net::SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: uuid::Uuid,
    service_id: uuid::Uuid,
    label: &str,
) -> Result<ConsumerStream> {
    open_consumer_stream(consumer_addr, server_ca_der, token, device_id, service_id)
        .await
        .map_err(|error| hint_drop_consumer_failure(cluster, ingress_node, label, error))
}

fn hint_drop_consumer_failure(
    cluster: &ProductionCluster,
    ingress_node: &str,
    label: &str,
    error: super::StreamConnectFailure,
) -> HarnessError {
    let context = ingress_readiness_context(cluster, ingress_node);
    match error {
        super::StreamConnectFailure::Status { status, body } => HarnessError::Http(format!(
            "hint-drop {label} consumer admission returned HTTP status {status} ({}); {context}",
            super::redacted_admission_failure(body.as_deref())
        )),
        super::StreamConnectFailure::Harness(error) => HarnessError::Http(format!(
            "hint-drop {label} consumer admission failed: {error}; {context}"
        )),
    }
}

fn ingress_readiness_context(cluster: &ProductionCluster, ingress_node: &str) -> String {
    let Ok(relay) = cluster.relay(ingress_node) else {
        return format!("ingress_node={ingress_node},relay=<missing>");
    };
    let membership = relay.membership.snapshot();
    let target_record_version = membership
        .memberships
        .iter()
        .find(|record| record.node_id == TARGET_NODE)
        .map(|record| record.record_version);
    format!(
        "ingress_node={ingress_node},membership_readiness={:?},membership_generation={},target_record_version={target_record_version:?},active_peer_count={},peer_ready={}",
        membership.readiness,
        membership.generation,
        membership.active_peer_count,
        relay.peer_runtime.is_ready(),
    )
}

fn retry_after_ms(body: Option<&[u8]>) -> Option<u64> {
    serde_json::from_slice::<serde_json::Value>(body?)
        .ok()?
        .get("retry_after_ms")
        .and_then(serde_json::Value::as_u64)
}

fn is_retryable_owner_not_ready(status: u16, body: Option<&[u8]>) -> bool {
    if status != 503 {
        return false;
    }
    let Some(body) = body else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    value.get("execution").and_then(serde_json::Value::as_str) == Some("not_dispatched")
        && value.get("retryable").and_then(serde_json::Value::as_bool) == Some(true)
        && matches!(
            value.get("code").and_then(serde_json::Value::as_str),
            Some("PEER_UNAVAILABLE" | "CLUSTER_UNREADY")
        )
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
    .map_err(|_| HarnessError::Timeout("hint-drop client startup timed out".into()))?
    .map_err(|error| HarnessError::Process(format!("hint-drop client startup failed: {error}")))
}

async fn wait_ready(client: &mut ConnectionHandle, label: &str) -> Result<()> {
    timeout(super::STARTUP_TIMEOUT, client.wait_ready())
        .await
        .map_err(|_| HarnessError::Timeout(format!("hint-drop {label} readiness timed out")))?
        .map(|_| ())
        .map_err(|error| HarnessError::Process(format!("hint-drop {label} not ready: {error}")))
}

async fn stop_client(client: &ConnectionHandle, label: &str, deadline: Instant) -> Result<()> {
    // `ConnectionHandle::stop` owns the supervisor join and is
    // cancellation-safe; await it to completion so the handle is never dropped
    // with an unjoined owner, then report a missed budget as evidence.
    let result = client.stop().await;
    let exceeded_deadline = Instant::now() > deadline;
    match result {
        Ok(()) if exceeded_deadline => Err(HarnessError::Timeout(format!(
            "{label} shutdown joined after the cleanup deadline"
        ))),
        Ok(()) => Ok(()),
        Err(error) => Err(HarnessError::Process(format!(
            "{label} shutdown failed: {error}"
        ))),
    }
}
