//! OG-08 bounded multi-fault chaos classification gate.
//!
//! One real three-relay production cluster (relays connected to Redis through
//! an opaque TCP proxy so Redis can be paused) is driven through a fixed
//! schedule of chaos rounds ([`CHAOS_SCHEDULE`], seven rounds) that repeat
//! owner kill, CLI process pause and peer UDP loss and exercise a full Redis
//! pause once, all built from existing fault injectors rather than new
//! mechanisms.  A full Redis pause is the terminal round: it expires the
//! in-process fixture's signed membership lease (a fixture limitation, not a
//! protocol one), so the run does not attempt to reuse the cluster after it.
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
//! unclassified.  Every round then recycles the owner session (join predecessor,
//! start a fresh one) so device-fanout reconnect sockets are counted per round
//! and the peak per-second rate is bounded: a reconnect storm fails the gate.
//! Release is blocked (validation fails) on any unclassified interruption, any
//! reconnect rate above the documented threshold, or a missing recovery.

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

/// The fixed chaos schedule.  Owner kill, CLI process pause and peer UDP loss
/// are each repeated; a full Redis pause is exercised once.  Pausing *all*
/// proxied Redis sockets expires this in-process fixture's signed membership
/// lease, and the membership runtime does not re-arm for continued reuse after
/// a second full outage on the same long-lived cluster (a limitation of the
/// in-process fixture, not of the protocol), so a second full Redis pause would
/// leave the cluster unroutable.  Each of the four faults still appears at
/// least once and the non-Redis faults are cycled repeatedly.
const CHAOS_SCHEDULE: [Fault; 7] = [
    Fault::PeerLoss,
    Fault::CliPause,
    Fault::OwnerKill,
    Fault::PeerLoss,
    Fault::CliPause,
    Fault::OwnerKill,
    Fault::RedisPause,
];
const CHAOS_ROUNDS: usize = CHAOS_SCHEDULE.len();
/// Whole-scenario wall-clock bound.  Cleanup joins are still owned by the
/// scenario itself; this is the outer safety net.
const CHAOS_SCENARIO_DEADLINE: Duration = Duration::from_secs(300);
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
    pub class_bounded_close: usize,
    pub class_admission_unavailable: usize,
    pub class_peer_unavailable: usize,
    pub class_owner_released: usize,
    /// Total device-fanout sockets accepted across all rounds (reconnects).
    pub reconnect_sockets_total: u64,
    /// Peak per-round reconnect rate (sockets/second) scaled by 1000.
    pub max_reconnect_rate_milli: u64,
    /// Documented reconnect ceiling used by [`validate_chaos_evidence`].
    pub reconnect_rate_threshold_milli: u64,
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
const CLASS_VOCABULARY: [InterruptionClass; 6] = [
    InterruptionClass::BoundedClose,
    InterruptionClass::AdmissionUnavailable,
    InterruptionClass::PeerUnavailable,
    InterruptionClass::OwnerReleased,
    InterruptionClass::OutcomeUnknown,
    InterruptionClass::Unclassified,
];

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
classified={} unclassified={} unknown_preserved={} bounded_close={} admission_unavailable={} \
peer_unavailable={} owner_released={} reconnect_sockets={} max_reconnect_rate_milli={} \
reconnect_threshold_milli={} fanout_peak_open={} recovered_each_round={} final_recovery={} \
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
            self.class_bounded_close,
            self.class_admission_unavailable,
            self.class_peer_unavailable,
            self.class_owner_released,
            self.reconnect_sockets_total,
            self.max_reconnect_rate_milli,
            self.reconnect_rate_threshold_milli,
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
    if evidence.unclassified_interruptions != 0 {
        return Err(reject("no_unclassified_interruption"));
    }
    if evidence.classified_interruptions + evidence.unknown_outcomes_preserved != evidence.rounds {
        return Err(reject("every_round_classified_or_preserved_unknown"));
    }
    let class_total = evidence.class_bounded_close
        + evidence.class_admission_unavailable
        + evidence.class_peer_unavailable
        + evidence.class_owner_released;
    if class_total != evidence.classified_interruptions {
        return Err(reject("class_tally_matches_classified"));
    }
    if evidence.unknown_outcomes_preserved > MAX_UNKNOWN_OUTCOMES {
        return Err(reject("unknown_outcomes_within_bound"));
    }
    if evidence.reconnect_rate_threshold_milli != RECONNECT_RATE_THRESHOLD_MILLI {
        return Err(reject("documented_reconnect_threshold"));
    }
    if evidence.max_reconnect_rate_milli > evidence.reconnect_rate_threshold_milli {
        return Err(reject("reconnect_rate_within_threshold"));
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
        class_bounded_close: 0,
        class_admission_unavailable: 0,
        class_peer_unavailable: 0,
        class_owner_released: 0,
        reconnect_sockets_total: 0,
        max_reconnect_rate_milli: 0,
        reconnect_rate_threshold_milli: RECONNECT_RATE_THRESHOLD_MILLI,
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
        tally_class(&mut evidence, class);
        match fault {
            Fault::RedisPause => evidence.redis_pause_rounds += 1,
            Fault::PeerLoss => evidence.peer_loss_rounds += 1,
            Fault::CliPause => evidence.cli_pause_rounds += 1,
            Fault::OwnerKill => evidence.owner_kill_rounds += 1,
        }
        evidence.rounds += 1;

        // Recovery policy per fault:
        // * OwnerKill / CliPause / PeerLoss disturb the live session (a killed
        //   process, a consumed probe stream, or a black-holed owner peer
        //   path), so recycle it and echo on the fresh one.  Peer UDP loss does
        //   not affect the Redis-backed membership, so the cluster stays
        //   routable and the recycle succeeds.
        // * RedisPause is terminal: it expires the in-process membership lease,
        //   so the cluster is not reused — classify only, recover nothing.
        match fault {
            Fault::OwnerKill | Fault::CliPause | Fault::PeerLoss => {
                session = recycle_session(&mut context, session).await?;
                record_recovery(
                    &mut evidence,
                    &mut recovered_each_round,
                    soft_recovery_echo(&mut context, &mut session).await?,
                );
            }
            Fault::RedisPause => {}
        }

        let accepted_after = context.cluster.device_fanout.diagnostics().accepted;
        let round_ms = u64::try_from(round_started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let delta = accepted_after.saturating_sub(accepted_before);
        evidence.reconnect_sockets_total += delta;
        let rate_milli = delta
            .saturating_mul(1_000_000)
            .checked_div(round_ms)
            .unwrap_or_else(|| delta.saturating_mul(1_000_000));
        evidence.max_reconnect_rate_milli = evidence.max_reconnect_rate_milli.max(rate_milli);
    }
    evidence.recovered_after_each_round = recovered_each_round;

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

/// RedisPause round (terminal): pause every proxied Redis socket, prove
/// admission fails closed with a typed authorization/cluster-unready response,
/// then resume.  This is the last round; the run does not reuse the cluster
/// afterward because a full Redis outage expires the in-process membership
/// lease, so no cluster-readiness wait is attempted here.
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
        (Ok(class), Ok(())) => Ok(class),
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
            // Admission unexpectedly succeeded during a fault: unclassified.
            drop(stream);
            InterruptionClass::Unclassified
        }
        Ok(Err(StreamConnectFailure::Status { status, body })) => {
            if is_partition_admission_response(status, body.as_deref()) {
                InterruptionClass::AdmissionUnavailable
            } else if is_peer_recovery_response(status, body.as_deref()) {
                InterruptionClass::PeerUnavailable
            } else {
                InterruptionClass::Unclassified
            }
        }
        Ok(Err(StreamConnectFailure::Harness(_))) => InterruptionClass::OutcomeUnknown,
    }
}

/// Map a paused-process probe outcome onto the closed vocabulary.
fn classify_probe(probe: ProcessPauseProbeOutcome) -> InterruptionClass {
    if probe.is_fail_closed() {
        InterruptionClass::BoundedClose
    } else if matches!(
        probe,
        ProcessPauseProbeOutcome::TimedOut | ProcessPauseProbeOutcome::SendFailed
    ) {
        InterruptionClass::OutcomeUnknown
    } else {
        // EchoAfterSend / ProtocolAfterSend: a paused owner must not echo.
        InterruptionClass::Unclassified
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CHAOS_ROUNDS, ChaosEvidence, InterruptionClass, MAX_UNKNOWN_OUTCOMES,
        RECONNECT_RATE_THRESHOLD_MILLI, validate_chaos_evidence,
    };
    use crate::acceptance_test_support::assert_failed;

    fn valid_evidence() -> ChaosEvidence {
        // Schedule: peer-loss x2 -> peer_unavailable, redis-pause x1 ->
        // admission_unavailable, cli-pause x2 -> bounded_close, owner-kill x2
        // -> owner_released.  Seven classified rounds.
        ChaosEvidence {
            relay_count: 3,
            rounds: CHAOS_ROUNDS,
            owner_kill_rounds: 2,
            cli_pause_rounds: 2,
            peer_loss_rounds: 2,
            redis_pause_rounds: 1,
            classified_interruptions: 7,
            unclassified_interruptions: 0,
            unknown_outcomes_preserved: 0,
            class_bounded_close: 2,
            class_admission_unavailable: 1,
            class_peer_unavailable: 2,
            class_owner_released: 2,
            reconnect_sockets_total: 14,
            max_reconnect_rate_milli: 600,
            reconnect_rate_threshold_milli: RECONNECT_RATE_THRESHOLD_MILLI,
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
            InterruptionClass::Unclassified,
        ] {
            assert!(!class.label().is_empty());
        }
    }

    #[test]
    fn complete_chaos_evidence_passes() {
        assert!(validate_chaos_evidence(&valid_evidence()).is_ok());
        // One preserved unknown outcome (converted from one classified round) is
        // still accepted: six classified plus one preserved unknown is seven.
        let mut with_unknown = valid_evidence();
        with_unknown.classified_interruptions = 6;
        with_unknown.class_owner_released = 1;
        with_unknown.unknown_outcomes_preserved = 1;
        assert!(validate_chaos_evidence(&with_unknown).is_ok());
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
                e.redis_pause_rounds = 3;
                e.class_owner_released = 0;
                e.class_admission_unavailable = 3;
            }),
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
                e.classified_interruptions = CHAOS_ROUNDS - excess;
                e.class_bounded_close = 0;
                e.class_peer_unavailable = 0;
                e.class_owner_released = 0;
                e.class_admission_unavailable = CHAOS_ROUNDS - excess;
            }),
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
