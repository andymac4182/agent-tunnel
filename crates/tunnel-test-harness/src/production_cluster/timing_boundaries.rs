//! Real-clock timing boundaries for the EC-055 production acceptance row.
//!
//! The acceptance command uses the production cluster, real CLI, Redis proxy,
//! consumer streams and relay snapshots. Authorization and lease phases use
//! normal policy windows; the separate rotation phase configures a two-second
//! overlap. Every boundary is sampled from the live owner claim, relay
//! snapshot, client phase and monotonic clock.

use super::{
    ConsumerStream, ProcessPauseGuard, ProcessPauseProbeOutcome, ProductionCluster, RelaySnapshot,
    RunningHarness, assert_public_health_unready, connect_failure_to_harness,
    is_expected_revocation_close, is_explicit_no_owner_response, open_consumer_stream,
    start_cli_smoke, wait_for_fanout_drained,
};
use crate::acceptance::helpers::write_device_profile;
use crate::{
    Harness, HarnessError, HarnessOptions, ManagedProcess, OidcTokenOptions, ProxyConfig,
    ProxyHandle, Result, TcpProxy,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::{SinkExt, StreamExt};
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{
    AttachmentTicket, AttachmentTicketConsumeRequest, AttachmentTicketIssueRequest,
    AuthenticatedConsumer, Catalog, CatalogError, CatalogFixture, ConsumedAttachmentTicket,
    DeviceIdentity, DeviceListFilter, DeviceSummary, GrantSnapshot, GrantSpec, OwnerClaim,
    OwnerClaimRequest, OwnerToken, SharedCatalog, SignedMembershipRecord,
};
use tunnel_client::{ConnectOptions, ConnectionHandle, TransportProfile};
use tunnel_core::RotationConfig;
use uuid::Uuid;

/// The relay's current defaults are intentionally named here so a future
/// config refactor must update the fixture rather than silently weakening it.
/// `AUTHORIZATION_LIFETIME` is the relay-side cap; the generated client also
/// carries the five-second grant deadline.  The live probe below measures the
/// actual close time and checks it falls inside both configured windows.
const RELAY_CHALLENGE_INTERVAL: Duration = Duration::from_secs(2);
const AUTHORIZATION_LIFETIME: Duration = Duration::from_secs(5);
const OWNER_LEASE_SAFETY_MARGIN: Duration = Duration::from_secs(5);
const OWNER_LEASE_OBSERVATION_GRACE: Duration = Duration::from_millis(500);
/// Keep the authorization and lease phases on the normal production policy.
/// The short policy below is requested only by the dedicated overlap phase;
/// otherwise a 2--5 second pause could expire through rotation instead of
/// exercising the authorization or lease boundary under test.
const NORMAL_ROTATION: RotationConfig = RotationConfig {
    interval_seconds: 300,
    handshake_timeout_seconds: 10,
    overlap_seconds: 30,
};
const ROTATION: RotationConfig = RotationConfig {
    interval_seconds: 3,
    handshake_timeout_seconds: 1,
    overlap_seconds: 2,
};
const PHASE_TIMEOUT: Duration = Duration::from_secs(45);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const HEALTH_POLL_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_TIMING_DISPATCH_DELTA: u64 = 0;
const OWNER_LEASE_TTL: Duration = Duration::from_secs(30);

/// Payload-free evidence from one real three-relay timing-boundary run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimingBoundaryEvidence {
    /// Number of relays that served every phase.
    pub relay_count: usize,
    /// Monotonic duration from SIGSTOP until the paused-process probe closed
    /// after the bounded authority delay.
    pub authorization_probe_elapsed_ms: u64,
    /// The successful authorization result returned by real Redis was held
    /// by the fixture-only, scope-matched result gate until the relay's
    /// challenge deadline.  This is an injected timing boundary, not a
    /// Redis connectivity fault.
    pub authorization_result_delay_injected: bool,
    /// Owner lease remaining at the authorization-expiry observation.
    pub authorization_owner_remaining_ms: u64,
    /// The authorization probe failed after the relay challenge deadline but
    /// before the five-second client grant deadline while the owner still had
    /// usable lease time.
    pub authorization_expired_before_owner_safe_deadline: bool,
    /// Static, payload-free authorization invalidation code observed on the
    /// exact owner session/stream that was paused for this probe.
    pub authorization_typed_expiry_cause_observed: bool,
    /// Dispatch count before/after the paused-process probe.
    pub authorization_dispatch_before: u64,
    pub authorization_dispatch_after: u64,
    /// Time spent with Redis partitioned before the safe lease deadline.
    pub lease_partition_elapsed_ms: u64,
    /// Owner lease remaining at the exact pre-partition sample.
    pub lease_remaining_before_partition_ms: u64,
    /// Monotonic wait from the partition barrier to the sampled safe deadline.
    pub lease_safe_deadline_wait_ms: u64,
    /// The owner was still visible before the partition and was absent after
    /// the authoritative expiry was allowed to pass.
    pub lease_owner_withdrawn_after_expiry: bool,
    /// Public readiness failed closed while liveness remained available.
    pub lease_readiness_withdrawn: bool,
    /// Dispatch count before/after the partitioned post-deadline probe.
    pub lease_dispatch_before: u64,
    pub lease_dispatch_after: u64,
    /// Fresh recovery owner epoch and canary were observed after Redis was
    /// restored.
    pub lease_recovery_epoch_advanced: bool,
    pub lease_recovery_echo: bool,
    /// Exact phase and candidate generation sampled before overlap expiry.
    pub rotation_phase: String,
    pub rotation_candidate_generation: u64,
    /// Authoritative overlap duration captured from the relay's protocol
    /// timestamps (`rotation_deadline_ms - rotation_started_at_ms`) for the
    /// exact owner session and candidate generation.
    pub rotation_overlap_elapsed_ms: u64,
    pub rotation_terminal_phase: String,
    /// Static, payload-free deadline recovery status observed on the exact
    /// owner session/epoch after the candidate generation was fenced.
    pub rotation_typed_deadline_cause_observed: bool,
    /// Dispatch count before/after the overlap-expiry probe.
    pub rotation_dispatch_before: u64,
    pub rotation_dispatch_after: u64,
    /// A fresh post-recovery canary completed after the expired candidate was
    /// fenced.
    pub rotation_recovery_epoch_advanced: bool,
    pub rotation_recovery_echo: bool,
}

/// Validate the complete timing-boundary evidence contract.
pub fn validate_timing_boundary_evidence(evidence: &TimingBoundaryEvidence) -> Result<()> {
    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "timing boundary gate expected three relays, observed {}",
            evidence.relay_count
        )));
    }
    let authorization_ms = u64::try_from(AUTHORIZATION_LIFETIME.as_millis()).unwrap_or(u64::MAX);
    if evidence.authorization_probe_elapsed_ms > authorization_ms.saturating_add(1_000) {
        return Err(HarnessError::Process(format!(
            "authorization probe close observation exceeded the bounded grant window: {}ms > {}ms",
            evidence.authorization_probe_elapsed_ms,
            authorization_ms.saturating_add(1_000)
        )));
    }
    if !evidence.authorization_result_delay_injected {
        return Err(HarnessError::Unsupported(
            "timing authorization evidence did not observe the scoped real-Redis result delay"
                .into(),
        ));
    }
    if evidence.authorization_owner_remaining_ms
        <= u64::try_from(OWNER_LEASE_SAFETY_MARGIN.as_millis()).unwrap_or(u64::MAX)
    {
        return Err(HarnessError::Process(
            "authorization expired without a still-usable owner lease sample".into(),
        ));
    }
    if !evidence.authorization_expired_before_owner_safe_deadline {
        return Err(HarnessError::Process(
            "authorization expiry was not observed before the owner safe deadline".into(),
        ));
    }
    if evidence
        .authorization_dispatch_after
        .saturating_sub(evidence.authorization_dispatch_before)
        > MAX_TIMING_DISPATCH_DELTA
    {
        return Err(HarnessError::Process(
            "paused authorization probe advanced the relay dispatch counter".into(),
        ));
    }
    if evidence.lease_remaining_before_partition_ms
        <= u64::try_from(OWNER_LEASE_SAFETY_MARGIN.as_millis()).unwrap_or(u64::MAX)
    {
        return Err(HarnessError::Process(
            "Redis partition began without a usable owner lease sample".into(),
        ));
    }
    let lease_ttl_ms = u64::try_from(OWNER_LEASE_TTL.as_millis()).unwrap_or(u64::MAX);
    let lease_margin_ms = u64::try_from(OWNER_LEASE_SAFETY_MARGIN.as_millis()).unwrap_or(u64::MAX);
    let lease_grace_ms =
        u64::try_from(OWNER_LEASE_OBSERVATION_GRACE.as_millis()).unwrap_or(u64::MAX);
    if evidence.lease_remaining_before_partition_ms > lease_ttl_ms.saturating_add(1_000) {
        return Err(HarnessError::Process(format!(
            "owner lease sample exceeded the configured {}ms TTL: {}ms",
            lease_ttl_ms, evidence.lease_remaining_before_partition_ms
        )));
    }
    let expected_safe_wait = evidence
        .lease_remaining_before_partition_ms
        .saturating_sub(lease_margin_ms)
        .saturating_add(lease_grace_ms);
    let safe_wait_tolerance = 2_000_u64;
    if evidence.lease_safe_deadline_wait_ms < expected_safe_wait.saturating_sub(safe_wait_tolerance)
        || evidence.lease_safe_deadline_wait_ms
            > expected_safe_wait.saturating_add(safe_wait_tolerance)
    {
        return Err(HarnessError::Timeout(format!(
            "partition observation waited {}ms for the safe lease deadline; expected about {}ms from the sampled {}ms lease",
            evidence.lease_safe_deadline_wait_ms,
            expected_safe_wait,
            evidence.lease_remaining_before_partition_ms
        )));
    }
    if evidence.lease_partition_elapsed_ms < evidence.lease_safe_deadline_wait_ms
        || evidence.lease_partition_elapsed_ms
            > evidence
                .lease_remaining_before_partition_ms
                .saturating_add(2_000)
    {
        return Err(HarnessError::Timeout(format!(
            "partition boundary elapsed {}ms is inconsistent with the safe-deadline wait {}ms and sampled lease {}ms",
            evidence.lease_partition_elapsed_ms,
            evidence.lease_safe_deadline_wait_ms,
            evidence.lease_remaining_before_partition_ms
        )));
    }
    if !evidence.lease_owner_withdrawn_after_expiry || !evidence.lease_readiness_withdrawn {
        return Err(HarnessError::Process(
            "Redis partition did not withdraw readiness and owner after the observed lease expiry"
                .into(),
        ));
    }
    if evidence
        .lease_dispatch_after
        .saturating_sub(evidence.lease_dispatch_before)
        > MAX_TIMING_DISPATCH_DELTA
    {
        return Err(HarnessError::Process(
            "Redis partition post-deadline probe advanced the relay dispatch counter".into(),
        ));
    }
    if !evidence.lease_recovery_epoch_advanced || !evidence.lease_recovery_echo {
        return Err(HarnessError::Process(
            "Redis partition did not produce a higher-epoch fresh recovery canary".into(),
        ));
    }
    if !matches!(
        evidence.rotation_phase.as_str(),
        "preparing" | "quiescing" | "draining"
    ) || evidence.rotation_candidate_generation == 0
    {
        return Err(HarnessError::Process(format!(
            "rotation candidate barrier was not sampled in a valid phase: phase={}, generation={}",
            evidence.rotation_phase, evidence.rotation_candidate_generation
        )));
    }
    let overlap_ms = ROTATION.overlap_seconds.saturating_mul(1_000);
    if evidence.rotation_overlap_elapsed_ms != overlap_ms {
        return Err(HarnessError::Process(
            "rotation relay did not expose the exact configured overlap window".into(),
        ));
    }
    if !matches!(
        evidence.rotation_terminal_phase.as_str(),
        "aborting" | "recovering" | "closed" | "failed"
    ) {
        return Err(HarnessError::Process(format!(
            "rotation overlap expiry did not report a typed terminal phase: {}",
            evidence.rotation_terminal_phase
        )));
    }
    if evidence
        .rotation_dispatch_after
        .saturating_sub(evidence.rotation_dispatch_before)
        > MAX_TIMING_DISPATCH_DELTA
    {
        return Err(HarnessError::Process(
            "expired rotation candidate advanced the relay dispatch counter".into(),
        ));
    }
    if !evidence.rotation_recovery_epoch_advanced || !evidence.rotation_recovery_echo {
        return Err(HarnessError::Process(
            "rotation overlap expiry did not reach a higher-epoch fresh recovery canary".into(),
        ));
    }
    let mut missing_typed_causes = Vec::new();
    if !evidence.authorization_typed_expiry_cause_observed {
        missing_typed_causes.push("authorization invalidation cause");
    }
    if !evidence.rotation_typed_deadline_cause_observed {
        missing_typed_causes.push("rotation RecoveryReason::Deadline");
    }
    if !missing_typed_causes.is_empty() {
        return Err(HarnessError::Unsupported(format!(
            "EC-055 timing evidence remains partial; exposed diagnostics do not prove {}",
            missing_typed_causes.join(" and ")
        )));
    }
    Ok(())
}

#[cfg(test)]
mod c17_validator_tests {
    use super::{TimingBoundaryEvidence, validate_timing_boundary_evidence};
    use crate::acceptance_test_support::assert_failed;

    fn valid_evidence() -> TimingBoundaryEvidence {
        TimingBoundaryEvidence {
            relay_count: 3,
            authorization_probe_elapsed_ms: 1,
            authorization_result_delay_injected: true,
            authorization_owner_remaining_ms: 6_000,
            authorization_expired_before_owner_safe_deadline: true,
            authorization_typed_expiry_cause_observed: true,
            authorization_dispatch_before: 1,
            authorization_dispatch_after: 1,
            lease_partition_elapsed_ms: 5_500,
            lease_remaining_before_partition_ms: 10_000,
            lease_safe_deadline_wait_ms: 5_500,
            lease_owner_withdrawn_after_expiry: true,
            lease_readiness_withdrawn: true,
            lease_dispatch_before: 2,
            lease_dispatch_after: 2,
            lease_recovery_epoch_advanced: true,
            lease_recovery_echo: true,
            rotation_phase: "preparing".into(),
            rotation_candidate_generation: 2,
            rotation_overlap_elapsed_ms: 2_000,
            rotation_terminal_phase: "failed".into(),
            rotation_typed_deadline_cause_observed: true,
            rotation_dispatch_before: 3,
            rotation_dispatch_after: 3,
            rotation_recovery_epoch_advanced: true,
            rotation_recovery_echo: true,
        }
    }

    #[test]
    fn every_timing_flag_and_bound_reaches_the_shared_exit_path() {
        type Mutate = (&'static str, fn(&mut TimingBoundaryEvidence));
        let cases: [Mutate; 23] = [
            ("relay_count", |e| e.relay_count = 2),
            ("authorization_probe_elapsed_ms", |e| {
                e.authorization_probe_elapsed_ms = 6_001
            }),
            ("authorization_result_delay_injected", |e| {
                e.authorization_result_delay_injected = false
            }),
            ("authorization_owner_remaining_ms", |e| {
                e.authorization_owner_remaining_ms = 5_000
            }),
            ("authorization_expired_before_owner_safe_deadline", |e| {
                e.authorization_expired_before_owner_safe_deadline = false
            }),
            ("authorization_typed_expiry_cause_observed", |e| {
                e.authorization_typed_expiry_cause_observed = false
            }),
            ("authorization_dispatch", |e| {
                e.authorization_dispatch_after += 1
            }),
            ("lease_partition_elapsed_ms", |e| {
                e.lease_partition_elapsed_ms = 1
            }),
            ("lease_remaining_before_partition_ms", |e| {
                e.lease_remaining_before_partition_ms = 5_000
            }),
            ("lease_safe_deadline_wait_ms", |e| {
                e.lease_safe_deadline_wait_ms = 1
            }),
            ("lease_owner_withdrawn_after_expiry", |e| {
                e.lease_owner_withdrawn_after_expiry = false
            }),
            ("lease_readiness_withdrawn", |e| {
                e.lease_readiness_withdrawn = false
            }),
            ("lease_dispatch", |e| e.lease_dispatch_after += 1),
            ("lease_recovery_epoch_advanced", |e| {
                e.lease_recovery_epoch_advanced = false
            }),
            ("lease_recovery_echo", |e| e.lease_recovery_echo = false),
            ("rotation_phase", |e| e.rotation_phase = "active".into()),
            ("rotation_candidate_generation", |e| {
                e.rotation_candidate_generation = 0
            }),
            ("rotation_overlap_elapsed_ms", |e| {
                e.rotation_overlap_elapsed_ms = 1
            }),
            ("rotation_terminal_phase", |e| {
                e.rotation_terminal_phase = "active".into()
            }),
            ("rotation_typed_deadline_cause_observed", |e| {
                e.rotation_typed_deadline_cause_observed = false
            }),
            ("rotation_dispatch", |e| e.rotation_dispatch_after += 1),
            ("rotation_recovery_echo", |e| {
                e.rotation_recovery_echo = false
            }),
            ("rotation_recovery_epoch_advanced", |e| {
                e.rotation_recovery_epoch_advanced = false
            }),
        ];
        for (_, mutate) in cases {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            let diagnostic = assert_failed(validate_timing_boundary_evidence(&evidence));
            assert!(!diagnostic.is_empty());
        }
    }

    #[test]
    fn timing_validator_accepts_complete_evidence() {
        validate_timing_boundary_evidence(&valid_evidence())
            .expect("complete timing-boundary evidence is valid");
    }

    #[test]
    fn every_timing_condition_names_its_rejection() {
        const SAFE_WAIT: &str = "for the safe lease deadline";
        const PARTITION_ELAPSED: &str = "inconsistent with the safe-deadline wait";
        const WITHDRAWN: &str = "did not withdraw readiness and owner";
        const RECOVERY: &str = "higher-epoch fresh recovery canary";
        const ROTATION_PHASE: &str = "not sampled in a valid phase";
        type Case = (&'static str, &'static str, fn(&mut TimingBoundaryEvidence));
        let cases: &[Case] = &[
            ("relay_count", "expected three relays", |e| {
                e.relay_count = 2
            }),
            (
                "authorization_probe_elapsed_ms",
                "exceeded the bounded grant window",
                |e| e.authorization_probe_elapsed_ms = 6_001,
            ),
            (
                "authorization_result_delay_injected",
                "scoped real-Redis result delay",
                |e| e.authorization_result_delay_injected = false,
            ),
            (
                "authorization_owner_remaining_ms",
                "still-usable owner lease sample",
                |e| e.authorization_owner_remaining_ms = 5_000,
            ),
            (
                "authorization_expired_before_owner_safe_deadline",
                "not observed before the owner safe deadline",
                |e| e.authorization_expired_before_owner_safe_deadline = false,
            ),
            (
                "authorization_dispatch",
                "paused authorization probe advanced",
                |e| e.authorization_dispatch_after += 1,
            ),
            (
                "lease_remaining_below_margin",
                "began without a usable owner lease sample",
                |e| e.lease_remaining_before_partition_ms = 5_000,
            ),
            (
                "lease_remaining_above_ttl",
                "exceeded the configured",
                |e| e.lease_remaining_before_partition_ms = 31_001,
            ),
            ("lease_safe_deadline_wait_low", SAFE_WAIT, |e| {
                e.lease_safe_deadline_wait_ms = 3_499
            }),
            ("lease_safe_deadline_wait_high", SAFE_WAIT, |e| {
                e.lease_safe_deadline_wait_ms = 7_501
            }),
            (
                "lease_partition_elapsed_below_wait",
                PARTITION_ELAPSED,
                |e| e.lease_partition_elapsed_ms = 5_499,
            ),
            (
                "lease_partition_elapsed_above_lease",
                PARTITION_ELAPSED,
                |e| e.lease_partition_elapsed_ms = 12_001,
            ),
            ("lease_owner_withdrawn_after_expiry", WITHDRAWN, |e| {
                e.lease_owner_withdrawn_after_expiry = false
            }),
            ("lease_readiness_withdrawn", WITHDRAWN, |e| {
                e.lease_readiness_withdrawn = false
            }),
            ("lease_dispatch", "post-deadline probe advanced", |e| {
                e.lease_dispatch_after += 1
            }),
            ("lease_recovery_epoch_advanced", RECOVERY, |e| {
                e.lease_recovery_epoch_advanced = false
            }),
            ("lease_recovery_echo", RECOVERY, |e| {
                e.lease_recovery_echo = false
            }),
            ("rotation_phase", ROTATION_PHASE, |e| {
                e.rotation_phase = "active".into()
            }),
            ("rotation_candidate_generation", ROTATION_PHASE, |e| {
                e.rotation_candidate_generation = 0
            }),
            (
                "rotation_overlap_elapsed_ms",
                "exact configured overlap window",
                |e| e.rotation_overlap_elapsed_ms = 1_999,
            ),
            ("rotation_terminal_phase", "typed terminal phase", |e| {
                e.rotation_terminal_phase = "active".into()
            }),
            (
                "rotation_dispatch",
                "expired rotation candidate advanced",
                |e| e.rotation_dispatch_after += 1,
            ),
            ("rotation_recovery_epoch_advanced", RECOVERY, |e| {
                e.rotation_recovery_epoch_advanced = false
            }),
            ("rotation_recovery_echo", RECOVERY, |e| {
                e.rotation_recovery_echo = false
            }),
            (
                "authorization_typed_expiry_cause_observed",
                "authorization invalidation cause",
                |e| e.authorization_typed_expiry_cause_observed = false,
            ),
            (
                "rotation_typed_deadline_cause_observed",
                "rotation RecoveryReason::Deadline",
                |e| e.rotation_typed_deadline_cause_observed = false,
            ),
        ];
        for &(name, fragment, mutate) in cases {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            let diagnostic = assert_failed(validate_timing_boundary_evidence(&evidence));
            assert!(
                diagnostic.contains(fragment),
                "{name}: expected {fragment:?} in diagnostic {diagnostic}"
            );
        }
    }
}

/// Run the bounded real timing-boundary fixture.
///
/// The Redis proxy is installed before the production clusters start so both
/// stages use the same real Redis authority.  Authorization and lease timing
/// run against a normal-policy cluster; rotation runs against a second,
/// bounded cluster lifecycle whose relay policy is the same 3/1/2 policy
/// requested by its client.  Only the lease phase pauses the proxy.
pub async fn verify() -> Result<TimingBoundaryEvidence> {
    let base_options = HarnessOptions::from_env()?;
    let upstream_url =
        base_options
            .redis_url
            .clone()
            .ok_or_else(|| HarnessError::MissingRedisUrl {
                env_var: "TEST_REDIS_URL",
                guidance: "the timing-boundary gate requires TEST_REDIS_URL for its Redis proxy"
                    .to_owned(),
            })?;
    let target = super::redis_target_address(&upstream_url)?;
    let redis_proxy = TcpProxy::bind(target, ProxyConfig::default()).await?;
    let proxy_url = format!("redis://{}", redis_proxy.local_addr());
    let normal_options = base_options
        .clone()
        .redis_url(proxy_url.clone())
        .namespace_prefix("m7-timing-boundaries-normal")
        .rotation(NORMAL_ROTATION)
        .shared_device_uuid(true);
    let mut normal_harness =
        match timeout(super::STARTUP_TIMEOUT, Harness::start(normal_options)).await {
            Ok(Ok(harness)) => harness,
            Ok(Err(error)) => {
                let _ = redis_proxy.shutdown().await;
                return Err(error);
            }
            Err(_) => {
                let _ = redis_proxy.shutdown().await;
                return Err(HarnessError::Timeout(
                    "timing-boundary harness startup timed out".into(),
                ));
            }
        };
    let real_catalog = match normal_harness.production_catalog() {
        Ok(catalog) => Arc::new(catalog) as SharedCatalog,
        Err(error) => {
            let harness_cleanup = normal_harness.shutdown().await;
            let proxy_cleanup = shutdown_timing_proxy(redis_proxy).await;
            return Err(with_cleanup_failures(
                error,
                harness_cleanup
                    .err()
                    .into_iter()
                    .chain(proxy_cleanup.err())
                    .map(|cleanup| cleanup.to_string())
                    .collect(),
            ));
        }
    };
    let authorization_gate = AuthorizationDelayGate::default();
    let gated_catalog = Arc::new(AuthorizationDelayCatalog::new(
        real_catalog,
        authorization_gate.clone(),
    )) as SharedCatalog;
    let mut normal_cluster =
        match ProductionCluster::start_with_catalog(&mut normal_harness, gated_catalog).await {
            Ok(cluster) => cluster,
            Err(error) => {
                let harness_cleanup = normal_harness.shutdown().await;
                let proxy_cleanup = shutdown_timing_proxy(redis_proxy).await;
                let failures = harness_cleanup
                    .err()
                    .into_iter()
                    .map(|cleanup| cleanup.to_string())
                    .chain(proxy_cleanup.err().map(|cleanup| cleanup.to_string()))
                    .collect();
                return Err(with_cleanup_failures(error, failures));
            }
        };
    // Do not wrap this stage in an outer timeout.  The lease phase owns a
    // paused Redis proxy and has an explicit cleanup epilogue; cancelling the
    // future here would drop that epilogue before the proxy and client pair
    // are restored.  Every inner operation has its own deadline.
    let normal_scenario = run_normal(
        &mut normal_cluster,
        &normal_harness,
        &redis_proxy,
        &authorization_gate,
    )
    .await;
    let normal_cleanup =
        cleanup_timing_stage(normal_cluster, normal_harness, "timing normal").await;
    let normal = match (normal_scenario, normal_cleanup) {
        (Ok(evidence), Ok(())) => evidence,
        (Err(primary), Ok(())) => {
            let proxy_cleanup = shutdown_timing_proxy(redis_proxy).await;
            return Err(with_cleanup_failures(
                primary,
                proxy_cleanup
                    .err()
                    .into_iter()
                    .map(|e| e.to_string())
                    .collect(),
            ));
        }
        (Ok(_), Err(cleanup)) => {
            let proxy_cleanup = shutdown_timing_proxy(redis_proxy).await;
            return Err(with_cleanup_failures(
                cleanup,
                proxy_cleanup
                    .err()
                    .into_iter()
                    .map(|e| e.to_string())
                    .collect(),
            ));
        }
        (Err(primary), Err(cleanup)) => {
            let proxy_cleanup = shutdown_timing_proxy(redis_proxy).await;
            return Err(with_cleanup_failures(
                primary,
                std::iter::once(cleanup.to_string())
                    .chain(proxy_cleanup.err().map(|e| e.to_string()))
                    .collect(),
            ));
        }
    };

    // A client request cannot demonstrate the relay's overlap deadline when
    // the server has advertised the ordinary 300/10/30 policy.  Start a
    // fresh, isolated cluster with the short policy on both sides, then tear
    // it down before releasing the shared Redis proxy.
    let rotation_options = base_options
        .redis_url(proxy_url)
        .namespace_prefix("m7-timing-boundaries-rotation")
        .rotation(ROTATION)
        .shared_device_uuid(true);
    let mut rotation_harness =
        match timeout(super::STARTUP_TIMEOUT, Harness::start(rotation_options)).await {
            Ok(Ok(harness)) => harness,
            Ok(Err(error)) => {
                let proxy_cleanup = shutdown_timing_proxy(redis_proxy).await;
                return Err(with_cleanup_failures(
                    error,
                    proxy_cleanup
                        .err()
                        .into_iter()
                        .map(|e| e.to_string())
                        .collect(),
                ));
            }
            Err(_) => {
                let primary =
                    HarnessError::Timeout("timing rotation harness startup timed out".into());
                let proxy_cleanup = shutdown_timing_proxy(redis_proxy).await;
                return Err(with_cleanup_failures(
                    primary,
                    proxy_cleanup
                        .err()
                        .into_iter()
                        .map(|e| e.to_string())
                        .collect(),
                ));
            }
        };
    let mut rotation_cluster = match ProductionCluster::start(&mut rotation_harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let harness_cleanup = rotation_harness.shutdown().await;
            let proxy_cleanup = shutdown_timing_proxy(redis_proxy).await;
            let mut failures = Vec::new();
            if let Err(cleanup) = harness_cleanup {
                failures.push(cleanup.to_string());
            }
            if let Err(cleanup) = proxy_cleanup {
                failures.push(cleanup.to_string());
            }
            return Err(with_cleanup_failures(error, failures));
        }
    };
    // As above, retain the rotation proxy resume/join epilogue on all paths
    // rather than allowing a stage-level cancellation to drop it.
    let rotation_scenario = run_rotation_stage(&mut rotation_cluster, &rotation_harness).await;
    let rotation_cleanup =
        cleanup_timing_stage(rotation_cluster, rotation_harness, "timing rotation").await;
    let proxy_cleanup = shutdown_timing_proxy(redis_proxy).await;
    match (rotation_scenario, rotation_cleanup, proxy_cleanup) {
        (Ok(rotation), Ok(()), Ok(())) => {
            let evidence = combine_timing_evidence(normal, rotation);
            validate_timing_boundary_evidence(&evidence)?;
            Ok(evidence)
        }
        (Err(primary), cleanup, proxy) => {
            let failures = cleanup
                .err()
                .into_iter()
                .map(|error| error.to_string())
                .chain(proxy.err().map(|error| error.to_string()))
                .collect();
            Err(with_cleanup_failures(primary, failures))
        }
        (Ok(_), Err(cleanup), proxy) => {
            let failures: Vec<String> = std::iter::once(cleanup.to_string())
                .chain(proxy.err().map(|error| error.to_string()))
                .collect();
            Err(HarnessError::Process(format!(
                "timing rotation succeeded but cleanup failed: {}",
                failures.join("; ")
            )))
        }
        (Ok(_), Ok(()), Err(proxy)) => Err(proxy),
    }
}

struct NormalTimingEvidence {
    relay_count: usize,
    authorization: AuthorizationEvidence,
    lease: LeaseEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthorizationScope {
    tenant_id: Uuid,
    principal_id: Uuid,
    device_id: Uuid,
    service_id: Uuid,
}

struct AuthorizationDelayState {
    scope: Mutex<Option<AuthorizationScope>>,
    armed: AtomicBool,
    entered: AtomicBool,
    released: AtomicBool,
    matching_calls: AtomicU64,
    held_calls: AtomicU64,
    entered_notify: Notify,
    release_notify: Notify,
}

#[derive(Clone)]
struct AuthorizationDelayGate {
    state: Arc<AuthorizationDelayState>,
}

impl Default for AuthorizationDelayGate {
    fn default() -> Self {
        Self {
            state: Arc::new(AuthorizationDelayState {
                scope: Mutex::new(None),
                armed: AtomicBool::new(false),
                entered: AtomicBool::new(false),
                released: AtomicBool::new(false),
                matching_calls: AtomicU64::new(0),
                held_calls: AtomicU64::new(0),
                entered_notify: Notify::new(),
                release_notify: Notify::new(),
            }),
        }
    }
}

impl AuthorizationDelayGate {
    fn arm(&self, scope: AuthorizationScope) -> Result<()> {
        let mut current = self.state.scope.lock().map_err(|_| {
            HarnessError::Process("timing authorization gate scope lock poisoned".into())
        })?;
        *current = Some(scope);
        self.state.armed.store(true, Ordering::Release);
        self.state.entered.store(false, Ordering::Release);
        self.state.released.store(false, Ordering::Release);
        self.state.matching_calls.store(0, Ordering::Release);
        self.state.held_calls.store(0, Ordering::Release);
        Ok(())
    }

    fn matches(&self, scope: AuthorizationScope) -> bool {
        // Before arming, scope is None. After claiming the hold there is a
        // small interval before entered is set; scope must still match then
        // so a concurrent second call cannot bypass ambiguity detection.
        if self.state.released.load(Ordering::Acquire) {
            return false;
        }
        self.state
            .scope
            .lock()
            .map(|current| current.as_ref() == Some(&scope))
            .unwrap_or(false)
    }

    fn record_matching_call(&self) -> u64 {
        self.state.matching_calls.fetch_add(1, Ordering::AcqRel) + 1
    }

    fn claim_hold(&self) -> bool {
        self.state.armed.swap(false, Ordering::AcqRel)
    }

    fn mark_held(&self) {
        self.state.held_calls.fetch_add(1, Ordering::AcqRel);
        self.state.entered.store(true, Ordering::Release);
        self.state.entered_notify.notify_waiters();
    }

    fn release(&self) {
        self.state.released.store(true, Ordering::Release);
        self.state.release_notify.notify_waiters();
    }

    async fn wait_for_hit(&self, budget: Duration) -> Result<()> {
        let deadline = Instant::now() + budget;
        loop {
            if self.state.entered.load(Ordering::Acquire) {
                return Ok(());
            }
            let remaining = timing_remaining(deadline, "authorization result gate")?;
            let notified = self.state.entered_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state.entered.load(Ordering::Acquire) {
                return Ok(());
            }
            timeout(remaining, notified).await.map_err(|_| {
                HarnessError::Timeout("authorization result gate was not reached".into())
            })?;
        }
    }

    async fn wait_for_release(&self) -> std::result::Result<(), CatalogError> {
        let deadline = Instant::now() + PHASE_TIMEOUT;
        loop {
            if self.state.released.load(Ordering::Acquire) {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(CatalogError::Conflict(
                    "timing authorization result gate release timed out",
                ));
            }
            let notified = self.state.release_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state.released.load(Ordering::Acquire) {
                return Ok(());
            }
            timeout(remaining, notified).await.map_err(|_| {
                CatalogError::Conflict("timing authorization result gate release timed out")
            })?;
        }
    }

    fn exactly_one_hold(&self) -> bool {
        self.state.matching_calls.load(Ordering::Acquire) == 1
            && self.state.held_calls.load(Ordering::Acquire) == 1
            && self.state.released.load(Ordering::Acquire)
    }
}

/// Delegates every catalog operation to the real Redis catalog.  Only one
/// scope-matched successful `authorize` result is held after Redis returns;
/// current-owner, lease renewal and identity reads remain live authority
/// calls.  This is a timing fixture, never a production timeout change.
struct AuthorizationDelayCatalog {
    inner: SharedCatalog,
    gate: AuthorizationDelayGate,
}

impl AuthorizationDelayCatalog {
    fn new(inner: SharedCatalog, gate: AuthorizationDelayGate) -> Self {
        Self { inner, gate }
    }
}

#[async_trait]
impl Catalog for AuthorizationDelayCatalog {
    async fn resolve_device(
        &self,
        spki_fingerprint: &str,
        at: DateTime<Utc>,
    ) -> std::result::Result<Option<DeviceIdentity>, CatalogError> {
        self.inner.resolve_device(spki_fingerprint, at).await
    }

    async fn resolve_consumer(
        &self,
        issuer: &str,
        subject: &str,
        tenant_id: Option<Uuid>,
    ) -> std::result::Result<Option<AuthenticatedConsumer>, CatalogError> {
        self.inner
            .resolve_consumer(issuer, subject, tenant_id)
            .await
    }

    async fn authorize(
        &self,
        principal: &AuthenticatedConsumer,
        device_id: Uuid,
        service_id: Uuid,
        read_started_at: DateTime<Utc>,
        at: DateTime<Utc>,
    ) -> std::result::Result<Option<GrantSnapshot>, CatalogError> {
        let result = self
            .inner
            .authorize(principal, device_id, service_id, read_started_at, at)
            .await?;
        if result.is_some()
            && self.gate.matches(AuthorizationScope {
                tenant_id: principal.tenant_id,
                principal_id: principal.principal_id,
                device_id,
                service_id,
            })
        {
            let matching_calls = self.gate.record_matching_call();
            if matching_calls != 1 || !self.gate.claim_hold() {
                return Err(CatalogError::Conflict(
                    "timing authorization gate saw an ambiguous matching call",
                ));
            }
            self.gate.mark_held();
            self.gate.wait_for_release().await?;
        }
        Ok(result)
    }

    async fn list_devices_filtered(
        &self,
        principal: &AuthenticatedConsumer,
        filter: &DeviceListFilter,
        at: DateTime<Utc>,
    ) -> std::result::Result<Vec<DeviceSummary>, CatalogError> {
        self.inner
            .list_devices_filtered(principal, filter, at)
            .await
    }

    async fn upsert_grant(
        &self,
        spec: &GrantSpec,
    ) -> std::result::Result<GrantSnapshot, CatalogError> {
        self.inner.upsert_grant(spec).await
    }

    async fn revoke_grant(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        device_id: Uuid,
        service_id: Uuid,
        at: DateTime<Utc>,
    ) -> std::result::Result<u64, CatalogError> {
        self.inner
            .revoke_grant(tenant_id, principal_id, device_id, service_id, at)
            .await
    }

    async fn revoke_device(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        at: DateTime<Utc>,
    ) -> std::result::Result<u64, CatalogError> {
        self.inner.revoke_device(tenant_id, device_id, at).await
    }

    async fn revoke_credential(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        credential_id: Uuid,
        at: DateTime<Utc>,
    ) -> std::result::Result<u64, CatalogError> {
        self.inner
            .revoke_credential(tenant_id, device_id, credential_id, at)
            .await
    }

    async fn seed_fixture(
        &self,
        fixture: &CatalogFixture,
    ) -> std::result::Result<(), CatalogError> {
        self.inner.seed_fixture(fixture).await
    }

    async fn claim_owner(
        &self,
        request: &OwnerClaimRequest,
    ) -> std::result::Result<OwnerClaim, CatalogError> {
        self.inner.claim_owner(request).await
    }

    async fn renew_owner(
        &self,
        token: &OwnerToken,
        lease_expires_at: DateTime<Utc>,
    ) -> std::result::Result<bool, CatalogError> {
        self.inner.renew_owner(token, lease_expires_at).await
    }

    async fn release_owner(&self, token: &OwnerToken) -> std::result::Result<bool, CatalogError> {
        self.inner.release_owner(token).await
    }

    async fn current_owner(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        at: DateTime<Utc>,
    ) -> std::result::Result<Option<OwnerClaim>, CatalogError> {
        self.inner.current_owner(tenant_id, device_id, at).await
    }

    async fn issue_attachment_ticket(
        &self,
        request: &AttachmentTicketIssueRequest,
    ) -> std::result::Result<AttachmentTicket, CatalogError> {
        self.inner.issue_attachment_ticket(request).await
    }

    async fn consume_attachment_ticket(
        &self,
        request: &AttachmentTicketConsumeRequest,
    ) -> std::result::Result<ConsumedAttachmentTicket, CatalogError> {
        self.inner.consume_attachment_ticket(request).await
    }

    async fn read_signed_membership(
        &self,
    ) -> std::result::Result<Option<SignedMembershipRecord>, CatalogError> {
        self.inner.read_signed_membership().await
    }

    async fn read_signed_memberships(
        &self,
    ) -> std::result::Result<Vec<SignedMembershipRecord>, CatalogError> {
        self.inner.read_signed_memberships().await
    }
}

async fn run_normal(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    redis_proxy: &ProxyHandle,
    authorization_gate: &AuthorizationDelayGate,
) -> Result<NormalTimingEvidence> {
    if harness.rotation_config() != NORMAL_ROTATION {
        return Err(HarnessError::Process(format!(
            "timing normal stage relay policy was not the expected 300/10/30 policy: {:?}",
            harness.rotation_config()
        )));
    }
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(format!(
            "timing-boundary gate started {} relays, expected three",
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
            "timing-boundary gate started with {ready}/3 relays Ready"
        )));
    }
    let authorization = run_authorization_expiry(cluster, harness, authorization_gate).await?;
    let lease = run_lease_withdrawal(cluster, harness, redis_proxy).await?;
    Ok(NormalTimingEvidence {
        relay_count: cluster.relays.len(),
        authorization,
        lease,
    })
}

async fn run_rotation_stage(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
) -> Result<RotationEvidence> {
    if harness.rotation_config() != ROTATION {
        return Err(HarnessError::Process(format!(
            "timing rotation stage relay policy was not the expected 3/1/2 policy: {:?}",
            harness.rotation_config()
        )));
    }
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(format!(
            "timing rotation stage started {} relays, expected three",
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
            "timing rotation stage started with {ready}/3 relays Ready"
        )));
    }
    run_rotation_overlap(cluster, harness).await
}

fn combine_timing_evidence(
    normal: NormalTimingEvidence,
    rotation: RotationEvidence,
) -> TimingBoundaryEvidence {
    TimingBoundaryEvidence {
        relay_count: normal.relay_count,
        authorization_probe_elapsed_ms: normal.authorization.probe_elapsed_ms,
        authorization_result_delay_injected: normal.authorization.result_delay_injected,
        authorization_owner_remaining_ms: normal.authorization.owner_remaining_ms,
        authorization_expired_before_owner_safe_deadline: normal
            .authorization
            .expired_before_owner_safe_deadline,
        authorization_typed_expiry_cause_observed: normal.authorization.typed_expiry_cause_observed,
        authorization_dispatch_before: normal.authorization.dispatch_before,
        authorization_dispatch_after: normal.authorization.dispatch_after,
        lease_partition_elapsed_ms: normal.lease.partition_elapsed_ms,
        lease_remaining_before_partition_ms: normal.lease.remaining_before_partition_ms,
        lease_safe_deadline_wait_ms: normal.lease.safe_deadline_wait_ms,
        lease_owner_withdrawn_after_expiry: normal.lease.owner_withdrawn_after_expiry,
        lease_readiness_withdrawn: normal.lease.readiness_withdrawn,
        lease_dispatch_before: normal.lease.dispatch_before,
        lease_dispatch_after: normal.lease.dispatch_after,
        lease_recovery_epoch_advanced: normal.lease.recovery_epoch_advanced,
        lease_recovery_echo: normal.lease.recovery_echo,
        rotation_phase: rotation.phase,
        rotation_candidate_generation: rotation.candidate_generation,
        rotation_overlap_elapsed_ms: rotation.overlap_elapsed_ms,
        rotation_terminal_phase: rotation.terminal_phase,
        rotation_typed_deadline_cause_observed: rotation.typed_deadline_cause_observed,
        rotation_dispatch_before: rotation.dispatch_before,
        rotation_dispatch_after: rotation.dispatch_after,
        rotation_recovery_epoch_advanced: rotation.recovery_epoch_advanced,
        rotation_recovery_echo: rotation.recovery_echo,
    }
}

async fn cleanup_timing_stage(
    cluster: ProductionCluster,
    harness: RunningHarness,
    label: &str,
) -> Result<()> {
    let cluster_cleanup = cluster.shutdown().await;
    let harness_cleanup = harness.shutdown().await;
    match (cluster_cleanup, harness_cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(cluster), Err(harness)) => Err(HarnessError::Process(format!(
            "{label} cleanup failed: relay={cluster}; catalog={harness}"
        ))),
    }
}

async fn shutdown_timing_proxy(proxy: ProxyHandle) -> Result<()> {
    match timeout(super::CLEANUP_TIMEOUT, proxy.shutdown()).await {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "timing-boundary Redis proxy cleanup timed out".into(),
        )),
    }
}

/// Close a CLI consumer stream and reap its managed child on every setup
/// failure.  `ManagedProcess::Drop` only starts a kill and aborts output
/// drains; the timing fixture needs the bounded join so a failed phase cannot
/// leak a paused or still-writing child into the next stage.
async fn cleanup_cli_pair(
    mut stream: ConsumerStream,
    process: ManagedProcess,
    label: &str,
) -> Vec<String> {
    let mut failures = Vec::new();
    if let Err(error) = stream.close().await {
        failures.push(format!("closing {label} stream: {error}"));
    }
    match timeout(
        super::CLEANUP_TIMEOUT,
        process.shutdown(Duration::from_secs(5)),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => failures.push(format!("joining {label} CLI: {error}")),
        Err(_) => failures.push(format!("joining {label} CLI timed out")),
    }
    failures
}

/// Close a consumer stream and join a library connector while preserving both
/// cleanup errors.  This helper is used for early recovery-client failures,
/// where an ordinary `?` would otherwise drop the connector without awaiting
/// its supervisor.
async fn cleanup_connector_stream(
    mut stream: ConsumerStream,
    client: &ConnectionHandle,
    label: &str,
) -> Vec<String> {
    let mut failures = Vec::new();
    if let Err(error) = stream.close().await {
        failures.push(format!("closing {label} stream: {error}"));
    }
    if let Err(error) = super::join_connector_with_cleanup_timeout(client, label).await {
        failures.push(error.to_string());
    }
    failures
}

async fn cleanup_connector(client: &ConnectionHandle, label: &str) -> Vec<String> {
    match super::join_connector_with_cleanup_timeout(client, label).await {
        Ok(()) => Vec::new(),
        Err(error) => vec![error.to_string()],
    }
}

fn is_expected_rotation_deadline_stop(
    error: &tunnel_client::ClientError,
    readiness: &tunnel_client::Readiness,
) -> bool {
    matches!(
        error,
        tunnel_client::ClientError::Transport {
            scope: "control read",
            ..
        }
    ) && matches!(
        readiness,
        tunnel_client::Readiness::Closed { reason } if reason == "control read failed"
    )
}

struct AuthorizationEvidence {
    probe_elapsed_ms: u64,
    result_delay_injected: bool,
    owner_remaining_ms: u64,
    expired_before_owner_safe_deadline: bool,
    typed_expiry_cause_observed: bool,
    dispatch_before: u64,
    dispatch_after: u64,
}

struct AuthorizationPauseObservation {
    probe: super::ProcessPauseProbeOutcome,
    probe_elapsed_ms: u64,
    probe_response_elapsed_ms: u64,
    result_delay_injected: bool,
    owner_remaining_ms: u64,
    expired_before_owner_safe_deadline: bool,
    typed_expiry_cause_observed: bool,
    dispatch_after: u64,
}

struct AuthorizationChallengeBarrier {
    challenge_deadline_ms: u64,
    admission_deadline_ms: u64,
}

fn timing_remaining(deadline: Instant, label: &str) -> Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(HarnessError::Timeout(format!(
            "timing {label} exceeded its bounded wait"
        )));
    }
    Ok(remaining)
}

async fn timing_snapshot(
    relay: &super::ProductionRelay,
    deadline: Instant,
    label: &str,
) -> Result<RelaySnapshot> {
    let remaining = timing_remaining(deadline, label)?;
    timeout(remaining.min(Duration::from_secs(1)), relay.snapshot())
        .await
        .map_err(|_| HarnessError::Timeout(format!("reading {label} timing snapshot timed out")))?
}

async fn timing_poll_sleep(deadline: Instant, label: &str) -> Result<()> {
    let remaining = timing_remaining(deadline, label)?;
    sleep(POLL_INTERVAL.min(remaining)).await;
    Ok(())
}

fn authorization_stream<'a>(
    snapshot: &'a RelaySnapshot,
    session_id: &str,
    epoch: u64,
    stream_id: u64,
) -> Option<&'a tunnel_relay::RelayStreamSnapshot> {
    snapshot
        .sessions
        .iter()
        .find(|session| session.session_id == session_id && session.epoch == epoch)
        .and_then(|session| {
            session
                .streams
                .iter()
                .find(|stream| stream.stream_id == stream_id)
        })
}

async fn wait_for_authorization_challenge(
    relay: &super::ProductionRelay,
    session_id: &str,
    epoch: u64,
    stream_id: u64,
    budget: Duration,
) -> Result<AuthorizationChallengeBarrier> {
    let deadline = Instant::now() + budget;
    loop {
        let snapshot = timing_snapshot(relay, deadline, "authorization barrier").await?;
        if let Some(stream) = authorization_stream(&snapshot, session_id, epoch, stream_id)
            && stream.authorization_in_flight
        {
            let started = stream.authorization_started_at_ms.ok_or_else(|| {
                HarnessError::Unsupported(
                    "authorization challenge snapshot omitted its start time".into(),
                )
            })?;
            let challenge_deadline_ms = stream.authorization_deadline_ms.ok_or_else(|| {
                HarnessError::Unsupported(
                    "authorization challenge snapshot omitted its deadline".into(),
                )
            })?;
            let admission_deadline_ms =
                stream.authorization_admission_deadline_ms.ok_or_else(|| {
                    HarnessError::Unsupported(
                        "authorization challenge snapshot omitted the prior admission deadline"
                            .into(),
                    )
                })?;
            let expected = u64::try_from(RELAY_CHALLENGE_INTERVAL.as_millis()).unwrap_or(u64::MAX);
            if challenge_deadline_ms.saturating_sub(started) != expected {
                return Err(HarnessError::Process(format!(
                    "timing authorization challenge window was not the configured {expected}ms"
                )));
            }
            if challenge_deadline_ms <= started {
                return Err(HarnessError::Process(
                    "timing authorization challenge deadline was not after its start".into(),
                ));
            }
            return Ok(AuthorizationChallengeBarrier {
                challenge_deadline_ms,
                admission_deadline_ms,
            });
        }
        timing_poll_sleep(deadline, "authorization barrier").await?;
    }
}

async fn wait_for_authorization_deadline(
    relay: &super::ProductionRelay,
    session: (&str, u64),
    stream_id: u64,
    target_ms: u64,
    barrier: &AuthorizationChallengeBarrier,
    budget: Duration,
    label: &str,
) -> Result<()> {
    let deadline = Instant::now() + budget;
    let (session_id, epoch) = session;
    let challenge_deadline_ms = barrier.challenge_deadline_ms;
    loop {
        let snapshot = timing_snapshot(relay, deadline, label).await?;
        let stream =
            authorization_stream(&snapshot, session_id, epoch, stream_id).ok_or_else(|| {
                HarnessError::Process(format!(
                    "timing authorization stream disappeared before {label}"
                ))
            })?;
        if !stream.authorization_in_flight {
            return Err(HarnessError::Process(format!(
                "timing authorization challenge left flight before {label}"
            )));
        }
        if snapshot.monotonic_now_ms >= target_ms {
            return Ok(());
        }
        if target_ms != challenge_deadline_ms && snapshot.monotonic_now_ms >= challenge_deadline_ms
        {
            return Err(HarnessError::Timeout(
                "timing old authorization admission did not expire before the challenge deadline"
                    .into(),
            ));
        }
        timing_poll_sleep(deadline, label).await?;
    }
}

async fn send_authorization_probe(stream: &mut ConsumerStream) -> Result<()> {
    let payload = b"m7-timing-auth-expired";
    if payload.len() > super::MAX_RECORD_BYTES {
        return Err(HarnessError::InvalidInput(
            "timing authorization probe exceeded its bound".into(),
        ));
    }
    let length = u32::try_from(payload.len()).map_err(|_| {
        HarnessError::InvalidInput("timing authorization probe length overflow".into())
    })?;
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    timeout(
        super::PROCESS_PAUSE_EXCHANGE_TIMEOUT,
        stream.socket.send(Message::Binary(frame.into())),
    )
    .await
    .map_err(|_| HarnessError::Timeout("timing authorization probe send timed out".into()))?
    .map_err(|error| HarnessError::Http(format!("sending timing authorization probe: {error}")))
}

async fn read_authorization_probe(stream: &mut ConsumerStream) -> ProcessPauseProbeOutcome {
    let deadline = Instant::now() + super::PROCESS_PAUSE_EXCHANGE_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return ProcessPauseProbeOutcome::TimedOut;
        }
        let message = match timeout(remaining, stream.socket.next()).await {
            Err(_) => return ProcessPauseProbeOutcome::TimedOut,
            Ok(message) => message,
        };
        match message {
            Some(Ok(Message::Binary(_))) => return ProcessPauseProbeOutcome::EchoAfterSend,
            Some(Ok(Message::Close(_))) | None => {
                return ProcessPauseProbeOutcome::ClosedAfterSend;
            }
            Some(Ok(Message::Ping(bytes))) => {
                let pong_remaining = deadline.saturating_duration_since(Instant::now());
                if pong_remaining.is_zero()
                    || !matches!(
                        timeout(pong_remaining, stream.socket.send(Message::Pong(bytes))).await,
                        Ok(Ok(()))
                    )
                {
                    return ProcessPauseProbeOutcome::TransportAfterSend;
                }
            }
            Some(Ok(Message::Text(_))) => return ProcessPauseProbeOutcome::ProtocolAfterSend,
            Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
            Some(Err(_)) => return ProcessPauseProbeOutcome::TransportAfterSend,
        }
    }
}

async fn run_authorization_expiry(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    authorization_gate: &AuthorizationDelayGate,
) -> Result<AuthorizationEvidence> {
    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("timing auth device is missing".into()))?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("timing auth service is missing".into()))?;
    let principal = harness
        .topology
        .consumers_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("timing auth consumer is missing".into()))?;
    let canary = format!("m7-timing-auth:{}", device.id);
    let profile_directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    let mut profile = write_device_profile(
        profile_directory.path(),
        device.id,
        service_id,
        &canary,
        cluster.device_fanout.local_addr(),
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile.config.rotation = NORMAL_ROTATION;
    profile.config.validate().map_err(|error| {
        HarnessError::InvalidInput(format!("timing auth client config: {error}"))
    })?;
    let configured_grant_timeout = Duration::from_millis(profile.config.limits.grant_timeout_ms);
    if configured_grant_timeout != AUTHORIZATION_LIFETIME {
        return Err(HarnessError::InvalidInput(format!(
            "timing auth fixture expected the configured five-second grant timeout, observed {:?}",
            configured_grant_timeout
        )));
    }
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(90),
            ..OidcTokenOptions::default()
        },
    )?;
    let consumer_addr = cluster.relay("relay-c")?.consumer_addr()?;
    let (mut process, mut stream) = start_cli_smoke(
        harness,
        cluster.device_fanout.local_addr(),
        consumer_addr,
        &profile,
        &token,
        device.id,
        service_id,
    )
    .await?;
    if let Err(error) = stream
        .round_trip(b"m7-timing-auth-baseline", canary.as_bytes())
        .await
    {
        return Err(with_cleanup_failures(
            error,
            cleanup_cli_pair(stream, process, "timing auth baseline").await,
        ));
    }
    let owner_before = match current_owner(cluster, device.tenant_id, device.id).await {
        Ok(Some(owner)) => owner,
        Ok(None) => {
            return Err(with_cleanup_failures(
                HarnessError::Process("timing auth baseline did not retain an owner".into()),
                cleanup_cli_pair(stream, process, "timing auth baseline").await,
            ));
        }
        Err(error) => {
            return Err(with_cleanup_failures(
                error,
                cleanup_cli_pair(stream, process, "timing auth baseline").await,
            ));
        }
    };
    let owner_remaining_before_ms = match owner_remaining_ms(&owner_before, Utc::now()) {
        Ok(remaining) => remaining,
        Err(error) => {
            return Err(with_cleanup_failures(
                error,
                cleanup_cli_pair(stream, process, "timing auth baseline").await,
            ));
        }
    };
    if owner_remaining_before_ms
        <= u64::try_from(OWNER_LEASE_SAFETY_MARGIN.as_millis()).unwrap_or(u64::MAX)
    {
        return Err(with_cleanup_failures(
            HarnessError::Process(
                "timing auth baseline owner was already inside the safety margin".into(),
            ),
            cleanup_cli_pair(stream, process, "timing auth baseline").await,
        ));
    }
    let owner_relay = match cluster.relay(&owner_before.token.node_id) {
        Ok(relay) => relay,
        Err(error) => {
            return Err(with_cleanup_failures(
                error,
                cleanup_cli_pair(stream, process, "timing auth baseline").await,
            ));
        }
    };
    let baseline_snapshot = match owner_relay.snapshot().await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return Err(with_cleanup_failures(
                error,
                cleanup_cli_pair(stream, process, "timing auth baseline").await,
            ));
        }
    };
    let dispatch_before = baseline_snapshot.lifetime_application_dispatches;
    if dispatch_before == 0 {
        return Err(with_cleanup_failures(
            HarnessError::Process(
                "timing auth baseline did not advance a real dispatch counter".into(),
            ),
            cleanup_cli_pair(stream, process, "timing auth baseline").await,
        ));
    }
    let authorization_stream_id = match baseline_snapshot
        .sessions
        .iter()
        .find(|session| {
            session.session_id == owner_before.token.session_id
                && session.epoch == owner_before.token.epoch
        })
        .and_then(|session| {
            let mut streams = session.streams.iter().filter(|stream| !stream.terminal);
            let stream = streams.next()?;
            streams.next().is_none().then_some(stream.stream_id)
        }) {
        Some(stream_id) => stream_id,
        None => {
            return Err(with_cleanup_failures(
                HarnessError::Process(
                    "timing auth baseline did not expose exactly one owner stream".into(),
                ),
                cleanup_cli_pair(stream, process, "timing auth baseline stream").await,
            ));
        }
    };
    let mut pause_guard = match ProcessPauseGuard::new(&process) {
        Ok(guard) => guard,
        Err(error) => {
            return Err(with_cleanup_failures(
                error,
                cleanup_cli_pair(stream, process, "timing auth baseline").await,
            ));
        }
    };
    if let Err(error) = authorization_gate.arm(AuthorizationScope {
        tenant_id: principal.tenant_id,
        principal_id: principal.id,
        device_id: device.id,
        service_id,
    }) {
        drop(pause_guard);
        let cleanup_failures = cleanup_cli_pair(stream, process, "timing auth result gate").await;
        return Err(with_cleanup_failures(error, cleanup_failures));
    }
    // The real Redis authorize call completes first.  The fixture then holds
    // only that successful, scope-matched result while the client remains
    // running and emits its proactive challenge; owner and identity reads
    // remain live after the gate is released.
    if let Err(error) = authorization_gate.wait_for_hit(PHASE_TIMEOUT).await {
        authorization_gate.release();
        return Err(with_cleanup_failures(
            error,
            cleanup_cli_pair(stream, process, "timing auth result gate").await,
        ));
    }
    let challenge_barrier = match wait_for_authorization_challenge(
        owner_relay,
        &owner_before.token.session_id,
        owner_before.token.epoch,
        authorization_stream_id,
        PHASE_TIMEOUT,
    )
    .await
    {
        Ok(barrier) => barrier,
        Err(error) => {
            authorization_gate.release();
            let cleanup_failures = cleanup_cli_pair(stream, process, "timing auth barrier").await;
            return Err(with_cleanup_failures(error, cleanup_failures));
        }
    };
    if let Err(error) = pause_guard.pause(&mut process) {
        drop(pause_guard);
        authorization_gate.release();
        let cleanup_failures = cleanup_cli_pair(stream, process, "timing auth pause").await;
        return Err(with_cleanup_failures(error, cleanup_failures));
    }
    let pause_started = Instant::now();
    let observation = async {
        // Wait until the previous confirmed grant has expired while the
        // refresh challenge remains blocked in the relay. This prevents the
        // consumer probe from being dispatched under the old grant.
        wait_for_authorization_deadline(
            owner_relay,
            (&owner_before.token.session_id, owner_before.token.epoch),
            authorization_stream_id,
            challenge_barrier.admission_deadline_ms,
            &challenge_barrier,
            PHASE_TIMEOUT,
            "old authorization admission",
        )
        .await?;
        send_authorization_probe(&mut stream).await?;
        let probe_started = Instant::now();
        wait_for_authorization_deadline(
            owner_relay,
            (&owner_before.token.session_id, owner_before.token.epoch),
            authorization_stream_id,
            challenge_barrier.challenge_deadline_ms,
            &challenge_barrier,
            PHASE_TIMEOUT,
            "authorization challenge",
        )
        .await?;
        // Release only after the relay-local challenge deadline is observed.
        // The successful authorization came from real Redis; this bounded
        // fixture gate is the sole injected delay.
        authorization_gate.release();
        let probe = read_authorization_probe(&mut stream).await;
        // Capture the response boundary before any cleanup await.  Process
        // reaping and stream close are allowed to take their own bounded
        // cleanup budget and must not contaminate the auth-expiry sample.
        let probe_response_elapsed_ms =
            u64::try_from(probe_started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let probe_elapsed_ms =
            u64::try_from(pause_started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let owner_sample = current_owner(cluster, device.tenant_id, device.id).await?;
        let owner_remaining_ms = owner_sample
            .as_ref()
            .map(|owner| owner_remaining_ms(owner, Utc::now()))
            .transpose()?
            .unwrap_or_default();
        let expired_before_owner_safe_deadline = owner_sample.as_ref().is_some_and(|owner| {
            owner.token == owner_before.token
                && owner_remaining_ms
                    > u64::try_from(OWNER_LEASE_SAFETY_MARGIN.as_millis()).unwrap_or(u64::MAX)
        });
        let owner_snapshot = owner_relay.snapshot().await?;
        let matching_sessions = owner_snapshot
            .sessions
            .iter()
            .filter(|session| {
                session.session_id == owner_before.token.session_id
                    && session.epoch == owner_before.token.epoch
            })
            .collect::<Vec<_>>();
        let typed_expiry_cause_observed = matching_sessions.len() == 1
            && authorization_stream(
                &owner_snapshot,
                &owner_before.token.session_id,
                owner_before.token.epoch,
                authorization_stream_id,
            )
            .is_some_and(|stream| {
                stream.authorization_failure_code == Some("AUTHORIZATION_EXPIRED")
                    && stream.terminal
            });
        let dispatch_after = owner_snapshot.lifetime_application_dispatches;
        Ok::<_, HarnessError>(AuthorizationPauseObservation {
            probe,
            probe_elapsed_ms,
            probe_response_elapsed_ms,
            result_delay_injected: authorization_gate.exactly_one_hold(),
            owner_remaining_ms,
            expired_before_owner_safe_deadline,
            typed_expiry_cause_observed,
            dispatch_after,
        })
    }
    .await;
    // Every path through the paused observation releases SIGSTOP and joins
    // the real child before returning.  The guard's Drop is only a last-resort
    // CONT; it cannot reap the child or close the stream.
    let resume_result = pause_guard.resume(&mut process);
    authorization_gate.release();
    let stream_cleanup = stream.close().await;
    let process_cleanup = match timeout(
        super::CLEANUP_TIMEOUT,
        process.shutdown(Duration::from_secs(5)),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "joining timing auth CLI timed out".into(),
        )),
    };
    let mut cleanup_failures = Vec::new();
    if let Err(error) = resume_result {
        cleanup_failures.push(format!("resuming timing auth CLI: {error}"));
    }
    if let Err(error) = stream_cleanup {
        cleanup_failures.push(format!("closing timing auth stream: {error}"));
    }
    if let Err(error) = process_cleanup {
        cleanup_failures.push(format!("joining timing auth CLI: {error}"));
    }
    let observation = match observation {
        Ok(observation) => observation,
        Err(error) => {
            return Err(with_cleanup_failures(error, cleanup_failures));
        }
    };
    if !cleanup_failures.is_empty() {
        return Err(HarnessError::Process(format!(
            "timing auth observation cleanup failed: {}",
            cleanup_failures.join("; ")
        )));
    }
    if !observation.probe.is_fail_closed() {
        return Err(HarnessError::Process(format!(
            "timing auth probe returned {:?} instead of a bounded close",
            observation.probe
        )));
    }
    let probe_response_elapsed_ms = observation.probe_response_elapsed_ms;
    if probe_response_elapsed_ms
        > u64::try_from(AUTHORIZATION_LIFETIME.as_millis()).unwrap_or(u64::MAX)
    {
        return Err(HarnessError::Timeout(format!(
            "timing auth probe close exceeded its five-second grant window: {probe_response_elapsed_ms}ms"
        )));
    }
    wait_for_fanout_drained(&cluster.device_fanout, "timing authorization").await?;
    cluster
        .wait_for_no_owner(device.tenant_id, device.id)
        .await?;
    Ok(AuthorizationEvidence {
        probe_elapsed_ms: observation.probe_elapsed_ms,
        result_delay_injected: observation.result_delay_injected,
        owner_remaining_ms: observation.owner_remaining_ms,
        expired_before_owner_safe_deadline: observation.expired_before_owner_safe_deadline,
        typed_expiry_cause_observed: observation.typed_expiry_cause_observed,
        dispatch_before,
        dispatch_after: observation.dispatch_after,
    })
}

struct LeaseEvidence {
    partition_elapsed_ms: u64,
    remaining_before_partition_ms: u64,
    safe_deadline_wait_ms: u64,
    owner_withdrawn_after_expiry: bool,
    readiness_withdrawn: bool,
    dispatch_before: u64,
    dispatch_after: u64,
    recovery_epoch_advanced: bool,
    recovery_echo: bool,
}

struct LeasePartitionObservation {
    partition_elapsed_ms: u64,
    safe_deadline_wait_ms: u64,
    readiness_withdrawn: bool,
    dispatch_after: u64,
}

async fn run_lease_withdrawal(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    redis_proxy: &ProxyHandle,
) -> Result<LeaseEvidence> {
    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("timing lease device is missing".into()))?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("timing lease service is missing".into()))?;
    let canary = format!("m7-timing-lease:{}", device.id);
    let profile_directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    let mut profile = write_device_profile(
        profile_directory.path(),
        device.id,
        service_id,
        &canary,
        cluster.device_fanout.local_addr(),
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile.config.rotation = NORMAL_ROTATION;
    profile.config.validate().map_err(|error| {
        HarnessError::InvalidInput(format!("timing lease client config: {error}"))
    })?;
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(90),
            ..OidcTokenOptions::default()
        },
    )?;
    let consumer_addr = cluster.relay("relay-c")?.consumer_addr()?;
    let (client, mut stream) = start_cli_smoke(
        harness,
        cluster.device_fanout.local_addr(),
        consumer_addr,
        &profile,
        &token,
        device.id,
        service_id,
    )
    .await?;
    if let Err(error) = stream
        .round_trip(b"m7-timing-lease-baseline", canary.as_bytes())
        .await
    {
        return Err(with_cleanup_failures(
            error,
            cleanup_cli_pair(stream, client, "timing lease baseline").await,
        ));
    }
    let owner_before = match current_owner(cluster, device.tenant_id, device.id).await {
        Ok(Some(owner)) => owner,
        Ok(None) => {
            return Err(with_cleanup_failures(
                HarnessError::Process("timing lease baseline did not retain an owner".into()),
                cleanup_cli_pair(stream, client, "timing lease baseline").await,
            ));
        }
        Err(error) => {
            return Err(with_cleanup_failures(
                error,
                cleanup_cli_pair(stream, client, "timing lease baseline").await,
            ));
        }
    };
    let remaining_before_partition_ms = match owner_remaining_ms(&owner_before, Utc::now()) {
        Ok(remaining) => remaining,
        Err(error) => {
            return Err(with_cleanup_failures(
                error,
                cleanup_cli_pair(stream, client, "timing lease baseline").await,
            ));
        }
    };
    let owner_relay = match cluster.relay(&owner_before.token.node_id) {
        Ok(relay) => relay,
        Err(error) => {
            return Err(with_cleanup_failures(
                error,
                cleanup_cli_pair(stream, client, "timing lease baseline").await,
            ));
        }
    };
    let dispatch_before = match owner_relay.snapshot().await {
        Ok(snapshot) => snapshot.lifetime_application_dispatches,
        Err(error) => {
            return Err(with_cleanup_failures(
                error,
                cleanup_cli_pair(stream, client, "timing lease baseline").await,
            ));
        }
    };
    let safe_deadline = owner_before
        .lease_expires_at
        .signed_duration_since(Utc::now())
        .to_std()
        .unwrap_or_default()
        .saturating_sub(OWNER_LEASE_SAFETY_MARGIN);
    if safe_deadline.is_zero() {
        return Err(with_cleanup_failures(
            HarnessError::Process(
                "timing lease safe deadline was already expired at partition start".into(),
            ),
            cleanup_cli_pair(stream, client, "timing lease baseline").await,
        ));
    }
    let partition_started = Instant::now();
    if let Err(error) = redis_proxy.pause_all().await {
        return Err(with_cleanup_failures(
            error,
            cleanup_cli_pair(stream, client, "timing lease partition").await,
        ));
    }
    // Keep every fallible operation inside this future.  The Redis proxy is
    // resumed and the CLI pair is joined below even when readiness, probing,
    // or the lease snapshot fails while the partition is active.
    let partition_observation = async {
        let lease_wait_started = Instant::now();
        sleep(safe_deadline + OWNER_LEASE_OBSERVATION_GRACE).await;
        let safe_deadline_wait_ms =
            u64::try_from(lease_wait_started.elapsed().as_millis()).unwrap_or(u64::MAX);
        // The relay must stop readiness and dispatch by the safe deadline,
        // while Redis is still partitioned and the authoritative owner key
        // may remain present until its full observed expiry.
        let readiness_withdrawn = timeout(
            HEALTH_POLL_TIMEOUT,
            wait_for_public_unready(
                cluster.relay("relay-c")?.consumer_addr()?,
                &harness.pki.server_ca.certificate_der,
            ),
        )
        .await
        .map_err(|_| {
            HarnessError::Timeout("timing lease readiness did not withdraw by safe deadline".into())
        })??;
        let dispatch_probe = timeout(
            PHASE_TIMEOUT,
            stream.round_trip(b"m7-timing-lease-after-safe-deadline", canary.as_bytes()),
        )
        .await
        .map_err(|_| {
            HarnessError::Timeout("timing lease dispatch probe exceeded its deadline".into())
        })?;
        if dispatch_probe.is_ok() {
            return Err(HarnessError::Process(
                "timing lease dispatched a post-safe-deadline echo".into(),
            ));
        }
        if let Err(error) = &dispatch_probe
            && !is_expected_revocation_close(error)
        {
            return Err(HarnessError::Process(format!(
                "timing lease post-safe-deadline probe returned an unexpected error: {error}"
            )));
        }
        let dispatch_after = owner_relay
            .snapshot()
            .await?
            .lifetime_application_dispatches;
        let observed_expiry_wait = owner_before
            .lease_expires_at
            .signed_duration_since(Utc::now())
            .to_std()
            .unwrap_or_default();
        if !observed_expiry_wait.is_zero() {
            sleep(observed_expiry_wait + OWNER_LEASE_OBSERVATION_GRACE).await;
        }
        Ok::<_, HarnessError>(LeasePartitionObservation {
            partition_elapsed_ms: u64::try_from(partition_started.elapsed().as_millis())
                .unwrap_or(u64::MAX),
            safe_deadline_wait_ms,
            readiness_withdrawn,
            dispatch_after,
        })
    }
    .await;
    let resume_result = redis_proxy.resume_all().await;
    let stream_cleanup = stream.close().await;
    let client_cleanup = match timeout(
        super::CLEANUP_TIMEOUT,
        client.shutdown(Duration::from_secs(5)),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "joining timing lease CLI timed out".into(),
        )),
    };
    let mut cleanup_failures = Vec::new();
    if let Err(error) = resume_result {
        cleanup_failures.push(format!("resuming timing lease Redis proxy: {error}"));
    }
    if let Err(error) = stream_cleanup {
        cleanup_failures.push(format!("closing timing lease stream: {error}"));
    }
    if let Err(error) = client_cleanup {
        cleanup_failures.push(format!("joining timing lease CLI: {error}"));
    }
    let partition_observation = match partition_observation {
        Ok(observation) => observation,
        Err(error) => return Err(with_cleanup_failures(error, cleanup_failures)),
    };
    if !cleanup_failures.is_empty() {
        return Err(HarnessError::Process(format!(
            "timing lease partition cleanup failed: {}",
            cleanup_failures.join("; ")
        )));
    }
    let owner_withdrawn_after_expiry =
        wait_for_owner_absent(cluster, device.tenant_id, device.id, PHASE_TIMEOUT).await?;
    wait_for_fanout_drained(&cluster.device_fanout, "timing lease predecessor").await?;
    // Redis recovery can leave an individual relay's peer route stale for a
    // short interval after the predecessor owner has disappeared.  Do not
    // start the successor device connector until every actual fanout target
    // reports public readiness again; otherwise a deterministic target choice
    // can turn readiness lag into an opaque WebSocket handshake failure.
    let recovery_readiness_deadline = Instant::now() + PHASE_TIMEOUT;
    for relay in &cluster.relays {
        let consumer_addr = relay.consumer_addr()?;
        let remaining = timing_remaining(recovery_readiness_deadline, "timing lease readiness")?;
        timeout(
            remaining,
            super::wait_for_public_health_ready(
                consumer_addr,
                &harness.pki.server_ca.certificate_der,
            ),
        )
        .await
        .map_err(|_| {
            HarnessError::Timeout(format!(
                "timing lease relay {} public readiness did not recover",
                relay.node_id
            ))
        })??;
    }

    let mut fresh = timeout(
        super::STARTUP_TIMEOUT,
        tunnel_client::connect(ConnectOptions {
            config: profile.config.clone(),
            cancellation: CancellationToken::new(),
            profile: TransportProfile::M2,
        }),
    )
    .await
    .map_err(|_| HarnessError::Timeout("timing lease fresh client startup timed out".into()))?
    .map_err(|error| HarnessError::Process(format!("timing lease fresh client: {error}")))?;
    let fresh_readiness = match timeout(super::STARTUP_TIMEOUT, fresh.wait_ready()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(HarnessError::Process(format!(
            "timing lease fresh client readiness: {error}"
        ))),
        Err(_) => Err(HarnessError::Timeout(
            "timing lease fresh client readiness timed out".into(),
        )),
    };
    if let Err(error) = fresh_readiness {
        return Err(with_cleanup_failures(
            error,
            cleanup_connector(&fresh, "timing lease recovery").await,
        ));
    }
    let successor = match wait_for_higher_owner(
        cluster,
        device.tenant_id,
        device.id,
        owner_before.token.epoch,
        PHASE_TIMEOUT,
    )
    .await
    {
        Ok(owner) => owner,
        Err(error) => {
            return Err(with_cleanup_failures(
                error,
                cleanup_connector(&fresh, "timing lease recovery").await,
            ));
        }
    };
    let recovery_token = match harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(90),
            ..OidcTokenOptions::default()
        },
    ) {
        Ok(token) => token,
        Err(error) => {
            return Err(with_cleanup_failures(
                error,
                cleanup_connector(&fresh, "timing lease recovery").await,
            ));
        }
    };
    let mut recovery_stream = match open_consumer_stream(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &recovery_token,
        device.id,
        service_id,
    )
    .await
    {
        Ok(stream) => stream,
        Err(error) => {
            return Err(with_cleanup_failures(
                connect_failure_to_harness(error),
                cleanup_connector(&fresh, "timing lease recovery").await,
            ));
        }
    };
    if let Err(error) = recovery_stream
        .round_trip(b"m7-timing-lease-recovery", canary.as_bytes())
        .await
    {
        return Err(with_cleanup_failures(
            error,
            cleanup_connector_stream(recovery_stream, &fresh, "timing lease recovery").await,
        ));
    }
    let recovery_echo = true;
    if let Err(error) = recovery_stream.close().await {
        return Err(with_cleanup_failures(
            error,
            cleanup_connector(&fresh, "timing lease recovery").await,
        ));
    }
    super::join_connector_with_cleanup_timeout(&fresh, "timing lease recovery").await?;
    cluster
        .wait_for_no_owner(device.tenant_id, device.id)
        .await?;
    Ok(LeaseEvidence {
        partition_elapsed_ms: partition_observation.partition_elapsed_ms,
        remaining_before_partition_ms,
        safe_deadline_wait_ms: partition_observation.safe_deadline_wait_ms,
        owner_withdrawn_after_expiry,
        readiness_withdrawn: partition_observation.readiness_withdrawn,
        dispatch_before,
        dispatch_after: partition_observation.dispatch_after,
        recovery_epoch_advanced: successor.token.epoch > owner_before.token.epoch,
        recovery_echo,
    })
}

struct RotationEvidence {
    phase: String,
    candidate_generation: u64,
    overlap_elapsed_ms: u64,
    terminal_phase: String,
    typed_deadline_cause_observed: bool,
    dispatch_before: u64,
    dispatch_after: u64,
    recovery_epoch_advanced: bool,
    recovery_echo: bool,
}

struct RotationPausedObservation {
    barrier: RotationBarrier,
    overlap_elapsed_ms: u64,
    terminal_phase: String,
    typed_deadline_cause_observed: bool,
    authoritative_deadline_event_observed: bool,
    dispatch_before: u64,
    dispatch_after: u64,
}

async fn run_rotation_overlap(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
) -> Result<RotationEvidence> {
    let device_proxy =
        TcpProxy::bind(cluster.device_fanout.local_addr(), ProxyConfig::default()).await?;
    let scenario = run_rotation_overlap_with_proxy(cluster, harness, &device_proxy).await;
    let cleanup = timeout(super::CLEANUP_TIMEOUT, device_proxy.shutdown()).await;
    let cleanup = match cleanup {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "timing rotation proxy cleanup timed out".into(),
        )),
    };
    match (scenario, cleanup) {
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(cleanup)) => Err(with_cleanup_failures(error, vec![cleanup.to_string()])),
        (Ok(_), Err(error)) => Err(error),
        (Ok(evidence), Ok(())) => Ok(evidence),
    }
}

async fn run_rotation_overlap_with_proxy(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    device_proxy: &ProxyHandle,
) -> Result<RotationEvidence> {
    let device =
        harness.topology.devices_a.first().ok_or_else(|| {
            HarnessError::InvalidInput("timing rotation device is missing".into())
        })?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("timing rotation service is missing".into()))?;
    let canary = format!("m7-timing-rotation:{}", device.id);
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
    profile.config.rotation = ROTATION;
    profile.config.validate().map_err(|error| {
        HarnessError::InvalidInput(format!("timing rotation client config: {error}"))
    })?;
    let mut client = connect_rotation_client(profile.config.clone()).await?;
    let readiness = match timeout(super::STARTUP_TIMEOUT, client.wait_ready()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(HarnessError::Process(format!(
            "timing rotation client readiness: {error}"
        ))),
        Err(_) => Err(HarnessError::Timeout(
            "timing rotation client readiness timed out".into(),
        )),
    };
    if let Err(error) = readiness {
        return Err(with_cleanup_failures(
            error,
            cleanup_connector(&client, "timing rotation predecessor").await,
        ));
    }
    let owner = match current_owner(cluster, device.tenant_id, device.id).await {
        Ok(Some(owner)) => owner,
        Ok(None) => {
            return Err(with_cleanup_failures(
                HarnessError::Process("timing rotation client did not retain an owner".into()),
                cleanup_connector(&client, "timing rotation predecessor").await,
            ));
        }
        Err(error) => {
            return Err(with_cleanup_failures(
                error,
                cleanup_connector(&client, "timing rotation predecessor").await,
            ));
        }
    };
    let status = client.status_snapshot();
    if status.active_local_addr.is_none() {
        return Err(with_cleanup_failures(
            HarnessError::Process(
                "timing rotation client did not publish an active data socket".into(),
            ),
            cleanup_connector(&client, "timing rotation predecessor").await,
        ));
    }
    let consumer_addr = match cluster
        .relay("relay-c")
        .and_then(|relay| relay.consumer_addr())
    {
        Ok(addr) => addr,
        Err(error) => {
            return Err(with_cleanup_failures(
                error,
                cleanup_connector(&client, "timing rotation predecessor").await,
            ));
        }
    };
    let token = match harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(90),
            ..OidcTokenOptions::default()
        },
    ) {
        Ok(token) => token,
        Err(error) => {
            return Err(with_cleanup_failures(
                error,
                cleanup_connector(&client, "timing rotation predecessor").await,
            ));
        }
    };
    let mut stream = match open_consumer_stream(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &token,
        device.id,
        service_id,
    )
    .await
    {
        Ok(stream) => stream,
        Err(error) => {
            return Err(with_cleanup_failures(
                connect_failure_to_harness(error),
                cleanup_connector(&client, "timing rotation predecessor").await,
            ));
        }
    };
    if let Err(error) = stream
        .round_trip(b"m7-timing-rotation-baseline", canary.as_bytes())
        .await
    {
        return Err(with_cleanup_failures(
            error,
            cleanup_connector_stream(stream, &client, "timing rotation predecessor").await,
        ));
    }
    let mut paused_connection = None;
    let paused_observation = async {
        // Capture the exact active carrier while the predecessor is still
        // serving.  The pending record below is sent on the already admitted
        // consumer stream and is correlated to this generation/connection;
        // pausing a carrier selected only after PREPARE could otherwise
        // exercise a later clean rotation rather than the intended attempt.
        let active = wait_for_rotation_active_stream(cluster, &client, &owner).await?;
        let connection = wait_for_proxy_connection(device_proxy, active.local_addr).await?;
        paused_connection = Some(connection);
        device_proxy
            .pause(crate::Direction::ClientToTarget, connection)
            .await?;

        // Send exactly one bounded real consumer record without waiting for
        // its response.  The client-to-target proxy pause lets the connector
        // receive the real request while preventing its response/acknowledge
        // frame from reaching the relay.  The snapshot gate below proves that
        // this happened while the exact pre-rotation carrier was still active,
        // before PREPARE/freeze.
        send_rotation_record(&mut stream, b"m7-timing-rotation-pending").await?;
        wait_for_rotation_unacked_record(cluster, &client, &owner, &active).await?;

        let barrier = wait_for_rotation_barrier(cluster, &client, &owner).await?;
        // Bind the fault to the old carrier captured by the same
        // generation/deadline barrier.  The overlap deadline is the
        // old-carrier retirement boundary; pausing the candidate would test
        // candidate transport loss instead of forced retirement.
        if barrier.active_generation != active.generation
            || barrier.active_connection_id != active.connection_id
            || barrier.active_local_addr != active.local_addr
        {
            return Err(HarnessError::Process(
                "timing rotation barrier changed its active carrier after the outstanding record"
                    .into(),
            ));
        }
        let dispatch_before = total_dispatches(cluster).await?;
        let terminal = wait_for_rotation_terminal(cluster, &client, &owner, &barrier).await?;
        let overlap_elapsed_ms = barrier.deadline_ms.saturating_sub(barrier.started_at_ms);

        // Release the held response before the no-owner probe.  The resumed
        // stream is still closed by the outer cleanup epilogue; clearing the
        // handle here only prevents a second successful resume command.
        device_proxy
            .resume(crate::Direction::ClientToTarget, connection)
            .await?;
        paused_connection = None;
        wait_for_owner_absent(cluster, device.tenant_id, device.id, PHASE_TIMEOUT).await?;
        match open_consumer_stream(
            consumer_addr,
            &harness.pki.server_ca.certificate_der,
            &token,
            device.id,
            service_id,
        )
        .await
        {
            Err(super::StreamConnectFailure::Status { status, body })
                if is_explicit_no_owner_response(status, body.as_deref()) => {}
            Err(super::StreamConnectFailure::Status { status, .. }) => {
                return Err(HarnessError::Http(format!(
                    "timing rotation no-owner probe returned unexpected HTTP status {status}"
                )));
            }
            Err(super::StreamConnectFailure::Harness(error)) => return Err(error),
            Ok(mut probe_stream) => {
                let close_result = probe_stream.close().await;
                let primary = HarnessError::Process(
                    "timing rotation expired candidate unexpectedly admitted a stream".into(),
                );
                return match close_result {
                    Ok(()) => Err(primary),
                    Err(error) => Err(with_cleanup_failures(
                        primary,
                        vec![format!("closing admitted timing rotation probe: {error}")],
                    )),
                };
            }
        }
        let dispatch_after = total_dispatches(cluster).await?;
        Ok::<_, HarnessError>(RotationPausedObservation {
            barrier,
            overlap_elapsed_ms,
            terminal_phase: terminal.phase,
            typed_deadline_cause_observed: terminal.typed_deadline_cause_observed,
            authoritative_deadline_event_observed: terminal.authoritative_deadline_event_observed,
            dispatch_before,
            dispatch_after,
        })
    }
    .await;
    let authoritative_deadline_event_observed = matches!(
        &paused_observation,
        Ok(observation) if observation.authoritative_deadline_event_observed
    );
    // Resume the exact bound old carrier whenever it was observed, including
    // a pause failure after the proxy connection was selected.  Close and join
    // the predecessor only after this command so the proxy cannot retain a
    // stopped data path.
    let resume_result = if let Some(connection) = paused_connection {
        device_proxy
            .resume(crate::Direction::ClientToTarget, connection)
            .await
    } else {
        Ok(())
    };
    let stream_cleanup = stream.close().await;
    let client_cleanup = timeout(super::CLEANUP_TIMEOUT, client.stop()).await;
    let mut cleanup_failures = Vec::new();
    if let Err(error) = resume_result {
        cleanup_failures.push(format!("resuming timing rotation data direction: {error}"));
    }
    if let Err(error) = stream_cleanup {
        cleanup_failures.push(format!("closing timing rotation stream: {error}"));
    }
    match client_cleanup {
        Ok(Ok(())) => {}
        Ok(Err(error)) if authoritative_deadline_event_observed => {
            let readiness = client.readiness();
            if !is_expected_rotation_deadline_stop(&error, &readiness.borrow()) {
                cleanup_failures.push(format!(
                    "timing rotation CLI stop/supervisor error: {error}"
                ));
            }
        }
        Ok(Err(error)) => cleanup_failures.push(format!(
            "timing rotation CLI stop/supervisor error: {error}"
        )),
        Err(_) => cleanup_failures.push("timing rotation CLI stop/supervisor timed out".into()),
    }
    let paused_observation = match paused_observation {
        Ok(observation) => observation,
        Err(error) => return Err(with_cleanup_failures(error, cleanup_failures)),
    };
    if !cleanup_failures.is_empty() {
        return Err(HarnessError::Process(format!(
            "timing rotation paused-phase cleanup failed: {}",
            cleanup_failures.join("; ")
        )));
    }
    let barrier = paused_observation.barrier;
    let overlap_elapsed_ms = paused_observation.overlap_elapsed_ms;
    let terminal_phase = paused_observation.terminal_phase;
    let typed_deadline_cause_observed = paused_observation.typed_deadline_cause_observed;
    let dispatch_before = paused_observation.dispatch_before;
    let dispatch_after = paused_observation.dispatch_after;
    wait_for_fanout_drained(&cluster.device_fanout, "timing rotation predecessor").await?;
    cluster
        .wait_for_no_owner(device.tenant_id, device.id)
        .await?;
    let mut fresh = connect_rotation_client(profile.config.clone()).await?;
    let fresh_readiness = match timeout(super::STARTUP_TIMEOUT, fresh.wait_ready()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(HarnessError::Process(format!(
            "timing rotation recovery readiness: {error}"
        ))),
        Err(_) => Err(HarnessError::Timeout(
            "timing rotation recovery readiness timed out".into(),
        )),
    };
    if let Err(error) = fresh_readiness {
        return Err(with_cleanup_failures(
            error,
            cleanup_connector(&fresh, "timing rotation recovery").await,
        ));
    }
    let successor = match wait_for_higher_owner(
        cluster,
        device.tenant_id,
        device.id,
        owner.token.epoch,
        PHASE_TIMEOUT,
    )
    .await
    {
        Ok(owner) => owner,
        Err(error) => {
            return Err(with_cleanup_failures(
                error,
                cleanup_connector(&fresh, "timing rotation recovery").await,
            ));
        }
    };
    let recovery_token = match harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(90),
            ..OidcTokenOptions::default()
        },
    ) {
        Ok(token) => token,
        Err(error) => {
            return Err(with_cleanup_failures(
                error,
                cleanup_connector(&fresh, "timing rotation recovery").await,
            ));
        }
    };
    let mut recovery_stream = match open_consumer_stream(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &recovery_token,
        device.id,
        service_id,
    )
    .await
    {
        Ok(stream) => stream,
        Err(error) => {
            return Err(with_cleanup_failures(
                connect_failure_to_harness(error),
                cleanup_connector(&fresh, "timing rotation recovery").await,
            ));
        }
    };
    if let Err(error) = recovery_stream
        .round_trip(b"m7-timing-rotation-recovery", canary.as_bytes())
        .await
    {
        return Err(with_cleanup_failures(
            error,
            cleanup_connector_stream(recovery_stream, &fresh, "timing rotation recovery").await,
        ));
    }
    let recovery_echo = true;
    if let Err(error) = recovery_stream.close().await {
        return Err(with_cleanup_failures(
            error,
            cleanup_connector(&fresh, "timing rotation recovery").await,
        ));
    }
    super::join_connector_with_cleanup_timeout(&fresh, "timing rotation recovery").await?;
    cluster
        .wait_for_no_owner(device.tenant_id, device.id)
        .await?;
    Ok(RotationEvidence {
        phase: barrier.phase,
        candidate_generation: barrier.candidate_generation,
        overlap_elapsed_ms,
        terminal_phase,
        typed_deadline_cause_observed,
        dispatch_before,
        dispatch_after,
        recovery_epoch_advanced: successor.token.epoch > owner.token.epoch,
        recovery_echo,
    })
}

struct RotationActiveStream {
    generation: u64,
    connection_id: String,
    local_addr: SocketAddr,
    stream_id: u64,
    operation_id: String,
    emitted_before: u64,
}

async fn send_rotation_record(stream: &mut ConsumerStream, payload: &[u8]) -> Result<()> {
    if payload.len() > super::MAX_RECORD_BYTES {
        return Err(HarnessError::InvalidInput(
            "timing rotation record exceeded the 64 KiB bound".into(),
        ));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| HarnessError::InvalidInput("timing rotation record length overflow".into()))?;
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    timeout(
        super::EXCHANGE_TIMEOUT,
        stream.socket.send(Message::Binary(frame.into())),
    )
    .await
    .map_err(|_| HarnessError::Timeout("timing rotation record send timed out".into()))?
    .map_err(|error| HarnessError::Http(format!("sending timing rotation record: {error}")))
}

async fn wait_for_rotation_active_stream(
    cluster: &ProductionCluster,
    client: &ConnectionHandle,
    owner: &OwnerClaim,
) -> Result<RotationActiveStream> {
    let deadline = Instant::now() + PHASE_TIMEOUT;
    loop {
        let status = client.status_snapshot();
        if status.phase == "active"
            && status.session_id.as_deref() == Some(owner.token.session_id.as_str())
            && status.epoch == Some(owner.token.epoch)
            && let Some(generation) = status.active_generation
            && let Some(connection_id) = status.active_connection_id.as_deref()
            && let Some(local_addr) = status.active_local_addr
        {
            let snapshot = timing_snapshot(
                cluster.relay(&owner.token.node_id)?,
                deadline,
                "rotation active stream",
            )
            .await?;
            if let Some(session) = snapshot.sessions.iter().find(|session| {
                session.session_id == owner.token.session_id
                    && session.epoch == owner.token.epoch
                    && session.phase == "active"
                    && session.active_generation == generation
                    && session.active_connection_id == connection_id
            }) {
                let streams = session
                    .streams
                    .iter()
                    .filter(|stream| !stream.terminal)
                    .collect::<Vec<_>>();
                if streams.len() > 1 {
                    return Err(HarnessError::Process(format!(
                        "timing rotation active carrier had {} nonterminal consumer streams",
                        streams.len()
                    )));
                }
                if let Some(stream) = streams.first() {
                    return Ok(RotationActiveStream {
                        generation,
                        connection_id: connection_id.to_owned(),
                        local_addr,
                        stream_id: stream.stream_id,
                        operation_id: stream.operation_id.clone(),
                        emitted_before: stream.last_emitted_relay_to_connector,
                    });
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "timing rotation did not expose an active carrier and consumer stream".into(),
            ));
        }
        timing_poll_sleep(deadline, "rotation active stream").await?;
    }
}

async fn wait_for_rotation_unacked_record(
    cluster: &ProductionCluster,
    client: &ConnectionHandle,
    owner: &OwnerClaim,
    active: &RotationActiveStream,
) -> Result<()> {
    let deadline = Instant::now() + PHASE_TIMEOUT;
    loop {
        let status = client.status_snapshot();
        let status_matches = status.phase == "active"
            && status.session_id.as_deref() == Some(owner.token.session_id.as_str())
            && status.epoch == Some(owner.token.epoch)
            && status.active_generation == Some(active.generation)
            && status.active_connection_id.as_deref() == Some(active.connection_id.as_str())
            && status.active_local_addr == Some(active.local_addr);
        if !status_matches {
            return Err(HarnessError::Process(
                "timing rotation active carrier changed before the bounded record became unacked"
                    .into(),
            ));
        }
        let snapshot = timing_snapshot(
            cluster.relay(&owner.token.node_id)?,
            deadline,
            "rotation outstanding record",
        )
        .await?;
        if let Some(session) = snapshot.sessions.iter().find(|session| {
            session.session_id == owner.token.session_id
                && session.epoch == owner.token.epoch
                && session.phase == "active"
                && session.active_generation == active.generation
                && session.active_connection_id == active.connection_id
        }) && let Some(stream) = session.streams.iter().find(|stream| {
            stream.stream_id == active.stream_id
                && stream.operation_id == active.operation_id
                && !stream.terminal
        }) && stream.last_emitted_relay_to_connector > active.emitted_before
            && stream.last_emitted_relay_to_connector > stream.peer_acked_relay_to_connector
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "timing rotation record did not become emitted-but-unacknowledged before PREPARE"
                    .into(),
            ));
        }
        timing_poll_sleep(deadline, "rotation outstanding record").await?;
    }
}

struct RotationBarrier {
    phase: String,
    active_generation: u64,
    active_connection_id: String,
    active_local_addr: SocketAddr,
    candidate_generation: u64,
    candidate_connection_id: String,
    started_at_ms: u64,
    deadline_ms: u64,
}

struct RotationTerminalObservation {
    phase: String,
    typed_deadline_cause_observed: bool,
    authoritative_deadline_event_observed: bool,
}

async fn wait_for_rotation_barrier(
    cluster: &ProductionCluster,
    client: &ConnectionHandle,
    owner: &OwnerClaim,
) -> Result<RotationBarrier> {
    // This local deadline only bounds discovery.  The overlap evidence is
    // taken from the relay's authoritative protocol timestamps below.
    let deadline = Instant::now()
        + Duration::from_secs(
            ROTATION
                .interval_seconds
                .saturating_add(ROTATION.handshake_timeout_seconds)
                .saturating_add(1),
        );
    loop {
        let status = client.status_snapshot();
        if matches!(
            status.phase.as_str(),
            "preparing" | "quiescing" | "draining"
        ) && status.session_id.as_deref() == Some(owner.token.session_id.as_str())
            && status.epoch == Some(owner.token.epoch)
            && let Some(active_generation) = status.active_generation
            && let Some(active_connection_id) = status.active_connection_id.as_deref()
            && let Some(active_local_addr) = status.active_local_addr
            && let Some(candidate_generation) = status.candidate_generation
            && let Some(candidate_connection_id) = status.candidate_connection_id.as_deref()
        {
            let snapshot = cluster.relay(&owner.token.node_id)?.snapshot().await?;
            if let Some(session) = snapshot.sessions.iter().find(|session| {
                session.session_id == owner.token.session_id
                    && session.epoch == owner.token.epoch
                    && session.active_generation == active_generation
                    && session.active_connection_id == active_connection_id
                    && session.candidate_generation == Some(candidate_generation)
                    && session.candidate_connection_id.as_deref() == Some(candidate_connection_id)
                    && matches!(
                        session.phase.as_str(),
                        "preparing" | "quiescing" | "draining"
                    )
            }) {
                let (Some(started_at_ms), Some(deadline_ms)) =
                    (session.rotation_started_at_ms, session.rotation_deadline_ms)
                else {
                    continue;
                };
                let observed_overlap_ms = deadline_ms.saturating_sub(started_at_ms);
                let expected_overlap_ms = ROTATION.overlap_seconds.saturating_mul(1_000);
                if observed_overlap_ms != expected_overlap_ms {
                    return Err(HarnessError::Process(format!(
                        "timing rotation relay exposed overlap window {}ms, expected {}ms",
                        observed_overlap_ms, expected_overlap_ms
                    )));
                }
                return Ok(RotationBarrier {
                    phase: status.phase,
                    active_generation,
                    active_connection_id: active_connection_id.to_owned(),
                    active_local_addr,
                    candidate_generation,
                    candidate_connection_id: candidate_connection_id.to_owned(),
                    started_at_ms,
                    deadline_ms,
                });
            }
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "timing rotation did not expose a pre-commit candidate barrier".into(),
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_rotation_terminal(
    cluster: &ProductionCluster,
    client: &ConnectionHandle,
    owner: &OwnerClaim,
    barrier: &RotationBarrier,
) -> Result<RotationTerminalObservation> {
    let expected_active_generation = barrier.active_generation;
    let expected_active_connection_id = barrier.active_connection_id.as_str();
    let expected_candidate_generation = barrier.candidate_generation;
    let expected_candidate_connection_id = barrier.candidate_connection_id.as_str();
    let expected_started_at_ms = barrier.started_at_ms;
    let expected_deadline_ms = barrier.deadline_ms;
    // The relay's absolute protocol timestamps are authoritative evidence;
    // this local deadline is only a bounded polling budget because the relay
    // process owns the monotonic clock origin.  It is never reported as the
    // overlap duration and cannot turn an ordinary terminal phase into a
    // deadline pass.
    let authoritative_overlap_ms = expected_deadline_ms.saturating_sub(expected_started_at_ms);
    let deadline = Instant::now()
        + Duration::from_millis(
            authoritative_overlap_ms.saturating_add(
                ROTATION
                    .handshake_timeout_seconds
                    .saturating_add(1)
                    .saturating_mul(1_000),
            ),
        );
    let mut last_snapshot = None;
    loop {
        let status = client.status_snapshot();
        if status.session_id.as_deref() == Some(owner.token.session_id.as_str())
            && status.epoch == Some(owner.token.epoch)
        {
            let snapshot = timeout(
                deadline.saturating_duration_since(Instant::now()),
                cluster.relay(&owner.token.node_id)?.snapshot(),
            )
            .await
            .map_err(|_| {
                HarnessError::Timeout(format!(
                    "timing rotation relay snapshot exceeded deadline; {}",
                    rotation_timeout_diagnostics(
                        barrier,
                        owner.token.session_id.as_str(),
                        owner.token.epoch,
                        &status,
                        last_snapshot.as_ref(),
                    ),
                ))
            })??;
            last_snapshot = Some(snapshot.clone());
            // A relay deadline closes the session fail-closed on the
            // maintenance tick.  The bounded event is latched before that
            // removal, so require exact old/candidate identity and then wait
            // until the ordinary session entry is gone before accepting it.
            // The connector's closed status intentionally preserves the last
            // active/candidate identity for diagnostics, so the relay event
            // and terminal client phase are the causal evidence; candidate
            // fields are not required to be cleared by publish_closed.
            let exact_deadline_event = snapshot.rotation_deadline_events.iter().any(|event| {
                event.tenant_id == owner.token.tenant_id.to_string()
                    && event.device_id == owner.token.device_id.to_string()
                    && event.session_id == owner.token.session_id
                    && event.epoch == owner.token.epoch
                    && event.old_generation == expected_active_generation
                    && event.old_connection_id == expected_active_connection_id
                    && event.candidate_generation == expected_candidate_generation
                    && event.candidate_connection_id == expected_candidate_connection_id
                    && event.started_at_ms == expected_started_at_ms
                    && event.deadline_ms == expected_deadline_ms
                    && event.fired_at_ms >= expected_deadline_ms
                    && event.reason == "deadline"
            });
            let relay_session_present = snapshot.sessions.iter().any(|session| {
                session.session_id == owner.token.session_id && session.epoch == owner.token.epoch
            });
            if exact_deadline_event
                && !relay_session_present
                && matches!(status.phase.as_str(), "closed" | "failed")
            {
                return Ok(RotationTerminalObservation {
                    phase: status.phase,
                    typed_deadline_cause_observed: true,
                    authoritative_deadline_event_observed: true,
                });
            }
        }
        // A candidate timeout is only evidenced by the typed abort/recovery
        // transition and by the candidate generation being fenced out of the
        // status snapshot.  Unknown strings, an ordinary active snapshot, or
        // a still-present candidate are not accepted as expiry evidence.
        if matches!(
            status.phase.as_str(),
            "aborting" | "recovering" | "closed" | "failed"
        ) && status.session_id.as_deref() == Some(owner.token.session_id.as_str())
            && status.epoch == Some(owner.token.epoch)
            && status.candidate_generation.is_none()
        {
            let snapshot = timeout(
                deadline.saturating_duration_since(Instant::now()),
                cluster.relay(&owner.token.node_id)?.snapshot(),
            )
            .await
            .map_err(|_| {
                HarnessError::Timeout(format!(
                    "timing rotation relay snapshot exceeded deadline; {}",
                    rotation_timeout_diagnostics(
                        barrier,
                        owner.token.session_id.as_str(),
                        owner.token.epoch,
                        &status,
                        last_snapshot.as_ref(),
                    ),
                ))
            })??;
            last_snapshot = Some(snapshot.clone());
            // The relay retains the attempt identity while it enters
            // recovery, so candidate_generation alone is not physical
            // carrier evidence.  Count only phases that still own the
            // candidate-side rotation carrier.
            let relay_candidate_present = snapshot.sessions.iter().any(|session| {
                session.session_id == owner.token.session_id
                    && session.epoch == owner.token.epoch
                    && session.active_generation == expected_active_generation
                    && session.active_connection_id == expected_active_connection_id
                    && session.candidate_generation == Some(expected_candidate_generation)
                    && session.candidate_connection_id.as_deref()
                        == Some(expected_candidate_connection_id)
                    && matches!(
                        session.phase.as_str(),
                        "preparing"
                            | "quiescing"
                            | "draining"
                            | "committing"
                            | "retiring"
                            | "aborting"
                    )
            });
            if !relay_candidate_present {
                let matching_sessions = snapshot
                    .sessions
                    .iter()
                    .filter(|session| {
                        session.session_id == owner.token.session_id
                            && session.epoch == owner.token.epoch
                    })
                    .collect::<Vec<_>>();
                let typed_deadline_cause_observed = matching_sessions.len() == 1
                    && matching_sessions[0].candidate_generation
                        == Some(expected_candidate_generation)
                    && matching_sessions[0].rotation_started_at_ms == Some(expected_started_at_ms)
                    && matching_sessions[0].rotation_deadline_ms == Some(expected_deadline_ms)
                    && matching_sessions[0].rotation_recovery_reason == Some("deadline")
                    && matching_sessions[0].rotation_deadline_forced_retirement
                    && expected_deadline_ms > expected_started_at_ms;
                if typed_deadline_cause_observed {
                    return Ok(RotationTerminalObservation {
                        phase: status.phase,
                        typed_deadline_cause_observed,
                        authoritative_deadline_event_observed: false,
                    });
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "timing rotation did not expose deadline recovery for candidate generation {} (phase={}, candidate={:?}); {}",
                expected_candidate_generation,
                status.phase,
                status.candidate_generation,
                rotation_timeout_diagnostics(
                    barrier,
                    owner.token.session_id.as_str(),
                    owner.token.epoch,
                    &status,
                    last_snapshot.as_ref(),
                )
            )));
        }
        sleep(POLL_INTERVAL).await;
    }
}

fn rotation_timeout_diagnostics(
    barrier: &RotationBarrier,
    expected_session_id: &str,
    expected_epoch: u64,
    status: &tunnel_client::ConnectionStatus,
    snapshot: Option<&RelaySnapshot>,
) -> String {
    let barrier = format!(
        "barrier phase={} active={}/{}@{} candidate={}/{} started_ms={} deadline_ms={}",
        barrier.phase,
        barrier.active_generation,
        barrier.active_connection_id,
        barrier.active_local_addr,
        barrier.candidate_generation,
        barrier.candidate_connection_id,
        barrier.started_at_ms,
        barrier.deadline_ms,
    );
    let cli = format!(
        "cli phase={} session={:?} epoch={:?} active={:?}/{:?}@{:?} candidate={:?}/{:?}@{:?} rotation={:?} streams={}",
        status.phase,
        status.session_id,
        status.epoch,
        status.active_generation,
        status.active_connection_id,
        status.active_local_addr,
        status.candidate_generation,
        status.candidate_connection_id,
        status.candidate_local_addr,
        status.rotation_id,
        status.streams,
    );
    let relay = snapshot
        .map(|snapshot| {
            let sessions = snapshot
                .sessions
                .iter()
                .filter(|session| {
                    session.session_id == expected_session_id && session.epoch == expected_epoch
                })
                .map(|session| {
                    format!(
                        "session={} epoch={} phase={} active={}/{} candidate={:?}/{:?} started={:?} deadline={:?} reason={:?} forced={}",
                        session.device_id,
                        session.epoch,
                        session.phase,
                        session.active_generation,
                        session.active_connection_id,
                        session.candidate_generation,
                        session.candidate_connection_id,
                        session.rotation_started_at_ms,
                        session.rotation_deadline_ms,
                        session.rotation_recovery_reason,
                        session.rotation_deadline_forced_retirement,
                    )
                })
                .collect::<Vec<_>>();
            let events = snapshot
                .rotation_deadline_events
                .iter()
                .map(|event| {
                    format!(
                        "tenant={} device={} session={} epoch={} old={}/{} candidate={}/{} started={} deadline={} fired={} reason={}",
                        event.tenant_id,
                        event.device_id,
                        event.session_id,
                        event.epoch,
                        event.old_generation,
                        event.old_connection_id,
                        event.candidate_generation,
                        event.candidate_connection_id,
                        event.started_at_ms,
                        event.deadline_ms,
                        event.fired_at_ms,
                        event.reason,
                    )
                })
                .collect::<Vec<_>>();
            let terminal_events = snapshot
                .session_terminal_events
                .iter()
                .filter(|event| {
                    event.session_id == expected_session_id && event.epoch == expected_epoch
                })
                .map(|event| {
                    format!(
                        "tenant={} device={} session={} epoch={} active={}/{} candidate={:?}/{:?} rotation={:?} started={:?} deadline={:?} closed={} reason={}",
                        event.tenant_id,
                        event.device_id,
                        event.session_id,
                        event.epoch,
                        event.active_generation,
                        event.active_connection_id,
                        event.candidate_generation,
                        event.candidate_connection_id,
                        event.rotation_id,
                        event.rotation_started_at_ms,
                        event.rotation_deadline_ms,
                        event.closed_at_ms,
                        event.reason,
                    )
                })
                .collect::<Vec<_>>();
            format!(
                "relay_now_ms={} relay_current=[{}] latched_deadline_events({})=[{}] terminal_close_events({})=[{}]",
                snapshot.monotonic_now_ms,
                sessions.join(" | "),
                events.len(),
                events.join(" | "),
                terminal_events.len(),
                terminal_events.join(" | "),
            )
        })
        .unwrap_or_else(|| "relay_snapshot=unavailable".to_owned());
    format!("{barrier}; {cli}; {relay}; cli_stop_supervisor_error=reported_by_cleanup_epilogue")
}

async fn connect_rotation_client(config: tunnel_client::ConnectConfig) -> Result<ConnectionHandle> {
    timeout(
        super::STARTUP_TIMEOUT,
        tunnel_client::connect(ConnectOptions {
            config,
            cancellation: CancellationToken::new(),
            profile: TransportProfile::M2,
        }),
    )
    .await
    .map_err(|_| HarnessError::Timeout("timing rotation client startup timed out".into()))?
    .map_err(|error| HarnessError::Process(format!("starting timing rotation client: {error}")))
}

async fn wait_for_proxy_connection(
    proxy: &ProxyHandle,
    active_addr: SocketAddr,
) -> Result<crate::ConnectionId> {
    let deadline = Instant::now() + PHASE_TIMEOUT;
    loop {
        if let Some(connection) = proxy
            .diagnostics()
            .active_connections
            .into_iter()
            .find(|connection| connection.source_addr == active_addr)
        {
            return Ok(connection.id);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "timing rotation proxy did not expose the bound old data socket".into(),
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}

fn with_cleanup_failures(primary: HarnessError, cleanup_failures: Vec<String>) -> HarnessError {
    if cleanup_failures.is_empty() {
        primary
    } else {
        HarnessError::Process(format!(
            "{primary}; cleanup failures: {}",
            cleanup_failures.join("; ")
        ))
    }
}

async fn current_owner(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
) -> Result<Option<OwnerClaim>> {
    current_owner_with_budget(
        cluster,
        tenant_id,
        device_id,
        super::REDIS_PARTITION_OPERATION_TIMEOUT,
    )
    .await
}

async fn current_owner_with_budget(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    budget: Duration,
) -> Result<Option<OwnerClaim>> {
    timeout(
        budget,
        cluster
            .catalog
            .current_owner(tenant_id, device_id, Utc::now()),
    )
    .await
    .map_err(|_| HarnessError::Timeout("reading timing owner timed out".into()))?
    .map_err(|error| HarnessError::Redis(format!("reading timing owner: {error}")))
}

fn owner_remaining_ms(owner: &OwnerClaim, now: DateTime<Utc>) -> Result<u64> {
    let remaining = owner
        .lease_expires_at
        .signed_duration_since(now)
        .to_std()
        .map_err(|_| HarnessError::Process("timing owner lease was already expired".into()))?;
    Ok(u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX))
}

async fn wait_for_owner_absent(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    budget: Duration,
) -> Result<bool> {
    let deadline = Instant::now() + budget;
    loop {
        match current_owner(cluster, tenant_id, device_id).await {
            Ok(None) => return Ok(true),
            Ok(Some(_)) => {}
            Err(error) if Instant::now() >= deadline => return Err(error),
            Err(_) => {}
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "timing owner did not withdraw after lease expiry".into(),
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_higher_owner(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    predecessor_epoch: u64,
    budget: Duration,
) -> Result<OwnerClaim> {
    let deadline = Instant::now() + budget;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HarnessError::Timeout(
                "timing fresh owner did not advance the predecessor epoch".into(),
            ));
        }
        if let Some(owner) = current_owner_with_budget(
            cluster,
            tenant_id,
            device_id,
            remaining.min(super::REDIS_PARTITION_OPERATION_TIMEOUT),
        )
        .await?
            && owner.token.epoch > predecessor_epoch
            && cluster
                .relays
                .iter()
                .any(|relay| relay.node_id == owner.token.node_id)
        {
            return Ok(owner);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "timing fresh owner did not advance the predecessor epoch".into(),
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HarnessError::Timeout(
                "timing fresh owner did not advance the predecessor epoch".into(),
            ));
        }
        sleep(POLL_INTERVAL.min(remaining)).await;
    }
}

async fn total_dispatches(cluster: &ProductionCluster) -> Result<u64> {
    let mut total = 0_u64;
    for relay in &cluster.relays {
        total = total.saturating_add(relay.snapshot().await?.lifetime_application_dispatches);
    }
    Ok(total)
}

async fn wait_for_public_unready(consumer_addr: SocketAddr, server_ca_der: &[u8]) -> Result<bool> {
    let deadline = Instant::now() + HEALTH_POLL_TIMEOUT;
    loop {
        if assert_public_health_unready(consumer_addr, server_ca_der)
            .await
            .is_ok()
        {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "timing lease public readiness did not become unready".into(),
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod terminal_cleanup_tests {
    use super::is_expected_rotation_deadline_stop;
    use tunnel_client::{ClientError, Readiness};

    #[test]
    fn accepts_only_the_authoritative_deadline_control_terminal() {
        let expected = ClientError::Transport {
            scope: "control read",
            detail: "control socket closed".to_owned(),
        };
        let closed = Readiness::Closed {
            reason: "control read failed".to_owned(),
        };
        assert!(is_expected_rotation_deadline_stop(&expected, &closed));

        assert!(!is_expected_rotation_deadline_stop(
            &ClientError::Transport {
                scope: "data read",
                detail: "data socket closed".to_owned(),
            },
            &closed,
        ));
        assert!(!is_expected_rotation_deadline_stop(
            &expected,
            &Readiness::Closed {
                reason: "cancelled".to_owned(),
            },
        ));
        assert!(!is_expected_rotation_deadline_stop(
            &expected,
            &Readiness::Stopping,
        ));
    }
}
