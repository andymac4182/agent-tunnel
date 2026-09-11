//! Production owner-contention and stale-cleanup acceptance.
//!
//! The fixture intentionally launches two fresh CLI processes before either
//! process is observed as ready.  Their identical tenant/device/certificate
//! scope enters two different relay device listeners, so the Redis owner claim
//! is the only authority that can select a winner.  The losing process must
//! terminate after the failed control admission; the client has no automatic
//! reconnect policy.

use super::{
    ConsumerStream, ProductionCluster, RunningHarness, SCENARIO_TIMEOUT, STARTUP_TIMEOUT,
    connect_failure_to_harness, open_consumer_stream,
};
use crate::acceptance::helpers::{DeviceProfile, write_device_profile};
use crate::{Harness, HarnessError, HarnessOptions, ManagedProcess, ProcessSpec, Result};
use chrono::Utc;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tempfile::tempdir;
use tokio::time::{sleep, timeout};
use tunnel_catalog::OwnerClaim;
use uuid::Uuid;

const DUPLICATE_TERMINAL_TIMEOUT: Duration = Duration::from_secs(12);
const DUPLICATE_SETTLE_TIMEOUT: Duration = Duration::from_secs(2);
const SUCCESSOR_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const PROCESS_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const HIGH_EPOCH_BASE: u64 = 1_u64 << 53;
const HIGH_EPOCH_REDIS_TIMEOUT: Duration = Duration::from_secs(2);

const SEED_HIGH_EPOCH_SCRIPT: &str = r#"
local active_incarnation = redis.call('GET', KEYS[4])
if active_incarnation ~= ARGV[2] then
    return {'incarnation_mismatch'}
end
if redis.call('EXISTS', KEYS[1]) == 1 then
    return {'owner_present'}
end
local generation = redis.call('GET', KEYS[2])
if not generation then
    return {'missing_generation'}
end
local epoch = redis.call('GET', KEYS[3])
if epoch and epoch ~= '0' then
    return {'unexpected_epoch', epoch}
end
redis.call('SET', KEYS[3], ARGV[1])
return {'ok', generation, epoch or '0'}
"#;

/// Payload-free evidence from the real three-relay owner contention gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipEvidence {
    /// Number of relays started through the production serving boundary.
    pub relay_count: usize,
    /// Both exact-scope CLI launches began before the owner was observed.
    pub concurrent_launches: bool,
    /// Exactly one of the two concurrent claims became the Redis owner.
    pub one_atomic_winner: bool,
    /// The relay actors recorded exactly one authoritative duplicate-control
    /// rejection across the three relays.  A remote-forwarded registration
    /// may account for the rejection on the existing owner's relay rather
    /// than the duplicate's direct ingress.
    pub actual_control_conflict_recorded: bool,
    /// The losing CLI reached a terminal non-success state within its bound.
    pub duplicate_terminal_conflict: bool,
    /// The active owner's complete token stayed unchanged while the duplicate
    /// process terminated; this is the observable no-reconnect assertion.
    pub duplicate_reconnect_loop_absent: bool,
    /// The original owner returned an echo after the duplicate was rejected.
    pub original_owner_preserved: bool,
    /// An independent device session and its stream survived the contention
    /// and handoff phases.
    pub sibling_preserved: bool,
    /// The replacement claimed the same scope on a higher retained epoch.
    pub successor_higher_epoch: bool,
    /// The original CLI observed the durable high epoch after its claim.
    pub original_epoch: u64,
    /// The successor CLI observed a strictly higher durable epoch.
    pub successor_epoch: u64,
    /// The guarded epoch seed did not mutate catalog generation metadata.
    pub catalog_generation_preserved: bool,
    /// Releasing the old complete token after successor admission was fenced.
    pub stale_cleanup_rejected: bool,
    /// The higher-epoch successor returned its echo through a public route.
    pub successor_echo: bool,
    /// Wall-clock milliseconds spent in the bounded scenario.
    pub elapsed_ms: u64,
}

/// Validate the bounded owner-contention evidence contract.
pub fn validate_ownership_evidence(evidence: &OwnershipEvidence) -> Result<()> {
    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "owner-contention expected three relays, observed {}",
            evidence.relay_count
        )));
    }
    let required = [
        ("concurrent_launches", evidence.concurrent_launches),
        ("one_atomic_winner", evidence.one_atomic_winner),
        (
            "actual_control_conflict_recorded",
            evidence.actual_control_conflict_recorded,
        ),
        (
            "duplicate_terminal_conflict",
            evidence.duplicate_terminal_conflict,
        ),
        (
            "duplicate_reconnect_loop_absent",
            evidence.duplicate_reconnect_loop_absent,
        ),
        (
            "original_owner_preserved",
            evidence.original_owner_preserved,
        ),
        ("sibling_preserved", evidence.sibling_preserved),
        ("successor_higher_epoch", evidence.successor_higher_epoch),
        (
            "catalog_generation_preserved",
            evidence.catalog_generation_preserved,
        ),
        ("stale_cleanup_rejected", evidence.stale_cleanup_rejected),
        ("successor_echo", evidence.successor_echo),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "owner-contention required gate {name} was false"
        )));
    }
    if evidence.original_epoch <= HIGH_EPOCH_BASE {
        return Err(HarnessError::Process(format!(
            "owner-contention original epoch {} did not exceed the high-epoch boundary",
            evidence.original_epoch
        )));
    }
    if evidence.successor_epoch <= evidence.original_epoch {
        return Err(HarnessError::Process(format!(
            "owner-contention successor epoch {} did not exceed original epoch {}",
            evidence.successor_epoch, evidence.original_epoch
        )));
    }
    Ok(())
}

#[cfg(test)]
mod c17_validator_tests {
    use super::{HIGH_EPOCH_BASE, OwnershipEvidence, validate_ownership_evidence};
    use crate::acceptance_test_support::assert_rejected;

    fn valid_evidence() -> OwnershipEvidence {
        OwnershipEvidence {
            relay_count: 3,
            concurrent_launches: true,
            one_atomic_winner: true,
            actual_control_conflict_recorded: true,
            duplicate_terminal_conflict: true,
            duplicate_reconnect_loop_absent: true,
            original_owner_preserved: true,
            sibling_preserved: true,
            successor_higher_epoch: true,
            original_epoch: HIGH_EPOCH_BASE + 1,
            successor_epoch: HIGH_EPOCH_BASE + 2,
            catalog_generation_preserved: true,
            stale_cleanup_rejected: true,
            successor_echo: true,
            elapsed_ms: 1,
        }
    }

    #[test]
    fn every_owner_contention_flag_and_epoch_bound_reaches_the_shared_exit_path() {
        type Disable = (&'static str, fn(&mut OwnershipEvidence));
        let flags: [Disable; 11] = [
            ("concurrent_launches", |e| e.concurrent_launches = false),
            ("one_atomic_winner", |e| e.one_atomic_winner = false),
            ("actual_control_conflict_recorded", |e| {
                e.actual_control_conflict_recorded = false
            }),
            ("duplicate_terminal_conflict", |e| {
                e.duplicate_terminal_conflict = false
            }),
            ("duplicate_reconnect_loop_absent", |e| {
                e.duplicate_reconnect_loop_absent = false
            }),
            ("original_owner_preserved", |e| {
                e.original_owner_preserved = false
            }),
            ("sibling_preserved", |e| e.sibling_preserved = false),
            ("successor_higher_epoch", |e| {
                e.successor_higher_epoch = false
            }),
            ("catalog_generation_preserved", |e| {
                e.catalog_generation_preserved = false
            }),
            ("stale_cleanup_rejected", |e| {
                e.stale_cleanup_rejected = false
            }),
            ("successor_echo", |e| e.successor_echo = false),
        ];
        for (name, disable) in flags {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_rejected(validate_ownership_evidence(&evidence), name);
        }

        type Mutate = (&'static str, fn(&mut OwnershipEvidence));
        let bounds: [Mutate; 3] = [
            ("relay_count", |e: &mut OwnershipEvidence| e.relay_count = 2),
            ("original_epoch", |e: &mut OwnershipEvidence| {
                e.original_epoch = HIGH_EPOCH_BASE
            }),
            ("successor_epoch", |e: &mut OwnershipEvidence| {
                e.successor_epoch = e.original_epoch
            }),
        ];
        for (name, mutate) in bounds {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(validate_ownership_evidence(&evidence), "owner-contention");
            let _ = name;
        }
    }

    #[test]
    fn owner_contention_validator_accepts_complete_evidence() {
        validate_ownership_evidence(&valid_evidence())
            .expect("complete owner-contention evidence is valid");
    }
}

/// Run the bounded real three-relay owner contention and stale cleanup gate.
pub async fn verify() -> Result<OwnershipEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(super::ROTATION)
        .shared_device_uuid(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| {
            HarnessError::Timeout("owner-contention harness startup timed out".into())
        })??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };

    let scenario = match timeout(SCENARIO_TIMEOUT, run(&mut cluster, &harness)).await {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "owner-contention production scenario exceeded its bounded deadline".into(),
        )),
    };
    let cluster_cleanup = cluster.shutdown().await;
    let harness_cleanup = harness.shutdown().await;
    match (scenario, cluster_cleanup, harness_cleanup) {
        (Ok(evidence), Ok(()), Ok(())) => {
            validate_ownership_evidence(&evidence)?;
            Ok(evidence)
        }
        (scenario, cluster_cleanup, harness_cleanup) => {
            let mut failure = scenario.err();
            if let Err(error) = cluster_cleanup {
                append_cleanup_failure(&mut failure, "owner-contention relay cleanup", error);
            }
            if let Err(error) = harness_cleanup {
                append_cleanup_failure(&mut failure, "owner-contention Redis cleanup", error);
            }
            Err(failure.expect("owner-contention cleanup failure was not recorded"))
        }
    }
}

fn append_cleanup_failure(slot: &mut Option<HarnessError>, label: &str, error: HarnessError) {
    *slot = Some(match slot.take() {
        Some(primary) => HarnessError::Process(format!("{primary}; {label}: {error}")),
        None => HarnessError::Process(format!("{label}: {error}")),
    });
}

async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
) -> Result<OwnershipEvidence> {
    let started = Instant::now();
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(format!(
            "owner-contention gate started {} relays, expected three",
            cluster.relays.len()
        )));
    }
    cluster.wait_for_peer_readiness(STARTUP_TIMEOUT).await?;

    let original =
        harness.topology.devices_a.first().ok_or_else(|| {
            HarnessError::InvalidInput("owner-contention device is missing".into())
        })?;
    let sibling = harness.topology.devices_a.get(1).ok_or_else(|| {
        HarnessError::InvalidInput("owner-contention sibling device is missing".into())
    })?;
    let original_service = *harness
        .topology
        .service_ids
        .get(&original.id)
        .ok_or_else(|| HarnessError::InvalidInput("owner-contention service is missing".into()))?;
    let sibling_service = *harness
        .topology
        .service_ids
        .get(&sibling.id)
        .ok_or_else(|| {
            HarnessError::InvalidInput("owner-contention sibling service is missing".into())
        })?;
    let original_canary = format!("m7-owner-contention:{}", original.id);
    let sibling_canary = format!("m7-owner-contention-sibling:{}", sibling.id);
    let token = harness.oidc.issue(&harness.topology.consumers_a[0].name)?;
    let high_epoch_setup =
        seed_high_owner_epoch(cluster, harness, original.tenant_id, original.id).await?;

    let profile_root = tempdir().map_err(HarnessError::Io)?;
    let relay_a_device = device_addr(cluster, "relay-a")?;
    let relay_b_device = device_addr(cluster, "relay-b")?;
    let relay_c_device = device_addr(cluster, "relay-c")?;
    let profile_a = write_device_profile(
        profile_root.path(),
        original.id,
        original_service,
        &original_canary,
        relay_a_device,
        &original.certificate.certificate_pem,
        &original.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    let profile_b = write_device_profile(
        profile_root.path(),
        original.id,
        original_service,
        &original_canary,
        relay_b_device,
        &original.certificate.certificate_pem,
        &original.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    let profile_sibling = write_device_profile(
        profile_root.path(),
        sibling.id,
        sibling_service,
        &sibling_canary,
        relay_c_device,
        &sibling.certificate.certificate_pem,
        &sibling.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;

    // Capture the redacted actor counters before either exact-scope process is
    // launched.  The loser must later account for one authoritative
    // owner-busy/control-conflict admission somewhere in the relay path;
    // generic transport failure alone is deliberately insufficient evidence.
    let control_conflicts_before = control_conflict_counts(cluster).await?;

    // Spawn both exact-scope CLIs together.  No readiness/status call occurs
    // until both child processes have been returned by the two spawn futures.
    let (spawn_a, spawn_b) = tokio::join!(
        spawn_cli("m7-owner-contention-a", &profile_a),
        spawn_cli("m7-owner-contention-b", &profile_b),
    );
    let mut process_a = match spawn_a {
        Ok(process) => Some(process),
        Err(error) => {
            if let Ok(process) = spawn_b {
                let _ = process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
            }
            return Err(error);
        }
    };
    let mut process_b = match spawn_b {
        Ok(process) => Some(process),
        Err(error) => {
            if let Some(process) = process_a.take() {
                let _ = process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
            }
            return Err(error);
        }
    };
    let concurrent_launches = true;

    let predecessor =
        wait_for_owner(cluster, original.tenant_id, original.id, STARTUP_TIMEOUT).await?;
    if predecessor.token.tenant_id != original.tenant_id
        || predecessor.token.device_id != original.id
        || !matches!(predecessor.token.node_id.as_str(), "relay-a" | "relay-b")
    {
        shutdown_process(&mut process_a, "contention relay-a").await?;
        shutdown_process(&mut process_b, "contention relay-b").await?;
        return Err(HarnessError::Process(
            "concurrent owner claim returned an unexpected scope or relay".into(),
        ));
    }
    let expected_original_epoch = high_epoch_setup
        .seeded_epoch
        .checked_add(1)
        .ok_or_else(|| HarnessError::Process("owner-contention epoch overflow".into()))?;
    if predecessor.token.epoch != expected_original_epoch {
        shutdown_process(&mut process_a, "contention relay-a").await?;
        shutdown_process(&mut process_b, "contention relay-b").await?;
        return Err(HarnessError::Process(format!(
            "original owner claimed epoch {}, expected {} after guarded high-epoch seed",
            predecessor.token.epoch, expected_original_epoch
        )));
    }
    // The catalog returned one complete owner token for the concurrent
    // same-scope launches.  The separate actor counter below proves that the
    // other control path was rejected authoritatively rather than merely
    // failing before admission.
    let one_atomic_winner = true;
    let winner_is_a = predecessor.token.node_id == "relay-a";

    let winner_process = if winner_is_a {
        process_a.take()
    } else {
        process_b.take()
    }
    .ok_or_else(|| HarnessError::Process("owner winner process was not retained".into()))?;
    let mut loser_process = if winner_is_a {
        process_b.take()
    } else {
        process_a.take()
    }
    .ok_or_else(|| HarnessError::Process("owner loser process was not retained".into()))?;

    // A loser that remains alive beyond this bound would indicate an
    // accidental reconnect/supervision loop.  The non-success exit is the
    // CLI's terminal observation; relay HTTP deliberately redacts conflict
    // details, so the test also holds the complete Redis token unchanged.
    wait_for_process_exit(&mut loser_process, DUPLICATE_TERMINAL_TIMEOUT).await?;
    // Let the bounded output drain publish the CLI's structured terminal
    // diagnostic before the process is consumed by shutdown.
    let duplicate_diagnostic = wait_for_terminal_diagnostic(&loser_process).await;
    let loser_status = loser_process
        .shutdown(PROCESS_SHUTDOWN_TIMEOUT)
        .await
        .map_err(|error| HarnessError::Process(format!("joining duplicate owner CLI: {error}")))?;
    let duplicate_terminal_conflict = !loser_status.success() && duplicate_diagnostic;
    let actual_control_conflict_recorded =
        wait_for_control_conflict_delta(cluster, &control_conflicts_before).await?;
    if !actual_control_conflict_recorded {
        let _ = winner_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
        return Err(HarnessError::Process(
            "duplicate CLI did not produce exactly one authoritative control-conflict counter increment".into(),
        ));
    }
    if !duplicate_terminal_conflict {
        let _ = winner_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
        return Err(HarnessError::Process(
            "duplicate owner CLI exited successfully instead of terminally failing".into(),
        ));
    }
    let duplicate_reconnect_loop_absent =
        owner_stayed_same(cluster, original.tenant_id, original.id, &predecessor).await?;
    if !duplicate_reconnect_loop_absent {
        let _ = winner_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
        return Err(HarnessError::Process(
            "duplicate owner CLI changed the active complete owner token".into(),
        ));
    }

    let original_consumer_addr = consumer_addr_other_than(cluster, &predecessor.token.node_id)?;
    let mut original_stream = match wait_for_consumer_stream(
        original_consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &token,
        original.id,
        original_service,
        STARTUP_TIMEOUT,
    )
    .await
    {
        Ok(stream) => stream,
        Err(error) => {
            let _ = winner_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
            return Err(error);
        }
    };
    let original_owner_preserved = original_stream
        .round_trip(b"owner-contention-original", original_canary.as_bytes())
        .await
        .is_ok();
    if !original_owner_preserved {
        let _ = original_stream.close().await;
        let _ = winner_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
        return Err(HarnessError::Process(
            "original owner did not return its post-conflict canary".into(),
        ));
    }

    let sibling_process = spawn_cli("m7-owner-contention-sibling", &profile_sibling).await?;
    let sibling_owner =
        wait_for_owner(cluster, sibling.tenant_id, sibling.id, STARTUP_TIMEOUT).await?;
    if sibling_owner.token.tenant_id != sibling.tenant_id
        || sibling_owner.token.device_id != sibling.id
        || sibling_owner.token.node_id != "relay-c"
    {
        let _ = original_stream.close().await;
        let _ = winner_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
        let _ = sibling_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
        return Err(HarnessError::Process(
            "sibling owner did not remain on its distinct relay and scope".into(),
        ));
    }
    let sibling_consumer_addr = consumer_addr_other_than(cluster, &sibling_owner.token.node_id)?;
    let mut sibling_stream = match wait_for_consumer_stream(
        sibling_consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &token,
        sibling.id,
        sibling_service,
        STARTUP_TIMEOUT,
    )
    .await
    {
        Ok(stream) => stream,
        Err(error) => {
            let _ = original_stream.close().await;
            let _ = winner_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
            let _ = sibling_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
            return Err(error);
        }
    };
    let sibling_preserved = sibling_stream
        .round_trip(
            b"owner-contention-sibling-before-handoff",
            sibling_canary.as_bytes(),
        )
        .await
        .is_ok();
    if !sibling_preserved {
        let _ = original_stream.close().await;
        let _ = sibling_stream.close().await;
        let _ = winner_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
        let _ = sibling_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
        return Err(HarnessError::Process(
            "sibling stream did not survive the contention phase".into(),
        ));
    }

    original_stream.close().await?;
    winner_process
        .shutdown(PROCESS_SHUTDOWN_TIMEOUT)
        .await
        .map_err(|error| HarnessError::Process(format!("joining original owner CLI: {error}")))?;
    cluster
        .wait_for_no_owner(original.tenant_id, original.id)
        .await?;

    let successor_profile = write_device_profile(
        profile_root.path(),
        original.id,
        original_service,
        &original_canary,
        relay_c_device,
        &original.certificate.certificate_pem,
        &original.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    let successor_process = spawn_cli("m7-owner-contention-successor", &successor_profile).await?;
    let successor =
        wait_for_owner(cluster, original.tenant_id, original.id, SUCCESSOR_TIMEOUT).await?;
    let successor_higher_epoch = successor.token.tenant_id == predecessor.token.tenant_id
        && successor.token.device_id == predecessor.token.device_id
        && successor.token.node_id == "relay-c"
        && predecessor.token.epoch > HIGH_EPOCH_BASE
        && successor.token.epoch > predecessor.token.epoch
        && successor.token.session_id != predecessor.token.session_id
        && successor.token.boot_id != predecessor.token.boot_id;
    if !successor_higher_epoch {
        let _ = successor_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
        let _ = sibling_stream.close().await;
        let _ = sibling_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
        return Err(HarnessError::Process(
            "successor did not claim the same scope at a higher epoch".into(),
        ));
    }
    let successor_consumer_addr = consumer_addr_other_than(cluster, &successor.token.node_id)?;
    let mut successor_stream = match wait_for_consumer_stream(
        successor_consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &token,
        original.id,
        original_service,
        SUCCESSOR_TIMEOUT,
    )
    .await
    {
        Ok(stream) => stream,
        Err(error) => {
            let _ = successor_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
            let _ = sibling_stream.close().await;
            let _ = sibling_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
            return Err(error);
        }
    };
    let stale_cleanup_rejected = !cluster
        .catalog
        .release_owner(&predecessor.token)
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("releasing stale contention owner: {error}"))
        })?;
    let current_after_stale = cluster
        .catalog
        .current_owner(original.tenant_id, original.id, Utc::now())
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("reading successor after stale release: {error}"))
        })?;
    if current_after_stale.as_ref().map(|owner| &owner.token) != Some(&successor.token) {
        let _ = successor_stream.close().await;
        let _ = successor_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
        let _ = sibling_stream.close().await;
        let _ = sibling_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
        return Err(HarnessError::Process(
            "stale predecessor cleanup changed the successor owner".into(),
        ));
    }
    let sibling_after_stale = cluster
        .catalog
        .current_owner(sibling.tenant_id, sibling.id, Utc::now())
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("reading sibling after stale release: {error}"))
        })?;
    if sibling_after_stale.as_ref().map(|owner| &owner.token) != Some(&sibling_owner.token) {
        let _ = successor_stream.close().await;
        let _ = successor_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
        let _ = sibling_stream.close().await;
        let _ = sibling_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
        return Err(HarnessError::Process(
            "stale predecessor cleanup changed the sibling owner token".into(),
        ));
    }
    let successor_echo = successor_stream
        .round_trip(b"owner-contention-successor", original_canary.as_bytes())
        .await
        .is_ok();
    let sibling_after = sibling_stream
        .round_trip(
            b"owner-contention-sibling-after-handoff",
            sibling_canary.as_bytes(),
        )
        .await
        .is_ok();
    let _ = successor_stream.close().await;
    let _ = sibling_stream.close().await;
    successor_process
        .shutdown(PROCESS_SHUTDOWN_TIMEOUT)
        .await
        .map_err(|error| HarnessError::Process(format!("joining successor CLI: {error}")))?;
    sibling_process
        .shutdown(PROCESS_SHUTDOWN_TIMEOUT)
        .await
        .map_err(|error| HarnessError::Process(format!("joining sibling CLI: {error}")))?;
    if !sibling_after {
        return Err(HarnessError::Process(
            "sibling stream did not survive successor admission".into(),
        ));
    }

    Ok(OwnershipEvidence {
        relay_count: cluster.relays.len(),
        concurrent_launches,
        one_atomic_winner,
        actual_control_conflict_recorded,
        duplicate_terminal_conflict,
        duplicate_reconnect_loop_absent,
        original_owner_preserved,
        sibling_preserved: sibling_preserved && sibling_after,
        successor_higher_epoch,
        original_epoch: predecessor.token.epoch,
        successor_epoch: successor.token.epoch,
        catalog_generation_preserved: high_epoch_setup.catalog_generation_preserved,
        stale_cleanup_rejected,
        successor_echo,
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

#[derive(Clone, Debug)]
struct HighEpochSetup {
    seeded_epoch: u64,
    catalog_generation_preserved: bool,
}

/// Seed only the durable owner epoch for this run's fresh fixture namespace.
///
/// This is deliberately a test-only mutation: the namespace must be the
/// random `-fixture-<uuid>` lease opened by this harness, the production
/// catalog clone must refer to that same namespace, the active deployment
/// incarnation must be the fixture incarnation, and the scoped owner must be
/// absent.  The guarded Lua operation then accepts only the fresh epoch `0`,
/// writes a decimal value above the JavaScript-safe integer boundary, and
/// leaves catalog generation untouched.  Actual ownership still comes from
/// the real CLI claim path immediately afterwards.
async fn seed_high_owner_epoch(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    tenant_id: Uuid,
    device_id: Uuid,
) -> Result<HighEpochSetup> {
    let catalog = harness.production_catalog()?;
    let namespace = harness.redis.namespace();
    if catalog.namespace() != namespace || !namespace.contains("-fixture-") {
        return Err(HarnessError::InvalidInput(
            "owner-contention high-epoch mutation requires the harness-owned fixture namespace"
                .into(),
        ));
    }
    let current_owner = cluster
        .catalog
        .current_owner(tenant_id, device_id, Utc::now())
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("checking owner before high-epoch seed: {error}"))
        })?;
    if current_owner.is_some() {
        return Err(HarnessError::Process(
            "owner-contention high-epoch seed found an active owner".into(),
        ));
    }

    let prefix = format!("tunnel-catalog:{namespace}:");
    let owner_key = format!(
        "{prefix}coord:owner:{}:{tenant_id}:{device_id}",
        super::DEPLOYMENT_INCARCATION
    );
    let generation_key = format!("{prefix}meta:catalog_generation");
    let epoch_key = format!("{prefix}coord:epoch:{tenant_id}:{device_id}");
    let active_incarnation_key = format!("{prefix}meta:active_incarnation");
    let client = redis::Client::open(harness.redis.redis_url()).map_err(|error| {
        HarnessError::Redis(format!("opening high-epoch guard connection: {error}"))
    })?;
    let mut connection = timeout(
        HIGH_EPOCH_REDIS_TIMEOUT,
        client.get_multiplexed_async_connection(),
    )
    .await
    .map_err(|_| HarnessError::Timeout("connecting high-epoch guard to Redis timed out".into()))?
    .map_err(|error| {
        HarnessError::Redis(format!("connecting high-epoch guard to Redis: {error}"))
    })?;

    let mut command = redis::cmd("EVAL");
    command
        .arg(SEED_HIGH_EPOCH_SCRIPT)
        .arg(4)
        .arg(&owner_key)
        .arg(&generation_key)
        .arg(&epoch_key)
        .arg(&active_incarnation_key)
        .arg(HIGH_EPOCH_BASE.to_string())
        .arg(super::DEPLOYMENT_INCARCATION);
    let reply: Vec<String> = timeout(
        HIGH_EPOCH_REDIS_TIMEOUT,
        command.query_async(&mut connection),
    )
    .await
    .map_err(|_| HarnessError::Timeout("high-epoch Redis guard timed out".into()))?
    .map_err(|error| HarnessError::Redis(format!("running high-epoch Redis guard: {error}")))?;
    if reply.first().map(String::as_str) != Some("ok") {
        return Err(HarnessError::Process(format!(
            "high-epoch Redis guard refused fresh fixture state ({})",
            reply
                .first()
                .map(String::as_str)
                .unwrap_or("missing status")
        )));
    }
    let generation_before = reply.get(1).cloned().ok_or_else(|| {
        HarnessError::Redis("high-epoch Redis guard omitted catalog generation".into())
    })?;
    if reply.get(2).map(String::as_str) != Some("0") {
        return Err(HarnessError::Process(
            "high-epoch Redis guard did not confirm an initial zero epoch".into(),
        ));
    }

    let generation_after: Option<String> = timeout(
        HIGH_EPOCH_REDIS_TIMEOUT,
        redis::cmd("GET")
            .arg(&generation_key)
            .query_async(&mut connection),
    )
    .await
    .map_err(|_| HarnessError::Timeout("reading high-epoch catalog generation timed out".into()))?
    .map_err(|error| {
        HarnessError::Redis(format!("reading high-epoch catalog generation: {error}"))
    })?;
    if generation_after.as_deref() != Some(generation_before.as_str()) {
        return Err(HarnessError::Process(
            "high-epoch seed changed catalog generation metadata".into(),
        ));
    }
    let epoch_after: Option<String> = timeout(
        HIGH_EPOCH_REDIS_TIMEOUT,
        redis::cmd("GET")
            .arg(&epoch_key)
            .query_async(&mut connection),
    )
    .await
    .map_err(|_| HarnessError::Timeout("reading high-epoch owner epoch timed out".into()))?
    .map_err(|error| HarnessError::Redis(format!("reading high-epoch owner epoch: {error}")))?;
    let epoch_after = epoch_after.ok_or_else(|| {
        HarnessError::Redis("high-epoch owner epoch disappeared after guarded seed".into())
    })?;
    let seeded_epoch = epoch_after.parse::<u64>().map_err(|_| {
        HarnessError::Redis("high-epoch owner epoch was not a bounded decimal value".into())
    })?;
    if seeded_epoch != HIGH_EPOCH_BASE {
        return Err(HarnessError::Process(format!(
            "high-epoch seed stored {seeded_epoch}, expected {HIGH_EPOCH_BASE}"
        )));
    }
    Ok(HighEpochSetup {
        seeded_epoch,
        catalog_generation_preserved: true,
    })
}

async fn spawn_cli(name: &str, profile: &DeviceProfile) -> Result<ManagedProcess> {
    let binary = super::client_binary_path()?;
    ManagedProcess::spawn(
        name,
        ProcessSpec::new(binary)
            .arg("connect")
            .arg("--config")
            .arg(profile.config_path.to_string_lossy().to_string())
            .arg("--json"),
    )
    .await
}

async fn wait_for_process_exit(
    process: &mut ManagedProcess,
    budget: Duration,
) -> Result<std::process::ExitStatus> {
    let deadline = Instant::now() + budget;
    loop {
        if let Some(status) = process.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "duplicate owner CLI did not reach a terminal state".into(),
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_terminal_diagnostic(process: &ManagedProcess) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let output_bytes = process.stdout();
        let output = String::from_utf8_lossy(&output_bytes);
        if output.lines().any(is_owner_busy_diagnostic) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(POLL_INTERVAL).await;
    }
}

fn is_owner_busy_diagnostic(line: &str) -> bool {
    if line.len() > 8 * 1024 {
        return false;
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
        return false;
    };
    value.get("command").and_then(serde_json::Value::as_str) == Some("connect")
        && value.get("ok").and_then(serde_json::Value::as_bool) == Some(false)
        && value
            .pointer("/error/code")
            .and_then(serde_json::Value::as_str)
            == Some("OWNER_BUSY")
        && value
            .pointer("/error/retryable")
            .and_then(serde_json::Value::as_bool)
            == Some(false)
        && value
            .pointer("/error/message")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|message| {
                message.len() <= 256 && message.contains("stop it before starting another session")
            })
}

async fn shutdown_process(slot: &mut Option<ManagedProcess>, label: &str) -> Result<()> {
    if let Some(process) = slot.take() {
        process
            .shutdown(PROCESS_SHUTDOWN_TIMEOUT)
            .await
            .map_err(|error| HarnessError::Process(format!("joining {label}: {error}")))?;
    }
    Ok(())
}

async fn wait_for_consumer_stream(
    consumer_addr: SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
    budget: Duration,
) -> Result<ConsumerStream> {
    let deadline = Instant::now() + budget;
    loop {
        match open_consumer_stream(consumer_addr, server_ca_der, token, device_id, service_id).await
        {
            Ok(stream) => return Ok(stream),
            Err(_) if Instant::now() < deadline => sleep(POLL_INTERVAL).await,
            Err(error) => return Err(connect_failure_to_harness(error)),
        }
    }
}

async fn wait_for_owner(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    budget: Duration,
) -> Result<OwnerClaim> {
    let deadline = Instant::now() + budget;
    loop {
        match cluster
            .catalog
            .current_owner(tenant_id, device_id, Utc::now())
            .await
        {
            Ok(Some(owner)) => return Ok(owner),
            Ok(None) if Instant::now() >= deadline => {
                return Err(HarnessError::Timeout(format!(
                    "owner for device {device_id} was not established before its deadline"
                )));
            }
            Err(error) if Instant::now() >= deadline => {
                return Err(HarnessError::Redis(format!(
                    "reading owner for device {device_id}: {error}"
                )));
            }
            Ok(None) | Err(_) => sleep(POLL_INTERVAL).await,
        }
    }
}

async fn owner_stayed_same(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    expected: &OwnerClaim,
) -> Result<bool> {
    let deadline = Instant::now() + DUPLICATE_SETTLE_TIMEOUT;
    loop {
        let observed = cluster
            .catalog
            .current_owner(tenant_id, device_id, Utc::now())
            .await
            .map_err(|error| {
                HarnessError::Redis(format!("reading duplicate owner stability: {error}"))
            })?;
        if observed.as_ref().map(|owner| &owner.token) != Some(&expected.token) {
            return Ok(false);
        }
        if Instant::now() >= deadline {
            return Ok(true);
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn control_conflict_counts(cluster: &ProductionCluster) -> Result<BTreeMap<String, u64>> {
    let mut counts = BTreeMap::new();
    for relay in &cluster.relays {
        let snapshot = relay.snapshot().await?;
        counts.insert(
            relay.node_id.clone(),
            snapshot.control_registration_conflicts,
        );
    }
    Ok(counts)
}

async fn wait_for_control_conflict_delta(
    cluster: &ProductionCluster,
    before: &BTreeMap<String, u64>,
) -> Result<bool> {
    let deadline = Instant::now() + DUPLICATE_SETTLE_TIMEOUT;
    loop {
        let after = control_conflict_counts(cluster).await?;
        // Forwarded control can finish on either ingress relay or on the
        // existing owner's relay.  Accept exactly one monotonic increment
        // anywhere in this three-relay path, while rejecting missing,
        // decreasing, or repeated increments.
        let deltas = ["relay-a", "relay-b", "relay-c"].into_iter().map(|node| {
            after.get(node).and_then(|after_count| {
                before
                    .get(node)
                    .and_then(|before_count| after_count.checked_sub(*before_count))
            })
        });
        let exact = deltas.flatten().filter(|delta| *delta == 1).count() == 1
            && ["relay-a", "relay-b", "relay-c"].into_iter().all(|node| {
                after
                    .get(node)
                    .and_then(|after_count| {
                        before
                            .get(node)
                            .and_then(|before_count| after_count.checked_sub(*before_count))
                    })
                    .is_some_and(|delta| delta <= 1)
            });
        if exact {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        sleep(POLL_INTERVAL).await;
    }
}

fn device_addr(cluster: &ProductionCluster, node_id: &str) -> Result<SocketAddr> {
    cluster
        .relay(node_id)?
        .running
        .as_ref()
        .map(|relay| relay.device_addr)
        .ok_or_else(|| HarnessError::Process(format!("production relay {node_id} is not running")))
}

fn consumer_addr_other_than(
    cluster: &ProductionCluster,
    excluded_node: &str,
) -> Result<SocketAddr> {
    let relay = cluster
        .relays
        .iter()
        .find(|relay| relay.node_id != excluded_node)
        .ok_or_else(|| {
            HarnessError::Process(format!(
                "no consumer ingress relay remains outside owner {excluded_node}"
            ))
        })?;
    relay.consumer_addr()
}

#[cfg(test)]
mod diagnostic_tests {
    use super::is_owner_busy_diagnostic;

    #[test]
    fn owner_busy_requires_one_actionable_non_retryable_diagnostic() {
        let expected = serde_json::json!({
            "command": "connect",
            "ok": false,
            "error": {
                "code": "OWNER_BUSY",
                "retryable": false,
                "message": "device already has an active owner; stop it before starting another session"
            }
        });
        assert!(is_owner_busy_diagnostic(&expected.to_string()));
        for (path, replacement) in [
            ("/error/code", serde_json::json!("TRANSPORT_ERROR")),
            ("/error/retryable", serde_json::json!(true)),
            ("/command", serde_json::json!("status")),
            ("/ok", serde_json::json!(true)),
            ("/error/message", serde_json::json!("unclassified failure")),
        ] {
            let mut rejected = expected.clone();
            *rejected.pointer_mut(path).unwrap() = replacement;
            assert!(!is_owner_busy_diagnostic(&rejected.to_string()), "{path}");
        }
        assert!(!is_owner_busy_diagnostic("not JSON"));
        assert!(!is_owner_busy_diagnostic(&format!(
            "{expected}\n{expected}"
        )));
    }
}
