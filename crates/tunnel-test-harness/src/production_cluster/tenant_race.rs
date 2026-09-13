//! Concurrent same-identifier tenant isolation and the duplicate exact-scope
//! owner race, proved inside one production three-relay run.
//!
//! The matrix records that the production gate alone is insufficient evidence
//! for tenant isolation when the tenant-B device is offline or when a `503` is
//! accepted in place of a routed canary.  Both properties in this module are
//! therefore observed while both tenant sessions hold live complete owner
//! tokens at the identical device and service UUIDs:
//!
//! * the two tenants exchange exact, distinct canaries through the same route
//!   identity, on separated owner nodes and sessions, and neither route ever
//!   returns the other tenant's canary; and
//! * two real CLI processes race for one tenant's exact owner scope while the
//!   other tenant's same-identifier session stays online, so a scope key that
//!   dropped its tenant qualifier would evict the surviving tenant instead of
//!   leaving it untouched.
//!
//! Every field below is a count, a boolean or an epoch number.  No payload,
//! credential or canary byte is recorded.

use super::ownership::{
    HIGH_EPOCH_BASE, PROCESS_SHUTDOWN_TIMEOUT, consumer_addr_other_than,
    control_conflict_count_total, device_addr, is_owner_busy_diagnostic, owner_stayed_same,
    spawn_cli, wait_for_consumer_stream, wait_for_owner, wait_for_process_exit,
};
use super::{ProductionCluster, RunningHarness, STARTUP_TIMEOUT};
use crate::acceptance::helpers::write_device_profile;
use crate::fixture::DeviceFixture;
use crate::{HarnessError, Result};
use chrono::Utc;
use std::time::{Duration, Instant};
use tempfile::tempdir;
use tokio::time::sleep;
use tunnel_catalog::OwnerClaim;
use uuid::Uuid;

const RACE_TERMINAL_TIMEOUT: Duration = Duration::from_secs(12);
const RACE_SETTLE_WINDOW: Duration = Duration::from_secs(2);
const RACE_SUCCESSOR_TIMEOUT: Duration = Duration::from_secs(20);
const DIAGNOSTIC_DRAIN_TIMEOUT: Duration = Duration::from_secs(8);

/// Payload-free evidence that two same-identifier tenant sessions were live at
/// the same instants with exact, distinct canaries and separated owners.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcurrentTenantIsolationEvidence {
    /// Both tenant fixtures enrolled the identical device UUID.
    pub shared_device_identifier: bool,
    /// Both tenant fixtures enrolled the identical service UUID.
    pub shared_service_identifier: bool,
    /// The two sessions belong to two distinct Redis tenant scopes.
    pub distinct_tenant_scopes: bool,
    /// The two device certificates are distinct enrolled credentials.
    pub distinct_device_credentials: bool,
    /// Number of instants at which both tenants simultaneously held a live
    /// complete owner token for the shared device identifier.
    pub concurrent_owner_samples: usize,
    /// The two concurrent owner tokens were committed on distinct relay nodes.
    pub distinct_owner_nodes: bool,
    /// The two concurrent owner tokens carry distinct session identifiers.
    pub distinct_owner_sessions: bool,
    /// Exact tenant-A canary matches observed while tenant B was online.
    pub tenant_a_exact_canaries: usize,
    /// Exact tenant-B canary matches observed while tenant A was online.
    pub tenant_b_exact_canaries: usize,
    /// The two tenants' canary byte strings differ.
    pub distinct_canaries: bool,
    /// Neither tenant's route ever returned the other tenant's canary.
    pub cross_tenant_canary_absent: bool,
    /// Committed scheduled replacement generations observed for tenant A.
    pub tenant_a_rotations: u64,
    /// Committed scheduled replacement generations observed for tenant B.
    pub tenant_b_rotations: u64,
}

/// Validate the concurrent same-identifier isolation contract.
///
/// `required_rotations` is the production gate's real rotation bound, which
/// both tenants must reach while the other tenant is online.
pub fn validate_concurrent_tenant_isolation_evidence(
    evidence: &ConcurrentTenantIsolationEvidence,
    required_rotations: u64,
) -> Result<()> {
    let required = [
        (
            "shared_device_identifier",
            evidence.shared_device_identifier,
        ),
        (
            "shared_service_identifier",
            evidence.shared_service_identifier,
        ),
        ("distinct_tenant_scopes", evidence.distinct_tenant_scopes),
        (
            "distinct_device_credentials",
            evidence.distinct_device_credentials,
        ),
        ("distinct_owner_nodes", evidence.distinct_owner_nodes),
        ("distinct_owner_sessions", evidence.distinct_owner_sessions),
        ("distinct_canaries", evidence.distinct_canaries),
        (
            "cross_tenant_canary_absent",
            evidence.cross_tenant_canary_absent,
        ),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "concurrent tenant isolation gate {name} was false"
        )));
    }
    let minimums = [
        (
            "concurrent_owner_samples",
            evidence.concurrent_owner_samples as u64,
            2,
        ),
        (
            "tenant_a_exact_canaries",
            evidence.tenant_a_exact_canaries as u64,
            2,
        ),
        (
            "tenant_b_exact_canaries",
            evidence.tenant_b_exact_canaries as u64,
            2,
        ),
        (
            "tenant_a_rotations",
            evidence.tenant_a_rotations,
            required_rotations,
        ),
        (
            "tenant_b_rotations",
            evidence.tenant_b_rotations,
            required_rotations,
        ),
    ];
    if let Some((name, observed, minimum)) = minimums
        .into_iter()
        .find(|(_, observed, minimum)| observed < minimum)
    {
        return Err(HarnessError::Process(format!(
            "concurrent tenant isolation {name}={observed} is below required minimum {minimum}"
        )));
    }
    Ok(())
}

/// Payload-free evidence from the duplicate exact-scope owner race observed
/// while the same-identifier tenant session stayed online.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerRaceEvidence {
    /// Both exact-scope CLI processes were spawned before any readiness or
    /// owner observation occurred.
    pub concurrent_launches: bool,
    /// Exactly one of the two racing claims became the Redis owner.
    pub one_atomic_winner: bool,
    /// Total relay control-registration conflict increments across the three
    /// relays while the race resolved.  Exactly one authoritative rejection is
    /// required; a reconnect storm would record more.
    pub control_conflict_delta: u64,
    /// The same total after a further settle window, proving the loser did not
    /// retry once it had terminated.
    pub control_conflict_delta_after_settle: u64,
    /// The losing CLI emitted the exact non-retryable `OWNER_BUSY` terminal
    /// diagnostic on its structured output.
    pub loser_terminal_owner_busy: bool,
    /// The losing CLI exited with a non-success status inside its bound.
    pub loser_exit_non_success: bool,
    /// The winner's complete owner token was unchanged across the settle
    /// window after the loser terminated.
    pub winner_token_unchanged: bool,
    /// The winning owner returned its exact canary after the rejection.
    pub winner_canary_preserved: bool,
    /// The racing tenant's independent sibling device kept its own owner and
    /// returned its exact canary.
    pub tenant_sibling_preserved: bool,
    /// The other tenant's session at the identical device/service UUIDs kept
    /// its unchanged complete owner token across the whole race.
    pub same_identifier_tenant_owner_unchanged: bool,
    /// That same-identifier tenant also returned its exact canary after the
    /// race resolved.
    pub same_identifier_tenant_canary_preserved: bool,
    /// The winner's retained durable epoch.
    pub winner_epoch: u64,
    /// The successor's strictly higher retained durable epoch.
    pub successor_epoch: u64,
    /// The successor claimed the same scope at a strictly higher epoch with a
    /// distinct session and boot identity.
    pub successor_higher_epoch: bool,
    /// Both retained epochs stayed above the JavaScript-safe integer bound.
    pub epochs_above_js_safe_bound: bool,
    /// Releasing the loser-era predecessor token after successor admission was
    /// refused by compare-release.
    pub stale_cleanup_rejected: bool,
    /// The successor returned its exact canary through a public route.
    pub successor_canary: bool,
    /// Wall-clock milliseconds spent in the bounded race phase.
    pub elapsed_ms: u64,
}

/// Validate the duplicate exact-scope owner race contract.
pub fn validate_owner_race_evidence(evidence: &OwnerRaceEvidence) -> Result<()> {
    let required = [
        ("concurrent_launches", evidence.concurrent_launches),
        ("one_atomic_winner", evidence.one_atomic_winner),
        (
            "loser_terminal_owner_busy",
            evidence.loser_terminal_owner_busy,
        ),
        ("loser_exit_non_success", evidence.loser_exit_non_success),
        ("winner_token_unchanged", evidence.winner_token_unchanged),
        ("winner_canary_preserved", evidence.winner_canary_preserved),
        (
            "tenant_sibling_preserved",
            evidence.tenant_sibling_preserved,
        ),
        (
            "same_identifier_tenant_owner_unchanged",
            evidence.same_identifier_tenant_owner_unchanged,
        ),
        (
            "same_identifier_tenant_canary_preserved",
            evidence.same_identifier_tenant_canary_preserved,
        ),
        ("successor_higher_epoch", evidence.successor_higher_epoch),
        (
            "epochs_above_js_safe_bound",
            evidence.epochs_above_js_safe_bound,
        ),
        ("stale_cleanup_rejected", evidence.stale_cleanup_rejected),
        ("successor_canary", evidence.successor_canary),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "duplicate owner race gate {name} was false"
        )));
    }
    if evidence.control_conflict_delta != 1 {
        return Err(HarnessError::Process(format!(
            "duplicate owner race control_conflict_delta={} authoritative control conflicts, expected exactly one",
            evidence.control_conflict_delta
        )));
    }
    if evidence.control_conflict_delta_after_settle != 1 {
        return Err(HarnessError::Process(format!(
            "duplicate owner race control_conflict_delta_after_settle={} grew past one after the settle window, which is a reconnect storm",
            evidence.control_conflict_delta_after_settle
        )));
    }
    if evidence.successor_epoch <= evidence.winner_epoch {
        return Err(HarnessError::Process(format!(
            "duplicate owner race successor epoch {} did not exceed winner epoch {}",
            evidence.successor_epoch, evidence.winner_epoch
        )));
    }
    if evidence.winner_epoch <= HIGH_EPOCH_BASE {
        return Err(HarnessError::Process(format!(
            "duplicate owner race winner epoch {} was not retained above the JavaScript-safe bound {HIGH_EPOCH_BASE}",
            evidence.winner_epoch
        )));
    }
    Ok(())
}

/// Inputs for one duplicate exact-scope owner race.
pub(super) struct OwnerRaceInputs<'a> {
    /// The device whose exact owner scope is contested.  It must currently
    /// have no owner.
    pub(super) contested: &'a DeviceFixture,
    /// The contested device's echo service UUID.
    pub(super) contested_service: Uuid,
    /// The contested device's exact expected canary.
    pub(super) contested_canary: &'a str,
    /// An independent device in the same tenant that must survive.
    pub(super) sibling: &'a DeviceFixture,
    /// The sibling's echo service UUID.
    pub(super) sibling_service: Uuid,
    /// The sibling's exact expected canary.
    pub(super) sibling_canary: &'a str,
    /// The other tenant's still-online owner token at the identical device and
    /// service UUIDs.
    pub(super) same_identifier_owner: &'a OwnerClaim,
    /// The other tenant's echo service UUID, which is the identical UUID.
    pub(super) same_identifier_service: Uuid,
    /// The other tenant's exact expected canary.
    pub(super) same_identifier_canary: &'a str,
    /// An authorized consumer token for the other tenant.
    pub(super) same_identifier_token: &'a str,
    /// An authorized consumer token for the contested tenant.
    pub(super) token: &'a str,
}

/// Race two real CLI processes for one exact owner scope while the
/// same-identifier tenant session stays online.
pub(super) async fn race_exact_owner_scope(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    inputs: OwnerRaceInputs<'_>,
) -> Result<OwnerRaceEvidence> {
    let started = Instant::now();
    let contested = inputs.contested;
    let sibling = inputs.sibling;
    if cluster
        .catalog
        .current_owner(contested.tenant_id, contested.id, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("reading pre-race owner: {error}")))?
        .is_some()
    {
        return Err(HarnessError::Process(
            "duplicate owner race started with an existing owner for the contested scope".into(),
        ));
    }

    let profile_root = tempdir().map_err(HarnessError::Io)?;
    // The two contenders enter two different relay device listeners, and
    // neither is the relay hosting the surviving same-identifier tenant's
    // control socket.  The Redis claim is therefore the only authority that
    // can pick a winner, and the surviving tenant is not collaterally
    // involved in either contender's ingress.
    let same_identifier_node = inputs.same_identifier_owner.token.node_id.as_str();
    let contender_nodes = ["relay-a", "relay-b", "relay-c"]
        .into_iter()
        .filter(|node| *node != same_identifier_node)
        .collect::<Vec<_>>();
    let [first_node, second_node] = contender_nodes.as_slice() else {
        return Err(HarnessError::Process(format!(
            "duplicate owner race needs two relays outside the surviving owner node {same_identifier_node}"
        )));
    };
    let first_profile = write_device_profile(
        profile_root.path(),
        contested.id,
        inputs.contested_service,
        inputs.contested_canary,
        device_addr(cluster, first_node)?,
        &contested.certificate.certificate_pem,
        &contested.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    let second_profile = write_device_profile(
        profile_root.path(),
        contested.id,
        inputs.contested_service,
        inputs.contested_canary,
        device_addr(cluster, second_node)?,
        &contested.certificate.certificate_pem,
        &contested.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;

    let conflicts_before = control_conflict_count_total(cluster).await?;
    // Both children exist before any readiness, status or owner observation.
    let (first_spawn, second_spawn) = tokio::join!(
        spawn_cli("m7-tenant-race-first", &first_profile),
        spawn_cli("m7-tenant-race-second", &second_profile),
    );
    let mut first = match first_spawn {
        Ok(process) => Some(process),
        Err(error) => {
            if let Ok(process) = second_spawn {
                let _ = process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
            }
            return Err(error);
        }
    };
    let mut second = match second_spawn {
        Ok(process) => Some(process),
        Err(error) => {
            if let Some(process) = first.take() {
                let _ = process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
            }
            return Err(error);
        }
    };
    let concurrent_launches = true;

    let winner =
        match wait_for_owner(cluster, contested.tenant_id, contested.id, STARTUP_TIMEOUT).await {
            Ok(owner) => owner,
            Err(error) => {
                shutdown_slot(&mut first).await;
                shutdown_slot(&mut second).await;
                return Err(error);
            }
        };
    if winner.token.tenant_id != contested.tenant_id
        || winner.token.device_id != contested.id
        || !matches!(winner.token.node_id.as_str(), node if node == *first_node || node == *second_node)
    {
        shutdown_slot(&mut first).await;
        shutdown_slot(&mut second).await;
        return Err(HarnessError::Process(
            "duplicate owner race winner reported an unexpected scope or relay".into(),
        ));
    }
    // One complete owner token exists for two concurrent exact-scope claims.
    let one_atomic_winner = true;
    let winner_is_first = winner.token.node_id == *first_node;
    let winner_process = if winner_is_first {
        first.take()
    } else {
        second.take()
    }
    .ok_or_else(|| HarnessError::Process("duplicate owner race winner was not retained".into()))?;
    let mut loser_process = if winner_is_first {
        second.take()
    } else {
        first.take()
    }
    .ok_or_else(|| HarnessError::Process("duplicate owner race loser was not retained".into()))?;

    // A loser that outlives this bound would be supervising or reconnecting.
    let loser_exit = match wait_for_process_exit(&mut loser_process, RACE_TERMINAL_TIMEOUT).await {
        Ok(status) => status,
        Err(error) => {
            let _ = loser_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
            let _ = winner_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
            return Err(error);
        }
    };
    // Drain the loser's bounded structured output for the exact terminal
    // diagnostic.  The assertion itself is unchanged; this gate simply allows a
    // longer drain window than the component gate, because the production run
    // reaches this phase on a busy machine and a short window turns a real pass
    // into a timing failure.
    let loser_terminal_owner_busy =
        wait_for_owner_busy_diagnostic(&loser_process, DIAGNOSTIC_DRAIN_TIMEOUT).await;
    let loser_exit_non_success = !loser_exit.success();
    // Record only the loser's structured error codes, never its output, so a
    // failure names what the CLI actually reported instead of a bare false.
    let loser_codes = structured_error_codes(&loser_process);
    loser_process
        .shutdown(PROCESS_SHUTDOWN_TIMEOUT)
        .await
        .map_err(|error| {
            HarnessError::Process(format!("joining duplicate owner race loser: {error}"))
        })?;
    if !loser_terminal_owner_busy {
        let _ = winner_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
        return Err(HarnessError::Process(format!(
            "duplicate owner race loser did not emit the exact non-retryable OWNER_BUSY terminal diagnostic; exit_non_success={loser_exit_non_success}, observed error codes=[{}]",
            loser_codes.join(",")
        )));
    }

    let conflicts_after = control_conflict_count_total(cluster).await?;
    let control_conflict_delta = conflicts_after.saturating_sub(conflicts_before);
    // Hold the scope open for a further window: a silent reconnect loop in the
    // terminated loser's place would keep incrementing the relay counter.
    sleep(RACE_SETTLE_WINDOW).await;
    let control_conflict_delta_after_settle = control_conflict_count_total(cluster)
        .await?
        .saturating_sub(conflicts_before);
    let winner_token_unchanged =
        owner_stayed_same(cluster, contested.tenant_id, contested.id, &winner).await?;

    let winner_canary_preserved = match probe_exact_canary(
        cluster,
        harness,
        &winner.token.node_id,
        inputs.token,
        contested.id,
        inputs.contested_service,
        b"tenant-race-winner",
        inputs.contested_canary,
    )
    .await
    {
        Ok(result) => result,
        Err(error) => {
            let _ = winner_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
            return Err(error);
        }
    };

    // The identical device/service UUID tenant was never part of this race.
    // A scope key that lost its tenant qualifier would have evicted it.
    let same_identifier_tenant_owner_unchanged = cluster
        .catalog
        .current_owner(
            inputs.same_identifier_owner.token.tenant_id,
            inputs.same_identifier_owner.token.device_id,
            Utc::now(),
        )
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("reading same-identifier tenant owner: {error}"))
        })?
        .as_ref()
        .map(|owner| &owner.token)
        == Some(&inputs.same_identifier_owner.token);
    // The surviving tenant must also still serve its own exact canary through
    // a fresh public route at the identical device and service UUIDs.
    let same_identifier_tenant_canary_preserved = probe_exact_canary(
        cluster,
        harness,
        same_identifier_node,
        inputs.same_identifier_token,
        inputs.same_identifier_owner.token.device_id,
        inputs.same_identifier_service,
        b"tenant-race-same-identifier",
        inputs.same_identifier_canary,
    )
    .await?;

    // An independent device in the contested tenant must also survive.
    let sibling_profile = write_device_profile(
        profile_root.path(),
        sibling.id,
        inputs.sibling_service,
        inputs.sibling_canary,
        device_addr(cluster, second_node)?,
        &sibling.certificate.certificate_pem,
        &sibling.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    let sibling_process = match spawn_cli("m7-tenant-race-sibling", &sibling_profile).await {
        Ok(process) => process,
        Err(error) => {
            let _ = winner_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
            return Err(error);
        }
    };
    let sibling_owner =
        match wait_for_owner(cluster, sibling.tenant_id, sibling.id, STARTUP_TIMEOUT).await {
            Ok(owner) => owner,
            Err(error) => {
                let _ = sibling_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
                let _ = winner_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
                return Err(error);
            }
        };
    let tenant_sibling_preserved = sibling_owner.token.device_id == sibling.id
        && sibling_owner.token.tenant_id == sibling.tenant_id
        && probe_exact_canary(
            cluster,
            harness,
            &sibling_owner.token.node_id,
            inputs.token,
            sibling.id,
            inputs.sibling_service,
            b"tenant-race-sibling",
            inputs.sibling_canary,
        )
        .await?;

    // Release the winner's scope through a real process exit, then admit a
    // successor on a third relay.
    winner_process
        .shutdown(PROCESS_SHUTDOWN_TIMEOUT)
        .await
        .map_err(|error| {
            HarnessError::Process(format!("joining duplicate owner race winner: {error}"))
        })?;
    cluster
        .wait_for_no_owner(contested.tenant_id, contested.id)
        .await?;
    // Admit the successor on the contender relay that did NOT win, so the
    // successor's relay incarnation is genuinely a different node and boot
    // identity rather than the winner's own relay restarting the same scope.
    let successor_node = if winner_is_first {
        second_node
    } else {
        first_node
    };
    let successor_profile = write_device_profile(
        profile_root.path(),
        contested.id,
        inputs.contested_service,
        inputs.contested_canary,
        device_addr(cluster, successor_node)?,
        &contested.certificate.certificate_pem,
        &contested.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    let successor_process = match spawn_cli("m7-tenant-race-successor", &successor_profile).await {
        Ok(process) => process,
        Err(error) => {
            let _ = sibling_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
            return Err(error);
        }
    };
    let successor = match wait_for_owner(
        cluster,
        contested.tenant_id,
        contested.id,
        RACE_SUCCESSOR_TIMEOUT,
    )
    .await
    {
        Ok(owner) => owner,
        Err(error) => {
            let _ = successor_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
            let _ = sibling_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
            return Err(error);
        }
    };
    // The successor holds the identical tenant/device scope at a strictly
    // higher retained epoch, on the expected distinct relay node, with a
    // distinct session and boot identity.  Pinning the node here keeps the
    // boot-identity clause meaningful: a successor admitted on the winner's own
    // relay would share its boot id and could never satisfy it.
    let successor_higher_epoch = successor.token.tenant_id == winner.token.tenant_id
        && successor.token.device_id == winner.token.device_id
        && successor.token.node_id == *successor_node
        && successor.token.node_id != winner.token.node_id
        && successor.token.epoch > winner.token.epoch
        && successor.token.session_id != winner.token.session_id
        && successor.token.boot_id != winner.token.boot_id;
    let epochs_above_js_safe_bound =
        winner.token.epoch > HIGH_EPOCH_BASE && successor.token.epoch > HIGH_EPOCH_BASE;

    // Compare-release with the superseded complete token must be refused and
    // must not disturb the successor or the same-identifier tenant.
    let stale_release = cluster
        .catalog
        .release_owner(&winner.token)
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("releasing superseded race owner: {error}"))
        })?;
    let stale_cleanup_rejected = !stale_release;
    let successor_after_stale = cluster
        .catalog
        .current_owner(contested.tenant_id, contested.id, Utc::now())
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("reading successor after stale release: {error}"))
        })?;
    if successor_after_stale.as_ref().map(|owner| &owner.token) != Some(&successor.token) {
        let _ = successor_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
        let _ = sibling_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
        return Err(HarnessError::Process(
            "stale race cleanup changed the successor owner token".into(),
        ));
    }
    let same_identifier_after_stale = cluster
        .catalog
        .current_owner(
            inputs.same_identifier_owner.token.tenant_id,
            inputs.same_identifier_owner.token.device_id,
            Utc::now(),
        )
        .await
        .map_err(|error| {
            HarnessError::Redis(format!(
                "reading same-identifier tenant after stale release: {error}"
            ))
        })?;
    if same_identifier_after_stale
        .as_ref()
        .map(|owner| &owner.token)
        != Some(&inputs.same_identifier_owner.token)
    {
        let _ = successor_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
        let _ = sibling_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
        return Err(HarnessError::Process(
            "stale race cleanup changed the same-identifier tenant's owner token".into(),
        ));
    }

    let successor_canary = probe_exact_canary(
        cluster,
        harness,
        &successor.token.node_id,
        inputs.token,
        contested.id,
        inputs.contested_service,
        b"tenant-race-successor",
        inputs.contested_canary,
    )
    .await?;
    successor_process
        .shutdown(PROCESS_SHUTDOWN_TIMEOUT)
        .await
        .map_err(|error| {
            HarnessError::Process(format!("joining duplicate owner race successor: {error}"))
        })?;
    sibling_process
        .shutdown(PROCESS_SHUTDOWN_TIMEOUT)
        .await
        .map_err(|error| {
            HarnessError::Process(format!("joining duplicate owner race sibling: {error}"))
        })?;
    cluster
        .wait_for_no_owner(contested.tenant_id, contested.id)
        .await?;

    Ok(OwnerRaceEvidence {
        concurrent_launches,
        one_atomic_winner,
        control_conflict_delta,
        control_conflict_delta_after_settle,
        loser_terminal_owner_busy,
        loser_exit_non_success,
        winner_token_unchanged,
        winner_canary_preserved,
        tenant_sibling_preserved,
        same_identifier_tenant_owner_unchanged,
        same_identifier_tenant_canary_preserved,
        winner_epoch: winner.token.epoch,
        successor_epoch: successor.token.epoch,
        successor_higher_epoch,
        epochs_above_js_safe_bound,
        stale_cleanup_rejected,
        successor_canary,
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

/// Poll a terminated CLI's bounded structured output for the exact
/// non-retryable `OWNER_BUSY` terminal diagnostic.
async fn wait_for_owner_busy_diagnostic(process: &crate::ManagedProcess, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        let bytes = process.stdout();
        if String::from_utf8_lossy(&bytes)
            .lines()
            .any(is_owner_busy_diagnostic)
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(50)).await;
    }
}

/// Collect the bounded `error.code` strings from a CLI's structured output.
///
/// Only the short code tokens are returned.  Messages, payloads and any other
/// field are deliberately discarded so a failing gate can name what the client
/// reported without recording its output.
fn structured_error_codes(process: &crate::ManagedProcess) -> Vec<String> {
    let bytes = process.stdout();
    let text = String::from_utf8_lossy(&bytes);
    let mut codes = Vec::new();
    for line in text.lines().take(256) {
        if line.len() > 8 * 1024 {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if let Some(code) = value
            .pointer("/error/code")
            .and_then(serde_json::Value::as_str)
            && code.len() <= 64
            && !codes.iter().any(|seen| seen == code)
        {
            codes.push(code.to_owned());
        }
    }
    codes
}

async fn shutdown_slot(slot: &mut Option<crate::ManagedProcess>) {
    if let Some(process) = slot.take() {
        let _ = process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
    }
}

/// Open one public consumer stream through an ingress that is not the owner
/// relay and require the exact expected canary.
#[allow(clippy::too_many_arguments)]
async fn probe_exact_canary(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    owner_node: &str,
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
    record: &[u8],
    expected_canary: &str,
) -> Result<bool> {
    let ingress = consumer_addr_other_than(cluster, owner_node)?;
    let mut stream = wait_for_consumer_stream(
        ingress,
        &harness.pki.server_ca.certificate_der,
        token,
        device_id,
        service_id,
        STARTUP_TIMEOUT,
    )
    .await?;
    let matched = stream
        .round_trip(record, expected_canary.as_bytes())
        .await
        .is_ok();
    let _ = stream.close().await;
    Ok(matched)
}

#[cfg(test)]
mod tests {
    use super::{
        ConcurrentTenantIsolationEvidence, HIGH_EPOCH_BASE, OwnerRaceEvidence,
        validate_concurrent_tenant_isolation_evidence, validate_owner_race_evidence,
    };
    use crate::acceptance_test_support::{assert_failed, assert_rejected};

    const REQUIRED_ROTATIONS: u64 = 3;

    fn valid_isolation() -> ConcurrentTenantIsolationEvidence {
        ConcurrentTenantIsolationEvidence {
            shared_device_identifier: true,
            shared_service_identifier: true,
            distinct_tenant_scopes: true,
            distinct_device_credentials: true,
            concurrent_owner_samples: 2,
            distinct_owner_nodes: true,
            distinct_owner_sessions: true,
            tenant_a_exact_canaries: 2,
            tenant_b_exact_canaries: 2,
            distinct_canaries: true,
            cross_tenant_canary_absent: true,
            tenant_a_rotations: REQUIRED_ROTATIONS,
            tenant_b_rotations: REQUIRED_ROTATIONS,
        }
    }

    #[test]
    fn valid_isolation_evidence_is_accepted() {
        validate_concurrent_tenant_isolation_evidence(&valid_isolation(), REQUIRED_ROTATIONS)
            .expect("baseline concurrent tenant isolation evidence must pass");
    }

    #[test]
    fn isolation_evidence_rejects_each_required_false_gate() {
        type Disable = (&'static str, fn(&mut ConcurrentTenantIsolationEvidence));
        let gates: [Disable; 8] = [
            ("shared_device_identifier", |e| {
                e.shared_device_identifier = false
            }),
            ("shared_service_identifier", |e| {
                e.shared_service_identifier = false
            }),
            ("distinct_tenant_scopes", |e| {
                e.distinct_tenant_scopes = false
            }),
            ("distinct_device_credentials", |e| {
                e.distinct_device_credentials = false
            }),
            ("distinct_owner_nodes", |e| e.distinct_owner_nodes = false),
            ("distinct_owner_sessions", |e| {
                e.distinct_owner_sessions = false
            }),
            ("distinct_canaries", |e| e.distinct_canaries = false),
            ("cross_tenant_canary_absent", |e| {
                e.cross_tenant_canary_absent = false
            }),
        ];
        for (name, disable) in gates {
            let mut evidence = valid_isolation();
            disable(&mut evidence);
            assert_rejected(
                validate_concurrent_tenant_isolation_evidence(&evidence, REQUIRED_ROTATIONS),
                name,
            );
        }
    }

    #[test]
    fn isolation_evidence_rejects_insufficient_counts() {
        type Mutate = fn(&mut ConcurrentTenantIsolationEvidence);
        // An offline tenant-B device or an accepted 503 in place of a routed
        // canary shows up here as a missing concurrent sample or a missing
        // exact canary; both must fail.
        let counts: [Mutate; 5] = [
            |e| e.concurrent_owner_samples = 1,
            |e| e.tenant_a_exact_canaries = 1,
            |e| e.tenant_b_exact_canaries = 1,
            |e| e.tenant_a_rotations = REQUIRED_ROTATIONS - 1,
            |e| e.tenant_b_rotations = REQUIRED_ROTATIONS - 1,
        ];
        for mutate in counts {
            let mut evidence = valid_isolation();
            mutate(&mut evidence);
            assert_failed(validate_concurrent_tenant_isolation_evidence(
                &evidence,
                REQUIRED_ROTATIONS,
            ));
        }
    }

    fn valid_race() -> OwnerRaceEvidence {
        OwnerRaceEvidence {
            concurrent_launches: true,
            one_atomic_winner: true,
            control_conflict_delta: 1,
            control_conflict_delta_after_settle: 1,
            loser_terminal_owner_busy: true,
            loser_exit_non_success: true,
            winner_token_unchanged: true,
            winner_canary_preserved: true,
            tenant_sibling_preserved: true,
            same_identifier_tenant_owner_unchanged: true,
            same_identifier_tenant_canary_preserved: true,
            winner_epoch: HIGH_EPOCH_BASE + 1,
            successor_epoch: HIGH_EPOCH_BASE + 2,
            successor_higher_epoch: true,
            epochs_above_js_safe_bound: true,
            stale_cleanup_rejected: true,
            successor_canary: true,
            elapsed_ms: 1,
        }
    }

    #[test]
    fn valid_race_evidence_is_accepted() {
        validate_owner_race_evidence(&valid_race())
            .expect("baseline duplicate owner race evidence must pass");
    }

    #[test]
    fn race_evidence_rejects_each_required_false_gate() {
        type Disable = (&'static str, fn(&mut OwnerRaceEvidence));
        let gates: [Disable; 13] = [
            ("concurrent_launches", |e| e.concurrent_launches = false),
            ("one_atomic_winner", |e| e.one_atomic_winner = false),
            ("loser_terminal_owner_busy", |e| {
                e.loser_terminal_owner_busy = false
            }),
            ("loser_exit_non_success", |e| {
                e.loser_exit_non_success = false
            }),
            ("winner_token_unchanged", |e| {
                e.winner_token_unchanged = false
            }),
            ("winner_canary_preserved", |e| {
                e.winner_canary_preserved = false
            }),
            ("tenant_sibling_preserved", |e| {
                e.tenant_sibling_preserved = false
            }),
            ("same_identifier_tenant_owner_unchanged", |e| {
                e.same_identifier_tenant_owner_unchanged = false
            }),
            ("same_identifier_tenant_canary_preserved", |e| {
                e.same_identifier_tenant_canary_preserved = false
            }),
            ("successor_higher_epoch", |e| {
                e.successor_higher_epoch = false
            }),
            ("epochs_above_js_safe_bound", |e| {
                e.epochs_above_js_safe_bound = false
            }),
            ("stale_cleanup_rejected", |e| {
                e.stale_cleanup_rejected = false
            }),
            ("successor_canary", |e| e.successor_canary = false),
        ];
        for (name, disable) in gates {
            let mut evidence = valid_race();
            disable(&mut evidence);
            assert_rejected(validate_owner_race_evidence(&evidence), name);
        }
    }

    #[test]
    fn race_evidence_rejects_conflict_and_epoch_mutations() {
        type Mutate = fn(&mut OwnerRaceEvidence);
        let mutations: [Mutate; 7] = [
            // A missing authoritative rejection is not evidence of a fenced
            // loser; a generic transport failure would land here.
            |e| e.control_conflict_delta = 0,
            // More than one increment is a reconnect storm.
            |e| e.control_conflict_delta = 2,
            |e| e.control_conflict_delta_after_settle = 2,
            // Equal or lower successor epochs break the retention rule.
            |e| e.successor_epoch = e.winner_epoch,
            |e| e.successor_epoch = e.winner_epoch - 1,
            // An epoch that fell back below the JavaScript-safe bound means
            // the durable counter was not retained.
            |e| {
                e.winner_epoch = 1;
                e.successor_epoch = 2;
            },
            |e| {
                e.winner_epoch = HIGH_EPOCH_BASE;
                e.successor_epoch = HIGH_EPOCH_BASE + 1;
            },
        ];
        for mutate in mutations {
            let mut evidence = valid_race();
            mutate(&mut evidence);
            assert_failed(validate_owner_race_evidence(&evidence));
        }
    }
}
