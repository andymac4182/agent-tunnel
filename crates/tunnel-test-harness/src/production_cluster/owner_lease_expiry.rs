//! Production Redis owner-lease expiry, epoch retention and stale-release
//! fencing with a real relay and a real owner process.
//!
//! The existing owner-contention gate proves successor admission after a
//! *graceful* owner disappearance: the CLI exits, the relay releases its lease
//! and a successor claims the retained epoch.  That path never proves the
//! durable lease itself expires.  This gate removes the release entirely.
//!
//! Every relay reaches Redis through an opaque TCP proxy.  Once an authorized
//! CLI owner session is serving, the proxy pauses both directions of every
//! Redis socket, including sockets accepted after the barrier.  The relay can
//! therefore neither renew nor release the lease, and the owner hash can only
//! disappear through the `PEXPIREAT` deadline written by the claim script.  A
//! second catalog handle, connected directly to the upstream Redis rather than
//! through the proxy, observes that expiry and attempts the predecessor's
//! exact compare-and-release.
//!
//! The durable epoch key carries no TTL, so the successor must resume above
//! the retained high epoch seeded for this fixture namespace rather than
//! restarting at one.

use super::{
    ConsumerStream, ProductionCluster, RunningHarness, STARTUP_TIMEOUT, assert_public_health_ready,
    device_dispatch_counter, start_cli_smoke, wait_for_fanout_drained,
    wait_for_public_health_ready,
};
use crate::acceptance::helpers::write_device_profile;
use crate::{
    Harness, HarnessError, HarnessOptions, ManagedProcess, OidcTokenOptions, ProxyConfig,
    ProxyHandle, Result, TcpProxy,
};
use chrono::{DateTime, Utc};
use std::time::{Duration, Instant};
use tempfile::tempdir;
use tokio::time::{sleep, timeout};
use tunnel_catalog::{Catalog, OwnerClaim, RedisCatalog};

/// Poll interval for the direct (unproxied) lease observer.
const OBSERVER_POLL: Duration = Duration::from_millis(250);
/// Bounded budget for one direct observer command.
const OBSERVER_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum wall time allowed between the partition barrier and the observed
/// disappearance of the owner hash.  The relay's configured owner lease is 30
/// seconds, so this bounds the natural expiry plus Redis/clock slack.
const LEASE_EXPIRY_BUDGET: Duration = Duration::from_secs(75);
/// The relay's configured owner lease.
const CONFIGURED_OWNER_LEASE: Duration = Duration::from_secs(30);
/// The relay renews once a third of the owner lease has elapsed.  The barrier
/// must therefore survive at least this long before the expiry is observed, or
/// no renewal tick was actually missed.
const MISSED_RENEWAL_FLOOR: Duration = Duration::from_secs(CONFIGURED_OWNER_LEASE.as_secs() / 3);
/// Bounded budget for the successor CLI to claim the retained epoch.
const SUCCESSOR_TIMEOUT: Duration = Duration::from_secs(30);
/// Bounded budget for the predecessor owner record to clear after resume.
const PREDECESSOR_CLEAR_TIMEOUT: Duration = Duration::from_secs(45);
/// Bounded process join budget.
const PROCESS_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
/// Whole-scenario bound, generous enough for one natural 30-second lease.
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(180);
/// The documented floor for a retained epoch seed above `2^53`.
const HIGH_EPOCH_FLOOR: u64 = 1_u64 << 53;

/// Payload-free evidence from the real owner-lease expiry gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerLeaseExpiryEvidence {
    /// Number of relays started through the production serving boundary.
    pub relay_count: usize,
    /// The retained epoch seeded for this fixture namespace before any claim.
    pub seeded_epoch: u64,
    /// The epoch the real CLI owner session claimed above the seed.
    pub original_epoch: u64,
    /// The guarded epoch seed left catalog generation metadata unchanged.
    pub catalog_generation_preserved: bool,
    /// The real CLI owner session completed a routed canary before the
    /// partition.
    pub baseline_echo: bool,
    /// Number of proxied Redis sockets paused for the renewal barrier,
    /// including sockets discovered after the barrier.
    pub paused_redis_connections: usize,
    /// The direct observer still saw the predecessor's exact owner token after
    /// the barrier and before the lease deadline.  Without this the later
    /// absence could be a pre-existing condition rather than an expiry.
    pub owner_present_after_barrier: bool,
    /// The owner hash disappeared while every relay Redis socket was paused,
    /// so no relay release or delete could have removed it.
    pub owner_expired_while_partitioned: bool,
    /// The disappearance was observed at or after the lease deadline recorded
    /// in the predecessor's own claim.
    pub owner_absent_after_lease_deadline: bool,
    /// Wall-clock milliseconds from the renewal barrier to the observed
    /// disappearance.  The barrier is raised after the claim, so this is
    /// shorter than the lease itself; the deadline proof is
    /// `owner_absent_after_lease_deadline` and `lease_deadline_margin_ms`.
    pub lease_expiry_elapsed_ms: u64,
    /// Non-negative wall-clock milliseconds between the lease deadline written
    /// into the predecessor's own claim and the observed disappearance.
    pub lease_deadline_margin_ms: u64,
    /// The owner relay's per-device application-dispatch counter did not
    /// advance between the barrier and the observed expiry.  This is relay
    /// no-forward evidence, not a claim about device side effects.
    pub expired_owner_dispatch_unchanged: bool,
    /// The predecessor's exact compare-and-release was refused after expiry.
    pub stale_release_refused_after_expiry: bool,
    /// The successor CLI claimed the same tenant/device scope.
    pub successor_scope_matched: bool,
    /// The successor's durable epoch, read from the authoritative catalog.
    pub successor_epoch: u64,
    /// The successor ran on a fresh session and boot identity.
    pub successor_fresh_session: bool,
    /// The predecessor's exact compare-and-release was still refused once a
    /// successor held the lease.
    pub stale_release_refused_after_successor: bool,
    /// The successor's complete owner token was unchanged by that refusal.
    pub successor_token_unchanged: bool,
    /// The successor returned its canary through a public consumer route.
    pub successor_echo: bool,
    /// Maximum simultaneously open device fanout sockets observed.
    pub fanout_peak_open: usize,
    /// Wall-clock milliseconds spent in the bounded scenario.
    pub elapsed_ms: u64,
}

/// Validate the bounded owner-lease expiry contract.
pub fn validate_owner_lease_expiry_evidence(evidence: &OwnerLeaseExpiryEvidence) -> Result<()> {
    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "owner-lease expiry expected three relays, observed {}",
            evidence.relay_count
        )));
    }
    let required = [
        (
            "catalog_generation_preserved",
            evidence.catalog_generation_preserved,
        ),
        ("baseline_echo", evidence.baseline_echo),
        (
            "owner_present_after_barrier",
            evidence.owner_present_after_barrier,
        ),
        (
            "owner_expired_while_partitioned",
            evidence.owner_expired_while_partitioned,
        ),
        (
            "owner_absent_after_lease_deadline",
            evidence.owner_absent_after_lease_deadline,
        ),
        (
            "expired_owner_dispatch_unchanged",
            evidence.expired_owner_dispatch_unchanged,
        ),
        (
            "stale_release_refused_after_expiry",
            evidence.stale_release_refused_after_expiry,
        ),
        ("successor_scope_matched", evidence.successor_scope_matched),
        ("successor_fresh_session", evidence.successor_fresh_session),
        (
            "stale_release_refused_after_successor",
            evidence.stale_release_refused_after_successor,
        ),
        (
            "successor_token_unchanged",
            evidence.successor_token_unchanged,
        ),
        ("successor_echo", evidence.successor_echo),
    ];
    for (field, satisfied) in required {
        if !satisfied {
            return Err(HarnessError::Process(format!(
                "owner-lease expiry evidence is incomplete: {field}"
            )));
        }
    }
    if evidence.seeded_epoch < HIGH_EPOCH_FLOOR {
        return Err(HarnessError::Process(format!(
            "owner-lease expiry seeded epoch {} was not above the JavaScript-safe boundary",
            evidence.seeded_epoch
        )));
    }
    if evidence.original_epoch <= evidence.seeded_epoch {
        return Err(HarnessError::Process(format!(
            "owner-lease expiry original epoch {} did not exceed the retained seed {}",
            evidence.original_epoch, evidence.seeded_epoch
        )));
    }
    if evidence.successor_epoch <= evidence.original_epoch {
        return Err(HarnessError::Process(format!(
            "owner-lease expiry successor epoch {} did not exceed predecessor epoch {}",
            evidence.successor_epoch, evidence.original_epoch
        )));
    }
    if evidence.paused_redis_connections == 0 {
        return Err(HarnessError::Process(
            "owner-lease expiry paused no Redis connections".into(),
        ));
    }
    if evidence.lease_expiry_elapsed_ms
        < u64::try_from(MISSED_RENEWAL_FLOOR.as_millis()).unwrap_or(u64::MAX)
    {
        return Err(HarnessError::Process(format!(
            "owner-lease expiry observed a disappearance after only {} ms, before one renewal tick could be missed",
            evidence.lease_expiry_elapsed_ms
        )));
    }
    if evidence.lease_expiry_elapsed_ms
        > u64::try_from(LEASE_EXPIRY_BUDGET.as_millis()).unwrap_or(u64::MAX)
    {
        return Err(HarnessError::Process(format!(
            "owner-lease expiry exceeded its bounded budget at {} ms",
            evidence.lease_expiry_elapsed_ms
        )));
    }
    if evidence.lease_deadline_margin_ms
        > u64::try_from(LEASE_EXPIRY_BUDGET.as_millis()).unwrap_or(u64::MAX)
    {
        return Err(HarnessError::Process(format!(
            "owner-lease expiry deadline margin {} ms exceeded its bounded budget",
            evidence.lease_deadline_margin_ms
        )));
    }
    if evidence.fanout_peak_open > 3 {
        return Err(HarnessError::Process(format!(
            "owner-lease expiry fanout exceeded the bounded three-socket peak: {}",
            evidence.fanout_peak_open
        )));
    }
    Ok(())
}

/// Run the bounded real owner-lease expiry, epoch retention and stale-release
/// gate.
pub async fn verify() -> Result<OwnerLeaseExpiryEvidence> {
    let base_options = HarnessOptions::from_env()?;
    let upstream_url =
        base_options
            .redis_url
            .clone()
            .ok_or_else(|| HarnessError::MissingRedisUrl {
                env_var: "TEST_REDIS_URL",
                guidance:
                    "The owner-lease expiry gate requires TEST_REDIS_URL for its opaque TCP proxy."
                        .to_owned(),
            })?;
    let target = super::redis_target_address(&upstream_url)?;
    let redis_proxy = TcpProxy::bind(target, ProxyConfig::default()).await?;
    let proxy_url = format!("redis://{}", redis_proxy.local_addr());
    let options = base_options
        .redis_url(proxy_url)
        .namespace_prefix("m7-owner-lease-expiry")
        .rotation(super::ROTATION);
    let mut harness = match timeout(STARTUP_TIMEOUT, Harness::start(options)).await {
        Ok(Ok(harness)) => harness,
        Ok(Err(error)) => {
            let _ = redis_proxy.shutdown().await;
            return Err(error);
        }
        Err(_) => {
            let _ = redis_proxy.shutdown().await;
            return Err(HarnessError::Timeout(
                "owner-lease expiry harness startup timed out".into(),
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
        SCENARIO_TIMEOUT,
        run(&mut cluster, &harness, &redis_proxy, &upstream_url),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "owner-lease expiry scenario exceeded its bounded deadline".into(),
        )),
    };
    // The scenario always resumes the proxy before returning so catalog
    // namespace cleanup stays authoritative and bounded.
    let cluster_cleanup = cluster.shutdown().await;
    let harness_cleanup = harness.shutdown().await;
    let proxy_cleanup = redis_proxy.shutdown().await;
    match (scenario, cluster_cleanup, harness_cleanup, proxy_cleanup) {
        (Ok(evidence), Ok(()), Ok(()), Ok(())) => {
            validate_owner_lease_expiry_evidence(&evidence)?;
            Ok(evidence)
        }
        (scenario, cluster_cleanup, harness_cleanup, proxy_cleanup) => {
            let mut failure = scenario.err();
            for (label, result) in [
                ("owner-lease expiry relay cleanup", cluster_cleanup),
                ("owner-lease expiry Redis cleanup", harness_cleanup),
                ("owner-lease expiry proxy cleanup", proxy_cleanup),
            ] {
                if let Err(error) = result {
                    failure = Some(match failure.take() {
                        Some(primary) => {
                            HarnessError::Process(format!("{primary}; {label}: {error}"))
                        }
                        None => HarnessError::Process(format!("{label}: {error}")),
                    });
                }
            }
            Err(failure.expect("owner-lease expiry cleanup failure was not recorded"))
        }
    }
}

async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    redis_proxy: &ProxyHandle,
    upstream_url: &str,
) -> Result<OwnerLeaseExpiryEvidence> {
    let started = Instant::now();
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(format!(
            "owner-lease expiry gate started {} relays, expected three",
            cluster.relays.len()
        )));
    }
    cluster.wait_for_peer_readiness(STARTUP_TIMEOUT).await?;

    let device =
        harness.topology.devices_a.first().ok_or_else(|| {
            HarnessError::InvalidInput("owner-lease expiry device is missing".into())
        })?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| {
            HarnessError::InvalidInput("owner-lease expiry device has no echo service".into())
        })?;
    let canary = format!("m7-owner-lease-expiry:{}", device.id);
    let ingress_addr = cluster.relay("relay-b")?.consumer_addr()?;

    // Seed the retained epoch above 2^53 before any claim so the successor
    // must resume from a retained high value rather than restarting at one.
    let seed =
        super::ownership::seed_high_owner_epoch(cluster, harness, device.tenant_id, device.id)
            .await?;

    let profile_directory = tempdir().map_err(HarnessError::Io)?;
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
    profile.config.rotation = super::ROTATION;
    profile.config.validate().map_err(|error| {
        HarnessError::InvalidInput(format!("owner-lease expiry client config: {error}"))
    })?;

    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(150),
            ..OidcTokenOptions::default()
        },
    )?;
    let (mut cli_process, mut cli_stream) = start_cli_smoke(
        harness,
        cluster.device_fanout.local_addr(),
        ingress_addr,
        &profile,
        &token,
        device.id,
        service_id,
    )
    .await?;

    // The direct observer deliberately bypasses the proxy.  It is the only
    // authority reader that still works while the relays are partitioned, and
    // it never writes anything except the predecessor's exact
    // compare-and-release attempt.
    let observer = match RedisCatalog::connect_with_deployment_incarnation(
        upstream_url,
        harness.redis.namespace(),
        super::DEPLOYMENT_INCARCATION,
    )
    .await
    {
        Ok(observer) => observer,
        Err(error) => {
            let _ = cli_stream.close().await;
            let _ = cli_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
            return Err(HarnessError::Redis(format!(
                "opening direct owner-lease observer: {error}"
            )));
        }
    };

    let phase = run_partitioned_phase(
        cluster,
        harness,
        redis_proxy,
        &observer,
        &mut cli_process,
        &mut cli_stream,
        device.tenant_id,
        device.id,
        &canary,
        ingress_addr,
    )
    .await;
    let resume_result = redis_proxy.resume_all().await;
    let phase = match (phase, resume_result) {
        (Ok(phase), Ok(())) => phase,
        (Err(error), _) => {
            let _ = cli_stream.close().await;
            let _ = cli_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
            return Err(error);
        }
        (Ok(_), Err(error)) => {
            let _ = cli_stream.close().await;
            let _ = cli_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
            return Err(error);
        }
    };

    // Join the predecessor process before the successor starts.  An expired
    // lease leaves the old session with no authority, but only a joined child
    // proves the successor's canary cannot come from the old process.
    let _ = cli_stream.close().await;
    cli_process
        .shutdown(PROCESS_SHUTDOWN_TIMEOUT)
        .await
        .map_err(|error| {
            HarnessError::Process(format!("joining expired-lease owner CLI: {error}"))
        })?;
    wait_for_public_health_ready(ingress_addr, &harness.pki.server_ca.certificate_der).await?;
    cluster
        .wait_for_owner_clear(device.tenant_id, device.id, PREDECESSOR_CLEAR_TIMEOUT)
        .await?;
    wait_for_fanout_drained(&cluster.device_fanout, "expired-lease predecessor").await?;

    let (successor_process, mut successor_stream) = start_cli_smoke(
        harness,
        cluster.device_fanout.local_addr(),
        ingress_addr,
        &profile,
        &token,
        device.id,
        service_id,
    )
    .await?;
    let successor =
        match wait_for_owner(cluster, device.tenant_id, device.id, SUCCESSOR_TIMEOUT).await {
            Ok(successor) => successor,
            Err(error) => {
                let _ = successor_stream.close().await;
                let _ = successor_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
                return Err(error);
            }
        };
    let successor_scope_matched = successor.token.tenant_id == device.tenant_id
        && successor.token.device_id == device.id
        && cluster
            .relays
            .iter()
            .any(|relay| relay.node_id == successor.token.node_id);
    let successor_fresh_session = successor.token.session_id != phase.owner_before.token.session_id;

    // The predecessor's exact complete token must still be refused once a
    // successor holds the lease.  A prefix or scope-only match would let the
    // dead owner delete live state.
    let stale_release_refused_after_successor =
        match observer.release_owner(&phase.owner_before.token).await {
            Ok(released) => !released,
            Err(error) => {
                let _ = successor_stream.close().await;
                let _ = successor_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
                return Err(HarnessError::Redis(format!(
                    "stale release after successor admission: {error}"
                )));
            }
        };
    let successor_after_release = match observer
        .current_owner(device.tenant_id, device.id, Utc::now())
        .await
    {
        Ok(owner) => owner,
        Err(error) => {
            let _ = successor_stream.close().await;
            let _ = successor_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
            return Err(HarnessError::Redis(format!(
                "re-reading successor owner after stale release: {error}"
            )));
        }
    };
    let successor_token_unchanged =
        successor_after_release.as_ref().map(|owner| &owner.token) == Some(&successor.token);

    let successor_echo = successor_stream
        .round_trip(b"owner-lease-expiry-successor", canary.as_bytes())
        .await
        .is_ok();
    let stream_cleanup = successor_stream.close().await;
    let process_cleanup = successor_process.shutdown(PROCESS_SHUTDOWN_TIMEOUT).await;
    stream_cleanup?;
    process_cleanup.map_err(|error| {
        HarnessError::Process(format!("joining owner-lease expiry successor CLI: {error}"))
    })?;
    wait_for_fanout_drained(&cluster.device_fanout, "expired-lease successor").await?;
    let fanout = cluster.device_fanout.diagnostics();

    Ok(OwnerLeaseExpiryEvidence {
        relay_count: cluster.relays.len(),
        seeded_epoch: seed.seeded_epoch,
        original_epoch: phase.owner_before.token.epoch,
        catalog_generation_preserved: seed.catalog_generation_preserved,
        baseline_echo: phase.baseline_echo,
        paused_redis_connections: phase.paused_redis_connections,
        owner_present_after_barrier: phase.owner_present_after_barrier,
        owner_expired_while_partitioned: phase.owner_expired_while_partitioned,
        owner_absent_after_lease_deadline: phase.owner_absent_after_lease_deadline,
        lease_expiry_elapsed_ms: phase.lease_expiry_elapsed_ms,
        lease_deadline_margin_ms: phase.lease_deadline_margin_ms,
        expired_owner_dispatch_unchanged: phase.expired_owner_dispatch_unchanged,
        stale_release_refused_after_expiry: phase.stale_release_refused_after_expiry,
        successor_scope_matched,
        successor_epoch: successor.token.epoch,
        successor_fresh_session,
        stale_release_refused_after_successor,
        successor_token_unchanged,
        successor_echo,
        fanout_peak_open: fanout.peak_open,
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

/// Observations taken while every relay Redis socket is paused.
struct PartitionedPhase {
    owner_before: OwnerClaim,
    baseline_echo: bool,
    paused_redis_connections: usize,
    owner_present_after_barrier: bool,
    owner_expired_while_partitioned: bool,
    owner_absent_after_lease_deadline: bool,
    lease_expiry_elapsed_ms: u64,
    lease_deadline_margin_ms: u64,
    expired_owner_dispatch_unchanged: bool,
    stale_release_refused_after_expiry: bool,
}

#[allow(clippy::too_many_arguments)]
async fn run_partitioned_phase(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    redis_proxy: &ProxyHandle,
    observer: &RedisCatalog,
    cli_process: &mut ManagedProcess,
    cli_stream: &mut ConsumerStream,
    tenant_id: uuid::Uuid,
    device_id: uuid::Uuid,
    canary: &str,
    ingress_addr: std::net::SocketAddr,
) -> Result<PartitionedPhase> {
    cli_stream
        .round_trip(b"owner-lease-expiry-baseline", canary.as_bytes())
        .await?;
    let baseline_echo = true;
    assert_public_health_ready(ingress_addr, &harness.pki.server_ca.certificate_der).await?;
    if cli_process.try_wait()?.is_some() {
        return Err(HarnessError::Process(
            "owner-lease expiry CLI exited before the renewal barrier".into(),
        ));
    }

    let owner_before = observer
        .current_owner(tenant_id, device_id, Utc::now())
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("reading owner-lease expiry predecessor: {error}"))
        })?
        .ok_or_else(|| {
            HarnessError::Process("owner-lease expiry CLI did not claim an owner".into())
        })?;
    if owner_before.token.tenant_id != tenant_id
        || owner_before.token.device_id != device_id
        || !cluster
            .relays
            .iter()
            .any(|relay| relay.node_id == owner_before.token.node_id)
    {
        return Err(HarnessError::Process(
            "owner-lease expiry predecessor did not match the fixture scope".into(),
        ));
    }
    let owner_relay = cluster.relay(&owner_before.token.node_id)?;
    let baseline_snapshot = owner_relay.snapshot().await?;
    let device_dispatch_before = device_dispatch_counter(&baseline_snapshot, device_id);
    let lifetime_dispatch_before = baseline_snapshot.lifetime_application_dispatches;
    if device_dispatch_before == 0 || lifetime_dispatch_before == 0 {
        return Err(HarnessError::Process(
            "owner-lease expiry baseline echo did not advance the owner dispatch counter".into(),
        ));
    }

    // Pause both directions of every Redis socket.  From here the relay can
    // neither renew nor release the lease, so the only remaining way for the
    // owner hash to disappear is its own Redis expiry deadline.
    let barrier = Instant::now();
    redis_proxy.pause_all().await?;
    let paused_redis_connections = redis_proxy.diagnostics().active_connections.len();
    if paused_redis_connections == 0 {
        return Err(HarnessError::Process(
            "owner-lease expiry barrier paused no active Redis connections".into(),
        ));
    }

    let lease_deadline: DateTime<Utc> = owner_before.lease_expires_at;
    let mut owner_present_after_barrier = false;
    let owner_absent_after_lease_deadline;
    let lease_expiry_elapsed_ms;
    let lease_deadline_margin_ms;
    let expiry_deadline = barrier + LEASE_EXPIRY_BUDGET;
    loop {
        let observed_at = Utc::now();
        match timeout(
            OBSERVER_TIMEOUT,
            observer.current_owner(tenant_id, device_id, observed_at),
        )
        .await
        {
            Ok(Ok(Some(owner))) => {
                if owner.token != owner_before.token {
                    return Err(HarnessError::Process(format!(
                        "owner-lease expiry saw a different owner token on {} during the barrier",
                        owner.token.node_id
                    )));
                }
                owner_present_after_barrier = true;
            }
            Ok(Ok(None)) => {
                lease_expiry_elapsed_ms =
                    u64::try_from(barrier.elapsed().as_millis()).unwrap_or(u64::MAX);
                let margin = (observed_at - lease_deadline).num_milliseconds();
                owner_absent_after_lease_deadline = margin >= 0;
                lease_deadline_margin_ms = u64::try_from(margin).unwrap_or(0);
                break;
            }
            Ok(Err(error)) if Instant::now() >= expiry_deadline => {
                return Err(HarnessError::Redis(format!(
                    "owner-lease expiry observer failed before the lease bound: {error}"
                )));
            }
            Err(_) if Instant::now() >= expiry_deadline => {
                return Err(HarnessError::Timeout(
                    "owner-lease expiry observer exceeded its bounded deadline".into(),
                ));
            }
            Ok(Err(_)) | Err(_) => {}
        }
        if Instant::now() >= expiry_deadline {
            return Err(HarnessError::Timeout(
                "owner lease did not expire while every relay Redis socket was paused".into(),
            ));
        }
        sleep(OBSERVER_POLL).await;
    }

    // The proxy is still paused here, so no relay command could have removed
    // the owner hash between the barrier and this observation.
    let still_paused = redis_proxy.diagnostics().active_connections.len();
    let owner_expired_while_partitioned = still_paused > 0;

    // The predecessor's exact compare-and-release must be refused: the hash it
    // names no longer exists, and a scope-only delete would be unfenced.
    let stale_release_refused_after_expiry = match timeout(
        OBSERVER_TIMEOUT,
        observer.release_owner(&owner_before.token),
    )
    .await
    {
        Ok(Ok(released)) => !released,
        Ok(Err(error)) => {
            return Err(HarnessError::Redis(format!(
                "stale release after lease expiry: {error}"
            )));
        }
        Err(_) => {
            return Err(HarnessError::Timeout(
                "stale release after lease expiry exceeded its bounded deadline".into(),
            ));
        }
    };

    // The relay's lifetime application-dispatch counter is monotonic and
    // survives session teardown, so it is the authoritative no-forward
    // evidence here.  The per-device counter is additionally required not to
    // advance; it legitimately drops to zero once the expired owner session is
    // unregistered, which is why equality alone would be the wrong contract.
    let expiry_snapshot = owner_relay.snapshot().await?;
    let device_dispatch_after = device_dispatch_counter(&expiry_snapshot, device_id);
    let lifetime_dispatch_after = expiry_snapshot.lifetime_application_dispatches;
    if lifetime_dispatch_after > lifetime_dispatch_before {
        return Err(HarnessError::Process(format!(
            "owner-lease expiry advanced the relay application-dispatch counter from {lifetime_dispatch_before} to {lifetime_dispatch_after}"
        )));
    }
    if device_dispatch_after > device_dispatch_before {
        return Err(HarnessError::Process(format!(
            "owner-lease expiry advanced the owner device-dispatch counter from {device_dispatch_before} to {device_dispatch_after}"
        )));
    }
    let expired_owner_dispatch_unchanged = lifetime_dispatch_after == lifetime_dispatch_before
        && device_dispatch_after <= device_dispatch_before;

    Ok(PartitionedPhase {
        owner_before,
        baseline_echo,
        paused_redis_connections,
        owner_present_after_barrier,
        owner_expired_while_partitioned,
        owner_absent_after_lease_deadline,
        lease_expiry_elapsed_ms,
        lease_deadline_margin_ms,
        expired_owner_dispatch_unchanged,
        stale_release_refused_after_expiry,
    })
}

async fn wait_for_owner(
    cluster: &ProductionCluster,
    tenant_id: uuid::Uuid,
    device_id: uuid::Uuid,
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
            Ok(None) => {}
            Err(error) if Instant::now() >= deadline => {
                return Err(HarnessError::Redis(format!(
                    "owner-lease expiry successor owner was not visible: {error}"
                )));
            }
            Err(_) => {}
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "owner-lease expiry successor did not claim the retained epoch".into(),
            ));
        }
        sleep(OBSERVER_POLL).await;
    }
}

#[cfg(test)]
mod c17_validator_tests {
    use super::{HIGH_EPOCH_FLOOR, OwnerLeaseExpiryEvidence, validate_owner_lease_expiry_evidence};
    use crate::acceptance_test_support::assert_rejected;

    fn valid_evidence() -> OwnerLeaseExpiryEvidence {
        OwnerLeaseExpiryEvidence {
            relay_count: 3,
            seeded_epoch: HIGH_EPOCH_FLOOR,
            original_epoch: HIGH_EPOCH_FLOOR + 1,
            catalog_generation_preserved: true,
            baseline_echo: true,
            paused_redis_connections: 4,
            owner_present_after_barrier: true,
            owner_expired_while_partitioned: true,
            owner_absent_after_lease_deadline: true,
            lease_expiry_elapsed_ms: 29_800,
            lease_deadline_margin_ms: 120,
            expired_owner_dispatch_unchanged: true,
            stale_release_refused_after_expiry: true,
            successor_scope_matched: true,
            successor_epoch: HIGH_EPOCH_FLOOR + 2,
            successor_fresh_session: true,
            stale_release_refused_after_successor: true,
            successor_token_unchanged: true,
            successor_echo: true,
            fanout_peak_open: 2,
            elapsed_ms: 90_000,
        }
    }

    #[test]
    fn owner_lease_expiry_validator_accepts_complete_evidence() {
        validate_owner_lease_expiry_evidence(&valid_evidence())
            .expect("complete owner-lease expiry evidence is valid");
    }

    #[test]
    fn every_owner_lease_expiry_flag_and_bound_reaches_the_shared_exit_path() {
        type Disable = (&'static str, fn(&mut OwnerLeaseExpiryEvidence));
        let flags: [Disable; 12] = [
            ("catalog_generation_preserved", |e| {
                e.catalog_generation_preserved = false
            }),
            ("baseline_echo", |e| e.baseline_echo = false),
            ("owner_present_after_barrier", |e| {
                e.owner_present_after_barrier = false
            }),
            ("owner_expired_while_partitioned", |e| {
                e.owner_expired_while_partitioned = false
            }),
            ("owner_absent_after_lease_deadline", |e| {
                e.owner_absent_after_lease_deadline = false
            }),
            ("expired_owner_dispatch_unchanged", |e| {
                e.expired_owner_dispatch_unchanged = false
            }),
            ("stale_release_refused_after_expiry", |e| {
                e.stale_release_refused_after_expiry = false
            }),
            ("successor_scope_matched", |e| {
                e.successor_scope_matched = false
            }),
            ("successor_fresh_session", |e| {
                e.successor_fresh_session = false
            }),
            ("stale_release_refused_after_successor", |e| {
                e.stale_release_refused_after_successor = false
            }),
            ("successor_token_unchanged", |e| {
                e.successor_token_unchanged = false
            }),
            ("successor_echo", |e| e.successor_echo = false),
        ];
        for (name, disable) in flags {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_rejected(validate_owner_lease_expiry_evidence(&evidence), name);
        }

        type Mutate = (&'static str, fn(&mut OwnerLeaseExpiryEvidence));
        let bounds: [Mutate; 9] = [
            ("three relays", |e: &mut OwnerLeaseExpiryEvidence| {
                e.relay_count = 2
            }),
            ("JavaScript-safe boundary", |e| {
                e.seeded_epoch = 1;
                e.original_epoch = 2;
                e.successor_epoch = 3;
            }),
            ("retained seed", |e| e.original_epoch = e.seeded_epoch),
            ("predecessor epoch", |e| {
                e.successor_epoch = e.original_epoch
            }),
            ("paused no Redis connections", |e| {
                e.paused_redis_connections = 0
            }),
            ("before one renewal tick", |e| {
                e.lease_expiry_elapsed_ms = 9_999
            }),
            ("bounded budget", |e| e.lease_expiry_elapsed_ms = 10_000_000),
            ("deadline margin", |e| {
                e.lease_deadline_margin_ms = 10_000_000
            }),
            ("three-socket peak", |e| e.fanout_peak_open = 4),
        ];
        for (expected, mutate) in bounds {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(validate_owner_lease_expiry_evidence(&evidence), expected);
        }
    }
}
