//! Cross-relay handover racing peer grace against owner readiness (EC-025,
//! M7-C52).
//!
//! Through a non-owner ingress, a same-owner data rotation is driven while two
//! things are delayed independently: the peer route from the ingress to the
//! owner (the peer-path drop controls) and the owner's own data readiness (the
//! accelerated rotation handover).  Every consumer request forwarded through
//! the ingress must take exactly one hop to the exact owner, revalidate the
//! owner token and peer trust before body dispatch, never dispatch to a stale
//! owner or an unrelated backend, and either complete with the exact owner or
//! return the typed not-dispatched outcome.
//!
//! A third arm crosses the peer-trust boundary inside a single request: the
//! peer admission barrier parks one request after consumer admission and owner
//! selection but before the peer open, the owner's signed peer binding is
//! retracted while it is held, and the released request must be refused by the
//! relay's own post-handshake trust revalidation with nothing dispatched.  The
//! barrier is one-shot -- once released it refuses every later admission on the
//! ingress -- so that arm runs on its own cluster with its own barrier.

use super::admission::{PublicStreamProbe, open_public_stream_with_authorization};
use super::{ConsumerStream, ProductionCluster, start_cli_smoke};
use crate::acceptance::helpers::write_device_profile;
use crate::cluster_fixture::{FixturePeerKey, M7_MEMBERSHIP_LIFETIME, MembershipRecordOptions};
use crate::{
    Harness, HarnessError, HarnessOptions, ManagedProcess, OidcTokenOptions, Result, RunningHarness,
};
use chrono::Utc;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::{Instant, sleep, timeout};
use tunnel_catalog::RedisMembershipPublisher;
use tunnel_relay::{PeerAdmissionBarrier, PeerAdmissionScope};
use uuid::Uuid;

const INGRESS_NODE: &str = "relay-c";
const NODES: [&str; 3] = ["relay-a", "relay-b", "relay-c"];
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(180);
const PHASE_TIMEOUT: Duration = Duration::from_secs(30);
const READINESS_FLIP_TIMEOUT: Duration = Duration::from_secs(20);
const ROTATION_WAIT_TIMEOUT: Duration = Duration::from_secs(40);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const CANARY: &[u8] = b"m7-ec025-canary";
const ACROSS_ROTATION_REQUESTS: usize = 6;

/// Bound for the ingress membership runtime to observe the re-issued record.
/// The relay's own peer-admission hold budget is its 30-second operation
/// timeout, so this stays comfortably inside the held window.
const TRUST_WITHDRAWAL_TIMEOUT: Duration = Duration::from_secs(15);
/// The exact refusal the re-issue must produce. The ingress relay's own
/// membership stays valid, so it answers about the peer rather than about
/// itself; `CLUSTER_UNREADY` and `PEER_UNAVAILABLE` are explicitly rejected
/// below so the gate cannot pass on generic unavailability.
const TRUST_CROSSING_CODE: &str = "PEER_UNTRUSTED";
const TRUST_CROSSING_EXECUTION: &str = "not_dispatched";
const TRUST_CROSSING_STATUS: u16 = 503;
const TRUST_CROSSING_FAULT_ROLE: &str = "ingress";
/// The reissue is observed exactly where the relay revalidates signed peer
/// trust against the completed mTLS handshake: after the pooled connection is
/// in hand and before any envelope is sent.
const TRUST_CROSSING_FAULT_STAGE: &str = "pool_connect";
const TRUST_CROSSING_FAULT_CAUSE: &str = "identity_mismatch";

/// Typed owner-loss / unreadiness codes that carry `not_dispatched` at the
/// ingress when the peer route to the owner is unavailable.
const NOT_DISPATCHED_CODES: [&str; 3] = ["CLUSTER_UNREADY", "PEER_UNAVAILABLE", "PEER_UNTRUSTED"];

/// Payload-free evidence for the cross-relay handover / peer-grace race.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ec025HandoverEvidence {
    pub relay_count: usize,
    pub ingress_is_not_owner: bool,
    pub owner_node_unchanged: bool,
    /// Baseline request through the non-owner ingress dispatched exactly once
    /// at the exact owner and nowhere else.
    pub baseline_exact_owner_dispatch: bool,
    /// The peer admission barrier observed the exact owner scope before the
    /// one-hop peer stream opened: the ingress resolved the exact owner.
    pub exact_owner_scope_observed: bool,
    /// After releasing the barrier the request completed at the exact owner.
    pub barrier_completed_exact_owner: bool,
    /// With the peer route to the owner dropped, the request returned a typed
    /// not-dispatched outcome.
    pub peer_delay_typed_not_dispatched: bool,
    /// Nothing dispatched anywhere while the peer route was dropped.
    pub peer_delay_zero_dispatch: bool,
    /// At least one same-owner rotation completed during the handover window.
    pub rotation_observed: bool,
    /// Across the rotation window no non-owner relay dispatched anything.
    pub across_rotation_no_foreign_dispatch: bool,
    /// Every request across the rotation window either completed with the exact
    /// owner or returned the typed not-dispatched outcome.
    pub across_rotation_completed_or_typed: bool,
    /// Count of across-rotation requests that completed at the exact owner.
    pub across_rotation_completed: usize,
    /// Count of across-rotation requests admitted then interrupted mid-handover.
    pub across_rotation_interrupted: usize,
    /// Count of across-rotation requests that returned typed not-dispatched.
    pub across_rotation_not_dispatched: usize,
    /// Third arm: one request that crossed a peer-trust boundary between
    /// consumer admission and body dispatch.
    pub trust_crossing: Ec025TrustCrossing,
    pub cleanup_joined: bool,
}

/// Payload-free evidence for the peer-trust boundary crossed mid-request.
///
/// The peer admission barrier holds the request after consumer admission and
/// owner-route resolution but before the remote HTTP/3 admission call. While it
/// is held, the owner's signed peer binding is re-issued at a higher record
/// version onto a different peer endpoint, so the signed directory no longer
/// attests the binding this request selected. The certificate itself stays
/// trusted, which keeps the pooled ingress->owner connection alive: the only
/// thing that can refuse the released request is the relay's own post-handshake
/// revalidation of signed peer trust (`binding_for_certificate`), which runs
/// after the connection is in hand and before any envelope is sent.
///
/// A harder withdrawal -- retracting the owner's SPKI outright -- was measured
/// first and is *not* what this arm does: the membership invalidation
/// dispatcher tears the pooled connection down before the held request
/// resumes, so the request fails in the transport with `PEER_UNAVAILABLE` and
/// execution `unknown`, which is not a typed not-dispatched outcome and never
/// reaches the trust revalidation this clause is about.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Ec025TrustCrossing {
    /// The barrier observed the exact owner scope: consumer admission, owner
    /// selection and owner-token resolution had all already passed.
    pub scope_observed: bool,
    /// A healthy request through the same ingress completed at the exact owner
    /// immediately before the arm, so the refusal below is caused by the
    /// re-issue rather than by a cluster that was never able to forward.
    pub healthy_baseline_completed: bool,
    /// The ingress relay's own membership runtime absorbed the re-issued owner
    /// record while the request was still held at the barrier.
    pub withdrawn_while_held: bool,
    /// The request was still parked at the barrier once the re-issue landed.
    pub still_held_at_withdrawal: bool,
    /// Status, code and execution of the released request's refusal.
    pub refusal_status: u16,
    pub refusal_code: Option<String>,
    pub refusal_execution: Option<String>,
    /// Application dispatch delta on every relay across the whole held
    /// request, including the release.
    pub dispatch_delta: [u64; 3],
    /// The exact owner's application dispatch delta, kept separately so the
    /// "owner read no request body" clause names its own observation.
    pub owner_dispatch_delta: u64,
    /// The bounded peer fault tuple the ingress recorded for this request.
    pub fault_role: Option<String>,
    pub fault_stage: Option<String>,
    pub fault_cause: Option<String>,
}

fn validate_trust_crossing(crossing: &Ec025TrustCrossing) -> Result<()> {
    let required = [
        ("trust crossing scope observed", crossing.scope_observed),
        (
            "trust crossing healthy baseline completed",
            crossing.healthy_baseline_completed,
        ),
        (
            "trust crossing withdrawn while held",
            crossing.withdrawn_while_held,
        ),
        (
            "trust crossing request still held at withdrawal",
            crossing.still_held_at_withdrawal,
        ),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "EC-025 handover gate was false: {name}"
        )));
    }
    // Assert the exact refusal the withdrawal produces. A weaker variant
    // (`CLUSTER_UNREADY`, `PEER_UNAVAILABLE`) would mean the request was
    // refused for generic unavailability rather than by the post-admission
    // peer-trust revalidation, so it is rejected here by name.
    if crossing.refusal_status != TRUST_CROSSING_STATUS
        || crossing.refusal_code.as_deref() != Some(TRUST_CROSSING_CODE)
        || crossing.refusal_execution.as_deref() != Some(TRUST_CROSSING_EXECUTION)
    {
        return Err(HarnessError::Process(format!(
            "EC-025 trust crossing expected status={TRUST_CROSSING_STATUS} code={TRUST_CROSSING_CODE} execution={TRUST_CROSSING_EXECUTION}, observed status={} code={:?} execution={:?}",
            crossing.refusal_status, crossing.refusal_code, crossing.refusal_execution
        )));
    }
    if crossing.dispatch_delta != [0, 0, 0] || crossing.owner_dispatch_delta != 0 {
        return Err(HarnessError::Process(format!(
            "EC-025 trust crossing dispatched: delta_a={} delta_b={} delta_c={} owner_delta={}",
            crossing.dispatch_delta[0],
            crossing.dispatch_delta[1],
            crossing.dispatch_delta[2],
            crossing.owner_dispatch_delta
        )));
    }
    if crossing.fault_role.as_deref() != Some(TRUST_CROSSING_FAULT_ROLE)
        || crossing.fault_stage.as_deref() != Some(TRUST_CROSSING_FAULT_STAGE)
        || crossing.fault_cause.as_deref() != Some(TRUST_CROSSING_FAULT_CAUSE)
    {
        return Err(HarnessError::Process(format!(
            "EC-025 trust crossing expected a {TRUST_CROSSING_FAULT_ROLE}/{TRUST_CROSSING_FAULT_STAGE}/{TRUST_CROSSING_FAULT_CAUSE} peer fault, observed role={:?} stage={:?} cause={:?}",
            crossing.fault_role, crossing.fault_stage, crossing.fault_cause
        )));
    }
    Ok(())
}

pub fn validate_ec025_handover_evidence(evidence: &Ec025HandoverEvidence) -> Result<()> {
    validate_handover_arms(evidence)?;
    validate_trust_crossing(&evidence.trust_crossing)?;
    Ok(())
}

/// Validate everything proved on the first cluster: the two original arms plus
/// the across-rotation accounting.
fn validate_handover_arms(evidence: &Ec025HandoverEvidence) -> Result<()> {
    let required = [
        ("three relays", evidence.relay_count == 3),
        ("ingress is not owner", evidence.ingress_is_not_owner),
        ("owner node unchanged", evidence.owner_node_unchanged),
        (
            "baseline exact-owner dispatch",
            evidence.baseline_exact_owner_dispatch,
        ),
        (
            "exact owner scope observed",
            evidence.exact_owner_scope_observed,
        ),
        (
            "barrier completed at exact owner",
            evidence.barrier_completed_exact_owner,
        ),
        (
            "peer delay typed not_dispatched",
            evidence.peer_delay_typed_not_dispatched,
        ),
        (
            "peer delay zero dispatch",
            evidence.peer_delay_zero_dispatch,
        ),
        ("rotation observed", evidence.rotation_observed),
        (
            "across rotation no foreign dispatch",
            evidence.across_rotation_no_foreign_dispatch,
        ),
        (
            "across rotation completed or typed",
            evidence.across_rotation_completed_or_typed,
        ),
        ("joined cleanup", evidence.cleanup_joined),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "EC-025 handover gate was false: {name}"
        )));
    }
    if evidence.across_rotation_completed
        + evidence.across_rotation_interrupted
        + evidence.across_rotation_not_dispatched
        != ACROSS_ROTATION_REQUESTS
    {
        return Err(HarnessError::Process(format!(
            "EC-025 across-rotation requests unaccounted: completed={} interrupted={} not_dispatched={} expected={}",
            evidence.across_rotation_completed,
            evidence.across_rotation_interrupted,
            evidence.across_rotation_not_dispatched,
            ACROSS_ROTATION_REQUESTS
        )));
    }
    // The handover must still forward real work: at least one across-rotation
    // request completed at the exact owner. A run that only ever refused would
    // not prove the "completes with the exact owner" arm.
    if evidence.across_rotation_completed == 0 {
        return Err(HarnessError::Process(
            "EC-025 no across-rotation request completed at the exact owner".into(),
        ));
    }
    Ok(())
}

/// Run the real cross-relay handover / peer-grace race.
///
/// The peer admission barrier is one-shot: once released it refuses every
/// later admission on the ingress relay, so a single cluster can hold exactly
/// one request. The first two arms (baseline, across-rotation, the held
/// request that completes at the exact owner, and the dropped peer route) run
/// on the first cluster; the peer-trust boundary crossing needs its own held
/// request and therefore its own cluster and barrier.
pub async fn verify() -> Result<Ec025HandoverEvidence> {
    let mut evidence = verify_handover().await?;
    evidence.trust_crossing = verify_trust_crossing().await?;
    validate_ec025_handover_evidence(&evidence)?;
    Ok(evidence)
}

async fn verify_handover() -> Result<Ec025HandoverEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(super::ROTATION)
        .shared_device_uuid(true);
    let mut harness = timeout(super::STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("EC-025 harness startup timed out".into()))??;

    let peer_barrier = std::sync::Arc::new(PeerAdmissionBarrier::default());
    let mut cluster = match ProductionCluster::start_with_peer_admission_barrier(
        &mut harness,
        INGRESS_NODE,
        std::sync::Arc::clone(&peer_barrier),
    )
    .await
    {
        Ok(cluster) => cluster,
        Err(primary) => {
            return match harness.shutdown().await {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(HarnessError::Process(format!(
                    "{primary}; EC-025 harness cleanup failed: {cleanup}"
                ))),
            };
        }
    };

    let mut resources = HandoverResources::default();
    let scenario = timeout(
        SCENARIO_TIMEOUT,
        run(&mut cluster, &harness, &peer_barrier, &mut resources),
    )
    .await
    .map_err(|_| HarnessError::Timeout("EC-025 handover race timed out".into()))?;

    let cleanup = resources.cleanup().await;
    let cluster_cleanup = cluster.shutdown().await;
    let harness_cleanup = harness.shutdown().await;

    let (mut evidence, mut failure) = match scenario {
        Ok(evidence) => (Some(evidence), None),
        Err(error) => (None, Some(error)),
    };
    append_cleanup(&mut failure, "EC-025 resources", cleanup);
    append_cleanup(&mut failure, "EC-025 relay cleanup", cluster_cleanup);
    append_cleanup(&mut failure, "EC-025 catalog cleanup", harness_cleanup);
    if let Some(evidence) = evidence.as_mut() {
        evidence.cleanup_joined = failure.is_none();
        if failure.is_none()
            && let Err(error) = validate_handover_arms(evidence)
        {
            evidence.cleanup_joined = false;
            failure = Some(error);
        }
    }
    match (evidence, failure) {
        (Some(evidence), None) => Ok(evidence),
        (_, Some(error)) => Err(error),
        (None, None) => Err(HarnessError::Process(
            "EC-025 produced no evidence or failure".into(),
        )),
    }
}

#[derive(Default)]
struct HandoverResources {
    connector: Option<ManagedProcess>,
    stream: Option<ConsumerStream>,
    _profile_dir: Option<tempfile::TempDir>,
}

impl HandoverResources {
    async fn cleanup(&mut self) -> Result<()> {
        let mut first = None;
        if let Some(mut stream) = self.stream.take() {
            append_cleanup(&mut first, "EC-025 consumer stream", stream.close().await);
        }
        if let Some(connector) = self.connector.take() {
            let result = connector
                .shutdown(Duration::from_secs(5))
                .await
                .map(|_| ())
                .map_err(|error| {
                    HarnessError::Process(format!("EC-025 connector shutdown: {error}"))
                });
            append_cleanup(&mut first, "EC-025 connector", result);
        }
        match first {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    peer_barrier: &PeerAdmissionBarrier,
    resources: &mut HandoverResources,
) -> Result<Ec025HandoverEvidence> {
    cluster
        .wait_for_peer_readiness(super::STARTUP_TIMEOUT)
        .await?;

    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("EC-025 device is missing".into()))?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("EC-025 service is missing".into()))?;
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(300),
            ..OidcTokenOptions::default()
        },
    )?;
    let authorization = format!("Bearer {token}");
    let service_path = service_id.to_string();
    let server_ca = harness.pki.server_ca.certificate_der.clone();
    let ingress = cluster.relay(INGRESS_NODE)?.consumer_addr()?;

    // ---- Start the real connector and drive the accelerated same-owner rotation.
    let profile_dir = tempfile::tempdir().map_err(HarnessError::Io)?;
    let mut profile = write_device_profile(
        profile_dir.path(),
        device.id,
        service_id,
        std::str::from_utf8(CANARY).expect("canary is ascii"),
        cluster.device_fanout.local_addr(),
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile.config.rotation = super::ROTATION;
    profile
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("EC-025 config: {error}")))?;
    resources._profile_dir = Some(profile_dir);
    let (connector, stream) = start_cli_smoke(
        harness,
        cluster.device_fanout.local_addr(),
        ingress,
        &profile,
        &token,
        device.id,
        service_id,
    )
    .await?;
    resources.connector = Some(connector);
    if let Some(mut previous) = resources.stream.replace(stream) {
        let _ = previous.close().await;
    }
    let owner = wait_for_owner(cluster, device.tenant_id, device.id).await?;
    let owner_node = owner.token.node_id.clone();
    let ingress_is_not_owner = owner_node != INGRESS_NODE;
    if !ingress_is_not_owner {
        return Err(HarnessError::Process(
            "EC-025 owner unexpectedly landed on the ingress relay".into(),
        ));
    }
    let owner_index = node_index(&owner_node)?;

    // ---- Phase 0: baseline one-hop dispatch at the exact owner. ----
    let before = counters(cluster).await?;
    echo_once(
        ingress,
        &server_ca,
        &authorization,
        device.id,
        &service_path,
    )
    .await?
    .require_completed("EC-025 baseline")?;
    let after = counters(cluster).await?;
    let baseline_delta = subtract(after, before);
    let baseline_exact_owner_dispatch = exact_owner_only(&baseline_delta, owner_index);

    // ---- Phase 1: the owner's data readiness is delayed by the rotation. ----
    // The peer admission barrier is one-shot and, once released, refuses every
    // later admission on the ingress, so all non-barrier requests run first and
    // the barrier is the last healthy-route phase.
    let rotation_start = owner_rotations_completed(cluster, &owner_node, device.id).await?;
    let before = counters(cluster).await?;
    let mut across_rotation_completed = 0_usize;
    let mut across_rotation_interrupted = 0_usize;
    let mut across_rotation_not_dispatched = 0_usize;
    let mut across_rotation_completed_or_typed = true;
    for _ in 0..ACROSS_ROTATION_REQUESTS {
        match echo_once(
            ingress,
            &server_ca,
            &authorization,
            device.id,
            &service_path,
        )
        .await?
        {
            EchoOutcome::Completed => across_rotation_completed += 1,
            EchoOutcome::Interrupted => across_rotation_interrupted += 1,
            EchoOutcome::TypedNotDispatched => across_rotation_not_dispatched += 1,
            EchoOutcome::Untyped => across_rotation_completed_or_typed = false,
        }
        sleep(Duration::from_millis(400)).await;
    }
    let after = counters(cluster).await?;
    let rotation_delta = subtract(after, before);
    tracing::warn!(
        completed = across_rotation_completed,
        interrupted = across_rotation_interrupted,
        not_dispatched = across_rotation_not_dispatched,
        delta_a = rotation_delta[0],
        delta_b = rotation_delta[1],
        delta_c = rotation_delta[2],
        owner_index,
        "EC-025 across-rotation distribution",
    );
    let across_rotation_no_foreign_dispatch = NODES
        .iter()
        .enumerate()
        .all(|(index, _)| index == owner_index || rotation_delta[index] == 0);
    let rotation_end =
        wait_for_rotation_progress(cluster, &owner_node, device.id, rotation_start).await?;
    let rotation_observed = rotation_end > rotation_start;

    // ---- Same owner throughout (read from the authoritative catalog). ----
    let mid_owner = wait_for_owner(cluster, device.tenant_id, device.id).await?;
    let owner_node_unchanged = mid_owner.token.node_id == owner_node;

    // ---- Phase 2: the peer admission barrier proves exact-owner resolution.
    // The held request resolves the exact owner scope before the one-hop peer
    // stream opens, then completes at that exact owner after release. ----
    let scope = PeerAdmissionScope::for_owner(&owner.token, service_id);
    if !peer_barrier.arm(scope.clone()) {
        return Err(HarnessError::Process(
            "EC-025 peer admission barrier was already armed".into(),
        ));
    }
    let phase2_deadline = Instant::now() + PHASE_TIMEOUT;
    let mut held = Box::pin(open_public_stream_with_authorization(
        ingress,
        &server_ca,
        &authorization,
        device.id,
        &service_path,
        &[],
    ));
    tokio::select! {
        result = &mut held => {
            return Err(early_result_error("EC-025 barrier", result));
        }
        waited = timeout(remaining(phase2_deadline), peer_barrier.wait_reached()) => {
            waited.map_err(|_| HarnessError::Timeout(
                "EC-025 peer admission barrier was not reached".into(),
            ))?;
        }
    }
    let exact_owner_scope_observed =
        peer_barrier.hit_count() == 1 && peer_barrier.observed_scope() == Some(scope);
    let before = counters(cluster).await?;
    peer_barrier.release();
    let outcome = timeout(remaining(phase2_deadline), &mut held)
        .await
        .map_err(|_| HarnessError::Timeout("EC-025 barrier result timed out".into()))??;
    let barrier_completed_exact_owner = match outcome {
        PublicStreamProbe::Accepted(mut consumer) => {
            let round = consumer.round_trip(&[], CANARY).await;
            let _ = consumer.close().await;
            round.map_err(|error| HarnessError::Http(format!("EC-025 barrier echo: {error}")))?;
            let after = counters(cluster).await?;
            exact_owner_only(&subtract(after, before), owner_index)
        }
        PublicStreamProbe::Rejected(failure) => {
            return Err(HarnessError::Process(format!(
                "EC-025 barrier request was rejected after release: status={} code={:?} execution={:?}",
                failure.status, failure.code, failure.execution
            )));
        }
    };

    // ---- Phase 3: the peer route to the owner is dropped independently. This
    // is terminal: the drop leaves the pooled ingress->owner peer connection
    // broken, so it is exercised last and only restored for clean teardown.
    // With the ingress unready the request short-circuits at the cluster-unready
    // check before the released barrier is reached. ----
    cluster.set_peer_path_drop_from(&owner_node, INGRESS_NODE, true)?;
    wait_for_ingress_unready(cluster).await?;
    let before = counters(cluster).await?;
    let dropped = echo_once(
        ingress,
        &server_ca,
        &authorization,
        device.id,
        &service_path,
    )
    .await?;
    let after = counters(cluster).await?;
    let peer_delay_zero_dispatch = subtract(after, before) == [0, 0, 0];
    let peer_delay_typed_not_dispatched = dropped.is_typed_not_dispatched();
    cluster.set_peer_path_drop_from(&owner_node, INGRESS_NODE, false)?;

    Ok(Ec025HandoverEvidence {
        relay_count: cluster.relays.len(),
        ingress_is_not_owner,
        owner_node_unchanged,
        baseline_exact_owner_dispatch,
        exact_owner_scope_observed,
        barrier_completed_exact_owner,
        peer_delay_typed_not_dispatched,
        peer_delay_zero_dispatch,
        rotation_observed,
        across_rotation_no_foreign_dispatch,
        across_rotation_completed_or_typed,
        across_rotation_completed,
        across_rotation_interrupted,
        across_rotation_not_dispatched,
        trust_crossing: Ec025TrustCrossing::default(),
        cleanup_joined: false,
    })
}

// ---------------------------------------------------------------------------
// Third arm: a peer-trust boundary crossed between admission and dispatch.
// ---------------------------------------------------------------------------

/// Start a fresh cluster whose ingress carries its own one-shot peer admission
/// barrier, hold one request at that barrier, withdraw the exact owner's signed
/// peer trust while it is held, then release it.
async fn verify_trust_crossing() -> Result<Ec025TrustCrossing> {
    let options = HarnessOptions::from_env()?
        .rotation(super::ROTATION)
        .shared_device_uuid(true);
    let mut harness = timeout(super::STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| {
            HarnessError::Timeout("EC-025 trust-crossing harness startup timed out".into())
        })??;

    let peer_barrier = std::sync::Arc::new(PeerAdmissionBarrier::default());
    let mut cluster = match ProductionCluster::start_with_peer_admission_barrier(
        &mut harness,
        INGRESS_NODE,
        std::sync::Arc::clone(&peer_barrier),
    )
    .await
    {
        Ok(cluster) => cluster,
        Err(primary) => {
            return match harness.shutdown().await {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(HarnessError::Process(format!(
                    "{primary}; EC-025 trust-crossing harness cleanup failed: {cleanup}"
                ))),
            };
        }
    };

    let mut resources = HandoverResources::default();
    let scenario = timeout(
        SCENARIO_TIMEOUT,
        run_trust_crossing(&mut cluster, &harness, &peer_barrier, &mut resources),
    )
    .await
    .map_err(|_| HarnessError::Timeout("EC-025 trust crossing timed out".into()))?;

    let cleanup = resources.cleanup().await;
    let cluster_cleanup = cluster.shutdown().await;
    let harness_cleanup = harness.shutdown().await;

    let (crossing, mut failure) = match scenario {
        Ok(crossing) => (Some(crossing), None),
        Err(error) => (None, Some(error)),
    };
    append_cleanup(&mut failure, "EC-025 trust-crossing resources", cleanup);
    append_cleanup(
        &mut failure,
        "EC-025 trust-crossing relays",
        cluster_cleanup,
    );
    append_cleanup(
        &mut failure,
        "EC-025 trust-crossing catalog",
        harness_cleanup,
    );
    match (crossing, failure) {
        (Some(crossing), None) => Ok(crossing),
        (_, Some(error)) => Err(error),
        (None, None) => Err(HarnessError::Process(
            "EC-025 trust crossing produced no evidence or failure".into(),
        )),
    }
}

#[allow(clippy::too_many_lines)]
async fn run_trust_crossing(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    peer_barrier: &PeerAdmissionBarrier,
    resources: &mut HandoverResources,
) -> Result<Ec025TrustCrossing> {
    cluster
        .wait_for_peer_readiness(super::STARTUP_TIMEOUT)
        .await?;

    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("EC-025 device is missing".into()))?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("EC-025 service is missing".into()))?;
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(300),
            ..OidcTokenOptions::default()
        },
    )?;
    let authorization = format!("Bearer {token}");
    let service_path = service_id.to_string();
    let server_ca = harness.pki.server_ca.certificate_der.clone();
    let ingress = cluster.relay(INGRESS_NODE)?.consumer_addr()?;

    let profile_dir = tempfile::tempdir().map_err(HarnessError::Io)?;
    let mut profile = write_device_profile(
        profile_dir.path(),
        device.id,
        service_id,
        std::str::from_utf8(CANARY).expect("canary is ascii"),
        cluster.device_fanout.local_addr(),
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile.config.rotation = super::ROTATION;
    profile
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("EC-025 config: {error}")))?;
    resources._profile_dir = Some(profile_dir);
    let (connector, stream) = start_cli_smoke(
        harness,
        cluster.device_fanout.local_addr(),
        ingress,
        &profile,
        &token,
        device.id,
        service_id,
    )
    .await?;
    resources.connector = Some(connector);
    if let Some(mut previous) = resources.stream.replace(stream) {
        let _ = previous.close().await;
    }

    let owner = wait_for_owner(cluster, device.tenant_id, device.id).await?;
    let owner_node = owner.token.node_id.clone();
    if owner_node == INGRESS_NODE {
        return Err(HarnessError::Process(
            "EC-025 trust-crossing owner unexpectedly landed on the ingress relay".into(),
        ));
    }
    let owner_index = node_index(&owner_node)?;

    // The same ingress forwards a healthy request one hop to the exact owner
    // immediately before the arm.  Without this, a refusal after the
    // withdrawal could not be attributed to the withdrawal.
    let before_baseline = counters(cluster).await?;
    let baseline = echo_once(
        ingress,
        &server_ca,
        &authorization,
        device.id,
        &service_path,
    )
    .await?;
    let after_baseline = counters(cluster).await?;
    let healthy_baseline_completed = baseline == EchoOutcome::Completed
        && exact_owner_only(&subtract(after_baseline, before_baseline), owner_index);
    if !healthy_baseline_completed {
        return Err(HarnessError::Process(format!(
            "EC-025 trust-crossing baseline did not complete at the exact owner: {baseline:?}"
        )));
    }

    // ---- Hold one request after consumer admission, before the peer open.
    let scope = PeerAdmissionScope::for_owner(&owner.token, service_id);
    if !peer_barrier.arm(scope.clone()) {
        return Err(HarnessError::Process(
            "EC-025 trust-crossing peer admission barrier was already armed".into(),
        ));
    }
    let deadline = Instant::now() + PHASE_TIMEOUT;
    let before = counters(cluster).await?;
    // No request body is sent, so the owner cannot have read one even if the
    // relay had forwarded the head.
    let mut held = Box::pin(open_public_stream_with_authorization(
        ingress,
        &server_ca,
        &authorization,
        device.id,
        &service_path,
        &[],
    ));
    tokio::select! {
        result = &mut held => {
            return Err(early_result_error("EC-025 trust-crossing barrier", result));
        }
        waited = timeout(remaining(deadline), peer_barrier.wait_reached()) => {
            waited.map_err(|_| HarnessError::Timeout(
                "EC-025 trust-crossing peer admission barrier was not reached".into(),
            ))?;
        }
    }
    let scope_observed =
        peer_barrier.hit_count() == 1 && peer_barrier.observed_scope() == Some(scope);

    // ---- Retract the signed peer binding this request selected, while the
    // request is parked at the barrier.  The ingress relay's own signed record
    // is not touched, so it stays a trusted, ready member and answers about the
    // peer rather than about itself.
    let reissued_version = fixture_record_version(cluster, &owner_node)?.saturating_add(1);
    reissue_owner_peer_binding(cluster, harness, &owner_node).await?;
    let withdrawn_while_held =
        wait_for_reissued_binding(cluster, &owner_node, reissued_version).await?;

    // The barrier must still be holding the request: the boundary is crossed
    // mid-request or not at all.
    let still_held_at_withdrawal = tokio::select! {
        biased;
        result = &mut held => {
            return Err(early_result_error(
                "EC-025 trust-crossing request left the barrier before release",
                result,
            ));
        }
        () = sleep(POLL_INTERVAL) => true,
    };

    // Take the fault watermark after the publication has settled, so any
    // collateral fault the reissue caused on an unrelated stream is already
    // counted and the first later tuple belongs to the released request.
    let faults_before = ingress_fault_watermark(cluster).await?;
    peer_barrier.release();
    let outcome = timeout(remaining(deadline), &mut held)
        .await
        .map_err(|_| HarnessError::Timeout("EC-025 trust-crossing result timed out".into()))??;
    let (refusal_status, refusal_code, refusal_execution) = match outcome {
        PublicStreamProbe::Accepted(mut consumer) => {
            let _ = consumer.close().await;
            return Err(HarnessError::Process(
                "EC-025 trust-crossing request was admitted after its peer trust was withdrawn"
                    .into(),
            ));
        }
        PublicStreamProbe::Rejected(failure) => (
            failure.status,
            failure.code.map(str::to_owned),
            failure.execution.map(str::to_owned),
        ),
    };
    let after = counters(cluster).await?;
    let dispatch_delta = subtract(after, before);
    let owner_dispatch_delta = dispatch_delta[owner_index];
    let fault = ingress_fault_since(cluster, faults_before).await?;
    tracing::warn!(
        status = refusal_status,
        code = ?refusal_code,
        execution = ?refusal_execution,
        delta_a = dispatch_delta[0],
        delta_b = dispatch_delta[1],
        delta_c = dispatch_delta[2],
        owner_index,
        fault_role = ?fault.as_ref().map(|(role, _, _)| role.clone()),
        fault_stage = ?fault.as_ref().map(|(_, stage, _)| stage.clone()),
        fault_cause = ?fault.as_ref().map(|(_, _, cause)| cause.clone()),
        "EC-025 trust crossing outcome",
    );
    let (fault_role, fault_stage, fault_cause) = match fault {
        Some((role, stage, cause)) => (Some(role), Some(stage), Some(cause)),
        None => (None, None, None),
    };

    Ok(Ec025TrustCrossing {
        scope_observed,
        healthy_baseline_completed,
        withdrawn_while_held,
        still_held_at_withdrawal,
        refusal_status,
        refusal_code,
        refusal_execution,
        dispatch_delta,
        owner_dispatch_delta,
        fault_role,
        fault_stage,
        fault_cause,
    })
}

/// Publish a higher signed membership record for the owner node that keeps its
/// certificate trusted but moves its attested peer endpoint.  The record stays
/// valid and signed by the same authority, so this retracts the exact signed
/// binding the held request selected rather than causing a directory outage.
async fn reissue_owner_peer_binding(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    owner_node: &str,
) -> Result<()> {
    let node = cluster
        .fixture
        .nodes
        .iter()
        .find(|node| node.node_id == owner_node)
        .ok_or_else(|| {
            HarnessError::InvalidInput("EC-025 owner node is missing from the fixture".into())
        })?;
    // Re-sign the owner's peer binding onto a different, real peer endpoint.
    // The certificate stays trusted, so the pooled ingress->owner connection
    // survives the publication and the refusal can only come from the relay's
    // post-handshake revalidation of the signed peer binding.
    let peer_endpoint = cluster
        .peer_proxies
        .get(INGRESS_NODE)
        .ok_or_else(|| {
            HarnessError::InvalidInput("EC-025 substitute peer proxy is missing".into())
        })?
        .address();
    let current_version = cluster
        .fixture
        .memberships
        .get(owner_node)
        .map(|record| record.payload.record_version)
        .ok_or_else(|| {
            HarnessError::InvalidInput("EC-025 owner has no signed membership record".into())
        })?;
    let now = Utc::now();
    let withdrawn = FixturePeerKey {
        key_id: format!("{owner_node}-peer-withdrawn"),
        spki_sha256: node.peer_spki_fingerprint()?,
        not_before: now,
        expires_at: now + M7_MEMBERSHIP_LIFETIME,
        revoked: false,
    };
    let record = cluster
        .checkpoint_authority
        .issuer
        .sign_membership_with_endpoint_and_keys(
            &cluster.fixture.deployment_id,
            &cluster.fixture.deployment_incarnation,
            node,
            MembershipRecordOptions {
                record_version: current_version.saturating_add(1),
                peer_endpoint,
                keys: vec![withdrawn],
                now,
                expires_at: now + M7_MEMBERSHIP_LIFETIME,
            },
        )?;
    let publisher =
        RedisMembershipPublisher::connect(harness.redis.redis_url(), harness.redis.namespace())
            .await
            .map_err(|error| {
                HarnessError::Redis(format!("EC-025 withdrawal publisher: {error}"))
            })?;
    publisher
        .publish_signed_membership_for_node(owner_node, &record.catalog_record())
        .await
        .map_err(|error| HarnessError::Redis(format!("EC-025 publishing withdrawal: {error}")))
}

/// The signed record version currently held for one node in the fixture.
fn fixture_record_version(cluster: &ProductionCluster, node_id: &str) -> Result<u64> {
    cluster
        .fixture
        .memberships
        .get(node_id)
        .map(|record| record.payload.record_version)
        .ok_or_else(|| {
            HarnessError::InvalidInput("EC-025 node has no signed membership record".into())
        })
}

/// Wait until the ingress relay's own membership runtime has absorbed the
/// re-signed owner record, so the binding the held request selected is no
/// longer the one the signed directory attests.
async fn wait_for_reissued_binding(
    cluster: &ProductionCluster,
    owner_node: &str,
    expected_version: u64,
) -> Result<bool> {
    let deadline = Instant::now() + TRUST_WITHDRAWAL_TIMEOUT;
    loop {
        let snapshot = cluster.relay(INGRESS_NODE)?.membership.snapshot();
        let observed = snapshot
            .memberships
            .iter()
            .find(|membership| membership.node_id == owner_node)
            .map_or(0, |membership| membership.record_version);
        if observed >= expected_version {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "EC-025 ingress membership stayed on record version {observed}, expected {expected_version}"
            )));
        }
        sleep(POLL_INTERVAL).await;
    }
}

/// Highest peer-fault sequence the ingress relay has recorded so far.
async fn ingress_fault_watermark(cluster: &ProductionCluster) -> Result<u64> {
    Ok(cluster
        .relay(INGRESS_NODE)?
        .snapshot()
        .await?
        .peer_fault_diagnostics
        .recent
        .iter()
        .map(|event| event.sequence)
        .max()
        .unwrap_or(0))
}

/// The first peer fault the ingress relay recorded after `watermark`, as its
/// bounded `(role, stage, cause)` tuple.
async fn ingress_fault_since(
    cluster: &ProductionCluster,
    watermark: u64,
) -> Result<Option<(String, String, String)>> {
    Ok(cluster
        .relay(INGRESS_NODE)?
        .snapshot()
        .await?
        .peer_fault_diagnostics
        .recent
        .iter()
        .find(|event| event.sequence > watermark)
        .map(|event| {
            (
                event.role.as_str().to_owned(),
                event.stage.as_str().to_owned(),
                event.cause.as_str().to_owned(),
            )
        }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EchoOutcome {
    /// 101 upgrade plus an exact echo round-trip.
    Completed,
    /// 101 upgrade, then the echo was interrupted mid-handover. This is a
    /// legitimate post-dispatch interruption during a live rotation (the
    /// request still forwarded one hop to the exact owner), never a stale or
    /// unrelated-backend dispatch.
    Interrupted,
    /// A typed 503 not-dispatched rejection at the ingress.
    TypedNotDispatched,
    /// Any other outcome: an untyped or wrongly-typed rejection. A violation.
    Untyped,
}

impl EchoOutcome {
    fn is_typed_not_dispatched(&self) -> bool {
        matches!(self, EchoOutcome::TypedNotDispatched)
    }

    fn require_completed(self, label: &str) -> Result<()> {
        match self {
            EchoOutcome::Completed => Ok(()),
            other => Err(HarnessError::Process(format!(
                "{label} did not complete: {other:?}"
            ))),
        }
    }
}

/// Fire one echo through the ingress and classify it.
async fn echo_once(
    ingress: SocketAddr,
    server_ca: &[u8],
    authorization: &str,
    device_id: Uuid,
    service_path: &str,
) -> Result<EchoOutcome> {
    let probe = open_public_stream_with_authorization(
        ingress,
        server_ca,
        authorization,
        device_id,
        service_path,
        &[],
    )
    .await?;
    match probe {
        PublicStreamProbe::Accepted(mut consumer) => {
            let round = consumer.round_trip(&[], CANARY).await;
            let _ = consumer.close().await;
            match round {
                Ok(()) => Ok(EchoOutcome::Completed),
                Err(error) => {
                    tracing::warn!(%error, "EC-025 echo interrupted after admission");
                    Ok(EchoOutcome::Interrupted)
                }
            }
        }
        PublicStreamProbe::Rejected(failure) => {
            let typed = failure.status == 503
                && failure
                    .code
                    .is_some_and(|code| NOT_DISPATCHED_CODES.contains(&code))
                && failure.execution == Some("not_dispatched");
            if typed {
                Ok(EchoOutcome::TypedNotDispatched)
            } else {
                tracing::warn!(
                    status = failure.status,
                    code = ?failure.code,
                    execution = ?failure.execution,
                    "EC-025 untyped rejection",
                );
                Ok(EchoOutcome::Untyped)
            }
        }
    }
}

async fn counters(cluster: &ProductionCluster) -> Result<[u64; 3]> {
    let mut dispatch = [0_u64; 3];
    for (index, node) in NODES.into_iter().enumerate() {
        dispatch[index] = cluster
            .relay(node)?
            .snapshot()
            .await?
            .lifetime_application_dispatches;
    }
    Ok(dispatch)
}

fn subtract(after: [u64; 3], before: [u64; 3]) -> [u64; 3] {
    [
        after[0].saturating_sub(before[0]),
        after[1].saturating_sub(before[1]),
        after[2].saturating_sub(before[2]),
    ]
}

fn exact_owner_only(delta: &[u64; 3], owner_index: usize) -> bool {
    delta[owner_index] == 1
        && delta
            .iter()
            .enumerate()
            .all(|(index, value)| index == owner_index || *value == 0)
}

fn node_index(node_id: &str) -> Result<usize> {
    NODES
        .iter()
        .position(|candidate| *candidate == node_id)
        .ok_or_else(|| HarnessError::InvalidInput("EC-025 owner outside the relay set".into()))
}

async fn wait_for_ingress_unready(cluster: &ProductionCluster) -> Result<()> {
    let deadline = Instant::now() + READINESS_FLIP_TIMEOUT;
    loop {
        if !cluster.relay(INGRESS_NODE)?.peer_runtime.is_ready() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "EC-025 ingress did not become unready after the peer route drop".into(),
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn owner_rotations_completed(
    cluster: &ProductionCluster,
    owner_node: &str,
    device_id: Uuid,
) -> Result<u64> {
    let snapshot = cluster.relay(owner_node)?.snapshot().await?;
    Ok(snapshot
        .sessions
        .iter()
        .find(|session| session.device_id == device_id.to_string())
        .map_or(0, |session| session.rotations_completed))
}

async fn wait_for_rotation_progress(
    cluster: &ProductionCluster,
    owner_node: &str,
    device_id: Uuid,
    start: u64,
) -> Result<u64> {
    let deadline = Instant::now() + ROTATION_WAIT_TIMEOUT;
    loop {
        let current = owner_rotations_completed(cluster, owner_node, device_id).await?;
        if current > start {
            return Ok(current);
        }
        if Instant::now() >= deadline {
            return Ok(current);
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_owner(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
) -> Result<tunnel_catalog::OwnerClaim> {
    let deadline = Instant::now() + super::STARTUP_TIMEOUT;
    loop {
        if let Some(owner) = cluster
            .catalog
            .current_owner(tenant_id, device_id, Utc::now())
            .await
            .map_err(|error| HarnessError::Redis(format!("EC-025 owner lookup: {error}")))?
        {
            return Ok(owner);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "EC-025 owner did not become visible".into(),
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}

fn early_result_error(label: &str, result: Result<PublicStreamProbe>) -> HarnessError {
    match result {
        Ok(PublicStreamProbe::Accepted(_)) => {
            HarnessError::Process(format!("{label} upgraded before its barrier"))
        }
        Ok(PublicStreamProbe::Rejected(failure)) => HarnessError::Process(format!(
            "{label} was rejected before its barrier: status={} code={:?} execution={:?}",
            failure.status, failure.code, failure.execution
        )),
        Err(error) => HarnessError::Http(format!("{label} ended before its barrier: {error}")),
    }
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn append_cleanup(slot: &mut Option<HarnessError>, label: &str, result: Result<()>) {
    if let Err(error) = result {
        let combined = match slot.take() {
            Some(primary) => HarnessError::Process(format!("{primary}; {label}: {error}")),
            None => HarnessError::Process(format!("{label}: {error}")),
        };
        *slot = Some(combined);
    }
}

#[cfg(test)]
mod c17_validator_tests {
    use super::*;
    use crate::acceptance_test_support::{assert_failed, assert_rejected};

    fn valid_evidence() -> Ec025HandoverEvidence {
        Ec025HandoverEvidence {
            relay_count: 3,
            ingress_is_not_owner: true,
            owner_node_unchanged: true,
            baseline_exact_owner_dispatch: true,
            exact_owner_scope_observed: true,
            barrier_completed_exact_owner: true,
            peer_delay_typed_not_dispatched: true,
            peer_delay_zero_dispatch: true,
            rotation_observed: true,
            across_rotation_no_foreign_dispatch: true,
            across_rotation_completed_or_typed: true,
            across_rotation_completed: ACROSS_ROTATION_REQUESTS,
            across_rotation_interrupted: 0,
            across_rotation_not_dispatched: 0,
            trust_crossing: valid_trust_crossing(),
            cleanup_joined: true,
        }
    }

    fn valid_trust_crossing() -> Ec025TrustCrossing {
        Ec025TrustCrossing {
            scope_observed: true,
            healthy_baseline_completed: true,
            withdrawn_while_held: true,
            still_held_at_withdrawal: true,
            refusal_status: TRUST_CROSSING_STATUS,
            refusal_code: Some(TRUST_CROSSING_CODE.to_owned()),
            refusal_execution: Some(TRUST_CROSSING_EXECUTION.to_owned()),
            dispatch_delta: [0, 0, 0],
            owner_dispatch_delta: 0,
            fault_role: Some(TRUST_CROSSING_FAULT_ROLE.to_owned()),
            fault_stage: Some(TRUST_CROSSING_FAULT_STAGE.to_owned()),
            fault_cause: Some(TRUST_CROSSING_FAULT_CAUSE.to_owned()),
        }
    }

    #[test]
    fn every_ec025_trust_crossing_condition_reaches_the_shared_exit_path() {
        type Mutate = (&'static str, fn(&mut Ec025TrustCrossing));
        let cases: [Mutate; 15] = [
            ("scope_observed", |c| c.scope_observed = false),
            ("healthy_baseline_completed", |c| {
                c.healthy_baseline_completed = false
            }),
            ("withdrawn_while_held", |c| c.withdrawn_while_held = false),
            ("still_held_at_withdrawal", |c| {
                c.still_held_at_withdrawal = false
            }),
            ("refusal_status", |c| c.refusal_status = 500),
            // The two weaker unavailability codes a sibling gate returns are
            // rejected by name: neither proves the withdrawal caused it.
            ("cluster_unready_is_not_enough", |c| {
                c.refusal_code = Some("CLUSTER_UNREADY".to_owned())
            }),
            ("peer_unavailable_is_not_enough", |c| {
                c.refusal_code = Some("PEER_UNAVAILABLE".to_owned())
            }),
            ("refusal_execution", |c| {
                c.refusal_execution = Some("unknown".to_owned())
            }),
            ("dispatch_delta", |c| c.dispatch_delta = [0, 1, 0]),
            ("owner_dispatch_delta", |c| {
                c.dispatch_delta = [1, 0, 0];
                c.owner_dispatch_delta = 1;
            }),
            // A fault the transport raised, or one raised after the envelope
            // was already on the wire, would not prove the revalidation.
            ("fault_cause_transport", |c| {
                c.fault_cause = Some("transport_h3".to_owned())
            }),
            ("fault_cause_membership", |c| {
                c.fault_cause = Some("membership".to_owned())
            }),
            ("fault_stage_body", |c| {
                c.fault_stage = Some("body".to_owned())
            }),
            ("fault_role", |c| c.fault_role = Some("owner".to_owned())),
            ("fault_absent", |c| {
                c.fault_role = None;
                c.fault_stage = None;
                c.fault_cause = None;
            }),
        ];
        for (_, mutate) in cases {
            let mut evidence = valid_evidence();
            mutate(&mut evidence.trust_crossing);
            assert_rejected(validate_ec025_handover_evidence(&evidence), "EC-025");
        }
    }

    #[test]
    fn ec025_validator_accepts_complete_evidence() {
        assert!(validate_ec025_handover_evidence(&valid_evidence()).is_ok());
    }

    #[test]
    fn every_ec025_required_flag_reaches_the_shared_exit_path() {
        type Disable = (&'static str, fn(&mut Ec025HandoverEvidence));
        let flags: [Disable; 11] = [
            ("ingress_is_not_owner", |e| e.ingress_is_not_owner = false),
            ("owner_node_unchanged", |e| e.owner_node_unchanged = false),
            ("baseline_exact_owner_dispatch", |e| {
                e.baseline_exact_owner_dispatch = false
            }),
            ("exact_owner_scope_observed", |e| {
                e.exact_owner_scope_observed = false
            }),
            ("barrier_completed_exact_owner", |e| {
                e.barrier_completed_exact_owner = false
            }),
            ("peer_delay_typed_not_dispatched", |e| {
                e.peer_delay_typed_not_dispatched = false
            }),
            ("peer_delay_zero_dispatch", |e| {
                e.peer_delay_zero_dispatch = false
            }),
            ("rotation_observed", |e| e.rotation_observed = false),
            ("across_rotation_no_foreign_dispatch", |e| {
                e.across_rotation_no_foreign_dispatch = false
            }),
            ("across_rotation_completed_or_typed", |e| {
                e.across_rotation_completed_or_typed = false
            }),
            ("cleanup_joined", |e| e.cleanup_joined = false),
        ];
        for (_, disable) in flags {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_failed(validate_ec025_handover_evidence(&evidence));
        }
    }

    #[test]
    fn every_ec025_count_condition_reaches_the_shared_exit_path() {
        type Mutate = (&'static str, fn(&mut Ec025HandoverEvidence));
        let counts: [Mutate; 4] = [
            ("relay_count", |e| e.relay_count = 2),
            ("across_rotation_undercount", |e| {
                e.across_rotation_completed = 0;
                e.across_rotation_interrupted = 0;
                e.across_rotation_not_dispatched = 0;
            }),
            ("across_rotation_overcount", |e| {
                e.across_rotation_completed = ACROSS_ROTATION_REQUESTS;
                e.across_rotation_interrupted = ACROSS_ROTATION_REQUESTS;
            }),
            ("across_rotation_no_completion", |e| {
                e.across_rotation_completed = 0;
                e.across_rotation_not_dispatched = ACROSS_ROTATION_REQUESTS;
            }),
        ];
        for (_, mutate) in counts {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(validate_ec025_handover_evidence(&evidence), "EC-025");
        }
    }
}
