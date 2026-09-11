//! Real M7-C20/C26 production capacity phase.
//!
//! This fixture uses real listeners, three device CLI owners, one public
//! consumer canary, and authenticated PeerRuntime consumer admissions.  The
//! three tenant-A devices are attached directly to relay-a so their owner
//! placement is explicit.  Their bounded 64-stream actor limits provide 192
//! possible authenticated consumer exchanges; the transport's configured
//! maximum is held from relay-b to relay-a to exhaust relay-b's single pooled
//! H3 route without changing production limits or the public ingress limit.

use super::{
    ConsumerStream, LIVEZ_BODY, ProductionCluster, READYZ_BODY, RunningHarness, SCENARIO_TIMEOUT,
    STARTUP_TIMEOUT, UNREADYZ_BODY, open_consumer_stream, public_health_request,
};
use crate::acceptance::helpers::{DeviceProfile, write_device_profile};
use crate::{
    Harness, HarnessError, HarnessOptions, ManagedProcess, OidcTokenOptions, ProcessSpec, Result,
};
use chrono::Utc;
use futures_util::future::join_all;
use std::future::Future;
use std::time::{Duration, Instant};
use tempfile::tempdir;
use tokio::time::{sleep, timeout};
use tunnel_catalog::OwnerToken;
use tunnel_cluster::envelope::{
    ConsumerStreamsRequest, Destination, ForwardedConsumerBearer, InternalRequest, InternalRoute,
    RequestEnvelope,
};
use tunnel_cluster::peer_frame::PeerRecordKind;
use tunnel_core::RotationConfig;
use tunnel_relay::{
    MembershipReadiness, PeerRuntimeError, RelaySnapshot,
    peer_runtime::{PeerExchangeRecv, PeerExchangeSend, PeerOpenDiagnostic},
    routing::OwnerScope,
};
use tunnel_transport::{
    PeerPoolConnectionStats, PeerPoolStats, PeerServerConnectionStats, PeerServerStats,
    PeerTransportError, PeerTransportLimits,
};
use uuid::Uuid;

const TARGET_NODE: &str = "relay-a";
const INGRESS_NODE: &str = "relay-b";
const CAPACITY_LOSS_TIMEOUT: Duration = Duration::from_secs(12);
const CAPACITY_RECOVERY_TIMEOUT: Duration = Duration::from_secs(20);
const CAPACITY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
const CAPACITY_COMPARISON_WINDOW: Duration = Duration::from_secs(5);
const CAPACITY_DIAGNOSTIC_TIMEOUT: Duration = Duration::from_millis(500);
// The configured peer QUIC connection idle timeout is longer than this
// fixture's bounded phases. The actor and H3 receive paths have their own idle
// bounds, so keep every retained request alive with a bounded zero-length echo
// exchange well inside those paths. This exercises the real owner route and
// never changes transport limits or sends application payload.
const CAPACITY_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(1);
const CAPACITY_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(2);
const CAPACITY_KEEPALIVE_RECORD: [u8; 4] = [0; 4];
const CAPACITY_KEEPALIVE_REQUEST: &[u8] = b"m7-peer-capacity-keepalive";
const HOLDER_CLOSE_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const MAX_STREAMS_PER_DEVICE: usize = 64;

/// Evidence from one real three-relay H3 capacity withdrawal/recovery phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerCapacityEvidence {
    pub relay_count: usize,
    pub membership_ready_relays: usize,
    pub peer_stream_limit: usize,
    pub per_device_streams: [usize; 3],
    pub owner_count_on_target: usize,
    pub held_authenticated_streams: usize,
    pub baseline_echo: bool,
    pub public_livez_ok_during_capacity: bool,
    pub public_readyz_unready_during_capacity: bool,
    pub capacity_route_withdrawn: bool,
    pub capacity_probe_typed: bool,
    pub selected_admission_rejected: bool,
    pub selected_dispatch_not_advanced: bool,
    pub held_stream_survived: bool,
    pub public_readyz_ok_after_recovery: bool,
    pub fresh_recovery_echo: bool,
    pub elapsed_ms: u64,
}

/// Validate the mandatory evidence fields before a caller promotes the phase
/// to C20/C26 production evidence.
pub fn validate_peer_capacity_evidence(evidence: &PeerCapacityEvidence) -> Result<()> {
    let max_elapsed_ms = u64::try_from(SCENARIO_TIMEOUT.as_millis()).unwrap_or(u64::MAX);
    if evidence.elapsed_ms == 0 || evidence.elapsed_ms > max_elapsed_ms {
        return Err(HarnessError::Process(format!(
            "peer capacity phase elapsed_ms={} is outside its bounded nonzero range 1..={max_elapsed_ms}",
            evidence.elapsed_ms
        )));
    }
    if evidence.relay_count != 3 || evidence.membership_ready_relays != 3 {
        return Err(HarnessError::Process(
            "peer capacity phase did not start three Ready relays".into(),
        ));
    }
    if evidence.owner_count_on_target != 3 {
        return Err(HarnessError::Process(format!(
            "peer capacity phase expected three owners on {TARGET_NODE}, observed {}",
            evidence.owner_count_on_target
        )));
    }
    if evidence.peer_stream_limit == 0
        || evidence.held_authenticated_streams != evidence.peer_stream_limit
    {
        return Err(HarnessError::Process(format!(
            "peer capacity phase held {} authenticated streams, expected configured limit {}",
            evidence.held_authenticated_streams, evidence.peer_stream_limit
        )));
    }
    if evidence
        .per_device_streams
        .iter()
        .any(|streams| *streams == 0 || *streams > MAX_STREAMS_PER_DEVICE)
        || evidence.per_device_streams.iter().sum::<usize>() != evidence.held_authenticated_streams
    {
        return Err(HarnessError::Process(format!(
            "peer capacity per-device occupancy {:?} exceeds the configured actor bound {MAX_STREAMS_PER_DEVICE} or does not sum to {}",
            evidence.per_device_streams, evidence.held_authenticated_streams
        )));
    }
    let required = [
        ("baseline_echo", evidence.baseline_echo),
        (
            "public_livez_ok_during_capacity",
            evidence.public_livez_ok_during_capacity,
        ),
        (
            "public_readyz_unready_during_capacity",
            evidence.public_readyz_unready_during_capacity,
        ),
        (
            "capacity_route_withdrawn",
            evidence.capacity_route_withdrawn,
        ),
        ("capacity_probe_typed", evidence.capacity_probe_typed),
        (
            "selected_admission_rejected",
            evidence.selected_admission_rejected,
        ),
        (
            "selected_dispatch_not_advanced",
            evidence.selected_dispatch_not_advanced,
        ),
        ("held_stream_survived", evidence.held_stream_survived),
        (
            "public_readyz_ok_after_recovery",
            evidence.public_readyz_ok_after_recovery,
        ),
        ("fresh_recovery_echo", evidence.fresh_recovery_echo),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "peer capacity required gate {name} was false"
        )));
    }
    Ok(())
}

struct CapacityResources {
    processes: Vec<ManagedProcess>,
    streams: Vec<ConsumerStream>,
    peer_streams: Vec<PeerConsumerStream>,
    owned_devices: Vec<Uuid>,
    owner_tokens: Vec<OwnerToken>,
    /// Keep client configuration and certificate tempdirs alive until every
    /// process has been reaped, including when the scenario deadline fires.
    profiles: Vec<DeviceProfile>,
    profile_root: Option<tempfile::TempDir>,
}

impl CapacityResources {
    fn new(stream_limit: usize) -> Self {
        Self {
            processes: Vec::with_capacity(3),
            streams: Vec::with_capacity(1),
            peer_streams: Vec::with_capacity(stream_limit.saturating_sub(1)),
            owned_devices: Vec::with_capacity(3),
            owner_tokens: Vec::with_capacity(3),
            profiles: Vec::with_capacity(3),
            profile_root: None,
        }
    }
}

/// An authenticated long-lived owner admission opened through the production
/// PeerRuntime path.  Keeping both halves alive retains the real H3 stream
/// permit and the owner actor registration until the phase explicitly cancels
/// it.
struct PeerConsumerStream {
    send: PeerExchangeSend,
    recv: PeerExchangeRecv,
    expected_canary: Vec<u8>,
}

impl PeerConsumerStream {
    fn cancel(&mut self) {
        self.send.cancel();
        self.recv.cancel();
    }
}

impl Drop for PeerConsumerStream {
    fn drop(&mut self) {
        self.cancel();
    }
}

impl PeerConsumerStream {
    /// An empty request is echoed as one complete length-prefixed response:
    /// four bytes of canary length followed by this device's canary. Keeping
    /// that exact expected body prevents an unrelated or truncated
    /// `ConsumerChunk` from counting as a live holder.
    fn expected_keepalive_response(&self) -> Result<Vec<u8>> {
        let canary_len = u32::try_from(self.expected_canary.len()).map_err(|_| {
            HarnessError::InvalidInput("peer-capacity device canary exceeds framing limit".into())
        })?;
        let mut response = Vec::with_capacity(4 + self.expected_canary.len());
        response.extend_from_slice(&canary_len.to_be_bytes());
        response.extend_from_slice(&self.expected_canary);
        Ok(response)
    }
}

/// Prove every retained owner-side H3 exchange is still live without
/// extending the production idle timeout. A zero-length length-prefixed
/// ConsumerChunk is a bounded real echo operation; its response is consumed
/// before the next pulse, so a reset/FIN cannot be mistaken for a retained
/// client-side handle. This is needed even when other traffic keeps Quinn's
/// connection idle timer active: `PeerExchangeRecv::recv_message` reaches the
/// per-stream `PeerClientRecv::recv_chunk` idle deadline independently.
async fn keep_capacity_peer_streams_alive(
    streams: &mut [PeerConsumerStream],
    phase: &'static str,
    public_stream_count: usize,
) -> Result<()> {
    let peer_stream_count = streams.len();
    let outcomes = join_all(streams.iter_mut().enumerate().map(
        |(stream_index, stream)| async move {
            pulse_capacity_peer_stream(
                stream,
                phase,
                stream_index,
                public_stream_count,
                peer_stream_count,
            )
            .await
        },
    ))
    .await;
    if let Some(error) = outcomes.into_iter().find_map(|result| result.err()) {
        return Err(error);
    }
    Ok(())
}

/// Authenticate one retained peer exchange with a real bounded echo before it
/// is counted as a holder. An HTTP 200 response only proves that the
/// PeerRuntime envelope was accepted; the owner M2 stream can still be
/// `open_pending` until its first authenticated record. Keep the exact canary
/// check here so a later roster pulse cannot hide a stream that never became a
/// usable owner exchange.
async fn pulse_capacity_peer_stream(
    stream: &mut PeerConsumerStream,
    phase: &'static str,
    stream_index: usize,
    public_stream_count: usize,
    peer_stream_count: usize,
) -> Result<()> {
    let expected_response = stream.expected_keepalive_response()?;
    let pulse = async {
        stream
            .send
            .send_message(PeerRecordKind::ConsumerChunk, &CAPACITY_KEEPALIVE_RECORD)
            .await
            .map_err(|error| peer_admission_harness_error("capacity keepalive send", error))?;
        let response =
            stream.recv.recv_message().await.map_err(|error| {
                peer_admission_harness_error("capacity keepalive receive", error)
            })?;
        match response {
            Some(record)
                if record.kind() == PeerRecordKind::ConsumerChunk
                    && record.body() == expected_response.as_slice() =>
            {
                Ok(())
            }
            Some(record) if record.kind() != PeerRecordKind::ConsumerChunk => {
                Err(HarnessError::Process(
                    "peer-capacity keepalive returned an unexpected record kind".into(),
                ))
            }
            Some(record) => Err(HarnessError::Process(format!(
                "peer-capacity keepalive response did not match its device canary (body_len={}, expected_len={})",
                record.body_len(),
                expected_response.len()
            ))),
            None => Err(HarnessError::Process(
                "peer-capacity keepalive stream ended before its response".into(),
            )),
        }
    };
    let result = timeout(CAPACITY_KEEPALIVE_TIMEOUT, pulse)
        .await
        .map_err(|_| {
            HarnessError::Timeout(format!(
                "peer-capacity {phase} peer keepalive timed out at stream_index={stream_index}, public_streams={public_stream_count}, peer_streams={peer_stream_count}"
            ))
        })?;
    result.map_err(|error| {
        annotate_capacity_stream_failure(
            "peer",
            phase,
            stream_index,
            public_stream_count,
            peer_stream_count,
            error,
        )
    })
}

/// Keep the retained public canary alive with the same bounded exact echo used
/// for the authenticated peer exchanges.  The public ingress has its own H3
/// receive idle bound, so owner-side pulses alone cannot prove all held
/// streams survived the capacity transition.
async fn keep_capacity_public_streams_alive(
    streams: &mut [ConsumerStream],
    canary: &[u8],
    phase: &'static str,
    peer_stream_count: usize,
) -> Result<()> {
    let public_stream_count = streams.len();
    let outcomes = join_all(streams.iter_mut().enumerate().map(|(stream_index, stream)| async move {
        let result = timeout(
            CAPACITY_KEEPALIVE_TIMEOUT,
            stream.round_trip(CAPACITY_KEEPALIVE_REQUEST, canary),
        )
        .await
        .map_err(|_| {
            HarnessError::Timeout(format!(
                "peer-capacity {phase} public keepalive timed out at stream_index={stream_index}, public_streams={public_stream_count}, peer_streams={peer_stream_count}"
            ))
        })?
        .map_err(|error| {
            HarnessError::Http(format!("peer-capacity public keepalive failed: {error}"))
        });
        result.map_err(|error| {
            annotate_capacity_stream_failure(
                "public",
                phase,
                stream_index,
                public_stream_count,
                peer_stream_count,
                error,
            )
        })
    }))
    .await;
    if let Some(error) = outcomes.into_iter().find_map(|result| result.err()) {
        return Err(error);
    }
    Ok(())
}

fn annotate_capacity_stream_failure(
    role: &str,
    phase: &'static str,
    stream_index: usize,
    public_stream_count: usize,
    peer_stream_count: usize,
    error: HarnessError,
) -> HarnessError {
    let context = format!(
        "peer-capacity {phase} {role} keepalive failed at stream_index={stream_index}, public_streams={public_stream_count}, peer_streams={peer_stream_count}"
    );
    match error {
        HarnessError::Timeout(message) => HarnessError::Timeout(format!("{context}: {message}")),
        HarnessError::Http(message) => HarnessError::Http(format!("{context}: {message}")),
        HarnessError::Process(message) => HarnessError::Process(format!("{context}: {message}")),
        other => HarnessError::Process(format!("{context}: {other}")),
    }
}

async fn keep_capacity_streams_alive(
    public_streams: &mut [ConsumerStream],
    peer_streams: &mut [PeerConsumerStream],
    canary: &[u8],
    phase: &'static str,
) -> Result<()> {
    let public_stream_count = public_streams.len();
    let peer_stream_count = peer_streams.len();
    let (public_result, peer_result) = tokio::join!(
        keep_capacity_public_streams_alive(public_streams, canary, phase, peer_stream_count),
        keep_capacity_peer_streams_alive(peer_streams, phase, public_stream_count),
    );
    match (public_result, peer_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(public_error), Ok(())) => Err(public_error),
        (Ok(()), Err(peer_error)) => Err(peer_error),
        (Err(public_error), Err(peer_error)) => Err(HarnessError::Process(format!(
            "peer-capacity {phase} public and peer keepalive failures: public={public_error}; peer={peer_error}"
        ))),
    }
}

enum CapacityAdmissionWaitError<E> {
    Admission(E),
    Keepalive(HarnessError),
}

/// Await one bounded peer admission while retaining a heartbeat for every
/// already-admitted exchange. A heartbeat at the top of the outer fill loop is
/// insufficient: opening a stream and accepting its response can each wait
/// for eight seconds, while keeping each actor/H3 receive operation inside its
/// shorter bounded idle window.
async fn await_with_keepalive<T, E, F>(
    admission: F,
    keepalive: CapacityKeepalive<'_>,
) -> std::result::Result<T, CapacityAdmissionWaitError<E>>
where
    F: Future<Output = std::result::Result<T, E>>,
{
    let CapacityKeepalive {
        cluster,
        owners,
        public_streams,
        peer_streams,
        canary,
        next_keepalive_at,
        phase,
    } = keepalive;
    tokio::pin!(admission);
    loop {
        if public_streams.is_empty() && peer_streams.is_empty() {
            return (&mut admission)
                .await
                .map_err(CapacityAdmissionWaitError::Admission);
        }
        let wait = next_keepalive_at.saturating_duration_since(Instant::now());
        // Dropping a pulse after it has sent a request would leave its exact
        // response queued for the next pulse.  Track the point at which the
        // pulse starts touching either exchange so an admission win can drop
        // only the pre-send sleep, or otherwise join the pulse to completion.
        let pulse_started = std::cell::Cell::new(false);
        let pulse = async {
            sleep(wait).await;
            pulse_started.set(true);
            keep_capacity_streams_alive(public_streams, peer_streams, canary, phase).await
        };
        tokio::pin!(pulse);
        tokio::select! {
            result = &mut admission => {
                let admission_result = result;
                if pulse_started.get() {
                    let pulse_result = (&mut pulse).await;
                    if let Err(error) = pulse_result {
                        return Err(CapacityAdmissionWaitError::Keepalive(
                            annotate_capacity_keepalive_failure(cluster, owners, error).await,
                        ));
                    }
                    *next_keepalive_at = Instant::now() + CAPACITY_KEEPALIVE_INTERVAL;
                }
                return admission_result.map_err(CapacityAdmissionWaitError::Admission);
            },
            pulse_result = &mut pulse => {
                if let Err(error) = pulse_result {
                    return Err(CapacityAdmissionWaitError::Keepalive(
                        annotate_capacity_keepalive_failure(cluster, owners, error).await,
                    ));
                }
                *next_keepalive_at = Instant::now() + CAPACITY_KEEPALIVE_INTERVAL;
            }
        }
    }
}

struct CapacityKeepalive<'a> {
    cluster: &'a ProductionCluster,
    owners: &'a [OwnerToken],
    public_streams: &'a mut [ConsumerStream],
    peer_streams: &'a mut [PeerConsumerStream],
    canary: &'a [u8],
    next_keepalive_at: &'a mut Instant,
    phase: &'static str,
}

async fn assert_owner_bindings_with_keepalive(
    expected_streams: &[usize; 3],
    budget: Duration,
    keepalive: CapacityKeepalive<'_>,
) -> Result<()> {
    let cluster_for_admission = keepalive.cluster;
    let owners_for_admission = keepalive.owners;
    match await_with_keepalive(
        assert_owner_bindings(
            cluster_for_admission,
            owners_for_admission,
            expected_streams,
            budget,
        ),
        keepalive,
    )
    .await
    {
        Ok(()) => Ok(()),
        Err(CapacityAdmissionWaitError::Admission(error)) => Err(error),
        Err(CapacityAdmissionWaitError::Keepalive(error)) => Err(error),
    }
}

fn remaining_capacity_window(deadline: Instant, stage: &str) -> Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(HarnessError::Timeout(format!(
            "peer-capacity {stage} exceeded its absolute comparison deadline"
        )));
    }
    Ok(remaining)
}

/// Run the real capacity phase with bounded phase deadlines and ordered
/// cleanup.  ManagedProcess owns the final child/output reaping step, so the
/// fixture reports its result only after that cleanup future completes.
pub async fn verify() -> Result<PeerCapacityEvidence> {
    // Capacity filling intentionally runs longer than the normal M7 rotation
    // interval.  Use the validated five-minute default for this fixture so a
    // 128-stream occupancy observation is not interleaved with a separate
    // owner fence/roster transition.
    let capacity_rotation = RotationConfig::default();
    let options = HarnessOptions::from_env()?
        .rotation(capacity_rotation)
        .shared_device_uuid(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("peer-capacity harness startup timed out".into()))??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let cleanup_deadline = tokio::time::Instant::now() + super::CLEANUP_TIMEOUT;
            return match harness.shutdown_until(cleanup_deadline).await {
                Ok(()) => Err(error),
                Err(cleanup) => Err(HarnessError::Process(format!(
                    "{error}; peer-capacity harness startup cleanup failed: {cleanup}"
                ))),
            };
        }
    };

    let peer_stream_limit = PeerTransportLimits::default().max_streams_per_connection;
    let mut resources = CapacityResources::new(peer_stream_limit);
    let scenario = match timeout(
        SCENARIO_TIMEOUT,
        run(&mut cluster, &harness, peer_stream_limit, &mut resources),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "peer-capacity production scenario exceeded its bounded deadline".into(),
        )),
    };
    let resource_cleanup =
        cleanup_resources(&cluster, harness.topology.tenant_a.id, &mut resources).await;
    let cleanup_deadline = tokio::time::Instant::now() + super::CLEANUP_TIMEOUT;
    let cluster_cleanup = cluster.shutdown_until(cleanup_deadline).await;
    let harness_cleanup = harness.shutdown_until(cleanup_deadline).await;
    let mut cleanup_errors = Vec::new();
    if let Err(error) = resource_cleanup {
        cleanup_errors.push(format!("peer-capacity resource cleanup failed: {error}"));
    }
    if let Err(error) = cluster_cleanup {
        cleanup_errors.push(format!("peer-capacity relay cleanup failed: {error}"));
    }
    if let Err(error) = harness_cleanup {
        cleanup_errors.push(format!("peer-capacity Redis cleanup failed: {error}"));
    }
    match scenario {
        Err(error) if cleanup_errors.is_empty() => Err(error),
        Err(error) => Err(HarnessError::Process(format!(
            "{error}; {}",
            cleanup_errors.join("; ")
        ))),
        Ok(_) if !cleanup_errors.is_empty() => {
            Err(HarnessError::Process(cleanup_errors.join("; ")))
        }
        Ok(evidence) => Ok(evidence),
    }
}

async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    peer_stream_limit: usize,
    resources: &mut CapacityResources,
) -> Result<PeerCapacityEvidence> {
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(format!(
            "peer-capacity phase started {} relays, expected three",
            cluster.relays.len()
        )));
    }
    cluster.wait_for_peer_readiness(STARTUP_TIMEOUT).await?;
    let membership_ready_relays = cluster
        .relays
        .iter()
        .filter(|relay| matches!(relay.membership.readiness(), MembershipReadiness::Ready))
        .count();
    if membership_ready_relays != 3 {
        return Err(HarnessError::Process(format!(
            "peer-capacity phase started with {membership_ready_relays}/3 Ready memberships"
        )));
    }

    let ingress_addr = cluster.relay(INGRESS_NODE)?.consumer_addr()?;
    let target_device_addr = cluster
        .relay(TARGET_NODE)?
        .running
        .as_ref()
        .ok_or_else(|| HarnessError::Process("target relay has no device listener".into()))?
        .device_addr;
    let stream_targets = distribute_streams(peer_stream_limit)?;
    let held_streams = stream_targets.iter().sum::<usize>();
    if held_streams != peer_stream_limit {
        return Err(HarnessError::Process(format!(
            "peer-capacity distribution held {held_streams} streams, expected the configured transport limit {peer_stream_limit}"
        )));
    }
    if stream_targets
        .iter()
        .any(|streams| *streams > MAX_STREAMS_PER_DEVICE)
    {
        return Err(HarnessError::Process(format!(
            "peer-capacity configured transport limit {peer_stream_limit} would exceed the per-device actor bound {MAX_STREAMS_PER_DEVICE}: {stream_targets:?}"
        )));
    }
    let devices = harness
        .topology
        .devices_a
        .iter()
        .take(stream_targets.len())
        .collect::<Vec<_>>();
    if devices.len() != stream_targets.len() {
        return Err(HarnessError::InvalidInput(
            "peer-capacity phase requires three tenant-A devices".into(),
        ));
    }
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        super::OidcTokenOptions {
            expires_in: Duration::from_secs(120),
            ..OidcTokenOptions::default()
        },
    )?;
    let profile_root = tempdir().map_err(HarnessError::Io)?;
    let mut profiles = Vec::with_capacity(devices.len());
    for (index, device) in devices.iter().enumerate() {
        let service_id = *harness
            .topology
            .service_ids
            .get(&device.id)
            .ok_or_else(|| HarnessError::InvalidInput("peer-capacity service is missing".into()))?;
        let mut profile = write_device_profile(
            profile_root.path(),
            device.id,
            service_id,
            &format!("m7-peer-capacity:{index}:{}", device.id),
            target_device_addr,
            &device.certificate.certificate_pem,
            &device.certificate.private_key_pem,
            &harness.pki.server_ca.certificate_pem,
        )?;
        profile.config.rotation = harness.rotation_config();
        profile.config.validate().map_err(|error| {
            HarnessError::InvalidInput(format!("peer-capacity client config: {error}"))
        })?;
        profiles.push(profile);
    }
    // The phase is bounded independently of cleanup.  Move the profiles into
    // the resource guard before any child is spawned so a timed-out scenario
    // cannot remove a live client's config while its process is being reaped.
    resources.profiles = profiles;
    resources.profile_root = Some(profile_root);

    let phase = run_capacity_phase(
        cluster,
        harness,
        peer_stream_limit,
        ingress_addr,
        target_device_addr,
        &token,
        &devices,
        &stream_targets,
        resources,
    )
    .await;
    match phase {
        Err(error) => Err(error),
        Ok(evidence) => {
            validate_peer_capacity_evidence(&evidence)?;
            Ok(evidence)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_capacity_phase(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    peer_stream_limit: usize,
    ingress_addr: std::net::SocketAddr,
    target_device_addr: std::net::SocketAddr,
    token: &str,
    devices: &[&crate::DeviceFixture],
    stream_targets: &[usize; 3],
    resources: &mut CapacityResources,
) -> Result<PeerCapacityEvidence> {
    let phase_started = Instant::now();
    if resources.profiles.len() != devices.len() {
        return Err(HarnessError::InvalidInput(
            "peer-capacity profile/resource count changed before client startup".into(),
        ));
    }
    for (index, device) in devices.iter().enumerate() {
        let config_path = {
            let profile = &resources.profiles[index];
            if !profile
                .config
                .relay_url
                .contains(&format!(":{}", target_device_addr.port()))
            {
                return Err(HarnessError::InvalidInput(format!(
                    "peer-capacity profile is not pinned to the {TARGET_NODE} device listener"
                )));
            }
            profile.config_path.clone()
        };
        start_direct_cli(&config_path, resources).await?;
        resources.owned_devices.push(device.id);
        let owner = wait_for_owner(cluster, device, resources).await?;
        if owner.node_id != TARGET_NODE {
            return Err(HarnessError::Process(format!(
                "peer-capacity device owner landed on {}, expected {TARGET_NODE}",
                owner.node_id
            )));
        }
        resources.owner_tokens.push(owner);
    }

    // The three real CLI processes establish the owner actors, while only one
    // public consumer stream is retained as the external survival canary.
    assert_owner_bindings(
        cluster,
        &resources.owner_tokens,
        &[0, 0, 0],
        CAPACITY_HANDSHAKE_TIMEOUT,
    )
    .await?;
    let selected_device = devices[0];
    let selected_service = *harness
        .topology
        .service_ids
        .get(&selected_device.id)
        .ok_or_else(|| HarnessError::InvalidInput("peer-capacity service is missing".into()))?;
    let canary = resources
        .profiles
        .first()
        .map(|profile| profile.canary.clone())
        .ok_or_else(|| {
            HarnessError::InvalidInput("peer-capacity canary profile is missing".into())
        })?;
    let public_canary = timeout(
        CAPACITY_HANDSHAKE_TIMEOUT,
        open_consumer_stream(
            ingress_addr,
            &harness.pki.server_ca.certificate_der,
            token,
            selected_device.id,
            selected_service,
        ),
    )
    .await
    .map_err(|_| HarnessError::Timeout("peer-capacity public canary handshake timed out".into()))?
    .map_err(super::connect_failure_to_harness)?;
    resources.streams.push(public_canary);
    timeout(
        CAPACITY_HANDSHAKE_TIMEOUT,
        resources
            .streams
            .first_mut()
            .expect("public canary was pushed")
            .round_trip(b"m7-peer-capacity-baseline", canary.as_bytes()),
    )
    .await
    .map_err(|_| HarnessError::Timeout("peer-capacity baseline echo timed out".into()))?
    .map_err(|error| HarnessError::Http(format!("peer-capacity baseline echo failed: {error}")))?;
    let mut next_keepalive_at = Instant::now() + CAPACITY_KEEPALIVE_INTERVAL;
    assert_owner_bindings_with_keepalive(
        &[1, 0, 0],
        CAPACITY_HANDSHAKE_TIMEOUT,
        CapacityKeepalive {
            cluster,
            owners: &resources.owner_tokens,
            public_streams: &mut resources.streams,
            peer_streams: &mut resources.peer_streams,
            canary: canary.as_bytes(),
            next_keepalive_at: &mut next_keepalive_at,
            phase: "owner_bindings_initial",
        },
    )
    .await?;
    for (index, desired) in stream_targets.iter().copied().enumerate() {
        let device = devices[index];
        let service_id = *harness
            .topology
            .service_ids
            .get(&device.id)
            .ok_or_else(|| HarnessError::InvalidInput("peer-capacity service is missing".into()))?;
        let public_streams = usize::from(index == 0);
        let peer_target = desired.saturating_sub(public_streams);
        let expected_canary = resources.profiles[index].canary.as_bytes().to_vec();
        for peer_index in 0..peer_target {
            let public_held = resources.streams.len();
            let peer_held_before = resources.peer_streams.len();
            let held_before = public_held + peer_held_before;
            let route_attempt = timeout(
                CAPACITY_HANDSHAKE_TIMEOUT,
                cluster
                    .relay(INGRESS_NODE)?
                    .peer_runtime
                    .resolve(OwnerScope::new(device.tenant_id, device.id), Utc::now()),
            );
            let route = match await_with_keepalive(
                route_attempt,
                CapacityKeepalive {
                    cluster,
                    owners: &resources.owner_tokens,
                    public_streams: &mut resources.streams,
                    peer_streams: &mut resources.peer_streams,
                    canary: canary.as_bytes(),
                    next_keepalive_at: &mut next_keepalive_at,
                    phase: "fill_route",
                },
            )
            .await
            {
                Err(CapacityAdmissionWaitError::Keepalive(error)) => return Err(error),
                Ok(Err(error)) => {
                    return Err(peer_admission_harness_error("resolve owner route", error));
                }
                Ok(Ok(route)) => route,
                Err(CapacityAdmissionWaitError::Admission(_)) => {
                    return Err(HarnessError::Timeout(format!(
                        "peer-capacity owner route resolution timed out at device_index={index}, peer_index={peer_index}"
                    )));
                }
            };
            if route.is_local() {
                return Err(HarnessError::Process(format!(
                    "peer-capacity direct admission selected a local route for device_index={index}"
                )));
            }
            let request_id = format!("m7-peer-capacity-{index}-{peer_index}-{}", Uuid::new_v4());
            let owner = route.owner_token().clone();
            let destination = Destination::new(owner.clone(), service_id);
            let bearer =
                ForwardedConsumerBearer::new(token.to_owned(), owner).map_err(|error| {
                    HarnessError::InvalidInput(format!(
                        "peer-capacity forwarded consumer bearer: {error}"
                    ))
                })?;
            let request = InternalRequest::ConsumerStreams(ConsumerStreamsRequest {
                stream_id: request_id.clone(),
                required_scope: tunnel_relay::ECHO_OPERATION.to_owned(),
                bearer,
                bytes: Vec::new(),
            });
            let envelope = RequestEnvelope::new(
                InternalRoute::ConsumerStreams,
                request_id,
                cluster.relay(INGRESS_NODE)?.peer_runtime.source().clone(),
                destination,
                20_000,
                None,
                request,
            );
            let diagnostic = PeerOpenDiagnostic::new();
            let open_attempt = timeout(
                CAPACITY_HANDSHAKE_TIMEOUT,
                cluster
                    .relay(INGRESS_NODE)?
                    .peer_runtime
                    .open_with_diagnostics(&route, envelope, &diagnostic),
            );
            let exchange = match await_with_keepalive(
                open_attempt,
                CapacityKeepalive {
                    cluster,
                    owners: &resources.owner_tokens,
                    public_streams: &mut resources.streams,
                    peer_streams: &mut resources.peer_streams,
                    canary: canary.as_bytes(),
                    next_keepalive_at: &mut next_keepalive_at,
                    phase: "fill_open",
                },
            )
            .await
            {
                Err(CapacityAdmissionWaitError::Keepalive(error)) => return Err(error),
                Err(CapacityAdmissionWaitError::Admission(_)) => {
                    let pool = match cluster.relay(INGRESS_NODE) {
                        Ok(relay) => match timeout(
                            CAPACITY_DIAGNOSTIC_TIMEOUT,
                            relay.peer_runtime.peer_pool_stats(),
                        )
                        .await
                        {
                            Ok(stats) => format_peer_pool_stats(&stats),
                            Err(_) => "unavailable".to_owned(),
                        },
                        Err(_) => "unavailable".to_owned(),
                    };
                    let route_pool = match cluster.relay(INGRESS_NODE) {
                        Ok(relay) => match timeout(
                            CAPACITY_DIAGNOSTIC_TIMEOUT,
                            relay.peer_runtime.route_pool_stats(&route),
                        )
                        .await
                        {
                            Ok(Some(stats)) => format_peer_pool_connection_stats(&stats),
                            Ok(None) => "missing".to_owned(),
                            Err(_) => "unavailable".to_owned(),
                        },
                        Err(_) => "unavailable".to_owned(),
                    };
                    let target_server = cluster
                        .relay(TARGET_NODE)
                        .ok()
                        .and_then(|relay| relay.peer_server_stats())
                        .map(|stats| format_peer_server_stats(&stats, TARGET_NODE, INGRESS_NODE))
                        .unwrap_or_else(|| "unavailable".to_owned());
                    let target_owner_streams = match cluster.relay(TARGET_NODE) {
                        Ok(relay) => match timeout(CAPACITY_DIAGNOSTIC_TIMEOUT, relay.snapshot())
                            .await
                        {
                            Ok(Ok(snapshot)) => {
                                format_owner_stream_diagnostics(&snapshot, &resources.owner_tokens)
                            }
                            Ok(Err(_)) | Err(_) => "unavailable".to_owned(),
                        },
                        Err(_) => "unavailable".to_owned(),
                    };
                    return Err(HarnessError::Timeout(format!(
                        "peer-capacity direct admission timed out at ingress={INGRESS_NODE}, device_index={index}, device_target={desired}, peer_index={peer_index}, public_held={public_held}, peer_held_before={peer_held_before}, held_before={held_before}, target_total={}, owner_count={}, open_stage={}, route_pool={route_pool}, target_server={target_server}, target_owner_streams={target_owner_streams}, {pool}",
                        stream_targets.iter().sum::<usize>(),
                        resources.owner_tokens.len(),
                        diagnostic.stage(),
                    )));
                }
                Ok(Ok(exchange)) => exchange,
                Ok(Err(error)) => {
                    return Err(peer_admission_harness_error(
                        &format!(
                            "direct admission at ingress={INGRESS_NODE}, device_index={index}, device_target={desired}, peer_index={peer_index}, public_held={public_held}, peer_held_before={peer_held_before}, held_before={held_before}"
                        ),
                        error,
                    ));
                }
            };
            let (send, recv) = exchange.split();
            let mut admitted = PeerConsumerStream {
                send,
                recv,
                expected_canary: expected_canary.clone(),
            };
            let response_attempt =
                timeout(CAPACITY_HANDSHAKE_TIMEOUT, admitted.recv.accept_response());
            match await_with_keepalive(
                response_attempt,
                CapacityKeepalive {
                    cluster,
                    owners: &resources.owner_tokens,
                    public_streams: &mut resources.streams,
                    peer_streams: &mut resources.peer_streams,
                    canary: canary.as_bytes(),
                    next_keepalive_at: &mut next_keepalive_at,
                    phase: "fill_response",
                },
            )
            .await
            {
                Err(CapacityAdmissionWaitError::Keepalive(error)) => return Err(error),
                Err(CapacityAdmissionWaitError::Admission(_)) => {
                    return Err(HarnessError::Timeout(format!(
                        "peer-capacity direct admission response timed out at device_index={index}, peer_index={peer_index}, public_held={public_held}, peer_held_before={peer_held_before}, held_before={held_before}"
                    )));
                }
                Ok(Err(error)) => {
                    return Err(peer_admission_harness_error(
                        &format!(
                            "direct admission response at device_index={index}, peer_index={peer_index}, public_held={public_held}, peer_held_before={peer_held_before}, held_before={held_before}"
                        ),
                        error,
                    ));
                }
                Ok(Ok(_response)) => {}
            }
            // The response headers above only prove that the PeerRuntime
            // envelope was accepted.  The owner M2 stream remains pending
            // until its first authenticated record, so pulse this admission
            // before adding it to the held roster.  The existing roster keeps
            // its scheduled bounded pulses through await_with_keepalive;
            // sending a full-roster pulse for every admission would create a
            // quadratic burst while the capacity fixture is filling.
            let public_stream_count = resources.streams.len();
            let admitted_index = resources.peer_streams.len();
            let admitted_peer_count = admitted_index.saturating_add(1);
            pulse_capacity_peer_stream(
                &mut admitted,
                "fill_authenticated",
                admitted_index,
                public_stream_count,
                admitted_peer_count,
            )
            .await?;
            resources.peer_streams.push(admitted);
        }
    }
    let held_streams = resources.streams.len() + resources.peer_streams.len();
    if held_streams != stream_targets.iter().sum::<usize>() {
        return Err(HarnessError::Process(format!(
            "peer-capacity phase held {} authenticated streams ({} public, {} peer), expected configured limit {}",
            held_streams,
            resources.streams.len(),
            resources.peer_streams.len(),
            stream_targets.iter().sum::<usize>()
        )));
    }
    assert_owner_bindings_with_keepalive(
        stream_targets,
        CAPACITY_HANDSHAKE_TIMEOUT,
        CapacityKeepalive {
            cluster,
            owners: &resources.owner_tokens,
            public_streams: &mut resources.streams,
            peer_streams: &mut resources.peer_streams,
            canary: canary.as_bytes(),
            next_keepalive_at: &mut next_keepalive_at,
            phase: "owner_bindings_full",
        },
    )
    .await?;

    let (public_livez_ok_during_capacity, public_readyz_unready_during_capacity) =
        wait_for_capacity_loss(
            cluster,
            ingress_addr,
            &harness.pki.server_ca.certificate_der,
            &mut resources.streams,
            &mut resources.peer_streams,
            canary.as_bytes(),
            &resources.owner_tokens,
        )
        .await?;
    let capacity_probe_attempt = timeout(
        CAPACITY_COMPARISON_WINDOW,
        assert_capacity_probe(
            cluster,
            &resources.owner_tokens,
            resources.streams.len(),
            resources.peer_streams.len(),
        ),
    );
    let capacity_probe_typed = match await_with_keepalive(
        capacity_probe_attempt,
        CapacityKeepalive {
            cluster,
            owners: &resources.owner_tokens,
            public_streams: &mut resources.streams,
            peer_streams: &mut resources.peer_streams,
            canary: canary.as_bytes(),
            next_keepalive_at: &mut next_keepalive_at,
            phase: "capacity_probe",
        },
    )
    .await
    {
        Err(CapacityAdmissionWaitError::Keepalive(error)) => return Err(error),
        Err(CapacityAdmissionWaitError::Admission(_)) => {
            return Err(HarnessError::Timeout(
                "peer-capacity typed capacity probe exceeded its bounded deadline".into(),
            ));
        }
        Ok(Ok(value)) => value,
        Ok(Err(error)) => return Err(error),
    };
    let capacity_route_withdrawn = cluster
        .relay(INGRESS_NODE)?
        .peer_runtime
        .peer_readiness()
        .is_some_and(|readiness| {
            let snapshot = readiness.snapshot();
            snapshot.required_routes >= 2
                && snapshot.reachable_routes < snapshot.required_routes
                && snapshot.capacity_ready_routes < snapshot.required_routes
                && !readiness.is_ready()
        });

    // The loss/probe path can consume more than one per-stream idle interval
    // before the dispatch invariant starts.  Reset every held stream here and
    // start the pulse-free comparison window only after the exact responses
    // have arrived.  Measure the real pulse/comparison durations rather than
    // relying on the configured constants to imply an idle-time margin.
    let precomparison_pulse_started = Instant::now();
    match timeout(
        CAPACITY_KEEPALIVE_TIMEOUT,
        keep_capacity_streams_alive(
            &mut resources.streams,
            &mut resources.peer_streams,
            canary.as_bytes(),
            "comparison_pre",
        ),
    )
    .await
    {
        Err(_) => {
            return Err(annotate_capacity_keepalive_failure(
                cluster,
                &resources.owner_tokens,
                HarnessError::Timeout("peer-capacity pre-comparison keepalive timed out".into()),
            )
            .await);
        }
        Ok(Err(error)) => {
            return Err(annotate_capacity_keepalive_failure(
                cluster,
                &resources.owner_tokens,
                error,
            )
            .await);
        }
        Ok(Ok(())) => {}
    }
    let last_all_pulse_completed = Instant::now();
    let pre_pulse_elapsed =
        last_all_pulse_completed.saturating_duration_since(precomparison_pulse_started);
    if pre_pulse_elapsed >= CAPACITY_KEEPALIVE_TIMEOUT {
        return Err(HarnessError::Timeout(format!(
            "peer-capacity pre-comparison keepalive used its entire bound (elapsed_ms={})",
            pre_pulse_elapsed.as_millis()
        )));
    }

    let selected_owner = resources.owner_tokens.first().cloned().ok_or_else(|| {
        HarnessError::Process("peer-capacity selected owner identity is missing".into())
    })?;
    // Keep this dispatch invariant pulse-free.  The selected public admission
    // uses one absolute five-second window, below the ten-second per-stream
    // receive idle bound; allowing a heartbeat here would itself advance the
    // selected owner's lifetime dispatch counter and invalidate the proof.
    let comparison_deadline = last_all_pulse_completed + CAPACITY_COMPARISON_WINDOW;
    let before_rejection = timeout(
        remaining_capacity_window(comparison_deadline, "pre-rejection snapshot")?,
        cluster.relay(TARGET_NODE)?.snapshot(),
    )
    .await
    .map_err(|_| {
        HarnessError::Timeout("peer-capacity pre-rejection snapshot timed out".into())
    })??;
    let before_dispatch = owner_session_dispatch_counter(&before_rejection, &selected_owner)
        .ok_or_else(|| {
            HarnessError::Process(
                "peer-capacity selected owner session disappeared before admission check".into(),
            )
        })?;
    let selected_admission_rejected = match timeout(
        remaining_capacity_window(comparison_deadline, "selected admission")?,
        open_consumer_stream(
            ingress_addr,
            &harness.pki.server_ca.certificate_der,
            token,
            selected_device.id,
            selected_service,
        ),
    )
    .await
    {
        Err(_) => {
            return Err(HarnessError::Timeout(
                "peer-capacity selected admission timed out instead of returning CLUSTER_UNREADY"
                    .into(),
            ));
        }
        Ok(Err(super::StreamConnectFailure::Status { status, body }))
            if is_exact_cluster_unready(status, body.as_deref()) =>
        {
            true
        }
        Ok(Err(super::StreamConnectFailure::Status { status, .. })) => {
            return Err(HarnessError::Http(format!(
                "peer-capacity selected admission returned unexpected bounded status {status}"
            )));
        }
        Ok(Err(super::StreamConnectFailure::Harness(error))) => {
            return Err(error);
        }
        Ok(Ok(mut stream)) => {
            let _ = timeout(
                remaining_capacity_window(comparison_deadline, "unexpected admission close")?,
                stream.close(),
            )
            .await;
            return Err(HarnessError::Process(
                "peer-capacity selected admission unexpectedly upgraded".into(),
            ));
        }
    };
    let after_rejection = timeout(
        remaining_capacity_window(comparison_deadline, "post-rejection snapshot")?,
        cluster.relay(TARGET_NODE)?.snapshot(),
    )
    .await
    .map_err(|_| {
        HarnessError::Timeout("peer-capacity post-rejection snapshot timed out".into())
    })??;
    let after_dispatch = owner_session_dispatch_counter(&after_rejection, &selected_owner)
        .ok_or_else(|| {
            HarnessError::Process(
                "peer-capacity selected owner session disappeared after admission check".into(),
            )
        })?;

    let comparison_elapsed = Instant::now().saturating_duration_since(last_all_pulse_completed);
    if comparison_elapsed >= CAPACITY_COMPARISON_WINDOW {
        return Err(HarnessError::Timeout(format!(
            "peer-capacity dispatch comparison exceeded its measured idle window (elapsed_ms={})",
            comparison_elapsed.as_millis()
        )));
    }

    // Both snapshots above define the no-dispatch window.  Pulse all 128
    // retained exchanges only after the post-rejection sample and before
    // interpreting the counter comparison, so this liveness proof cannot
    // advance either sampled value.  It also proves exact responses after the
    // rejected request; owner bindings alone do not prove retained streams.
    let post_rejection_pulse_started = Instant::now();
    match timeout(
        CAPACITY_KEEPALIVE_TIMEOUT,
        keep_capacity_streams_alive(
            &mut resources.streams,
            &mut resources.peer_streams,
            canary.as_bytes(),
            "comparison_post",
        ),
    )
    .await
    {
        Err(_) => {
            return Err(annotate_capacity_keepalive_failure(
                cluster,
                &resources.owner_tokens,
                HarnessError::Timeout("peer-capacity post-rejection keepalive timed out".into()),
            )
            .await);
        }
        Ok(Err(error)) => {
            return Err(annotate_capacity_keepalive_failure(
                cluster,
                &resources.owner_tokens,
                error,
            )
            .await);
        }
        Ok(Ok(())) => {}
    }
    next_keepalive_at = Instant::now() + CAPACITY_KEEPALIVE_INTERVAL;
    let post_rejection_pulse_completed = Instant::now();
    let post_pulse_duration =
        post_rejection_pulse_completed.saturating_duration_since(post_rejection_pulse_started);
    if post_pulse_duration >= CAPACITY_KEEPALIVE_TIMEOUT {
        return Err(HarnessError::Timeout(format!(
            "peer-capacity post-rejection keepalive used its entire bound (elapsed_ms={})",
            post_pulse_duration.as_millis()
        )));
    }
    let post_pulse_elapsed =
        post_rejection_pulse_completed.saturating_duration_since(last_all_pulse_completed);
    if post_pulse_elapsed >= CAPACITY_COMPARISON_WINDOW + CAPACITY_KEEPALIVE_TIMEOUT {
        return Err(HarnessError::Timeout(format!(
            "peer-capacity post-rejection keepalive completed outside its measured idle window (elapsed_ms={})",
            post_pulse_elapsed.as_millis()
        )));
    }
    let total_elapsed =
        post_rejection_pulse_completed.saturating_duration_since(precomparison_pulse_started);
    let maximum_total =
        CAPACITY_KEEPALIVE_TIMEOUT + CAPACITY_COMPARISON_WINDOW + CAPACITY_KEEPALIVE_TIMEOUT;
    if total_elapsed >= maximum_total {
        return Err(HarnessError::Timeout(format!(
            "peer-capacity pulse-to-post-comparison interval exceeded its bounded margin (elapsed_ms={})",
            total_elapsed.as_millis()
        )));
    }
    let selected_dispatch_not_advanced = after_dispatch == before_dispatch;
    assert_owner_bindings_with_keepalive(
        stream_targets,
        CAPACITY_HANDSHAKE_TIMEOUT,
        CapacityKeepalive {
            cluster,
            owners: &resources.owner_tokens,
            public_streams: &mut resources.streams,
            peer_streams: &mut resources.peer_streams,
            canary: canary.as_bytes(),
            next_keepalive_at: &mut next_keepalive_at,
            phase: "owner_bindings_post_rejection",
        },
    )
    .await?;

    let held_stream_survived = timeout(
        CAPACITY_HANDSHAKE_TIMEOUT,
        resources.streams[0].round_trip(b"m7-peer-capacity-survival", canary.as_bytes()),
    )
    .await
    .is_ok_and(|result| result.is_ok());
    if !held_stream_survived {
        return Err(HarnessError::Http(
            "peer-capacity readiness probe damaged the held customer stream".into(),
        ));
    }
    assert_owner_bindings_with_keepalive(
        stream_targets,
        CAPACITY_HANDSHAKE_TIMEOUT,
        CapacityKeepalive {
            cluster,
            owners: &resources.owner_tokens,
            public_streams: &mut resources.streams,
            peer_streams: &mut resources.peer_streams,
            canary: canary.as_bytes(),
            next_keepalive_at: &mut next_keepalive_at,
            phase: "owner_bindings_recovery",
        },
    )
    .await?;

    close_streams(&mut resources.streams).await?;
    cancel_peer_streams(&mut resources.peer_streams);
    wait_for_owner_streams_drained(
        cluster,
        &resources.owner_tokens,
        Instant::now() + CAPACITY_RECOVERY_TIMEOUT,
    )
    .await?;
    cluster
        .wait_for_peer_readiness(CAPACITY_RECOVERY_TIMEOUT)
        .await
        .map_err(|error| {
            HarnessError::Timeout(format!("peer-capacity route recovery failed: {error}"))
        })?;
    wait_for_public_ready(
        ingress_addr,
        &harness.pki.server_ca.certificate_der,
        CAPACITY_RECOVERY_TIMEOUT,
    )
    .await?;
    let fresh = timeout(
        CAPACITY_HANDSHAKE_TIMEOUT,
        open_consumer_stream(
            ingress_addr,
            &harness.pki.server_ca.certificate_der,
            token,
            selected_device.id,
            selected_service,
        ),
    )
    .await
    .map_err(|_| HarnessError::Timeout("peer-capacity recovery admission timed out".into()))?
    .map_err(super::connect_failure_to_harness)?;
    resources.streams.push(fresh);
    let fresh_recovery_echo = resources
        .streams
        .last_mut()
        .expect("fresh recovery stream was pushed")
        .round_trip(b"m7-peer-capacity-recovery", canary.as_bytes())
        .await
        .is_ok();

    Ok(PeerCapacityEvidence {
        relay_count: cluster.relays.len(),
        membership_ready_relays: 3,
        peer_stream_limit,
        per_device_streams: *stream_targets,
        owner_count_on_target: resources.owner_tokens.len(),
        held_authenticated_streams: held_streams,
        baseline_echo: true,
        public_livez_ok_during_capacity,
        public_readyz_unready_during_capacity,
        capacity_route_withdrawn,
        capacity_probe_typed,
        selected_admission_rejected,
        selected_dispatch_not_advanced,
        held_stream_survived,
        public_readyz_ok_after_recovery: true,
        fresh_recovery_echo,
        elapsed_ms: u64::try_from(phase_started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

/// Force one production refresh after the holders have filled the pooled H3
/// route.  The public health transition alone is insufficient evidence: a
/// timeout, blackhole, or unrelated route failure must not be labelled as
/// stream-capacity exhaustion.  The transport classification is checked at
/// the actual refresh boundary and only its exact typed result is accepted.
async fn assert_capacity_probe(
    cluster: &ProductionCluster,
    owners: &[OwnerToken],
    public_stream_count: usize,
    peer_stream_count: usize,
) -> Result<bool> {
    let relay = cluster.relay(INGRESS_NODE)?;
    let targets = super::required_peer_routes(&relay.membership, INGRESS_NODE);
    let target_count = targets.len();
    let before_pool = match timeout(
        CAPACITY_DIAGNOSTIC_TIMEOUT,
        relay.peer_runtime.peer_pool_stats(),
    )
    .await
    {
        Ok(stats) => format_peer_pool_stats(&stats),
        Err(_) => "unavailable".to_owned(),
    };
    let before_readiness = relay
        .peer_runtime
        .peer_readiness()
        .map(|readiness| {
            let snapshot = readiness.snapshot();
            format!(
                "required={},reachable={},capacity_ready={},ready={}",
                snapshot.required_routes,
                snapshot.reachable_routes,
                snapshot.capacity_ready_routes,
                readiness.is_ready(),
            )
        })
        .unwrap_or_else(|| "unavailable".to_owned());
    let before_target = match timeout(
        CAPACITY_DIAGNOSTIC_TIMEOUT,
        cluster.relay(TARGET_NODE)?.snapshot(),
    )
    .await
    {
        Ok(Ok(snapshot)) => format!(
            "owners={},peer_consumer={}",
            format_owner_stream_diagnostics(&snapshot, owners),
            format_peer_consumer_diagnostics(&snapshot),
        ),
        Ok(Err(_)) | Err(_) => "unavailable".to_owned(),
    };
    match relay.peer_runtime.refresh_required_routes(targets).await {
        Err(PeerRuntimeError::Transport(PeerTransportError::Capacity)) => {
            let readiness = relay.peer_runtime.peer_readiness().ok_or_else(|| {
                HarnessError::Process(
                    "peer-capacity typed probe had no readiness state to withdraw".into(),
                )
            })?;
            let snapshot = readiness.snapshot();
            if snapshot.required_routes == 0
                || snapshot.capacity_ready_routes >= snapshot.required_routes
                || readiness.is_ready()
            {
                return Err(HarnessError::Process(format!(
                    "peer-capacity typed probe did not immediately withdraw aggregate readiness: required_routes={}, capacity_ready_routes={}, ready={}",
                    snapshot.required_routes,
                    snapshot.capacity_ready_routes,
                    readiness.is_ready(),
                )));
            }
            Ok(true)
        }
        Err(PeerRuntimeError::Transport(PeerTransportError::Timeout)) => {
            Err(HarnessError::Timeout(
                "peer-capacity refresh returned a generic timeout instead of typed capacity".into(),
            ))
        }
        Err(_) => Err(HarnessError::Process(
            "peer-capacity refresh returned an unexpected bounded transport result".into(),
        )),
        Ok(()) => {
            let after_pool = match timeout(
                CAPACITY_DIAGNOSTIC_TIMEOUT,
                relay.peer_runtime.peer_pool_stats(),
            )
            .await
            {
                Ok(stats) => format_peer_pool_stats(&stats),
                Err(_) => "unavailable".to_owned(),
            };
            let after_readiness = relay
                .peer_runtime
                .peer_readiness()
                .map(|readiness| {
                    let snapshot = readiness.snapshot();
                    format!(
                        "required={},reachable={},capacity_ready={},ready={}",
                        snapshot.required_routes,
                        snapshot.reachable_routes,
                        snapshot.capacity_ready_routes,
                        readiness.is_ready(),
                    )
                })
                .unwrap_or_else(|| "unavailable".to_owned());
            let after_target = match timeout(
                CAPACITY_DIAGNOSTIC_TIMEOUT,
                cluster.relay(TARGET_NODE)?.snapshot(),
            )
            .await
            {
                Ok(Ok(snapshot)) => format!(
                    "owners={},peer_consumer={}",
                    format_owner_stream_diagnostics(&snapshot, owners),
                    format_peer_consumer_diagnostics(&snapshot),
                ),
                Ok(Err(_)) | Err(_) => "unavailable".to_owned(),
            };
            Err(HarnessError::Process(format!(
                "peer-capacity refresh unexpectedly succeeded while route permits were held: targets={target_count}, public_streams={public_stream_count}, peer_streams={peer_stream_count}, before_pool={before_pool}, after_pool={after_pool}, before_readiness={before_readiness}, after_readiness={after_readiness}, before_target={before_target}, after_target={after_target}"
            )))
        }
    }
}

async fn start_direct_cli(
    config_path: &std::path::Path,
    resources: &mut CapacityResources,
) -> Result<()> {
    let binary = super::client_binary_path()?;
    let process = ManagedProcess::spawn(
        "m7-peer-capacity-cli",
        ProcessSpec::new(binary)
            .arg("connect")
            .arg("--config")
            .arg(config_path.to_string_lossy().to_string())
            .arg("--json"),
    )
    .await?;
    // Transfer ownership before the first await after spawn.  If the outer
    // scenario deadline cancels this future, cleanup_resources still owns the
    // child and can perform the required kill+wait reaping.
    resources.processes.push(process);
    Ok(())
}

async fn wait_for_owner(
    cluster: &ProductionCluster,
    device: &crate::DeviceFixture,
    resources: &mut CapacityResources,
) -> Result<OwnerToken> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HarnessError::Timeout(
                "peer-capacity CLI did not establish an active owner within its bound".into(),
            ));
        }
        let exited = resources
            .processes
            .last_mut()
            .expect("peer-capacity process was retained")
            .try_wait()?
            .is_some();
        if exited {
            return Err(HarnessError::Process(
                "peer-capacity CLI exited before owner readiness".into(),
            ));
        }
        let owner = match timeout(
            remaining,
            cluster
                .catalog
                .current_owner(device.tenant_id, device.id, Utc::now()),
        )
        .await
        {
            Ok(Ok(owner)) => owner,
            Ok(Err(error)) => {
                return Err(HarnessError::Redis(format!(
                    "reading peer-capacity owner: {error}"
                )));
            }
            Err(_) => {
                return Err(HarnessError::Timeout(
                    "peer-capacity owner lookup exceeded its startup deadline".into(),
                ));
            }
        };
        if let Some(owner) = owner
            && owner.token.node_id == TARGET_NODE
        {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let snapshot = match timeout(remaining, cluster.relay(TARGET_NODE)?.snapshot()).await {
                Ok(snapshot) => snapshot?,
                Err(_) => {
                    return Err(HarnessError::Timeout(
                        "peer-capacity owner snapshot exceeded its startup deadline".into(),
                    ));
                }
            };
            let owner_ready = snapshot.sessions.iter().any(|session| {
                session.device_id == device.id.to_string()
                    && session.session_id == owner.token.session_id
                    && session.epoch == owner.token.epoch
                    && session.phase == "active"
                    && session.sockets >= 2
                    && !session.active_connection_id.is_empty()
                    && session.candidate_generation.is_none()
            });
            if owner_ready {
                return Ok(owner.token);
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let _ = timeout(remaining, sleep(POLL_INTERVAL)).await;
    }
    Err(HarnessError::Timeout(
        "peer-capacity CLI did not establish an active owner within its bound".into(),
    ))
}

fn peer_admission_harness_error(stage: &str, error: PeerRuntimeError) -> HarnessError {
    let category = match error {
        PeerRuntimeError::Capacity { .. } => "owner_capacity",
        PeerRuntimeError::OwnerNotReady { .. } => "owner_not_ready",
        PeerRuntimeError::RemoteStatus(status) => {
            return HarnessError::Http(format!(
                "peer-capacity {stage} failed with owner status {}",
                status.as_u16()
            ));
        }
        PeerRuntimeError::Transport(PeerTransportError::Capacity) => "transport_capacity",
        PeerRuntimeError::Transport(PeerTransportError::Timeout) => "transport_timeout",
        PeerRuntimeError::Transport(_) => "transport",
        PeerRuntimeError::Routing(_) => "routing",
        PeerRuntimeError::Membership(_) => "membership",
        PeerRuntimeError::InvalidEndpoint(_) => "invalid_endpoint",
        PeerRuntimeError::PeerIdentityMismatch => "peer_identity",
        PeerRuntimeError::Envelope(_) => "envelope",
        PeerRuntimeError::Frame(_) => "frame",
        PeerRuntimeError::InvalidRoute(_) => "invalid_route",
        PeerRuntimeError::UnexpectedRecord(_) => "unexpected_record",
        PeerRuntimeError::MembershipExpired => "trust_expired",
        PeerRuntimeError::Closed => "closed",
    };
    HarnessError::Http(format!("peer-capacity {stage} failed: {category}"))
}

fn format_peer_pool_stats(stats: &PeerPoolStats) -> String {
    let streams = stats
        .pooled_connections
        .iter()
        .map(|connection| {
            format!(
                "{}/{}{}",
                connection.available_stream_permits,
                connection.max_stream_permits,
                if connection.closed { ":closed" } else { "" }
            )
        })
        .collect::<Vec<_>>();
    format!(
        "pool_connections={}, connection_permits={}/{}, stream_permits=[{}]",
        stats.pooled_connections.len(),
        stats.available_connection_permits,
        stats.max_connection_permits,
        streams.join(",")
    )
}

fn format_peer_pool_connection_stats(stats: &PeerPoolConnectionStats) -> String {
    format!(
        "{}/{}{}",
        stats.available_stream_permits,
        stats.max_stream_permits,
        if stats.closed { ":closed" } else { "" }
    )
}

fn format_peer_server_stats(
    stats: &PeerServerStats,
    target_node: &str,
    expected_peer: &str,
) -> String {
    let connections = stats
        .connections
        .iter()
        .filter(|connection| connection.peer_node_id == expected_peer)
        .map(|connection| format_peer_server_connection_stats(connection, target_node))
        .collect::<Vec<_>>();
    if connections.is_empty() {
        "none".to_owned()
    } else {
        connections.join(";")
    }
}

fn format_peer_server_connection_stats(
    stats: &PeerServerConnectionStats,
    target_node: &str,
) -> String {
    format!(
        "target={} peer={}#{} accepted={} resolving={} active={} completed={} cancelled={} error={} permits={}/{} max_streams_bidi=tx:{}/rx:{} blocked_bidi=tx:{}/rx:{} reset=tx:{}/rx:{} stop=tx:{}/rx:{}",
        target_node,
        stats.peer_node_id,
        stats.connection_id,
        stats.accepted_streams,
        stats.resolving_streams,
        stats.active_streams,
        stats.completed_streams,
        stats.cancelled_streams,
        stats.error_streams,
        stats.available_stream_permits,
        stats.max_stream_permits,
        stats.frame_tx_max_streams_bidi,
        stats.frame_rx_max_streams_bidi,
        stats.frame_tx_streams_blocked_bidi,
        stats.frame_rx_streams_blocked_bidi,
        stats.frame_tx_reset_stream,
        stats.frame_rx_reset_stream,
        stats.frame_tx_stop_sending,
        stats.frame_rx_stop_sending,
    )
}

fn format_owner_stream_diagnostics(snapshot: &RelaySnapshot, owners: &[OwnerToken]) -> String {
    owners
        .iter()
        .enumerate()
        .map(|(index, owner)| {
            let Some(session) = snapshot.sessions.iter().find(|session| {
                session.device_id == owner.device_id.to_string()
                    && session.session_id == owner.session_id
                    && session.epoch == owner.epoch
            }) else {
                return format!("owner{index}=missing");
            };
            let total = session.streams.len();
            let terminal = session.streams.iter().filter(|stream| stream.terminal).count();
            let active = total.saturating_sub(terminal);
            let terminal_with_expired_admission = session
                .streams
                .iter()
                .filter(|stream| {
                    stream.terminal
                        && stream.authorization_admission_deadline_ms.is_some_and(|deadline| {
                            deadline <= snapshot.monotonic_now_ms
                        })
                })
                .count();
            let terminal_with_live_admission = session
                .streams
                .iter()
                .filter(|stream| {
                    stream.terminal
                        && stream.authorization_admission_deadline_ms.is_some_and(|deadline| {
                            deadline > snapshot.monotonic_now_ms
                        })
                })
                .count();
            let terminal_without_admission_deadline = session
                .streams
                .iter()
                .filter(|stream| {
                    stream.terminal && stream.authorization_admission_deadline_ms.is_none()
                })
                .count();
            let authorization_in_flight = session
                .streams
                .iter()
                .filter(|stream| stream.authorization_in_flight)
                .count();
            let authorization_failures = session
                .streams
                .iter()
                .filter_map(|stream| stream.authorization_failure_code)
                .fold([0usize; 7], |mut counts, code| {
                    let slot = match code {
                        "AUTHORIZATION_EXPIRED" => 0,
                        "AUTHORIZATION_CHANGED" => 1,
                        "AUTHORIZATION_UNAVAILABLE" => 2,
                        "GRANT_UNAVAILABLE" => 3,
                        "OWNER_UNAVAILABLE" => 4,
                        "DEVICE_AUTHORIZATION_UNAVAILABLE" => 5,
                        _ => 6,
                    };
                    counts[slot] = counts[slot].saturating_add(1);
                    counts
                });
            format!(
                "owner{index}=phase:{},streams:{active}/{total} terminal:{terminal} terminal_auth_deadline:expired:{terminal_with_expired_admission} live:{terminal_with_live_admission} missing:{terminal_without_admission_deadline} auth_inflight:{authorization_in_flight} auth_failures:expired:{} changed:{} unavailable:{} grant:{} owner:{} device:{} other:{} queue_messages:{} sockets:{}",
                session.phase,
                authorization_failures[0],
                authorization_failures[1],
                authorization_failures[2],
                authorization_failures[3],
                authorization_failures[4],
                authorization_failures[5],
                authorization_failures[6],
                session.queue_messages,
                session.sockets,
            )
        })
        .collect::<Vec<_>>()
        .join(";")
}

async fn annotate_capacity_keepalive_failure(
    cluster: &ProductionCluster,
    owners: &[OwnerToken],
    error: HarnessError,
) -> HarnessError {
    let target_snapshot = match cluster.relay(TARGET_NODE) {
        Ok(relay) => match timeout(CAPACITY_DIAGNOSTIC_TIMEOUT, relay.snapshot()).await {
            Ok(Ok(snapshot)) => Some(snapshot),
            Ok(Err(_)) | Err(_) => None,
        },
        Err(_) => None,
    };
    let target_owner_streams = target_snapshot.as_ref().map_or_else(
        || "unavailable".to_owned(),
        |snapshot| format_owner_stream_diagnostics(snapshot, owners),
    );
    let target_peer_consumer = target_snapshot.as_ref().map_or_else(
        || "unavailable".to_owned(),
        format_peer_consumer_diagnostics,
    );
    let target_server = cluster
        .relay(TARGET_NODE)
        .ok()
        .and_then(|relay| relay.peer_server_stats())
        .map(|stats| format_peer_server_stats(&stats, TARGET_NODE, INGRESS_NODE))
        .unwrap_or_else(|| "unavailable".to_owned());
    let ingress_pool = match cluster.relay(INGRESS_NODE) {
        Ok(relay) => match timeout(
            CAPACITY_DIAGNOSTIC_TIMEOUT,
            relay.peer_runtime.peer_pool_stats(),
        )
        .await
        {
            Ok(stats) => format_peer_pool_stats(&stats),
            Err(_) => "unavailable".to_owned(),
        },
        Err(_) => "unavailable".to_owned(),
    };
    let readiness = cluster
        .relay(INGRESS_NODE)
        .ok()
        .and_then(|relay| relay.peer_runtime.peer_readiness())
        .map(|state| {
            let snapshot = state.snapshot();
            format!(
                "required_routes={} reachable_routes={} capacity_ready_routes={} ready={}",
                snapshot.required_routes,
                snapshot.reachable_routes,
                snapshot.capacity_ready_routes,
                state.is_ready(),
            )
        })
        .unwrap_or_else(|| "unavailable".to_owned());
    let context = format!(
        "target_owner_streams={target_owner_streams}, target_peer_consumer={target_peer_consumer}, target_server={target_server}, ingress_pool={ingress_pool}, readiness={readiness}"
    );
    match error {
        HarnessError::Timeout(message) => HarnessError::Timeout(format!("{message}; {context}")),
        HarnessError::Http(message) => HarnessError::Http(format!("{message}; {context}")),
        HarnessError::Process(message) => HarnessError::Process(format!("{message}; {context}")),
        other => other,
    }
}

fn format_peer_consumer_diagnostics(snapshot: &RelaySnapshot) -> String {
    let diagnostics = &snapshot.peer_consumer_diagnostics;
    let event = |event: Option<&tunnel_relay::PeerConsumerDiagnosticEventSnapshot>| {
        event.map_or_else(
            || "none".to_owned(),
            |event| {
                format!(
                    "role={},outcome={},h3_code={}",
                    event.role.as_str(),
                    event.outcome.as_str(),
                    event
                        .h3_code
                        .map_or("none", tunnel_relay::PeerConsumerDiagnosticH3Code::as_str),
                )
            },
        )
    };
    format!(
        "ingress_send_count={},ingress_receive_count={},owner_send_count={},owner_receive_count={},last_ingress_send={},last_ingress_receive={},last_owner_send={},last_owner_receive={}",
        diagnostics.ingress_send_count,
        diagnostics.ingress_receive_count,
        diagnostics.owner_send_count,
        diagnostics.owner_receive_count,
        event(diagnostics.last_ingress_send.as_ref()),
        event(diagnostics.last_ingress_receive.as_ref()),
        event(diagnostics.last_owner_send.as_ref()),
        event(diagnostics.last_owner_receive.as_ref()),
    )
}

async fn wait_for_capacity_loss(
    cluster: &ProductionCluster,
    ingress_addr: std::net::SocketAddr,
    server_ca_der: &[u8],
    public_streams: &mut [ConsumerStream],
    peer_streams: &mut [PeerConsumerStream],
    canary: &[u8],
    owners: &[OwnerToken],
) -> Result<(bool, bool)> {
    let deadline = Instant::now() + CAPACITY_LOSS_TIMEOUT;
    let mut next_keepalive_at = Instant::now() + CAPACITY_KEEPALIVE_INTERVAL;
    loop {
        if (!public_streams.is_empty() || !peer_streams.is_empty())
            && Instant::now() >= next_keepalive_at
        {
            if let Err(error) =
                keep_capacity_streams_alive(public_streams, peer_streams, canary, "capacity_loss")
                    .await
            {
                return Err(annotate_capacity_keepalive_failure(cluster, owners, error).await);
            }
            next_keepalive_at = Instant::now() + CAPACITY_KEEPALIVE_INTERVAL;
        }
        let live = public_health_request(ingress_addr, server_ca_der, "/livez").await;
        let ready = public_health_request(ingress_addr, server_ca_der, "/readyz").await;
        let live_ok = live
            .as_ref()
            .is_ok_and(|response| response.status == 200 && response.body.as_slice() == LIVEZ_BODY);
        let ready_unready = ready.as_ref().is_ok_and(|response| {
            response.status == 503 && response.body.as_slice() == UNREADYZ_BODY
        });
        let route_withdrawn = cluster
            .relay(INGRESS_NODE)
            .ok()
            .and_then(|relay| relay.peer_runtime.peer_readiness())
            .is_some_and(|readiness| {
                let snapshot = readiness.snapshot();
                snapshot.required_routes >= 2
                    && snapshot.reachable_routes < snapshot.required_routes
                    && snapshot.capacity_ready_routes < snapshot.required_routes
                    && !readiness.is_ready()
            });
        let membership_ready = cluster
            .relays
            .iter()
            .all(|relay| matches!(relay.membership.readiness(), MembershipReadiness::Ready));
        if live_ok && ready_unready && route_withdrawn && membership_ready {
            return Ok((true, true));
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "peer-capacity exhaustion did not produce livez=200/readyz=503 within its bound"
                    .into(),
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_public_ready(
    ingress_addr: std::net::SocketAddr,
    server_ca_der: &[u8],
    budget: Duration,
) -> Result<()> {
    let deadline = Instant::now() + budget;
    loop {
        let live = public_health_request(ingress_addr, server_ca_der, "/livez").await;
        let ready = public_health_request(ingress_addr, server_ca_der, "/readyz").await;
        if let (Ok(live), Ok(ready)) = (live, ready)
            && live.status == 200
            && live.body.as_slice() == LIVEZ_BODY
            && ready.status == 200
            && ready.body.as_slice() == READYZ_BODY
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "peer-capacity readyz did not recover within its bound".into(),
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}

fn distribute_streams(limit: usize) -> Result<[usize; 3]> {
    if limit < 3 {
        return Err(HarnessError::InvalidInput(
            "peer-capacity fixture requires at least three peer request streams".into(),
        ));
    }
    let base = limit / 3;
    let remainder = limit % 3;
    Ok([
        base + usize::from(remainder > 0),
        base + usize::from(remainder > 1),
        base,
    ])
}

async fn assert_owner_bindings(
    cluster: &ProductionCluster,
    owners: &[OwnerToken],
    expected_streams: &[usize; 3],
    budget: Duration,
) -> Result<()> {
    if owners.len() != expected_streams.len() {
        return Err(HarnessError::Process(
            "peer-capacity owner identity count changed during the phase".into(),
        ));
    }
    let deadline = Instant::now() + budget;
    for (owner, expected_streams) in owners.iter().zip(expected_streams) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HarnessError::Timeout(
                "peer-capacity owner binding check exceeded its phase deadline".into(),
            ));
        }
        let current = match timeout(
            remaining,
            cluster
                .catalog
                .current_owner(owner.tenant_id, owner.device_id, Utc::now()),
        )
        .await
        {
            Ok(Ok(Some(current))) => current,
            Ok(Ok(None)) => {
                return Err(HarnessError::Process(
                    "peer-capacity owner disappeared".into(),
                ));
            }
            Ok(Err(error)) => {
                return Err(HarnessError::Redis(format!(
                    "reading peer-capacity owner: {error}"
                )));
            }
            Err(_) => {
                return Err(HarnessError::Timeout(
                    "peer-capacity owner lookup exceeded its phase deadline".into(),
                ));
            }
        };
        if current.token != *owner {
            return Err(HarnessError::Process(format!(
                "peer-capacity owner identity changed for device {}",
                owner.device_id
            )));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HarnessError::Timeout(
                "peer-capacity owner binding snapshot exceeded its phase deadline".into(),
            ));
        }
        let snapshot = match timeout(remaining, cluster.relay(TARGET_NODE)?.snapshot()).await {
            Ok(Ok(snapshot)) => snapshot,
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                return Err(HarnessError::Timeout(
                    "peer-capacity owner snapshot exceeded its phase deadline".into(),
                ));
            }
        };
        let session_matches = snapshot.sessions.iter().any(|session| {
            session.device_id == owner.device_id.to_string()
                && session.session_id == owner.session_id
                && session.epoch == owner.epoch
                && session
                    .streams
                    .iter()
                    .filter(|stream| !stream.terminal)
                    .count()
                    == *expected_streams
        });
        if !session_matches {
            return Err(HarnessError::Process(format!(
                "peer-capacity target session identity or stream count changed for device {}",
                owner.device_id
            )));
        }
    }
    Ok(())
}

fn owner_session_dispatch_counter(snapshot: &RelaySnapshot, owner: &OwnerToken) -> Option<u64> {
    snapshot
        .sessions
        .iter()
        .find(|session| {
            session.device_id == owner.device_id.to_string()
                && session.session_id == owner.session_id
                && session.epoch == owner.epoch
        })
        .map(|session| {
            session
                .streams
                .iter()
                .map(|stream| stream.last_emitted_relay_to_connector)
                .sum()
        })
}

fn is_exact_cluster_unready(status: u16, body: Option<&[u8]>) -> bool {
    if status != 503 {
        return false;
    }
    let Some(body) = body else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    value.get("code").and_then(serde_json::Value::as_str) == Some("CLUSTER_UNREADY")
        && value.get("execution").and_then(serde_json::Value::as_str) == Some("not_dispatched")
}

async fn close_streams(streams: &mut [ConsumerStream]) -> Result<()> {
    close_streams_by_deadline(streams, Instant::now() + HOLDER_CLOSE_TIMEOUT).await
}

fn cancel_peer_streams(streams: &mut Vec<PeerConsumerStream>) {
    for stream in streams.iter_mut() {
        stream.cancel();
    }
    streams.clear();
}

async fn wait_for_owner_streams_drained(
    cluster: &ProductionCluster,
    owners: &[OwnerToken],
    deadline: Instant,
) -> Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HarnessError::Timeout(
                "peer-capacity owner streams did not drain after cancellation".into(),
            ));
        }
        let snapshot = match timeout(remaining, cluster.relay(TARGET_NODE)?.snapshot()).await {
            Ok(snapshot) => snapshot?,
            Err(_) => {
                return Err(HarnessError::Timeout(
                    "peer-capacity owner snapshot exceeded cleanup deadline".into(),
                ));
            }
        };
        let drained = owners.iter().all(|owner| {
            snapshot
                .sessions
                .iter()
                .find(|session| {
                    session.device_id == owner.device_id.to_string()
                        && session.session_id == owner.session_id
                        && session.epoch == owner.epoch
                })
                .is_none_or(|session| session.streams.iter().all(|stream| stream.terminal))
        });
        if drained {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "peer-capacity owner streams did not drain after cancellation".into(),
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if timeout(remaining, sleep(POLL_INTERVAL)).await.is_err() {
            return Err(HarnessError::Timeout(
                "peer-capacity owner streams did not drain after cancellation".into(),
            ));
        }
    }
}

async fn close_streams_by_deadline(
    streams: &mut [ConsumerStream],
    deadline: Instant,
) -> Result<()> {
    let mut errors = Vec::new();
    for stream in streams.iter_mut() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match timeout(remaining, stream.close()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => errors.push(error.to_string()),
            Err(_) => errors.push("peer-capacity holder close timed out".into()),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(HarnessError::Process(format!(
            "peer-capacity holder cleanup attempted all {} streams; {} error(s): {}",
            streams.len(),
            errors.len(),
            errors.join("; ")
        )))
    }
}

async fn cleanup_resources(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    resources: &mut CapacityResources,
) -> Result<()> {
    let deadline = Instant::now() + super::CLEANUP_TIMEOUT;
    let stream_count = resources.streams.len();
    let peer_stream_count = resources.peer_streams.len();
    let process_count = resources.processes.len();
    let owner_count = resources.owned_devices.len();
    let mut errors = Vec::new();
    if let Err(error) = close_streams_by_deadline(&mut resources.streams, deadline).await {
        errors.push(format!("streams: {error}"));
    }
    cancel_peer_streams(&mut resources.peer_streams);
    if let Err(error) =
        wait_for_owner_streams_drained(cluster, &resources.owner_tokens, deadline).await
    {
        errors.push(format!("peer streams: {error}"));
    }
    while let Some(process) = resources.processes.pop() {
        // ManagedProcess::shutdown owns the final child/output reaping step.
        // Do not put another timeout around it: dropping that future would
        // kill via Drop without reaping the child.
        let grace = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(5));
        if let Err(error) = process.shutdown(grace).await {
            errors.push(format!("process: {error}"));
        }
    }
    for device_id in &resources.owned_devices {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match timeout(remaining, cluster.wait_for_no_owner(tenant_id, *device_id)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => errors.push(format!("owner {}: {error}", device_id)),
            Err(_) => errors.push(format!("owner {device_id}: cleanup timed out")),
        }
    }
    // Only release the profile roots after every retained client process has
    // been given its reap attempt.  This keeps credentials available during
    // the entire failure path without retaining them after cleanup.
    resources.profiles.clear();
    resources.profile_root.take();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(HarnessError::Process(format!(
            "peer-capacity cleanup attempted {stream_count} public streams, {peer_stream_count} peer streams, {process_count} processes, and {owner_count} owners; {} error(s): {}",
            errors.len(),
            errors.join("; ")
        )))
    }
}

#[cfg(test)]
mod c17_validator_tests {
    use super::{PeerCapacityEvidence, validate_peer_capacity_evidence};
    use crate::acceptance_test_support::assert_rejected;

    fn valid_evidence() -> PeerCapacityEvidence {
        PeerCapacityEvidence {
            relay_count: 3,
            membership_ready_relays: 3,
            peer_stream_limit: 192,
            per_device_streams: [64, 64, 64],
            owner_count_on_target: 3,
            held_authenticated_streams: 192,
            baseline_echo: true,
            public_livez_ok_during_capacity: true,
            public_readyz_unready_during_capacity: true,
            capacity_route_withdrawn: true,
            capacity_probe_typed: true,
            selected_admission_rejected: true,
            selected_dispatch_not_advanced: true,
            held_stream_survived: true,
            public_readyz_ok_after_recovery: true,
            fresh_recovery_echo: true,
            elapsed_ms: 1,
        }
    }

    #[test]
    fn every_peer_capacity_flag_and_bound_reaches_the_shared_exit_path() {
        type Disable = (&'static str, fn(&mut PeerCapacityEvidence));
        let flags: [Disable; 10] = [
            ("baseline_echo", |e| e.baseline_echo = false),
            ("public_livez_ok_during_capacity", |e| {
                e.public_livez_ok_during_capacity = false
            }),
            ("public_readyz_unready_during_capacity", |e| {
                e.public_readyz_unready_during_capacity = false
            }),
            ("capacity_route_withdrawn", |e| {
                e.capacity_route_withdrawn = false
            }),
            ("capacity_probe_typed", |e| e.capacity_probe_typed = false),
            ("selected_admission_rejected", |e| {
                e.selected_admission_rejected = false
            }),
            ("selected_dispatch_not_advanced", |e| {
                e.selected_dispatch_not_advanced = false
            }),
            ("held_stream_survived", |e| e.held_stream_survived = false),
            ("public_readyz_ok_after_recovery", |e| {
                e.public_readyz_ok_after_recovery = false
            }),
            ("fresh_recovery_echo", |e| e.fresh_recovery_echo = false),
        ];
        for (name, disable) in flags {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_rejected(validate_peer_capacity_evidence(&evidence), name);
        }

        type Mutate = (&'static str, fn(&mut PeerCapacityEvidence));
        let bounds: [Mutate; 8] = [
            ("elapsed_ms", |e| e.elapsed_ms = 0),
            ("relay_count", |e| e.relay_count = 2),
            ("membership_ready_relays", |e| e.membership_ready_relays = 2),
            ("owner_count_on_target", |e| e.owner_count_on_target = 2),
            ("peer_stream_limit", |e| e.peer_stream_limit = 0),
            ("held_authenticated_streams", |e| {
                e.held_authenticated_streams = 1
            }),
            ("per_device_streams", |e| e.per_device_streams[0] = 0),
            ("per_device_stream_sum", |e| {
                e.per_device_streams = [64, 64, 63]
            }),
        ];
        for (_, mutate) in bounds {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(validate_peer_capacity_evidence(&evidence), "peer capacity");
        }
    }
}
