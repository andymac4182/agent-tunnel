//! Real-socket M2 acceptance flow.
//!
//! The M2 gate deliberately keeps one public consumer WebSocket open while a
//! production connector rotates its data carrier.  Application records cross
//! the public TLS listener and are checked against the redacted snapshots
//! emitted by the client and relay actors.  No actor method is used to route
//! application data.

use crate::acceptance::helpers::write_device_profile;
use crate::{
    ConnectionId, Direction, Harness, HarnessError, HarnessOptions, OidcTokenOptions, ProxyConfig,
    ProxyHandle, Result, RunningHarness, TcpProxy,
};
use futures_util::{SinkExt, StreamExt};
use rustls::{ClientConfig, RootCertStore, pki_types::CertificateDer};
use std::{
    collections::BTreeSet,
    io::ErrorKind,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time::{sleep, timeout};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
    tungstenite::{Message, client::IntoClientRequest, http::HeaderValue},
};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::Catalog;
use tunnel_client::{
    ClientError, ConnectConfig, ConnectOptions, ConnectionHandle, ConnectionStatus, Readiness,
    TransportProfile,
};
use tunnel_core::RotationConfig;
use tunnel_relay::{RelaySessionSnapshot, RelaySnapshot, RelayStreamSnapshot};
use uuid::Uuid;

const ECHO_SUBPROTOCOL: &str = "agent-tunnel.echo.v1";
const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_CANARY_BYTES: usize = 256;
const SNAPSHOT_POLL: Duration = Duration::from_millis(100);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
const ROTATION_WAIT: Duration = Duration::from_secs(90);
// Proxy pauses fail closed after 30 seconds.  Keep the candidate gate below
// that bound so the active data path is never resumed implicitly while the
// harness is still deciding which exact candidate to close.
const CANDIDATE_GATE_WAIT: Duration = Duration::from_secs(25);
const ROTATION_WAIT_MARGIN_SECONDS: u64 = 30;
const CLIENT_QUEUE_LIMIT_BYTES: usize = 8 * 1024 * 1024;
const RELAY_QUEUE_LIMIT_BYTES: usize = 4 * 1024 * 1024;
const CLIENT_QUEUE_LIMIT_FRAMES: usize = 128;
const RELAY_QUEUE_LIMIT_MESSAGES: usize = 128;
// Pacing between continuous consumer records.  The relay observes its writer
// barrier on a 500 ms maintenance tick, so every rotation keeps the relay
// writer frozen long enough for several paced records to land inside the
// quiesce/drain/commit window.
const CONTINUOUS_TRAFFIC_PACING: Duration = Duration::from_millis(5);
// After every request has received exactly one validated response, any
// further record within this window is a duplicate adapter delivery.
const STRAY_RESPONSE_WINDOW: Duration = Duration::from_millis(250);

type ConsumerSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

#[derive(Clone, Debug)]
struct RunPlan {
    name: &'static str,
    rotation: RotationConfig,
    rotations: u64,
    deadline: Duration,
    faults: bool,
}

impl RunPlan {
    fn accelerated() -> Self {
        Self {
            name: "accelerated",
            rotation: RotationConfig {
                interval_seconds: 3,
                handshake_timeout_seconds: 1,
                overlap_seconds: 2,
            },
            rotations: 3,
            deadline: Duration::from_secs(180),
            faults: false,
        }
    }

    fn default_intervals() -> Self {
        Self {
            name: "default",
            rotation: RotationConfig::default(),
            rotations: 3,
            // Three complete 300-second intervals are a required acceptance
            // condition.  The caller's bounded outer timeout is slightly
            // larger so cleanup remains observable after the final interval.
            deadline: Duration::from_secs(930),
            faults: false,
        }
    }

    fn faults() -> Self {
        Self {
            name: "faults",
            rotation: RotationConfig {
                interval_seconds: 3,
                handshake_timeout_seconds: 1,
                overlap_seconds: 2,
            },
            rotations: 3,
            deadline: Duration::from_secs(180),
            faults: true,
        }
    }

    /// Bound one clean handover wait from the policy under test.  The
    /// accelerated plan keeps the historical 90-second bound; production
    /// defaults need to cover the full interval, overlap, and a bounded
    /// scheduling margin before declaring a rotation missing.
    fn clean_rotation_wait(&self) -> Duration {
        let policy_bound = self
            .rotation
            .interval_seconds
            .saturating_add(self.rotation.overlap_seconds)
            .saturating_add(ROTATION_WAIT_MARGIN_SECONDS);
        Duration::from_secs(policy_bound.max(ROTATION_WAIT.as_secs()))
    }
}

/// Run the accelerated M2 acceptance flow.
pub async fn verify() -> Result<()> {
    run(RunPlan::accelerated()).await
}

/// Run M2 with the production 300/10/30-second policy.  This intentionally
/// takes at least three real interval boundaries; callers must allocate the
/// corresponding wall-clock timeout rather than replacing it with a mock.
pub async fn verify_default() -> Result<()> {
    run(RunPlan::default_intervals()).await
}

/// Run the accelerated targeted-fault acceptance.  Each fault is addressed to
/// an exact proxy source address obtained from the connector snapshot; the
/// harness never treats connection ordinal as a control/data role.
pub async fn verify_faults() -> Result<()> {
    run(RunPlan::faults()).await
}

async fn run(plan: RunPlan) -> Result<()> {
    let options = HarnessOptions::from_env()?.rotation(plan.rotation.clone());
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| {
            HarnessError::Timeout(format!("M2 {} harness startup timed out", plan.name))
        })??;
    let plan_name = plan.name;

    let scenario = timeout(plan.deadline, run_scenario(&mut harness, plan));
    let result = match scenario.await {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(format!(
            "M2 {} acceptance exceeded its bounded inner timeout",
            plan_name
        ))),
    };
    let cleanup = timeout(CLEANUP_TIMEOUT, harness.shutdown()).await;
    let cleanup = match cleanup {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "M2 harness cleanup exceeded its bounded timeout".to_owned(),
        )),
    };
    match (result, cleanup) {
        (Err(error), Err(cleanup_error)) => Err(HarnessError::Process(format!(
            "{error}; M2 harness cleanup also failed: {cleanup_error}"
        ))),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

async fn run_scenario(harness: &mut RunningHarness, plan: RunPlan) -> Result<()> {
    let scenario_started = Instant::now();
    let (consumer_addr, device_addr) = harness.start_production_relay().await?;

    // The relay address is ephemeral, so the proxy is attached after relay
    // startup and retained by RunningHarness for deterministic shutdown.
    let proxy = TcpProxy::bind(device_addr, ProxyConfig::default()).await?;
    let proxy_addr = proxy.local_addr();
    harness.proxy = Some(proxy);

    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("tenant A has no M2 device".to_owned()))?;
    let device_id = device.id;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device_id)
        .ok_or_else(|| HarnessError::InvalidInput("M2 device has no echo service".to_owned()))?;
    let canary = format!("m2-canary:{device_id}");
    if canary.len() > MAX_CANARY_BYTES {
        return Err(HarnessError::InvalidInput(
            "M2 device canary exceeds the 256-byte response bound".to_owned(),
        ));
    }
    let profile_directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    let mut profile = write_device_profile(
        profile_directory.path(),
        device_id,
        service_id,
        &canary,
        proxy_addr,
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile.config.rotation = plan.rotation.clone();
    profile.config.validate().map_err(|error| {
        HarnessError::InvalidInput(format!("M2 device profile is invalid: {error}"))
    })?;

    let cancellation = CancellationToken::new();
    let mut handle = timeout(
        STARTUP_TIMEOUT,
        tunnel_client::connect(ConnectOptions {
            config: profile.config.clone(),
            cancellation: cancellation.clone(),
            profile: TransportProfile::M2,
        }),
    )
    .await
    .map_err(|_| HarnessError::Timeout("M2 connector startup timed out".to_owned()))?
    .map_err(|error| HarnessError::Process(format!("M2 connector failed to connect: {error}")))?;
    let session = match timeout(STARTUP_TIMEOUT, handle.wait_ready()).await {
        Err(_) => {
            return Err(annotate_m2_failure(
                harness,
                &handle,
                "connector readiness",
                HarnessError::Timeout("M2 connector readiness timed out".to_owned()),
            )
            .await);
        }
        Ok(Err(error)) => {
            return Err(annotate_m2_failure(
                harness,
                &handle,
                "connector readiness",
                HarnessError::Process(format!("M2 connector did not become ready: {error}")),
            )
            .await);
        }
        Ok(Ok(session)) => session,
    };

    let consumer_token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: plan.deadline + Duration::from_secs(120),
            ..OidcTokenOptions::default()
        },
    )?;
    let mut stream = match open_consumer_stream(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &consumer_token,
        device_id,
        service_id,
    )
    .await
    .map_err(connect_failure_to_harness)
    {
        Ok(stream) => stream,
        Err(error) => {
            return Err(annotate_m2_failure(harness, &handle, "consumer handshake", error).await);
        }
    };

    let connected_result = run_connected_scenario(ConnectedScenario {
        harness,
        handle: &mut handle,
        stream: &mut stream,
        device_id,
        service_id,
        consumer_addr,
        session_id: &session.session_id,
        canary: canary.as_bytes(),
        config: &profile.config,
        consumer_token: &consumer_token,
        scenario_started,
        plan,
    })
    .await;
    match connected_result {
        Ok(()) => Ok(()),
        Err(error) => Err(annotate_m2_failure(harness, &handle, "scenario", error).await),
    }
}

struct ConnectedScenario<'a> {
    harness: &'a mut RunningHarness,
    handle: &'a mut ConnectionHandle,
    stream: &'a mut ConsumerStream,
    device_id: Uuid,
    service_id: Uuid,
    consumer_addr: SocketAddr,
    session_id: &'a str,
    canary: &'a [u8],
    config: &'a ConnectConfig,
    consumer_token: &'a str,
    scenario_started: Instant,
    plan: RunPlan,
}

async fn run_connected_scenario(context: ConnectedScenario<'_>) -> Result<()> {
    let ConnectedScenario {
        harness,
        handle,
        stream,
        device_id,
        service_id,
        consumer_addr,
        session_id,
        canary,
        config,
        consumer_token,
        scenario_started,
        plan,
    } = context;
    let mut evidence = RotationEvidence::default();
    let first_payload = record_payload(0);
    stream
        .round_trip(&first_payload, canary)
        .await
        .map_err(|error| stage_error("initial", error))?;
    let first = wait_for_quiet_snapshot(
        harness,
        handle,
        device_id,
        session_id,
        stream_id_hint(stream),
        plan.deadline.min(Duration::from_secs(30)),
        true,
    )
    .await
    .map_err(|error| stage_error("initial snapshot", error))?;
    stream.set_stream_id(first.stream.stream_id);
    evidence
        .observe(&first, session_id, stream)
        .map_err(|error| stage_error("initial evidence", error))?;
    verify_record_framing(stream, canary)
        .await
        .map_err(|error| stage_error("framing", error))?;
    verify_slow_consumer(harness, handle, stream, device_id, session_id, canary)
        .await
        .map_err(|error| stage_error("slow-consumer", error))?;
    if plan.faults {
        return run_fault_sequence(FaultScenario {
            harness,
            handle,
            stream,
            device_id,
            service_id,
            session_id,
            canary,
            initial: first,
            plan,
            config,
            valid_token: consumer_token,
        })
        .await
        .map_err(|error| stage_error("faults", error));
    }
    // Keep consumer traffic flowing continuously across every handover.  At
    // least one record is written while the relay writer is quiesced,
    // draining or committing in each rotation, so the immutable fence and
    // frozen-writer contract is exercised by real sockets rather than only by
    // post-commit probes.  The strict validator below proves contiguous
    // per-stream sequences, no duplicate delivery, no counter reset and no
    // drain rejection across the whole stage.
    let baseline = wait_for_quiet_snapshot(
        harness,
        handle,
        device_id,
        session_id,
        stream_id_hint(stream),
        Duration::from_secs(10),
        true,
    )
    .await
    .map_err(|error| stage_error("continuous baseline", error))?;
    let mut traffic = run_continuous_traffic_rotations(ContinuousTraffic {
        harness,
        handle,
        stream,
        device_id,
        session_id,
        canary,
        evidence: &mut evidence,
        baseline: &baseline,
        plan: &plan,
    })
    .await?;
    let settled = wait_for_quiet_snapshot(
        harness,
        handle,
        device_id,
        session_id,
        stream_id_hint(stream),
        Duration::from_secs(10),
        true,
    )
    .await
    .map_err(|error| stage_error("continuous settle", error))?;
    evidence
        .observe(&settled, session_id, stream)
        .map_err(|error| stage_error("continuous settle evidence", error))?;
    traffic.relay_emitted_delta = settled
        .stream
        .last_emitted_relay_to_connector
        .saturating_sub(baseline.stream.last_emitted_relay_to_connector);
    traffic.relay_received_delta = settled
        .stream
        .recv_contiguous_connector_to_relay
        .saturating_sub(baseline.stream.recv_contiguous_connector_to_relay);
    traffic.relay_last_emitted = settled.stream.last_emitted_relay_to_connector;
    traffic.relay_peer_acked = settled.stream.peer_acked_relay_to_connector;
    traffic.relay_recv_contiguous = settled.stream.recv_contiguous_connector_to_relay;
    traffic.relay_delivered_contiguous = settled.stream.delivered_contiguous_connector_to_relay;
    traffic.client_emitted_sequences = settled.client.emitted_sequences;
    traffic.client_received_sequences = settled.client.received_sequences;
    traffic.total_replayed_frames = settled.relay.total_replayed_frames;
    traffic.stray_response_observed = stream
        .observe_stray_response(STRAY_RESPONSE_WINDOW)
        .await
        .map_err(|error| stage_error("continuous stray-response window", error))?;
    require_m2_continuous_traffic_evidence(&traffic)
        .map_err(|error| stage_error("continuous traffic", error))?;
    tracing::info!(
        target: "tunnel_test_harness::m2",
        plan = plan.name,
        rotations_observed = traffic.rotations_observed,
        records_round_tripped = traffic.records_round_tripped,
        records_during_freeze = traffic.records_during_freeze,
        handover_phases = ?traffic.handover_phases_observed,
        relay_last_emitted = traffic.relay_last_emitted,
        relay_recv_contiguous = traffic.relay_recv_contiguous,
        "M2 continuous traffic evidence"
    );
    println!(
        "M2 continuous traffic passed: plan={} rotations={} records={} records_during_freeze={} handover_phases={:?} relay_emitted_delta={} relay_received_delta={} replayed_frames={}",
        plan.name,
        traffic.rotations_observed,
        traffic.records_round_tripped,
        traffic.records_during_freeze,
        traffic.handover_phases_observed,
        traffic.relay_emitted_delta,
        traffic.relay_received_delta,
        traffic.total_replayed_frames,
    );

    let final_status = handle.status_snapshot();
    if final_status.rotations_completed < plan.rotations {
        return Err(HarnessError::Process(format!(
            "M2 client reports {} completed rotations, expected at least {}",
            final_status.rotations_completed, plan.rotations
        )));
    }
    if evidence.generations.len() < (plan.rotations + 1) as usize {
        return Err(HarnessError::Process(format!(
            "M2 observed only {} data generations, expected at least {}",
            evidence.generations.len(),
            plan.rotations + 1
        )));
    }
    if evidence.connections.len() != evidence.generations.len() {
        return Err(HarnessError::Process(
            "M2 reused an active carrier connection ID across generations".to_owned(),
        ));
    }
    if final_status.replay_frames != 0 || final_status.replay_bytes != 0 {
        return Err(HarnessError::Process(
            "clean M2 rotation reported retained replay frames".to_owned(),
        ));
    }

    let final_snapshot = wait_for_quiet_snapshot(
        harness,
        handle,
        device_id,
        session_id,
        stream_id_hint(stream),
        Duration::from_secs(10),
        true,
    )
    .await
    .map_err(|error| stage_error("final snapshot", error))?;
    evidence
        .observe(&final_snapshot, session_id, stream)
        .map_err(|error| stage_error("final evidence", error))?;
    if final_snapshot.relay.rotations_completed < plan.rotations
        || final_snapshot.relay.total_replayed_frames != 0
    {
        return Err(HarnessError::Process(format!(
            "M2 relay rotation evidence was incomplete: rotations_completed={}, total_replayed_frames={}",
            final_snapshot.relay.rotations_completed, final_snapshot.relay.total_replayed_frames
        )));
    }
    let required_elapsed = Duration::from_secs(
        plan.rotation
            .interval_seconds
            .checked_mul(plan.rotations)
            .ok_or_else(|| {
                HarnessError::InvalidInput("M2 rotation elapsed-time bound overflowed".to_owned())
            })?,
    );
    if scenario_started.elapsed() < required_elapsed {
        return Err(HarnessError::Process(format!(
            "M2 completed {} rotations before {} real seconds elapsed",
            plan.rotations,
            required_elapsed.as_secs()
        )));
    }
    if final_snapshot.relay.candidate_generation.is_some()
        || final_snapshot.relay.sockets > 2
        || final_snapshot.relay.phase != "active"
        || final_snapshot.stream.terminal
    {
        return Err(HarnessError::Process(format!(
            "M2 final handover did not retire its candidate: phase={}, sockets={}, candidate={:?}",
            final_snapshot.relay.phase,
            final_snapshot.relay.sockets,
            final_snapshot.relay.candidate_generation
        )));
    }
    tracing::info!(
        target: "tunnel_test_harness::m2",
        plan = plan.name,
        elapsed_seconds = scenario_started.elapsed().as_secs_f64(),
        rotations_completed = final_snapshot.relay.rotations_completed,
        generations = ?evidence.generations,
        active_connections = ?evidence.connections,
        "M2 real-socket acceptance evidence"
    );

    stream
        .close()
        .await
        .map_err(|error| stage_error("close", error))?;
    let stop_result = timeout(STARTUP_TIMEOUT, handle.stop())
        .await
        .map_err(|_| HarnessError::Timeout("M2 connector shutdown timed out".to_owned()))?
        .map_err(|error| HarnessError::Process(format!("M2 connector shutdown failed: {error}")));

    stop_result?;
    verify_proxy_retirement(harness, plan.rotations)
        .await
        .map_err(|error| stage_error("proxy retirement", error))?;
    verify_consumer_rejections(
        harness,
        consumer_addr,
        device_id,
        service_id,
        consumer_token,
    )
    .await
    .map_err(|error| stage_error("consumer authorization", error))?;
    Ok(())
}

/// Payload-free evidence for the continuous-traffic rotation stage.  Counts
/// and cursors come from the redacted relay/client snapshots and the
/// harness's own record accounting; no record body is retained.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ContinuousTrafficEvidence {
    pub rotations_required: u64,
    pub rotations_observed: u64,
    pub records_round_tripped: u64,
    /// Records written while the relay reported `quiescing`, `draining` or
    /// `committing`, i.e. while its old writer had to be frozen.
    pub records_during_freeze: u64,
    pub handover_phases_observed: BTreeSet<String>,
    pub relay_emitted_delta: u64,
    pub relay_received_delta: u64,
    pub relay_last_emitted: u64,
    pub relay_peer_acked: u64,
    pub relay_recv_contiguous: u64,
    pub relay_delivered_contiguous: u64,
    pub client_emitted_sequences: u64,
    pub client_received_sequences: u64,
    pub total_replayed_frames: u64,
    pub connector_terminal_phase_observed: bool,
    pub stray_response_observed: bool,
}

/// Every mandatory continuous-traffic condition.  A false flag or a count
/// below its bound fails the command with a bounded, payload-free diagnostic
/// naming each failed condition.
pub fn require_m2_continuous_traffic_evidence(evidence: &ContinuousTrafficEvidence) -> Result<()> {
    let checks = [
        (
            "rotations_observed_at_least_required",
            evidence.rotations_required > 0
                && evidence.rotations_observed >= evidence.rotations_required,
        ),
        (
            "records_round_tripped_nonzero",
            evidence.records_round_tripped > 0,
        ),
        (
            "records_during_freeze_nonzero",
            evidence.records_during_freeze > 0,
        ),
        (
            "relay_emitted_contiguous",
            evidence.relay_emitted_delta == evidence.records_round_tripped,
        ),
        (
            "relay_received_contiguous",
            evidence.relay_received_delta == evidence.records_round_tripped,
        ),
        (
            "relay_peer_acked_reaches_last_emitted",
            evidence.relay_peer_acked == evidence.relay_last_emitted,
        ),
        (
            "relay_delivered_reaches_received",
            evidence.relay_delivered_contiguous == evidence.relay_recv_contiguous,
        ),
        (
            "client_relay_cursors_agree",
            evidence.client_received_sequences == evidence.relay_last_emitted
                && evidence.client_emitted_sequences == evidence.relay_recv_contiguous,
        ),
        ("no_replayed_frames", evidence.total_replayed_frames == 0),
        (
            "connector_never_terminal",
            !evidence.connector_terminal_phase_observed,
        ),
        ("no_stray_response", !evidence.stray_response_observed),
    ];
    let failed = checks
        .iter()
        .filter_map(|(name, passed)| (!*passed).then_some(*name))
        .collect::<Vec<_>>();
    if failed.is_empty() {
        Ok(())
    } else {
        Err(HarnessError::Process(format!(
            "M2 continuous traffic returned incomplete acceptance evidence: {}",
            failed.join(", ")
        )))
    }
}

struct ContinuousTraffic<'a> {
    harness: &'a RunningHarness,
    handle: &'a ConnectionHandle,
    stream: &'a mut ConsumerStream,
    device_id: Uuid,
    session_id: &'a str,
    canary: &'a [u8],
    evidence: &'a mut RotationEvidence,
    baseline: &'a StreamSnapshot,
    plan: &'a RunPlan,
}

/// Round-trip paced records without pause until the required number of
/// clean generation advances has been observed.  The relay phase is sampled
/// immediately before each write so a record can be attributed to the frozen
/// window it entered; each response is validated byte-for-byte in order, so a
/// lost, duplicated or reordered delivery fails at the record that exposed
/// it.  Sequence cursors are filled in by the caller from the settled
/// snapshot.
async fn run_continuous_traffic_rotations(
    context: ContinuousTraffic<'_>,
) -> Result<ContinuousTrafficEvidence> {
    let ContinuousTraffic {
        harness,
        handle,
        stream,
        device_id,
        session_id,
        canary,
        evidence,
        baseline,
        plan,
    } = context;
    let mut traffic = ContinuousTrafficEvidence {
        rotations_required: plan.rotations,
        ..ContinuousTrafficEvidence::default()
    };
    let mut generation = baseline.relay.active_generation;
    let mut record_index = 0_u64;
    let rotation_budget = plan.clean_rotation_wait();
    let mut last_rotation = Instant::now();
    while traffic.rotations_observed < plan.rotations {
        let sampled = wait_for_stream_snapshot(
            harness,
            handle,
            device_id,
            session_id,
            stream.stream_id_hint(),
            SNAPSHOT_POLL,
        )
        .await
        .map_err(|error| stage_error("continuous snapshot", error))?;
        evidence
            .observe(&sampled, session_id, stream)
            .map_err(|error| stage_error("continuous evidence", error))?;
        if matches!(sampled.client.phase.as_str(), "closed" | "failed") {
            traffic.connector_terminal_phase_observed = true;
            return Err(HarnessError::Process(format!(
                "M2 connector reached terminal phase {} during continuous traffic after {} records ({} during freeze)",
                sampled.client.phase, traffic.records_round_tripped, traffic.records_during_freeze
            )));
        }
        let phase = sampled.relay.phase.clone();
        let frozen_phase = matches!(phase.as_str(), "quiescing" | "draining" | "committing");
        if phase != "active" {
            traffic.handover_phases_observed.insert(phase.clone());
        }
        let payload = record_payload(record_index);
        stream.round_trip(&payload, canary).await.map_err(|error| {
            stage_error(
                &format!("continuous record {record_index} written in relay phase {phase}"),
                error,
            )
        })?;
        record_index = record_index.saturating_add(1);
        traffic.records_round_tripped = traffic.records_round_tripped.saturating_add(1);
        if frozen_phase {
            traffic.records_during_freeze = traffic.records_during_freeze.saturating_add(1);
        }
        if sampled.relay.active_generation > generation
            && sampled.relay.candidate_generation.is_none()
            && sampled.relay.sockets <= 2
        {
            generation = sampled.relay.active_generation;
            traffic.rotations_observed = traffic.rotations_observed.saturating_add(1);
            last_rotation = Instant::now();
        }
        if last_rotation.elapsed() >= rotation_budget {
            return Err(HarnessError::Timeout(format!(
                "M2 data generation did not advance beyond {generation} while continuous traffic flowed ({} records)",
                traffic.records_round_tripped
            )));
        }
        sleep(CONTINUOUS_TRAFFIC_PACING).await;
    }
    Ok(traffic)
}

fn stage_error(stage: &str, error: HarnessError) -> HarnessError {
    HarnessError::Process(format!("M2 {stage} stage failed: {error}"))
}

/// Add bounded, payload-free diagnostics to a connected scenario failure.
///
/// The public consumer stream intentionally reports only the framing error;
/// the connector status, terminal join outcome (when it is already
/// available), and relay actor snapshot make a failure actionable without
/// copying records, JWTs, or certificate material into the harness error.
async fn annotate_m2_failure(
    harness: &RunningHarness,
    handle: &ConnectionHandle,
    stage: &str,
    error: HarnessError,
) -> HarnessError {
    let client_status = handle.status_snapshot();
    let readiness = handle.readiness().borrow().clone();
    let relay_snapshot = match harness.production_snapshot().await {
        Ok(snapshot) => redacted_relay_snapshot(&snapshot),
        Err(snapshot_error) => format!("unavailable ({snapshot_error})"),
    };
    let connector_outcome = match timeout(Duration::from_secs(5), handle.stop()).await {
        Ok(Ok(())) => "stopped cleanly".to_owned(),
        Ok(Err(error)) => format!("terminal error: {error}"),
        Err(_) => "stop timed out".to_owned(),
    };
    HarnessError::Process(format!(
        "M2 {stage} failed: {error}; client_status={}; readiness={}; connector_outcome={connector_outcome}; relay_snapshot={relay_snapshot}",
        redacted_client_status(&client_status),
        redacted_readiness(&readiness),
    ))
}

fn redacted_readiness(readiness: &Readiness) -> String {
    match readiness {
        Readiness::Connecting => "connecting".to_owned(),
        Readiness::ControlOpen => "control_open".to_owned(),
        Readiness::DataOpening => "data_opening".to_owned(),
        Readiness::Ready(_) => "ready".to_owned(),
        Readiness::Stopping => "stopping".to_owned(),
        Readiness::Closed { reason } => format!("closed({reason})"),
    }
}

fn redacted_client_status(status: &ConnectionStatus) -> String {
    format!(
        "phase={},session_id={:?},epoch={:?},active_generation={:?},active_connection_id={:?},candidate_generation={:?},candidate_connection_id={:?},rotation_id={:?},streams={},emitted_sequences={},received_sequences={},drain_fences={},drain_acks={},replay_frames={},replay_bytes={},queue_frames={},queue_bytes={},rotations_completed={},control_local_addr={:?},active_local_addr={:?},candidate_local_addr={:?}",
        status.phase,
        status.session_id,
        status.epoch,
        status.active_generation,
        status.active_connection_id,
        status.candidate_generation,
        status.candidate_connection_id,
        status.rotation_id,
        status.streams,
        status.emitted_sequences,
        status.received_sequences,
        status.drain_fences,
        status.drain_acks,
        status.replay_frames,
        status.replay_bytes,
        status.queue_frames,
        status.queue_bytes,
        status.rotations_completed,
        status.control_local_addr,
        status.active_local_addr,
        status.candidate_local_addr,
    )
}

fn annotate_revocation_handle_failure(
    handle: &ConnectionHandle,
    error: HarnessError,
) -> HarnessError {
    let status = handle.status_snapshot();
    let readiness = handle.readiness().borrow().clone();
    HarnessError::Process(format!(
        "{error}; revocation_client_status={}; revocation_readiness={}",
        redacted_client_status(&status),
        redacted_readiness(&readiness),
    ))
}

fn redacted_relay_snapshot(snapshot: &RelaySnapshot) -> String {
    let sessions = snapshot
        .sessions
        .iter()
        .map(|session| {
            let streams = session
                .streams
                .iter()
                .map(|stream| {
                    format!(
                        "{{stream_id={},operation_id={:?},last_emitted={},peer_acked={},recv_contiguous={},delivered_contiguous={},replay_frames={},replay_bytes={},queue_bytes={},terminal={}}}",
                        stream.stream_id,
                        stream.operation_id,
                        stream.last_emitted_relay_to_connector,
                        stream.peer_acked_relay_to_connector,
                        stream.recv_contiguous_connector_to_relay,
                        stream.delivered_contiguous_connector_to_relay,
                        stream.replay_frames_relay_to_connector,
                        stream.replay_bytes_relay_to_connector,
                        stream.queue_bytes,
                        stream.terminal,
                    )
                })
                .collect::<Vec<_>>();
            format!(
                "{{device_id={:?},session_id={:?},epoch={},profile={},phase={},active_generation={},active_connection_id={:?},candidate_generation={:?},candidate_connection_id={:?},sockets={},queue_bytes={},queue_messages={},drain_fences={},drain_proofs={},replay_frames={},replay_bytes={},rotations_completed={},total_replayed_frames={},streams={streams:?}}}",
                session.device_id,
                session.session_id,
                session.epoch,
                session.profile,
                session.phase,
                session.active_generation,
                session.active_connection_id,
                session.candidate_generation,
                session.candidate_connection_id,
                session.sockets,
                session.queue_bytes,
                session.queue_messages,
                session.drain_fences,
                session.drain_proofs,
                session.replay_frames,
                session.replay_bytes,
                session.rotations_completed,
                session.total_replayed_frames,
            )
        })
        .collect::<Vec<_>>();
    format!("sessions={sessions:?}")
}

struct FaultScenario<'a> {
    harness: &'a mut RunningHarness,
    handle: &'a ConnectionHandle,
    stream: &'a mut ConsumerStream,
    device_id: Uuid,
    service_id: Uuid,
    session_id: &'a str,
    canary: &'a [u8],
    initial: StreamSnapshot,
    plan: RunPlan,
    config: &'a ConnectConfig,
    valid_token: &'a str,
}

async fn run_fault_sequence(context: FaultScenario<'_>) -> Result<()> {
    let FaultScenario {
        harness,
        handle,
        stream,
        device_id,
        service_id,
        session_id,
        canary,
        initial,
        plan,
        config,
        valid_token,
    } = context;
    let proxy = harness.proxy.as_ref().ok_or_else(|| {
        HarnessError::InvalidInput("M2 fault flow requires its real TCP proxy".to_owned())
    })?;
    let initial_status = handle.status_snapshot();
    let active_id = wait_for_connection_for_addr(
        proxy,
        initial_status.active_local_addr,
        "active data carrier",
        STARTUP_TIMEOUT,
    )
    .await
    .map_err(|error| stage_error("data-loss active mapping", error))?;

    // Old-data loss: pause the exact active data socket, enqueue a record,
    // then close that socket.  The response must arrive once after retained
    // recovery on the replacement carrier.
    proxy
        .pause(Direction::TargetToClient, active_id)
        .await
        .map_err(|error| HarnessError::Proxy(format!("pausing active data carrier: {error}")))
        .map_err(|error| stage_error("data-loss pause", error))?;
    let recovery_payload = record_payload(100);
    stream
        .send_record(&recovery_payload)
        .await
        .map_err(|error| stage_error("data-loss replay send", error))?;
    sleep(Duration::from_millis(50)).await;
    proxy
        .close(active_id)
        .await
        .map_err(|error| HarnessError::Proxy(format!("closing active data carrier: {error}")))
        .map_err(|error| stage_error("data-loss close", error))?;
    let recovery_response = stream
        .receive_response()
        .await
        .map_err(|error| stage_error("data-loss replay response", error))?;
    stream
        .validate_response(&recovery_response, canary, &recovery_payload)
        .map_err(|error| stage_error("data-loss replay validation", error))?;
    let recovered = wait_for_quiet_snapshot(
        harness,
        handle,
        device_id,
        session_id,
        stream.stream_id_hint(),
        Duration::from_secs(30),
        false,
    )
    .await
    .map_err(|error| stage_error("data-loss recovery snapshot", error))?;
    if recovered.relay.session_id != initial.relay.session_id
        || recovered.relay.epoch != initial.relay.epoch
        || recovered.stream.stream_id != initial.stream.stream_id
        || recovered.stream.operation_id != initial.stream.operation_id
        || recovered.relay.active_connection_id == initial.relay.active_connection_id
    {
        return Err(HarnessError::Process(
            "M2 old-data recovery changed logical identity or failed to retire the lost carrier"
                .to_owned(),
        ));
    }

    // Candidate abort: hold the active data response direction, enqueue one
    // bounded record, and wait until the relay has emitted that request while
    // its ACK is still outstanding.  The immutable drain fence then cannot
    // complete, so closing the exact pre-commit candidate is deterministic
    // while the public stream remains a real socket path.
    let gap_status = handle.status_snapshot();
    let gap_session_id = gap_status.session_id.clone().ok_or_else(|| {
        HarnessError::Process("M2 candidate gate lost the client session ID".to_owned())
    })?;
    let gap_epoch = gap_status.epoch.ok_or_else(|| {
        HarnessError::Process("M2 candidate gate lost the client epoch".to_owned())
    })?;
    let before_generation = gap_status.active_generation.ok_or_else(|| {
        HarnessError::Process("M2 candidate gate lost the active generation".to_owned())
    })?;
    if gap_session_id != session_id || gap_epoch != recovered.relay.epoch {
        return Err(HarnessError::Process(
            "M2 candidate gate changed the logical session after old-data recovery".to_owned(),
        ));
    }
    if before_generation != recovered.relay.active_generation {
        return Err(HarnessError::Process(
            "M2 candidate gate changed the active generation after old-data recovery".to_owned(),
        ));
    }
    let gap_active_id = wait_for_connection_for_addr(
        proxy,
        gap_status.active_local_addr,
        "candidate-abort active data carrier",
        STARTUP_TIMEOUT,
    )
    .await
    .map_err(|error| stage_error("candidate-abort active mapping", error))?;
    let stream_id = stream.stream_id_hint().ok_or_else(|| {
        HarnessError::Process("M2 candidate gate lost the public stream ID".to_owned())
    })?;
    let after_abort = run_candidate_abort_gate(CandidateAbortGate {
        harness,
        handle,
        stream,
        proxy,
        device_id,
        session_id,
        epoch: gap_epoch,
        active_generation: before_generation,
        active_id: gap_active_id,
        stream_id,
        baseline_last_emitted: recovered.stream.last_emitted_relay_to_connector,
        canary,
        budget: CANDIDATE_GATE_WAIT,
    })
    .await
    .map_err(|error| stage_error("candidate-abort", error))?;
    if after_abort.relay.active_generation != before_generation
        || after_abort.relay.session_id != initial.relay.session_id
        || after_abort.stream.operation_id != initial.stream.operation_id
    {
        return Err(HarnessError::Process(
            "M2 candidate abort changed the active logical session".to_owned(),
        ));
    }

    // Control loss is an explicit interruption.  Closing the exact control
    // source address must end this session; the relay may not silently attach
    // a fresh epoch behind the same client handle.
    let control_id = wait_for_connection_for_addr(
        proxy,
        handle.status_snapshot().control_local_addr,
        "control carrier",
        STARTUP_TIMEOUT,
    )
    .await
    .map_err(|error| stage_error("control-loss control mapping", error))?;
    proxy
        .close(control_id)
        .await
        .map_err(|error| HarnessError::Proxy(format!("closing control carrier: {error}")))
        .map_err(|error| stage_error("control-loss close", error))?;
    wait_for_client_closed(handle, ROTATION_WAIT)
        .await
        .map_err(|error| stage_error("control-loss client interruption", error))?;
    stream
        .close()
        .await
        .map_err(|error| stage_error("control-loss consumer close", error))?;
    let stop_result = timeout(Duration::from_secs(30), handle.stop())
        .await
        .map_err(|_| {
            HarnessError::Timeout("M2 control-loss client shutdown timed out".to_owned())
        })?;
    let readiness = handle.readiness().borrow().clone();
    assert_expected_control_loss(stop_result, &readiness)
        .map_err(|error| stage_error("control-loss client shutdown", error))?;
    wait_for_session_absent(harness, device_id, ROTATION_WAIT)
        .await
        .map_err(|error| stage_error("control-loss relay cleanup", error))?;
    wait_for_proxy_idle(proxy, Duration::from_secs(30))
        .await
        .map_err(|error| stage_error("control-loss proxy cleanup", error))?;

    // Cancellation during a pending replacement is a separate terminal case
    // from physical control loss.  Keep this session isolated and complete its
    // carrier retirement before starting the authorization-revocation case so
    // the proxy's global peak still proves the three-socket per-session bound.
    let cancel_token = CancellationToken::new();
    let mut cancel_handle = timeout(
        STARTUP_TIMEOUT,
        tunnel_client::connect(ConnectOptions {
            config: config.clone(),
            cancellation: cancel_token.clone(),
            profile: TransportProfile::M2,
        }),
    )
    .await
    .map_err(|_| HarnessError::Timeout("M2 cancellation-session startup timed out".to_owned()))?
    .map_err(|error| HarnessError::Process(format!("M2 cancellation-session failed: {error}")))?;
    let cancel_session = timeout(STARTUP_TIMEOUT, cancel_handle.wait_ready())
        .await
        .map_err(|_| {
            HarnessError::Timeout("M2 cancellation-session readiness timed out".to_owned())
        })?
        .map_err(|error| {
            HarnessError::Process(format!("M2 cancellation-session was not ready: {error}"))
        })?;
    let mut cancel_stream = open_consumer_stream(
        harness
            .production_addresses()
            .ok_or_else(|| {
                HarnessError::InvalidInput("M2 relay stopped during cancellation fault".to_owned())
            })?
            .0,
        &harness.pki.server_ca.certificate_der,
        valid_token,
        device_id,
        service_id,
    )
    .await
    .map_err(connect_failure_to_harness)
    .map_err(|error| stage_error("cancellation consumer handshake", error))?;
    let cancel_payload = record_payload(102);
    cancel_stream
        .round_trip(&cancel_payload, canary)
        .await
        .map_err(|error| stage_error("cancellation response", error))?;
    let cancel_initial = wait_for_stream_snapshot(
        harness,
        &cancel_handle,
        device_id,
        &cancel_session.session_id,
        None,
        Duration::from_secs(30),
    )
    .await
    .map_err(|error| stage_error("cancellation initial snapshot", error))?;
    cancel_stream.set_stream_id(cancel_initial.stream.stream_id);
    let _cancel_candidate = wait_for_candidate(harness, &cancel_handle, proxy, ROTATION_WAIT)
        .await
        .map_err(|error| stage_error("cancellation candidate", error))?;
    cancel_token.cancel();
    timeout(Duration::from_secs(30), cancel_handle.stop())
        .await
        .map_err(|_| {
            HarnessError::Timeout("M2 cancellation-session shutdown timed out".to_owned())
        })?
        .map_err(|error| {
            HarnessError::Process(format!("M2 cancellation-session shutdown failed: {error}"))
        })
        .map_err(|error| stage_error("cancellation client shutdown", error))?;
    wait_for_client_closed(&cancel_handle, Duration::from_secs(5))
        .await
        .map_err(|error| stage_error("cancellation terminal state", error))?;
    cancel_stream
        .close()
        .await
        .map_err(|error| stage_error("cancellation consumer close", error))?;
    wait_for_session_absent(harness, device_id, ROTATION_WAIT)
        .await
        .map_err(|error| stage_error("cancellation relay cleanup", error))?;
    wait_for_proxy_idle(proxy, Duration::from_secs(30))
        .await
        .map_err(|error| stage_error("cancellation proxy cleanup", error))?;

    // Start a fresh session for the revocation-during-drain case.  This keeps
    // the control-loss result independent from the authorization result while
    // using the same production certificate and socket proxy.
    let mut second_handle = timeout(
        STARTUP_TIMEOUT,
        tunnel_client::connect(ConnectOptions {
            config: config.clone(),
            cancellation: CancellationToken::new(),
            profile: TransportProfile::M2,
        }),
    )
    .await
    .map_err(|_| HarnessError::Timeout("M2 fresh fault-session startup timed out".to_owned()))?
    .map_err(|error| HarnessError::Process(format!("M2 fresh fault-session failed: {error}")))?;
    let second_session = timeout(STARTUP_TIMEOUT, second_handle.wait_ready())
        .await
        .map_err(|_| {
            HarnessError::Timeout("M2 fresh fault-session readiness timed out".to_owned())
        })?
        .map_err(|error| {
            HarnessError::Process(format!("M2 fresh fault-session was not ready: {error}"))
        })?;
    if second_session.session_id == session_id {
        return Err(HarnessError::Process(
            "M2 control-loss reconnect reused the retired session ID".to_owned(),
        ));
    }
    let mut second_stream = open_consumer_stream(
        harness
            .production_addresses()
            .ok_or_else(|| {
                HarnessError::InvalidInput("M2 relay stopped during fault flow".to_owned())
            })?
            .0,
        &harness.pki.server_ca.certificate_der,
        valid_token,
        device_id,
        service_id,
    )
    .await
    .map_err(connect_failure_to_harness)
    .map_err(|error| stage_error("revocation consumer handshake", error))?;
    let second_payload = record_payload(103);
    second_stream
        .round_trip(&second_payload, canary)
        .await
        .map_err(|error| stage_error("revocation initial response", error))?;
    let second_initial = wait_for_stream_snapshot(
        harness,
        &second_handle,
        device_id,
        &second_session.session_id,
        None,
        Duration::from_secs(30),
    )
    .await
    .map_err(|error| stage_error("revocation initial snapshot", error))?;
    second_stream.set_stream_id(second_initial.stream.stream_id);
    let candidate_id = wait_for_candidate(harness, &second_handle, proxy, ROTATION_WAIT)
        .await
        .map_err(|error| stage_error("revocation candidate", error))?;
    let catalog = harness
        .production_catalog()
        .map_err(|error| stage_error("revocation catalog", error))?;
    catalog
        .revoke_grant(
            harness.topology.tenant_a.id,
            harness.topology.consumers_a[0].id,
            device_id,
            service_id,
            chrono::Utc::now(),
        )
        .await
        .map_err(|error| HarnessError::Redis(format!("revoking M2 drain grant: {error}")))
        .map_err(|error| stage_error("revocation catalog update", error))?;
    let revoked_payload = record_payload(104);
    let mut revocation_observed = false;
    // A stream authorization confirmation is deliberately short-lived.  Give
    // the bounded cache time to expire, accepting any already-authorized
    // response, then require the next record to receive an explicit terminal
    // outcome after the catalog revocation.  This avoids treating an in-flight
    // authorization as a revocation bypass while keeping the fault finite.
    let revocation_started = Instant::now();
    let revocation_deadline = Duration::from_secs(8);
    let fresh_auth_bound = Duration::from_secs(5);
    for attempt in 0..8_u8 {
        let remaining = revocation_deadline.saturating_sub(revocation_started.elapsed());
        if remaining.is_zero() {
            break;
        }
        let payload = if attempt == 0 {
            revoked_payload.clone()
        } else {
            record_payload(104 + u64::from(attempt))
        };
        if second_stream.send_record(&payload).await.is_err() {
            revocation_observed = true;
            break;
        }
        match timeout(
            remaining.min(Duration::from_secs(3)),
            second_stream.receive_response(),
        )
        .await
        {
            Ok(Ok(response)) => {
                let elapsed = revocation_started.elapsed();
                if elapsed > fresh_auth_bound {
                    return Err(HarnessError::Process(format!(
                        "M2 revoked stream completed a newly dispatched record after the {}s fresh-authorization bound (elapsed {:.3}s)",
                        fresh_auth_bound.as_secs(),
                        elapsed.as_secs_f64()
                    )));
                }
                second_stream
                    .validate_response(&response, canary, &payload)
                    .map_err(|error| stage_error("revocation response validation", error))?;
            }
            Ok(Err(_)) => {
                revocation_observed = true;
                break;
            }
            Err(_) => {
                return Err(stage_error(
                    "revocation response wait",
                    HarnessError::Timeout(format!(
                        "M2 revocation during drain did not produce an explicit stream outcome within {}s",
                        revocation_deadline.as_secs()
                    )),
                ));
            }
        }
        sleep(
            Duration::from_secs(1)
                .min(revocation_deadline.saturating_sub(revocation_started.elapsed())),
        )
        .await;
    }
    if !revocation_observed {
        return Err(HarnessError::Timeout(format!(
            "M2 revoked stream continued completing records for {:.3}s without an explicit outcome",
            revocation_started.elapsed().as_secs_f64()
        )));
    }
    // The candidate was observed by source address before revocation; close
    // it only after the authorization result is visible so this fault cannot
    // be confused with a candidate-abort pass.
    if proxy
        .connections()
        .into_iter()
        .any(|connection| connection.id == candidate_id)
    {
        proxy
            .close(candidate_id)
            .await
            .map_err(|error| HarnessError::Proxy(format!("closing revoked candidate: {error}")))
            .map_err(|error| stage_error("revocation candidate close", error))
            .map_err(|error| annotate_revocation_handle_failure(&second_handle, error))?;
    }
    second_stream
        .close()
        .await
        .map_err(|error| stage_error("revocation consumer close", error))
        .map_err(|error| annotate_revocation_handle_failure(&second_handle, error))?;
    timeout(Duration::from_secs(30), second_handle.stop())
        .await
        .map_err(|_| HarnessError::Timeout("M2 fresh fault-session shutdown timed out".to_owned()))?
        .map_err(|error| {
            HarnessError::Process(format!("M2 fresh fault-session shutdown failed: {error}"))
        })
        .map_err(|error| stage_error("revocation client shutdown", error))
        .map_err(|error| annotate_revocation_handle_failure(&second_handle, error))?;
    verify_proxy_retirement(harness, plan.rotations)
        .await
        .map_err(|error| stage_error("revocation proxy retirement", error))?;
    verify_consumer_rejections(
        harness,
        harness
            .production_addresses()
            .ok_or_else(|| {
                HarnessError::InvalidInput("M2 relay stopped during fault flow".to_owned())
            })?
            .0,
        device_id,
        service_id,
        valid_token,
    )
    .await
    .map_err(|error| stage_error("revocation authorization rejection", error))
}

async fn wait_for_connection_for_addr(
    proxy: &ProxyHandle,
    local_addr: Option<SocketAddr>,
    role: &str,
    budget: Duration,
) -> Result<ConnectionId> {
    let local_addr = local_addr.ok_or_else(|| {
        HarnessError::Unsupported(format!(
            "M2 {role} fault requires connector local-address diagnostics"
        ))
    })?;
    let started = Instant::now();
    loop {
        let matches = proxy
            .connections()
            .into_iter()
            .filter(|connection| connection.source_addr == local_addr)
            .map(|connection| connection.id)
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [connection_id] => return Ok(*connection_id),
            [_first, _second, ..] => {
                return Err(HarnessError::Process(format!(
                    "M2 proxy mapped more than one {role} connection to connector source {local_addr}"
                )));
            }
            [] if started.elapsed() >= budget => {
                return Err(HarnessError::Process(format!(
                    "M2 proxy has no live {role} connection for connector source {local_addr}"
                )));
            }
            [] => sleep(SNAPSHOT_POLL).await,
        }
    }
}

async fn wait_for_candidate(
    harness: &RunningHarness,
    handle: &ConnectionHandle,
    proxy: &ProxyHandle,
    budget: Duration,
) -> Result<ConnectionId> {
    let started = Instant::now();
    loop {
        let status = handle.status_snapshot();
        if status.candidate_generation.is_some()
            && let Some(local_addr) = status.candidate_local_addr
            && let Some(connection_id) = proxy
                .connections()
                .into_iter()
                .find(|connection| connection.source_addr == local_addr)
                .map(|connection| connection.id)
        {
            return Ok(connection_id);
        }
        if matches!(status.phase.as_str(), "closed" | "failed") {
            return Err(HarnessError::Process(
                "M2 client reached a terminal phase before a rotation candidate appeared"
                    .to_owned(),
            ));
        }
        if started.elapsed() >= budget {
            return Err(HarnessError::Timeout(
                "M2 rotation candidate did not appear before fault deadline".to_owned(),
            ));
        }
        harness.production_snapshot().await?;
        sleep(SNAPSHOT_POLL).await;
    }
}

struct CandidateAbortGate<'a> {
    harness: &'a RunningHarness,
    handle: &'a ConnectionHandle,
    stream: &'a mut ConsumerStream,
    proxy: &'a ProxyHandle,
    device_id: Uuid,
    session_id: &'a str,
    epoch: u64,
    active_generation: u64,
    active_id: ConnectionId,
    stream_id: u64,
    baseline_last_emitted: u64,
    canary: &'a [u8],
    budget: Duration,
}

#[derive(Clone, Debug)]
struct CandidateGate {
    proxy_id: ConnectionId,
    generation: u64,
    connection_id: String,
}

struct OutstandingRecordWait<'a> {
    harness: &'a RunningHarness,
    handle: &'a ConnectionHandle,
    device_id: Uuid,
    session_id: &'a str,
    stream_id: u64,
    active_generation: u64,
    baseline_last_emitted: u64,
    budget: Duration,
}

struct PrecommitCandidateWait<'a> {
    harness: &'a RunningHarness,
    handle: &'a ConnectionHandle,
    proxy: &'a ProxyHandle,
    device_id: Uuid,
    session_id: &'a str,
    epoch: u64,
    active_generation: u64,
    budget: Duration,
}

struct CandidateAbortCompletion<'a> {
    harness: &'a RunningHarness,
    handle: &'a ConnectionHandle,
    device_id: Uuid,
    session_id: &'a str,
    epoch: u64,
    active_generation: u64,
    stream_id: u64,
    budget: Duration,
}

struct CandidateAbortDecisionWait<'a> {
    harness: &'a RunningHarness,
    handle: &'a ConnectionHandle,
    device_id: Uuid,
    session_id: &'a str,
    epoch: u64,
    active_generation: u64,
    candidate_generation: u64,
    budget: Duration,
}

fn is_candidate_precommit_phase(phase: &str) -> bool {
    matches!(phase, "preparing" | "quiescing" | "draining")
}

async fn run_candidate_abort_gate(context: CandidateAbortGate<'_>) -> Result<StreamSnapshot> {
    let CandidateAbortGate {
        harness,
        handle,
        stream,
        proxy,
        device_id,
        session_id,
        epoch,
        active_generation,
        active_id,
        stream_id,
        baseline_last_emitted,
        canary,
        budget,
    } = context;

    proxy
        .pause(Direction::TargetToClient, active_id)
        .await
        .map_err(|error| HarnessError::Proxy(format!("pausing active data carrier: {error}")))
        .map_err(|error| stage_error("candidate-abort pause", error))?;

    // The active carrier remains paused until this future has either closed the
    // candidate and consumed the retained response, or returned an error.  The
    // final resume below therefore runs for every path, including mapping and
    // assertion failures.
    let outcome = async {
        let payload = record_payload(101);
        stream
            .send_record(&payload)
            .await
            .map_err(|error| stage_error("candidate-abort gap send", error))?;
        let _outstanding = wait_for_outstanding_record(OutstandingRecordWait {
            harness,
            handle,
            device_id,
            session_id,
            stream_id,
            active_generation,
            baseline_last_emitted,
            budget,
        })
        .await
        .map_err(|error| stage_error("candidate-abort outstanding gap", error))?;
        let candidate = wait_for_precommit_candidate(PrecommitCandidateWait {
            harness,
            handle,
            proxy,
            device_id,
            session_id,
            epoch,
            active_generation,
            budget,
        })
        .await
        .map_err(|error| stage_error("candidate-abort candidate mapping", error))?;

        // Re-read both redacted actors immediately before the close.  The
        // outstanding request makes a successful drain impossible, while this
        // identity check prevents a stale proxy source mapping from being
        // applied to a later attempt.
        let client = handle.status_snapshot();
        let relay_snapshot = harness.production_snapshot().await?;
        let relay = relay_snapshot
            .sessions
            .iter()
            .find(|session| session.device_id == device_id.to_string())
            .ok_or_else(|| {
                HarnessError::Process(
                    "M2 candidate gate lost the relay session before close".to_owned(),
                )
            })?;
        if client.session_id.as_deref() != Some(session_id)
            || client.epoch != Some(epoch)
            || client.active_generation != Some(active_generation)
            || client.candidate_generation != Some(candidate.generation)
            || client.candidate_connection_id.as_deref()
                != Some(candidate.connection_id.as_str())
            || !is_candidate_precommit_phase(&client.phase)
            || relay.session_id != session_id
            || relay.epoch != epoch
            || relay.active_generation != active_generation
            || relay.candidate_generation != Some(candidate.generation)
            || relay.candidate_connection_id.as_deref() != Some(candidate.connection_id.as_str())
            || !is_candidate_precommit_phase(&relay.phase)
        {
            return Err(HarnessError::Process(format!(
                "M2 candidate gate lost precommit identity before close: client_phase={}, client_generation={:?}, client_candidate={:?}, relay_phase={}, relay_generation={}, relay_candidate={:?}",
                client.phase,
                client.active_generation,
                client.candidate_generation,
                relay.phase,
                relay.active_generation,
                relay.candidate_generation,
            )));
        }

        proxy
            .close(candidate.proxy_id)
            .await
            .map_err(|error| HarnessError::Proxy(format!("closing rotation candidate: {error}")))
            .map_err(|error| stage_error("candidate-abort close", error))?;

        // Do not release the retained request until the relay has observed
        // the physical candidate close and entered its owner-decided abort.
        // Otherwise a queued drain ACK could race the disconnect event and
        // make the replacement look committed before ABORT is recorded.
        wait_for_candidate_abort_decision(CandidateAbortDecisionWait {
            harness,
            handle,
            device_id,
            session_id,
            epoch,
            active_generation,
            candidate_generation: candidate.generation,
            budget,
        })
        .await
        .map_err(|error| stage_error("candidate-abort owner decision", error))?;

        // Resuming the old carrier releases the deliberately retained request
        // after the candidate close.  Its response is the one application
        // effect that proves the stream survived the abort.
        proxy
            .resume(Direction::TargetToClient, active_id)
            .await
            .map_err(|error| HarnessError::Proxy(format!("resuming active data carrier: {error}")))
            .map_err(|error| stage_error("candidate-abort resume", error))?;
        let response = stream
            .receive_response()
            .await
            .map_err(|error| stage_error("candidate-abort retained response", error))?;
        stream
            .validate_response(&response, canary, &payload)
            .map_err(|error| stage_error("candidate-abort retained response validation", error))?;
        match timeout(Duration::from_millis(500), stream.receive_response()).await {
            Err(_) => {}
            Ok(Ok(_)) => {
                return Err(HarnessError::Process(
                    "M2 candidate abort emitted a duplicate response record".to_owned(),
                ));
            }
            Ok(Err(error)) => {
                return Err(stage_error("candidate-abort duplicate probe", error));
            }
        }

        wait_for_candidate_abort_completion(CandidateAbortCompletion {
            harness,
            handle,
            device_id,
            session_id,
            epoch,
            active_generation,
            stream_id,
            budget,
        })
        .await
        .map_err(|error| stage_error("candidate-abort completion", error))
    }
    .await;

    let resume = proxy.resume(Direction::TargetToClient, active_id).await;
    match (outcome, resume) {
        (Ok(snapshot), Ok(())) => Ok(snapshot),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(stage_error(
            "candidate-abort cleanup resume",
            HarnessError::Proxy(format!("resuming active data carrier: {error}")),
        )),
        (Err(error), Err(resume_error)) => Err(HarnessError::Process(format!(
            "{error}; M2 candidate-abort cleanup resume failed: {resume_error}"
        ))),
    }
}

async fn wait_for_outstanding_record(context: OutstandingRecordWait<'_>) -> Result<StreamSnapshot> {
    let OutstandingRecordWait {
        harness,
        handle,
        device_id,
        session_id,
        stream_id,
        active_generation,
        baseline_last_emitted,
        budget,
    } = context;
    let started = Instant::now();
    loop {
        let snapshot = wait_for_stream_snapshot(
            harness,
            handle,
            device_id,
            session_id,
            Some(stream_id),
            SNAPSHOT_POLL,
        )
        .await;
        match snapshot {
            Ok(snapshot)
                if snapshot.relay.active_generation == active_generation
                    && snapshot.stream.last_emitted_relay_to_connector > baseline_last_emitted
                    && snapshot.stream.last_emitted_relay_to_connector
                        > snapshot.stream.peer_acked_relay_to_connector =>
            {
                return Ok(snapshot);
            }
            Ok(_) | Err(HarnessError::Timeout(_)) => {}
            Err(error) => return Err(error),
        }
        if started.elapsed() >= budget {
            return Err(HarnessError::Timeout(format!(
                "M2 candidate-abort record did not become outstanding within {budget:?}"
            )));
        }
        sleep(SNAPSHOT_POLL).await;
    }
}

async fn wait_for_precommit_candidate(
    context: PrecommitCandidateWait<'_>,
) -> Result<CandidateGate> {
    let PrecommitCandidateWait {
        harness,
        handle,
        proxy,
        device_id,
        session_id,
        epoch,
        active_generation,
        budget,
    } = context;
    let started = Instant::now();
    loop {
        let latest_client = handle.status_snapshot();
        if matches!(latest_client.phase.as_str(), "closed" | "failed") {
            return Err(HarnessError::Process(format!(
                "M2 client reached {} before a deterministic candidate gate: candidate={:?}, local_addr={:?}",
                latest_client.phase,
                latest_client.candidate_generation,
                latest_client.candidate_local_addr,
            )));
        }
        let relay_snapshot = harness.production_snapshot().await?;
        let relay = relay_snapshot
            .sessions
            .iter()
            .find(|session| session.device_id == device_id.to_string());
        let Some(relay) = relay else {
            if started.elapsed() >= budget {
                return Err(HarnessError::Timeout(
                    "M2 relay session disappeared before candidate gate".to_owned(),
                ));
            }
            sleep(SNAPSHOT_POLL).await;
            continue;
        };
        if latest_client.session_id.as_deref() != Some(session_id)
            || latest_client.epoch != Some(epoch)
            || latest_client.active_generation != Some(active_generation)
            || relay.session_id != session_id
            || relay.epoch != epoch
            || relay.active_generation != active_generation
        {
            return Err(HarnessError::Process(format!(
                "M2 candidate gate identity changed: client_session={:?}, client_epoch={:?}, client_active={:?}, relay_session={}, relay_epoch={}, relay_active={}",
                latest_client.session_id,
                latest_client.epoch,
                latest_client.active_generation,
                relay.session_id,
                relay.epoch,
                relay.active_generation,
            )));
        }
        let Some(generation) = latest_client.candidate_generation else {
            if started.elapsed() >= budget {
                return Err(HarnessError::Timeout(format!(
                    "M2 candidate did not appear before gate deadline; client_phase={}, relay_phase={}",
                    latest_client.phase, relay.phase
                )));
            }
            sleep(SNAPSHOT_POLL).await;
            continue;
        };
        let Some(local_addr) = latest_client.candidate_local_addr else {
            // CandidateOpened can publish its generation before the local
            // address is available to the status watcher.  Keep waiting for
            // the exact source mapping instead of treating that transient as
            // an unsupported diagnostic surface.
            if started.elapsed() >= budget {
                return Err(HarnessError::Timeout(format!(
                    "M2 candidate local address stayed pending; generation={generation}, client_phase={}, relay_phase={}",
                    latest_client.phase, relay.phase
                )));
            }
            sleep(SNAPSHOT_POLL).await;
            continue;
        };
        let Some(connection_id) = latest_client.candidate_connection_id.clone() else {
            return Err(HarnessError::Process(
                "M2 candidate generation was published without its connection ID".to_owned(),
            ));
        };
        if relay.candidate_generation != Some(generation)
            || relay.candidate_connection_id.as_deref() != Some(connection_id.as_str())
        {
            if started.elapsed() >= budget {
                return Err(HarnessError::Timeout(format!(
                    "M2 client/relay candidate identities did not converge: client=({generation},{connection_id}), relay=({:?},{:?})",
                    relay.candidate_generation, relay.candidate_connection_id
                )));
            }
            sleep(SNAPSHOT_POLL).await;
            continue;
        }
        if !is_candidate_precommit_phase(&latest_client.phase)
            || !is_candidate_precommit_phase(&relay.phase)
        {
            return Err(HarnessError::Process(format!(
                "M2 candidate reached a non-precommit phase before fault close: client_phase={}, relay_phase={}, generation={generation}, connection_id={connection_id}",
                latest_client.phase, relay.phase
            )));
        }
        let matches = proxy
            .connections()
            .into_iter()
            .filter(|connection| connection.source_addr == local_addr)
            .map(|connection| connection.id)
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [proxy_id] => {
                return Ok(CandidateGate {
                    proxy_id: *proxy_id,
                    generation,
                    connection_id,
                });
            }
            [_first, _second, ..] => {
                return Err(HarnessError::Process(format!(
                    "M2 proxy mapped more than one candidate connection to connector source {local_addr}"
                )));
            }
            [] => {}
        }
        if started.elapsed() >= budget {
            return Err(HarnessError::Timeout(format!(
                "M2 candidate source mapping did not appear: generation={generation}, connection_id={connection_id}, local_addr={local_addr}, client_phase={}, relay_phase={}",
                latest_client.phase, relay.phase
            )));
        }
        sleep(SNAPSHOT_POLL).await;
    }
}

async fn wait_for_candidate_abort_completion(
    context: CandidateAbortCompletion<'_>,
) -> Result<StreamSnapshot> {
    let CandidateAbortCompletion {
        harness,
        handle,
        device_id,
        session_id,
        epoch,
        active_generation,
        stream_id,
        budget,
    } = context;
    let started = Instant::now();
    loop {
        let snapshot = wait_for_stream_snapshot(
            harness,
            handle,
            device_id,
            session_id,
            Some(stream_id),
            SNAPSHOT_POLL,
        )
        .await;
        match snapshot {
            Ok(snapshot)
                if snapshot.client.session_id.as_deref() == Some(session_id)
                    && snapshot.client.epoch == Some(epoch)
                    && snapshot.client.phase == "active"
                    && snapshot.client.active_generation == Some(active_generation)
                    && snapshot.client.candidate_generation.is_none()
                    && snapshot.relay.session_id == session_id
                    && snapshot.relay.epoch == epoch
                    && snapshot.relay.phase == "active"
                    && snapshot.relay.active_generation == active_generation
                    && snapshot.relay.candidate_generation.is_none()
                    && snapshot.relay.sockets <= 2
                    && snapshot.relay.replay_frames == 0
                    && snapshot.relay.replay_bytes == 0
                    && snapshot.stream.replay_frames_relay_to_connector == 0
                    && snapshot.stream.replay_bytes_relay_to_connector == 0
                    && snapshot.client.replay_frames == 0
                    && snapshot.client.replay_bytes == 0 =>
            {
                return Ok(snapshot);
            }
            Ok(_) | Err(HarnessError::Timeout(_)) => {}
            Err(error) => return Err(error),
        }
        if started.elapsed() >= budget {
            return Err(HarnessError::Timeout(
                "M2 candidate abort did not converge to bilateral active/no-candidate state"
                    .to_owned(),
            ));
        }
        sleep(SNAPSHOT_POLL).await;
    }
}

async fn wait_for_candidate_abort_decision(context: CandidateAbortDecisionWait<'_>) -> Result<()> {
    let CandidateAbortDecisionWait {
        harness,
        handle,
        device_id,
        session_id,
        epoch,
        active_generation,
        candidate_generation,
        budget,
    } = context;
    let started = Instant::now();
    loop {
        let client = handle.status_snapshot();
        if client.session_id.as_deref() != Some(session_id)
            || client.epoch != Some(epoch)
            || client.active_generation != Some(active_generation)
        {
            return Err(HarnessError::Process(format!(
                "M2 candidate abort changed client identity before owner decision: phase={}, session={:?}, epoch={:?}, active={:?}",
                client.phase, client.session_id, client.epoch, client.active_generation
            )));
        }
        if matches!(client.phase.as_str(), "closed" | "failed") {
            return Err(HarnessError::Process(format!(
                "M2 candidate abort terminated the client before owner decision: phase={}",
                client.phase
            )));
        }
        let relay_snapshot = harness.production_snapshot().await?;
        let relay = relay_snapshot
            .sessions
            .iter()
            .find(|session| session.device_id == device_id.to_string())
            .ok_or_else(|| {
                HarnessError::Process(
                    "M2 relay session disappeared before candidate abort decision".to_owned(),
                )
            })?;
        if relay.session_id != session_id
            || relay.epoch != epoch
            || relay.active_generation != active_generation
        {
            return Err(HarnessError::Process(format!(
                "M2 candidate abort changed relay identity before owner decision: phase={}, session={}, epoch={}, active={}",
                relay.phase, relay.session_id, relay.epoch, relay.active_generation
            )));
        }
        if client.phase == "aborting" || relay.phase == "aborting" {
            return Ok(());
        }
        if relay.phase == "active"
            && relay.candidate_generation.is_none()
            && client.phase == "active"
            && client.candidate_generation.is_none()
        {
            return Ok(());
        }
        if !is_candidate_precommit_phase(&relay.phase) {
            return Err(HarnessError::Process(format!(
                "M2 candidate close did not produce an owner abort: relay_phase={}, client_phase={}, candidate_generation={:?}, expected_candidate_generation={candidate_generation}",
                relay.phase, client.phase, relay.candidate_generation
            )));
        }
        if started.elapsed() >= budget {
            return Err(HarnessError::Timeout(
                "M2 owner abort decision was not observable before the bounded gate deadline"
                    .to_owned(),
            ));
        }
        sleep(SNAPSHOT_POLL).await;
    }
}

async fn wait_for_client_closed(handle: &ConnectionHandle, budget: Duration) -> Result<()> {
    let started = Instant::now();
    loop {
        let status = handle.status_snapshot();
        if matches!(status.phase.as_str(), "closed" | "failed") {
            return Ok(());
        }
        if started.elapsed() >= budget {
            return Err(HarnessError::Timeout(
                "M2 control loss did not produce an explicit client interruption".to_owned(),
            ));
        }
        sleep(SNAPSHOT_POLL).await;
    }
}

fn assert_expected_control_loss(
    stop_result: std::result::Result<(), ClientError>,
    readiness: &Readiness,
) -> Result<()> {
    match stop_result {
        Err(ClientError::Transport {
            scope: "control read",
            ..
        }) => {}
        Err(error) => {
            return Err(HarnessError::Process(format!(
                "M2 control-loss shutdown returned an unexpected client error: {error}"
            )));
        }
        Ok(()) => {
            return Err(HarnessError::Process(
                "M2 control-loss shutdown completed cleanly after the control socket was closed"
                    .to_owned(),
            ));
        }
    }
    match readiness {
        Readiness::Closed { reason } if reason == "control read failed" => Ok(()),
        Readiness::Closed { reason } => Err(HarnessError::Process(format!(
            "M2 control-loss shutdown had an unexpected terminal readiness reason: {reason}"
        ))),
        other => Err(HarnessError::Process(format!(
            "M2 control-loss shutdown did not publish a closed readiness state: {other:?}"
        ))),
    }
}

async fn wait_for_session_absent(
    harness: &RunningHarness,
    device_id: Uuid,
    budget: Duration,
) -> Result<()> {
    let started = Instant::now();
    loop {
        let snapshot = harness.production_snapshot().await?;
        if !snapshot
            .sessions
            .iter()
            .any(|session| session.device_id == device_id.to_string())
        {
            return Ok(());
        }
        if started.elapsed() >= budget {
            return Err(HarnessError::Timeout(
                "M2 relay retained the control-loss session past its cleanup deadline".to_owned(),
            ));
        }
        sleep(SNAPSHOT_POLL).await;
    }
}

async fn wait_for_proxy_idle(proxy: &ProxyHandle, budget: Duration) -> Result<()> {
    let started = Instant::now();
    loop {
        let stats = proxy.stats();
        if stats.active == 0 && proxy.connections().is_empty() {
            return Ok(());
        }
        if started.elapsed() >= budget {
            return Err(HarnessError::Timeout(format!(
                "M2 proxy retained {} active sockets after session cleanup",
                stats.active
            )));
        }
        sleep(SNAPSHOT_POLL).await;
    }
}

#[derive(Default)]
struct RotationEvidence {
    session_id: Option<String>,
    epoch: Option<u64>,
    operation_id: Option<String>,
    stream_id: Option<u64>,
    generations: BTreeSet<u64>,
    connections: BTreeSet<String>,
    last_emitted: u64,
    peer_acked: u64,
    recv_contiguous: u64,
    delivered_contiguous: u64,
}

impl RotationEvidence {
    fn observe(
        &mut self,
        snapshot: &StreamSnapshot,
        expected_session_id: &str,
        stream: &ConsumerStream,
    ) -> Result<()> {
        let relay = &snapshot.relay;
        if relay.profile != "m2" {
            return Err(HarnessError::Process(format!(
                "relay selected profile {:?} for M2 connector",
                relay.profile
            )));
        }
        if relay.session_id != expected_session_id {
            return Err(HarnessError::Process(
                "client and relay session identity diverged during M2 stream".to_owned(),
            ));
        }
        if let Some(client_session_id) = snapshot.client.session_id.as_deref()
            && client_session_id != relay.session_id
        {
            return Err(HarnessError::Process(
                "client and relay session IDs diverged during M2 stream".to_owned(),
            ));
        }
        if let Some(client_epoch) = snapshot.client.epoch
            && client_epoch != relay.epoch
        {
            return Err(HarnessError::Process(
                "client and relay epochs diverged during M2 stream".to_owned(),
            ));
        }
        if relay.sockets > 3 {
            return Err(HarnessError::Process(format!(
                "M2 relay exposed {} sockets; maximum temporary bound is three",
                relay.sockets
            )));
        }
        if snapshot.client.streams != 1 || relay.streams.len() != 1 {
            return Err(HarnessError::Process(format!(
                "M2 expected exactly one logical stream (client={}, relay={})",
                snapshot.client.streams,
                relay.streams.len()
            )));
        }
        // A rotation can briefly retain an unacknowledged frame while the
        // bilateral drain proof is being exchanged.  `wait_for_quiet_snapshot`
        // asserts that these transient counters settle before a clean record
        // boundary is accepted; the cumulative replay counter is forbidden
        // throughout the clean run.
        if relay.total_replayed_frames != 0 {
            return Err(HarnessError::Process(
                "clean M2 stream reported a replayed frame".to_owned(),
            ));
        }
        if let Some(previous) = self.session_id.as_deref()
            && previous != relay.session_id
        {
            return Err(HarnessError::Process(
                "M2 session ID changed across a data rotation".to_owned(),
            ));
        }
        if let Some(previous) = self.epoch
            && previous != relay.epoch
        {
            return Err(HarnessError::Process(
                "M2 epoch changed across a data rotation".to_owned(),
            ));
        }
        if let Some(previous) = self.operation_id.as_deref()
            && previous != snapshot.stream.operation_id
        {
            return Err(HarnessError::Process(
                "M2 operation ID changed across a data rotation".to_owned(),
            ));
        }
        if let Some(previous) = self.stream_id
            && previous != snapshot.stream.stream_id
        {
            return Err(HarnessError::Process(
                "M2 stream ID changed across a data rotation".to_owned(),
            ));
        }
        if stream.stream_id_hint() != Some(snapshot.stream.stream_id) {
            return Err(HarnessError::Process(
                "consumer stream and relay stream IDs diverged".to_owned(),
            ));
        }
        if relay.active_generation < self.generations.last().copied().unwrap_or(0) {
            return Err(HarnessError::Process(
                "M2 active generation moved backwards".to_owned(),
            ));
        }
        if snapshot.stream.last_emitted_relay_to_connector < self.last_emitted
            || snapshot.stream.peer_acked_relay_to_connector < self.peer_acked
            || snapshot.stream.recv_contiguous_connector_to_relay < self.recv_contiguous
            || snapshot.stream.delivered_contiguous_connector_to_relay < self.delivered_contiguous
        {
            return Err(HarnessError::Process(
                "M2 stream sequence counters moved backwards".to_owned(),
            ));
        }
        if let Some(candidate) = relay.candidate_generation
            && candidate <= relay.active_generation
        {
            return Err(HarnessError::Process(
                "M2 candidate generation did not advance beyond active generation".to_owned(),
            ));
        }
        if relay.active_connection_id.is_empty() {
            return Err(HarnessError::Process(
                "M2 relay snapshot omitted the active connection ID".to_owned(),
            ));
        }

        self.session_id = Some(relay.session_id.clone());
        self.epoch = Some(relay.epoch);
        self.operation_id = Some(snapshot.stream.operation_id.clone());
        self.stream_id = Some(snapshot.stream.stream_id);
        self.generations.insert(relay.active_generation);
        self.connections.insert(relay.active_connection_id.clone());
        self.last_emitted = snapshot.stream.last_emitted_relay_to_connector;
        self.peer_acked = snapshot.stream.peer_acked_relay_to_connector;
        self.recv_contiguous = snapshot.stream.recv_contiguous_connector_to_relay;
        self.delivered_contiguous = snapshot.stream.delivered_contiguous_connector_to_relay;
        Ok(())
    }
}

struct StreamSnapshot {
    client: ConnectionStatus,
    relay: RelaySessionSnapshot,
    stream: RelayStreamSnapshot,
}

async fn wait_for_stream_snapshot(
    harness: &RunningHarness,
    handle: &ConnectionHandle,
    device_id: Uuid,
    session_id: &str,
    stream_id_hint: Option<u64>,
    budget: Duration,
) -> Result<StreamSnapshot> {
    let started = Instant::now();
    loop {
        let client = handle.status_snapshot();
        let relay_snapshot = harness.production_snapshot().await?;
        if let Some(session) = relay_snapshot
            .sessions
            .iter()
            .find(|candidate| candidate.device_id == device_id.to_string())
            && session.session_id == session_id
        {
            let stream = match stream_id_hint {
                Some(id) => session.streams.iter().find(|stream| stream.stream_id == id),
                None if session.streams.len() == 1 => session.streams.first(),
                None => None,
            };
            if let Some(stream) = stream {
                return Ok(StreamSnapshot {
                    client,
                    relay: session.clone(),
                    stream: stream.clone(),
                });
            }
        }
        if matches!(client.phase.as_str(), "closed" | "failed") {
            return Err(HarnessError::Process(
                "M2 connector reached a terminal phase before the public stream appeared"
                    .to_owned(),
            ));
        }
        if started.elapsed() >= budget {
            return Err(HarnessError::Timeout(
                "M2 relay snapshot did not expose the public stream before its deadline".to_owned(),
            ));
        }
        sleep(SNAPSHOT_POLL).await;
    }
}

async fn wait_for_quiet_snapshot(
    harness: &RunningHarness,
    handle: &ConnectionHandle,
    device_id: Uuid,
    session_id: &str,
    stream_id_hint: Option<u64>,
    budget: Duration,
    require_no_replay_total: bool,
) -> Result<StreamSnapshot> {
    let started = Instant::now();
    loop {
        let snapshot = wait_for_stream_snapshot(
            harness,
            handle,
            device_id,
            session_id,
            stream_id_hint,
            SNAPSHOT_POLL,
        )
        .await?;
        let quiet = snapshot.relay.replay_frames == 0
            && snapshot.relay.replay_bytes == 0
            && snapshot.stream.replay_frames_relay_to_connector == 0
            && snapshot.stream.replay_bytes_relay_to_connector == 0
            && snapshot.client.replay_frames == 0
            && snapshot.client.replay_bytes == 0;
        if quiet && (!require_no_replay_total || snapshot.relay.total_replayed_frames == 0) {
            return Ok(snapshot);
        }
        if started.elapsed() >= budget {
            return Err(HarnessError::Timeout(
                "M2 stream replay counters did not settle before the bounded quiet deadline"
                    .to_owned(),
            ));
        }
        sleep(SNAPSHOT_POLL).await;
    }
}

fn record_payload(index: u64) -> Vec<u8> {
    format!("m2-record-{index:04}-{}", Uuid::new_v4()).into_bytes()
}

struct ConsumerStream {
    socket: ConsumerSocket,
    stream_id: Option<u64>,
    peer_close_received: bool,
}

impl ConsumerStream {
    fn stream_id_hint(&self) -> Option<u64> {
        self.stream_id
    }

    fn set_stream_id(&mut self, stream_id: u64) {
        self.stream_id = Some(stream_id);
    }

    async fn round_trip(&mut self, payload: &[u8], canary: &[u8]) -> Result<()> {
        self.send_record(payload).await?;
        let response = self.receive_response().await?;
        self.validate_response(&response, canary, payload)
    }

    async fn send_record(&mut self, payload: &[u8]) -> Result<()> {
        if payload.len() > MAX_RECORD_BYTES {
            return Err(HarnessError::InvalidInput(
                "M2 request record exceeds the 64 KiB bound".to_owned(),
            ));
        }
        let frame_len = u32::try_from(payload.len()).map_err(|_| {
            HarnessError::InvalidInput("M2 request length does not fit a u32".to_owned())
        })?;
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&frame_len.to_be_bytes());
        frame.extend_from_slice(payload);
        self.send_bytes(&frame).await
    }

    async fn send_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.socket
            .send(Message::Binary(bytes.to_vec().into()))
            .await
            .map_err(|error| HarnessError::Http(format!("sending M2 echo record: {error}")))?;
        Ok(())
    }

    async fn receive_response(&mut self) -> Result<Vec<u8>> {
        let bytes = timeout(Duration::from_secs(30), async {
            loop {
                match self.socket.next().await {
                    Some(Ok(Message::Binary(bytes))) => break Ok(bytes.to_vec()),
                    Some(Ok(Message::Ping(bytes))) => {
                        self.socket
                            .send(Message::Pong(bytes))
                            .await
                            .map_err(|error| {
                                HarnessError::Http(format!("replying to M2 ping: {error}"))
                            })?;
                    }
                    Some(Ok(Message::Close(_))) => {
                        self.peer_close_received = true;
                        break Err(HarnessError::Http(
                            "M2 consumer stream closed before its echo response".to_owned(),
                        ));
                    }
                    None => {
                        break Err(HarnessError::Http(
                            "M2 consumer stream closed before its echo response".to_owned(),
                        ));
                    }
                    Some(Ok(Message::Text(_))) => {
                        break Err(HarnessError::Http(
                            "M2 consumer stream returned a text message".to_owned(),
                        ));
                    }
                    Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
                    Some(Err(error)) => {
                        break Err(HarnessError::Http(format!(
                            "reading M2 echo record: {error}"
                        )));
                    }
                }
            }
        })
        .await
        .map_err(|_| HarnessError::Timeout("M2 echo record response timed out".to_owned()))??;
        Ok(bytes)
    }

    /// Return true when an unsolicited binary record arrives within `window`.
    /// Every request has already received exactly one validated response, so
    /// any further record is a duplicate adapter delivery or a replay.  The
    /// window is bounded; silence is the expected outcome.
    async fn observe_stray_response(&mut self, window: Duration) -> Result<bool> {
        let deadline = Instant::now() + window;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            match timeout(remaining, self.socket.next()).await {
                Err(_) => return Ok(false),
                Ok(Some(Ok(Message::Binary(_)))) => return Ok(true),
                Ok(Some(Ok(Message::Ping(bytes)))) => {
                    self.socket
                        .send(Message::Pong(bytes))
                        .await
                        .map_err(|error| {
                            HarnessError::Http(format!("replying to M2 ping: {error}"))
                        })?;
                }
                Ok(Some(Ok(Message::Pong(_)))) | Ok(Some(Ok(Message::Frame(_)))) => {}
                Ok(Some(Ok(Message::Text(_)))) => {
                    return Err(HarnessError::Http(
                        "M2 consumer stream returned a text message".to_owned(),
                    ));
                }
                Ok(Some(Ok(Message::Close(_)))) => {
                    self.peer_close_received = true;
                    return Err(HarnessError::Http(
                        "M2 consumer stream closed while checking for stray responses".to_owned(),
                    ));
                }
                Ok(None) => {
                    return Err(HarnessError::Http(
                        "M2 consumer stream ended while checking for stray responses".to_owned(),
                    ));
                }
                Ok(Some(Err(error))) => {
                    return Err(HarnessError::Http(format!(
                        "reading M2 stray-response window: {error}"
                    )));
                }
            }
        }
    }

    fn validate_response(&self, response: &[u8], canary: &[u8], payload: &[u8]) -> Result<()> {
        if canary.len() > MAX_CANARY_BYTES {
            return Err(HarnessError::InvalidInput(
                "M2 response canary exceeds the 256-byte bound".to_owned(),
            ));
        }
        if response.len() < 4 {
            return Err(HarnessError::Http(
                "M2 echo response omitted its length prefix".to_owned(),
            ));
        }
        let declared =
            u32::from_be_bytes([response[0], response[1], response[2], response[3]]) as usize;
        if declared != response.len() - 4
            || declared < canary.len()
            || declared > MAX_RECORD_BYTES + MAX_CANARY_BYTES
        {
            return Err(HarnessError::Http(
                "M2 echo response length violated the record bounds".to_owned(),
            ));
        }
        if response[4..4 + canary.len()] != *canary || response[4 + canary.len()..] != *payload {
            return Err(HarnessError::Http(
                "M2 echo response canary or payload did not match exactly".to_owned(),
            ));
        }
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        if self.peer_close_received {
            return match timeout(Duration::from_secs(5), self.socket.flush()).await {
                Err(_) => Err(HarnessError::Timeout(
                    "M2 consumer close acknowledgement flush timed out".to_owned(),
                )),
                Ok(Ok(()))
                | Ok(Err(
                    tokio_tungstenite::tungstenite::Error::AlreadyClosed
                    | tokio_tungstenite::tungstenite::Error::ConnectionClosed,
                )) => Ok(()),
                Ok(Err(tokio_tungstenite::tungstenite::Error::Io(error)))
                    if matches!(
                        error.kind(),
                        ErrorKind::UnexpectedEof
                            | ErrorKind::BrokenPipe
                            | ErrorKind::ConnectionReset
                            | ErrorKind::ConnectionAborted
                            | ErrorKind::NotConnected
                    ) =>
                {
                    Ok(())
                }
                Ok(Err(error)) => Err(HarnessError::Http(format!(
                    "flushing M2 consumer close acknowledgement: {error}"
                ))),
            };
        }
        match timeout(
            Duration::from_secs(5),
            self.socket.send(Message::Close(None)),
        )
        .await
        {
            Err(_) => {
                return Err(HarnessError::Timeout(
                    "M2 consumer close handshake send timed out".to_owned(),
                ));
            }
            Ok(Err(
                tokio_tungstenite::tungstenite::Error::AlreadyClosed
                | tokio_tungstenite::tungstenite::Error::ConnectionClosed,
            )) => {
                return Ok(());
            }
            Ok(Err(error)) => {
                return Err(HarnessError::Http(format!(
                    "sending M2 consumer close frame: {error}"
                )));
            }
            Ok(Ok(())) => {}
        }
        timeout(Duration::from_secs(5), async {
            loop {
                match self.socket.next().await {
                    Some(Ok(Message::Close(_))) => {
                        self.peer_close_received = true;
                        return Ok(());
                    }
                    None => {
                        return Err(HarnessError::Http(
                            "M2 consumer close handshake ended before peer close".to_owned(),
                        ));
                    }
                    Some(Ok(Message::Ping(bytes))) => self
                        .socket
                        .send(Message::Pong(bytes))
                        .await
                        .map_err(|error| {
                            HarnessError::Http(format!(
                                "replying to M2 close-handshake ping: {error}"
                            ))
                        })?,
                    Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
                    Some(Ok(Message::Binary(_))) | Some(Ok(Message::Text(_))) => {}
                    Some(Err(
                        tokio_tungstenite::tungstenite::Error::AlreadyClosed
                        | tokio_tungstenite::tungstenite::Error::ConnectionClosed,
                    )) => {
                        return Err(HarnessError::Http(
                            "M2 consumer close handshake ended before peer close".to_owned(),
                        ));
                    }
                    Some(Err(error)) => {
                        return Err(HarnessError::Http(format!(
                            "reading M2 consumer close handshake: {error}"
                        )));
                    }
                }
            }
        })
        .await
        .map_err(|_| HarnessError::Timeout("M2 consumer close handshake timed out".to_owned()))?
    }
}

fn encode_record(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > MAX_RECORD_BYTES {
        return Err(HarnessError::InvalidInput(
            "M2 request record exceeds the 64 KiB bound".to_owned(),
        ));
    }
    let length = u32::try_from(payload.len()).map_err(|_| {
        HarnessError::InvalidInput("M2 request length does not fit a u32".to_owned())
    })?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

async fn verify_record_framing(stream: &mut ConsumerStream, canary: &[u8]) -> Result<()> {
    // Empty records are valid and must still produce the canary-prefixed
    // response record.
    stream
        .send_bytes(&[0, 0, 0, 0])
        .await
        .map_err(|error| stage_error("framing empty send", error))?;
    receive_and_validate_framing(stream, canary, &[], "empty").await?;

    // Exercise the inclusive 64 KiB request boundary repeatedly.  Three
    // sequential records prove that application credit is replenished over
    // the stream rather than only accepting the initial window.
    let maximum = vec![0xA5; MAX_RECORD_BYTES];
    for index in 0..3_u8 {
        stream
            .round_trip(&maximum, canary)
            .await
            .map_err(|error| stage_error(&format!("framing maximum record {index}"), error))?;
    }

    // Two records in one consumer WebSocket message must be coalesced by the
    // client parser and returned as two ordered responses.
    let first = b"coalesced-one";
    let second = b"coalesced-two";
    let mut combined = encode_record(first)?;
    combined.extend_from_slice(&encode_record(second)?);
    stream
        .send_bytes(&combined)
        .await
        .map_err(|error| stage_error("framing coalesced send", error))?;
    receive_and_validate_framing(stream, canary, first, "coalesced first").await?;
    receive_and_validate_framing(stream, canary, second, "coalesced second").await?;

    // Split the four-byte length prefix and body across separate consumer
    // WebSocket messages; transport message boundaries must not reset the
    // application record parser.
    let split = encode_record(b"split-record")?;
    stream
        .send_bytes(&split[..2])
        .await
        .map_err(|error| stage_error("framing split header", error))?;
    stream
        .send_bytes(&split[2..])
        .await
        .map_err(|error| stage_error("framing split body", error))?;
    receive_and_validate_framing(stream, canary, b"split-record", "split").await
}

async fn receive_and_validate_framing(
    stream: &mut ConsumerStream,
    canary: &[u8],
    payload: &[u8],
    stage: &str,
) -> Result<()> {
    let response = stream
        .receive_response()
        .await
        .map_err(|error| stage_error(&format!("framing {stage} receive"), error))?;
    stream
        .validate_response(&response, canary, payload)
        .map_err(|error| stage_error(&format!("framing {stage} validate"), error))
}

async fn verify_slow_consumer(
    harness: &RunningHarness,
    handle: &ConnectionHandle,
    stream: &mut ConsumerStream,
    device_id: Uuid,
    session_id: &str,
    canary: &[u8],
) -> Result<()> {
    // A finite producer budget leaves responses unread long enough to exercise
    // the bounded actor queues without turning this acceptance into a load
    // test.  Every payload is retained locally so the drain below proves that
    // no response was duplicated or silently dropped.
    let payloads = (0..16_u8)
        .map(|index| {
            let mut payload = vec![index; 1_024];
            payload.extend_from_slice(b"-slow-consumer");
            payload
        })
        .collect::<Vec<_>>();
    for (index, payload) in payloads.iter().enumerate() {
        stream
            .send_record(payload)
            .await
            .map_err(|error| stage_error(&format!("slow-consumer send {index}"), error))?;
    }
    sleep(Duration::from_millis(100)).await;
    let snapshot = wait_for_stream_snapshot(
        harness,
        handle,
        device_id,
        session_id,
        stream.stream_id_hint(),
        Duration::from_secs(10),
    )
    .await
    .map_err(|error| stage_error("slow-consumer snapshot", error))?;
    if snapshot.client.queue_bytes > CLIENT_QUEUE_LIMIT_BYTES
        || snapshot.client.queue_frames > CLIENT_QUEUE_LIMIT_FRAMES
        || snapshot.relay.queue_bytes > RELAY_QUEUE_LIMIT_BYTES
        || snapshot.relay.queue_messages > RELAY_QUEUE_LIMIT_MESSAGES
        || snapshot.stream.queue_bytes > RELAY_QUEUE_LIMIT_BYTES
    {
        return Err(HarnessError::Process(format!(
            "M2 slow-consumer queues exceeded bounds: client={} bytes/{} frames, relay={} bytes/{} messages, stream={} bytes",
            snapshot.client.queue_bytes,
            snapshot.client.queue_frames,
            snapshot.relay.queue_bytes,
            snapshot.relay.queue_messages,
            snapshot.stream.queue_bytes
        )));
    }
    for (index, payload) in payloads.iter().enumerate() {
        let response = stream
            .receive_response()
            .await
            .map_err(|error| stage_error(&format!("slow-consumer receive {index}"), error))?;
        stream
            .validate_response(&response, canary, payload)
            .map_err(|error| stage_error(&format!("slow-consumer validate {index}"), error))?;
    }
    Ok(())
}

async fn open_consumer_stream(
    consumer_addr: std::net::SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
) -> std::result::Result<ConsumerStream, ConnectFailure> {
    let tls = consumer_tls(server_ca_der).map_err(ConnectFailure::Harness)?;
    let url = format!(
        "wss://localhost:{}/v1/devices/{device_id}/services/{service_id}/stream",
        consumer_addr.port()
    );
    let mut request = url.into_client_request().map_err(|error| {
        ConnectFailure::Harness(HarnessError::Http(format!(
            "building M2 consumer WebSocket request: {error}"
        )))
    })?;
    request.headers_mut().insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).map_err(|error| {
            ConnectFailure::Harness(HarnessError::Http(format!(
                "building M2 consumer authorization header: {error}"
            )))
        })?,
    );
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(ECHO_SUBPROTOCOL),
    );
    let result = timeout(
        Duration::from_secs(30),
        connect_async_tls_with_config(request, None, true, Some(Connector::Rustls(tls))),
    )
    .await
    .map_err(|_| {
        ConnectFailure::Harness(HarnessError::Timeout(
            "M2 consumer WebSocket handshake timed out".to_owned(),
        ))
    })?;
    match result {
        Ok((socket, response)) => {
            let selected = response
                .headers()
                .get("sec-websocket-protocol")
                .and_then(|value| value.to_str().ok());
            if selected != Some(ECHO_SUBPROTOCOL) {
                return Err(ConnectFailure::Harness(HarnessError::Http(
                    "M2 consumer WebSocket did not select agent-tunnel.echo.v1".to_owned(),
                )));
            }
            Ok(ConsumerStream {
                socket,
                stream_id: None,
                peer_close_received: false,
            })
        }
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            Err(ConnectFailure::Status(response.status().as_u16()))
        }
        Err(error) => Err(ConnectFailure::Harness(HarnessError::Http(format!(
            "M2 consumer WebSocket handshake failed: {error}"
        )))),
    }
}

fn consumer_tls(server_ca_der: &[u8]) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(server_ca_der.to_vec()))
        .map_err(|error| HarnessError::Pki(format!("adding relay server CA: {error}")))?;
    ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| HarnessError::Pki(format!("configuring consumer TLS: {error}")))
        .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
        .map(Arc::new)
        .map_err(|error| HarnessError::Pki(format!("building consumer TLS: {error}")))
}

enum ConnectFailure {
    Status(u16),
    Harness(HarnessError),
}

fn connect_failure_to_harness(error: ConnectFailure) -> HarnessError {
    match error {
        ConnectFailure::Status(status) => HarnessError::Http(format!(
            "authorized M2 consumer WebSocket was rejected with HTTP status {status}"
        )),
        ConnectFailure::Harness(error) => error,
    }
}

async fn verify_proxy_retirement(harness: &RunningHarness, rotations: u64) -> Result<()> {
    let Some(proxy) = harness.proxy.as_ref() else {
        return Err(HarnessError::InvalidInput(
            "M2 harness proxy was not retained for retirement evidence".to_owned(),
        ));
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let stats = proxy.stats();
        if stats.active == 0 && stats.completed == stats.accepted {
            if stats.accepted < 2 + rotations {
                return Err(HarnessError::Process(format!(
                    "M2 proxy accepted {} sockets; expected control, initial data, and rotations",
                    stats.accepted
                )));
            }
            if proxy.diagnostics().peak_active > 3 {
                return Err(HarnessError::Process(format!(
                    "M2 proxy peak active sockets exceeded three: {}",
                    proxy.diagnostics().peak_active
                )));
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "M2 proxy did not close all retired sockets: active={}, completed={}, accepted={}",
                stats.active, stats.completed, stats.accepted
            )));
        }
        sleep(SNAPSHOT_POLL).await;
    }
}

async fn verify_consumer_rejections(
    harness: &RunningHarness,
    consumer_addr: std::net::SocketAddr,
    device_id: Uuid,
    service_id: Uuid,
    valid_token: &str,
) -> Result<()> {
    let expired = harness
        .oidc
        .issue_expired(&harness.topology.consumers_a[0].name)?;
    expect_consumer_status(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &expired,
        device_id,
        service_id,
        &[401],
        "expired M2 consumer token",
    )
    .await?;

    let insufficient_scope = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(1_200),
            scope: Some("files:read".to_owned()),
            ..OidcTokenOptions::default()
        },
    )?;
    expect_consumer_status(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &insufficient_scope,
        device_id,
        service_id,
        &[401],
        "insufficient-scope M2 consumer token",
    )
    .await?;

    let cross_tenant = harness.oidc.issue_with(
        &harness.topology.consumers_b[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(1_200),
            ..OidcTokenOptions::default()
        },
    )?;
    expect_consumer_status(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &cross_tenant,
        device_id,
        service_id,
        &[403, 404],
        "cross-tenant M2 consumer token",
    )
    .await?;

    let catalog = harness.production_catalog()?;
    catalog
        .revoke_grant(
            harness.topology.tenant_a.id,
            harness.topology.consumers_a[0].id,
            device_id,
            service_id,
            chrono::Utc::now(),
        )
        .await
        .map_err(|error| HarnessError::Redis(format!("revoking M2 echo grant: {error}")))?;
    expect_consumer_status(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        valid_token,
        device_id,
        service_id,
        &[403, 404],
        "revoked M2 consumer grant",
    )
    .await
}

async fn expect_consumer_status(
    consumer_addr: std::net::SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
    expected: &[u16],
    label: &str,
) -> Result<()> {
    match open_consumer_stream(consumer_addr, server_ca_der, token, device_id, service_id).await {
        Err(ConnectFailure::Status(status)) if expected.contains(&status) => Ok(()),
        Err(ConnectFailure::Status(status)) => Err(HarnessError::Http(format!(
            "{label} returned unexpected HTTP status {status}"
        ))),
        Err(ConnectFailure::Harness(error)) => Err(error),
        Ok(mut stream) => {
            stream.close().await?;
            Err(HarnessError::Process(format!(
                "{label} unexpectedly completed a WebSocket upgrade"
            )))
        }
    }
}

// The public route does not expose stream identifiers in an HTTP header.  The
// relay snapshot is authoritative; while the stream is first being admitted
// it is the only stream for this isolated device.  Once captured, all later
// calls pass the same identifier back through the redacted snapshot.
fn stream_id_hint(stream: &ConsumerStream) -> Option<u64> {
    stream.stream_id_hint()
}

#[cfg(test)]
mod c17_validator_tests {
    use super::assert_expected_control_loss;
    use crate::acceptance_test_support::assert_rejected;
    use tunnel_client::{ClientError, Readiness};

    fn control_read_loss() -> ClientError {
        ClientError::Transport {
            scope: "control read",
            detail: "control socket closed".to_owned(),
        }
    }

    fn closed(reason: &str) -> Readiness {
        Readiness::Closed {
            reason: reason.to_owned(),
        }
    }

    #[test]
    fn m2_control_loss_gate_accepts_the_exact_terminal_pair() {
        assert_expected_control_loss(Err(control_read_loss()), &closed("control read failed"))
            .expect("exact control-loss terminal pair passes");
    }

    #[test]
    fn m2_control_loss_gate_rejects_every_other_outcome_on_the_shared_exit_path() {
        assert_rejected(
            assert_expected_control_loss(Ok(()), &closed("control read failed")),
            "completed cleanly",
        );
        assert_rejected(
            assert_expected_control_loss(
                Err(ClientError::Transport {
                    scope: "data read",
                    detail: "data socket closed".to_owned(),
                }),
                &closed("control read failed"),
            ),
            "unexpected client error",
        );
        assert_rejected(
            assert_expected_control_loss(Err(control_read_loss()), &closed("cancelled")),
            "unexpected terminal readiness reason",
        );
        assert_rejected(
            assert_expected_control_loss(Err(control_read_loss()), &Readiness::Stopping),
            "did not publish a closed readiness state",
        );
    }
}
