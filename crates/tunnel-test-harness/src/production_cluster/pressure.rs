//! M7-I07 production resource pressure and cancellation gate.
//!
//! The scenario deliberately fills one real consumer stream while a second
//! stream remains available.  It records only bounded queue counters and the
//! relay's lifetime application-dispatch counter; it makes no claim about
//! desktop or adapter side effects.

use super::{
    ConsumerStream, ProductionCluster, ProductionRelay, RunningHarness, connect_failure_to_harness,
    open_consumer_stream, start_cli_smoke,
};
use crate::acceptance::helpers::write_device_profile;
use crate::{HarnessError, ManagedProcess, Result};
use chrono::Utc;
use futures_util::SinkExt;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use tokio::{
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

const PRESSURE_QUEUE_LIMIT_BYTES: usize = 4 * 1024 * 1024;
const PRESSURE_BULK_RECORDS: usize = 256;
const PRESSURE_PAYLOAD_BYTES: usize = 64 * 1024;
const PRESSURE_OBSERVE_TIMEOUT: Duration = Duration::from_secs(6);
const PRESSURE_MIN_OBSERVE: Duration = Duration::from_millis(500);
const PRESSURE_SIBLING_TIMEOUT: Duration = Duration::from_secs(8);
const PRESSURE_CANCEL_TIMEOUT: Duration = Duration::from_secs(5);
const PRESSURE_SETTLE_TIMEOUT: Duration = Duration::from_secs(2);
const PRESSURE_RECORD_HEADER_BYTES: usize = 4;
const PRESSURE_M2_INITIAL_WINDOW_BYTES: usize = 128 * 1024;

/// Payload-free evidence from the bounded production pressure gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PressureEvidence {
    /// Number of production relays serving during the pressure run.
    pub relay_count: usize,
    /// A real CLI control/data pair completed a baseline routed canary.
    pub baseline_echo: bool,
    /// The bounded bulk sender was started against the production stream.
    pub bulk_attempted: bool,
    /// Number of bulk records accepted by the consumer WebSocket before
    /// cancellation or relay backpressure stopped the sender.
    pub bulk_records_attempted: usize,
    /// Backpressure was observed as a nonzero relay queue or a sender that
    /// remained blocked, and every sampled queue stayed within its configured
    /// 4 MiB session budget.
    pub bounded_backpressure: bool,
    /// The production relay snapshot reported nonzero queued application
    /// bytes while the bulk sender was active.
    pub queue_budget_observed: bool,
    /// An independent consumer stream returned its canary during pressure.
    pub sibling_canary: bool,
    /// Cancelling the bulk stream stopped and joined its sender within the
    /// bounded cancellation deadline.
    pub cancellation_responsive: bool,
    /// After the cancelled stream reached terminal cleanup and its bounded
    /// in-flight work settled, the relay lifetime application-dispatch counter
    /// remained unchanged across the fixed observation window.  This is
    /// transport no-replay evidence for that stream, not desktop effect
    /// evidence.
    pub cancellation_not_replayed: bool,
    /// A fresh CLI session acquired the same scope with a newer owner epoch.
    pub recovery_owner_verified: bool,
    /// The fresh CLI session returned its canary after pressure cleanup.
    pub recovery_echo: bool,
    /// Maximum physical device fanout sockets observed during the run.
    pub fanout_peak_open: usize,
    /// Wall-clock milliseconds spent in the pressure and recovery scenario.
    pub elapsed_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BulkPumpOutcome {
    Cancelled { sent: usize },
    Completed { sent: usize },
    SendFailed { sent: usize },
}

struct PressureObservation {
    queue_budget_observed: bool,
    sender_blocked: bool,
}

/// Shared progress for the bulk WebSocket writer.
///
/// `JoinHandle::is_finished` only says that the bounded pump has ended; it
/// cannot distinguish a writer that is still making progress from one stalled
/// in the transport.  Keep one monotonic send-start marker so the pressure
/// gate can require an actual pending write before cancelling the stream.
struct PumpProgress {
    started: Instant,
    send_started_ms: AtomicU64,
}

impl PumpProgress {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            send_started_ms: AtomicU64::new(0),
        }
    }

    fn begin_send(&self) {
        let elapsed_ms = self.started.elapsed().as_millis();
        let marker = u64::try_from(elapsed_ms.saturating_add(1)).unwrap_or(u64::MAX);
        self.send_started_ms.store(marker, Ordering::Release);
    }

    fn end_send(&self) {
        self.send_started_ms.store(0, Ordering::Release);
    }

    fn send_blocked_for(&self, minimum: Duration) -> bool {
        let marker = self.send_started_ms.load(Ordering::Acquire);
        if marker == 0 {
            return false;
        }
        let started_ms = marker.saturating_sub(1);
        let elapsed_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let minimum_ms = u64::try_from(minimum.as_millis()).unwrap_or(u64::MAX);
        elapsed_ms.saturating_sub(started_ms) >= minimum_ms
    }
}

/// Run the bounded real three-relay I07 scenario.
pub(super) async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
) -> Result<PressureEvidence> {
    let started = Instant::now();
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(format!(
            "pressure gate started {} relays, expected three",
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
            "pressure gate started with {ready}/3 relays Ready"
        )));
    }

    // Saturate through a non-owner relay so this gate exercises the bounded
    // ConsumerChunk prefix/body path as well as the owner's queue.  The
    // sender observes a real pending WebSocket write before cancellation;
    // it does not infer pressure from a lifetime transfer quota because the
    // peer record and HTTP/3 body charges are released after each send.
    let bulk_consumer_addr = cluster.relay("relay-b")?.consumer_addr()?;
    let sibling_consumer_addr = cluster.relay("relay-c")?.consumer_addr()?;
    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("tenant A has no pressure device".into()))?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("pressure device has no echo service".into()))?;
    let canary = format!("m7-pressure:{}", device.id);
    validate_pressure_message_budget(canary.len())?;
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
    profile.config.rotation = super::ROTATION;
    profile
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("pressure client config: {error}")))?;
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        crate::OidcTokenOptions {
            expires_in: Duration::from_secs(90),
            ..crate::OidcTokenOptions::default()
        },
    )?;

    let (mut process, mut bulk_stream) = start_cli_smoke(
        harness,
        cluster.device_fanout.local_addr(),
        bulk_consumer_addr,
        &profile,
        &token,
        device.id,
        service_id,
    )
    .await?;
    let baseline_result = bulk_stream
        .round_trip(b"m7-pressure-baseline", canary.as_bytes())
        .await;
    if let Err(error) = baseline_result {
        let _ = bulk_stream.close().await;
        let _ = process.shutdown(Duration::from_secs(5)).await;
        return Err(error);
    }

    let mut sibling_stream = match open_consumer_stream(
        sibling_consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &token,
        device.id,
        service_id,
    )
    .await
    {
        Ok(stream) => stream,
        Err(error) => {
            let _ = bulk_stream.close().await;
            let _ = process.shutdown(Duration::from_secs(5)).await;
            return Err(connect_failure_to_harness(error));
        }
    };
    let sibling_baseline_result = match timeout(
        PRESSURE_SIBLING_TIMEOUT,
        sibling_stream.round_trip(b"m7-pressure-sibling-baseline", canary.as_bytes()),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            let _ = sibling_stream.close().await;
            let _ = bulk_stream.close().await;
            let _ = process.shutdown(Duration::from_secs(5)).await;
            return Err(HarnessError::Timeout(
                "pressure sibling baseline timed out".into(),
            ));
        }
    };
    if let Err(error) = sibling_baseline_result {
        let _ = sibling_stream.close().await;
        let _ = bulk_stream.close().await;
        let _ = process.shutdown(Duration::from_secs(5)).await;
        return Err(error);
    }

    let owner = match cluster
        .catalog
        .current_owner(device.tenant_id, device.id, Utc::now())
        .await
    {
        Ok(Some(owner)) => owner,
        Ok(None) => {
            let _ = sibling_stream.close().await;
            let _ = bulk_stream.close().await;
            let _ = process.shutdown(Duration::from_secs(5)).await;
            return Err(HarnessError::Process(
                "pressure CLI did not retain an owner after baseline".into(),
            ));
        }
        Err(error) => {
            let _ = sibling_stream.close().await;
            let _ = bulk_stream.close().await;
            let _ = process.shutdown(Duration::from_secs(5)).await;
            return Err(HarnessError::Redis(format!(
                "reading pressure owner: {error}"
            )));
        }
    };
    if owner.token.tenant_id != device.tenant_id
        || owner.token.device_id != device.id
        || cluster
            .relays
            .iter()
            .all(|relay| relay.node_id != owner.token.node_id)
    {
        let _ = sibling_stream.close().await;
        let _ = bulk_stream.close().await;
        let _ = process.shutdown(Duration::from_secs(5)).await;
        return Err(HarnessError::Process(
            "pressure owner did not match the fixture scope".into(),
        ));
    }
    let owner_relay = cluster.relay(&owner.token.node_id)?;
    let baseline_snapshot = match owner_relay.snapshot().await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let _ = sibling_stream.close().await;
            let _ = bulk_stream.close().await;
            let _ = process.shutdown(Duration::from_secs(5)).await;
            return Err(error);
        }
    };
    if baseline_snapshot.lifetime_application_dispatches == 0 {
        let _ = sibling_stream.close().await;
        let _ = bulk_stream.close().await;
        let _ = process.shutdown(Duration::from_secs(5)).await;
        return Err(HarnessError::Process(
            "pressure baseline did not advance the relay application-dispatch counter".into(),
        ));
    }
    let baseline_dispatches = baseline_snapshot.lifetime_application_dispatches;
    let owner_epoch = owner.token.epoch;

    let pressure_result = run_pressure_phase(
        owner_relay,
        device.id,
        baseline_dispatches,
        canary.as_bytes(),
        bulk_stream,
        sibling_stream,
    )
    .await;
    let (pressure, mut bulk_stream, mut sibling_stream) = match pressure_result {
        Ok(result) => result,
        Err(error) => {
            let client_diagnostics = client_terminal_diagnostics(&mut process).await;
            let _ = process.shutdown(Duration::from_secs(5)).await;
            return Err(annotate_pressure_error(error, client_diagnostics));
        }
    };
    sibling_stream.close().await?;
    bulk_stream.close().await?;
    process
        .shutdown(Duration::from_secs(5))
        .await
        .map_err(|error| HarnessError::Process(format!("joining pressure CLI: {error}")))?;

    cluster
        .wait_for_no_owner(device.tenant_id, device.id)
        .await?;
    super::wait_for_fanout_drained(&cluster.device_fanout, "pressure CLI").await?;

    let (fresh_process, mut fresh_stream) = start_cli_smoke(
        harness,
        cluster.device_fanout.local_addr(),
        sibling_consumer_addr,
        &profile,
        &token,
        device.id,
        service_id,
    )
    .await?;
    let fresh_owner = match cluster
        .catalog
        .current_owner(device.tenant_id, device.id, Utc::now())
        .await
    {
        Ok(owner) => owner,
        Err(error) => {
            let _ = fresh_stream.close().await;
            let _ = fresh_process.shutdown(Duration::from_secs(5)).await;
            return Err(HarnessError::Redis(format!(
                "reading pressure recovery owner: {error}"
            )));
        }
    };
    let recovery_owner_verified = matches!(
        fresh_owner,
        Some(owner)
            if owner.token.tenant_id == device.tenant_id
                && owner.token.device_id == device.id
                && owner.token.epoch > owner_epoch
                && cluster
                    .relays
                    .iter()
                    .any(|relay| relay.node_id == owner.token.node_id)
    );
    if !recovery_owner_verified {
        let _ = fresh_stream.close().await;
        let _ = fresh_process.shutdown(Duration::from_secs(5)).await;
        return Err(HarnessError::Process(
            "pressure recovery owner was not a live scoped owner".into(),
        ));
    }
    let recovery_echo = fresh_stream
        .round_trip(b"m7-pressure-recovery", canary.as_bytes())
        .await;
    let stream_cleanup = fresh_stream.close().await;
    let process_cleanup = fresh_process.shutdown(Duration::from_secs(5)).await;
    stream_cleanup?;
    process_cleanup.map_err(|error| {
        HarnessError::Process(format!("joining pressure recovery CLI: {error}"))
    })?;
    recovery_echo?;
    super::wait_for_fanout_drained(&cluster.device_fanout, "pressure recovery").await?;
    let fanout = cluster.device_fanout.diagnostics();

    Ok(PressureEvidence {
        relay_count: cluster.relays.len(),
        baseline_echo: true,
        bulk_attempted: true,
        bulk_records_attempted: pressure.bulk_records_attempted,
        bounded_backpressure: pressure.bounded_backpressure,
        queue_budget_observed: pressure.queue_budget_observed,
        sibling_canary: pressure.sibling_canary,
        cancellation_responsive: pressure.cancellation_responsive,
        cancellation_not_replayed: pressure.cancellation_not_replayed,
        recovery_owner_verified,
        recovery_echo: true,
        fanout_peak_open: fanout.peak_open,
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

struct PressurePhase {
    bulk_records_attempted: usize,
    bounded_backpressure: bool,
    queue_budget_observed: bool,
    sibling_canary: bool,
    cancellation_responsive: bool,
    cancellation_not_replayed: bool,
}

async fn run_pressure_phase(
    owner_relay: &ProductionRelay,
    device_id: uuid::Uuid,
    baseline_dispatches: u64,
    canary: &[u8],
    bulk_stream: ConsumerStream,
    mut sibling_stream: ConsumerStream,
) -> Result<(PressurePhase, ConsumerStream, ConsumerStream)> {
    let bulk_stream_id = identify_bulk_stream(owner_relay, device_id).await?;
    let cancellation = CancellationToken::new();
    let progress = Arc::new(PumpProgress::new());
    let mut pump = Some(tokio::spawn(pump_bulk(
        bulk_stream,
        cancellation.clone(),
        Arc::clone(&progress),
    )));
    let observation = match observe_pressure(
        owner_relay,
        device_id,
        bulk_stream_id,
        pump.as_ref().unwrap(),
        &progress,
    )
    .await
    {
        Ok(observation) => observation,
        Err(error) => {
            cancel_and_close_bulk(&cancellation, &mut pump).await;
            let _ = sibling_stream.close().await;
            return Err(error);
        }
    };
    let sibling_result = match timeout(
        PRESSURE_SIBLING_TIMEOUT,
        sibling_stream.round_trip(b"m7-pressure-sibling-live", canary),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            cancel_and_close_bulk(&cancellation, &mut pump).await;
            let _ = sibling_stream.close().await;
            return Err(HarnessError::Timeout(
                "pressure sibling canary timed out".into(),
            ));
        }
    };
    let sibling_canary = sibling_result.is_ok();
    if let Err(error) = sibling_result {
        cancel_and_close_bulk(&cancellation, &mut pump).await;
        let _ = sibling_stream.close().await;
        return Err(error);
    }

    let counter_before_cancel = match owner_relay.snapshot().await {
        Ok(snapshot) => snapshot.lifetime_application_dispatches,
        Err(error) => {
            cancel_and_close_bulk(&cancellation, &mut pump).await;
            let _ = sibling_stream.close().await;
            return Err(error);
        }
    };
    let cancel_started = Instant::now();
    cancellation.cancel();
    let (mut bulk_stream, outcome) = reap_bulk(pump.take().expect("pressure pump")).await?;
    let cancellation_responsive = cancel_started.elapsed() <= PRESSURE_CANCEL_TIMEOUT
        && matches!(outcome, BulkPumpOutcome::Cancelled { .. });
    let bulk_records_attempted = match outcome {
        BulkPumpOutcome::Cancelled { sent }
        | BulkPumpOutcome::Completed { sent }
        | BulkPumpOutcome::SendFailed { sent } => sent,
    };
    let ambiguous_bulk_send = matches!(
        outcome,
        BulkPumpOutcome::Cancelled { .. } | BulkPumpOutcome::SendFailed { .. }
    );
    let _ = bulk_stream.close().await;
    let _ = sibling_stream.close().await;
    let cancellation_not_replayed = wait_for_cleanup_and_stable_dispatch(
        owner_relay,
        device_id,
        bulk_stream_id,
        counter_before_cancel,
        baseline_dispatches,
        bulk_records_attempted,
        ambiguous_bulk_send,
    )
    .await?;
    Ok((
        PressurePhase {
            bulk_records_attempted,
            bounded_backpressure: observation.queue_budget_observed || observation.sender_blocked,
            queue_budget_observed: observation.queue_budget_observed,
            sibling_canary,
            cancellation_responsive,
            cancellation_not_replayed,
        },
        bulk_stream,
        sibling_stream,
    ))
}

async fn cancel_and_close_bulk(
    cancellation: &CancellationToken,
    pump: &mut Option<JoinHandle<(ConsumerStream, BulkPumpOutcome)>>,
) {
    cancellation.cancel();
    if let Some(pump) = pump.take()
        && let Ok((mut stream, _)) = reap_bulk(pump).await
    {
        let _ = stream.close().await;
    }
}

async fn observe_pressure(
    owner_relay: &ProductionRelay,
    device_id: uuid::Uuid,
    bulk_stream_id: u64,
    pump: &JoinHandle<(ConsumerStream, BulkPumpOutcome)>,
    progress: &PumpProgress,
) -> Result<PressureObservation> {
    let deadline = Instant::now() + PRESSURE_OBSERVE_TIMEOUT;
    let started = Instant::now();
    let mut max_queue_bytes = 0;
    let mut max_queue_messages = 0;
    let mut max_bulk_queue_bytes = 0;
    let mut within_budget = true;
    loop {
        let snapshot = owner_relay.snapshot().await?;
        let Some(session) = snapshot
            .sessions
            .iter()
            .find(|session| session.device_id == device_id.to_string())
        else {
            return Err(HarnessError::Process(format!(
                "pressure owner snapshot lost the live device: {}",
                pressure_snapshot_diagnostics(
                    owner_relay,
                    &snapshot,
                    device_id,
                    Some(bulk_stream_id),
                    "pressure_observe",
                )
            )));
        };
        let Some(bulk_stream) = session
            .streams
            .iter()
            .find(|stream| stream.stream_id == bulk_stream_id)
        else {
            return Err(HarnessError::Process(format!(
                "pressure owner snapshot lost bulk stream {bulk_stream_id}: {}",
                pressure_snapshot_diagnostics(
                    owner_relay,
                    &snapshot,
                    device_id,
                    Some(bulk_stream_id),
                    "pressure_observe_missing_stream",
                )
            )));
        };
        if bulk_stream.terminal {
            return Err(HarnessError::Process(format!(
                "pressure bulk stream {bulk_stream_id} became terminal before cancellation: {}",
                pressure_snapshot_diagnostics(
                    owner_relay,
                    &snapshot,
                    device_id,
                    Some(bulk_stream_id),
                    "pressure_observe_terminal",
                )
            )));
        }
        if pump.is_finished() {
            return Err(HarnessError::Process(format!(
                "pressure sender completed before bounded backpressure (bulk_stream={bulk_stream_id}, elapsed_ms={}, {})",
                started.elapsed().as_millis(),
                pressure_snapshot_diagnostics(
                    owner_relay,
                    &snapshot,
                    device_id,
                    Some(bulk_stream_id),
                    "pressure_observe_sender_completed",
                )
            )));
        }
        max_queue_bytes = max_queue_bytes.max(session.queue_bytes);
        max_queue_messages = max_queue_messages.max(session.queue_messages);
        max_bulk_queue_bytes = max_bulk_queue_bytes.max(bulk_stream.queue_bytes);
        within_budget &= session.queue_bytes <= PRESSURE_QUEUE_LIMIT_BYTES;
        let queue_budget_observed = max_bulk_queue_bytes > 0;
        let sender_blocked = progress.send_blocked_for(PRESSURE_MIN_OBSERVE);
        if queue_budget_observed || sender_blocked {
            if !within_budget {
                return Err(HarnessError::Process(format!(
                    "pressure session queue exceeded {} bytes: {}",
                    PRESSURE_QUEUE_LIMIT_BYTES, max_queue_bytes
                )));
            }
            return Ok(PressureObservation {
                queue_budget_observed,
                sender_blocked,
            });
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Process(format!(
                "pressure sender completed without observable bounded backpressure (bulk_stream={}, queue_bytes={}, bulk_queue_bytes={}, queue_messages={})",
                bulk_stream_id, max_queue_bytes, max_bulk_queue_bytes, max_queue_messages
            )));
        }
        sleep(Duration::from_millis(50)).await;
    }
}

async fn pump_bulk(
    mut stream: ConsumerStream,
    cancellation: CancellationToken,
    progress: Arc<PumpProgress>,
) -> (ConsumerStream, BulkPumpOutcome) {
    let payload = vec![b'p'; PRESSURE_PAYLOAD_BYTES];
    let mut sent = 0;
    for _ in 0..PRESSURE_BULK_RECORDS {
        let Ok(length) = u32::try_from(payload.len()) else {
            return (stream, BulkPumpOutcome::SendFailed { sent });
        };
        let mut frame = Vec::with_capacity(payload.len() + 4);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&payload);
        progress.begin_send();
        let send = stream.socket.send(Message::Binary(frame.into()));
        let result = tokio::select! {
            _ = cancellation.cancelled() => {
                progress.end_send();
                return (stream, BulkPumpOutcome::Cancelled { sent });
            }
            result = send => result,
        };
        progress.end_send();
        match result {
            Ok(()) => sent += 1,
            Err(_) => return (stream, BulkPumpOutcome::SendFailed { sent }),
        }
    }
    (stream, BulkPumpOutcome::Completed { sent })
}

async fn reap_bulk(
    mut pump: JoinHandle<(ConsumerStream, BulkPumpOutcome)>,
) -> Result<(ConsumerStream, BulkPumpOutcome)> {
    match timeout(PRESSURE_CANCEL_TIMEOUT, &mut pump).await {
        Ok(result) => result
            .map_err(|error| HarnessError::Process(format!("joining pressure sender: {error}"))),
        Err(_) => {
            pump.abort();
            let _ = pump.await;
            Err(HarnessError::Timeout(
                "pressure sender cancellation timed out".into(),
            ))
        }
    }
}

async fn identify_bulk_stream(relay: &ProductionRelay, device_id: uuid::Uuid) -> Result<u64> {
    let snapshot = relay.snapshot().await?;
    let Some(session) = snapshot
        .sessions
        .iter()
        .find(|session| session.device_id == device_id.to_string())
    else {
        return Err(HarnessError::Process(format!(
            "pressure owner snapshot lost the live device before saturation: {}",
            pressure_snapshot_diagnostics(relay, &snapshot, device_id, None, "identify_bulk")
        )));
    };
    if session.streams.len() != 2 {
        let sample_ids = session
            .streams
            .iter()
            .take(4)
            .map(|stream| stream.stream_id)
            .collect::<Vec<_>>();
        return Err(HarnessError::Process(format!(
            "pressure expected exactly two admitted streams before saturation: count={}, sample_ids={sample_ids:?}",
            session.streams.len()
        )));
    }
    // The bulk consumer is admitted and completes its baseline before the
    // sibling stream is opened.  The actor allocates stream IDs monotonically
    // within one device session, so the lower of these two IDs is the bulk
    // stream.  Keep this correlation in the snapshot path rather than using
    // the global dispatch counter to infer cleanup.
    session
        .streams
        .iter()
        .map(|stream| stream.stream_id)
        .min()
        .ok_or_else(|| HarnessError::Process("pressure bulk stream ID is missing".into()))
}

/// Format only bounded phase and counter state when a pressure snapshot loses
/// the expected device or stream.  This intentionally omits device/session
/// identifiers, endpoints, pins, payloads, and backend error text.
fn pressure_snapshot_diagnostics(
    relay: &ProductionRelay,
    snapshot: &tunnel_relay::RelaySnapshot,
    device_id: uuid::Uuid,
    bulk_stream_id: Option<u64>,
    phase: &str,
) -> String {
    let session = snapshot
        .sessions
        .iter()
        .find(|session| session.device_id == device_id.to_string());
    let (device_present, stream_count, queue_bytes, queue_messages, terminal_streams) = session
        .map_or((false, 0, 0, 0, 0), |session| {
            (
                true,
                session.streams.len(),
                session.queue_bytes,
                session.queue_messages,
                session
                    .streams
                    .iter()
                    .filter(|stream| stream.terminal)
                    .count(),
            )
        });
    let bulk = session.and_then(|session| {
        bulk_stream_id.and_then(|stream_id| {
            session
                .streams
                .iter()
                .find(|stream| stream.stream_id == stream_id)
        })
    });
    let bulk_summary = bulk.map_or_else(
        || "bulk_present=false".to_owned(),
        |stream| {
            format!(
                "bulk_present=true, bulk_terminal={}, bulk_terminal_reason=not_exposed_by_relay_snapshot, bulk_last_emitted={}, bulk_peer_acked={}, bulk_recv_contiguous={}, bulk_delivered_contiguous={}, bulk_queue_bytes={}, bulk_replay_frames={}, bulk_replay_bytes={}",
                stream.terminal,
                stream.last_emitted_relay_to_connector,
                stream.peer_acked_relay_to_connector,
                stream.recv_contiguous_connector_to_relay,
                stream.delivered_contiguous_connector_to_relay,
                stream.queue_bytes,
                stream.replay_frames_relay_to_connector,
                stream.replay_bytes_relay_to_connector,
            )
        },
    );
    let readiness = relay.peer_runtime.peer_readiness().map_or_else(
        || "readiness=unconfigured".to_owned(),
        |readiness| {
            let state = readiness.snapshot();
            format!(
                "readiness_listener={:?}, readiness_routes_known={}, readiness_required_routes={}, readiness_reachable_routes={}, readiness_capacity_ready_routes={}, readiness_available_capacity={:?}, readiness_required_capacity={}, readiness_revision={}",
                state.listener,
                state.routes_known,
                state.required_routes,
                state.reachable_routes,
                state.capacity_ready_routes,
                state.available_capacity,
                state.required_capacity,
                state.revision,
            )
        },
    );
    format!(
        "phase={phase}, relay={}, dispatches={}, sessions={}, device_present={}, device_streams={}, device_queue_bytes={}, device_queue_messages={}, device_terminal_streams={}, {bulk_summary}, {readiness}",
        relay.node_id,
        snapshot.lifetime_application_dispatches,
        snapshot.sessions.len(),
        device_present,
        stream_count,
        queue_bytes,
        queue_messages,
        terminal_streams,
    )
}

/// Validate the exact one-record pressure shape before opening the stream.
/// The request includes the four-byte public record length; the response adds
/// the local canary and its own four-byte length.  A single record must fit
/// the public body limits and the negotiated 128 KiB M2 direction window.
fn validate_pressure_message_budget(canary_len: usize) -> Result<()> {
    let request_bytes = PRESSURE_RECORD_HEADER_BYTES.saturating_add(PRESSURE_PAYLOAD_BYTES);
    let response_body = canary_len.saturating_add(PRESSURE_PAYLOAD_BYTES);
    let response_bytes = PRESSURE_RECORD_HEADER_BYTES.saturating_add(response_body);
    let public_request_limit = super::MAX_RECORD_BYTES.saturating_add(PRESSURE_RECORD_HEADER_BYTES);
    let public_response_limit = super::MAX_RECORD_BYTES
        .saturating_add(super::MAX_CANARY_BYTES)
        .saturating_add(PRESSURE_RECORD_HEADER_BYTES);
    if request_bytes > public_request_limit {
        return Err(HarnessError::InvalidInput(format!(
            "pressure record request exceeds public bound: bytes={request_bytes}, limit={public_request_limit}"
        )));
    }
    if response_bytes > public_response_limit {
        return Err(HarnessError::InvalidInput(format!(
            "pressure echo response exceeds public bound: bytes={response_bytes}, limit={public_response_limit}"
        )));
    }
    if request_bytes > PRESSURE_M2_INITIAL_WINDOW_BYTES
        || response_bytes > PRESSURE_M2_INITIAL_WINDOW_BYTES
    {
        return Err(HarnessError::InvalidInput(format!(
            "pressure record exceeds one M2 direction window: request_bytes={request_bytes}, response_bytes={response_bytes}, window={PRESSURE_M2_INITIAL_WINDOW_BYTES}"
        )));
    }
    Ok(())
}

async fn wait_for_cleanup_and_stable_dispatch(
    relay: &ProductionRelay,
    device_id: uuid::Uuid,
    bulk_stream_id: u64,
    counter_before_cancel: u64,
    baseline_dispatches: u64,
    bulk_records_attempted: usize,
    ambiguous_bulk_send: bool,
) -> Result<bool> {
    if counter_before_cancel < baseline_dispatches {
        return Err(HarnessError::Process(
            "pressure dispatch counter moved backwards".into(),
        ));
    }

    // The first two baseline records are included in baseline_dispatches.  A
    // pressure phase adds exactly one known sibling record, then one dispatch
    // per successful bulk send.  Cancellation or a failed send can race one
    // additional in-flight write, so retain one explicitly accounted-for
    // ambiguity without using it as proof of no replay.
    let accepted_records = u64::try_from(bulk_records_attempted).map_err(|_| {
        HarnessError::Process(format!(
            "pressure accepted-record count does not fit dispatch counter: {bulk_records_attempted}"
        ))
    })?;
    let ambiguous_records = if ambiguous_bulk_send { 1 } else { 0 };
    let maximum_dispatches = baseline_dispatches
        .checked_add(1)
        .and_then(|value| value.checked_add(accepted_records))
        .and_then(|value| value.checked_add(ambiguous_records))
        .ok_or_else(|| {
            HarnessError::Process(format!(
                "pressure dispatch workload bound overflow: baseline={baseline_dispatches}, sibling=1, accepted_records={bulk_records_attempted}, ambiguous_records={ambiguous_records}"
            ))
        })?;
    if counter_before_cancel > maximum_dispatches {
        return Err(HarnessError::Process(format!(
            "pressure dispatch counter exceeded known pre-cancel workload: baseline={baseline_dispatches}, sibling=1, accepted_records={bulk_records_attempted}, ambiguous_records={ambiguous_records}, before_cancel={counter_before_cancel}, maximum_dispatches={maximum_dispatches}"
        )));
    }

    let deadline = Instant::now() + PRESSURE_SETTLE_TIMEOUT;
    let mut samples = 0_u32;
    let mut cleanup_seen = false;
    let mut cleanup_counter = None;
    let mut stable_samples = 0_u32;
    while Instant::now() < deadline {
        sleep(Duration::from_millis(100)).await;
        let snapshot = relay.snapshot().await.map_err(|error| {
            HarnessError::Process(format!(
                "pressure cleanup snapshot failed: phase=stream_cleanup, sample={samples}, counter_before_cancel={counter_before_cancel}, maximum_dispatches={maximum_dispatches}, error={error}"
            ))
        })?;
        let observed = snapshot.lifetime_application_dispatches;
        samples = samples.saturating_add(1);
        if observed < baseline_dispatches {
            return Err(HarnessError::Process(format!(
                "pressure dispatch counter moved backwards after cancellation: baseline={baseline_dispatches}, before_cancel={counter_before_cancel}, observed={observed}, samples={samples}"
            )));
        }
        if observed > maximum_dispatches {
            return Err(HarnessError::Process(format!(
                "pressure dispatch exceeded known workload after cancellation: baseline={baseline_dispatches}, sibling=1, accepted_records={bulk_records_attempted}, ambiguous_records={ambiguous_records}, maximum_dispatches={maximum_dispatches}, observed={observed}, samples={samples}"
            )));
        }

        let Some(session) = snapshot
            .sessions
            .iter()
            .find(|session| session.device_id == device_id.to_string())
        else {
            return Err(HarnessError::Process(format!(
                "pressure owner snapshot lost the live device during stream cleanup: {}",
                pressure_snapshot_diagnostics(
                    relay,
                    &snapshot,
                    device_id,
                    Some(bulk_stream_id),
                    "stream_cleanup",
                )
            )));
        };
        let bulk_stream = session
            .streams
            .iter()
            .find(|stream| stream.stream_id == bulk_stream_id);
        let converged = bulk_stream.is_none_or(|stream| {
            stream.terminal
                && stream.queue_bytes == 0
                && stream.replay_frames_relay_to_connector == 0
                && stream.replay_bytes_relay_to_connector == 0
        });
        if !cleanup_seen {
            if converged {
                cleanup_seen = true;
                cleanup_counter = Some(observed);
            }
        } else {
            let expected = cleanup_counter.expect("cleanup counter is set");
            if observed != expected {
                return Err(HarnessError::Process(format!(
                    "pressure dispatch advanced after bulk stream cleanup: bulk_stream={bulk_stream_id}, cleanup_counter={expected}, observed={observed}, baseline={baseline_dispatches}, sibling=1, accepted_records={bulk_records_attempted}, ambiguous_records={ambiguous_records}, samples={samples}"
                )));
            }
            stable_samples = stable_samples.saturating_add(1);
        }
    }
    if !cleanup_seen {
        // Preserve the final bounded stream/queue/rotation state. The prior
        // timeout only reported counters, so it could not distinguish a
        // missing terminal FIN from replay debt, queue retention, or a
        // rotation phase holding the terminal output.
        let final_state = match timeout(Duration::from_millis(250), relay.snapshot()).await {
            Ok(Ok(snapshot)) => pressure_snapshot_diagnostics(
                relay,
                &snapshot,
                device_id,
                Some(bulk_stream_id),
                "stream_cleanup_timeout",
            ),
            _ => "phase=stream_cleanup_timeout, final_snapshot=unavailable".to_owned(),
        };
        return Err(HarnessError::Timeout(format!(
            "pressure bulk stream did not reach terminal cleanup within {:?}: bulk_stream={bulk_stream_id}, baseline={baseline_dispatches}, before_cancel={counter_before_cancel}, accepted_records={bulk_records_attempted}, ambiguous_records={ambiguous_records}, maximum_dispatches={maximum_dispatches}, samples={samples}; {final_state}",
            PRESSURE_SETTLE_TIMEOUT
        )));
    }
    if stable_samples < 2 {
        return Err(HarnessError::Timeout(format!(
            "pressure dispatch counter lacked a fixed post-cleanup stable window: bulk_stream={bulk_stream_id}, cleanup_counter={}, stable_samples={stable_samples}, baseline={baseline_dispatches}, accepted_records={bulk_records_attempted}, ambiguous_records={ambiguous_records}, samples={samples}",
            cleanup_counter.expect("cleanup counter is set")
        )));
    }
    Ok(true)
}

const CLIENT_DIAGNOSTIC_LINE_LIMIT: usize = 32;
const CLIENT_DIAGNOSTIC_VALUE_LIMIT: usize = 4;
const CLIENT_DIAGNOSTIC_TOKEN_LIMIT: usize = 48;

/// Capture only terminal state and stable fields from the client's JSON error
/// diagnostic before [`ManagedProcess::shutdown`] consumes the child.  The
/// client error message is deliberately ignored because it may contain
/// backend or configuration text that is not suitable for a pressure-gate
/// failure summary.
async fn client_terminal_diagnostics(process: &mut ManagedProcess) -> String {
    let terminal = match process.try_wait() {
        Ok(Some(status)) => format!(
            "state=exited,success={},exit_code={},signal={}",
            status.success(),
            status
                .code()
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            process_signal(status).map_or_else(|| "none".to_owned(), |signal| signal.to_string()),
        ),
        Ok(None) => "state=running".to_owned(),
        Err(_) => "state=unknown".to_owned(),
    };

    // Let the output drain tasks make progress after an already-exited client
    // without adding an unbounded wait to the pressure failure path.
    tokio::task::yield_now().await;
    let mut fields = ClientDiagnosticFields::default();
    collect_client_json_errors(&process.stdout(), &mut fields);
    collect_client_json_errors(&process.stderr(), &mut fields);
    format!(
        "client_terminal={terminal}, cli_error_records={}, cli_error_codes={:?}, cli_error_retryable={:?}, cli_error_phases={:?}",
        fields.records, fields.codes, fields.retryable, fields.phases,
    )
}

#[cfg(unix)]
fn process_signal(status: std::process::ExitStatus) -> Option<i32> {
    std::os::unix::process::ExitStatusExt::signal(&status)
}

#[cfg(not(unix))]
fn process_signal(_status: std::process::ExitStatus) -> Option<i32> {
    None
}

#[derive(Default)]
struct ClientDiagnosticFields {
    records: usize,
    codes: Vec<String>,
    retryable: Vec<bool>,
    phases: Vec<String>,
}

fn collect_client_json_errors(bytes: &[u8], fields: &mut ClientDiagnosticFields) {
    for line in String::from_utf8_lossy(bytes)
        .lines()
        .take(CLIENT_DIAGNOSTIC_LINE_LIMIT)
    {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
            continue;
        };
        let Some(error) = value.get("error").and_then(serde_json::Value::as_object) else {
            continue;
        };
        fields.records = fields.records.saturating_add(1);
        push_diagnostic_token(&mut fields.codes, error.get("code"));
        if let Some(retryable) = error.get("retryable").and_then(serde_json::Value::as_bool)
            && fields.retryable.len() < CLIENT_DIAGNOSTIC_VALUE_LIMIT
        {
            fields.retryable.push(retryable);
        }
        let phase = error.get("phase").or_else(|| value.get("phase"));
        push_diagnostic_token(&mut fields.phases, phase);
    }
}

fn push_diagnostic_token(values: &mut Vec<String>, value: Option<&serde_json::Value>) {
    if values.len() >= CLIENT_DIAGNOSTIC_VALUE_LIMIT {
        return;
    }
    let Some(value) = value.and_then(serde_json::Value::as_str) else {
        return;
    };
    let token = value
        .chars()
        .take(CLIENT_DIAGNOSTIC_TOKEN_LIMIT)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if !token.is_empty() {
        values.push(token);
    }
}

fn annotate_pressure_error(error: HarnessError, client_diagnostics: String) -> HarnessError {
    match error {
        HarnessError::Process(message) => {
            HarnessError::Process(format!("{message}; {client_diagnostics}"))
        }
        HarnessError::Timeout(message) => {
            HarnessError::Timeout(format!("{message}; {client_diagnostics}"))
        }
        error => HarnessError::Process(format!("{error}; {client_diagnostics}")),
    }
}

pub(super) fn validate_pressure_evidence(evidence: &PressureEvidence) -> Result<()> {
    let flags = [
        ("baseline_echo", evidence.baseline_echo),
        ("bulk_attempted", evidence.bulk_attempted),
        ("bounded_backpressure", evidence.bounded_backpressure),
        ("queue_budget_observed", evidence.queue_budget_observed),
        ("sibling_canary", evidence.sibling_canary),
        ("cancellation_responsive", evidence.cancellation_responsive),
        (
            "cancellation_not_replayed",
            evidence.cancellation_not_replayed,
        ),
        ("recovery_owner_verified", evidence.recovery_owner_verified),
        ("recovery_echo", evidence.recovery_echo),
    ];
    if let Some((name, false)) = flags.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "production pressure required gate {name} was false"
        )));
    }
    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "production pressure requires exactly three relays, observed {}",
            evidence.relay_count
        )));
    }
    if evidence.bulk_records_attempted == 0 {
        return Err(HarnessError::Process(
            "production pressure sent no bounded bulk records".into(),
        ));
    }
    if evidence.fanout_peak_open > 3 {
        return Err(HarnessError::Process(format!(
            "production pressure fanout exceeded three sockets: {}",
            evidence.fanout_peak_open
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{PressureEvidence, validate_pressure_evidence, validate_pressure_message_budget};
    use crate::acceptance_test_support::assert_rejected;

    fn valid_evidence() -> PressureEvidence {
        PressureEvidence {
            relay_count: 3,
            baseline_echo: true,
            bulk_attempted: true,
            bulk_records_attempted: 8,
            bounded_backpressure: true,
            queue_budget_observed: true,
            sibling_canary: true,
            cancellation_responsive: true,
            cancellation_not_replayed: true,
            recovery_owner_verified: true,
            recovery_echo: true,
            fanout_peak_open: 3,
            elapsed_ms: 1_000,
        }
    }

    #[test]
    fn pressure_validation_rejects_each_required_false_gate() {
        type DisabledGate = (&'static str, fn(&mut PressureEvidence));
        let fields: [DisabledGate; 9] = [
            ("baseline_echo", |e| e.baseline_echo = false),
            ("bulk_attempted", |e| e.bulk_attempted = false),
            ("bounded_backpressure", |e| e.bounded_backpressure = false),
            ("queue_budget_observed", |e| e.queue_budget_observed = false),
            ("sibling_canary", |e| e.sibling_canary = false),
            ("cancellation_responsive", |e| {
                e.cancellation_responsive = false
            }),
            ("cancellation_not_replayed", |e| {
                e.cancellation_not_replayed = false
            }),
            ("recovery_owner_verified", |e| {
                e.recovery_owner_verified = false
            }),
            ("recovery_echo", |e| e.recovery_echo = false),
        ];
        for (name, disable) in fields {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_rejected(validate_pressure_evidence(&evidence), name);
        }
    }

    #[test]
    fn pressure_validation_requires_a_real_bulk_attempt_and_socket_bound() {
        let mut evidence = valid_evidence();
        evidence.bulk_records_attempted = 0;
        assert_rejected(validate_pressure_evidence(&evidence), "production pressure");
        let mut evidence = valid_evidence();
        evidence.fanout_peak_open = 4;
        assert_rejected(validate_pressure_evidence(&evidence), "production pressure");
        let mut evidence = valid_evidence();
        evidence.relay_count = 2;
        assert_rejected(validate_pressure_evidence(&evidence), "production pressure");
    }

    #[test]
    fn maximum_pressure_record_includes_prefix_canary_and_window_budget() {
        assert!(validate_pressure_message_budget(48).is_ok());
        assert!(validate_pressure_message_budget(256).is_ok());
        assert!(validate_pressure_message_budget(257).is_err());
    }
}
