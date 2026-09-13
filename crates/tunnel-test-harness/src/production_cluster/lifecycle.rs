//! Production cross-relay consumer-stream cancellation and write-stall gate.
//!
//! This gate keeps one real CLI/device owner alive while two public consumer
//! WebSockets enter through the two non-owner relays.  One consumer stops
//! reading and is driven with a small, bounded workload until the owner-side
//! response path is held by the exact task-owned TCP proxy connection. The stream is
//! then cancelled and joined while the sibling remains usable.  The evidence
//! is deliberately transport scoped: it proves stream cleanup and no replay
//! after cleanup, not completion of an external adapter side effect.

use super::{
    CLEANUP_TIMEOUT, ConsumerStream, ProductionCluster, RunningHarness, SCENARIO_TIMEOUT,
    connect_failure_to_harness, device_dispatch_counter, open_consumer_stream, start_cli_smoke,
    wait_for_fanout_drained,
};
use crate::acceptance::helpers::write_device_profile;
use crate::{
    ConnectionId, Direction, Harness, HarnessError, HarnessOptions, ManagedProcess,
    OidcTokenOptions, ProxyConfig, ProxyHandle, Result, TcpProxy,
};
use chrono::Utc;
use futures_util::SinkExt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tempfile::tempdir;
use tokio::{
    task::JoinHandle,
    time::{sleep, timeout, timeout_at},
};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use tunnel_core::RotationConfig;
use tunnel_relay::{
    ConsumerIngressKind, MembershipReadiness, PeerTransportDiagnosticEventSnapshot, RelaySnapshot,
};
use uuid::Uuid;

// The public response writer can block outside the actor's retained-byte
// accounting.  Keep enough framed traffic to fill the real ingress path, but
// cap it below an unbounded flood.  This is the same 16 MiB bound used by the
// existing pressure gate's 256 x 64 KiB workload.
const STALL_RECORDS: usize = 256;
// Bound the producer's own writes and cleanup wait.  This outcome is a
// bounded workload/cleanup signal only; physical response-path proof comes
// from the relay-b typed response-write timeout diagnostic below.
const STALL_SEND_TIMEOUT: Duration = Duration::from_secs(4);
// Keep one independent sibling stream making bounded, successful progress
// while the target response writer is deliberately blackholed. The first
// canary starts after the target accepts its first pressure frame; later
// attempts are spaced below the production peer receive-idle bound. This is
// fixture isolation, not a transport timeout change.
const SIBLING_CANARY_ATTEMPTS: usize = 64;
const SIBLING_CANARY_INTERVAL: Duration = Duration::from_secs(2);
const SIBLING_CANARY_TIMEOUT: Duration = Duration::from_secs(3);
const STALL_POLL: Duration = Duration::from_millis(50);
const CLEANUP_STABLE_SAMPLES: u8 = 2;
const DIAGNOSTIC_TIMEOUT: Duration = Duration::from_secs(2);
// Limit only the stalled consumer proxy's target-side kernel receive buffer
// so the paused response path reaches the relay writer within the M2 overlap
// window.  The setting is fixture causality evidence, never proof of a stall.
const STALL_TARGET_RECEIVE_BUFFER_BYTES: u32 = 8 * 1024;
// The lifecycle fixture scopes a smaller listener send buffer to relay-b so
// the paused consumer path reaches the relay's typed physical write timeout
// before the peer data-idle deadline. Production listener defaults are
// unchanged.
const STALL_CONSUMER_SEND_BUFFER_BYTES: u32 = 8 * 1024;

/// Bounded evidence from the real three-relay stream lifecycle gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleEvidence {
    pub relay_count: usize,
    pub membership_ready_relays: usize,
    pub non_owner_ingress_relays: usize,
    pub baseline_streams: usize,
    pub baseline_owner_sockets: u8,
    pub physical_path_paused: bool,
    pub proxy_target_to_client_paused: bool,
    pub proxy_connection_closed: bool,
    pub stalled_records_sent: usize,
    pub queue_bytes_observed: bool,
    pub physical_response_path_blocked: bool,
    pub cancellation_joined: bool,
    pub stalled_stream_cleaned: bool,
    pub dispatch_stable_after_cleanup: bool,
    pub sibling_canary_during_stall: bool,
    pub sibling_canary_after_cancel: bool,
    pub sibling_stream_isolated: bool,
    pub fresh_authorized_stream: bool,
    pub physical_socket_bound: bool,
    /// Requested value for the scoped relay-B fixture.
    pub accepted_consumer_send_buffer_requested_bytes: u32,
    /// Last effective accepted-socket value observed by transport. This is
    /// observational; `physical_response_path_blocked` remains the causal
    /// writer-timeout proof for the stalled target stream.
    pub accepted_consumer_send_buffer_effective_bytes: usize,
    pub fanout_peak_open: usize,
    pub elapsed_ms: u64,
}

/// Validate the focused lifecycle evidence contract.
pub fn validate_lifecycle_evidence(evidence: &LifecycleEvidence) -> Result<()> {
    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "stream lifecycle expected three relays, observed {}",
            evidence.relay_count
        )));
    }
    if evidence.membership_ready_relays != 3 {
        return Err(HarnessError::Process(format!(
            "stream lifecycle expected three Ready memberships, observed {}",
            evidence.membership_ready_relays
        )));
    }
    if evidence.non_owner_ingress_relays != 2 {
        return Err(HarnessError::Process(format!(
            "stream lifecycle expected two non-owner ingress relays, observed {}",
            evidence.non_owner_ingress_relays
        )));
    }
    if evidence.baseline_streams != 2 {
        return Err(HarnessError::Process(format!(
            "stream lifecycle expected two baseline streams, observed {}",
            evidence.baseline_streams
        )));
    }
    if !(2..=3).contains(&evidence.baseline_owner_sockets) {
        return Err(HarnessError::Process(format!(
            "stream lifecycle baseline owner exposed {} sockets, expected two or three",
            evidence.baseline_owner_sockets
        )));
    }
    let required = [
        ("physical_path_paused", evidence.physical_path_paused),
        (
            "proxy_target_to_client_paused",
            evidence.proxy_target_to_client_paused,
        ),
        ("proxy_connection_closed", evidence.proxy_connection_closed),
        (
            "physical_response_path_blocked",
            evidence.physical_response_path_blocked,
        ),
        ("queue_bytes_observed", evidence.queue_bytes_observed),
        ("cancellation_joined", evidence.cancellation_joined),
        ("stalled_stream_cleaned", evidence.stalled_stream_cleaned),
        (
            "dispatch_stable_after_cleanup",
            evidence.dispatch_stable_after_cleanup,
        ),
        (
            "sibling_canary_during_stall",
            evidence.sibling_canary_during_stall,
        ),
        (
            "sibling_canary_after_cancel",
            evidence.sibling_canary_after_cancel,
        ),
        ("sibling_stream_isolated", evidence.sibling_stream_isolated),
        ("fresh_authorized_stream", evidence.fresh_authorized_stream),
        ("physical_socket_bound", evidence.physical_socket_bound),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "stream lifecycle required gate {name} was false"
        )));
    }
    if evidence.stalled_records_sent == 0 {
        return Err(HarnessError::Process(
            "stream lifecycle sent no bounded stalled records".into(),
        ));
    }
    if evidence.accepted_consumer_send_buffer_requested_bytes != STALL_CONSUMER_SEND_BUFFER_BYTES {
        return Err(HarnessError::Process(format!(
            "stream lifecycle accepted consumer buffer request was {}, expected {}",
            evidence.accepted_consumer_send_buffer_requested_bytes,
            STALL_CONSUMER_SEND_BUFFER_BYTES
        )));
    }
    if evidence.accepted_consumer_send_buffer_effective_bytes == 0 {
        return Err(HarnessError::Process(
            "stream lifecycle did not observe an accepted consumer socket buffer".into(),
        ));
    }
    if evidence.fanout_peak_open > 3 {
        return Err(HarnessError::Process(format!(
            "stream lifecycle device fanout exceeded three sockets: {}",
            evidence.fanout_peak_open
        )));
    }
    Ok(())
}

/// Run the bounded production three-relay stream cancellation gate.
pub async fn verify() -> Result<LifecycleEvidence> {
    // Keep this fixture on the normal rotation policy so its bounded physical
    // writer/cancellation cleanup is not preempted by accelerated rotation.
    // Rotation-under-stall remains a separate required pressure gate.
    let options = HarnessOptions::from_env()?
        .rotation(lifecycle_rotation_policy())
        .shared_device_uuid(true);
    // Harness::start owns Redis, fixture catalog and optional proxy handles
    // while it is constructing the returned value.  A consuming total
    // timeout here would drop that future mid-start and detach those owners;
    // the individual authority operations already carry their own bounded
    // deadlines and report cleanup on every error path.
    let mut harness = Harness::start(options).await?;
    let mut cluster = match ProductionCluster::start_with_consumer_send_buffer(
        &mut harness,
        "relay-b",
        STALL_CONSUMER_SEND_BUFFER_BYTES,
    )
    .await
    {
        Ok(cluster) => cluster,
        Err(error) => {
            return match harness.shutdown().await {
                Ok(()) => Err(error),
                Err(cleanup) => Err(HarnessError::Process(format!(
                    "starting stream lifecycle production cluster failed: {error}; harness cleanup failed: {cleanup}"
                ))),
            };
        }
    };

    // `run` owns the absolute scenario deadline and performs bounded client
    // cleanup before returning its payload-free diagnostics. Do not wrap it
    // in an outer timeout that would drop its resources before diagnostics
    // and joins are collected.
    let scenario = match run(&mut cluster, &harness).await {
        Ok(evidence) => validate_lifecycle_evidence(&evidence).map(|()| evidence),
        Err(error) => Err(error),
    };
    // Both shutdown methods own their listener/process/task joins.  Await
    // them directly instead of putting consuming futures behind an outer
    // timeout that would drop the owner before its nested joins complete.
    let cluster_cleanup = cluster.shutdown().await;
    let harness_cleanup = harness.shutdown().await;
    finish_lifecycle(scenario, cluster_cleanup, harness_cleanup)
}

fn finish_lifecycle(
    scenario: Result<LifecycleEvidence>,
    cluster_cleanup: Result<()>,
    harness_cleanup: Result<()>,
) -> Result<LifecycleEvidence> {
    let mut cleanup_errors = Vec::new();
    if let Err(error) = cluster_cleanup {
        cleanup_errors.push(format!("relay cleanup: {error}"));
    }
    if let Err(error) = harness_cleanup {
        cleanup_errors.push(format!("harness cleanup: {error}"));
    }
    match scenario {
        Err(error) => Err(with_cleanup_errors(error, cleanup_errors)),
        Ok(evidence) if cleanup_errors.is_empty() => Ok(evidence),
        Ok(_) => Err(HarnessError::Process(format!(
            "stream lifecycle cleanup failed: {}",
            cleanup_errors.join("; ")
        ))),
    }
}

struct LifecycleResources {
    process: Option<ManagedProcess>,
    stalled: Option<ConsumerStream>,
    sibling: Option<ConsumerStream>,
    fresh: Option<ConsumerStream>,
    consumer_proxy: Option<ProxyHandle>,
}

impl LifecycleResources {
    const fn new() -> Self {
        Self {
            process: None,
            stalled: None,
            sibling: None,
            fresh: None,
            consumer_proxy: None,
        }
    }

    async fn cleanup_until(&mut self, deadline: Instant) -> Result<()> {
        // The stalled socket has deliberately not been read.  Dropping it is
        // the final transport cancellation after the bounded Close attempt;
        // calling ConsumerStream::close here could wait on the blackholed
        // response and obscure the scenario's shared deadline.
        drop(self.stalled.take());
        let mut first_error = None;
        if let Some(mut stream) = self.sibling.take()
            && let Err(error) = close_consumer_stream_until(&mut stream, deadline, "sibling").await
        {
            first_error = Some(error);
        }
        if let Some(mut stream) = self.fresh.take()
            && let Err(error) = close_consumer_stream_until(&mut stream, deadline, "fresh").await
        {
            first_error.get_or_insert(error);
        }
        // Do not put ManagedProcess::shutdown behind a cancellable outer
        // timeout. It owns the child, kills after its grace period, waits for
        // reaping, and joins output drains; retaining the local owner here
        // guarantees no child is detached when the shared cleanup deadline
        // expires while a stream close is blackholed.
        if let Some(process) = self.process.take() {
            let grace = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(5));
            if let Err(error) = process.shutdown(grace).await {
                first_error.get_or_insert_with(|| {
                    HarnessError::Process(format!("joining stream lifecycle CLI: {error}"))
                });
            }
        }
        if let Some(proxy) = self.consumer_proxy.take()
            && let Err(error) = shutdown_consumer_proxy_until(proxy, deadline).await
        {
            first_error.get_or_insert(error);
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

async fn close_consumer_stream_until(
    stream: &mut ConsumerStream,
    deadline: Instant,
    label: &str,
) -> Result<()> {
    timeout_at(deadline.into(), stream.close())
        .await
        .map_err(|_| {
            HarnessError::Timeout(format!(
                "stream lifecycle {label} consumer close exceeded its cleanup deadline"
            ))
        })??;
    Ok(())
}

async fn shutdown_consumer_proxy_until(mut proxy: ProxyHandle, deadline: Instant) -> Result<()> {
    match proxy.shutdown_until(deadline.into()).await {
        Ok(()) => Ok(()),
        Err(graceful_error) => {
            // `ProxyHandle::shutdown_until` retains its JoinHandle when the
            // forced grace period expires.  Finish the join on the same owned
            // handle before returning; dropping it here would abort and
            // detach the accept task.
            match proxy.shutdown().await {
                Ok(()) => Err(HarnessError::Process(format!(
                    "consumer proxy cleanup exceeded its shared deadline: {graceful_error}; forced join completed"
                ))),
                Err(forced_error) => Err(HarnessError::Process(format!(
                    "consumer proxy cleanup failed: {graceful_error}; forced join failed: {forced_error}"
                ))),
            }
        }
    }
}

async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
) -> Result<LifecycleEvidence> {
    let started = Instant::now();
    let deadline = Instant::now() + SCENARIO_TIMEOUT;
    let mut resources = LifecycleResources::new();
    let diagnostic_device_id = harness.topology.devices_a.first().map(|device| device.id);
    let scenario = match run_phase(cluster, harness, deadline, &mut resources).await {
        Ok(evidence) => Ok(evidence),
        Err(error) => {
            Err(
                augment_failure_diagnostics(error, cluster, &mut resources, diagnostic_device_id)
                    .await,
            )
        }
    };
    let cleanup_deadline = Instant::now() + CLEANUP_TIMEOUT;
    let resource_cleanup = resources.cleanup_until(cleanup_deadline).await;
    let mut cleanup_errors = Vec::new();
    if let Err(error) = resource_cleanup {
        cleanup_errors.push(format!("client resource cleanup: {error}"));
    }
    let fanout = match timeout_at(
        cleanup_deadline.into(),
        wait_for_fanout_drained(&cluster.device_fanout, "stream lifecycle"),
    )
    .await
    {
        Ok(Ok(diagnostics)) => Some(diagnostics),
        Ok(Err(error)) => {
            cleanup_errors.push(format!("fanout cleanup: {error}"));
            None
        }
        Err(_) => {
            cleanup_errors.push("fanout cleanup: stream lifecycle fanout cleanup timed out".into());
            None
        }
    };
    match scenario {
        Err(error) => Err(with_cleanup_errors(error, cleanup_errors)),
        Ok(mut evidence) if cleanup_errors.is_empty() => {
            let Some(fanout) = fanout else {
                return Err(HarnessError::Process(
                    "stream lifecycle fanout diagnostics were unavailable".into(),
                ));
            };
            evidence.fanout_peak_open = fanout.peak_open;
            evidence.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            Ok(evidence)
        }
        Ok(_) => Err(HarnessError::Process(format!(
            "stream lifecycle cleanup failed: {}",
            cleanup_errors.join("; ")
        ))),
    }
}

const CLI_DIAGNOSTIC_LINE_LIMIT: usize = 32;
const CLI_DIAGNOSTIC_VALUE_LIMIT: usize = 4;
const CLI_DIAGNOSTIC_TOKEN_LIMIT: usize = 48;

/// Add bounded, payload-free state to a lifecycle failure before resource
/// cleanup consumes the client process and relay sessions.  This is
/// investigation evidence only; it does not change any acceptance predicate.
async fn augment_failure_diagnostics(
    primary: HarnessError,
    cluster: &ProductionCluster,
    resources: &mut LifecycleResources,
    device_id: Option<Uuid>,
) -> HarnessError {
    let owner = match cluster.relay("relay-a") {
        Ok(relay) => diagnostic_relay_snapshot(relay, "owner", device_id).await,
        Err(error) => format!("owner_relay_error={error}"),
    };
    let ingress = match cluster.relay("relay-b") {
        Ok(relay) => diagnostic_relay_snapshot(relay, "ingress", device_id).await,
        Err(error) => format!("ingress_relay_error={error}"),
    };
    let accepted_consumer_send_buffer_effective_bytes = cluster
        .relay("relay-b")
        .ok()
        .and_then(super::ProductionRelay::accepted_consumer_send_buffer_bytes)
        .map_or_else(|| "unknown".to_owned(), |bytes| bytes.to_string());
    let cli = match resources.process.as_mut() {
        Some(process) => cli_terminal_diagnostic(process).await,
        None => "cli_process=absent".to_owned(),
    };
    HarnessError::Process(format!(
        "{primary}; lifecycle failure diagnostics: lifecycle_rotation_interval_seconds={}; target_receive_buffer_bytes={STALL_TARGET_RECEIVE_BUFFER_BYTES}; relay_b_consumer_send_buffer_requested_bytes={STALL_CONSUMER_SEND_BUFFER_BYTES}; relay_b_accepted_consumer_send_buffer_effective_bytes={accepted_consumer_send_buffer_effective_bytes}; accepted_buffer_observation_only=true; writer_timeout_required=true; {owner}; {ingress}; {cli}",
        lifecycle_rotation_policy().interval_seconds,
    ))
}

async fn diagnostic_relay_snapshot(
    relay: &super::ProductionRelay,
    label: &str,
    device_id: Option<Uuid>,
) -> String {
    match timeout(DIAGNOSTIC_TIMEOUT, relay.snapshot()).await {
        Ok(Ok(snapshot)) => relay_snapshot_diagnostic(label, &snapshot, device_id),
        Ok(Err(error)) => format!("{label}_snapshot_error={error}"),
        Err(_) => format!("{label}_snapshot_timeout=true"),
    }
}

fn lifecycle_rotation_policy() -> RotationConfig {
    RotationConfig::default()
}

fn relay_snapshot_diagnostic(
    label: &str,
    snapshot: &RelaySnapshot,
    device_id: Option<Uuid>,
) -> String {
    let device = snapshot
        .sessions
        .iter()
        .find(|session| device_id.is_none_or(|expected| session.device_id == expected.to_string()));
    let aggregate_queue_bytes = snapshot
        .sessions
        .iter()
        .map(|session| session.queue_bytes)
        .fold(0_usize, |total, value| total.saturating_add(value));
    let aggregate_queue_messages = snapshot
        .sessions
        .iter()
        .map(|session| session.queue_messages)
        .fold(0_usize, |total, value| total.saturating_add(value));
    let session = device.map_or_else(
        || {
            "session=missing,phase=unknown,queue_bytes=unknown,queue_messages=unknown,streams=unknown"
                .to_owned()
        },
        |session| {
            format!(
                "session=present,phase={},queue_bytes={},queue_messages={},streams={}",
                session.phase,
                session.queue_bytes,
                session.queue_messages,
                session.streams.len()
            )
        },
    );
    let peer_transport = &snapshot.peer_transport_diagnostics;
    let last_owner_send = peer_transport_event_diagnostic(peer_transport.last_owner_send.as_ref());
    let last_ingress_receive =
        peer_transport_event_diagnostic(peer_transport.last_ingress_receive.as_ref());
    let peer_consumer = &snapshot.peer_consumer_diagnostics;
    let last_peer_consumer_ingress_receive =
        peer_consumer_event_diagnostic(peer_consumer.last_ingress_receive.as_ref());
    let last_peer_consumer_owner_receive =
        peer_consumer_event_diagnostic(peer_consumer.last_owner_receive.as_ref());
    let last_peer_consumer_ingress_send =
        peer_consumer_event_diagnostic(peer_consumer.last_ingress_send.as_ref());
    let last_peer_consumer_owner_send =
        peer_consumer_event_diagnostic(peer_consumer.last_owner_send.as_ref());
    format!(
        "{label}_{session},{label}_aggregate_queue_bytes={aggregate_queue_bytes},{label}_aggregate_queue_messages={aggregate_queue_messages},{label}_session_count={},{label}_dispatches={},{label}_response_write_timeout_count={},{label}_peer_owner_send_count={},{label}_peer_ingress_receive_count={},{label}_peer_last_owner_send={},{label}_peer_last_ingress_receive={},peer_consumer_ingress_send_count={},peer_consumer_ingress_receive_count={},peer_consumer_owner_send_count={},peer_consumer_owner_receive_count={},peer_consumer_last_ingress_send={},peer_consumer_last_ingress_receive={},peer_consumer_last_owner_send={},peer_consumer_last_owner_receive={}",
        snapshot.sessions.len(),
        snapshot.lifetime_application_dispatches,
        snapshot.consumer_write_diagnostics.timeout_count,
        peer_transport.owner_send_count,
        peer_transport.ingress_receive_count,
        last_owner_send,
        last_ingress_receive,
        peer_consumer.ingress_send_count,
        peer_consumer.ingress_receive_count,
        peer_consumer.owner_send_count,
        peer_consumer.owner_receive_count,
        last_peer_consumer_ingress_send,
        last_peer_consumer_ingress_receive,
        last_peer_consumer_owner_send,
        last_peer_consumer_owner_receive,
    )
}

fn peer_consumer_event_diagnostic(
    event: Option<&tunnel_relay::PeerConsumerDiagnosticEventSnapshot>,
) -> String {
    event.map_or_else(
        || "none".to_owned(),
        |event| {
            format!(
                "sequence={},observed_at_ms={},tenant_id={},device_id={},session_id={},epoch={},service_id={},request_id={},role={},outcome={},h3_code={}",
                event.sequence,
                event.observed_at_ms,
                event.tenant_id,
                event.device_id,
                event.session_id,
                event.epoch,
                event.service_id,
                event.request_id,
                event.role.as_str(),
                event.outcome.as_str(),
                event
                    .h3_code
                    .map_or("none", tunnel_relay::PeerConsumerDiagnosticH3Code::as_str),
            )
        },
    )
}

fn peer_transport_event_diagnostic(event: Option<&PeerTransportDiagnosticEventSnapshot>) -> String {
    event.map_or_else(
        || "none".to_owned(),
        |event| {
            format!(
                "sequence={},device_id={},session_id={},epoch={},generation={},connection_id={},role={},outcome={}",
                event.sequence,
                event.device_id,
                event.session_id,
                event.epoch,
                event.generation,
                event.connection_id,
                event.role.as_str(),
                event.outcome.as_str(),
            )
        },
    )
}

async fn cli_terminal_diagnostic(process: &mut ManagedProcess) -> String {
    let terminal = match process.try_wait() {
        Ok(Some(status)) => format!(
            "state=exited,success={},exit_code={},signal={}",
            status.success(),
            status
                .code()
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            process_signal(status).map_or_else(|| "none".to_owned(), |signal| signal.to_string())
        ),
        Ok(None) => "state=running".to_owned(),
        Err(_) => "state=unknown".to_owned(),
    };

    // Give the bounded output drains one scheduling opportunity after a
    // terminal client state, without waiting on the client or extending the
    // scenario's workload.
    tokio::task::yield_now().await;
    let mut fields = ClientDiagnosticFields::default();
    collect_client_json_errors(&process.stdout(), &mut fields);
    collect_client_json_errors(&process.stderr(), &mut fields);
    format!(
        "cli_terminal={terminal},cli_error_records={},cli_error_codes={:?},cli_error_retryable={:?},cli_error_phases={:?},cli_transport_causes={:?},cli_recovery_triggers={:?},cli_protocol_causes={:?}",
        fields.records,
        fields.codes,
        fields.retryable,
        fields.phases,
        fields.transport_causes,
        fields.recovery_triggers,
        fields.protocol_causes,
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
    transport_causes: Vec<String>,
    recovery_triggers: Vec<String>,
    protocol_causes: Vec<String>,
}

fn collect_client_json_errors(bytes: &[u8], fields: &mut ClientDiagnosticFields) {
    for line in String::from_utf8_lossy(bytes)
        .lines()
        .take(CLI_DIAGNOSTIC_LINE_LIMIT)
    {
        if line.len() > 8 * 1024 {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
            continue;
        };
        let Some(error) = value.get("error").and_then(serde_json::Value::as_object) else {
            continue;
        };
        fields.records = fields.records.saturating_add(1);
        push_diagnostic_token(&mut fields.codes, error.get("code"));
        if let Some(message) = error.get("message").and_then(serde_json::Value::as_str) {
            match error.get("code").and_then(serde_json::Value::as_str) {
                Some("TRANSPORT_ERROR") => {
                    push_transport_cause(&mut fields.transport_causes, message);
                    if fields.recovery_triggers.len() < CLI_DIAGNOSTIC_VALUE_LIMIT
                        && let Some(trigger) = classify_recovery_trigger(message)
                    {
                        fields.recovery_triggers.push(trigger);
                    }
                }
                Some("PROTOCOL_ERROR") => {
                    push_protocol_cause(&mut fields.protocol_causes, message);
                    if fields.recovery_triggers.len() < CLI_DIAGNOSTIC_VALUE_LIMIT
                        && let Some(trigger) = classify_recovery_trigger(message)
                    {
                        fields.recovery_triggers.push(trigger);
                    }
                }
                _ => {}
            }
        }
        if let Some(retryable) = error.get("retryable").and_then(serde_json::Value::as_bool)
            && fields.retryable.len() < CLI_DIAGNOSTIC_VALUE_LIMIT
        {
            fields.retryable.push(retryable);
        }
        let phase = error.get("phase").or_else(|| value.get("phase"));
        push_diagnostic_token(&mut fields.phases, phase);
    }
}

fn push_diagnostic_token(values: &mut Vec<String>, value: Option<&serde_json::Value>) {
    if values.len() >= CLI_DIAGNOSTIC_VALUE_LIMIT {
        return;
    }
    let Some(value) = value.and_then(serde_json::Value::as_str) else {
        return;
    };
    if value.is_empty()
        || value.len() > CLI_DIAGNOSTIC_TOKEN_LIMIT
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return;
    }
    values.push(value.to_owned());
}

fn push_transport_cause(values: &mut Vec<String>, message: &str) {
    if values.len() >= CLI_DIAGNOSTIC_VALUE_LIMIT {
        return;
    }
    values.push(classify_transport_cause(message).to_owned());
}

fn push_protocol_cause(values: &mut Vec<String>, message: &str) {
    if values.len() >= CLI_DIAGNOSTIC_VALUE_LIMIT {
        return;
    }
    values.push(classify_protocol_cause(message).to_owned());
}

/// Convert the client's safe transport message into a closed diagnostic
/// category.  The raw message is deliberately omitted because the category
/// is enough to distinguish a control/data read or writer loss without
/// copying transport details into the harness failure.
fn classify_transport_cause(message: &str) -> &'static str {
    let base = message
        .split_once("; recovery_trigger=")
        .map_or(message, |(base, _)| base);
    if matches!(
        base,
        "data rotation failed: bounded rotation state failure"
            | "data rotation failed: owner abort decision deadline expired"
            | "data rotation failed: retained recovery required"
            | "data rotation failed: rotation reached terminal state"
    ) {
        return "data_rotation";
    }
    if matches!(
        base,
        "retained recovery failed: bounded rotation state failure"
            | "retained recovery failed: recovery episode deadline expired"
            | "retained recovery failed: recovery candidate phase deadline expired"
            | "retained recovery failed: retained recovery required"
            | "retained recovery failed: rotation reached terminal state"
    ) {
        return "retained_recovery";
    }
    let Some(scope) = base.strip_suffix(" failed") else {
        return "unknown";
    };
    match scope {
        "control handshake" => "control_handshake",
        "control pong" => "control_pong",
        "control read" => "control_read",
        "control write" => "control_write",
        "data attachment" => "data_attachment",
        "data read" => "data_read",
        "session" => "session",
        "websocket handshake" => "websocket_handshake",
        "websocket request" => "websocket_request",
        "writer" => "writer",
        "active data carrier" => "active_data_carrier",
        "active data writer" => "active_data_writer",
        "candidate data carrier" => "candidate_data_carrier",
        "data actor" => "data_actor",
        "owner fencing handshake" => "owner_fencing_handshake",
        "recovery active carrier" => "recovery_active_carrier",
        "recovery candidate" => "recovery_candidate",
        "recovery old carrier" => "recovery_old_carrier",
        "recovery pending carrier" => "recovery_pending_carrier",
        "recovery retiring carrier" => "recovery_retiring_carrier",
        "retired data carrier" => "retired_data_carrier",
        "stream forget barrier" => "stream_forget_barrier",
        _ => "unknown",
    }
}

/// Extract the client's closed recovery-trigger tuple without preserving the
/// original transport text.  This parser is intentionally allowlisted and
/// bounded because the message is emitted into a harness failure summary.
fn classify_recovery_trigger(message: &str) -> Option<String> {
    let (_, metadata) = message.split_once("; recovery_trigger=")?;
    let (trigger, metadata) = metadata.split_once("; recovery_role=")?;
    let (role, generation) = metadata.split_once("; recovery_generation=")?;
    let trigger = match trigger {
        "data_writer_failed" | "data_reader_closed" | "data_writer_closed" => trigger,
        _ => return None,
    };
    let role = match role {
        "active"
        | "candidate"
        | "retiring"
        | "pending_candidate"
        | "pending_candidate_close"
        | "recovery_closed"
        | "unknown" => role,
        _ => return None,
    };
    let generation = generation.parse::<u64>().ok()?;
    Some(format!("{trigger}/{role}/g{generation}"))
}

/// Reduce the client's safe protocol message to a bounded source category.
/// The raw message is deliberately omitted because it may contain codec or
/// validation detail that is not needed in the harness failure.
pub(super) fn classify_protocol_cause(message: &str) -> &'static str {
    match message {
        // STREAM_FORGET failures are emitted from a closed, allowlisted set
        // of connector-side validation branches. Keep their diagnostics
        // category-only: the stream id, operation id, cursor values, and
        // sequence error text must never enter the harness summary.
        "STREAM_FORGET context mismatch" => "stream_forget_context",
        "STREAM_FORGET operation identity mismatch" => "stream_forget_operation",
        "STREAM_FORGET unknown stream or OPEN journal entry" => "stream_forget_unknown",
        "STREAM_FORGET no-stream evidence mismatch" => "stream_forget_no_stream",
        "STREAM_FORGET operation or terminal evidence mismatch" => "stream_forget_terminal",
        "STREAM_FORGET owner direction mismatch" => "stream_forget_direction",
        "STREAM_FORGET owner sender evidence is incomplete" => "stream_forget_sender_incomplete",
        "STREAM_FORGET owner and connector receive evidence mismatch" => {
            "stream_forget_receive_mismatch"
        }
        "STREAM_FORGET connector sender evidence is incomplete" => {
            "stream_forget_connector_incomplete"
        }
        "STREAM_FORGET before local adapter input debt drained" => "stream_forget_adapter_debt",
        "STREAM_FORGET before deferred output and control debt drained" => {
            "stream_forget_output_debt"
        }
        "STREAM_FORGET terminal proof did not converge before its deadline" => {
            "stream_forget_terminal_proof"
        }
        "STREAM_FORGET changed while carrier barriers were pending" => {
            "stream_forget_barrier_mutation"
        }
        _ if message.starts_with("STREAM_FORGET sequence mismatch: ") => "stream_forget_sequence",
        "binary message on control socket" => "control_message_kind",
        "text message on data socket" => "data_message_kind",
        "M2 control message received while using the explicit M1 profile" => {
            "unexpected_m2_control"
        }
        "OPEN context does not match the authenticated session" => "open_context",
        "authorization confirmation context mismatch" => "authorization_context",
        "authorization invalidation context mismatch" => "authorization_invalidation_context",
        "CANCEL context mismatch" => "cancel_context",
        "PING context mismatch" => "ping_context",
        "data frame epoch does not match session" => "data_epoch",
        "data frame generation does not match active socket" => "data_generation",
        "piggybacked data ACK exceeds emitted sequence" | "data ACK exceeds emitted sequence" => {
            "data_ack_sequence"
        }
        "duplicate or post-FIN DATA frame"
        | "duplicate or repeated FIN frame"
        | "RESET sequence is stale, gapped, or follows FIN"
        | "DATA received after local FIN" => "data_sequence",
        "stream ID must be nonzero" => "sequence_stream_id",
        _ if message.starts_with("frame addresses stream ") && message.contains(", expected ") => {
            "sequence_stream_mismatch"
        }
        _ if message.starts_with("next emitted sequence must ") => "sequence_not_next",
        _ if message.starts_with("received sequence gap: ") => "sequence_gap",
        _ if message.starts_with("duplicate sequence ") => "sequence_duplicate_conflict",
        _ if message.starts_with("cannot process ")
            && message.contains(" after terminal state ") =>
        {
            "sequence_after_terminal"
        }
        _ if message.starts_with("byte credit exceeded: ") => "sequence_credit_exceeded",
        _ if message.starts_with("byte credit decreased from ") => "sequence_credit_decreased",
        _ if message.starts_with("acknowledgement ")
            && message.contains(" exceeds last emitted ") =>
        {
            "sequence_ack_beyond_sent"
        }
        _ if message.starts_with("acknowledgement ") && message.contains(" exceeds received ") => {
            "sequence_ack_beyond_received"
        }
        _ if message.starts_with("delivery cursor ") && message.contains(" exceeds received ") => {
            "sequence_delivery_beyond_received"
        }
        _ if message.starts_with("counter ") && message.ends_with(" is exhausted") => {
            "sequence_counter_exhausted"
        }
        _ if message.starts_with("receive byte counter exhausted") => {
            "sequence_receive_counter_exhausted"
        }
        _ if message.starts_with("receive credit exhausted") => "sequence_receive_credit_exhausted",
        _ if message.starts_with("window update for unknown stream") => {
            "sequence_window_unknown_stream"
        }
        "echo output length overflow"
        | "outbound sequence exhausted"
        | "echo output frame index overflow" => "stream_state",
        "ordinary rotation message entered recovery journal" => "recovery_journal_scope",
        "ordinary ROTATE_PREPARE during retained recovery" => "recovery_rotation_interleave",
        // Every `ROTATE_*` category below comes from a fixed connector-side
        // source string.  Keep the exact handler/validation branch while
        // omitting attempt IDs, message IDs, and state-machine details.
        _ if message.starts_with("ROTATE_") => classify_rotation_protocol_cause(message),
        _ if message.starts_with("recovery ")
            || message.starts_with("RECOVERY")
            || message.starts_with("RESUME")
            || message.starts_with("RESUMED") =>
        {
            classify_recovery_protocol_cause(message)
        }
        _ if message.starts_with("invalid OWNER_FENCE") || message.starts_with("OWNER_FENCE") => {
            "owner_fence_protocol"
        }
        _ if message.starts_with("expected ")
            || message.starts_with("relay selected ")
            || message.starts_with("relay did not ") =>
        {
            "control_negotiation"
        }
        _ if message.starts_with("invalid ")
            || message.contains("codec")
            || message.contains("context") =>
        {
            "protocol_validation"
        }
        _ => "unknown",
    }
}

fn classify_rotation_protocol_cause(message: &str) -> &'static str {
    match message {
        "ROTATE_PREPARE identity mismatch" => "rotation_prepare_identity",
        "ROTATE_PREPARE changed while a candidate is pending" => {
            "rotation_prepare_candidate_pending"
        }
        "ROTATE_QUIESCE reply correlation mismatch" => "rotation_quiesce_reply",
        "ROTATE_QUIESCE semantic duplicate changed message ID" => {
            "rotation_quiesce_duplicate_message"
        }
        "ROTATE_QUIESCE attempt changed while a barrier is pending" => "rotation_quiesce_attempt",
        "ROTATE_QUIESCE in the wrong phase" => "rotation_quiesce_phase",
        "ROTATE_QUIESCE candidate identity mismatch" => "rotation_quiesce_candidate",
        "ROTATE_FROZEN reply correlation mismatch" => "rotation_frozen_reply",
        "ROTATE_FROZEN semantic duplicate changed message ID" => {
            "rotation_frozen_duplicate_message"
        }
        "ROTATE_DRAINED without an attempt" => "rotation_drained_missing_attempt",
        "ROTATE_DRAINED attempt mismatch" => "rotation_drained_attempt",
        "ROTATE_DRAINED reply correlation mismatch" => "rotation_drained_reply",
        "ROTATE_DRAINED semantic duplicate changed message ID" => {
            "rotation_drained_duplicate_message"
        }
        "ROTATE_COMMIT without an attempt" => "rotation_commit_missing_attempt",
        "ROTATE_COMMIT attempt mismatch" => "rotation_commit_attempt",
        "ROTATE_COMMIT reply correlation mismatch" => "rotation_commit_reply",
        "ROTATE_COMMIT semantic duplicate changed message ID" => {
            "rotation_commit_duplicate_message"
        }
        "ROTATE_COMMIT snapshot mismatch" => "rotation_commit_snapshot",
        "ROTATE_COMMIT without matching candidate carrier" => "rotation_commit_candidate",
        "ROTATE_COMMIT without candidate carrier" => "rotation_commit_missing_candidate",
        "ROTATE_RETIRE without an attempt" => "rotation_retire_missing_attempt",
        "ROTATE_RETIRE attempt mismatch" => "rotation_retire_attempt",
        "ROTATE_RETIRE reply correlation mismatch" => "rotation_retire_reply",
        "ROTATE_RETIRE semantic duplicate changed message ID" => {
            "rotation_retire_duplicate_message"
        }
        "ROTATE_RETIRE in the wrong phase" => "rotation_retire_phase",
        "ROTATE_RETIRE snapshot mismatch" => "rotation_retire_snapshot",
        "ROTATE_RETIRE without old carrier" => "rotation_retire_missing_old_carrier",
        "ROTATE_COMPLETE without an attempt" => "rotation_complete_missing_attempt",
        "ROTATE_COMPLETE identity mismatch" => "rotation_complete_identity",
        "ROTATE_COMPLETE reply correlation mismatch" => "rotation_complete_reply",
        "ROTATE_COMPLETE did not activate carrier" => "rotation_complete_activation",
        "ROTATE_ABORT reply correlation mismatch" => "rotation_abort_reply",
        "ROTATE_ABORT without an attempt" => "rotation_abort_missing_attempt",
        "ROTATE_ABORT attempt mismatch" => "rotation_abort_attempt",
        "ROTATE_ABORT semantic duplicate changed message ID" => "rotation_abort_duplicate_message",
        "ROTATE_ABORT candidate closure attempt mismatch" => "rotation_abort_candidate",
        "ROTATE_ABORTED without an active abort attempt" => "rotation_aborted_missing_attempt",
        "ROTATE_ABORTED attempt mismatch" => "rotation_aborted_attempt",
        "ROTATE_ABORTED outside the abort phase" => "rotation_aborted_phase",
        "ROTATE_ABORTED reply correlation mismatch" => "rotation_aborted_reply",
        _ if message.starts_with("ROTATE_ABORTED rejected: ") => "rotation_aborted_rejected",
        "ROTATE_ABORTED did not complete bilateral closure" => "rotation_aborted_closure",
        _ => "rotation_protocol_unknown",
    }
}

fn classify_recovery_protocol_cause(message: &str) -> &'static str {
    let message = message
        .split_once("; recovery_trigger=")
        .map_or(message, |(base, _)| base);
    match message {
        "recovery prepare deadline overflow" => "recovery_prepare_deadline_overflow",
        "recovery prepare deadline expired" => "recovery_prepare_deadline_expired",
        "recovery response was not journaled" => "recovery_response_not_journaled",
        "recovery candidate PREPARE does not bind the episode" => {
            "recovery_candidate_prepare_binding"
        }
        "recovery DATA_READY session identity mismatch" => "recovery_data_ready_session",
        "recovery DATA_READY does not bind the candidate" => "recovery_data_ready_candidate",
        "unexpected recovery rotation message" => "recovery_message_order",
        "active recovery journal disappeared" => "recovery_active_journal_missing",
        "completed recovery journal disappeared" => "recovery_completed_journal_missing",
        "new message arrived for a completed recovery candidate" => "recovery_completed_replay",
        "RECOVERY_BEGIN session identity mismatch" => "recovery_begin_session",
        "RECOVERY_BEGIN exceeds the local recovery budget" => "recovery_begin_budget",
        "RECOVERY_BEGIN arrived after the retained episode deadline" => "recovery_begin_expired",
        "RECOVERY_BEGIN changed a completed recovery episode" => {
            "recovery_begin_completed_mutation"
        }
        "RECOVERY_BEGIN changed while a recovery episode is active"
        | "RECOVERY_BEGIN changed an active recovery episode" => "recovery_begin_phase",
        "RECOVERY_BEGIN changed the immutable episode roster" => "recovery_begin_roster",
        "RECOVERY_BEGIN attempt is not the current retry" => "recovery_begin_attempt",
        "RECOVERY_BEGIN changed the retained transport anchor" => "recovery_begin_anchor",
        "RECOVERY_BEGIN extends the existing recovery deadline" => {
            "recovery_begin_deadline_extension"
        }
        "recovery deadline overflow" => "recovery_deadline_overflow",
        "RECOVERY_BEGIN duplicate has no matching retained state" => "recovery_begin_duplicate",
        "recovery begin without a rotation anchor" => "recovery_begin_anchor_missing",
        "RECOVERY_CLOSED without RECOVERY_BEGIN" => "recovery_closed_order",
        "RECOVERY_CLOSED changed the completed recovery episode" => {
            "recovery_closed_completed_mutation"
        }
        "completed RECOVERY_CLOSED was not retained in the journal" => {
            "recovery_closed_journal_missing"
        }
        "RECOVERY_CLOSED context mismatch" => "recovery_closed_context",
        "RECOVERY_CLOSED physical connection set mismatch" => "recovery_closed_connections",
        "RECOVERY_CLOSED changed after acknowledgement" => "recovery_closed_ack_mutation",
        "recovery attachment without RECOVERY_BEGIN" => "recovery_attachment_order",
        "recovery attachment binding mismatch" => "recovery_attachment_binding",
        "recovery candidate installed outside recovery phase" => "recovery_candidate_phase",
        "RESUME without RECOVERY_BEGIN" => "recovery_resume_order",
        "RESUME does not bind the completed recovery episode" => "recovery_resume_episode",
        "RESUME changed a completed recovery request" => "recovery_resume_completed_mutation",
        "completed recovery request was not retained in the journal" => {
            "recovery_resume_journal_missing"
        }
        "RESUME recovery attempt mismatch" => "recovery_resume_attempt",
        "RESUME recovery snapshot mismatch" => "recovery_resume_snapshot",
        "RESUME recovery remaining budget is zero" => "recovery_resume_remaining_zero",
        "RESUME recovery remaining budget exceeds local deadline"
        | "RESUME recovery remaining budget exceeds protocol bound" => {
            "recovery_resume_remaining_budget"
        }
        "RESUME recovery local deadline expired" => "recovery_resume_deadline_expired",
        "RESUME recovery context or deadline mismatch" => "recovery_resume_context",
        "RESUME reply_to does not bind the recovery stage" => "recovery_resume_reply",
        "RESUME entries do not match the immutable roster" => "recovery_resume_roster",
        "duplicate RESUME snapshot changed its message" => "recovery_resume_snapshot_mutation",
        "duplicate RESUME ready changed its message" => "recovery_resume_ready_mutation",
        "connector received peer-originated RESUMED" => "recovery_resumed_direction",
        "RESUMED without retained recovery" => "recovery_resumed_order",
        "recovery snapshots arrived before candidate carrier" => "recovery_candidate_missing",
        "missing recovery state" => "recovery_state_missing",
        "recovery state disappeared" => "recovery_state_disappeared",
        "recovery candidate disappeared" => "recovery_candidate_missing",
        "recovery candidate identity mismatch" => "recovery_candidate_identity",
        _ if message.starts_with("recovery transport loss rejected: ") => {
            "recovery_transport_loss_rejected"
        }
        "recovery closure rejected: connection is not allocated" => {
            "recovery_closure_not_allocated"
        }
        _ if message.starts_with("recovery closure rejected: invalid phase ") => {
            "recovery_closure_phase"
        }
        "recovery closure rejected: incomplete physical closure evidence" => {
            "recovery_closure_incomplete"
        }
        "recovery closure rejected: closure evidence references another connection" => {
            "recovery_closure_connection_mismatch"
        }
        _ if message.starts_with("recovery closure rejected: ") => "recovery_closure_rejected",
        _ if message.starts_with("recovery begin rejected: ") => "recovery_begin_rejected",
        _ if message.starts_with("recovery candidate reservation rejected: ") => {
            "recovery_candidate_reservation_rejected"
        }
        _ if message.starts_with("recovery roster contains unknown stream ") => {
            "recovery_roster_stream_missing"
        }
        _ if message.starts_with("recovery peer snapshot omitted stream ") => {
            "recovery_snapshot_stream_missing"
        }
        _ if message.starts_with("recovery activation rejected: ") => {
            "recovery_activation_rejected"
        }
        _ if message.starts_with("recovery candidate closure rejected: ") => {
            "recovery_candidate_closure_rejected"
        }
        _ if message.starts_with("missing recovery plan for stream ") => {
            "recovery_plan_stream_missing"
        }
        _ => "recovery_unknown",
    }
}

async fn run_phase(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    deadline: Instant,
    resources: &mut LifecycleResources,
) -> Result<LifecycleEvidence> {
    let ready = cluster
        .relays
        .iter()
        .filter(|relay| matches!(relay.membership.readiness(), MembershipReadiness::Ready))
        .count();
    if cluster.relays.len() != 3 || ready != 3 {
        return Err(HarnessError::Process(format!(
            "stream lifecycle requires three Ready relays, observed relays={} ready={ready}",
            cluster.relays.len()
        )));
    }
    let relay_b_consumer_addr = cluster.relay("relay-b")?.consumer_addr()?;
    let relay_c_consumer_addr = cluster.relay("relay-c")?.consumer_addr()?;
    let consumer_proxy = timeout_at(
        deadline.into(),
        TcpProxy::bind(
            relay_b_consumer_addr,
            ProxyConfig {
                target_receive_buffer_bytes: Some(STALL_TARGET_RECEIVE_BUFFER_BYTES),
                ..ProxyConfig::default()
            },
        ),
    )
    .await
    .map_err(|_| HarnessError::Timeout("lifecycle consumer proxy bind timed out".into()))??;
    let consumer_proxy_addr = consumer_proxy.local_addr();
    resources.consumer_proxy = Some(consumer_proxy);
    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("tenant A has no lifecycle device".into()))?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("lifecycle device has no echo service".into()))?;
    let canary = format!("m7-lifecycle:{}", device.id);
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
    // This gate isolates physical writer cleanup under the normal policy; it
    // supplies no accelerated/default rotation-under-stall completion proof.
    // The separate rotation-pressure gate remains required for that behavior.
    profile.config.rotation = lifecycle_rotation_policy();
    profile
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("lifecycle client config: {error}")))?;
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(180),
            ..OidcTokenOptions::default()
        },
    )?;

    let (process, stalled) = timeout_at(
        deadline.into(),
        start_cli_smoke(
            harness,
            cluster.device_fanout.local_addr(),
            consumer_proxy_addr,
            &profile,
            &token,
            device.id,
            service_id,
        ),
    )
    .await
    .map_err(|_| {
        HarnessError::Timeout("lifecycle CLI startup exceeded the scenario deadline".into())
    })??;
    resources.process = Some(process);
    resources.stalled = Some(stalled);
    timeout_at(
        deadline.into(),
        resources
            .stalled
            .as_mut()
            .ok_or_else(|| HarnessError::Process("lifecycle stalled stream was lost".into()))?
            .round_trip(b"m7-lifecycle-baseline-stalled", canary.as_bytes()),
    )
    .await
    .map_err(|_| HarnessError::Timeout("lifecycle stalled baseline timed out".into()))??;

    let owner = timeout_at(
        deadline.into(),
        cluster
            .catalog
            .current_owner(device.tenant_id, device.id, Utc::now()),
    )
    .await
    .map_err(|_| HarnessError::Timeout("reading lifecycle owner exceeded its deadline".into()))?
    .map_err(|error| HarnessError::Redis(format!("reading lifecycle owner: {error}")))?
    .ok_or_else(|| HarnessError::Process("lifecycle CLI did not retain an owner".into()))?;
    if owner.token.tenant_id != device.tenant_id
        || owner.token.device_id != device.id
        || owner.token.node_id != "relay-a"
    {
        return Err(HarnessError::Process(format!(
            "lifecycle owner was not the expected relay-a scope: node={}, epoch={}",
            owner.token.node_id, owner.token.epoch
        )));
    }
    let owner_relay = cluster.relay(&owner.token.node_id)?;
    let ingress_relay = cluster.relay("relay-b")?;

    let sibling = timeout_at(
        deadline.into(),
        open_consumer_stream(
            relay_c_consumer_addr,
            &harness.pki.server_ca.certificate_der,
            &token,
            device.id,
            service_id,
        ),
    )
    .await
    .map_err(|_| HarnessError::Timeout("lifecycle sibling stream open timed out".into()))?
    .map_err(connect_failure_to_harness)?;
    resources.sibling = Some(sibling);
    timeout_at(
        deadline.into(),
        resources
            .sibling
            .as_mut()
            .ok_or_else(|| HarnessError::Process("lifecycle sibling stream was lost".into()))?
            .round_trip(b"m7-lifecycle-baseline-sibling", canary.as_bytes()),
    )
    .await
    .map_err(|_| HarnessError::Timeout("lifecycle sibling baseline timed out".into()))??;

    let baseline_snapshot = snapshot_until(owner_relay, deadline, "owner baseline").await?;
    let baseline_ingress_snapshot =
        snapshot_until(ingress_relay, deadline, "ingress baseline").await?;
    let baseline_session = lifecycle_session(&baseline_snapshot, device.id)?;
    if baseline_session.streams.len() != 2 {
        return Err(HarnessError::Process(format!(
            "lifecycle expected exactly two admitted owner streams, observed {}",
            baseline_session.streams.len()
        )));
    }
    let mut stream_ids = baseline_session
        .streams
        .iter()
        .map(|stream| stream.stream_id)
        .collect::<Vec<_>>();
    stream_ids.sort_unstable();
    let stalled_stream_id = stream_ids[0];
    let sibling_stream_id = stream_ids[1];
    let baseline_dispatches = baseline_snapshot.lifetime_application_dispatches;
    let baseline_device_dispatches = device_dispatch_counter(&baseline_snapshot, device.id);
    let baseline_owner_sockets = baseline_session.sockets;
    let accepted_consumer_send_buffer_effective_bytes = cluster
        .relay("relay-b")?
        .accepted_consumer_send_buffer_bytes()
        .ok_or_else(|| {
            HarnessError::Process(
                "lifecycle consumer listener accepted no socket configuration sample".into(),
            )
        })?;
    let baseline_response_write_timeout_count = baseline_ingress_snapshot
        .consumer_write_diagnostics
        .timeout_count;
    if baseline_dispatches < 2 || baseline_device_dispatches < 2 {
        return Err(HarnessError::Process(format!(
            "lifecycle baseline counters were not advanced: dispatches={baseline_dispatches}, device_dispatches={baseline_device_dispatches}"
        )));
    }

    let consumer_proxy = resources
        .consumer_proxy
        .as_ref()
        .ok_or_else(|| HarnessError::Process("lifecycle consumer proxy was lost".into()))?;
    let stalled_proxy_id = wait_for_proxy_connection(consumer_proxy, deadline).await?;
    timeout_at(
        deadline.into(),
        consumer_proxy.pause(Direction::TargetToClient, stalled_proxy_id),
    )
    .await
    .map_err(|_| HarnessError::Timeout("lifecycle consumer proxy pause timed out".into()))??;
    // ProxyHandle::pause resolves only after the exact connection's
    // target-to-client barrier is installed.  Keep that command result
    // separate from the direction-specific counter below.
    let physical_path_paused = true;
    let proxy_target_to_client_paused = consumer_proxy.stats().paused_target_to_client > 0;
    if !proxy_target_to_client_paused {
        return Err(HarnessError::Process(
            "lifecycle consumer proxy did not acknowledge the exact target-to-client pause".into(),
        ));
    }

    let stalled_payload = lifecycle_stalled_payload();
    let cancellation = CancellationToken::new();
    let target_started = Arc::new(AtomicBool::new(false));
    let sibling = resources
        .sibling
        .take()
        .ok_or_else(|| HarnessError::Process("lifecycle sibling stream was lost".into()))?;
    let stalled = resources
        .stalled
        .take()
        .ok_or_else(|| HarnessError::Process("lifecycle stalled stream was lost".into()))?;
    let sibling_canary_count = Arc::new(AtomicUsize::new(0));
    let sibling_pump = tokio::spawn(pump_sibling_canaries(
        sibling,
        canary.clone().into_bytes(),
        cancellation.clone(),
        sibling_canary_count.clone(),
        target_started.clone(),
        deadline,
    ));
    let pump = tokio::spawn(pump_unread_stream(
        stalled,
        stalled_payload,
        cancellation.clone(),
        target_started,
        deadline,
    ));
    let mut active_stall = ActiveStall {
        pump: Some(pump),
        sibling_pump: Some(sibling_pump),
        sibling_canary_count,
        cancellation,
        proxy_id: stalled_proxy_id,
        trace: StallTrace::default(),
    };
    let observation = observe_stall(
        StallObservationContext {
            relay: owner_relay,
            ingress_relay,
            device_id: device.id,
            service_id,
            stalled_stream_id,
            baseline_response_write_timeout_count,
            deadline,
        },
        &mut active_stall,
    )
    .await;
    let mut teardown = active_stall.shutdown(consumer_proxy, deadline).await;
    if let Ok(teardown) = &mut teardown {
        resources.sibling = teardown.sibling.take();
    }
    let observation = match (observation, teardown) {
        (Err(observation_error), Err(teardown_error)) => {
            return Err(combine_errors(observation_error, teardown_error));
        }
        (Err(error), Ok(teardown)) => {
            return Err(annotate_stall_failure(error, &teardown));
        }
        (Ok(_), Err(error)) => return Err(error),
        (Ok(observation), Ok(teardown)) => (observation, teardown),
    };
    let (observation, teardown) = observation;
    let stalled_records_sent = teardown.stalled_records_sent;
    let queue_bytes_observed = observation.queue_bytes_observed;
    let sibling_canary_during_stall = observation.sibling_canary_during_stall;
    let proxy_connection_closed = teardown.proxy_connection_closed;
    let cancellation_joined = teardown.cancellation_joined;
    let physical_response_path_blocked = physical_path_paused
        && proxy_target_to_client_paused
        && observation.response_write_timeout_observed
        && stalled_records_sent > 0;
    if !physical_response_path_blocked {
        return Err(HarnessError::Process(format!(
            "lifecycle unread consumer did not reach a controlled response-path stall: proxy_paused={proxy_target_to_client_paused}, proxy_closed={proxy_connection_closed}, sent={stalled_records_sent}, response_write_timeout_observed={}, response_write_timeout_count={}, baseline_response_write_timeout_count={baseline_response_write_timeout_count}, queue_bytes_observed={queue_bytes_observed}, sibling_canary={:?}, pump={:?}; {}",
            observation.response_write_timeout_observed,
            observation.response_write_timeout_count,
            teardown.sibling_outcome,
            teardown.outcome,
            format_stall_trace(teardown.trace, Some(teardown.outcome))
        )));
    }

    let maximum_dispatches = baseline_dispatches
        .checked_add(1)
        .and_then(|value| {
            value.checked_add(u64::try_from(stalled_records_sent).unwrap_or(u64::MAX))
        })
        .and_then(|value| {
            value.checked_add(
                u64::try_from(teardown.sibling_outcome.attempted()).unwrap_or(u64::MAX),
            )
        })
        .ok_or_else(|| HarnessError::Process("lifecycle dispatch bound overflowed".into()))?;
    let cleanup = wait_for_stalled_cleanup(
        owner_relay,
        device.id,
        stalled_stream_id,
        sibling_stream_id,
        baseline_dispatches,
        maximum_dispatches,
        deadline,
    )
    .await?;
    let sibling_canary_after_cancel = timeout_at(
        deadline.into(),
        resources
            .sibling
            .as_mut()
            .ok_or_else(|| HarnessError::Process("lifecycle sibling stream was lost".into()))?
            .round_trip(b"m7-lifecycle-sibling-after-cancel", canary.as_bytes()),
    )
    .await
    .map_err(|_| HarnessError::Timeout("lifecycle sibling after-cancel timed out".into()))?
    .is_ok();
    if !sibling_canary_after_cancel {
        return Err(HarnessError::Process(
            "lifecycle sibling did not survive stalled-stream cancellation".into(),
        ));
    }

    let fresh = timeout_at(
        deadline.into(),
        open_consumer_stream(
            consumer_proxy_addr,
            &harness.pki.server_ca.certificate_der,
            &token,
            device.id,
            service_id,
        ),
    )
    .await
    .map_err(|_| HarnessError::Timeout("lifecycle fresh stream open timed out".into()))?
    .map_err(connect_failure_to_harness)?;
    resources.fresh = Some(fresh);
    let fresh_authorized_stream = timeout_at(
        deadline.into(),
        resources
            .fresh
            .as_mut()
            .ok_or_else(|| HarnessError::Process("lifecycle fresh stream was lost".into()))?
            .round_trip(b"m7-lifecycle-fresh-authorized", canary.as_bytes()),
    )
    .await
    .map_err(|_| HarnessError::Timeout("lifecycle fresh stream echo timed out".into()))?
    .is_ok();
    if !fresh_authorized_stream {
        return Err(HarnessError::Process(
            "lifecycle fresh authorized stream did not return its canary".into(),
        ));
    }

    let final_snapshot = snapshot_until(owner_relay, deadline, "owner final").await?;
    let final_session = lifecycle_session(&final_snapshot, device.id)?;
    let stalled_final_clean = final_session
        .streams
        .iter()
        .find(|stream| stream.stream_id == stalled_stream_id)
        .is_none_or(|stream| {
            stream.terminal
                && stream.queue_bytes == 0
                && stream.replay_frames_relay_to_connector == 0
                && stream.replay_bytes_relay_to_connector == 0
        });
    let sibling_stream_isolated = stalled_final_clean
        && final_session
            .streams
            .iter()
            .any(|stream| stream.stream_id == sibling_stream_id && !stream.terminal)
        && final_session
            .streams
            .iter()
            .any(|stream| stream.stream_id != stalled_stream_id && !stream.terminal)
        && final_session.queue_bytes == 0
        && final_session.replay_frames == 0
        && final_session.replay_bytes == 0;
    let physical_socket_bound = (2..=3).contains(&final_session.sockets);

    Ok(LifecycleEvidence {
        relay_count: cluster.relays.len(),
        membership_ready_relays: ready,
        non_owner_ingress_relays: 2,
        baseline_streams: 2,
        baseline_owner_sockets,
        physical_path_paused,
        proxy_target_to_client_paused,
        proxy_connection_closed,
        stalled_records_sent,
        queue_bytes_observed,
        physical_response_path_blocked,
        cancellation_joined,
        stalled_stream_cleaned: cleanup.cleaned,
        dispatch_stable_after_cleanup: cleanup.dispatch_stable,
        sibling_canary_during_stall,
        sibling_canary_after_cancel,
        sibling_stream_isolated,
        fresh_authorized_stream,
        physical_socket_bound,
        accepted_consumer_send_buffer_requested_bytes: STALL_CONSUMER_SEND_BUFFER_BYTES,
        accepted_consumer_send_buffer_effective_bytes,
        fanout_peak_open: 0,
        elapsed_ms: 0,
    })
}

fn lifecycle_session(
    snapshot: &RelaySnapshot,
    device_id: Uuid,
) -> Result<&tunnel_relay::RelaySessionSnapshot> {
    snapshot
        .sessions
        .iter()
        .find(|session| session.device_id == device_id.to_string())
        .ok_or_else(|| {
            HarnessError::Process(format!(
                "lifecycle owner snapshot lost device session: dispatches={}, sessions={}",
                snapshot.lifetime_application_dispatches,
                snapshot.sessions.len()
            ))
        })
}

async fn snapshot_until(
    relay: &super::ProductionRelay,
    deadline: Instant,
    label: &str,
) -> Result<RelaySnapshot> {
    timeout_at(deadline.into(), relay.snapshot())
        .await
        .map_err(|_| {
            HarnessError::Timeout(format!(
                "stream lifecycle {label} relay snapshot exceeded its deadline"
            ))
        })?
}

async fn wait_for_proxy_connection(proxy: &ProxyHandle, deadline: Instant) -> Result<ConnectionId> {
    loop {
        let connections = proxy.connections();
        match connections.as_slice() {
            [connection] => return Ok(connection.id),
            [] => {}
            _ => {
                return Err(HarnessError::Proxy(format!(
                    "lifecycle expected one CLI connection at the consumer proxy, observed {}",
                    connections.len()
                )));
            }
        }
        let remaining = remaining(deadline, "consumer proxy connection")?;
        sleep(STALL_POLL.min(remaining)).await;
    }
}

async fn wait_for_proxy_idle(proxy: &ProxyHandle, deadline: Instant) -> Result<()> {
    loop {
        if proxy.stats().active == 0 && proxy.connections().is_empty() {
            return Ok(());
        }
        let remaining = remaining(deadline, "consumer proxy connection cleanup")?;
        sleep(STALL_POLL.min(remaining)).await;
    }
}

struct StallObservation {
    queue_bytes_observed: bool,
    response_write_timeout_observed: bool,
    response_write_timeout_count: u64,
    sibling_canary_during_stall: bool,
}

struct StallTeardown {
    outcome: StallPumpOutcome,
    stalled_records_sent: usize,
    sibling: Option<ConsumerStream>,
    sibling_outcome: SiblingCanaryOutcome,
    cancellation_joined: bool,
    proxy_connection_closed: bool,
    trace: StallTrace,
}

struct ActiveStall {
    pump: Option<JoinHandle<(ConsumerStream, StallPumpOutcome)>>,
    sibling_pump: Option<JoinHandle<(ConsumerStream, SiblingCanaryOutcome)>>,
    sibling_canary_count: Arc<AtomicUsize>,
    cancellation: CancellationToken,
    proxy_id: ConnectionId,
    trace: StallTrace,
}

#[derive(Clone, Copy, Debug)]
struct StallTrace {
    snapshots: u32,
    target_seen: bool,
    target_present: bool,
    target_phase: &'static str,
    target_queue_bytes: usize,
    target_queue_messages: usize,
    target_replay_frames: usize,
    target_replay_bytes: usize,
    latest_sessions: usize,
    latest_queue_bytes: usize,
    latest_queue_messages: usize,
    latest_replay_frames: usize,
    latest_replay_bytes: usize,
    latest_dispatches: u64,
}

impl Default for StallTrace {
    fn default() -> Self {
        Self {
            snapshots: 0,
            target_seen: false,
            target_present: false,
            target_phase: "unknown",
            target_queue_bytes: 0,
            target_queue_messages: 0,
            target_replay_frames: 0,
            target_replay_bytes: 0,
            latest_sessions: 0,
            latest_queue_bytes: 0,
            latest_queue_messages: 0,
            latest_replay_frames: 0,
            latest_replay_bytes: 0,
            latest_dispatches: 0,
        }
    }
}

fn bounded_lifecycle_phase(phase: &str) -> &'static str {
    match phase {
        "active" => "active",
        "preparing" => "preparing",
        "quiescing" => "quiescing",
        "draining" => "draining",
        "committing" => "committing",
        "retiring" => "retiring",
        "aborting" => "aborting",
        "recovering" => "recovering",
        "closed" => "closed",
        _ => "unknown",
    }
}

impl StallTrace {
    fn observe(&mut self, snapshot: &RelaySnapshot, device_id: Uuid) {
        self.snapshots = self.snapshots.saturating_add(1);
        self.latest_sessions = snapshot.sessions.len();
        self.latest_queue_bytes = snapshot
            .sessions
            .iter()
            .map(|session| session.queue_bytes)
            .fold(0_usize, |total, value| total.saturating_add(value));
        self.latest_queue_messages = snapshot
            .sessions
            .iter()
            .map(|session| session.queue_messages)
            .fold(0_usize, |total, value| total.saturating_add(value));
        self.latest_replay_frames = snapshot
            .sessions
            .iter()
            .map(|session| session.replay_frames)
            .fold(0_usize, |total, value| total.saturating_add(value));
        self.latest_replay_bytes = snapshot
            .sessions
            .iter()
            .map(|session| session.replay_bytes)
            .fold(0_usize, |total, value| total.saturating_add(value));
        self.latest_dispatches = snapshot.lifetime_application_dispatches;
        if let Some(session) = snapshot
            .sessions
            .iter()
            .find(|session| session.device_id == device_id.to_string())
        {
            self.target_seen = true;
            self.target_present = true;
            self.target_phase = bounded_lifecycle_phase(&session.phase);
            self.target_queue_bytes = session.queue_bytes;
            self.target_queue_messages = session.queue_messages;
            self.target_replay_frames = session.replay_frames;
            self.target_replay_bytes = session.replay_bytes;
        } else if self.target_seen {
            self.target_present = false;
        }
    }
}

fn format_stall_trace(trace: StallTrace, outcome: Option<StallPumpOutcome>) -> String {
    let pump = outcome.map_or_else(
        || "unknown".to_owned(),
        |outcome| format!("{outcome:?},sent={}", outcome.sent()),
    );
    format!(
        "stall_trace=pump={pump},snapshots={},target_seen={},target_present={},target_phase={},target_queue_bytes={},target_queue_messages={},target_replay_frames={},target_replay_bytes={},latest_sessions={},latest_queue_bytes={},latest_queue_messages={},latest_replay_frames={},latest_replay_bytes={},latest_dispatches={}",
        trace.snapshots,
        trace.target_seen,
        trace.target_present,
        trace.target_phase,
        trace.target_queue_bytes,
        trace.target_queue_messages,
        trace.target_replay_frames,
        trace.target_replay_bytes,
        trace.latest_sessions,
        trace.latest_queue_bytes,
        trace.latest_queue_messages,
        trace.latest_replay_frames,
        trace.latest_replay_bytes,
        trace.latest_dispatches,
    )
}

impl ActiveStall {
    async fn shutdown(mut self, proxy: &ProxyHandle, deadline: Instant) -> Result<StallTeardown> {
        self.cancellation.cancel();
        let mut first_error = None;
        let mut joined = false;
        let mut outcome = None;
        let mut sibling_joined = false;
        let mut sibling = None;
        let mut sibling_outcome = None;
        if let Some(pump) = self.pump.take() {
            match reap_stall_pump(pump, deadline).await {
                Ok((stream, pump_outcome)) => {
                    joined = true;
                    outcome = Some(pump_outcome);
                    let _ = cancel_unread_stream(stream, deadline).await;
                }
                Err(error) => first_error = Some(error),
            }
        } else {
            first_error = Some(HarnessError::Process(
                "lifecycle stall pump was lost before cancellation".into(),
            ));
        }
        if let Some(pump) = self.sibling_pump.take() {
            match reap_sibling_pump(pump, deadline).await {
                Ok((stream, canary_outcome)) => {
                    sibling_joined = true;
                    sibling = Some(stream);
                    sibling_outcome = Some(canary_outcome);
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        } else {
            first_error.get_or_insert(HarnessError::Process(
                "lifecycle sibling canary pump was lost before cancellation".into(),
            ));
        }

        let proxy_connection_closed =
            match timeout_at(deadline.into(), proxy.close(self.proxy_id)).await {
                Ok(Ok(())) => true,
                Ok(Err(error)) => {
                    if proxy
                        .connections()
                        .iter()
                        .all(|connection| connection.id != self.proxy_id)
                    {
                        true
                    } else {
                        first_error.get_or_insert(error);
                        false
                    }
                }
                Err(_) => {
                    if proxy
                        .connections()
                        .iter()
                        .all(|connection| connection.id != self.proxy_id)
                    {
                        true
                    } else {
                        first_error.get_or_insert(HarnessError::Timeout(
                            "lifecycle consumer proxy close timed out".into(),
                        ));
                        false
                    }
                }
            };
        if let Err(error) = wait_for_proxy_idle(proxy, deadline).await {
            first_error.get_or_insert(error);
        }
        let Some(outcome) = outcome else {
            return Err(first_error.take().unwrap_or_else(|| {
                HarnessError::Process("lifecycle stall pump produced no outcome".into())
            }));
        };
        let Some(sibling_outcome) = sibling_outcome else {
            return Err(first_error.take().unwrap_or_else(|| {
                HarnessError::Process("lifecycle sibling canary produced no outcome".into())
            }));
        };
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(StallTeardown {
            outcome,
            stalled_records_sent: outcome.sent(),
            sibling,
            sibling_outcome,
            cancellation_joined: joined && sibling_joined && proxy_connection_closed,
            proxy_connection_closed,
            trace: self.trace,
        })
    }
}

struct StallObservationContext<'a> {
    relay: &'a super::ProductionRelay,
    ingress_relay: &'a super::ProductionRelay,
    device_id: Uuid,
    service_id: Uuid,
    stalled_stream_id: u64,
    baseline_response_write_timeout_count: u64,
    deadline: Instant,
}

async fn observe_stall(
    context: StallObservationContext<'_>,
    active: &mut ActiveStall,
) -> Result<StallObservation> {
    let StallObservationContext {
        relay,
        ingress_relay,
        device_id,
        service_id,
        stalled_stream_id,
        baseline_response_write_timeout_count,
        deadline,
    } = context;
    let mut queue_bytes_observed = false;
    let mut response_write_timeout_observed = false;
    let mut response_write_timeout_count;
    loop {
        let snapshot = snapshot_until(relay, deadline, "owner observation").await?;
        active.trace.observe(&snapshot, device_id);
        let ingress_snapshot =
            snapshot_until(ingress_relay, deadline, "ingress observation").await?;
        response_write_timeout_count = ingress_snapshot.consumer_write_diagnostics.timeout_count;
        response_write_timeout_observed |= ingress_snapshot
            .consumer_write_diagnostics
            .recent_timeouts
            .iter()
            .any(|event| {
                event.sequence > baseline_response_write_timeout_count
                    && event.scope.device_id == device_id
                    && event.scope.service_id == service_id
                    && event.scope.ingress == ConsumerIngressKind::Forwarded
            });
        let session = lifecycle_session(&snapshot, device_id)?;
        if let Some(stream) = session
            .streams
            .iter()
            .find(|stream| stream.stream_id == stalled_stream_id)
        {
            queue_bytes_observed |=
                stream.queue_bytes > 0 || stream.replay_bytes_relay_to_connector > 0;
        }
        // A producer can hit its four-second bound before the relay's
        // five-second physical response-write bound expires. Keep the path
        // paused and observe the typed writer result even after that producer
        // has finished; its outcome does not prove response-path pressure.
        if response_write_timeout_observed {
            break;
        }
        let remaining = remaining(deadline, "write-stall observation")?;
        sleep(STALL_POLL.min(remaining)).await;
    }
    let sibling_canary_during_stall = active.sibling_canary_count.load(Ordering::Acquire) > 0;
    if !sibling_canary_during_stall {
        return Err(HarnessError::Process(
            "lifecycle sibling canary made no bounded progress before the target response-path timeout".into(),
        ));
    }
    Ok(StallObservation {
        queue_bytes_observed,
        response_write_timeout_observed,
        response_write_timeout_count,
        sibling_canary_during_stall,
    })
}

fn annotate_stall_failure(error: HarnessError, teardown: &StallTeardown) -> HarnessError {
    HarnessError::Process(format!(
        "{error}; sibling_canary={:?}; {}",
        teardown.sibling_outcome,
        format_stall_trace(teardown.trace, Some(teardown.outcome))
    ))
}

fn combine_errors(primary: HarnessError, cleanup: HarnessError) -> HarnessError {
    HarnessError::Process(format!(
        "stream lifecycle observation failed: {primary}; cleanup failed: {cleanup}"
    ))
}

fn with_cleanup_errors(primary: HarnessError, cleanup_errors: Vec<String>) -> HarnessError {
    if cleanup_errors.is_empty() {
        primary
    } else {
        HarnessError::Process(format!(
            "{primary}; stream lifecycle cleanup failed: {}",
            cleanup_errors.join("; ")
        ))
    }
}

fn lifecycle_stalled_payload() -> Vec<u8> {
    let mut payload = vec![b'l'; super::MAX_RECORD_BYTES];
    let marker = b"m7-lifecycle-stall";
    payload[..marker.len()].copy_from_slice(marker);
    payload
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StallPumpOutcome {
    Cancelled { sent: usize },
    WriteTimedOut { sent: usize },
    StallWindowElapsed { sent: usize },
    PeerClosed { sent: usize },
}

impl StallPumpOutcome {
    const fn sent(self) -> usize {
        match self {
            Self::Cancelled { sent }
            | Self::WriteTimedOut { sent }
            | Self::StallWindowElapsed { sent }
            | Self::PeerClosed { sent } => sent,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SiblingCanaryOutcome {
    Cancelled { attempted: usize, completed: usize },
    Completed { attempted: usize, completed: usize },
    TimedOut { attempted: usize, completed: usize },
    PeerClosed { attempted: usize, completed: usize },
}

impl SiblingCanaryOutcome {
    const fn attempted(self) -> usize {
        match self {
            Self::Cancelled { attempted, .. }
            | Self::Completed { attempted, .. }
            | Self::TimedOut { attempted, .. }
            | Self::PeerClosed { attempted, .. } => attempted,
        }
    }
}

/// Keep the sibling data direction making bounded, real echo progress while
/// the target response path is paused. The stream remains owned by this task
/// and is returned on every cooperative outcome so shutdown can close it
/// before the scenario advances to cleanup.
async fn pump_sibling_canaries(
    mut stream: ConsumerStream,
    canary: Vec<u8>,
    cancellation: CancellationToken,
    completed_count: Arc<AtomicUsize>,
    target_started: Arc<AtomicBool>,
    deadline: Instant,
) -> (ConsumerStream, SiblingCanaryOutcome) {
    let mut attempted = 0_usize;
    let mut completed = 0_usize;
    for attempt in 0..SIBLING_CANARY_ATTEMPTS {
        if attempt == 0 {
            while !target_started.load(Ordering::Acquire) {
                let wait_deadline = (Instant::now() + STALL_POLL).min(deadline);
                if wait_deadline <= Instant::now() {
                    return (
                        stream,
                        SiblingCanaryOutcome::TimedOut {
                            attempted,
                            completed,
                        },
                    );
                }
                let wait = sleep(wait_deadline.saturating_duration_since(Instant::now()));
                tokio::pin!(wait);
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => {
                        return (
                            stream,
                            SiblingCanaryOutcome::Cancelled { attempted, completed },
                        );
                    }
                    _ = &mut wait => {}
                }
            }
        }
        if attempt > 0 {
            let wait_deadline = (Instant::now() + SIBLING_CANARY_INTERVAL).min(deadline);
            if wait_deadline <= Instant::now() {
                return (
                    stream,
                    SiblingCanaryOutcome::TimedOut {
                        attempted,
                        completed,
                    },
                );
            }
            let wait = sleep(wait_deadline.saturating_duration_since(Instant::now()));
            tokio::pin!(wait);
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    return (
                        stream,
                        SiblingCanaryOutcome::Cancelled { attempted, completed },
                    );
                }
                _ = &mut wait => {}
            }
        }

        let operation_deadline = (Instant::now() + SIBLING_CANARY_TIMEOUT).min(deadline);
        if operation_deadline <= Instant::now() {
            return (
                stream,
                SiblingCanaryOutcome::TimedOut {
                    attempted,
                    completed,
                },
            );
        }
        attempted = attempted.saturating_add(1);
        let payload = format!("m7-lifecycle-sibling-during-stall-{attempt}");
        let round_trip = stream.round_trip(payload.as_bytes(), &canary);
        let result = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                return (
                    stream,
                    SiblingCanaryOutcome::Cancelled { attempted, completed },
                );
            }
            result = timeout_at(operation_deadline.into(), round_trip) => result,
        };
        match result {
            Ok(Ok(())) => {
                completed = completed.saturating_add(1);
                completed_count.fetch_add(1, Ordering::Release);
            }
            Ok(Err(_)) => {
                return (
                    stream,
                    SiblingCanaryOutcome::PeerClosed {
                        attempted,
                        completed,
                    },
                );
            }
            Err(_) => {
                return (
                    stream,
                    SiblingCanaryOutcome::TimedOut {
                        attempted,
                        completed,
                    },
                );
            }
        }
    }
    (
        stream,
        SiblingCanaryOutcome::Completed {
            attempted,
            completed,
        },
    )
}

async fn pump_unread_stream(
    mut stream: ConsumerStream,
    payload: Vec<u8>,
    cancellation: CancellationToken,
    target_started: Arc<AtomicBool>,
    deadline: Instant,
) -> (ConsumerStream, StallPumpOutcome) {
    let mut sent = 0;
    for _ in 0..STALL_RECORDS {
        let Ok(length) = u32::try_from(payload.len()) else {
            return (stream, StallPumpOutcome::PeerClosed { sent });
        };
        let mut frame = Vec::with_capacity(payload.len() + 4);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&payload);
        let send_deadline = (Instant::now() + STALL_SEND_TIMEOUT).min(deadline);
        if send_deadline <= Instant::now() {
            return (stream, StallPumpOutcome::WriteTimedOut { sent });
        }
        let send = stream.socket.send(Message::Binary(frame.into()));
        let result = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                return (stream, StallPumpOutcome::Cancelled { sent });
            }
            result = timeout_at(send_deadline.into(), send) => result,
        };
        match result {
            Ok(Ok(())) => {
                sent += 1;
                target_started.store(true, Ordering::Release);
            }
            Ok(Err(_)) => return (stream, StallPumpOutcome::PeerClosed { sent }),
            Err(_) => return (stream, StallPumpOutcome::WriteTimedOut { sent }),
        }
    }
    let wait_deadline = (Instant::now() + STALL_SEND_TIMEOUT).min(deadline);
    if wait_deadline <= Instant::now() {
        return (stream, StallPumpOutcome::StallWindowElapsed { sent });
    }
    let wait = sleep(wait_deadline.saturating_duration_since(Instant::now()));
    tokio::pin!(wait);
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            (stream, StallPumpOutcome::Cancelled { sent })
        }
        _ = &mut wait => (stream, StallPumpOutcome::StallWindowElapsed { sent }),
    }
}

async fn reap_stall_pump(
    mut pump: JoinHandle<(ConsumerStream, StallPumpOutcome)>,
    deadline: Instant,
) -> Result<(ConsumerStream, StallPumpOutcome)> {
    match timeout_at(deadline.into(), &mut pump).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(error)) => Err(HarnessError::Process(format!(
            "joining lifecycle stall pump: {error}"
        ))),
        Err(_) => Err(abort_and_join_pump(pump, "lifecycle stall pump").await),
    }
}

async fn reap_sibling_pump(
    mut pump: JoinHandle<(ConsumerStream, SiblingCanaryOutcome)>,
    deadline: Instant,
) -> Result<(ConsumerStream, SiblingCanaryOutcome)> {
    match timeout_at(deadline.into(), &mut pump).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(error)) => Err(HarnessError::Process(format!(
            "joining lifecycle sibling canary pump: {error}"
        ))),
        Err(_) => Err(abort_and_join_pump(pump, "lifecycle sibling canary pump").await),
    }
}

async fn abort_and_join_pump<T>(pump: JoinHandle<T>, label: &str) -> HarnessError {
    // These pumps only await cancellation-safe socket, channel, and timer
    // operations.  After abort, await the same owned handle to completion;
    // returning after a second timeout would drop the JoinHandle and detach
    // the task that still owns a ConsumerStream.
    pump.abort();
    match pump.await {
        Ok(_) => HarnessError::Timeout(format!(
            "{label} exceeded its deadline and completed after forced cancellation"
        )),
        Err(error) if error.is_cancelled() => HarnessError::Timeout(format!(
            "{label} exceeded its deadline and was aborted after a joined cancellation"
        )),
        Err(error) => HarnessError::Process(format!(
            "joining {label} after forced cancellation: {error}"
        )),
    }
}

async fn cancel_unread_stream(mut stream: ConsumerStream, deadline: Instant) -> bool {
    stream.closed = true;
    let sent = timeout_at(deadline.into(), stream.socket.send(Message::Close(None)))
        .await
        .is_ok_and(|result| result.is_ok());
    drop(stream);
    sent
}

struct CleanupObservation {
    cleaned: bool,
    dispatch_stable: bool,
}

async fn wait_for_stalled_cleanup(
    relay: &super::ProductionRelay,
    device_id: Uuid,
    stalled_stream_id: u64,
    sibling_stream_id: u64,
    baseline_dispatches: u64,
    maximum_dispatches: u64,
    deadline: Instant,
) -> Result<CleanupObservation> {
    let mut first_cleanup_counter = None;
    let mut first_cleanup_device_counter = None;
    let mut stable_samples = 0_u8;
    loop {
        let snapshot = snapshot_until(relay, deadline, "stalled cleanup").await?;
        let session = lifecycle_session(&snapshot, device_id)?;
        let dispatches = snapshot.lifetime_application_dispatches;
        let device_dispatches = device_dispatch_counter(&snapshot, device_id);
        if dispatches < baseline_dispatches {
            return Err(HarnessError::Process(format!(
                "lifecycle dispatch counter moved backwards: baseline={baseline_dispatches}, observed={dispatches}/{device_dispatches}"
            )));
        }
        if dispatches > maximum_dispatches || device_dispatches > maximum_dispatches {
            return Err(HarnessError::Process(format!(
                "lifecycle dispatch exceeded bounded stalled workload: maximum={maximum_dispatches}, observed={dispatches}/{device_dispatches}"
            )));
        }
        let stalled = session
            .streams
            .iter()
            .find(|stream| stream.stream_id == stalled_stream_id);
        let sibling = session
            .streams
            .iter()
            .find(|stream| stream.stream_id == sibling_stream_id)
            .ok_or_else(|| {
                HarnessError::Process(
                    "lifecycle sibling stream disappeared during stalled cleanup".into(),
                )
            })?;
        let stalled_clean = stalled.is_none_or(|stream| {
            stream.terminal
                && stream.queue_bytes == 0
                && stream.replay_frames_relay_to_connector == 0
                && stream.replay_bytes_relay_to_connector == 0
        });
        let queues_clean =
            session.queue_bytes == 0 && session.replay_frames == 0 && session.replay_bytes == 0;
        if !stalled_clean || !queues_clean || sibling.terminal {
            stable_samples = 0;
        } else if let Some(first) = first_cleanup_counter {
            if dispatches == first
                && device_dispatches == first_cleanup_device_counter.expect("device counter set")
            {
                stable_samples = stable_samples.saturating_add(1);
            } else {
                return Err(HarnessError::Process(format!(
                    "lifecycle dispatch advanced after stalled cleanup: first={first}/{}, observed={dispatches}/{device_dispatches}",
                    first_cleanup_device_counter.expect("device counter set")
                )));
            }
        } else {
            first_cleanup_counter = Some(dispatches);
            first_cleanup_device_counter = Some(device_dispatches);
            stable_samples = 1;
        }
        if stable_samples >= CLEANUP_STABLE_SAMPLES {
            return Ok(CleanupObservation {
                cleaned: true,
                dispatch_stable: true,
            });
        }
        let remaining = remaining(deadline, "stalled stream cleanup")?;
        sleep(STALL_POLL.min(remaining)).await;
    }
}

fn remaining(deadline: Instant, phase: &str) -> Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(HarnessError::Timeout(format!(
            "stream lifecycle {phase} exceeded its absolute deadline"
        )));
    }
    Ok(remaining)
}

#[cfg(test)]
mod tests {
    use super::{
        ClientDiagnosticFields, LifecycleEvidence, classify_protocol_cause,
        classify_recovery_trigger, classify_transport_cause, collect_client_json_errors,
        validate_lifecycle_evidence,
    };
    use crate::acceptance_test_support::assert_rejected;

    fn valid_evidence() -> LifecycleEvidence {
        LifecycleEvidence {
            relay_count: 3,
            membership_ready_relays: 3,
            non_owner_ingress_relays: 2,
            baseline_streams: 2,
            baseline_owner_sockets: 2,
            physical_path_paused: true,
            proxy_target_to_client_paused: true,
            proxy_connection_closed: true,
            stalled_records_sent: 1,
            queue_bytes_observed: true,
            physical_response_path_blocked: true,
            cancellation_joined: true,
            stalled_stream_cleaned: true,
            dispatch_stable_after_cleanup: true,
            sibling_canary_during_stall: true,
            sibling_canary_after_cancel: true,
            sibling_stream_isolated: true,
            fresh_authorized_stream: true,
            physical_socket_bound: true,
            accepted_consumer_send_buffer_requested_bytes: super::STALL_CONSUMER_SEND_BUFFER_BYTES,
            accepted_consumer_send_buffer_effective_bytes: super::STALL_CONSUMER_SEND_BUFFER_BYTES
                as usize,
            fanout_peak_open: 3,
            elapsed_ms: 1,
        }
    }

    #[test]
    fn lifecycle_validation_accepts_complete_evidence() {
        assert!(validate_lifecycle_evidence(&valid_evidence()).is_ok());
    }

    #[test]
    fn lifecycle_validation_rejects_missing_physical_stall() {
        let mut evidence = valid_evidence();
        evidence.physical_response_path_blocked = false;
        assert!(validate_lifecycle_evidence(&evidence).is_err());
    }

    #[test]
    fn every_lifecycle_flag_and_bound_reaches_the_shared_exit_path() {
        type Disable = (&'static str, fn(&mut LifecycleEvidence));
        let flags: [Disable; 13] = [
            ("physical_path_paused", |e| e.physical_path_paused = false),
            ("proxy_target_to_client_paused", |e| {
                e.proxy_target_to_client_paused = false
            }),
            ("proxy_connection_closed", |e| {
                e.proxy_connection_closed = false
            }),
            ("physical_response_path_blocked", |e| {
                e.physical_response_path_blocked = false
            }),
            ("queue_bytes_observed", |e| e.queue_bytes_observed = false),
            ("cancellation_joined", |e| e.cancellation_joined = false),
            ("stalled_stream_cleaned", |e| {
                e.stalled_stream_cleaned = false
            }),
            ("dispatch_stable_after_cleanup", |e| {
                e.dispatch_stable_after_cleanup = false
            }),
            ("sibling_canary_during_stall", |e| {
                e.sibling_canary_during_stall = false
            }),
            ("sibling_canary_after_cancel", |e| {
                e.sibling_canary_after_cancel = false
            }),
            ("sibling_stream_isolated", |e| {
                e.sibling_stream_isolated = false
            }),
            ("fresh_authorized_stream", |e| {
                e.fresh_authorized_stream = false
            }),
            ("physical_socket_bound", |e| e.physical_socket_bound = false),
        ];
        for (name, disable) in flags {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_rejected(validate_lifecycle_evidence(&evidence), name);
        }

        type Mutate = (&'static str, fn(&mut LifecycleEvidence));
        let bounds: [Mutate; 9] = [
            ("relay_count", |e| e.relay_count = 2),
            ("membership_ready_relays", |e| e.membership_ready_relays = 2),
            ("non_owner_ingress_relays", |e| {
                e.non_owner_ingress_relays = 1
            }),
            ("baseline_streams", |e| e.baseline_streams = 1),
            ("baseline_owner_sockets", |e| e.baseline_owner_sockets = 1),
            ("stalled_records_sent", |e| e.stalled_records_sent = 0),
            ("accepted_consumer_send_buffer_requested_bytes", |e| {
                e.accepted_consumer_send_buffer_requested_bytes = 1
            }),
            ("accepted_consumer_send_buffer_effective_bytes", |e| {
                e.accepted_consumer_send_buffer_effective_bytes = 0
            }),
            ("fanout_peak_open", |e| e.fanout_peak_open = 4),
        ];
        for (_, mutate) in bounds {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(validate_lifecycle_evidence(&evidence), "stream lifecycle");
        }
    }

    #[test]
    fn lifecycle_diagnostic_preserves_only_allowlisted_recovery_trigger() {
        let message = "retained recovery failed: recovery episode deadline expired; recovery_trigger=data_writer_failed; recovery_role=active; recovery_generation=7";
        assert_eq!(classify_transport_cause(message), "retained_recovery");
        assert_eq!(
            classify_recovery_trigger(message).as_deref(),
            Some("data_writer_failed/active/g7")
        );
        assert_eq!(
            classify_recovery_trigger(
                "retained recovery failed: recovery episode deadline expired; recovery_trigger=raw_error; recovery_role=active; recovery_generation=7"
            ),
            None
        );
        assert_eq!(
            classify_transport_cause(
                "retained recovery failed: arbitrary detail; recovery_trigger=data_writer_failed; recovery_role=active; recovery_generation=7"
            ),
            "unknown"
        );
    }

    #[test]
    fn lifecycle_protocol_diagnostic_preserves_safe_resume_category_and_trigger() {
        let message = "RESUME recovery remaining budget exceeds local deadline; recovery_trigger=data_writer_failed; recovery_role=active; recovery_generation=7";
        assert_eq!(
            classify_protocol_cause(message),
            "recovery_resume_remaining_budget"
        );
        assert_eq!(
            classify_protocol_cause(
                "RESUME recovery remaining budget exceeds protocol bound; recovery_trigger=data_writer_failed; recovery_role=active; recovery_generation=7"
            ),
            "recovery_resume_remaining_budget"
        );
        assert_eq!(
            classify_protocol_cause(
                "RESUME recovery local deadline expired; recovery_trigger=data_reader_closed; recovery_role=active; recovery_generation=7"
            ),
            "recovery_resume_deadline_expired"
        );
        assert_eq!(
            classify_recovery_trigger(message).as_deref(),
            Some("data_writer_failed/active/g7")
        );
        assert_eq!(
            classify_protocol_cause(
                "RESUME recovery remaining budget exceeds local deadline; recovery_trigger=raw_error; recovery_role=active; recovery_generation=7"
            ),
            "recovery_resume_remaining_budget"
        );
        assert_eq!(
            classify_recovery_trigger(
                "RESUME recovery remaining budget exceeds local deadline; recovery_trigger=raw_error; recovery_role=active; recovery_generation=7"
            ),
            None
        );

        let mut fields = ClientDiagnosticFields::default();
        collect_client_json_errors(
            br#"{"error":{"code":"PROTOCOL_ERROR","message":"RESUME recovery remaining budget exceeds local deadline; recovery_trigger=data_writer_failed; recovery_role=active; recovery_generation=7","retryable":false}}"#,
            &mut fields,
        );
        assert_eq!(
            fields.protocol_causes,
            vec!["recovery_resume_remaining_budget"]
        );
        assert_eq!(
            fields.recovery_triggers,
            vec!["data_writer_failed/active/g7"]
        );
    }

    #[test]
    fn lifecycle_protocol_diagnostic_classifies_owner_forget_failures_without_payload() {
        let cases = [
            (
                "STREAM_FORGET before local adapter input debt drained",
                "stream_forget_adapter_debt",
            ),
            (
                "STREAM_FORGET before deferred output and control debt drained",
                "stream_forget_output_debt",
            ),
            (
                "STREAM_FORGET owner sender evidence is incomplete",
                "stream_forget_sender_incomplete",
            ),
            (
                "STREAM_FORGET owner and connector receive evidence mismatch",
                "stream_forget_receive_mismatch",
            ),
            (
                "STREAM_FORGET sequence mismatch: stream 17 contains secret bytes",
                "stream_forget_sequence",
            ),
        ];
        let mut fields = ClientDiagnosticFields::default();
        for (message, category) in cases {
            assert_eq!(classify_protocol_cause(message), category);
            let line = format!(
                r#"{{"error":{{"code":"PROTOCOL_ERROR","message":{message:?},"retryable":false}}}}"#
            );
            let mut single = ClientDiagnosticFields::default();
            collect_client_json_errors(line.as_bytes(), &mut single);
            assert_eq!(single.protocol_causes, vec![category]);
            collect_client_json_errors(line.as_bytes(), &mut fields);
        }
        // The combined diagnostic window deliberately retains at most four
        // distinct causes, even when more valid categories are observed.
        assert_eq!(
            fields.protocol_causes,
            vec![
                "stream_forget_adapter_debt",
                "stream_forget_output_debt",
                "stream_forget_sender_incomplete",
                "stream_forget_receive_mismatch",
            ]
        );
        assert!(
            !fields
                .protocol_causes
                .iter()
                .any(|category| category.contains("secret") || category.contains("17"))
        );
    }

    #[test]
    fn lifecycle_protocol_diagnostic_classifies_sequence_terminal_and_invalidation() {
        let cases = [
            ("received sequence gap: expected 4, got 9", "sequence_gap"),
            (
                "cannot process Fin after terminal state Fin",
                "sequence_after_terminal",
            ),
            (
                "authorization invalidation context mismatch",
                "authorization_invalidation_context",
            ),
            (
                "STREAM_FORGET terminal proof did not converge before its deadline",
                "stream_forget_terminal_proof",
            ),
        ];
        for (message, category) in cases {
            assert_eq!(classify_protocol_cause(message), category);
        }
        assert_eq!(
            classify_protocol_cause("unrecognized private protocol detail"),
            "unknown"
        );
    }

    #[test]
    fn lifecycle_protocol_diagnostic_distinguishes_rotation_handlers() {
        let cases = [
            (
                "ROTATE_PREPARE identity mismatch",
                "rotation_prepare_identity",
            ),
            (
                "ROTATE_QUIESCE in the wrong phase",
                "rotation_quiesce_phase",
            ),
            (
                "ROTATE_FROZEN reply correlation mismatch",
                "rotation_frozen_reply",
            ),
            (
                "ROTATE_DRAINED reply correlation mismatch",
                "rotation_drained_reply",
            ),
            (
                "ROTATE_COMMIT snapshot mismatch",
                "rotation_commit_snapshot",
            ),
            (
                "ROTATE_COMMITTED unexpected message",
                "rotation_protocol_unknown",
            ),
            (
                "ROTATE_RETIRE snapshot mismatch",
                "rotation_retire_snapshot",
            ),
            (
                "ROTATE_RETIRED unexpected message",
                "rotation_protocol_unknown",
            ),
            (
                "ROTATE_COMPLETE identity mismatch",
                "rotation_complete_identity",
            ),
            ("ROTATE_ABORT attempt mismatch", "rotation_abort_attempt"),
            (
                "ROTATE_ABORTED outside the abort phase",
                "rotation_aborted_phase",
            ),
            (
                "ROTATE_PRIVATE detail with secret=redacted",
                "rotation_protocol_unknown",
            ),
        ];
        for (message, category) in cases {
            assert_eq!(classify_protocol_cause(message), category);
        }
    }

    #[test]
    fn lifecycle_rejects_more_than_three_baseline_owner_sockets() {
        let mut evidence = valid_evidence();
        evidence.baseline_owner_sockets = 4;
        assert_rejected(
            validate_lifecycle_evidence(&evidence),
            "expected two or three",
        );
    }
}
