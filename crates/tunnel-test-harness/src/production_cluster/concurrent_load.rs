//! Bounded concurrent multi-ingress and stream-cap coverage for the real
//! three-relay production fixture.
//!
//! The gate owns no fixture setup: it starts the same three
//! [`ProductionCluster`] relays used by the other M7 gates, drives one real
//! `tunnel-client` process per tenant, and then opens a bounded set of public
//! consumer WebSockets through both non-owner relays.
//!
//! The stream admission portion attempts 128 streams in total.  One stream is
//! the real CLI stream, 64 are cap-fill attempts, and the remaining 63 are
//! made after the observed session has filled.  The CLI consumer stream counts
//! toward the configured 64-stream device cap, so exactly 63 fill attempts
//! must be accepted and the 64th must return an explicit typed capacity
//! refusal before the 63 over-cap attempts begin.  Fill admission is paced in
//! windows of four complete round trips so the cap result is isolated from the
//! connector's bounded control queue.  The separate burst case remains a
//! required client regression: a focused M2 test should feed more than the
//! 16-frame control queue's worth of concurrent `OPEN` responses and assert a
//! bounded, classified queue outcome without treating it as device capacity.
//! The over-cap probes use the same window. Existing WebSockets hold public
//! admission permits, so sending all 63 rejected probes at once can exhaust
//! the separate 64-request ingress limit before the device cap is checked.
//! The workload phase still drives every admitted stream concurrently.
//!
//! The cancellation bit below covers bounded harness/client stream teardown
//! while the sibling streams are active.  It deliberately does not claim the
//! separate EC-028 proof of reserved rotation/revocation control capacity.

use super::{
    CLEANUP_TIMEOUT, ConsumerStream, ProductionCluster, ProductionRelay, RunningHarness,
    SCENARIO_TIMEOUT, STARTUP_TIMEOUT, open_consumer_stream, start_cli_smoke,
    wait_for_fanout_drained,
};
use crate::acceptance::helpers::write_device_profile;
use crate::{Harness, HarnessError, HarnessOptions, ManagedProcess, OidcTokenOptions, Result};
use chrono::Utc;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tempfile::tempdir;
use tokio::{
    sync::mpsc,
    task::JoinSet,
    time::{sleep, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;
use tunnel_relay::MembershipReadiness;
use uuid::Uuid;

const TOTAL_STREAM_ATTEMPTS: usize = 128;
const CAP_FILL_ATTEMPTS: usize = 64;
const CAP_FILL_WINDOW: usize = 4;
const DEVICE_STREAM_CAP: usize = 64;
const WORKLOAD_RECORDS_PER_STREAM: usize = 4;
const WORKLOAD_PAYLOAD_BYTES: usize = 8 * 1024;
const PROBE_PAYLOAD_BYTES: usize = 32;
const QUEUE_LIMIT_BYTES: usize = 4 * 1024 * 1024;
const QUEUE_LIMIT_MESSAGES: usize = 128;
const SINGLE_STREAM_PRODUCERS: usize = 4;
const MAX_ERROR_BODY_BYTES: usize = 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(6);
const PROBE_BATCH_TIMEOUT: Duration = Duration::from_secs(30);
const LOAD_TIMEOUT: Duration = Duration::from_secs(45);
const LOAD_SNAPSHOT_POLL: Duration = Duration::from_millis(25);
const WORKER_HOLD_TIMEOUT: Duration = Duration::from_secs(5);
const STREAM_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
const PROCESS_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(8);

fn bounded_deadline(shared: Instant, budget: Duration) -> Instant {
    let phase = Instant::now() + budget;
    if shared < phase { shared } else { phase }
}

/// Redacted evidence from the bounded concurrent ingress/cap scenario.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConcurrentLoadEvidence {
    pub relay_count: usize,
    pub membership_ready_relays: usize,
    pub non_owner_ingress_relays: usize,
    pub attempted_streams: usize,
    pub cap_fill_attempts: usize,
    pub over_cap_attempts: usize,
    pub accepted_streams: usize,
    pub fill_capacity_rejections: usize,
    pub over_cap_capacity_rejections: usize,
    pub reconnecting_failures: usize,
    pub transport_failures: usize,
    pub timeout_failures: usize,
    pub unknown_failures: usize,
    pub observed_stream_peak: usize,
    pub queue_samples: usize,
    pub max_queue_bytes: usize,
    pub max_queue_messages: usize,
    pub bounded_queue: bool,
    pub ordered_streams: usize,
    pub ordered_records: usize,
    pub sibling_progress: bool,
    /// A bounded set of producer tasks fed one live stream and each response
    /// was checked against its own payload.  This exercises the public stream
    /// framing path; it does not claim internal actor sequence instrumentation.
    pub same_stream_producers: usize,
    pub same_stream_ordered: bool,
    pub tenant_b_progress: bool,
    /// All stream workers observed the bounded release/cancel and joined.
    /// This is stream teardown evidence, not the EC-028 reserved-control gate.
    pub cancellation_responsive: bool,
    pub cleanup_joined: bool,
    pub fanout_peak_open: usize,
    pub elapsed_ms: u64,
}

/// Validate the evidence contract without turning an observed runtime cap
/// into a hard-coded claim about a future configuration.
pub fn validate_concurrent_load_evidence(evidence: &ConcurrentLoadEvidence) -> Result<()> {
    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "concurrent load expected three relays, observed {}",
            evidence.relay_count
        )));
    }
    if evidence.membership_ready_relays != 3 {
        return Err(HarnessError::Process(format!(
            "concurrent load expected three Ready memberships, observed {}",
            evidence.membership_ready_relays
        )));
    }
    if evidence.non_owner_ingress_relays != 2 {
        return Err(HarnessError::Process(format!(
            "concurrent load expected two non-owner ingress relays, observed {}",
            evidence.non_owner_ingress_relays
        )));
    }
    if evidence.attempted_streams != TOTAL_STREAM_ATTEMPTS
        || evidence.cap_fill_attempts != CAP_FILL_ATTEMPTS
        || evidence.cap_fill_attempts + evidence.over_cap_attempts + 1 != evidence.attempted_streams
    {
        return Err(HarnessError::Process(
            "concurrent load stream-admission accounting was inconsistent".into(),
        ));
    }
    if evidence.accepted_streams != DEVICE_STREAM_CAP {
        return Err(HarnessError::Process(format!(
            "concurrent load expected the configured {DEVICE_STREAM_CAP}-stream device cap including the CLI stream, observed {}",
            evidence.accepted_streams
        )));
    }
    if evidence.fill_capacity_rejections != 1
        || evidence.accepted_streams + evidence.fill_capacity_rejections
            != 1 + evidence.cap_fill_attempts
    {
        return Err(HarnessError::Process(
            "concurrent load did not observe exactly one typed capacity refusal while filling the configured cap".into(),
        ));
    }
    if evidence.over_cap_capacity_rejections != evidence.over_cap_attempts {
        return Err(HarnessError::Process(format!(
            "concurrent load did not receive typed capacity refusals for every over-cap attempt: {}/{}",
            evidence.over_cap_capacity_rejections, evidence.over_cap_attempts
        )));
    }
    if evidence.reconnecting_failures != 0
        || evidence.transport_failures != 0
        || evidence.timeout_failures != 0
        || evidence.unknown_failures != 0
    {
        return Err(HarnessError::Process(
            "concurrent load mixed capacity with reconnecting, transport, timeout, or unknown failures".into(),
        ));
    }
    if evidence.observed_stream_peak < evidence.accepted_streams {
        return Err(HarnessError::Process(format!(
            "concurrent load snapshot saw only {} of {} accepted streams",
            evidence.observed_stream_peak, evidence.accepted_streams
        )));
    }
    if evidence.queue_samples == 0 || !evidence.bounded_queue {
        return Err(HarnessError::Process(
            "concurrent load did not produce bounded queue observations".into(),
        ));
    }
    if evidence.max_queue_bytes > QUEUE_LIMIT_BYTES {
        return Err(HarnessError::Process(format!(
            "concurrent load queue exceeded its 4 MiB budget: {}",
            evidence.max_queue_bytes
        )));
    }
    if evidence.max_queue_messages > QUEUE_LIMIT_MESSAGES {
        return Err(HarnessError::Process(format!(
            "concurrent load queue exceeded its 128-message budget: {}",
            evidence.max_queue_messages
        )));
    }
    if evidence.ordered_streams != evidence.accepted_streams
        || evidence.ordered_records != evidence.accepted_streams * WORKLOAD_RECORDS_PER_STREAM
    {
        return Err(HarnessError::Process(format!(
            "concurrent load completed {} streams and {} records, expected {} and {}",
            evidence.ordered_streams,
            evidence.ordered_records,
            evidence.accepted_streams,
            evidence.accepted_streams * WORKLOAD_RECORDS_PER_STREAM
        )));
    }
    if evidence.same_stream_producers != SINGLE_STREAM_PRODUCERS {
        return Err(HarnessError::Process(format!(
            "concurrent load observed {} same-stream producers, expected {SINGLE_STREAM_PRODUCERS}",
            evidence.same_stream_producers
        )));
    }
    for (name, passed) in [
        ("same_stream_ordered", evidence.same_stream_ordered),
        ("tenant_b_progress", evidence.tenant_b_progress),
        ("sibling_progress", evidence.sibling_progress),
        ("cancellation_responsive", evidence.cancellation_responsive),
        ("cleanup_joined", evidence.cleanup_joined),
    ] {
        if !passed {
            return Err(HarnessError::Process(format!(
                "concurrent load required gate {name} was false"
            )));
        }
    }
    if evidence.fanout_peak_open > 3 {
        return Err(HarnessError::Process(format!(
            "concurrent load device fanout exceeded three sockets: {}",
            evidence.fanout_peak_open
        )));
    }
    Ok(())
}

#[cfg(test)]
mod c17_validator_tests {
    use super::{
        ConcurrentLoadEvidence, DEVICE_STREAM_CAP, SINGLE_STREAM_PRODUCERS, TOTAL_STREAM_ATTEMPTS,
        WORKLOAD_RECORDS_PER_STREAM, validate_concurrent_load_evidence,
    };
    use crate::acceptance_test_support::assert_failed;

    fn valid_evidence() -> ConcurrentLoadEvidence {
        ConcurrentLoadEvidence {
            relay_count: 3,
            membership_ready_relays: 3,
            non_owner_ingress_relays: 2,
            attempted_streams: TOTAL_STREAM_ATTEMPTS,
            cap_fill_attempts: 64,
            over_cap_attempts: 63,
            accepted_streams: DEVICE_STREAM_CAP,
            fill_capacity_rejections: 1,
            over_cap_capacity_rejections: 63,
            reconnecting_failures: 0,
            transport_failures: 0,
            timeout_failures: 0,
            unknown_failures: 0,
            observed_stream_peak: DEVICE_STREAM_CAP,
            queue_samples: 1,
            max_queue_bytes: 1,
            max_queue_messages: 1,
            bounded_queue: true,
            ordered_streams: DEVICE_STREAM_CAP,
            ordered_records: DEVICE_STREAM_CAP * WORKLOAD_RECORDS_PER_STREAM,
            sibling_progress: true,
            same_stream_producers: SINGLE_STREAM_PRODUCERS,
            same_stream_ordered: true,
            tenant_b_progress: true,
            cancellation_responsive: true,
            cleanup_joined: true,
            fanout_peak_open: 3,
            elapsed_ms: 1,
        }
    }

    #[test]
    fn every_concurrent_load_flag_and_bound_reaches_the_shared_exit_path() {
        type Mutate = (&'static str, fn(&mut ConcurrentLoadEvidence));
        let cases: [Mutate; 25] = [
            ("relay_count", |e| e.relay_count = 2),
            ("membership_ready_relays", |e| e.membership_ready_relays = 2),
            ("non_owner_ingress_relays", |e| {
                e.non_owner_ingress_relays = 1
            }),
            ("attempted_streams", |e| e.attempted_streams = 1),
            ("cap_fill_attempts", |e| e.cap_fill_attempts = 1),
            ("over_cap_attempts", |e| e.over_cap_attempts = 1),
            ("accepted_streams", |e| e.accepted_streams = 1),
            ("fill_capacity_rejections", |e| {
                e.fill_capacity_rejections = 0
            }),
            ("over_cap_capacity_rejections", |e| {
                e.over_cap_capacity_rejections = 0
            }),
            ("reconnecting_failures", |e| e.reconnecting_failures = 1),
            ("transport_failures", |e| e.transport_failures = 1),
            ("timeout_failures", |e| e.timeout_failures = 1),
            ("unknown_failures", |e| e.unknown_failures = 1),
            ("observed_stream_peak", |e| e.observed_stream_peak = 1),
            ("queue_samples", |e| e.queue_samples = 0),
            ("max_queue_bytes", |e| {
                e.max_queue_bytes = 4 * 1024 * 1024 + 1
            }),
            ("max_queue_messages", |e| e.max_queue_messages = 129),
            ("bounded_queue", |e| e.bounded_queue = false),
            ("ordered_streams", |e| e.ordered_streams = 1),
            ("ordered_records", |e| e.ordered_records = 1),
            ("same_stream_producers", |e| e.same_stream_producers = 1),
            ("sibling_progress", |e| e.sibling_progress = false),
            ("same_stream_ordered", |e| e.same_stream_ordered = false),
            ("tenant_b_progress", |e| e.tenant_b_progress = false),
            ("cleanup_joined", |e| e.cleanup_joined = false),
        ];
        for (_, mutate) in cases {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            let diagnostic = assert_failed(validate_concurrent_load_evidence(&evidence));
            assert!(!diagnostic.is_empty());
        }

        let mut evidence = valid_evidence();
        evidence.cancellation_responsive = false;
        assert!(!assert_failed(validate_concurrent_load_evidence(&evidence)).is_empty());
        let mut evidence = valid_evidence();
        evidence.fanout_peak_open = 4;
        assert!(!assert_failed(validate_concurrent_load_evidence(&evidence)).is_empty());
    }
}

/// Run the bounded real three-relay concurrent producer and stream-cap gate.
pub async fn verify() -> Result<ConcurrentLoadEvidence> {
    let started = Instant::now();
    let options = HarnessOptions::from_env()?
        .rotation(super::ROTATION)
        .shared_device_uuid(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("concurrent load harness startup timed out".into()))??;
    let cluster = match timeout(STARTUP_TIMEOUT, ProductionCluster::start(&mut harness)).await {
        Ok(Ok(cluster)) => cluster,
        Ok(Err(error)) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
        Err(_) => {
            let _ = harness.shutdown().await;
            return Err(HarnessError::Timeout(
                "concurrent load production cluster startup timed out".into(),
            ));
        }
    };

    let scenario_deadline = Instant::now() + SCENARIO_TIMEOUT;
    let mut resources = LoadResources::new();
    let scenario = match timeout_at(
        scenario_deadline.into(),
        run(&cluster, &harness, &mut resources, scenario_deadline),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "concurrent load scenario exceeded its bounded deadline".into(),
        )),
    };
    let scenario = match scenario {
        Ok(evidence) => Ok(evidence),
        Err(error) => Err(augment_failure_with_cli_diagnostics(error, &mut resources).await),
    };
    let cleanup_deadline = Instant::now() + CLEANUP_TIMEOUT;
    let resource_cleanup = resources.cleanup_until(cleanup_deadline).await;
    let fanout_cleanup = wait_for_fanouts(&cluster).await;
    let cluster_cleanup = cluster.shutdown().await;
    let harness_cleanup = harness.shutdown().await;

    let (mut evidence, mut failure) = match scenario {
        Ok(evidence) => (Some(evidence), None),
        Err(error) => (None, Some(error)),
    };
    if let Err(error) = resource_cleanup {
        append_failure(&mut failure, "concurrent load resource cleanup", error);
    }
    if let Err(error) = fanout_cleanup {
        append_failure(&mut failure, "concurrent load fanout cleanup", error);
    }
    if let Err(error) = cluster_cleanup {
        append_failure(&mut failure, "concurrent load relay cleanup", error);
    }
    if let Err(error) = harness_cleanup {
        append_failure(&mut failure, "concurrent load Redis cleanup", error);
    }
    if let Some(evidence) = evidence.as_mut() {
        evidence.cleanup_joined = failure.is_none();
        if failure.is_none()
            && let Err(error) = validate_concurrent_load_evidence(evidence)
        {
            append_failure(&mut failure, "concurrent load evidence validation", error);
        }
    }
    match (evidence, failure) {
        (Some(evidence), None) => Ok(evidence),
        (_, Some(error)) => Err(error),
        (None, None) => Err(HarnessError::Process(
            "concurrent load produced no evidence or failure".into(),
        )),
    }
    .map(|mut evidence| {
        evidence.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        evidence
    })
}

struct LoadResources {
    processes: Vec<ManagedProcess>,
    streams: Vec<ConsumerStream>,
    tenant_b_stream: Option<ConsumerStream>,
}

impl LoadResources {
    fn new() -> Self {
        Self {
            processes: Vec::new(),
            streams: Vec::new(),
            tenant_b_stream: None,
        }
    }

    async fn cleanup_until(&mut self, deadline: Instant) -> Result<()> {
        let mut streams = std::mem::take(&mut self.streams);
        if let Some(stream) = self.tenant_b_stream.take() {
            streams.push(stream);
        }
        let processes = std::mem::take(&mut self.processes);
        let (stream_cleanup, process_cleanup) = tokio::join!(
            cleanup_streams_until(streams, deadline),
            cleanup_processes_until(processes, deadline),
        );
        let mut failure = None;
        if let Err(error) = stream_cleanup {
            append_failure(&mut failure, "consumer stream cleanup", error);
        }
        if let Err(error) = process_cleanup {
            append_failure(&mut failure, "client process cleanup", error);
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

const CLI_DIAGNOSTIC_LINE_LIMIT: usize = 32;
const CLI_DIAGNOSTIC_VALUE_LIMIT: usize = 4;
const CLI_DIAGNOSTIC_TOKEN_LIMIT: usize = 48;

/// Keep the client-side terminal code and safe cause category attached to a
/// failed concurrent-load scenario before process cleanup consumes the child.
/// The raw JSON message is intentionally reduced to a bounded category so a
/// transport failure remains diagnostic evidence rather than a capacity claim.
async fn augment_failure_with_cli_diagnostics(
    primary: HarnessError,
    resources: &mut LoadResources,
) -> HarnessError {
    let mut diagnostics = Vec::with_capacity(resources.processes.len());
    for (index, process) in resources.processes.iter_mut().enumerate() {
        diagnostics.push(format!(
            "cli_{index}={}",
            cli_terminal_diagnostic(process).await
        ));
    }
    if diagnostics.is_empty() {
        diagnostics.push("cli_processes=none".to_owned());
    }
    let diagnostics = diagnostics.join(",");
    match primary {
        HarnessError::Process(message) => HarnessError::Process(format!(
            "{message}; concurrent load CLI diagnostics: {diagnostics}"
        )),
        HarnessError::Timeout(message) => HarnessError::Timeout(format!(
            "{message}; concurrent load CLI diagnostics: {diagnostics}"
        )),
        error => HarnessError::Process(format!(
            "{error}; concurrent load CLI diagnostics: {diagnostics}"
        )),
    }
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
    // terminal client state without extending the workload deadline.
    tokio::task::yield_now().await;
    let mut fields = ClientDiagnosticFields::default();
    collect_client_json_errors(&process.stdout(), &mut fields);
    collect_client_json_errors(&process.stderr(), &mut fields);
    format!(
        "{terminal},error_records={},error_codes={:?},error_retryable={:?},error_causes={:?}",
        fields.records, fields.codes, fields.retryable, fields.causes
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
    causes: Vec<String>,
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
        if let Some(retryable) = error.get("retryable").and_then(serde_json::Value::as_bool)
            && fields.retryable.len() < CLI_DIAGNOSTIC_VALUE_LIMIT
        {
            fields.retryable.push(retryable);
        }
        if let Some(message) = error.get("message").and_then(serde_json::Value::as_str) {
            push_cli_cause(&mut fields.causes, message);
        }
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

fn push_cli_cause(values: &mut Vec<String>, message: &str) {
    if values.len() >= CLI_DIAGNOSTIC_VALUE_LIMIT {
        return;
    }
    let cause = classify_cli_cause(message);
    if !values.iter().any(|value| value == cause) {
        values.push(cause.to_owned());
    }
}

/// Reduce the client's safe CLI message to a bounded source category.  The
/// message itself is deliberately omitted because the category is enough to
/// distinguish queue pressure, control/data loss, and generic transport.
fn classify_cli_cause(message: &str) -> &'static str {
    match message {
        "bounded connector queue limit reached" => "queue_limit",
        "authorization confirmation deadline expired" => "authorization_expired",
        "TLS/WebSocket handshake deadline exceeded" => "handshake_timeout",
        "connector cancelled" => "cancelled",
        "connector supervisor failed" => "supervisor_failed",
        "data rotation failed: bounded rotation state failure" => "data_rotation",
        "retained recovery failed: bounded rotation state failure" => "retained_recovery",
        _ => {
            let Some(scope) = message.strip_suffix(" failed") else {
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
    }
}

async fn run(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    resources: &mut LoadResources,
    deadline: Instant,
) -> Result<ConcurrentLoadEvidence> {
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(format!(
            "concurrent load started {} relays, expected three",
            cluster.relays.len()
        )));
    }
    let membership_ready_relays = cluster
        .relays
        .iter()
        .filter(|relay| matches!(relay.membership.readiness(), MembershipReadiness::Ready))
        .count();
    if membership_ready_relays != 3 {
        return Err(HarnessError::Process(format!(
            "concurrent load started with {membership_ready_relays}/3 relays Ready"
        )));
    }

    let device = harness.topology.devices_a.first().ok_or_else(|| {
        HarnessError::InvalidInput("tenant A has no concurrent-load device".into())
    })?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| {
            HarnessError::InvalidInput("concurrent-load device has no echo service".into())
        })?;
    let canary = format!("m7-concurrent-load:{device_id}", device_id = device.id);
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
        HarnessError::InvalidInput(format!("concurrent-load client config: {error}"))
    })?;
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(120),
            ..OidcTokenOptions::default()
        },
    )?;

    let device_b = harness.topology.devices_b.first().ok_or_else(|| {
        HarnessError::InvalidInput("tenant B has no concurrent-load device".into())
    })?;
    if device_b.id != device.id {
        return Err(HarnessError::InvalidInput(
            "concurrent-load fixture did not reuse the device UUID across tenants".into(),
        ));
    }
    let service_b_id = *harness
        .topology
        .service_ids
        .get(&device_b.id)
        .ok_or_else(|| {
            HarnessError::InvalidInput("tenant B concurrent-load device has no echo service".into())
        })?;
    if service_b_id != service_id {
        return Err(HarnessError::InvalidInput(
            "concurrent-load fixture did not reuse the service UUID across tenants".into(),
        ));
    }
    let tenant_b_canary = format!(
        "m7-concurrent-load:tenant-b:{device_id}",
        device_id = device_b.id
    );
    let profile_b_directory = tempdir().map_err(HarnessError::Io)?;
    let mut profile_b = write_device_profile(
        profile_b_directory.path(),
        device_b.id,
        service_b_id,
        &tenant_b_canary,
        cluster.tenant_b_fanout.local_addr(),
        &device_b.certificate.certificate_pem,
        &device_b.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile_b.config.rotation = super::ROTATION;
    profile_b.config.validate().map_err(|error| {
        HarnessError::InvalidInput(format!("tenant-B concurrent-load client config: {error}"))
    })?;
    let token_b = harness.oidc.issue_with(
        &harness.topology.consumers_b[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(120),
            ..OidcTokenOptions::default()
        },
    )?;

    let tenant_a = TenantLoad {
        tenant_id: device.tenant_id,
        device_id: device.id,
        service_id,
        canary: &canary,
        token: &token,
        profile: &profile,
        fanout_addr: cluster.device_fanout.local_addr(),
    };
    let tenant_b = TenantLoad {
        tenant_id: device_b.tenant_id,
        device_id: device_b.id,
        service_id: service_b_id,
        canary: &tenant_b_canary,
        token: &token_b,
        profile: &profile_b,
        fanout_addr: cluster.tenant_b_fanout.local_addr(),
    };
    run_inner(cluster, harness, resources, tenant_a, tenant_b, deadline).await
}

struct TenantLoad<'a> {
    tenant_id: Uuid,
    device_id: Uuid,
    service_id: Uuid,
    canary: &'a str,
    token: &'a str,
    profile: &'a crate::acceptance::helpers::DeviceProfile,
    fanout_addr: std::net::SocketAddr,
}

async fn run_inner(
    cluster: &ProductionCluster,
    harness: &RunningHarness,
    resources: &mut LoadResources,
    tenant_a: TenantLoad<'_>,
    tenant_b: TenantLoad<'_>,
    deadline: Instant,
) -> Result<ConcurrentLoadEvidence> {
    // Bootstrap through the fixture's regular non-owner ingress.  The owner
    // is established by this actual client session, so determine the two
    // non-owner ingress addresses only after the baseline echo succeeds.
    let bootstrap_addr = cluster.relay("relay-b")?.consumer_addr()?;
    let (process, cli_stream) = start_cli_smoke(
        harness,
        tenant_a.fanout_addr,
        bootstrap_addr,
        tenant_a.profile,
        tenant_a.token,
        tenant_a.device_id,
        tenant_a.service_id,
    )
    .await?;
    resources.processes.push(process);
    resources.streams.push(cli_stream);
    let cli_stream = resources
        .streams
        .last_mut()
        .ok_or_else(|| HarnessError::Process("concurrent load lost its CLI stream".into()))?;
    timeout(
        PROBE_TIMEOUT,
        cli_stream.round_trip(b"m7-concurrent-cli-baseline", tenant_a.canary.as_bytes()),
    )
    .await
    .map_err(|_| HarnessError::Timeout("concurrent load CLI baseline timed out".into()))??;

    // Keep one same-UUID tenant-B stream live while tenant A fills and uses
    // its own device cap.  relay-a is outside the tenant-B fanout's expected
    // owner set, so this is a routed public ingress rather than a local echo.
    let tenant_b_bootstrap = cluster.relay("relay-a")?.consumer_addr()?;
    let (process_b, tenant_b_stream) = start_cli_smoke(
        harness,
        tenant_b.fanout_addr,
        tenant_b_bootstrap,
        tenant_b.profile,
        tenant_b.token,
        tenant_b.device_id,
        tenant_b.service_id,
    )
    .await?;
    resources.processes.push(process_b);
    resources.tenant_b_stream = Some(tenant_b_stream);
    let tenant_b_stream = resources
        .tenant_b_stream
        .as_mut()
        .ok_or_else(|| HarnessError::Process("concurrent load lost its tenant-B stream".into()))?;
    timeout(
        PROBE_TIMEOUT,
        tenant_b_stream.round_trip(
            b"m7-concurrent-tenant-b-baseline",
            tenant_b.canary.as_bytes(),
        ),
    )
    .await
    .map_err(|_| HarnessError::Timeout("concurrent load tenant-B baseline timed out".into()))??;

    let owner = cluster
        .catalog
        .current_owner(tenant_a.tenant_id, tenant_a.device_id, Utc::now())
        .await
        .map_err(|_| HarnessError::Redis("reading concurrent-load owner failed".into()))?
        .ok_or_else(|| HarnessError::Process("concurrent-load device has no owner".into()))?;
    let owner_b = cluster
        .catalog
        .current_owner(tenant_b.tenant_id, tenant_b.device_id, Utc::now())
        .await
        .map_err(|_| HarnessError::Redis("reading concurrent-load tenant-B owner failed".into()))?
        .ok_or_else(|| {
            HarnessError::Process("concurrent-load tenant-B device has no owner".into())
        })?;
    if owner_b.token.tenant_id != tenant_b.tenant_id
        || owner_b.token.device_id != tenant_b.device_id
    {
        return Err(HarnessError::Process(
            "concurrent load tenant-B owner scope did not match its tenant/device".into(),
        ));
    }
    let owner_relay = cluster.relay(&owner.token.node_id)?;
    let ingress_relays: Vec<&ProductionRelay> = cluster
        .relays
        .iter()
        .filter(|relay| relay.node_id != owner.token.node_id)
        .take(2)
        .collect();
    if ingress_relays.len() != 2 {
        return Err(HarnessError::Process(
            "concurrent load could not select two non-owner ingress relays".into(),
        ));
    }
    let ingress_addresses = [
        ingress_relays[0].consumer_addr()?,
        ingress_relays[1].consumer_addr()?,
    ];

    let server_ca_der = harness.pki.server_ca.certificate_der.clone();
    let canary_bytes = Arc::new(tenant_a.canary.as_bytes().to_vec());
    let fill = run_probe_batch_windowed(
        CAP_FILL_ATTEMPTS,
        1,
        ProbeBatchContext {
            ingress_addresses,
            server_ca_der: server_ca_der.clone(),
            token: tenant_a.token.to_owned(),
            device_id: tenant_a.device_id,
            service_id: tenant_a.service_id,
            canary: Arc::clone(&canary_bytes),
            scenario_deadline: deadline,
        },
        CAP_FILL_WINDOW,
    )
    .await?;
    if fill.accepted.len() != CAP_FILL_ATTEMPTS.saturating_sub(1) || fill.capacity_rejections != 1 {
        let primary = HarnessError::Process(
            "concurrent load did not fill exactly 63 consumer streams beside the CLI stream with one explicit capacity refusal".into(),
        );
        let cleanup = cleanup_streams_until(
            fill.accepted
                .into_iter()
                .map(|probe| probe.stream)
                .collect(),
            bounded_deadline(deadline, STREAM_CLOSE_TIMEOUT),
        )
        .await;
        return match cleanup {
            Ok(()) => Err(primary),
            Err(error) => Err(HarnessError::Process(format!(
                "{primary}; fill stream cleanup also failed: {error}"
            ))),
        };
    }
    resources
        .streams
        .extend(fill.accepted.into_iter().map(|probe| probe.stream));

    let same_stream = run_same_stream_producers(
        resources
            .streams
            .first_mut()
            .ok_or_else(|| HarnessError::Process("concurrent load lost its CLI stream".into()))?,
        tenant_a.canary.as_bytes(),
        deadline,
    )
    .await?;

    // Capture the owner-side session while every successfully probed stream is
    // still held open.  The subsequent attempts are therefore genuinely
    // over-cap attempts rather than an inference from failed handshakes.
    let mut observation = LoadObservation::default();
    observe_snapshot(owner_relay, tenant_a.device_id, &mut observation).await?;

    let over_cap_attempts = TOTAL_STREAM_ATTEMPTS
        .saturating_sub(1)
        .saturating_sub(CAP_FILL_ATTEMPTS);
    let over_cap = run_probe_batch_windowed(
        over_cap_attempts,
        1 + CAP_FILL_ATTEMPTS,
        ProbeBatchContext {
            ingress_addresses,
            server_ca_der,
            token: tenant_a.token.to_owned(),
            device_id: tenant_a.device_id,
            service_id: tenant_a.service_id,
            canary: canary_bytes,
            scenario_deadline: deadline,
        },
        CAP_FILL_WINDOW,
    )
    .await?;
    if !over_cap.accepted.is_empty() {
        let primary =
            HarnessError::Process("concurrent load over-cap stream completed an echo".into());
        let cleanup = cleanup_streams_until(
            over_cap
                .accepted
                .into_iter()
                .map(|probe| probe.stream)
                .collect(),
            bounded_deadline(deadline, STREAM_CLOSE_TIMEOUT),
        )
        .await;
        return match cleanup {
            Ok(()) => Err(primary),
            Err(error) => Err(HarnessError::Process(format!(
                "{primary}; over-cap stream cleanup also failed: {error}"
            ))),
        };
    }

    let accepted_streams = resources.streams.len();
    if accepted_streams == 0 {
        return Err(HarnessError::Process(
            "concurrent load accepted no streams".into(),
        ));
    }
    let worker_streams = std::mem::take(&mut resources.streams);
    let load = run_load_workers(LoadWorkload {
        owner_relay,
        device_id: tenant_a.device_id,
        streams: worker_streams,
        canary: tenant_a.canary.as_bytes(),
        observation: &mut observation,
        tenant_b_stream: resources.tenant_b_stream.as_mut().ok_or_else(|| {
            HarnessError::Process("concurrent load lost its tenant-B stream".into())
        })?,
        tenant_b_canary: tenant_b.canary.as_bytes(),
        scenario_deadline: deadline,
    })
    .await?;
    let fanout_peak_open = cluster.device_fanout.diagnostics().peak_open;

    Ok(ConcurrentLoadEvidence {
        relay_count: cluster.relays.len(),
        membership_ready_relays: cluster
            .relays
            .iter()
            .filter(|relay| matches!(relay.membership.readiness(), MembershipReadiness::Ready))
            .count(),
        non_owner_ingress_relays: ingress_addresses.len(),
        attempted_streams: 1 + CAP_FILL_ATTEMPTS + over_cap_attempts,
        cap_fill_attempts: CAP_FILL_ATTEMPTS,
        over_cap_attempts,
        accepted_streams,
        fill_capacity_rejections: fill.capacity_rejections,
        over_cap_capacity_rejections: over_cap.capacity_rejections,
        reconnecting_failures: fill.reconnecting_failures + over_cap.reconnecting_failures,
        transport_failures: fill.transport_failures + over_cap.transport_failures,
        timeout_failures: fill.timeout_failures + over_cap.timeout_failures,
        unknown_failures: fill.unknown_failures + over_cap.unknown_failures,
        observed_stream_peak: observation.max_streams,
        queue_samples: observation.samples,
        max_queue_bytes: observation.max_queue_bytes,
        max_queue_messages: observation.max_queue_messages,
        bounded_queue: observation.bounded,
        ordered_streams: load.ordered_streams,
        ordered_records: load.ordered_records,
        sibling_progress: load.sibling_progress,
        same_stream_producers: same_stream.producers,
        same_stream_ordered: same_stream.ordered,
        tenant_b_progress: load.tenant_b_progress,
        cancellation_responsive: load.cancellation_responsive,
        cleanup_joined: false,
        fanout_peak_open,
        elapsed_ms: 0,
    })
}

enum ProbeResult {
    Accepted(Box<ProbeStream>),
    Capacity,
    Failure(ProbeFailure),
}

struct ProbeStream {
    stream: ConsumerStream,
}

#[derive(Clone, Copy, Debug)]
enum ProbeFailure {
    Reconnecting,
    /// A bounded source category is retained so a failed probe is not
    /// misreported as capacity without exposing tungstenite text, endpoints,
    /// credentials, or payloads.
    Transport(&'static str),
    UnexpectedHttpStatus {
        status: u16,
        code: &'static str,
    },
    Timeout,
    Unknown,
}

struct ProbeBatch {
    accepted: Vec<ProbeStream>,
    capacity_rejections: usize,
    reconnecting_failures: usize,
    transport_failures: usize,
    timeout_failures: usize,
    unknown_failures: usize,
}

impl ProbeBatch {
    fn empty() -> Self {
        Self {
            accepted: Vec::new(),
            capacity_rejections: 0,
            reconnecting_failures: 0,
            transport_failures: 0,
            timeout_failures: 0,
            unknown_failures: 0,
        }
    }

    fn append(&mut self, mut batch: Self) {
        self.accepted.append(&mut batch.accepted);
        self.capacity_rejections += batch.capacity_rejections;
        self.reconnecting_failures += batch.reconnecting_failures;
        self.transport_failures += batch.transport_failures;
        self.timeout_failures += batch.timeout_failures;
        self.unknown_failures += batch.unknown_failures;
    }
}

#[derive(Clone)]
struct ProbeBatchContext {
    ingress_addresses: [std::net::SocketAddr; 2],
    server_ca_der: Vec<u8>,
    token: String,
    device_id: Uuid,
    service_id: Uuid,
    canary: Arc<Vec<u8>>,
    scenario_deadline: Instant,
}

/// Admit streams in bounded windows, retaining every accepted stream for the
/// later workload.  Waiting for a complete round trip per window allows the
/// connector to drain its finite control responses before the next four OPENs
/// arrive; it leaves the separate control-queue burst regression explicit in
/// the module contract instead of misclassifying that pressure as capacity.
async fn run_probe_batch_windowed(
    attempts: usize,
    index_offset: usize,
    context: ProbeBatchContext,
    window: usize,
) -> Result<ProbeBatch> {
    if window == 0 {
        return Err(HarnessError::InvalidInput(
            "concurrent load admission window must be non-zero".into(),
        ));
    }
    let mut aggregate = ProbeBatch::empty();
    let mut offset = 0;
    while offset < attempts {
        let remaining = attempts - offset;
        let size = remaining.min(window);
        let batch = match run_probe_batch(
            size,
            index_offset + offset,
            ProbeBatchContext {
                ingress_addresses: context.ingress_addresses,
                server_ca_der: context.server_ca_der.clone(),
                token: context.token.clone(),
                device_id: context.device_id,
                service_id: context.service_id,
                canary: Arc::clone(&context.canary),
                scenario_deadline: context.scenario_deadline,
            },
        )
        .await
        {
            Ok(batch) => batch,
            Err(error) => {
                let cleanup = cleanup_streams_until(
                    aggregate
                        .accepted
                        .into_iter()
                        .map(|probe| probe.stream)
                        .collect(),
                    bounded_deadline(context.scenario_deadline, STREAM_CLOSE_TIMEOUT),
                )
                .await;
                return match cleanup {
                    Ok(()) => Err(error),
                    Err(cleanup_error) => Err(HarnessError::Process(format!(
                        "{error}; windowed fill cleanup also failed: {cleanup_error}"
                    ))),
                };
            }
        };
        aggregate.append(batch);
        offset += size;
    }
    Ok(aggregate)
}

async fn run_probe_batch(
    attempts: usize,
    index_offset: usize,
    context: ProbeBatchContext,
) -> Result<ProbeBatch> {
    let scenario_deadline = context.scenario_deadline;
    let deadline = bounded_deadline(scenario_deadline, PROBE_BATCH_TIMEOUT);
    let joined = run_probe_batch_inner(attempts, index_offset, context, deadline).await?;

    let mut accepted = Vec::new();
    let mut capacity_rejections = 0;
    let mut reconnecting_failures = 0;
    let mut transport_failures = 0;
    let mut transport_causes = Vec::new();
    let mut unexpected_http_statuses = Vec::new();
    let mut timeout_failures = 0;
    let mut unknown_failures = 0;
    for result in joined {
        match result {
            ProbeResult::Accepted(stream) => accepted.push(*stream),
            ProbeResult::Capacity => capacity_rejections += 1,
            ProbeResult::Failure(ProbeFailure::Reconnecting) => reconnecting_failures += 1,
            ProbeResult::Failure(ProbeFailure::Transport(cause)) => {
                transport_failures += 1;
                if transport_causes.len() < 4 && !transport_causes.contains(&cause) {
                    transport_causes.push(cause);
                }
            }
            ProbeResult::Failure(ProbeFailure::UnexpectedHttpStatus { status, code }) => {
                transport_failures += 1;
                let cause = "unexpected_http_status";
                if transport_causes.len() < 4 && !transport_causes.contains(&cause) {
                    transport_causes.push(cause);
                }
                let observation = (status, code);
                if unexpected_http_statuses.len() < 4
                    && !unexpected_http_statuses.contains(&observation)
                {
                    unexpected_http_statuses.push(observation);
                }
            }
            ProbeResult::Failure(ProbeFailure::Timeout) => timeout_failures += 1,
            ProbeResult::Failure(ProbeFailure::Unknown) => unknown_failures += 1,
        }
    }
    if reconnecting_failures != 0
        || transport_failures != 0
        || timeout_failures != 0
        || unknown_failures != 0
    {
        let cleanup = cleanup_streams_until(
            accepted.into_iter().map(|probe| probe.stream).collect(),
            bounded_deadline(scenario_deadline, STREAM_CLOSE_TIMEOUT),
        )
        .await;
        let mut failure = HarnessError::Process(format!(
            "concurrent load stream outcomes were not capacity-only: index_range={}..{},reconnecting={reconnecting_failures},transport={transport_failures},timeout={timeout_failures},unknown={unknown_failures},transport_causes={transport_causes:?},unexpected_http_statuses={unexpected_http_statuses:?}",
            index_offset,
            index_offset.saturating_add(attempts),
        ));
        if let Err(error) = cleanup {
            failure = HarnessError::Process(format!(
                "{failure}; probe stream cleanup also failed: {error}"
            ));
        }
        return Err(failure);
    }
    Ok(ProbeBatch {
        accepted,
        capacity_rejections,
        reconnecting_failures,
        transport_failures,
        timeout_failures,
        unknown_failures,
    })
}

async fn run_probe_batch_inner(
    attempts: usize,
    index_offset: usize,
    context: ProbeBatchContext,
    deadline: Instant,
) -> Result<Vec<ProbeResult>> {
    let mut tasks = JoinSet::new();
    for offset in 0..attempts {
        let ca = context.server_ca_der.clone();
        let task_token = context.token.clone();
        let task_canary = Arc::clone(&context.canary);
        let consumer_addr = context.ingress_addresses[offset % context.ingress_addresses.len()];
        let device_id = context.device_id;
        let service_id = context.service_id;
        tasks.spawn(async move {
            probe_one(
                index_offset + offset,
                consumer_addr,
                &ca,
                &task_token,
                device_id,
                service_id,
                task_canary.as_slice(),
            )
            .await
        });
    }
    let mut results = Vec::with_capacity(attempts);
    while !tasks.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            tasks.abort_all();
            let join_errors = abort_and_join(&mut tasks, deadline, "stream probe").await;
            return Err(HarnessError::Process(format_join_errors(
                "concurrent load stream admission deadline expired",
                join_errors,
            )));
        }
        match timeout(remaining, tasks.join_next()).await {
            Ok(Some(Ok(result))) => results.push(result),
            Ok(Some(Err(error))) => {
                tasks.abort_all();
                let join_errors = abort_and_join(&mut tasks, deadline, "stream probe").await;
                let mut message = format!("concurrent load stream probe task failed: {error}");
                if !join_errors.is_empty() {
                    message.push_str("; ");
                    message.push_str(&format_join_errors("probe task cleanup", join_errors));
                }
                return Err(HarnessError::Process(message));
            }
            Ok(None) => break,
            Err(_) => {
                tasks.abort_all();
                let join_errors = abort_and_join(&mut tasks, deadline, "stream probe").await;
                return Err(HarnessError::Process(format_join_errors(
                    "concurrent load stream admission timed out",
                    join_errors,
                )));
            }
        }
    }
    if results.len() != attempts {
        return Err(HarnessError::Process(format!(
            "concurrent load stream admission joined {} of {} probes",
            results.len(),
            attempts
        )));
    }
    Ok(results)
}

async fn probe_one(
    index: usize,
    consumer_addr: std::net::SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
    canary: &[u8],
) -> ProbeResult {
    let opened = match timeout(
        PROBE_TIMEOUT,
        open_consumer_stream(consumer_addr, server_ca_der, token, device_id, service_id),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(super::StreamConnectFailure::Status { status, body })) => {
            return classify_status_failure(status, body.as_deref());
        }
        Ok(Err(super::StreamConnectFailure::Harness(error))) => {
            return ProbeResult::Failure(classify_harness_failure(&error));
        }
        Err(_) => return ProbeResult::Failure(ProbeFailure::Timeout),
    };
    let mut stream = opened;
    let payload = probe_payload(index);
    match timeout(PROBE_TIMEOUT, stream.round_trip(&payload, canary)).await {
        Ok(Ok(())) => ProbeResult::Accepted(Box::new(ProbeStream { stream })),
        Ok(Err(error)) => {
            let close = timeout(STREAM_CLOSE_TIMEOUT, stream.close()).await;
            if close.is_err() {
                return ProbeResult::Failure(ProbeFailure::Unknown);
            }
            ProbeResult::Failure(classify_harness_failure(&error))
        }
        Err(_) => {
            if timeout(STREAM_CLOSE_TIMEOUT, stream.close()).await.is_err() {
                return ProbeResult::Failure(ProbeFailure::Unknown);
            }
            ProbeResult::Failure(ProbeFailure::Timeout)
        }
    }
}

fn classify_status_failure(status: u16, body: Option<&[u8]>) -> ProbeResult {
    let code = body
        .filter(|body| body.len() <= MAX_ERROR_BODY_BYTES)
        .and_then(|body| serde_json::from_slice::<serde_json::Value>(body).ok())
        .and_then(|value| {
            value
                .get("code")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        });
    match (status, code.as_deref()) {
        (429, Some("RESOURCE_EXHAUSTED" | "STREAM_LIMIT")) => ProbeResult::Capacity,
        (_, Some("RECONNECTING")) => ProbeResult::Failure(ProbeFailure::Reconnecting),
        _ => ProbeResult::Failure(ProbeFailure::UnexpectedHttpStatus {
            status,
            code: match code.as_deref() {
                Some("CLUSTER_UNREADY") => "CLUSTER_UNREADY",
                Some("PEER_UNTRUSTED") => "PEER_UNTRUSTED",
                Some("PEER_UNAVAILABLE") => "PEER_UNAVAILABLE",
                Some("STREAM_LIMIT") => "STREAM_LIMIT",
                Some("RESOURCE_EXHAUSTED") => "RESOURCE_EXHAUSTED",
                Some("RATE_LIMITED") => "RATE_LIMITED",
                Some("ADMISSION_LIMIT") => "ADMISSION_LIMIT",
                Some("SOCKET_LIMIT") => "SOCKET_LIMIT",
                Some("UNAUTHORIZED") => "UNAUTHORIZED",
                Some("FORBIDDEN") => "FORBIDDEN",
                Some(_) => "other",
                None => "absent_or_malformed",
            },
        }),
    }
}

fn classify_harness_failure(error: &HarnessError) -> ProbeFailure {
    match error {
        HarnessError::Timeout(_) => ProbeFailure::Timeout,
        HarnessError::Http(message) => ProbeFailure::Transport(classify_http_probe_cause(message)),
        _ => ProbeFailure::Unknown,
    }
}

/// Map only source-stable harness phases to bounded labels. The original
/// tungstenite/backend text is intentionally discarded.
fn classify_http_probe_cause(message: &str) -> &'static str {
    if message == "consumer protocol was not selected" {
        "protocol_not_selected"
    } else if message.starts_with("consumer handshake failed:") {
        "handshake_failed"
    } else if message.starts_with("sending production echo:") {
        "echo_send_failed"
    } else if message.starts_with("reading production echo:") {
        "echo_read_failed"
    } else if message == "production echo closed before response" {
        "echo_closed_before_response"
    } else if message == "production echo returned text" {
        "echo_unexpected_text"
    } else if message == "production echo response mismatch" {
        "echo_response_mismatch"
    } else {
        "http_probe_failed"
    }
}

fn probe_payload(index: usize) -> Vec<u8> {
    let mut payload = vec![0_u8; PROBE_PAYLOAD_BYTES];
    let bytes = index.to_be_bytes();
    for (offset, byte) in payload.iter_mut().enumerate() {
        *byte = bytes[offset % bytes.len()] ^ (offset as u8).wrapping_mul(17);
    }
    payload
}

struct SameStreamEvidence {
    producers: usize,
    ordered: bool,
}

/// Feed one real public stream from bounded concurrent producer tasks.  The
/// stream itself remains one ordered writer at the actor boundary, so this
/// proves the harness's producer fan-in and response matching.  It does not
/// expose the relay's private sequence-reservation counters or prove that
/// concurrent actor sends reserve unique monotonic sequence numbers.  EC-030's
/// internal reservation proof remains a core-level responsibility.
async fn run_same_stream_producers(
    stream: &mut ConsumerStream,
    canary: &[u8],
    scenario_deadline: Instant,
) -> Result<SameStreamEvidence> {
    let (sender, mut receiver) = mpsc::channel(SINGLE_STREAM_PRODUCERS);
    let mut producers = JoinSet::new();
    for index in 0..SINGLE_STREAM_PRODUCERS {
        let sender = sender.clone();
        producers.spawn(async move {
            sender
                .send((index, workload_payload(index, 0)))
                .await
                .map_err(|_| HarnessError::Process("same-stream producer queue closed".into()))
        });
    }
    drop(sender);

    let deadline = bounded_deadline(scenario_deadline, PROBE_BATCH_TIMEOUT);
    let mut acceptance_order = Vec::with_capacity(SINGLE_STREAM_PRODUCERS);
    let mut primary = None;
    loop {
        let item = match timeout_at(deadline.into(), receiver.recv()).await {
            Ok(item) => item,
            Err(_) => {
                primary = Some(HarnessError::Timeout(
                    "same-stream producer fan-in timed out".into(),
                ));
                break;
            }
        };
        let Some((index, payload)) = item else {
            break;
        };
        match timeout(PROBE_TIMEOUT, stream.round_trip(&payload, canary)).await {
            Ok(Ok(())) => acceptance_order.push(index),
            Ok(Err(error)) => {
                primary = Some(error);
                break;
            }
            Err(_) => {
                primary = Some(HarnessError::Timeout(
                    "same-stream producer response timed out".into(),
                ));
                break;
            }
        }
    }
    let join_errors = join_result_tasks(&mut producers, deadline, "same-stream producers").await;
    if let Some(primary) = primary {
        if join_errors.is_empty() {
            return Err(primary);
        }
        return Err(HarnessError::Process(format_join_errors(
            &primary.to_string(),
            join_errors,
        )));
    }
    if !join_errors.is_empty() {
        return Err(HarnessError::Process(format_join_errors(
            "same-stream producer task failed",
            join_errors,
        )));
    }
    let mut sorted = acceptance_order.clone();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != SINGLE_STREAM_PRODUCERS || acceptance_order.len() != SINGLE_STREAM_PRODUCERS
    {
        return Err(HarnessError::Process(
            "same-stream producer acceptance order was incomplete or duplicated".into(),
        ));
    }
    Ok(SameStreamEvidence {
        producers: SINGLE_STREAM_PRODUCERS,
        ordered: true,
    })
}

struct LoadObservation {
    samples: usize,
    max_streams: usize,
    max_queue_bytes: usize,
    max_queue_messages: usize,
    bounded: bool,
}

impl Default for LoadObservation {
    fn default() -> Self {
        Self {
            samples: 0,
            max_streams: 0,
            max_queue_bytes: 0,
            max_queue_messages: 0,
            bounded: true,
        }
    }
}

impl LoadObservation {
    fn record(&mut self, streams: usize, queue_bytes: usize, queue_messages: usize) {
        self.samples = self.samples.saturating_add(1);
        self.max_streams = self.max_streams.max(streams);
        self.max_queue_bytes = self.max_queue_bytes.max(queue_bytes);
        self.max_queue_messages = self.max_queue_messages.max(queue_messages);
        self.bounded &= queue_bytes <= QUEUE_LIMIT_BYTES && queue_messages <= QUEUE_LIMIT_MESSAGES;
    }
}

async fn observe_snapshot(
    owner_relay: &ProductionRelay,
    device_id: Uuid,
    observation: &mut LoadObservation,
) -> Result<()> {
    let snapshot = owner_relay.snapshot().await?;
    let device_key = device_id.to_string();
    let session = snapshot
        .sessions
        .iter()
        .find(|session| session.device_id == device_key)
        .ok_or_else(|| HarnessError::Process("concurrent load owner session disappeared".into()))?;
    observation.record(
        session.streams.len(),
        session.queue_bytes,
        session.queue_messages,
    );
    if session.queue_bytes > QUEUE_LIMIT_BYTES {
        return Err(HarnessError::Process(
            "concurrent load owner queue exceeded its bounded budget".into(),
        ));
    }
    if session.queue_messages > QUEUE_LIMIT_MESSAGES {
        return Err(HarnessError::Process(
            "concurrent load owner queue exceeded its bounded message budget".into(),
        ));
    }
    Ok(())
}

struct LoadResult {
    ordered_streams: usize,
    ordered_records: usize,
    sibling_progress: bool,
    tenant_b_progress: bool,
    cancellation_responsive: bool,
}

struct LoadWorkload<'a> {
    owner_relay: &'a ProductionRelay,
    device_id: Uuid,
    streams: Vec<ConsumerStream>,
    canary: &'a [u8],
    observation: &'a mut LoadObservation,
    tenant_b_stream: &'a mut ConsumerStream,
    tenant_b_canary: &'a [u8],
    scenario_deadline: Instant,
}

async fn run_load_workers(workload: LoadWorkload<'_>) -> Result<LoadResult> {
    let LoadWorkload {
        owner_relay,
        device_id,
        streams,
        canary,
        observation,
        tenant_b_stream,
        tenant_b_canary,
        scenario_deadline,
    } = workload;
    let accepted_streams = streams.len();
    let release = CancellationToken::new();
    let failure = CancellationToken::new();
    let ready = Arc::new(AtomicUsize::new(0));
    let canary = Arc::new(canary.to_vec());
    let mut tasks = JoinSet::new();
    for (index, stream) in streams.into_iter().enumerate() {
        let ready = Arc::clone(&ready);
        let release = release.clone();
        let failure = failure.clone();
        let canary = Arc::clone(&canary);
        tasks.spawn(async move {
            run_stream_worker(index, stream, canary, ready, release, failure).await
        });
    }

    let deadline = bounded_deadline(scenario_deadline, LOAD_TIMEOUT);
    let mut results = Vec::with_capacity(accepted_streams);
    let mut released = false;
    let mut tenant_b_progress = false;
    while results.len() < accepted_streams {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            failure.cancel();
            release.cancel();
            let join_errors = abort_and_join(&mut tasks, deadline, "load worker").await;
            let mut primary = HarnessError::Timeout(
                "concurrent load workers exceeded their bounded deadline".into(),
            );
            if !join_errors.is_empty() {
                primary =
                    HarnessError::Process(format_join_errors(&primary.to_string(), join_errors));
            }
            return Err(primary);
        }
        tokio::select! {
            result = timeout(remaining, tasks.join_next()) => {
                match result {
                    Ok(Some(Ok(Ok(worker)))) => results.push(worker),
                    Ok(Some(Ok(Err(error)))) => {
                        failure.cancel();
                        release.cancel();
                        let join_errors = cancel_and_join(&mut tasks, deadline, "load worker").await;
                        let mut primary = error;
                        if !join_errors.is_empty() {
                            primary = HarnessError::Process(format_join_errors(
                                &primary.to_string(),
                                join_errors,
                            ));
                        }
                        return Err(primary);
                    }
                    Ok(Some(Err(error))) => {
                        failure.cancel();
                        release.cancel();
                        let join_errors = cancel_and_join(&mut tasks, deadline, "load worker").await;
                        let mut message = format!("concurrent load stream worker task failed: {error}");
                        if !join_errors.is_empty() {
                            message.push_str("; ");
                            message.push_str(&format_join_errors("worker task cleanup", join_errors));
                        }
                        return Err(HarnessError::Process(message));
                    }
                    Ok(None) => {
                        failure.cancel();
                        release.cancel();
                        let join_errors = cancel_and_join(&mut tasks, deadline, "load worker").await;
                        if !join_errors.is_empty() {
                            return Err(HarnessError::Process(format_join_errors(
                                "concurrent load worker set ended before all streams joined",
                                join_errors,
                            )));
                        }
                        return Err(HarnessError::Process(
                            "concurrent load worker set ended before all streams joined".into(),
                        ));
                    }
                    Err(_) => {
                        failure.cancel();
                        release.cancel();
                        let join_errors = cancel_and_join(&mut tasks, deadline, "load worker").await;
                        let mut message =
                            "concurrent load workers exceeded their bounded deadline".to_owned();
                        if !join_errors.is_empty() {
                            message.push_str("; ");
                            message.push_str(&format_join_errors("worker task cleanup", join_errors));
                        }
                        return Err(HarnessError::Timeout(message));
                    }
                }
            }
            _ = sleep(LOAD_SNAPSHOT_POLL.min(remaining)) => {
                if let Err(error) = observe_snapshot(owner_relay, device_id, observation).await {
                    failure.cancel();
                    release.cancel();
                    let join_errors = cancel_and_join(&mut tasks, deadline, "load worker").await;
                    if join_errors.is_empty() {
                        return Err(error);
                    }
                    return Err(HarnessError::Process(format_join_errors(
                        &error.to_string(),
                        join_errors,
                    )));
                }
            }
        }
        if !released && ready.load(Ordering::Acquire) == accepted_streams {
            if let Err(error) = observe_snapshot(owner_relay, device_id, observation).await {
                failure.cancel();
                release.cancel();
                let join_errors = cancel_and_join(&mut tasks, deadline, "load worker").await;
                if join_errors.is_empty() {
                    return Err(error);
                }
                return Err(HarnessError::Process(format_join_errors(
                    &error.to_string(),
                    join_errors,
                )));
            }
            let tenant_b_result = timeout(
                PROBE_TIMEOUT,
                tenant_b_stream.round_trip(b"m7-concurrent-tenant-b-during-load", tenant_b_canary),
            )
            .await
            .map_err(|_| {
                HarnessError::Timeout("tenant-B concurrent load response timed out".into())
            })
            .and_then(|result| result);
            if let Err(error) = tenant_b_result {
                failure.cancel();
                release.cancel();
                let join_errors = cancel_and_join(&mut tasks, deadline, "load worker").await;
                if join_errors.is_empty() {
                    return Err(error);
                }
                return Err(HarnessError::Process(format_join_errors(
                    &error.to_string(),
                    join_errors,
                )));
            }
            tenant_b_progress = true;
            release.cancel();
            released = true;
        }
    }
    if !released {
        release.cancel();
    }
    let ordered_streams = results.len();
    let ordered_records = results.iter().map(|worker| worker.records).sum();
    let sibling_progress = results
        .iter()
        .any(|worker| worker.index == 0 && worker.records == WORKLOAD_RECORDS_PER_STREAM);
    Ok(LoadResult {
        ordered_streams,
        ordered_records,
        sibling_progress,
        tenant_b_progress,
        cancellation_responsive: released,
    })
}

struct WorkerResult {
    index: usize,
    records: usize,
}

async fn run_stream_worker(
    index: usize,
    mut stream: ConsumerStream,
    canary: Arc<Vec<u8>>,
    ready: Arc<AtomicUsize>,
    release: CancellationToken,
    failure: CancellationToken,
) -> Result<WorkerResult> {
    let mut records = 0;
    for sequence in 0..WORKLOAD_RECORDS_PER_STREAM {
        if failure.is_cancelled() {
            let _ = timeout(STREAM_CLOSE_TIMEOUT, stream.close()).await;
            return Err(HarnessError::Process(
                "concurrent load worker cancelled after a sibling failure".into(),
            ));
        }
        let payload = workload_payload(index, sequence);
        match timeout(
            PROBE_TIMEOUT,
            stream.round_trip(&payload, canary.as_slice()),
        )
        .await
        {
            Ok(Ok(())) => records += 1,
            Ok(Err(_)) | Err(_) => {
                failure.cancel();
                let _ = timeout(STREAM_CLOSE_TIMEOUT, stream.close()).await;
                return Err(HarnessError::Process(
                    "concurrent load stream lost ordered echo progress".into(),
                ));
            }
        }
    }
    ready.fetch_add(1, Ordering::Release);
    tokio::select! {
        _ = release.cancelled() => {}
        _ = sleep(WORKER_HOLD_TIMEOUT) => {
            failure.cancel();
            let _ = timeout(STREAM_CLOSE_TIMEOUT, stream.close()).await;
            return Err(HarnessError::Timeout("concurrent load worker release timed out".into()));
        }
    }
    timeout(STREAM_CLOSE_TIMEOUT, stream.close())
        .await
        .map_err(|_| HarnessError::Timeout("concurrent load stream close timed out".into()))??;
    Ok(WorkerResult { index, records })
}

fn workload_payload(index: usize, sequence: usize) -> Vec<u8> {
    let mut payload = vec![0_u8; WORKLOAD_PAYLOAD_BYTES];
    let index = index.to_be_bytes();
    let sequence = sequence.to_be_bytes();
    for (offset, byte) in payload.iter_mut().enumerate() {
        *byte = index[offset % index.len()]
            .wrapping_add(sequence[offset % sequence.len()])
            .wrapping_add((offset as u8).wrapping_mul(13));
    }
    payload
}

async fn abort_and_join<T>(tasks: &mut JoinSet<T>, deadline: Instant, label: &str) -> Vec<String>
where
    T: Send + 'static,
{
    tasks.abort_all();
    let mut errors = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            errors.push(format!(
                "{label} tasks did not join before the shared deadline"
            ));
            break;
        }
        match timeout(remaining, tasks.join_next()).await {
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(error))) if !error.is_cancelled() => {
                errors.push(format!("{label} task join failed: {error}"))
            }
            Ok(Some(Err(_))) => {}
            Ok(None) => break,
            Err(_) => {
                errors.push(format!(
                    "{label} tasks did not join before the shared deadline"
                ));
                break;
            }
        }
    }
    if !tasks.is_empty() {
        tasks.abort_all();
    }
    errors
}

/// Give owned stream workers a chance to observe the shared cancellation
/// tokens and close their sockets before aborting anything that remains.  A
/// JoinSet drop would abort without joining, so any residual task is reported
/// explicitly if the shared deadline is exhausted.
async fn cancel_and_join<T>(tasks: &mut JoinSet<T>, deadline: Instant, label: &str) -> Vec<String>
where
    T: Send + 'static,
{
    let mut errors = Vec::new();
    while !tasks.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            errors.push(format!(
                "{label} tasks did not join before the shared deadline"
            ));
            break;
        }
        match timeout(remaining, tasks.join_next()).await {
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(error))) if !error.is_cancelled() => {
                errors.push(format!("{label} task join failed: {error}"));
            }
            Ok(Some(Err(_))) => {}
            Ok(None) => break,
            Err(_) => {
                errors.push(format!(
                    "{label} tasks did not join before the shared deadline"
                ));
                break;
            }
        }
    }
    if !tasks.is_empty() {
        tasks.abort_all();
        errors.extend(abort_and_join(tasks, deadline, label).await);
    }
    errors
}

async fn join_result_tasks<T>(
    tasks: &mut JoinSet<Result<T>>,
    deadline: Instant,
    label: &str,
) -> Vec<String>
where
    T: Send + 'static,
{
    let mut errors = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            errors.push(format!("{label} tasks exceeded the shared deadline"));
            errors.extend(abort_and_join(tasks, deadline, label).await);
            break;
        }
        match timeout(remaining, tasks.join_next()).await {
            Ok(Some(Ok(Ok(_)))) => {}
            Ok(Some(Ok(Err(error)))) => {
                errors.push(format!("{label} task failed: {error}"));
                errors.extend(abort_and_join(tasks, deadline, label).await);
                break;
            }
            Ok(Some(Err(error))) => {
                errors.push(format!("{label} task join failed: {error}"));
                errors.extend(abort_and_join(tasks, deadline, label).await);
                break;
            }
            Ok(None) => break,
            Err(_) => {
                errors.push(format!("{label} tasks exceeded the shared deadline"));
                errors.extend(abort_and_join(tasks, deadline, label).await);
                break;
            }
        }
    }
    errors
}

fn format_join_errors(label: &str, errors: Vec<String>) -> String {
    if errors.is_empty() {
        label.to_owned()
    } else {
        format!("{label}: {}", errors.join("; "))
    }
}

async fn cleanup_streams_until(streams: Vec<ConsumerStream>, deadline: Instant) -> Result<()> {
    let mut tasks = JoinSet::new();
    for (index, mut stream) in streams.into_iter().enumerate() {
        tasks.spawn(async move {
            timeout_at(deadline.into(), stream.close())
                .await
                .map_err(|_| {
                    HarnessError::Timeout(format!(
                        "concurrent load stream {index} cleanup exceeded the shared deadline"
                    ))
                })??;
            Ok(())
        });
    }
    let errors = join_result_tasks(&mut tasks, deadline, "consumer cleanup").await;
    if errors.is_empty() {
        Ok(())
    } else {
        Err(HarnessError::Process(format_join_errors(
            "concurrent load consumer cleanup failed",
            errors,
        )))
    }
}

async fn cleanup_processes_until(processes: Vec<ManagedProcess>, deadline: Instant) -> Result<()> {
    let mut tasks = JoinSet::new();
    for (index, process) in processes.into_iter().enumerate() {
        tasks.spawn(async move {
            timeout_at(deadline.into(), process.shutdown(PROCESS_SHUTDOWN_TIMEOUT))
                .await
                .map_err(|_| {
                    HarnessError::Timeout(format!(
                        "concurrent load client process {index} cleanup exceeded the shared deadline"
                    ))
                })??;
            Ok(())
        });
    }
    let errors = join_result_tasks(&mut tasks, deadline, "client process cleanup").await;
    if errors.is_empty() {
        Ok(())
    } else {
        Err(HarnessError::Process(format_join_errors(
            "concurrent load client cleanup failed",
            errors,
        )))
    }
}

async fn wait_for_fanouts(cluster: &ProductionCluster) -> Result<()> {
    let (tenant_a, tenant_b) = tokio::join!(
        wait_for_fanout_drained(&cluster.device_fanout, "concurrent load tenant-A"),
        wait_for_fanout_drained(&cluster.tenant_b_fanout, "concurrent load tenant-B"),
    );
    let mut failure = None;
    if let Err(error) = tenant_a {
        append_failure(&mut failure, "tenant-A fanout", error);
    }
    if let Err(error) = tenant_b {
        append_failure(&mut failure, "tenant-B fanout", error);
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn append_failure(slot: &mut Option<HarnessError>, label: &str, error: HarnessError) {
    let error = match slot.take() {
        Some(primary) => HarnessError::Process(format!("{primary}; {label}: {error}")),
        None => HarnessError::Process(format!("{label}: {error}")),
    };
    *slot = Some(error);
}
