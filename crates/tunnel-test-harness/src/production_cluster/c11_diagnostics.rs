//! Bounded C11 multi-process diagnostic verification.
//!
//! This adapter invokes the existing M7 acceptance
//! commands as child processes; it does not duplicate Redis, peer, owner, or
//! writer fault setup.  Both child stdout and stderr are drained completely
//! into bounded memory before the child is considered joined.

#[path = "c11_window.rs"]
mod c11_window;
#[path = "og02_correlation.rs"]
mod og02_correlation;

use crate::{HarnessError, Result};
use c11_window::{
    C11EvidenceBundle, C11RunSpec, C11Window, FaultStage, RunOutcome, SafeField, Sentinel,
    SentinelKind,
};
pub use c11_window::{C11MatrixReport, PEER_FAULT_CAUSES, PEER_FAULT_STAGES};
pub use og02_correlation::{
    OG02_CORRELATION_FIELDS, Og02CorrelationReport, Og02RowReport, Og02Shortfall,
    og02_row_shortfall, verify_og02_correlation,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    process::{ExitStatus, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempfile::{TempDir, tempdir};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    task::JoinHandle,
    time::{Instant, timeout},
};

const CASE_TIMEOUT: Duration = Duration::from_secs(240);
// The child execution deadline remains CASE_TIMEOUT.  This larger parent
// window exists only to let a timed-out child be killed, reaped, and have
// both output readers to join; an outer timer never drops the case future.
const CASE_WALL_TIMEOUT: Duration = Duration::from_secs(250);
const MATRIX_TIMEOUT: Duration = Duration::from_secs(1_800);
const REAP_TIMEOUT: Duration = Duration::from_secs(3);
const OUTPUT_JOIN_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CAPTURE: usize = 1 << 20;
const MAX_CAPTURE_ENTRIES: usize = 256;

#[derive(Clone, Copy)]
struct MatrixCase {
    name: &'static str,
    command: &'static str,
    stage: FaultStage,
    outcome: RunOutcome,
    required_sentinels: &'static [SentinelKind],
    required_inner_process_counts: &'static [(&'static str, usize)],
    required_snapshot_roles: &'static [&'static str],
    required_safe_fields: &'static [SafeField],
    /// Exact `(role, stage, cause)` peer fault tuples the typed relay
    /// snapshots must carry.  Only tuples structurally implied by the induced
    /// fault are listed; timing-dependent tuples are reported, not required.
    required_peer_faults: &'static [(&'static str, &'static str, &'static str)],
}

const PRODUCTION_SENTINELS: &[SentinelKind] = &[
    SentinelKind::Credential,
    SentinelKind::ApplicationPayload,
    SentinelKind::FilesystemPath,
    SentinelKind::PrivateEndpoint,
];
const REDIS_TLS_SENTINELS: &[SentinelKind] =
    &[SentinelKind::Credential, SentinelKind::PrivateEndpoint];
const PRODUCTION_SNAPSHOT_ROLES: &[&str] = &[
    "snapshot-relay-relay-a",
    "snapshot-relay-relay-b",
    "snapshot-relay-relay-c",
    "snapshot-device_fanout",
    "snapshot-tenant_b_fanout",
];
// These are per-fixture minima, not a second global matrix.  The matcher uses
// complete diagnostic keys, so a field is listed only when the corresponding
// child output or typed relay snapshot really emits that key.  The matrix
// union check below still requires all nine families across the eight runs.
// Redis partition prints `relays`; the typed relay snapshot contributes the
// bounded application-dispatch counters.  Its public health flags are not a
// route/owner/close record, so those families remain matrix-level evidence.
const REDIS_PARTITION_SAFE_FIELDS: &[SafeField] = &[SafeField::Relay, SafeField::Counter];
const REDIS_TLS_SAFE_FIELDS: &[SafeField] = &[];
// Peer readiness prints the relay count and the selected-route counter is
// retained by the typed snapshot.  The human-readable `route_recovered` flag
// is intentionally not treated as a `route` key by the boundary matcher.
const PEER_READINESS_SAFE_FIELDS: &[SafeField] = &[SafeField::Relay, SafeField::Counter];
// Key rotation emits an explicit phase and candidate_generation; counters are
// provided by the typed relay snapshot.  `pin_revocation` is a compound
// summary label rather than the exact `revocation` key and is not promoted.
const KEY_ROTATION_SAFE_FIELDS: &[SafeField] = &[
    SafeField::Relay,
    SafeField::Phase,
    SafeField::EpochGenerationFence,
    SafeField::Counter,
];
// The production summary has exact `relays`, `tenants`, `ingress_relays`,
// `key_revocation`, and `owner_death` keys.  Counters come from the typed relay
// snapshots; generation/fencing and close are covered by the rotation and
// owner-loss cases where their exact keys are guaranteed.
const PRODUCTION_SAFE_FIELDS: &[SafeField] = &[
    SafeField::Relay,
    SafeField::Tenant,
    SafeField::Route,
    SafeField::RevocationOwnerDeath,
    SafeField::Counter,
];
// FP-05's typed Debug evidence has exact owner_relay, owner_loss, and
// post_terminal keys; relay counters come from its snapshots.
const OWNER_LOSS_SAFE_FIELDS: &[SafeField] = &[
    SafeField::Relay,
    SafeField::Owner,
    SafeField::RevocationOwnerDeath,
    SafeField::Counter,
    SafeField::CloseCause,
];
// Lifecycle and pressure both have relay summaries plus typed counters and
// terminal-event containers.  Their wrapper labels are not promoted as route
// or owner keys.
const WRITE_SAFE_FIELDS: &[SafeField] =
    &[SafeField::Relay, SafeField::Counter, SafeField::CloseCause];
// The OG-02 correlation bundle enforces its own family set per declared row;
// the shared scanner minimum is only what every production fixture emits.
const PRODUCTION_SAFE_FIELDS_MINIMUM: &[SafeField] = &[SafeField::Relay, SafeField::Counter];
// Key rotation withdraws the pooled peer pin mid-stream: the ingress and the
// owner both observe the stream reset while forwarding body records.
const KEY_ROTATION_PEER_FAULTS: &[(&str, &str, &str)] = &[
    ("ingress", "body", "transport_h3"),
    ("owner", "body", "transport_h3"),
];

const CASES: [MatrixCase; 8] = [
    MatrixCase {
        name: "redis-success",
        command: "verify-m7-redis-partition",
        stage: FaultStage::Redis,
        outcome: RunOutcome::Success,
        required_sentinels: PRODUCTION_SENTINELS,
        // `run_redis_partition` uses two library `tunnel_client::connect`
        // sessions (pre-partition and recovery); it does not call
        // `start_cli_smoke`/`ManagedProcess::spawn`.  The C11 child capture
        // therefore has no managed-process role for this case.
        required_inner_process_counts: &[],
        required_snapshot_roles: PRODUCTION_SNAPSHOT_ROLES,
        required_safe_fields: REDIS_PARTITION_SAFE_FIELDS,
        required_peer_faults: &[],
    },
    MatrixCase {
        name: "redis-fault",
        command: "verify-m7-redis-tls",
        stage: FaultStage::Redis,
        outcome: RunOutcome::Failure,
        required_sentinels: REDIS_TLS_SENTINELS,
        required_inner_process_counts: &[],
        required_snapshot_roles: &[],
        required_safe_fields: REDIS_TLS_SAFE_FIELDS,
        required_peer_faults: &[],
    },
    MatrixCase {
        name: "peer-success",
        command: "verify-m7-peer-readiness",
        stage: FaultStage::Peer,
        outcome: RunOutcome::Success,
        required_sentinels: PRODUCTION_SENTINELS,
        required_inner_process_counts: &[("m7-production-cli", 1)],
        required_snapshot_roles: PRODUCTION_SNAPSHOT_ROLES,
        required_safe_fields: PEER_READINESS_SAFE_FIELDS,
        required_peer_faults: &[],
    },
    MatrixCase {
        name: "peer-fault",
        command: "verify-m7-key-rotation",
        stage: FaultStage::Peer,
        outcome: RunOutcome::Failure,
        required_sentinels: PRODUCTION_SENTINELS,
        required_inner_process_counts: &[],
        required_snapshot_roles: PRODUCTION_SNAPSHOT_ROLES,
        required_safe_fields: KEY_ROTATION_SAFE_FIELDS,
        required_peer_faults: KEY_ROTATION_PEER_FAULTS,
    },
    MatrixCase {
        name: "owner-success",
        command: "verify-m7-production",
        stage: FaultStage::Owner,
        outcome: RunOutcome::Success,
        required_sentinels: PRODUCTION_SENTINELS,
        // The production gate composes the concurrent same-identifier tenant
        // race (four managed CLI roles) with its single production CLI.
        required_inner_process_counts: &[
            ("m7-production-cli", 1),
            ("m7-tenant-race-first", 1),
            ("m7-tenant-race-second", 1),
            ("m7-tenant-race-sibling", 1),
            ("m7-tenant-race-successor", 1),
        ],
        required_snapshot_roles: PRODUCTION_SNAPSHOT_ROLES,
        required_safe_fields: PRODUCTION_SAFE_FIELDS,
        required_peer_faults: &[],
    },
    MatrixCase {
        name: "owner-fault",
        command: "verify-m7-owner-loss-effect",
        stage: FaultStage::Owner,
        outcome: RunOutcome::Failure,
        required_sentinels: PRODUCTION_SENTINELS,
        required_inner_process_counts: &[],
        required_snapshot_roles: PRODUCTION_SNAPSHOT_ROLES,
        required_safe_fields: OWNER_LOSS_SAFE_FIELDS,
        required_peer_faults: &[],
    },
    MatrixCase {
        name: "write-success",
        command: "verify-m7-lifecycle",
        stage: FaultStage::Write,
        outcome: RunOutcome::Success,
        required_sentinels: PRODUCTION_SENTINELS,
        required_inner_process_counts: &[("m7-production-cli", 1)],
        required_snapshot_roles: PRODUCTION_SNAPSHOT_ROLES,
        required_safe_fields: WRITE_SAFE_FIELDS,
        required_peer_faults: &[],
    },
    MatrixCase {
        name: "write-fault",
        command: "verify-m7-pressure",
        stage: FaultStage::Write,
        outcome: RunOutcome::Failure,
        required_sentinels: PRODUCTION_SENTINELS,
        required_inner_process_counts: &[("m7-production-cli", 2)],
        required_snapshot_roles: PRODUCTION_SNAPSHOT_ROLES,
        required_safe_fields: WRITE_SAFE_FIELDS,
        required_peer_faults: &[],
    },
];

/// Run the eight-case C11 matrix against the existing acceptance commands.
///
/// `C11_SOURCE_ID`, `C11_BUILD_ID`, and optionally `C11_HARNESS_BINARY` are
/// required/consumed as safe identifiers. The raw child streams and exact
/// fixture values never leave this function.
pub async fn verify_c11_diagnostics() -> Result<C11MatrixReport> {
    let source_id = safe_environment_id("C11_SOURCE_ID")?;
    let build_id = safe_environment_id("C11_BUILD_ID")?;
    let binary = std::env::var_os("C11_HARNESS_BINARY")
        .map(PathBuf::from)
        .unwrap_or(std::env::current_exe().map_err(|_| {
            HarnessError::Process("C11 harness executable could not be resolved".into())
        })?);
    let matrix_started = now_millis()?;
    let mut bundle = C11EvidenceBundle::new(matrix_started);
    let matrix_deadline = Instant::now() + MATRIX_TIMEOUT;

    for case in CASES {
        let remaining = matrix_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HarnessError::Timeout(
                "C11 diagnostics matrix exceeded its bounded deadline".into(),
            ));
        }
        if remaining < CASE_WALL_TIMEOUT {
            return Err(HarnessError::Timeout(
                "C11 diagnostics matrix left insufficient cleanup time for the next case".into(),
            ));
        }
        // `run_case` owns every child and reader handle. Its internal waits
        // and cleanup joins are bounded, so do not wrap it in another
        // cancellable timeout that could detach those handles. The upfront
        // reservation leaves room for the child reap and both joins.
        let report = run_case(case, &binary, &source_id, &build_id).await?;
        // The child and all of its cleanup handles are already joined here,
        // so checking the absolute matrix deadline now cannot detach work.
        // The preflight reservation bounds each case's reap and output joins;
        // this postcondition turns any unexpected cleanup/scan overrun into a
        // failed matrix instead of allowing an out-of-window receipt through.
        if Instant::now() > matrix_deadline {
            return Err(HarnessError::Timeout(
                "C11 diagnostics matrix exceeded its bounded deadline after case cleanup".into(),
            ));
        }
        bundle
            .add(report)
            .map_err(|error| HarnessError::Process(format!("C11 diagnostics: {error}")))?;
    }

    let matrix_ended = now_millis()?;
    bundle
        .finish(matrix_ended)
        .map_err(|error| HarnessError::Process(format!("C11 diagnostics: {error}")))
}

async fn run_case(
    case: MatrixCase,
    binary: &std::path::Path,
    source_id: &str,
    build_id: &str,
) -> Result<c11_window::C11ScanReport> {
    let started = now_millis()?;
    let run_id = format!("c11-{}-{started}", case.name);
    let capture_dir = tempdir().map_err(|_| {
        HarnessError::Process(format!("C11 {} capture directory failed", case.name))
    })?;
    crate::c11_capture::harden_capture_directory(capture_dir.path())?;
    let captured = run_harness_child(binary, case.command, &capture_dir).await?;
    if !captured.status.success() {
        let preserved = preserve_child_failure(case.name, &captured);
        return Err(HarnessError::Process(format!(
            "C11 {} acceptance child exited unsuccessfully: {}{}",
            case.name,
            child_failure_summary(&captured),
            preserved.map_or_else(String::new, |path| format!(
                ",preserved={}",
                path.to_string_lossy()
            ))
        )));
    }
    let sentinels = captured.sentinels;
    let present_sentinels = sentinels
        .iter()
        .map(Sentinel::kind)
        .collect::<BTreeSet<_>>();
    for kind in case.required_sentinels {
        if !present_sentinels.contains(kind) {
            return Err(HarnessError::Process(format!(
                "C11 {} fixture did not record its {} sentinel",
                case.name,
                sentinel_kind_label(*kind)
            )));
        }
    }
    for (required_name, required_count) in case.required_inner_process_counts {
        let observed_count = captured
            .inner
            .iter()
            .filter(|process| process.name == *required_name)
            .count();
        if observed_count != *required_count {
            return Err(HarnessError::Process(format!(
                "C11 {} fixture joined {} {} process roles, expected {}",
                case.name, observed_count, required_name, required_count
            )));
        }
    }
    let expected_inner_count = case
        .required_inner_process_counts
        .iter()
        .map(|(_, count)| *count)
        .sum::<usize>();
    if captured.inner.len() != expected_inner_count {
        return Err(HarnessError::Process(format!(
            "C11 {} fixture joined {} managed process roles, expected {}",
            case.name,
            captured.inner.len(),
            expected_inner_count
        )));
    }
    if captured.inner.iter().any(|process| {
        !case
            .required_inner_process_counts
            .iter()
            .any(|(required_name, _)| process.name == *required_name)
    }) {
        return Err(HarnessError::Process(format!(
            "C11 {} fixture joined an undeclared managed process role",
            case.name
        )));
    }
    for required_role in case.required_snapshot_roles {
        if !captured
            .snapshots
            .iter()
            .any(|snapshot| snapshot.role == *required_role)
        {
            return Err(HarnessError::Process(format!(
                "C11 {} fixture did not capture required snapshot role",
                case.name
            )));
        }
    }
    let mut expected_roles = vec!["harness_stdout".to_owned(), "harness_stderr".to_owned()];
    for (index, _) in captured.inner.iter().enumerate() {
        expected_roles.push(format!("managed_process_{index}_stdout"));
        expected_roles.push(format!("managed_process_{index}_stderr"));
    }
    expected_roles.extend(
        captured
            .snapshots
            .iter()
            .map(|snapshot| snapshot.role.clone()),
    );
    let mut safe_field_roles = vec!["harness_stdout".to_owned(), "harness_stderr".to_owned()];
    for (index, _) in captured.inner.iter().enumerate() {
        safe_field_roles.push(format!("managed_process_{index}_stdout"));
        safe_field_roles.push(format!("managed_process_{index}_stderr"));
    }
    // RelaySnapshot is a typed runtime-owned, payload-free observation.  The
    // peer/proxy/fanout records are adapter-generated counter wrappers: retain
    // them for evidence and joining, but never let their labels manufacture a
    // safe-field observation.
    safe_field_roles.extend(
        captured
            .snapshots
            .iter()
            .filter(|snapshot| snapshot.role.starts_with("snapshot-relay-"))
            .map(|snapshot| snapshot.role.clone()),
    );
    let spec = C11RunSpec::new(
        run_id,
        source_id,
        build_id,
        case.stage,
        case.outcome,
        started,
        expected_roles.clone(),
        sentinels,
    )
    .map_err(|error| HarnessError::Process(format!("C11 {} diagnostics: {error}", case.name)))?
    .with_safe_field_roles(safe_field_roles)
    .map_err(|error| HarnessError::Process(format!("C11 {} diagnostics: {error}", case.name)))?
    // Each case declares the minimum safe families its real fixture can
    // produce. The matrix-level union check in `C11EvidenceBundle::finish`
    // remains in place, while transport-only Redis TLS is not forced to
    // invent relay-owned fields it never captures.
    .with_required_fields(case.required_safe_fields.iter().copied())
    .with_required_peer_faults(case.required_peer_faults)
    .map_err(|error| HarnessError::Process(format!("C11 {} diagnostics: {error}", case.name)))?
    .with_stream_limit(MAX_CAPTURE)
    .map_err(|error| HarnessError::Process(format!("C11 {} diagnostics: {error}", case.name)))?;
    let mut window = C11Window::new(spec);
    if captured.stdout.overflow || captured.stderr.overflow {
        return Err(HarnessError::Process(format!(
            "C11 {} diagnostics capture exceeded its bounded buffer",
            case.name
        )));
    }
    if captured.stdout.read_error || captured.stderr.read_error {
        return Err(HarnessError::Process(format!(
            "C11 {} diagnostics capture read failed",
            case.name
        )));
    }
    window
        .append("harness_stdout", &captured.stdout.bytes)
        .map_err(|error| {
            HarnessError::Process(format!("C11 {} diagnostics: {error}", case.name))
        })?;
    window
        .append("harness_stderr", &captured.stderr.bytes)
        .map_err(|error| {
            HarnessError::Process(format!("C11 {} diagnostics: {error}", case.name))
        })?;
    for (index, process) in captured.inner.iter().enumerate() {
        window
            .append(&format!("managed_process_{index}_stdout"), &process.stdout)
            .and_then(|()| {
                window.append(&format!("managed_process_{index}_stderr"), &process.stderr)
            })
            .map_err(|error| {
                HarnessError::Process(format!("C11 {} diagnostics: {error}", case.name))
            })?;
    }
    for snapshot in &captured.snapshots {
        window
            .append(&snapshot.role, &snapshot.bytes)
            .map_err(|error| {
                HarnessError::Process(format!("C11 {} diagnostics: {error}", case.name))
            })?;
    }
    for role in expected_roles {
        window
            .close(&role)
            .and_then(|()| window.mark_joined(&role))
            .map_err(|error| {
                HarnessError::Process(format!("C11 {} diagnostics: {error}", case.name))
            })?;
    }
    let report = window.finish(now_millis()?).map_err(|error| {
        HarnessError::Process(format!("C11 {} diagnostics: {error}", case.name))
    })?;
    Ok(report)
}

fn sentinel_kind_label(kind: SentinelKind) -> &'static str {
    match kind {
        SentinelKind::Credential => "credential",
        SentinelKind::ApplicationPayload => "application_payload",
        SentinelKind::FilesystemPath => "filesystem_path",
        SentinelKind::PrivateEndpoint => "private_endpoint",
    }
}

/// Summarize a failed acceptance child using only fixed diagnostic categories
/// and lengths.  The child output itself can contain fixture credentials,
/// payloads, paths, or endpoints, so no line or tail is ever copied into this
/// error.  The private capture directory remains available to the caller until
/// this case returns and is scanned by the normal success path.
/// Preserve a failing child's own stderr for diagnosis, when the operator asks.
///
/// The bundle's error deliberately carries counts and markers rather than child
/// bytes, and the capture directory is a `TempDir` that is removed when the case
/// ends, so an intermittent child failure leaves nothing to diagnose from. When
/// `C11_CHILD_FAILURE_DIR` names a directory, the bytes are written there and
/// the error names the path. The error still carries no child content: a path is
/// not payload, and the operator opts in by setting the variable.
fn preserve_child_failure(case: &str, child: &ChildOutput) -> Option<PathBuf> {
    let directory = std::env::var_os("C11_CHILD_FAILURE_DIR").map(PathBuf::from)?;
    std::fs::create_dir_all(&directory).ok()?;
    let started = now_millis().unwrap_or_default();
    let path = directory.join(format!("c11-child-{case}-{started}.stderr"));
    std::fs::write(&path, &child.stderr.bytes).ok()?;
    let stdout_path = directory.join(format!("c11-child-{case}-{started}.stdout"));
    std::fs::write(&stdout_path, &child.stdout.bytes).ok()?;
    Some(path)
}

fn child_failure_summary(child: &ChildOutput) -> String {
    let mut markers = BTreeSet::new();
    for bytes in [&child.stdout.bytes[..], &child.stderr.bytes[..]] {
        for (needle, label) in CHILD_ERROR_MARKERS {
            if contains_ascii_case_insensitive(bytes, needle) {
                markers.insert(*label);
            }
        }
    }
    let marker_text = if markers.is_empty() {
        "none".to_owned()
    } else {
        markers.into_iter().collect::<Vec<_>>().join("|")
    };
    format!(
        "status_code={:?},signal={:?},stdout_bytes={},stderr_bytes={},markers={marker_text}",
        child.status.code(),
        child_status_signal(&child.status),
        child.stdout.bytes.len(),
        child.stderr.bytes.len(),
    )
}

const CHILD_ERROR_MARKERS: &[(&[u8], &str)] = &[
    (b"tunnel-test-harness:", "harness_error"),
    (b"HTTP/TLS probe error:", "http"),
    (b"Redis harness error:", "redis"),
    (b"managed process error:", "managed_process"),
    (b"harness timeout:", "timeout"),
    (b"invalid harness input:", "invalid_input"),
    (b"owner-loss", "owner_loss"),
    (b"owner loss", "owner_loss"),
    (b"snapshot", "snapshot"),
    (b"cleanup", "cleanup"),
    (b"authorization", "authorization"),
    (b"recovery", "recovery"),
    (b"transport", "transport"),
    (b"sentinel", "sentinel"),
    (b"route", "route"),
    (b"stream", "stream"),
    (b"expected", "assertion"),
];

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.windows(needle.len()).any(|window| {
            window
                .iter()
                .zip(needle)
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
        })
}

#[cfg(unix)]
fn child_status_signal(status: &ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;

    status.signal()
}

#[cfg(not(unix))]
fn child_status_signal(_status: &ExitStatus) -> Option<i32> {
    None
}

struct ChildOutput {
    status: ExitStatus,
    stdout: CapturedStream,
    stderr: CapturedStream,
    inner: Vec<InnerProcessCapture>,
    snapshots: Vec<SnapshotCapture>,
    sentinels: Vec<Sentinel>,
}

struct CapturedStream {
    bytes: Vec<u8>,
    overflow: bool,
    read_error: bool,
}

struct InnerProcessCapture {
    name: String,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

struct SnapshotCapture {
    role: String,
    bytes: Vec<u8>,
}

async fn run_harness_child(
    binary: &std::path::Path,
    command: &str,
    capture_dir: &TempDir,
) -> Result<ChildOutput> {
    let mut child = Command::new(binary);
    child
        .arg(command)
        .env(
            "C11_INNER_CAPTURE_DIR",
            capture_dir.path().to_string_lossy().to_string(),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = child
        .spawn()
        .map_err(|_| HarnessError::Process("C11 acceptance child could not start".into()))?;
    let stdout_reader = child.stdout.take().ok_or_else(|| {
        HarnessError::Process("C11 acceptance child stdout pipe was unavailable".into())
    })?;
    let stderr_reader = child.stderr.take().ok_or_else(|| {
        HarnessError::Process("C11 acceptance child stderr pipe was unavailable".into())
    })?;
    let stdout_task = spawn_capture(Some(stdout_reader));
    let stderr_task = spawn_capture(Some(stderr_reader));
    let status = match timeout(CASE_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(_)) => {
            cleanup_child(&mut child, stdout_task, stderr_task).await?;
            return Err(HarnessError::Process(
                "C11 acceptance child wait failed".into(),
            ));
        }
        Err(_) => {
            cleanup_child(&mut child, stdout_task, stderr_task).await?;
            return Err(HarnessError::Timeout(
                "C11 acceptance child exceeded its bounded deadline".into(),
            ));
        }
    };
    let stdout = join_capture(stdout_task, "stdout").await;
    let stderr = join_capture(stderr_task, "stderr").await;
    let (stdout, stderr) = match (stdout, stderr) {
        (Ok(stdout), Ok(stderr)) => (stdout, stderr),
        (Err(_), _) | (_, Err(_)) => {
            return Err(HarnessError::Process(
                "C11 acceptance child output cleanup did not complete".into(),
            ));
        }
    };
    let (inner, snapshots, sentinels) = read_capture_directory(capture_dir.path())?;
    Ok(ChildOutput {
        status,
        stdout,
        stderr,
        inner,
        snapshots,
        sentinels,
    })
}

async fn cleanup_child(
    child: &mut tokio::process::Child,
    stdout_task: Option<JoinHandle<CapturedStream>>,
    stderr_task: Option<JoinHandle<CapturedStream>>,
) -> Result<()> {
    // A kill failure is harmless if the process exited between the child
    // deadline and this cleanup path. The reaping result is authoritative;
    // dropping a child or either reader without observing it is not.
    let _ = child.start_kill();
    let reaped = matches!(timeout(REAP_TIMEOUT, child.wait()).await, Ok(Ok(_)));
    let stdout = join_capture(stdout_task, "stdout").await;
    let stderr = join_capture(stderr_task, "stderr").await;
    if reaped && stdout.is_ok() && stderr.is_ok() {
        Ok(())
    } else {
        Err(HarnessError::Process(
            "C11 acceptance child cleanup did not complete".into(),
        ))
    }
}

fn read_capture_directory(
    directory: &std::path::Path,
) -> Result<(
    Vec<InnerProcessCapture>,
    Vec<SnapshotCapture>,
    Vec<Sentinel>,
)> {
    let mut process_files = BTreeMap::<String, (Option<Vec<u8>>, Option<Vec<u8>>)>::new();
    let mut snapshots = Vec::new();
    let mut sentinels = Vec::new();
    let mut entry_count = 0_usize;
    let entries = fs::read_dir(directory)
        .map_err(|_| HarnessError::Process("C11 capture directory could not be read".into()))?;
    for entry in entries {
        entry_count = entry_count.saturating_add(1);
        if entry_count > MAX_CAPTURE_ENTRIES {
            return Err(HarnessError::Process(
                "C11 capture directory contained too many files".into(),
            ));
        }
        let entry = entry.map_err(|_| {
            HarnessError::Process("C11 capture directory entry could not be read".into())
        })?;
        let file_type = entry.file_type().map_err(|_| {
            HarnessError::Process("C11 capture entry type could not be read".into())
        })?;
        if !file_type.is_file() {
            return Err(HarnessError::Process(
                "C11 capture directory contained a non-file entry".into(),
            ));
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "sentinels.bin" {
            sentinels = read_sentinel_manifest(&entry.path())?;
        } else if let Some(prefix) = name.strip_suffix(".stdout") {
            let bytes = bounded_file(&entry.path(), MAX_CAPTURE)?;
            process_files.entry(prefix.to_owned()).or_default().0 = Some(bytes);
        } else if let Some(prefix) = name.strip_suffix(".stderr") {
            let bytes = bounded_file(&entry.path(), MAX_CAPTURE)?;
            process_files.entry(prefix.to_owned()).or_default().1 = Some(bytes);
        } else if let Some(role) = name.strip_prefix("snapshot-")
            && let Some(role) = role.strip_suffix(".bin")
        {
            snapshots.push(SnapshotCapture {
                role: format!("snapshot-{role}"),
                bytes: read_snapshot_frames(&entry.path())?,
            });
        } else {
            return Err(HarnessError::Process(
                "C11 capture directory contained an unknown file".into(),
            ));
        }
    }
    snapshots.sort_by(|left, right| left.role.cmp(&right.role));
    let inner = process_files
        .into_iter()
        .map(|(prefix, (stdout, stderr))| {
            let Some(stdout) = stdout else {
                return Err(HarnessError::Process(
                    "C11 managed-process stdout capture was incomplete".into(),
                ));
            };
            let Some(stderr) = stderr else {
                return Err(HarnessError::Process(
                    "C11 managed-process stderr capture was incomplete".into(),
                ));
            };
            Ok(InnerProcessCapture {
                name: managed_process_name(&prefix)?,
                stdout,
                stderr,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((inner, snapshots, sentinels))
}

fn managed_process_name(prefix: &str) -> Result<String> {
    let mut parts = prefix.splitn(4, '-');
    if parts.next() != Some("managed")
        || parts
            .next()
            .is_none_or(|pid| pid.is_empty() || !pid.bytes().all(|byte| byte.is_ascii_digit()))
        || parts.next().is_none_or(|sequence| {
            sequence.is_empty() || !sequence.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err(HarnessError::Process(
            "C11 managed-process capture role was malformed".into(),
        ));
    }
    let Some(name) = parts.next() else {
        return Err(HarnessError::Process(
            "C11 managed-process capture role was missing".into(),
        ));
    };
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(HarnessError::Process(
            "C11 managed-process capture role was invalid".into(),
        ));
    }
    Ok(name.to_owned())
}

fn read_sentinel_manifest(path: &std::path::Path) -> Result<Vec<Sentinel>> {
    let bytes = bounded_file(path, 4 * MAX_CAPTURE)?;
    let mut offset = 0_usize;
    let mut values = Vec::new();
    while offset < bytes.len() {
        let Some(&kind_code) = bytes.get(offset) else {
            return Err(HarnessError::Process(
                "C11 sentinel manifest was truncated".into(),
            ));
        };
        offset = offset.saturating_add(1);
        let end = offset.saturating_add(4);
        if end > bytes.len() {
            return Err(HarnessError::Process(
                "C11 sentinel manifest was truncated".into(),
            ));
        }
        let length = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset = end;
        let end = offset.checked_add(length).ok_or_else(|| {
            HarnessError::Process("C11 sentinel manifest length overflowed".into())
        })?;
        if end > bytes.len() || length == 0 || length > 256 * 1024 {
            return Err(HarnessError::Process(
                "C11 sentinel manifest record exceeded its bound".into(),
            ));
        }
        // The high bit marks a tombstone: the value's socket has closed, so the
        // operating system may hand that port to anything else in this run and
        // an exact-bytes match would no longer prove a disclosure. Records are
        // applied in order, so a value can be recorded, retired, and recorded
        // again for a later socket.
        let retired = kind_code & crate::c11_capture::RETIRED_SENTINEL_FLAG != 0;
        let kind = match kind_code & !crate::c11_capture::RETIRED_SENTINEL_FLAG {
            1 => SentinelKind::Credential,
            2 => SentinelKind::ApplicationPayload,
            3 => SentinelKind::FilesystemPath,
            4 => SentinelKind::PrivateEndpoint,
            _ => {
                return Err(HarnessError::Process(
                    "C11 sentinel manifest contained an unknown category".into(),
                ));
            }
        };
        let value = bytes[offset..end].to_vec();
        if retired {
            values.retain(|sentinel: &Sentinel| {
                sentinel.kind() != kind || !sentinel.has_value(&value)
            });
        } else {
            values.push(
                Sentinel::new(kind, value).map_err(|_| {
                    HarnessError::Process("C11 sentinel manifest was invalid".into())
                })?,
            );
        }
        offset = end;
    }
    Ok(values)
}

fn read_snapshot_frames(path: &std::path::Path) -> Result<Vec<u8>> {
    let bytes = bounded_file(path, MAX_CAPTURE)?;
    let mut offset = 0_usize;
    let mut output = Vec::new();
    while offset < bytes.len() {
        let end = offset.saturating_add(4);
        if end > bytes.len() {
            return Err(HarnessError::Process(
                "C11 snapshot frame was truncated".into(),
            ));
        }
        let length = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset = end;
        let frame_end = offset
            .checked_add(length)
            .ok_or_else(|| HarnessError::Process("C11 snapshot frame length overflowed".into()))?;
        if frame_end > bytes.len() {
            return Err(HarnessError::Process(
                "C11 snapshot frame was truncated".into(),
            ));
        }
        if output.len().saturating_add(length) > MAX_CAPTURE {
            return Err(HarnessError::Process(
                "C11 snapshot capture exceeded its bounded buffer".into(),
            ));
        }
        output.extend_from_slice(&bytes[offset..frame_end]);
        offset = frame_end;
    }
    Ok(output)
}

fn bounded_file(path: &std::path::Path, limit: usize) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| HarnessError::Process("C11 capture file metadata could not be read".into()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(HarnessError::Process(
            "C11 capture file was not a regular file".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(HarnessError::Process(
                "C11 capture file permissions were not private".into(),
            ));
        }
    }
    if metadata.len() > u64::try_from(limit).unwrap_or(u64::MAX) {
        return Err(HarnessError::Process(
            "C11 capture file exceeded its bounded buffer".into(),
        ));
    }
    fs::read(path).map_err(|_| HarnessError::Process("C11 capture file could not be read".into()))
}

fn spawn_capture<R>(reader: Option<R>) -> Option<JoinHandle<CapturedStream>>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    reader.map(|mut reader| {
        tokio::spawn(async move {
            let mut bytes = Vec::new();
            let mut overflow = false;
            let mut read_error = false;
            let mut buffer = [0_u8; 16 * 1024];
            loop {
                match reader.read(&mut buffer).await {
                    Ok(0) => break,
                    Err(_) => {
                        read_error = true;
                        break;
                    }
                    Ok(read) => {
                        let remaining = MAX_CAPTURE.saturating_sub(bytes.len());
                        let accepted = read.min(remaining);
                        bytes.extend_from_slice(&buffer[..accepted]);
                        if accepted != read {
                            overflow = true;
                        }
                    }
                }
            }
            CapturedStream {
                bytes,
                overflow,
                read_error,
            }
        })
    })
}

async fn join_capture(
    task: Option<JoinHandle<CapturedStream>>,
    role: &'static str,
) -> Result<CapturedStream> {
    let Some(task) = task else {
        return Err(HarnessError::Process(format!(
            "C11 {role} capture pipe was unavailable"
        )));
    };
    let mut task = task;
    match timeout(OUTPUT_JOIN_TIMEOUT, &mut task).await {
        Ok(result) => {
            result.map_err(|_| HarnessError::Process(format!("C11 {role} capture join failed")))
        }
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(HarnessError::Process(format!(
                "C11 {role} capture join exceeded bound"
            )))
        }
    }
}

fn safe_environment_id(name: &'static str) -> Result<String> {
    let value = std::env::var(name)
        .map_err(|_| HarnessError::InvalidInput(format!("C11 diagnostics requires {name}")))?;
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(HarnessError::InvalidInput(format!(
            "C11 diagnostics {name} must be a bounded identifier"
        )));
    }
    Ok(value)
}

fn now_millis() -> Result<i64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HarnessError::Process("C11 diagnostics clock moved backwards".into()))?;
    i64::try_from(elapsed.as_millis())
        .map_err(|_| HarnessError::Process("C11 diagnostics timestamp overflow".into()))
}

#[cfg(test)]
mod sentinel_manifest_tests {
    use super::{SentinelKind, read_sentinel_manifest};
    use crate::c11_capture::RETIRED_SENTINEL_FLAG;

    fn record(kind_code: u8, value: &[u8]) -> Vec<u8> {
        let mut bytes = vec![kind_code];
        bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
        bytes.extend_from_slice(value);
        bytes
    }

    fn manifest(records: &[(u8, &[u8])]) -> Vec<u8> {
        records
            .iter()
            .flat_map(|(kind, value)| record(*kind, value))
            .collect()
    }

    #[test]
    fn a_retired_endpoint_is_dropped_and_can_be_recorded_again() {
        let path = tempfile::Builder::new()
            .prefix("c11-sentinels")
            .tempfile()
            .expect("sentinel manifest fixture");
        // Record a listener, retire it when its socket closes, then record a
        // different one: only the live value may still be scanned for.
        std::fs::write(
            path.path(),
            manifest(&[
                (4, b"127.0.0.1:51190"),
                (4 | RETIRED_SENTINEL_FLAG, b"127.0.0.1:51190"),
                (4, b"127.0.0.1:51191"),
            ]),
        )
        .expect("write sentinel manifest");
        let sentinels = read_sentinel_manifest(path.path()).expect("read sentinel manifest");
        assert_eq!(sentinels.len(), 1);
        assert_eq!(sentinels[0].kind(), SentinelKind::PrivateEndpoint);
        assert!(sentinels[0].has_value(b"127.0.0.1:51191"));

        // The same port recorded again after retirement is live once more.
        std::fs::write(
            path.path(),
            manifest(&[
                (4, b"127.0.0.1:51190"),
                (4 | RETIRED_SENTINEL_FLAG, b"127.0.0.1:51190"),
                (4, b"127.0.0.1:51190"),
            ]),
        )
        .expect("rewrite sentinel manifest");
        let sentinels = read_sentinel_manifest(path.path()).expect("reread sentinel manifest");
        assert_eq!(sentinels.len(), 1);
        assert!(sentinels[0].has_value(b"127.0.0.1:51190"));

        // Retirement is category-exact: a credential with the same bytes is
        // untouched by an endpoint tombstone.
        std::fs::write(
            path.path(),
            manifest(&[
                (1, b"shared-bytes"),
                (4, b"shared-bytes"),
                (4 | RETIRED_SENTINEL_FLAG, b"shared-bytes"),
            ]),
        )
        .expect("rewrite sentinel manifest again");
        let sentinels =
            read_sentinel_manifest(path.path()).expect("reread sentinel manifest again");
        assert_eq!(sentinels.len(), 1);
        assert_eq!(sentinels[0].kind(), SentinelKind::Credential);
    }
}
