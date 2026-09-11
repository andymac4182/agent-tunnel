//! OG-02 correlated fault evidence bundle.
//!
//! The eight-case C11 matrix proves the safe-field families across one
//! success and one fault run per stage.  This bundle drives the fault gates
//! the M7 sweep now runs, one child process each, through the same bounded
//! capture and redaction scanner, and reports for every row whether the
//! joined window carries the correlation OG-02 requires: relay, tenant and
//! owner identifiers, a phase, an epoch/generation/fence, queue and lease
//! counters, a close cause, and the relay's bounded peer stage/cause tuples.
//! A row declared complete fails the bundle when any family is missing; a
//! row not yet declared complete is reported with its missing families so the
//! gap stays visible rather than implied.  The four sensitive-value classes
//! are scanned on every row regardless of its declaration.

use super::c11_window::{FaultStage, RunOutcome, SafeField};
use super::{
    MatrixCase, PRODUCTION_SAFE_FIELDS_MINIMUM, PRODUCTION_SENTINELS, PRODUCTION_SNAPSHOT_ROLES,
    now_millis, run_case, safe_environment_id,
};
use crate::{HarnessError, Result};
use std::{path::PathBuf, time::Duration};
use tokio::time::Instant;

const BUNDLE_TIMEOUT: Duration = Duration::from_secs(1_500);
const ROW_WALL_TIMEOUT: Duration = Duration::from_secs(250);

/// The safe-field families OG-02 names for a correlated fault row.
pub const OG02_CORRELATION_FIELDS: [SafeField; 7] = [
    SafeField::Relay,
    SafeField::Tenant,
    SafeField::Owner,
    SafeField::Phase,
    SafeField::EpochGenerationFence,
    SafeField::Counter,
    SafeField::CloseCause,
];

#[derive(Clone, Copy)]
struct Og02Row {
    case: MatrixCase,
    /// Whether the row is declared to carry complete OG-02 correlation.  A
    /// declared row is enforced; an undeclared row is reported.
    expected_complete: bool,
}

// Exact tuples listed here were observed on real runs of each gate and are
// structurally implied by the fault the gate induces.  Timing-dependent
// tuples (pre-attachment `no_live_owner`, mixed h3/timeout body causes under
// saturation) are reported rather than required.
const ROWS: [Og02Row; 7] = [
    Og02Row {
        case: MatrixCase {
            name: "credential-expiry",
            command: "verify-m7-credential-expiry-rotation",
            stage: FaultStage::Owner,
            outcome: RunOutcome::Failure,
            required_sentinels: PRODUCTION_SENTINELS,
            required_inner_process_counts: &[("m7-production-cli", 2)],
            required_snapshot_roles: PRODUCTION_SNAPSHOT_ROLES,
            required_safe_fields: PRODUCTION_SAFE_FIELDS_MINIMUM,
            required_peer_faults: &[],
        },
        expected_complete: true,
    },
    Og02Row {
        case: MatrixCase {
            name: "trust-expiry",
            command: "verify-m7-trust-expiry",
            stage: FaultStage::Peer,
            outcome: RunOutcome::Failure,
            required_sentinels: PRODUCTION_SENTINELS,
            required_inner_process_counts: &[],
            required_snapshot_roles: PRODUCTION_SNAPSHOT_ROLES,
            required_safe_fields: PRODUCTION_SAFE_FIELDS_MINIMUM,
            required_peer_faults: &[("ingress", "body", "membership_expired")],
        },
        expected_complete: true,
    },
    Og02Row {
        case: MatrixCase {
            name: "goaway",
            command: "verify-m7-i08-goaway-rotation",
            stage: FaultStage::Peer,
            outcome: RunOutcome::Failure,
            required_sentinels: PRODUCTION_SENTINELS,
            required_inner_process_counts: &[("m7-production-cli", 1)],
            required_snapshot_roles: PRODUCTION_SNAPSHOT_ROLES,
            required_safe_fields: PRODUCTION_SAFE_FIELDS_MINIMUM,
            // A planned GOAWAY lands on the ingress relay either while it checks
            // out a stream permit or while it dispatches the HTTP/3 request;
            // both stages are legitimate and the cause is exact.
            required_peer_faults: &[(
                "ingress",
                "stream_permit_checkout|h3_dispatch",
                "transport_goaway",
            )],
        },
        expected_complete: true,
    },
    Og02Row {
        case: MatrixCase {
            name: "recovery-attempts",
            command: "verify-m7-i08-recovery-attempts",
            stage: FaultStage::Owner,
            outcome: RunOutcome::Failure,
            required_sentinels: PRODUCTION_SENTINELS,
            required_inner_process_counts: &[("m7-production-cli", 2)],
            required_snapshot_roles: PRODUCTION_SNAPSHOT_ROLES,
            required_safe_fields: PRODUCTION_SAFE_FIELDS_MINIMUM,
            required_peer_faults: &[],
        },
        expected_complete: true,
    },
    Og02Row {
        case: MatrixCase {
            name: "lease-expiry",
            command: "verify-m7-owner-lease-expiry",
            stage: FaultStage::Owner,
            outcome: RunOutcome::Failure,
            required_sentinels: PRODUCTION_SENTINELS,
            required_inner_process_counts: &[("m7-production-cli", 2)],
            required_snapshot_roles: PRODUCTION_SNAPSHOT_ROLES,
            required_safe_fields: PRODUCTION_SAFE_FIELDS_MINIMUM,
            required_peer_faults: &[],
        },
        expected_complete: true,
    },
    Og02Row {
        case: MatrixCase {
            name: "queue-saturation",
            command: "verify-m7-queue-saturation",
            stage: FaultStage::Write,
            outcome: RunOutcome::Failure,
            required_sentinels: PRODUCTION_SENTINELS,
            required_inner_process_counts: &[],
            required_snapshot_roles: PRODUCTION_SNAPSHOT_ROLES,
            required_safe_fields: PRODUCTION_SAFE_FIELDS_MINIMUM,
            required_peer_faults: &[],
        },
        expected_complete: true,
    },
    Og02Row {
        case: MatrixCase {
            name: "remote-body-limits",
            command: "verify-m7-remote-body-limits",
            stage: FaultStage::Write,
            outcome: RunOutcome::Failure,
            required_sentinels: PRODUCTION_SENTINELS,
            required_inner_process_counts: &[],
            required_snapshot_roles: PRODUCTION_SNAPSHOT_ROLES,
            required_safe_fields: PRODUCTION_SAFE_FIELDS_MINIMUM,
            required_peer_faults: &[],
        },
        expected_complete: true,
    },
];

/// Correlation evidence for one fault row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Og02RowReport {
    pub name: &'static str,
    pub command: &'static str,
    pub complete: bool,
    /// OG-02 families absent from every safe-field role of the joined window.
    pub missing_fields: Vec<&'static str>,
    /// Exact `role/stage/cause` tuples found in the typed relay snapshots.
    pub peer_fault_tuples: Vec<String>,
    pub captured_streams: usize,
    pub captured_bytes: usize,
    pub started_utc_ms: i64,
    pub ended_utc_ms: i64,
}

/// The bundle summary printed by `verify-m7-og02-correlation`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Og02CorrelationReport {
    pub source_id: String,
    pub build_id: String,
    pub window_started_utc_ms: i64,
    pub window_ended_utc_ms: i64,
    pub rows: Vec<Og02RowReport>,
}

impl Og02CorrelationReport {
    #[must_use]
    pub fn complete_rows(&self) -> usize {
        self.rows.iter().filter(|row| row.complete).count()
    }

    #[must_use]
    pub fn incomplete_rows(&self) -> usize {
        self.rows.len() - self.complete_rows()
    }
}

/// Run every fault row through the bounded capture and scanner.
pub async fn verify_og02_correlation() -> Result<Og02CorrelationReport> {
    let source_id = safe_environment_id("C11_SOURCE_ID")?;
    let build_id = safe_environment_id("C11_BUILD_ID")?;
    let binary = std::env::var_os("C11_HARNESS_BINARY")
        .map(PathBuf::from)
        .unwrap_or(std::env::current_exe().map_err(|_| {
            HarnessError::Process("OG-02 harness executable could not be resolved".into())
        })?);
    let window_started_utc_ms = now_millis()?;
    let deadline = Instant::now() + BUNDLE_TIMEOUT;
    let mut rows = Vec::with_capacity(ROWS.len());
    for row in ROWS {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining < ROW_WALL_TIMEOUT {
            return Err(HarnessError::Timeout(
                "OG-02 correlation bundle left insufficient time for the next row".into(),
            ));
        }
        let report = run_case(row.case, &binary, &source_id, &build_id).await?;
        if report.started_utc_ms < window_started_utc_ms {
            return Err(HarnessError::Process(format!(
                "OG-02 {} row started before the bundle window",
                row.case.name
            )));
        }
        let missing_fields = OG02_CORRELATION_FIELDS
            .iter()
            .filter(|field| !report.fields_present.contains(field))
            .map(|field| field.label())
            .collect::<Vec<_>>();
        let complete = missing_fields.is_empty() && !report.peer_faults_present.is_empty();
        if row.expected_complete && !complete {
            let missing = if missing_fields.is_empty() {
                "peer_fault_tuple".to_owned()
            } else {
                missing_fields.join(",")
            };
            return Err(HarnessError::Process(format!(
                "OG-02 {} row was declared complete but lacks correlation: {missing}",
                row.case.name
            )));
        }
        rows.push(Og02RowReport {
            name: row.case.name,
            command: row.case.command,
            complete,
            missing_fields,
            peer_fault_tuples: report
                .peer_faults_present
                .iter()
                .map(ToString::to_string)
                .collect(),
            captured_streams: report.bytes_by_role.len(),
            captured_bytes: report.bytes_by_role.values().sum(),
            started_utc_ms: report.started_utc_ms,
            ended_utc_ms: report.ended_utc_ms,
        });
    }
    let window_ended_utc_ms = now_millis()?;
    if rows
        .iter()
        .any(|row| row.ended_utc_ms > window_ended_utc_ms)
    {
        return Err(HarnessError::Process(
            "OG-02 correlation row ended after the bundle window".into(),
        ));
    }
    Ok(Og02CorrelationReport {
        source_id,
        build_id,
        window_started_utc_ms,
        window_ended_utc_ms,
        rows,
    })
}
