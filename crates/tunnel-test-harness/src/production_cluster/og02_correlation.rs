//! OG-02 correlated fault evidence bundle.
//!
//! The eight-case C11 matrix proves the safe-field families across one
//! success and one fault run per stage.  This bundle drives the fault gates
//! the M7 sweep now runs, one child process each, through the same bounded
//! capture and redaction scanner, and reports for every row whether the
//! joined window carries the correlation OG-02 requires: relay, tenant and
//! owner identifiers, a phase, an epoch/generation/fence, queue and lease
//! counters, a close cause, and the relay's bounded peer stage/cause tuples.
//! Completeness is per row, not global.  Every row must carry all seven
//! correlation families.  A row whose induced fault structurally produces a
//! relay peer fault additionally declares `peer_fault_required` and must carry
//! at least one typed tuple; a row whose fault produces none is complete
//! without one.  That distinction is the point of the rule: a single global
//! "at least one peer-fault tuple" requirement silently excluded every gate
//! that faults without a peer fault (the Redis partition, the owner loss and
//! the I04 kill) from OG-02's `every fault row` clause, so those gates could
//! never contribute evidence no matter how complete their correlation was.
//! The four sensitive-value classes are scanned on every row regardless.

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
    /// Whether this gate's induced fault structurally reaches a relay peer
    /// boundary, so the joined window must carry at least one typed
    /// `role/stage/cause` tuple.  A row that sets this to `false` still has to
    /// satisfy every OG-02 correlation family; it is only excused the tuple.
    peer_fault_required: bool,
}

/// The single way a row can fail its own OG-02 completeness rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Og02Shortfall {
    /// At least one OG-02 correlation family was absent from the window.
    MissingCorrelationFields,
    /// The row declares a peer fault required and the window carried none.
    MissingPeerFault,
}

impl Og02Shortfall {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::MissingCorrelationFields => "correlation_fields",
            Self::MissingPeerFault => "peer_fault_tuple",
        }
    }
}

/// Apply one row's own completeness rule to what its run actually produced.
///
/// The correlation families are required unconditionally: a row that declares
/// no peer fault is still held to every field OG-02 names.  The peer-fault
/// tuple is required only of a row that declares one, which is what lets a
/// gate faulting without a peer fault stand as OG-02 evidence rather than be
/// structurally excluded from the row's `every fault row` clause.
#[must_use]
pub fn og02_row_shortfall(
    peer_fault_required: bool,
    missing_fields: &[&str],
    peer_fault_count: usize,
) -> Option<Og02Shortfall> {
    if !missing_fields.is_empty() {
        return Some(Og02Shortfall::MissingCorrelationFields);
    }
    if peer_fault_required && peer_fault_count == 0 {
        return Some(Og02Shortfall::MissingPeerFault);
    }
    None
}

// Exact tuples listed here were observed on real runs of each gate and are
// structurally implied by the fault the gate induces.  Timing-dependent
// tuples (pre-attachment `no_live_owner`, mixed h3/timeout body causes under
// saturation) are reported rather than required.
const ROWS: [Og02Row; 10] = [
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
        peer_fault_required: true,
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
        peer_fault_required: true,
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
            // A planned GOAWAY reaches the ingress relay asynchronously with
            // respect to its own open pipeline, so captured runs have seen it
            // at stream permit checkout, HTTP/3 dispatch and the response
            // head; every ingress open stage is a legitimate landing point and
            // the cause is exact.
            required_peer_faults: &[(
                "ingress",
                "pool_connect|stream_permit_checkout|sender_lock|h3_dispatch|envelope_send|head",
                "transport_goaway",
            )],
        },
        peer_fault_required: true,
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
        peer_fault_required: true,
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
        peer_fault_required: true,
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
        peer_fault_required: true,
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
        peer_fault_required: true,
    },
    // The three rows below are the gates whose fault does not structurally
    // reach a relay peer boundary.  Each was run under this capture before
    // being declared here; the sentinel, role and process expectations are
    // what the gate really produced, not what its family of gates usually
    // produces.
    Og02Row {
        case: MatrixCase {
            // The C11 matrix declares this same command as its Redis *success*
            // arm, because the gate partitions Redis and then recovers.  OG-02
            // cares about the fault it induces on the way through -- admission
            // rejected and dispatch interrupted while the catalog is
            // unreachable -- so the row is declared at the Redis fault stage
            // here.  The two declarations are independent: this bundle does
            // not feed the C11 stage/outcome matrix.
            name: "redis-partition",
            command: "verify-m7-redis-partition",
            stage: FaultStage::Redis,
            outcome: RunOutcome::Failure,
            required_sentinels: PRODUCTION_SENTINELS,
            // `run_redis_partition` drives two library `tunnel_client::connect`
            // sessions rather than `ManagedProcess::spawn`, so the capture
            // joins no managed-process role.
            required_inner_process_counts: &[],
            required_snapshot_roles: PRODUCTION_SNAPSHOT_ROLES,
            required_safe_fields: PRODUCTION_SAFE_FIELDS_MINIMUM,
            // The partition severs the relays from the catalog, not from each
            // other: captured runs carry every OG-02 correlation family and no
            // peer fault tuple at all.  This is the exact row the old global
            // rule excluded.
            required_peer_faults: &[],
        },
        peer_fault_required: false,
    },
    Og02Row {
        case: MatrixCase {
            name: "owner-loss",
            command: "verify-m7-owner-loss-effect",
            stage: FaultStage::Owner,
            outcome: RunOutcome::Failure,
            required_sentinels: PRODUCTION_SENTINELS,
            required_inner_process_counts: &[],
            required_snapshot_roles: PRODUCTION_SNAPSHOT_ROLES,
            required_safe_fields: PRODUCTION_SAFE_FIELDS_MINIMUM,
            // The owner dies on its own side.  Whether the ingress relay is
            // mid-forward when it goes is a race, so captured runs have shown
            // an `ingress/body/transport_h3` tuple without that being
            // structural.  The tuple is reported, never required.
            required_peer_faults: &[],
        },
        peer_fault_required: false,
    },
    Og02Row {
        case: MatrixCase {
            name: "i04-fail-closed",
            command: "verify-m7-i04-fail-closed",
            stage: FaultStage::Owner,
            outcome: RunOutcome::Failure,
            required_sentinels: PRODUCTION_SENTINELS,
            // The fail-closed matrix runs the production CLI three times: the
            // baseline owner, the killed owner and the successor.
            required_inner_process_counts: &[("m7-production-cli", 3)],
            required_snapshot_roles: PRODUCTION_SNAPSHOT_ROLES,
            required_safe_fields: PRODUCTION_SAFE_FIELDS_MINIMUM,
            // Most of what this gate proves is refused *before* any owner
            // selection, so its peer faults are incidental to the owner kill
            // rather than implied by it; captured runs have shown a mix of
            // `no_live_owner`, `transport_h3` and `transport_timeout` tuples
            // whose membership depends on where the kill lands.
            required_peer_faults: &[],
        },
        peer_fault_required: false,
    },
];

/// Correlation evidence for one fault row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Og02RowReport {
    pub name: &'static str,
    pub command: &'static str,
    pub complete: bool,
    /// Whether this row's rule required at least one typed peer fault tuple.
    pub peer_fault_required: bool,
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
        let shortfall = og02_row_shortfall(
            row.peer_fault_required,
            &missing_fields,
            report.peer_faults_present.len(),
        );
        if let Some(shortfall) = shortfall {
            let detail = match shortfall {
                Og02Shortfall::MissingCorrelationFields => missing_fields.join(","),
                Og02Shortfall::MissingPeerFault => "none captured".to_owned(),
            };
            return Err(HarnessError::Process(format!(
                "OG-02 {} row failed its completeness rule (peer_fault_required={}): {}={detail}",
                row.case.name,
                row.peer_fault_required,
                shortfall.label(),
            )));
        }
        rows.push(Og02RowReport {
            name: row.case.name,
            command: row.case.command,
            complete: shortfall.is_none(),
            peer_fault_required: row.peer_fault_required,
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

/// C17 mutation coverage for the per-row OG-02 completeness rule.
///
/// The bundle itself needs Redis, three relay processes and ten child gates,
/// so these cases are the only cheap guard against the rule drifting back into
/// either of the two shapes that would make the row dishonest: a global
/// peer-fault requirement that excludes the gates faulting without one, or a
/// per-row exemption so broad that it also excuses the correlation fields.
#[cfg(test)]
mod c17_completeness_tests {
    use super::{
        OG02_CORRELATION_FIELDS, Og02Shortfall, PRODUCTION_SNAPSHOT_ROLES, ROWS, og02_row_shortfall,
    };

    /// Every OG-02 family present, which is what a passing row looks like.
    fn all_present() -> Vec<&'static str> {
        Vec::new()
    }

    #[test]
    fn row_requiring_a_peer_fault_fails_without_one() {
        assert_eq!(
            og02_row_shortfall(true, &all_present(), 0),
            Some(Og02Shortfall::MissingPeerFault),
            "a row declaring a peer fault required must fail when none was captured"
        );
        assert_eq!(
            og02_row_shortfall(true, &all_present(), 1),
            None,
            "the same row passes as soon as one tuple is captured"
        );
    }

    #[test]
    fn row_not_requiring_a_peer_fault_still_fails_on_a_missing_field() {
        for field in OG02_CORRELATION_FIELDS {
            let missing = vec![field.label()];
            assert_eq!(
                og02_row_shortfall(false, &missing, 0),
                Some(Og02Shortfall::MissingCorrelationFields),
                "a row excused the peer fault must still fail when {} is absent",
                field.label()
            );
            assert_eq!(
                og02_row_shortfall(false, &missing, 3),
                Some(Og02Shortfall::MissingCorrelationFields),
                "captured peer faults never substitute for the {} family",
                field.label()
            );
        }
    }

    #[test]
    fn row_not_requiring_a_peer_fault_passes_with_none() {
        assert_eq!(
            og02_row_shortfall(false, &all_present(), 0),
            None,
            "a gate whose fault produces no peer fault is complete on its correlation alone"
        );
    }

    #[test]
    fn missing_fields_outrank_a_missing_peer_fault() {
        assert_eq!(
            og02_row_shortfall(true, &["owner"], 0),
            Some(Og02Shortfall::MissingCorrelationFields),
            "a row missing both reports the correlation gap, the stronger failure"
        );
    }

    #[test]
    fn declared_rows_split_seven_peer_fault_rows_from_three_without() {
        let required = ROWS.iter().filter(|row| row.peer_fault_required).count();
        assert_eq!(ROWS.len(), 10, "the bundle drives ten fault gates");
        assert_eq!(
            required, 7,
            "the seven original rows declare a peer fault required"
        );
        let excused = ROWS
            .iter()
            .filter(|row| !row.peer_fault_required)
            .map(|row| row.case.command)
            .collect::<Vec<_>>();
        assert_eq!(
            excused,
            vec![
                "verify-m7-redis-partition",
                "verify-m7-owner-loss-effect",
                "verify-m7-i04-fail-closed",
            ],
            "exactly the three gates that fault without a peer fault are excused the tuple"
        );
    }

    #[test]
    fn every_row_is_held_to_the_full_correlation_set() {
        // No row may opt out of a correlation family, however it faults.
        for row in ROWS {
            assert_eq!(
                og02_row_shortfall(row.peer_fault_required, &["phase"], 9),
                Some(Og02Shortfall::MissingCorrelationFields),
                "{} must fail on an absent correlation family",
                row.case.name
            );
            assert_eq!(
                row.case.required_snapshot_roles, PRODUCTION_SNAPSHOT_ROLES,
                "{} joins the production relay and fanout snapshots",
                row.case.name
            );
        }
    }

    #[test]
    fn excused_rows_require_no_exact_peer_fault_tuples() {
        // A row excused the "at least one tuple" rule must not smuggle the
        // requirement back in through an exact tuple list.
        for row in ROWS.iter().filter(|row| !row.peer_fault_required) {
            assert!(
                row.case.required_peer_faults.is_empty(),
                "{} declares no peer fault required and must require no exact tuple",
                row.case.name
            );
        }
    }
}
