//! Complete bounded C11 diagnostic windows and redaction scanning.
//!
//! The collector reports only safe categories and stream roles. It scans all
//! captured bytes for the exact values used by each fixture and checks required
//! diagnostic fields across the joined window without retaining them in receipts.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const MAX_TOKEN_BYTES: usize = 128;
const MAX_SENTINEL_BYTES: usize = 256 * 1024;
/// Stream roles whose bytes are typed relay snapshots and therefore carry the
/// relay-owned peer fault tuples.
const RELAY_SNAPSHOT_ROLE_PREFIX: &str = "snapshot-relay-";
/// The relay's bounded ring size; a snapshot claiming more is not the relay's.
const MAX_PEER_FAULT_RECENT: usize = 32;
/// The relay's closed peer fault stage vocabulary, in dispatch order.
pub const PEER_FAULT_STAGES: [&str; 11] = [
    "validation",
    "pool_connect",
    "stream_permit_checkout",
    "sender_lock",
    "h3_dispatch",
    "envelope_send",
    "complete",
    "head",
    "body",
    "lease",
    "owner",
];
/// The relay's closed peer fault cause vocabulary.
pub const PEER_FAULT_CAUSES: [&str; 26] = [
    "no_live_owner",
    "catalog",
    "membership",
    "invalid_endpoint",
    "identity_mismatch",
    "transport_timeout",
    "transport_goaway",
    "transport_cancelled",
    "transport_h3",
    "transport_quic",
    "transport_capacity",
    "transport_pins_unavailable",
    "transport_body_limit",
    "transport_other",
    "envelope",
    "frame",
    "remote_unauthorized",
    "remote_forbidden",
    "remote_status",
    "invalid_route",
    "unexpected_record",
    "owner_not_ready",
    "capacity",
    "membership_expired",
    "closed",
    "deadline",
];
const PEER_FAULT_ROLES: [&str; 2] = ["ingress", "owner"];
const PEER_FAULT_SNAPSHOT_KEYS: [&str; 10] = [
    "fault_count",
    "ingress_count",
    "owner_count",
    "stage_counts",
    "cause_counts",
    "last_by_stage",
    "recent",
    "closure_stage_counts",
    "closure_cause_counts",
    "closures",
];
/// Task closure lifecycle stages, kept as their own closed vocabulary.
///
/// These are lifecycle ends, not faults, and the relay keeps them in a
/// separate ring so a routine close never reaches `fault_count` or the fault
/// rings.  The scan holds them to the same standard as the fault labels: a
/// closed set, bounded counts, and no payload-derived content.
const TASK_CLOSURE_STAGES: [&str; 3] = ["control", "data", "consumer_stream"];
const TASK_CLOSURE_CAUSES: [&str; 10] = [
    "peer_closed",
    "write_failed",
    "protocol_error",
    "record_too_large",
    "unexpected_message",
    "server_close",
    "stream_closed",
    "expired",
    "stream_failed",
    "liveness_timeout",
];
const TASK_CLOSURE_EVENT_KEYS: [&str; 9] = [
    "sequence",
    "observed_at_ms",
    "stage",
    "cause",
    "tenant_id",
    "device_id",
    "session_id",
    "epoch",
    "stream_id",
];
/// Relay bound on the retained closure ring (`MAX_TASK_CLOSURES`).
const MAX_TASK_CLOSURE_RECENT: usize = 32;
const PEER_FAULT_EVENT_KEYS: [&str; 12] = [
    "sequence",
    "observed_at_ms",
    "role",
    "stage",
    "cause",
    "tenant_id",
    "device_id",
    "session_id",
    "owner_epoch",
    "owner_node_id",
    "service_id",
    "request_id",
];

/// One exact `(role, stage, cause)` peer fault tuple observed in a typed relay
/// snapshot.  Only closed vocabulary labels are ever stored.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PeerFaultTuple {
    pub role: String,
    pub stage: String,
    pub cause: String,
}

impl PeerFaultTuple {
    pub fn new(role: &str, stage: &str, cause: &str) -> Result<Self, ScanFailure> {
        if !PEER_FAULT_ROLES.contains(&role) {
            return Err(ScanFailure::InvalidPeerFault {
                reason: "role outside the closed vocabulary",
            });
        }
        if !PEER_FAULT_STAGES.contains(&stage) {
            return Err(ScanFailure::InvalidPeerFault {
                reason: "stage outside the closed vocabulary",
            });
        }
        if !PEER_FAULT_CAUSES.contains(&cause) {
            return Err(ScanFailure::InvalidPeerFault {
                reason: "cause outside the closed vocabulary",
            });
        }
        Ok(Self {
            role: role.to_owned(),
            stage: stage.to_owned(),
            cause: cause.to_owned(),
        })
    }
}

impl fmt::Display for PeerFaultTuple {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}/{}", self.role, self.stage, self.cause)
    }
}

/// One required peer fault: an exact role and cause, satisfied by any one of
/// a closed set of stages.  Row declarations spell alternatives as
/// `"stage_a|stage_b"`; every alternative must be in the closed vocabulary.
/// A fault whose stage is timing-dependent (a planned GOAWAY can land while
/// the ingress relay checks out a stream permit or while it dispatches the
/// HTTP/3 request) is declared once with both stages instead of pinning one.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PeerFaultRequirement {
    pub role: String,
    pub stages: Vec<String>,
    pub cause: String,
}

impl PeerFaultRequirement {
    pub fn new(role: &str, stages: &str, cause: &str) -> Result<Self, ScanFailure> {
        let mut alternatives = Vec::new();
        for stage in stages.split('|') {
            let tuple = PeerFaultTuple::new(role, stage, cause)?;
            if !alternatives.contains(&tuple.stage) {
                alternatives.push(tuple.stage);
            }
        }
        Ok(Self {
            role: role.to_owned(),
            stages: alternatives,
            cause: cause.to_owned(),
        })
    }

    fn is_satisfied_by(&self, present: &BTreeSet<PeerFaultTuple>) -> bool {
        self.stages.iter().any(|stage| {
            present.contains(&PeerFaultTuple {
                role: self.role.clone(),
                stage: stage.clone(),
                cause: self.cause.clone(),
            })
        })
    }
}

impl fmt::Display for PeerFaultRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}/{}/{}",
            self.role,
            self.stages.join("|"),
            self.cause
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FaultStage {
    Redis,
    Peer,
    Owner,
    Write,
}

impl FaultStage {
    pub const ALL: [Self; 4] = [Self::Redis, Self::Peer, Self::Owner, Self::Write];

    fn label(self) -> &'static str {
        match self {
            Self::Redis => "redis",
            Self::Peer => "peer",
            Self::Owner => "owner",
            Self::Write => "write",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RunOutcome {
    Success,
    Failure,
}

impl RunOutcome {
    pub const ALL: [Self; 2] = [Self::Success, Self::Failure];

    fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SentinelKind {
    Credential,
    ApplicationPayload,
    FilesystemPath,
    PrivateEndpoint,
}

impl SentinelKind {
    fn label(self) -> &'static str {
        match self {
            Self::Credential => "credential",
            Self::ApplicationPayload => "application_payload",
            Self::FilesystemPath => "filesystem_path",
            Self::PrivateEndpoint => "private_endpoint",
        }
    }
}

/// Exact run-specific value retained only by the in-memory scanner.
///
/// Deliberately does not implement `Debug` or `Display`: a `ScanFailure`
/// cannot accidentally include the secret, payload, path, or endpoint.
pub struct Sentinel {
    kind: SentinelKind,
    value: Vec<u8>,
}

impl Sentinel {
    pub fn new(kind: SentinelKind, value: impl Into<Vec<u8>>) -> Result<Self, ScanFailure> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_SENTINEL_BYTES {
            return Err(ScanFailure::InvalidSentinel { kind });
        }
        Ok(Self { kind, value })
    }

    pub fn kind(&self) -> SentinelKind {
        self.kind
    }

    /// Compare this sentinel's exact bytes, for applying a manifest tombstone.
    ///
    /// Deliberately a comparison rather than an accessor: the value must not
    /// leave this type, so a failure or a log can never carry it.
    pub fn has_value(&self, value: &[u8]) -> bool {
        self.value == value
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SafeField {
    Relay,
    Tenant,
    Owner,
    Route,
    Phase,
    EpochGenerationFence,
    RevocationOwnerDeath,
    Counter,
    CloseCause,
}

impl SafeField {
    pub const ALL: [Self; 9] = [
        Self::Relay,
        Self::Tenant,
        Self::Owner,
        Self::Route,
        Self::Phase,
        Self::EpochGenerationFence,
        Self::RevocationOwnerDeath,
        Self::Counter,
        Self::CloseCause,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Relay => "relay",
            Self::Tenant => "tenant",
            Self::Owner => "owner",
            Self::Route => "route",
            Self::Phase => "phase",
            Self::EpochGenerationFence => "epoch_generation_fence",
            Self::RevocationOwnerDeath => "revocation_owner_death",
            Self::Counter => "counter",
            Self::CloseCause => "close_cause",
        }
    }

    fn matches(self, bytes: &[u8]) -> bool {
        let needles: &[&[u8]] = match self {
            Self::Relay => &[b"relay", b"relays"],
            Self::Tenant => &[b"tenant", b"tenants", b"tenant_id"],
            Self::Owner => &[
                b"owner",
                b"owners",
                b"owner_id",
                b"owner_relay",
                b"target_owner",
                b"sibling_owner",
            ],
            Self::Route => &[
                b"route",
                b"peer_ready",
                b"ingress",
                b"ingress_node",
                b"ingress_relays",
            ],
            Self::Phase => &[b"phase", b"stage"],
            Self::EpochGenerationFence => &[
                b"epoch",
                b"generation",
                b"active_generation",
                b"candidate_generation",
                b"fence",
            ],
            Self::RevocationOwnerDeath => &[
                b"revocation",
                b"owner_death",
                b"owner-death",
                b"owner_loss",
                b"key_revocation",
            ],
            Self::Counter => &[
                b"counter",
                b"dispatch",
                b"dispatches",
                b"dispatch_counter",
                b"queue_messages",
                b"queue_bytes",
                b"lifetime_application_dispatches",
                b"active_connections",
                b"streams",
                b"sockets",
            ],
            Self::CloseCause => &[
                b"reason",
                b"close",
                b"close_cause",
                b"cause",
                b"terminal",
                b"terminal_reason",
                b"terminal_event",
                b"terminal_events",
                b"session_terminal_events",
                b"rotation_recovery_reason",
                b"post_terminal",
            ],
        };
        needles
            .iter()
            .any(|needle| contains_ascii_case_insensitive_key(bytes, needle))
    }
}

pub struct C11RunSpec {
    pub run_id: String,
    pub source_id: String,
    pub build_id: String,
    pub stage: FaultStage,
    pub outcome: RunOutcome,
    pub started_utc_ms: i64,
    pub expected_roles: BTreeSet<String>,
    /// Roles whose bytes may establish a safe-field observation.  Adapter
    /// snapshots remain captured and joined, but wrapper text produced by the
    /// collector itself must not satisfy the matrix's diagnostic-field gate.
    pub safe_field_roles: BTreeSet<String>,
    pub required_fields: BTreeSet<SafeField>,
    /// Peer fault requirements the typed relay snapshots must satisfy: an
    /// exact role and cause at one of the declared stages.
    pub required_peer_faults: BTreeSet<PeerFaultRequirement>,
    sentinels: Vec<Sentinel>,
    pub max_bytes_per_stream: usize,
}

impl C11RunSpec {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: impl Into<String>,
        source_id: impl Into<String>,
        build_id: impl Into<String>,
        stage: FaultStage,
        outcome: RunOutcome,
        started_utc_ms: i64,
        expected_roles: impl IntoIterator<Item = impl Into<String>>,
        sentinels: Vec<Sentinel>,
    ) -> Result<Self, ScanFailure> {
        let run_id = validate_token("run_id", run_id.into())?;
        let source_id = validate_token("source_id", source_id.into())?;
        let build_id = validate_token("build_id", build_id.into())?;
        let expected_roles = expected_roles
            .into_iter()
            .map(|role| validate_token("stream_role", role.into()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        if expected_roles.is_empty() {
            return Err(ScanFailure::NoExpectedStreams);
        }
        let safe_field_roles = expected_roles.clone();
        Ok(Self {
            run_id,
            source_id,
            build_id,
            stage,
            outcome,
            started_utc_ms,
            expected_roles,
            safe_field_roles,
            required_fields: SafeField::ALL.into_iter().collect(),
            required_peer_faults: BTreeSet::new(),
            sentinels,
            max_bytes_per_stream: 1 << 20,
        })
    }

    /// Require `(role, stages, cause)` peer faults in the relay snapshots; the
    /// stage field may list `|`-separated closed-vocabulary alternatives.
    pub fn with_required_peer_faults<'a>(
        mut self,
        tuples: impl IntoIterator<Item = &'a (&'a str, &'a str, &'a str)>,
    ) -> Result<Self, ScanFailure> {
        self.required_peer_faults = tuples
            .into_iter()
            .map(|(role, stages, cause)| PeerFaultRequirement::new(role, stages, cause))
            .collect::<Result<BTreeSet<_>, _>>()?;
        Ok(self)
    }

    pub fn with_required_fields(mut self, fields: impl IntoIterator<Item = SafeField>) -> Self {
        self.required_fields = fields.into_iter().collect();
        self
    }

    pub fn with_safe_field_roles(
        mut self,
        roles: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, ScanFailure> {
        let roles = roles
            .into_iter()
            .map(|role| validate_token("safe_field_role", role.into()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        if roles.iter().any(|role| !self.expected_roles.contains(role)) {
            return Err(ScanFailure::SafeFieldRoleNotExpected);
        }
        self.safe_field_roles = roles;
        Ok(self)
    }

    pub fn with_stream_limit(mut self, max_bytes_per_stream: usize) -> Result<Self, ScanFailure> {
        if max_bytes_per_stream == 0 {
            return Err(ScanFailure::InvalidStreamLimit);
        }
        self.max_bytes_per_stream = max_bytes_per_stream;
        Ok(self)
    }
}

struct StreamCapture {
    bytes: Vec<u8>,
    closed: bool,
    joined: bool,
}

impl StreamCapture {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            closed: false,
            joined: false,
        }
    }
}

pub struct C11Window {
    spec: C11RunSpec,
    streams: BTreeMap<String, StreamCapture>,
}

impl C11Window {
    pub fn new(spec: C11RunSpec) -> Self {
        Self {
            spec,
            streams: BTreeMap::new(),
        }
    }

    pub fn append(&mut self, role: &str, bytes: &[u8]) -> Result<(), ScanFailure> {
        let limit = self.spec.max_bytes_per_stream;
        {
            let stream = self.stream_mut(role)?;
            if stream.closed {
                return Err(ScanFailure::AppendAfterClose {
                    role: role.to_owned(),
                });
            }
            let next_len = stream.bytes.len().checked_add(bytes.len()).ok_or_else(|| {
                ScanFailure::CaptureOverflow {
                    role: role.to_owned(),
                    limit,
                }
            })?;
            if next_len > limit {
                return Err(ScanFailure::CaptureOverflow {
                    role: role.to_owned(),
                    limit,
                });
            }
            stream.bytes.extend_from_slice(bytes);
        }
        let captured = &self
            .streams
            .get(role)
            .expect("stream is registered by stream_mut")
            .bytes;
        for sentinel in &self.spec.sentinels {
            if contains(captured, &sentinel.value) {
                return Err(ScanFailure::SensitiveValue {
                    role: role.to_owned(),
                    kind: sentinel.kind,
                });
            }
        }
        Ok(())
    }

    pub fn close(&mut self, role: &str) -> Result<(), ScanFailure> {
        let stream = self.stream_mut(role)?;
        if stream.closed {
            return Err(ScanFailure::DuplicateClose {
                role: role.to_owned(),
            });
        }
        stream.closed = true;
        Ok(())
    }

    pub fn mark_joined(&mut self, role: &str) -> Result<(), ScanFailure> {
        let stream = self.stream_mut(role)?;
        if !stream.closed {
            return Err(ScanFailure::JoinedBeforeClose {
                role: role.to_owned(),
            });
        }
        stream.joined = true;
        Ok(())
    }

    pub fn finish(self, ended_utc_ms: i64) -> Result<C11ScanReport, ScanFailure> {
        if ended_utc_ms < self.spec.started_utc_ms {
            return Err(ScanFailure::InvalidWindow);
        }
        for (role, stream) in &self.streams {
            if !stream.closed {
                return Err(ScanFailure::StreamNotClosed { role: role.clone() });
            }
            if !stream.joined {
                return Err(ScanFailure::StreamNotJoined { role: role.clone() });
            }
        }
        for role in &self.spec.expected_roles {
            if !self.streams.contains_key(role) {
                return Err(ScanFailure::MissingStream { role: role.clone() });
            }
        }

        // Every typed relay snapshot must carry a well-formed, closed
        // vocabulary peer fault table even when it is empty; the tuples it
        // holds are collected for the case's exact requirement and for the
        // bundle report.  Adapter snapshots and process streams are never
        // parsed here, so wrapper text cannot manufacture a tuple.
        let mut peer_faults_present = BTreeSet::new();
        for (role, stream) in &self.streams {
            if role.starts_with(RELAY_SNAPSHOT_ROLE_PREFIX) {
                peer_faults_present.extend(scan_peer_faults(&stream.bytes)?);
            }
        }
        for required in &self.spec.required_peer_faults {
            if !required.is_satisfied_by(&peer_faults_present) {
                return Err(ScanFailure::MissingPeerFault {
                    requirement: required.clone(),
                });
            }
        }

        let mut missing_fields = Vec::new();
        for field in &self.spec.required_fields {
            if !self
                .streams
                .iter()
                .filter(|(role, _)| self.spec.safe_field_roles.contains(*role))
                .any(|(_, stream)| field.matches(&stream.bytes))
            {
                missing_fields.push(*field);
            }
        }
        if !missing_fields.is_empty() {
            return Err(ScanFailure::MissingSafeFields {
                fields: missing_fields,
            });
        }

        let fields_present = SafeField::ALL
            .into_iter()
            .filter(|field| {
                self.streams
                    .iter()
                    .filter(|(role, _)| self.spec.safe_field_roles.contains(*role))
                    .map(|(_, stream)| stream)
                    .any(|stream| field.matches(&stream.bytes))
            })
            .collect();
        let bytes_by_role = self
            .streams
            .into_iter()
            .map(|(role, stream)| (role, stream.bytes.len()))
            .collect();
        Ok(C11ScanReport {
            run_id: self.spec.run_id,
            source_id: self.spec.source_id,
            build_id: self.spec.build_id,
            stage: self.spec.stage,
            outcome: self.spec.outcome,
            started_utc_ms: self.spec.started_utc_ms,
            ended_utc_ms,
            bytes_by_role,
            fields_present,
            peer_faults_present,
        })
    }

    fn stream_mut(&mut self, role: &str) -> Result<&mut StreamCapture, ScanFailure> {
        if !self.spec.expected_roles.contains(role) {
            return Err(ScanFailure::UnexpectedStream {
                role: role.to_owned(),
            });
        }
        Ok(self
            .streams
            .entry(role.to_owned())
            .or_insert_with(StreamCapture::new))
    }
}

#[derive(Debug)]
pub struct C11ScanReport {
    pub run_id: String,
    pub source_id: String,
    pub build_id: String,
    pub stage: FaultStage,
    pub outcome: RunOutcome,
    pub started_utc_ms: i64,
    pub ended_utc_ms: i64,
    pub bytes_by_role: BTreeMap<String, usize>,
    pub fields_present: BTreeSet<SafeField>,
    /// Exact tuples found in the typed relay snapshots of this run.
    pub peer_faults_present: BTreeSet<PeerFaultTuple>,
}

pub struct C11EvidenceBundle {
    matrix_started_utc_ms: i64,
    reports: BTreeMap<(FaultStage, RunOutcome), C11ScanReport>,
}

impl C11EvidenceBundle {
    pub fn new(matrix_started_utc_ms: i64) -> Self {
        Self {
            matrix_started_utc_ms,
            reports: BTreeMap::new(),
        }
    }

    pub fn add(&mut self, report: C11ScanReport) -> Result<(), ScanFailure> {
        if report.started_utc_ms < self.matrix_started_utc_ms {
            return Err(ScanFailure::RunOutsideMatrix {
                run_id: report.run_id,
            });
        }
        let key = (report.stage, report.outcome);
        if self.reports.contains_key(&key) {
            return Err(ScanFailure::DuplicateMatrixCase {
                stage: report.stage,
                outcome: report.outcome,
            });
        }
        self.reports.insert(key, report);
        Ok(())
    }

    pub fn finish(self, matrix_ended_utc_ms: i64) -> Result<C11MatrixReport, ScanFailure> {
        if matrix_ended_utc_ms < self.matrix_started_utc_ms {
            return Err(ScanFailure::InvalidWindow);
        }
        if self
            .reports
            .values()
            .any(|report| report.ended_utc_ms > matrix_ended_utc_ms)
        {
            return Err(ScanFailure::RunOutsideMatrix {
                run_id: "matrix-end".to_owned(),
            });
        }
        for stage in FaultStage::ALL {
            for outcome in RunOutcome::ALL {
                if !self.reports.contains_key(&(stage, outcome)) {
                    return Err(ScanFailure::MissingMatrixCase { stage, outcome });
                }
            }
        }
        let fields_present = self
            .reports
            .values()
            .flat_map(|report| report.fields_present.iter().copied())
            .collect::<BTreeSet<_>>();
        let missing_fields = SafeField::ALL
            .into_iter()
            .filter(|field| !fields_present.contains(field))
            .collect::<Vec<_>>();
        if !missing_fields.is_empty() {
            return Err(ScanFailure::MissingSafeFields {
                fields: missing_fields,
            });
        }
        let Some(first_report) = self.reports.values().next() else {
            return Err(ScanFailure::NoExpectedStreams);
        };
        let source_id = first_report.source_id.clone();
        let build_id = first_report.build_id.clone();
        if self
            .reports
            .values()
            .any(|report| report.source_id != source_id || report.build_id != build_id)
        {
            return Err(ScanFailure::MixedSourceBuild);
        }
        let captured_streams = self
            .reports
            .values()
            .map(|report| report.bytes_by_role.len())
            .sum();
        let captured_bytes = self
            .reports
            .values()
            .flat_map(|report| report.bytes_by_role.values())
            .sum();
        let runs = self.reports.len();
        let peer_fault_tuples = self
            .reports
            .values()
            .flat_map(|report| report.peer_faults_present.iter().cloned())
            .collect::<BTreeSet<_>>()
            .len();
        Ok(C11MatrixReport {
            matrix_started_utc_ms: self.matrix_started_utc_ms,
            matrix_ended_utc_ms,
            source_id,
            build_id,
            safe_field_count: fields_present.len(),
            captured_streams,
            captured_bytes,
            runs,
            peer_fault_tuples,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C11MatrixReport {
    pub matrix_started_utc_ms: i64,
    pub matrix_ended_utc_ms: i64,
    pub source_id: String,
    pub build_id: String,
    pub safe_field_count: usize,
    pub captured_streams: usize,
    pub captured_bytes: usize,
    pub runs: usize,
    /// Distinct exact peer fault tuples observed across the matrix.
    pub peer_fault_tuples: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScanFailure {
    InvalidToken {
        field: &'static str,
    },
    InvalidSentinel {
        kind: SentinelKind,
    },
    InvalidStreamLimit,
    NoExpectedStreams,
    UnexpectedStream {
        role: String,
    },
    AppendAfterClose {
        role: String,
    },
    CaptureOverflow {
        role: String,
        limit: usize,
    },
    SensitiveValue {
        role: String,
        kind: SentinelKind,
    },
    DuplicateClose {
        role: String,
    },
    JoinedBeforeClose {
        role: String,
    },
    StreamNotClosed {
        role: String,
    },
    StreamNotJoined {
        role: String,
    },
    MissingStream {
        role: String,
    },
    MissingSafeFields {
        fields: Vec<SafeField>,
    },
    SafeFieldRoleNotExpected,
    MixedSourceBuild,
    InvalidWindow,
    RunOutsideMatrix {
        run_id: String,
    },
    DuplicateMatrixCase {
        stage: FaultStage,
        outcome: RunOutcome,
    },
    MissingMatrixCase {
        stage: FaultStage,
        outcome: RunOutcome,
    },
    /// A required peer fault (exact role and cause at any declared stage) was
    /// absent from every relay snapshot.
    MissingPeerFault {
        requirement: PeerFaultRequirement,
    },
    /// A relay snapshot's peer fault table was malformed or outside the closed
    /// vocabulary.  The reason is a fixed label; no snapshot bytes are copied.
    InvalidPeerFault {
        reason: &'static str,
    },
}

impl fmt::Display for ScanFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidToken { field } => write!(formatter, "invalid bounded {field}"),
            Self::InvalidSentinel { kind } => {
                write!(formatter, "invalid {} sentinel", kind.label())
            }
            Self::InvalidStreamLimit => formatter.write_str("invalid stream capture limit"),
            Self::NoExpectedStreams => formatter.write_str("no expected diagnostic streams"),
            Self::UnexpectedStream { role } => write!(formatter, "unexpected stream role {role}"),
            Self::AppendAfterClose { role } => write!(formatter, "append after close for {role}"),
            Self::CaptureOverflow { role, limit } => {
                write!(formatter, "capture overflow for {role} at {limit} bytes")
            }
            Self::SensitiveValue { role, kind } => {
                write!(formatter, "sensitive {} value in {role}", kind.label())
            }
            Self::DuplicateClose { role } => write!(formatter, "duplicate close for {role}"),
            Self::JoinedBeforeClose { role } => write!(formatter, "join before close for {role}"),
            Self::StreamNotClosed { role } => write!(formatter, "stream not closed: {role}"),
            Self::StreamNotJoined { role } => write!(formatter, "stream not joined: {role}"),
            Self::MissingStream { role } => write!(formatter, "missing expected stream: {role}"),
            Self::MissingSafeFields { fields } => {
                write!(formatter, "missing safe fields: ")?;
                for (index, field) in fields.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str(",")?;
                    }
                    formatter.write_str(field.label())?;
                }
                Ok(())
            }
            Self::SafeFieldRoleNotExpected => {
                formatter.write_str("safe-field role was not an expected stream")
            }
            Self::MixedSourceBuild => formatter.write_str("matrix mixed source/build identities"),
            Self::InvalidWindow => formatter.write_str("invalid diagnostic window"),
            Self::RunOutsideMatrix { run_id } => {
                write!(formatter, "run outside matrix window: {run_id}")
            }
            Self::DuplicateMatrixCase { stage, outcome } => {
                write!(
                    formatter,
                    "duplicate {} {} matrix case",
                    stage.label(),
                    outcome.label()
                )
            }
            Self::MissingMatrixCase { stage, outcome } => {
                write!(
                    formatter,
                    "missing {} {} matrix case",
                    stage.label(),
                    outcome.label()
                )
            }
            Self::MissingPeerFault { requirement } => {
                write!(formatter, "missing peer fault tuple: {requirement}")
            }
            Self::InvalidPeerFault { reason } => {
                write!(formatter, "invalid peer fault table: {reason}")
            }
        }
    }
}

/// Parse every typed relay snapshot frame in `bytes` and return the exact
/// peer fault tuples it carries.
///
/// The table is validated strictly: only the relay's key set, only closed
/// vocabulary labels, bounded identifiers, consistent counters and the
/// relay's ring bound are accepted.  A snapshot that carries anything else
/// (an extra field, an unbounded string, an unknown cause) fails the window
/// so a payload or credential cannot ride along inside a diagnostic table.
fn scan_peer_faults(bytes: &[u8]) -> Result<BTreeSet<PeerFaultTuple>, ScanFailure> {
    let mut tuples = BTreeSet::new();
    let stream = serde_json::Deserializer::from_slice(bytes).into_iter::<serde_json::Value>();
    for document in stream {
        let document = document.map_err(|_| ScanFailure::InvalidPeerFault {
            reason: "relay snapshot frame was not a JSON document",
        })?;
        let table =
            document
                .get("peer_fault_diagnostics")
                .ok_or(ScanFailure::InvalidPeerFault {
                    reason: "relay snapshot omitted peer_fault_diagnostics",
                })?;
        tuples.extend(validate_peer_fault_table(table)?);
    }
    Ok(tuples)
}

fn validate_peer_fault_table(
    table: &serde_json::Value,
) -> Result<BTreeSet<PeerFaultTuple>, ScanFailure> {
    let object = table.as_object().ok_or(ScanFailure::InvalidPeerFault {
        reason: "table was not an object",
    })?;
    require_exact_keys(object, &PEER_FAULT_SNAPSHOT_KEYS, "table")?;
    let fault_count = json_u64(&object["fault_count"], "fault_count")?;
    let ingress_count = json_u64(&object["ingress_count"], "ingress_count")?;
    let owner_count = json_u64(&object["owner_count"], "owner_count")?;
    if ingress_count.checked_add(owner_count) != Some(fault_count) {
        return Err(ScanFailure::InvalidPeerFault {
            reason: "role counters do not sum to fault_count",
        });
    }
    let stage_counts = json_count_map(&object["stage_counts"], &PEER_FAULT_STAGES, "stage_counts")?;
    let cause_counts = json_count_map(&object["cause_counts"], &PEER_FAULT_CAUSES, "cause_counts")?;
    if stage_counts != fault_count || cause_counts != fault_count {
        return Err(ScanFailure::InvalidPeerFault {
            reason: "stage or cause counters do not sum to fault_count",
        });
    }
    let recent = object["recent"]
        .as_array()
        .ok_or(ScanFailure::InvalidPeerFault {
            reason: "recent was not an array",
        })?;
    if recent.len() > MAX_PEER_FAULT_RECENT || recent.len() as u64 > fault_count {
        return Err(ScanFailure::InvalidPeerFault {
            reason: "recent ring exceeds the relay bound",
        });
    }
    let mut tuples = BTreeSet::new();
    let mut last_sequence = 0_u64;
    for event in recent {
        let (tuple, sequence) = validate_peer_fault_event(event)?;
        if sequence <= last_sequence {
            return Err(ScanFailure::InvalidPeerFault {
                reason: "recent ring is not strictly ordered",
            });
        }
        last_sequence = sequence;
        tuples.insert(tuple);
    }
    // Closure entries are validated to the same standard, and separately: a
    // closure must never be counted as a fault, so these counters are checked
    // against the closure ring rather than against `fault_count`.
    let closure_stage_counts = json_count_map(
        &object["closure_stage_counts"],
        &TASK_CLOSURE_STAGES,
        "closure_stage_counts",
    )?;
    let closure_cause_counts = json_count_map(
        &object["closure_cause_counts"],
        &TASK_CLOSURE_CAUSES,
        "closure_cause_counts",
    )?;
    if closure_stage_counts != closure_cause_counts {
        return Err(ScanFailure::InvalidPeerFault {
            reason: "closure stage and cause counters disagree",
        });
    }
    let closures = object["closures"]
        .as_array()
        .ok_or(ScanFailure::InvalidPeerFault {
            reason: "closures was not an array",
        })?;
    if closures.len() > MAX_TASK_CLOSURE_RECENT || closures.len() as u64 > closure_stage_counts {
        return Err(ScanFailure::InvalidPeerFault {
            reason: "closure ring exceeds the relay bound",
        });
    }
    let mut last_closure_sequence = 0_u64;
    for closure in closures {
        let sequence = validate_task_closure_event(closure)?;
        if sequence <= last_closure_sequence {
            return Err(ScanFailure::InvalidPeerFault {
                reason: "closure ring is not strictly ordered",
            });
        }
        last_closure_sequence = sequence;
    }
    let last_by_stage =
        object["last_by_stage"]
            .as_object()
            .ok_or(ScanFailure::InvalidPeerFault {
                reason: "last_by_stage was not an object",
            })?;
    for (stage, event) in last_by_stage {
        if !PEER_FAULT_STAGES.contains(&stage.as_str()) {
            return Err(ScanFailure::InvalidPeerFault {
                reason: "last_by_stage key outside the closed vocabulary",
            });
        }
        let (tuple, _) = validate_peer_fault_event(event)?;
        if tuple.stage != *stage {
            return Err(ScanFailure::InvalidPeerFault {
                reason: "last_by_stage entry stage mismatch",
            });
        }
        tuples.insert(tuple);
    }
    Ok(tuples)
}

fn validate_peer_fault_event(
    event: &serde_json::Value,
) -> Result<(PeerFaultTuple, u64), ScanFailure> {
    let object = event.as_object().ok_or(ScanFailure::InvalidPeerFault {
        reason: "event was not an object",
    })?;
    require_exact_keys(object, &PEER_FAULT_EVENT_KEYS, "event")?;
    let sequence = json_u64(&object["sequence"], "sequence")?;
    if sequence == 0 {
        return Err(ScanFailure::InvalidPeerFault {
            reason: "event sequence was zero",
        });
    }
    json_u64(&object["observed_at_ms"], "observed_at_ms")?;
    let role = json_label(&object["role"], "role")?;
    let stage = json_label(&object["stage"], "stage")?;
    let cause = json_label(&object["cause"], "cause")?;
    let tuple = PeerFaultTuple::new(role, stage, cause)?;
    json_uuid(&object["tenant_id"], "tenant_id")?;
    json_uuid(&object["device_id"], "device_id")?;
    json_optional_token(&object["session_id"], "session_id")?;
    if !object["owner_epoch"].is_null() {
        json_u64(&object["owner_epoch"], "owner_epoch")?;
    }
    json_optional_token(&object["owner_node_id"], "owner_node_id")?;
    if !object["service_id"].is_null() {
        json_uuid(&object["service_id"], "service_id")?;
    }
    json_optional_token(&object["request_id"], "request_id")?;
    Ok((tuple, sequence))
}

/// Validate one task closure entry and return its diagnostic sequence.
///
/// A closure carries only bounded labels and owner-registration identifiers.
/// Anything derived from a request body, header, ticket or endpoint would fail
/// the exact-key check here, which is the point.
fn validate_task_closure_event(event: &serde_json::Value) -> Result<u64, ScanFailure> {
    let object = event.as_object().ok_or(ScanFailure::InvalidPeerFault {
        reason: "closure was not an object",
    })?;
    require_exact_keys(object, &TASK_CLOSURE_EVENT_KEYS, "event")?;
    let sequence = json_u64(&object["sequence"], "sequence")?;
    if sequence == 0 {
        return Err(ScanFailure::InvalidPeerFault {
            reason: "event sequence was zero",
        });
    }
    json_u64(&object["observed_at_ms"], "observed_at_ms")?;
    let stage = json_label(&object["stage"], "stage")?;
    if !TASK_CLOSURE_STAGES.contains(&stage) {
        return Err(ScanFailure::InvalidPeerFault {
            reason: "closure stage is outside the relay vocabulary",
        });
    }
    let cause = json_label(&object["cause"], "cause")?;
    if !TASK_CLOSURE_CAUSES.contains(&cause) {
        return Err(ScanFailure::InvalidPeerFault {
            reason: "closure cause is outside the relay vocabulary",
        });
    }
    json_uuid(&object["tenant_id"], "tenant_id")?;
    json_uuid(&object["device_id"], "device_id")?;
    json_optional_token(&object["session_id"], "session_id")?;
    json_u64(&object["epoch"], "epoch")?;
    if !object["stream_id"].is_null() {
        json_u64(&object["stream_id"], "stream_id")?;
    }
    Ok(sequence)
}

fn require_exact_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
    what: &'static str,
) -> Result<(), ScanFailure> {
    if object.len() != keys.len() || !keys.iter().all(|key| object.contains_key(*key)) {
        return Err(ScanFailure::InvalidPeerFault {
            reason: match what {
                "table" => "table keys differ from the relay schema",
                _ => "event keys differ from the relay schema",
            },
        });
    }
    Ok(())
}

fn json_u64(value: &serde_json::Value, field: &'static str) -> Result<u64, ScanFailure> {
    value.as_u64().ok_or(ScanFailure::InvalidPeerFault {
        reason: match field {
            "fault_count" | "ingress_count" | "owner_count" => "role counter was not a u64",
            "sequence" => "event sequence was not a u64",
            "observed_at_ms" => "event timestamp was not a u64",
            "owner_epoch" => "owner_epoch was not a u64",
            _ => "counter was not a u64",
        },
    })
}

fn json_count_map(
    value: &serde_json::Value,
    vocabulary: &[&str],
    field: &'static str,
) -> Result<u64, ScanFailure> {
    let object = value.as_object().ok_or(ScanFailure::InvalidPeerFault {
        reason: match field {
            "stage_counts" => "stage_counts was not an object",
            _ => "cause_counts was not an object",
        },
    })?;
    let mut total = 0_u64;
    for (key, count) in object {
        if !vocabulary.contains(&key.as_str()) {
            return Err(ScanFailure::InvalidPeerFault {
                reason: match field {
                    "stage_counts" => "stage_counts key outside the closed vocabulary",
                    _ => "cause_counts key outside the closed vocabulary",
                },
            });
        }
        total = total.checked_add(json_u64(count, "counter")?).ok_or(
            ScanFailure::InvalidPeerFault {
                reason: "counter overflow",
            },
        )?;
    }
    Ok(total)
}

fn json_label<'a>(
    value: &'a serde_json::Value,
    field: &'static str,
) -> Result<&'a str, ScanFailure> {
    value.as_str().ok_or(ScanFailure::InvalidPeerFault {
        reason: match field {
            "role" => "event role was not a string",
            "stage" => "event stage was not a string",
            _ => "event cause was not a string",
        },
    })
}

fn json_uuid(value: &serde_json::Value, field: &'static str) -> Result<(), ScanFailure> {
    let text = value.as_str().ok_or(ScanFailure::InvalidPeerFault {
        reason: match field {
            "tenant_id" => "tenant_id was not a string",
            "device_id" => "device_id was not a string",
            _ => "service_id was not a string",
        },
    })?;
    let bytes = text.as_bytes();
    let shaped = bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        });
    if !shaped {
        return Err(ScanFailure::InvalidPeerFault {
            reason: match field {
                "tenant_id" => "tenant_id was not a uuid",
                "device_id" => "device_id was not a uuid",
                _ => "service_id was not a uuid",
            },
        });
    }
    Ok(())
}

fn json_optional_token(value: &serde_json::Value, field: &'static str) -> Result<(), ScanFailure> {
    if value.is_null() {
        return Ok(());
    }
    let text = value.as_str().ok_or(ScanFailure::InvalidPeerFault {
        reason: match field {
            "session_id" => "session_id was not a string",
            "owner_node_id" => "owner_node_id was not a string",
            _ => "request_id was not a string",
        },
    })?;
    if validate_token(field, text.to_owned()).is_err() {
        return Err(ScanFailure::InvalidPeerFault {
            reason: match field {
                "session_id" => "session_id was not a bounded identifier",
                "owner_node_id" => "owner_node_id was not a bounded identifier",
                _ => "request_id was not a bounded identifier",
            },
        });
    }
    Ok(())
}

fn validate_token(field: &'static str, value: String) -> Result<String, ScanFailure> {
    if value.is_empty()
        || value.len() > MAX_TOKEN_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ScanFailure::InvalidToken { field });
    }
    Ok(value)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Match a complete diagnostic key/category instead of an arbitrary substring.
///
/// Snapshot and harness records use ASCII identifiers separated by punctuation
/// (`queue_messages=`, `owner-death`, JSON quotes, and similar forms). Treat
/// ASCII letters, digits, and underscores as identifier bytes so a value such
/// as `counterfeit` cannot satisfy the `counter` category while compound keys
/// remain matched by their full needle.
fn contains_ascii_case_insensitive_key(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .enumerate()
            .any(|(offset, window)| {
                window
                    .iter()
                    .zip(needle)
                    .all(|(left, right)| left.eq_ignore_ascii_case(right))
                    && is_identifier_boundary(haystack, offset, needle.len())
            })
}

fn is_identifier_boundary(haystack: &[u8], offset: usize, needle_len: usize) -> bool {
    let before_is_boundary = offset
        .checked_sub(1)
        .and_then(|index| haystack.get(index))
        .is_none_or(|byte| !is_identifier_byte(*byte));
    let after_is_boundary = haystack
        .get(offset.saturating_add(needle_len))
        .is_none_or(|byte| !is_identifier_byte(*byte));
    before_is_boundary && after_is_boundary
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[cfg(test)]
mod matcher_tests {
    use super::{SafeField, contains_ascii_case_insensitive_key};

    #[test]
    fn field_needles_do_not_match_identifier_substrings() {
        assert!(!contains_ascii_case_insensitive_key(
            b"counterfeit=true",
            b"counter"
        ));
        assert!(!contains_ascii_case_insensitive_key(
            b"reroute=true",
            b"route"
        ));
        assert!(!contains_ascii_case_insensitive_key(
            b"terminality=true",
            b"terminal"
        ));
    }

    #[test]
    fn field_needles_match_complete_compound_keys() {
        assert!(contains_ascii_case_insensitive_key(
            br#"{"queue_messages":1}"#,
            b"queue_messages"
        ));
        assert!(contains_ascii_case_insensitive_key(
            b"owner-death=true",
            b"owner-death"
        ));
        assert!(contains_ascii_case_insensitive_key(
            br#"{"session_terminal_events":1}"#,
            b"session_terminal_events"
        ));
    }

    #[test]
    fn safe_field_categories_use_boundary_matching() {
        assert!(!SafeField::Counter.matches(b"counterfeit=true"));
        assert!(!SafeField::Route.matches(b"reroute=true"));
        assert!(!SafeField::CloseCause.matches(b"terminality=true"));
    }

    #[test]
    fn owner_death_requires_an_exact_emitted_field() {
        // The FP-05 Debug field `owner_loss_close_observed` is intentionally
        // not enough: boundary matching must reject the `owner_loss` prefix.
        assert!(!SafeField::RevocationOwnerDeath.matches(b"owner_loss_close_observed=true"));
        assert!(SafeField::RevocationOwnerDeath.matches(b"owner_death=true"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> C11RunSpec {
        C11RunSpec::new(
            "run-1",
            "source-1",
            "build-1",
            FaultStage::Peer,
            RunOutcome::Success,
            100,
            ["relay-a"],
            vec![Sentinel::new(SentinelKind::Credential, b"secret-token").unwrap()],
        )
        .unwrap()
        .with_required_fields([
            SafeField::Relay,
            SafeField::Tenant,
            SafeField::Owner,
            SafeField::Route,
            SafeField::Phase,
            SafeField::EpochGenerationFence,
            SafeField::RevocationOwnerDeath,
            SafeField::Counter,
            SafeField::CloseCause,
        ])
    }

    const SAFE_LINE: &[u8] = b"relay=relay-a tenant=tenant-a owner=owner-a route=peer-route phase=ready epoch=2 generation=3 fence=4 revocation=false owner_death=false dispatch_counter=1 reason=CONTROL_CLOSED";

    #[test]
    fn complete_joined_window_returns_safe_report() {
        let mut window = C11Window::new(spec());
        window.append("relay-a", SAFE_LINE).unwrap();
        window.close("relay-a").unwrap();
        window.mark_joined("relay-a").unwrap();
        let report = window.finish(101).unwrap();
        assert_eq!(report.bytes_by_role["relay-a"], SAFE_LINE.len());
        assert_eq!(report.stage, FaultStage::Peer);
    }

    #[test]
    fn sensitive_value_failure_does_not_echo_value() {
        let secret = b"secret-token";
        let mut window = C11Window::new(spec());
        let error = window
            .append("relay-a", b"phase=ready secret-token")
            .unwrap_err();
        assert_eq!(
            error,
            ScanFailure::SensitiveValue {
                role: "relay-a".to_owned(),
                kind: SentinelKind::Credential,
            }
        );
        assert!(
            !error
                .to_string()
                .contains(std::str::from_utf8(secret).unwrap())
        );
        assert!(!format!("{error:?}").contains(std::str::from_utf8(secret).unwrap()));
    }

    #[test]
    fn every_sensitive_category_is_scanned_without_value_disclosure() {
        for (kind, value) in [
            (SentinelKind::Credential, "credential-sentinel"),
            (SentinelKind::ApplicationPayload, "payload-sentinel"),
            (SentinelKind::FilesystemPath, "/private/c11/state"),
            (
                SentinelKind::PrivateEndpoint,
                "https://private.invalid/peer",
            ),
        ] {
            let sentinel = Sentinel::new(kind, value.as_bytes()).unwrap();
            let spec = C11RunSpec::new(
                "run-sensitive",
                "source-1",
                "build-1",
                FaultStage::Write,
                RunOutcome::Failure,
                100,
                ["harness"],
                vec![sentinel],
            )
            .unwrap();
            let mut window = C11Window::new(spec);
            let error = window.append("harness", value.as_bytes()).unwrap_err();
            assert_eq!(
                error,
                ScanFailure::SensitiveValue {
                    role: "harness".to_owned(),
                    kind,
                }
            );
            assert!(!error.to_string().contains(value));
            assert!(!format!("{error:?}").contains(value));
        }
    }

    #[test]
    fn overflow_is_a_failure_even_before_close() {
        let spec = spec().with_stream_limit(4).unwrap();
        let mut window = C11Window::new(spec);
        let error = window.append("relay-a", b"12345").unwrap_err();
        assert_eq!(
            error,
            ScanFailure::CaptureOverflow {
                role: "relay-a".to_owned(),
                limit: 4,
            }
        );
    }

    #[test]
    fn adapter_wrapper_labels_do_not_establish_safe_fields() {
        let spec = C11RunSpec::new(
            "run-safe-role",
            "source-1",
            "build-1",
            FaultStage::Write,
            RunOutcome::Success,
            100,
            ["runtime", "adapter"],
            Vec::new(),
        )
        .unwrap()
        .with_required_fields([SafeField::Relay])
        .with_safe_field_roles(["runtime"])
        .unwrap();
        let mut window = C11Window::new(spec);
        window
            .append("adapter", b"route=relay-a relay=relay-a")
            .unwrap();
        window.append("runtime", b"phase=ready counter=1").unwrap();
        window.close("adapter").unwrap();
        window.close("runtime").unwrap();
        window.mark_joined("adapter").unwrap();
        window.mark_joined("runtime").unwrap();
        assert_eq!(
            window.finish(101).unwrap_err(),
            ScanFailure::MissingSafeFields {
                fields: vec![SafeField::Relay]
            }
        );
    }

    #[test]
    fn joined_cleanup_is_required() {
        let mut window = C11Window::new(spec());
        window.append("relay-a", SAFE_LINE).unwrap();
        window.close("relay-a").unwrap();
        assert_eq!(
            window.finish(101).unwrap_err(),
            ScanFailure::StreamNotJoined {
                role: "relay-a".to_owned()
            }
        );
    }

    #[test]
    fn matrix_requires_success_and_failure_for_each_fault_stage() {
        let mut bundle = C11EvidenceBundle::new(100);
        let mut window = C11Window::new(spec());
        window.append("relay-a", SAFE_LINE).unwrap();
        window.close("relay-a").unwrap();
        window.mark_joined("relay-a").unwrap();
        bundle.add(window.finish(101).unwrap()).unwrap();
        let error = bundle.finish(102).unwrap_err();
        assert_eq!(
            error,
            ScanFailure::MissingMatrixCase {
                stage: FaultStage::Redis,
                outcome: RunOutcome::Success,
            }
        );
    }
}

#[cfg(test)]
mod c17_validator_tests {
    use super::*;
    use crate::HarnessError;
    use crate::acceptance_test_support::assert_rejected;

    const SAFE_LINE: &[u8] = b"relay=relay-a tenant=tenant-a owner=owner-a route=peer-route phase=ready epoch=2 generation=3 fence=4 revocation=false owner_death=false dispatch_counter=1 reason=CONTROL_CLOSED";
    const RELAY_ONLY_LINE: &[u8] = b"relay=relay-a";

    /// Map a scanner failure through the same bounded `HarnessError` that
    /// `verify-m7-c11-diagnostics` returns, so every case proves the nonzero
    /// CLI exit path and the payload-free diagnostic rather than only the
    /// typed variant.
    fn cli_result(
        result: std::result::Result<(), ScanFailure>,
    ) -> std::result::Result<(), HarnessError> {
        result.map_err(|error| HarnessError::Process(format!("C11 diagnostics: {error}")))
    }

    fn spec_with_roles(roles: &[&str]) -> std::result::Result<C11RunSpec, ScanFailure> {
        C11RunSpec::new(
            "run-1",
            "source-1",
            "build-1",
            FaultStage::Peer,
            RunOutcome::Success,
            100,
            roles.iter().copied(),
            vec![Sentinel::new(
                SentinelKind::Credential,
                b"fixture-secret-token".to_vec(),
            )?],
        )
    }

    fn spec() -> C11RunSpec {
        spec_with_roles(&["relay-a"]).expect("valid spec")
    }

    fn report(
        stage: FaultStage,
        outcome: RunOutcome,
        source_id: &str,
        build_id: &str,
        started_utc_ms: i64,
        ended_utc_ms: i64,
        line: &[u8],
    ) -> C11ScanReport {
        let spec = C11RunSpec::new(
            format!("run-{}-{}", stage.label(), outcome.label()),
            source_id,
            build_id,
            stage,
            outcome,
            started_utc_ms,
            ["relay-a"],
            Vec::new(),
        )
        .expect("valid report spec")
        .with_required_fields([SafeField::Relay]);
        let mut window = C11Window::new(spec);
        window.append("relay-a", line).expect("append");
        window.close("relay-a").expect("close");
        window.mark_joined("relay-a").expect("join");
        window.finish(ended_utc_ms).expect("finish")
    }

    fn complete_bundle() -> C11EvidenceBundle {
        let mut bundle = C11EvidenceBundle::new(100);
        for stage in FaultStage::ALL {
            for outcome in RunOutcome::ALL {
                bundle
                    .add(report(
                        stage, outcome, "source-1", "build-1", 100, 101, SAFE_LINE,
                    ))
                    .expect("add");
            }
        }
        bundle
    }

    /// A relay snapshot document whose peer fault table carries exactly the
    /// given tuples, in the relay's own serialized shape.
    fn peer_fault_snapshot(tuples: &[(&str, &str, &str)]) -> String {
        let mut recent = Vec::new();
        let mut last_by_stage = BTreeMap::new();
        let mut stage_counts: BTreeMap<&str, u64> = BTreeMap::new();
        let mut cause_counts: BTreeMap<&str, u64> = BTreeMap::new();
        let mut ingress = 0_u64;
        let mut owner = 0_u64;
        for (index, (role, stage, cause)) in tuples.iter().enumerate() {
            let event = format!(
                "{{\"sequence\":{seq},\"observed_at_ms\":{seq},\"role\":\"{role}\",\"stage\":\"{stage}\",\"cause\":\"{cause}\",\"tenant_id\":\"00000000-0000-0000-0000-000000000001\",\"device_id\":\"00000000-0000-0000-0000-000000000002\",\"session_id\":\"session-7\",\"owner_epoch\":9,\"owner_node_id\":\"relay-b\",\"service_id\":\"00000000-0000-0000-0000-000000000003\",\"request_id\":\"request-1\"}}",
                seq = index + 1
            );
            recent.push(event.clone());
            last_by_stage.insert(*stage, event);
            *stage_counts.entry(stage).or_default() += 1;
            *cause_counts.entry(cause).or_default() += 1;
            match *role {
                "ingress" => ingress += 1,
                _ => owner += 1,
            }
        }
        let map = |counts: &BTreeMap<&str, u64>| {
            counts
                .iter()
                .map(|(key, count)| format!("\"{key}\":{count}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        format!(
            // The closure rings are present and empty: these fixtures exercise
            // the fault vocabulary, and an empty closure ring is the shape a
            // relay reports when no task body has ended yet.  They are spelled
            // out rather than omitted because the scan requires the table's
            // keys to match the relay schema exactly.
            "{{\"lifetime_application_dispatches\":1,\"peer_fault_diagnostics\":{{\"fault_count\":{},\"ingress_count\":{ingress},\"owner_count\":{owner},\"stage_counts\":{{{}}},\"cause_counts\":{{{}}},\"last_by_stage\":{{{}}},\"recent\":[{}],\"closure_stage_counts\":{{}},\"closure_cause_counts\":{{}},\"closures\":[]}},\"sessions\":[]}}",
            tuples.len(),
            map(&stage_counts),
            map(&cause_counts),
            last_by_stage
                .iter()
                .map(|(stage, event)| format!("\"{stage}\":{event}"))
                .collect::<Vec<_>>()
                .join(","),
            recent.join(","),
        )
    }

    /// Finish a window whose only relay snapshot role holds `snapshot`.
    fn relay_snapshot_window(
        required: &[(&str, &str, &str)],
        snapshot: &str,
    ) -> std::result::Result<(), ScanFailure> {
        let spec = spec_with_roles(&["snapshot-relay-relay-a"])?
            .with_required_fields(std::iter::empty::<SafeField>())
            .with_required_peer_faults(required)?;
        let mut window = C11Window::new(spec);
        window.append("snapshot-relay-relay-a", snapshot.as_bytes())?;
        window.close("snapshot-relay-relay-a")?;
        window.mark_joined("snapshot-relay-relay-a")?;
        window.finish(101).map(|_| ())
    }

    #[test]
    fn relay_snapshot_stage_alternatives_accept_either_declared_stage() {
        let required = [(
            "ingress",
            "stream_permit_checkout|h3_dispatch",
            "transport_goaway",
        )];
        for stage in ["stream_permit_checkout", "h3_dispatch"] {
            relay_snapshot_window(
                &required,
                &peer_fault_snapshot(&[("ingress", stage, "transport_goaway")]),
            )
            .unwrap_or_else(|failure| panic!("{stage} should satisfy the requirement: {failure}"));
        }
    }

    /// A dial that races an empty pin set is the normal shape of the
    /// `verify-m3-mcp-isolation` flake recorded on M7-C86, so the scanner must
    /// accept that cause on a real capture, not merely agree with the relay's
    /// list.  Nobody has observed it inside a capture window, so this drives
    /// the acceptance path directly.
    #[test]
    fn a_snapshot_carrying_an_unavailable_pin_dial_is_accepted() {
        let spec = spec_with_roles(&["snapshot-relay-relay-a"])
            .expect("spec")
            .with_required_fields(std::iter::empty::<SafeField>())
            .with_required_peer_faults(&[("ingress", "pool_connect", "transport_pins_unavailable")])
            .expect("tuples");
        let mut window = C11Window::new(spec);
        window
            .append(
                "snapshot-relay-relay-a",
                peer_fault_snapshot(&[("ingress", "pool_connect", "transport_pins_unavailable")])
                    .as_bytes(),
            )
            .expect("the scanner accepts a pins-unavailable dial");
        window.close("snapshot-relay-relay-a").expect("close");
        window.mark_joined("snapshot-relay-relay-a").expect("join");
        let report = window.finish(101).expect("finish");
        assert!(
            report.peer_faults_present.contains(
                &PeerFaultTuple::new("ingress", "pool_connect", "transport_pins_unavailable")
                    .unwrap()
            ),
            "the cause is counted, not merely tolerated"
        );
    }

    #[test]
    fn relay_snapshot_tuples_satisfy_exact_requirements_and_are_reported() {
        let spec = spec_with_roles(&["snapshot-relay-relay-a", "snapshot-relay-relay-b"])
            .expect("spec")
            .with_required_fields(std::iter::empty::<SafeField>())
            .with_required_peer_faults(&[
                ("ingress", "lease", "owner_not_ready"),
                ("owner", "body", "membership_expired"),
            ])
            .expect("tuples");
        let mut window = C11Window::new(spec);
        window
            .append(
                "snapshot-relay-relay-a",
                peer_fault_snapshot(&[("ingress", "lease", "owner_not_ready")]).as_bytes(),
            )
            .expect("append a");
        // An empty table on a relay that saw no fault is valid.
        window
            .append(
                "snapshot-relay-relay-b",
                peer_fault_snapshot(&[]).as_bytes(),
            )
            .expect("append b empty");
        window
            .append(
                "snapshot-relay-relay-b",
                peer_fault_snapshot(&[("owner", "body", "membership_expired")]).as_bytes(),
            )
            .expect("append b second frame");
        for role in ["snapshot-relay-relay-a", "snapshot-relay-relay-b"] {
            window.close(role).expect("close");
            window.mark_joined(role).expect("join");
        }
        let report = window.finish(101).expect("finish");
        assert_eq!(report.peer_faults_present.len(), 2);
        assert!(
            report
                .peer_faults_present
                .contains(&PeerFaultTuple::new("ingress", "lease", "owner_not_ready").unwrap())
        );
        assert!(
            report
                .peer_faults_present
                .contains(&PeerFaultTuple::new("owner", "body", "membership_expired").unwrap())
        );
    }

    #[test]
    fn complete_matrix_returns_a_bounded_report() {
        let report = complete_bundle().finish(200).expect("complete matrix");
        assert_eq!(report.runs, 8);
        assert_eq!(report.safe_field_count, SafeField::ALL.len());
        assert_eq!(report.captured_streams, 8);
        assert_eq!(report.captured_bytes, SAFE_LINE.len() * 8);
        assert_eq!(report.source_id, "source-1");
        assert_eq!(report.build_id, "build-1");
        assert_eq!(report.peer_fault_tuples, 0);
    }

    #[test]
    fn every_c11_window_spec_and_matrix_failure_reaches_the_shared_exit_path() {
        type Case = (
            &'static str,
            &'static str,
            fn() -> std::result::Result<(), ScanFailure>,
        );
        let cases: &[Case] = &[
            ("unexpected_stream", "unexpected stream role", || {
                C11Window::new(spec()).append("relay-z", SAFE_LINE)
            }),
            ("append_after_close", "append after close", || {
                let mut window = C11Window::new(spec());
                window.append("relay-a", SAFE_LINE)?;
                window.close("relay-a")?;
                window.append("relay-a", SAFE_LINE)
            }),
            ("capture_overflow", "capture overflow", || {
                let mut window = C11Window::new(spec().with_stream_limit(4)?);
                window.append("relay-a", b"12345")
            }),
            ("sensitive_value", "sensitive credential value", || {
                C11Window::new(spec()).append("relay-a", b"phase=ready fixture-secret-token")
            }),
            ("duplicate_close", "duplicate close", || {
                let mut window = C11Window::new(spec());
                window.append("relay-a", SAFE_LINE)?;
                window.close("relay-a")?;
                window.close("relay-a")
            }),
            ("joined_before_close", "join before close", || {
                let mut window = C11Window::new(spec());
                window.append("relay-a", SAFE_LINE)?;
                window.mark_joined("relay-a")
            }),
            ("stream_not_closed", "stream not closed", || {
                let mut window = C11Window::new(spec());
                window.append("relay-a", SAFE_LINE)?;
                window.finish(101).map(|_| ())
            }),
            ("stream_not_joined", "stream not joined", || {
                let mut window = C11Window::new(spec());
                window.append("relay-a", SAFE_LINE)?;
                window.close("relay-a")?;
                window.finish(101).map(|_| ())
            }),
            ("missing_stream", "missing expected stream: relay-b", || {
                let mut window = C11Window::new(spec_with_roles(&["relay-a", "relay-b"])?);
                window.append("relay-a", SAFE_LINE)?;
                window.close("relay-a")?;
                window.mark_joined("relay-a")?;
                window.finish(101).map(|_| ())
            }),
            ("missing_safe_fields", "missing safe fields", || {
                let mut window = C11Window::new(spec());
                window.append("relay-a", RELAY_ONLY_LINE)?;
                window.close("relay-a")?;
                window.mark_joined("relay-a")?;
                window.finish(101).map(|_| ())
            }),
            ("invalid_window", "invalid diagnostic window", || {
                let mut window = C11Window::new(spec());
                window.append("relay-a", SAFE_LINE)?;
                window.close("relay-a")?;
                window.mark_joined("relay-a")?;
                window.finish(99).map(|_| ())
            }),
            ("invalid_run_id", "invalid bounded run_id", || {
                C11RunSpec::new(
                    "",
                    "source-1",
                    "build-1",
                    FaultStage::Peer,
                    RunOutcome::Success,
                    100,
                    ["relay-a"],
                    Vec::new(),
                )
                .map(|_| ())
            }),
            ("invalid_source_id", "invalid bounded source_id", || {
                C11RunSpec::new(
                    "run-1",
                    "source 1",
                    "build-1",
                    FaultStage::Peer,
                    RunOutcome::Success,
                    100,
                    ["relay-a"],
                    Vec::new(),
                )
                .map(|_| ())
            }),
            ("invalid_build_id", "invalid bounded build_id", || {
                C11RunSpec::new(
                    "run-1",
                    "source-1",
                    "b".repeat(MAX_TOKEN_BYTES + 1),
                    FaultStage::Peer,
                    RunOutcome::Success,
                    100,
                    ["relay-a"],
                    Vec::new(),
                )
                .map(|_| ())
            }),
            ("invalid_stream_role", "invalid bounded stream_role", || {
                spec_with_roles(&["relay/a"]).map(|_| ())
            }),
            (
                "no_expected_streams",
                "no expected diagnostic streams",
                || spec_with_roles(&[]).map(|_| ()),
            ),
            (
                "invalid_sentinel_empty",
                "invalid credential sentinel",
                || Sentinel::new(SentinelKind::Credential, Vec::new()).map(|_| ()),
            ),
            (
                "invalid_sentinel_too_long",
                "invalid application_payload sentinel",
                || {
                    Sentinel::new(
                        SentinelKind::ApplicationPayload,
                        vec![b'x'; MAX_SENTINEL_BYTES + 1],
                    )
                    .map(|_| ())
                },
            ),
            (
                "invalid_stream_limit",
                "invalid stream capture limit",
                || spec().with_stream_limit(0).map(|_| ()),
            ),
            (
                "safe_field_role_not_expected",
                "safe-field role was not an expected stream",
                || spec().with_safe_field_roles(["relay-z"]).map(|_| ()),
            ),
            (
                "invalid_safe_field_role",
                "invalid bounded safe_field_role",
                || spec().with_safe_field_roles([""]).map(|_| ()),
            ),
            (
                "run_outside_matrix_start",
                "run outside matrix window",
                || {
                    C11EvidenceBundle::new(100).add(report(
                        FaultStage::Peer,
                        RunOutcome::Success,
                        "source-1",
                        "build-1",
                        99,
                        101,
                        SAFE_LINE,
                    ))
                },
            ),
            (
                "run_outside_matrix_end",
                "run outside matrix window: matrix-end",
                || complete_bundle().finish(100).map(|_| ()),
            ),
            (
                "duplicate_matrix_case",
                "duplicate peer success matrix case",
                || {
                    let mut bundle = C11EvidenceBundle::new(100);
                    bundle.add(report(
                        FaultStage::Peer,
                        RunOutcome::Success,
                        "source-1",
                        "build-1",
                        100,
                        101,
                        SAFE_LINE,
                    ))?;
                    bundle.add(report(
                        FaultStage::Peer,
                        RunOutcome::Success,
                        "source-1",
                        "build-1",
                        100,
                        101,
                        SAFE_LINE,
                    ))
                },
            ),
            (
                "missing_matrix_case",
                "missing redis success matrix case",
                || {
                    let mut bundle = C11EvidenceBundle::new(100);
                    bundle.add(report(
                        FaultStage::Peer,
                        RunOutcome::Success,
                        "source-1",
                        "build-1",
                        100,
                        101,
                        SAFE_LINE,
                    ))?;
                    bundle.finish(200).map(|_| ())
                },
            ),
            (
                "matrix_missing_safe_fields",
                "missing safe fields: tenant",
                || {
                    let mut bundle = C11EvidenceBundle::new(100);
                    for stage in FaultStage::ALL {
                        for outcome in RunOutcome::ALL {
                            bundle.add(report(
                                stage,
                                outcome,
                                "source-1",
                                "build-1",
                                100,
                                101,
                                RELAY_ONLY_LINE,
                            ))?;
                        }
                    }
                    bundle.finish(200).map(|_| ())
                },
            ),
            (
                "matrix_mixed_source_build",
                "mixed source/build identities",
                || {
                    let mut bundle = C11EvidenceBundle::new(100);
                    for stage in FaultStage::ALL {
                        for outcome in RunOutcome::ALL {
                            let source_id =
                                if stage == FaultStage::Write && outcome == RunOutcome::Failure {
                                    "source-2"
                                } else {
                                    "source-1"
                                };
                            bundle.add(report(
                                stage, outcome, source_id, "build-1", 100, 101, SAFE_LINE,
                            ))?;
                        }
                    }
                    bundle.finish(200).map(|_| ())
                },
            ),
            ("matrix_invalid_window", "invalid diagnostic window", || {
                C11EvidenceBundle::new(100).finish(99).map(|_| ())
            }),
            (
                "peer_fault_missing_required_tuple",
                "missing peer fault tuple: ingress/pool_connect/transport_timeout",
                || {
                    relay_snapshot_window(
                        &[("ingress", "pool_connect", "transport_timeout")],
                        &peer_fault_snapshot(&[("ingress", "lease", "owner_not_ready")]),
                    )
                },
            ),
            (
                "peer_fault_stage_alternatives_still_require_the_exact_cause",
                "missing peer fault tuple: ingress/stream_permit_checkout|h3_dispatch/transport_goaway",
                || {
                    relay_snapshot_window(
                        &[(
                            "ingress",
                            "stream_permit_checkout|h3_dispatch",
                            "transport_goaway",
                        )],
                        &peer_fault_snapshot(&[("ingress", "h3_dispatch", "transport_h3")]),
                    )
                },
            ),
            (
                "peer_fault_stage_alternative_outside_vocabulary",
                "invalid peer fault table: stage outside the closed vocabulary",
                || {
                    spec()
                        .with_required_peer_faults(&[(
                            "ingress",
                            "h3_dispatch|handshake",
                            "transport_goaway",
                        )])
                        .map(|_| ())
                },
            ),
            (
                "peer_fault_role_mismatch_is_not_the_required_tuple",
                "missing peer fault tuple: owner/lease/membership",
                || {
                    relay_snapshot_window(
                        &[("owner", "lease", "membership")],
                        &peer_fault_snapshot(&[("ingress", "lease", "membership")]),
                    )
                },
            ),
            (
                "peer_fault_cause_outside_vocabulary",
                "invalid peer fault table: cause outside the closed vocabulary",
                || {
                    relay_snapshot_window(
                        &[],
                        &peer_fault_snapshot(&[("ingress", "lease", "owner_not_ready")]).replace(
                            "\"cause\":\"owner_not_ready\"",
                            "\"cause\":\"owner_not_ready_detail\"",
                        ),
                    )
                },
            ),
            (
                "peer_fault_stage_outside_vocabulary",
                "invalid peer fault table: stage_counts key outside the closed vocabulary",
                || {
                    relay_snapshot_window(
                        &[],
                        &peer_fault_snapshot(&[("ingress", "lease", "owner_not_ready")])
                            .replace("\"lease\"", "\"lease_text\""),
                    )
                },
            ),
            (
                "peer_fault_extra_event_field_is_rejected",
                "invalid peer fault table: event keys differ from the relay schema",
                || {
                    relay_snapshot_window(
                        &[],
                        &peer_fault_snapshot(&[("ingress", "lease", "owner_not_ready")])
                            .replace("\"request_id\":", "\"payload\":\"x\",\"request_id\":"),
                    )
                },
            ),
            (
                "peer_fault_unbounded_request_id_is_rejected",
                "invalid peer fault table: request_id was not a bounded identifier",
                || {
                    relay_snapshot_window(
                        &[],
                        &peer_fault_snapshot(&[("ingress", "lease", "owner_not_ready")])
                            .replace("request-1", "Bearer secret/token"),
                    )
                },
            ),
            (
                "peer_fault_counter_mismatch_is_rejected",
                "invalid peer fault table: role counters do not sum to fault_count",
                || {
                    relay_snapshot_window(
                        &[],
                        &peer_fault_snapshot(&[("ingress", "lease", "owner_not_ready")])
                            .replace("\"ingress_count\":1", "\"ingress_count\":2"),
                    )
                },
            ),
            (
                "peer_fault_table_missing_from_relay_snapshot",
                "invalid peer fault table: relay snapshot omitted peer_fault_diagnostics",
                || relay_snapshot_window(&[], "{\"sessions\":[]}"),
            ),
            (
                "peer_fault_relay_snapshot_not_json",
                "invalid peer fault table: relay snapshot frame was not a JSON document",
                || relay_snapshot_window(&[], "relay=relay-a"),
            ),
            (
                "peer_fault_required_tuple_outside_vocabulary",
                "invalid peer fault table: stage outside the closed vocabulary",
                || {
                    spec()
                        .with_required_peer_faults(&[("ingress", "handshake", "closed")])
                        .map(|_| ())
                },
            ),
        ];
        for &(name, fragment, run) in cases {
            let result = cli_result(run());
            assert!(
                result.is_err(),
                "{name}: C11 scanner failure unexpectedly passed"
            );
            assert_rejected(result, fragment);
        }
    }
}

#[cfg(test)]
mod peer_fault_vocabulary_tests {
    use super::PEER_FAULT_CAUSES;
    use tunnel_relay::peer_fault_diagnostics::PeerFaultCause;

    /// The scanner refuses any snapshot carrying a cause outside its copy of
    /// the vocabulary, so a relay that gains a cause without this list gaining
    /// it makes `verify-m7-c11-diagnostics` and `verify-m7-og02-correlation`
    /// fail on a perfectly valid capture.  That is exactly what happened when
    /// `transport_pins_unavailable` was added on the relay side only.
    #[test]
    fn harness_peer_fault_causes_match_the_relay_vocabulary() {
        let mut relay: Vec<&str> = PeerFaultCause::ALL.iter().map(|c| c.as_str()).collect();
        let mut scanner: Vec<&str> = PEER_FAULT_CAUSES.to_vec();
        relay.sort_unstable();
        scanner.sort_unstable();
        assert_eq!(
            relay, scanner,
            "the C11 scanner's cause vocabulary has drifted from the relay's"
        );
    }
}
