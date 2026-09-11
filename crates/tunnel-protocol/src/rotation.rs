//! Pure data-socket rotation state machine.
//!
//! The machine in this module owns no sockets and performs no I/O.  A runtime
//! supplies monotonic millisecond ticks and translates the returned phase and
//! actions into control messages and socket operations.  Logical stream
//! sequence counters live in [`crate::sequence`]; this module only freezes and
//! validates their immutable handover fences.
//!
//! A rotation attempt consumes a generation as soon as it is prepared.  The
//! generation is never reused, including after an abort.  The overlap deadline
//! is absolute and is measured from the candidate dial start; no phase or
//! acknowledgement can extend it.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::rotation_control::{
    DrainProof, DrainSet, FenceSnapshot, RotationAttemptIdentity, StreamRoster,
};
use crate::sequence::Direction;

/// Monotonic clock unit used by the pure machine.
pub type RotationTime = u64;

/// Default interval between scheduled rotations (five minutes).
pub const DEFAULT_ROTATION_INTERVAL_MS: RotationTime = 300_000;
/// Default candidate attachment deadline.
pub const DEFAULT_HANDSHAKE_TIMEOUT_MS: RotationTime = 10_000;
/// Default total overlap deadline.
pub const DEFAULT_OVERLAP_TIMEOUT_MS: RotationTime = 30_000;
/// Default absolute budget for one retained-state recovery episode.
pub const DEFAULT_RECOVERY_TIMEOUT_MS: RotationTime = 30_000;
/// Maximum negotiated absolute budget for one retained-state recovery episode.
pub const MAX_RECOVERY_TIMEOUT_MS: RotationTime = DEFAULT_RECOVERY_TIMEOUT_MS;
/// Hard maximum for a drain roster.
pub const MAX_ROSTER_ENTRIES: usize = 128;
/// One control socket plus two data sockets is the maximum transition shape.
pub const MAX_DATA_SOCKETS: u8 = 2;
/// The control socket is present in every non-closed state.
pub const CONTROL_SOCKETS: u8 = 1;
/// Maximum total connector sockets during a transition.
pub const MAX_TOTAL_SOCKETS: u8 = CONTROL_SOCKETS + MAX_DATA_SOCKETS;
/// Bounded connection-ID tombstones retained for this authenticated session.
///
/// A physical connection ID is single-use for the lifetime of the session so
/// delayed close evidence can never target a later carrier.  Once this bound
/// is exhausted the caller must establish a fresh session/epoch rather than
/// evicting tombstones and risking ID reuse.
pub const MAX_CONNECTION_ID_HISTORY: usize = 256;
/// Maximum number of replacement candidates in one retained-state episode.
pub const MAX_RECOVERY_ATTEMPTS: u8 = 3;
/// Fixed gaps between successive physical candidates after an unexpected
/// candidate loss.  The first recovery attempt starts immediately; only the
/// second and third attempts are delayed.  These are protocol policy values,
/// rather than client-side timers, so both peers observe one coordinator-owned
/// schedule and the episode's absolute deadline remains authoritative.
pub const RECOVERY_RETRY_DELAYS_MS: [RotationTime; 2] = [100, 200];

/// Return the retry delay after a failed recovery attempt.
///
/// `completed_attempt_no` is the attempt that just lost its candidate.  A
/// completed first attempt gates attempt two by 100 ms and a completed second
/// attempt gates attempt three by 200 ms.  There is no delay after the final
/// bounded attempt because the caller must fail closed.
#[must_use]
pub const fn recovery_retry_delay_ms(completed_attempt_no: u64) -> Option<RotationTime> {
    match completed_attempt_no {
        1 => Some(RECOVERY_RETRY_DELAYS_MS[0]),
        2 => Some(RECOVERY_RETRY_DELAYS_MS[1]),
        _ => None,
    }
}

/// Configurable timing and roster policy for a rotation machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RotationConfig {
    /// The normal timer interval.  Explicit operator requests may occur sooner.
    pub rotation_interval_ms: RotationTime,
    /// Maximum time from candidate dial start to candidate readiness.
    pub handshake_timeout_ms: RotationTime,
    /// Absolute overlap budget from candidate dial start through retirement.
    pub overlap_timeout_ms: RotationTime,
    /// Absolute budget for one recovery episode, shared by all candidates.
    pub recovery_timeout_ms: RotationTime,
    /// Maximum number of stream IDs in one immutable snapshot.
    pub max_roster_entries: usize,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            rotation_interval_ms: DEFAULT_ROTATION_INTERVAL_MS,
            handshake_timeout_ms: DEFAULT_HANDSHAKE_TIMEOUT_MS,
            overlap_timeout_ms: DEFAULT_OVERLAP_TIMEOUT_MS,
            recovery_timeout_ms: DEFAULT_RECOVERY_TIMEOUT_MS,
            max_roster_entries: MAX_ROSTER_ENTRIES,
        }
    }
}

impl RotationConfig {
    /// Construct a policy with the protocol defaults for roster size.
    pub fn new(
        rotation_interval_ms: RotationTime,
        handshake_timeout_ms: RotationTime,
        overlap_timeout_ms: RotationTime,
    ) -> Result<Self, RotationError> {
        let config = Self {
            rotation_interval_ms,
            handshake_timeout_ms,
            overlap_timeout_ms,
            ..Self::default()
        };
        config.validate()?;
        Ok(config)
    }

    /// Validate timing and hard-bound invariants.
    pub fn validate(&self) -> Result<(), RotationError> {
        if self.handshake_timeout_ms == 0
            || self.overlap_timeout_ms == 0
            || self.recovery_timeout_ms == 0
            || self.rotation_interval_ms == 0
        {
            return Err(RotationError::InvalidConfig(
                "rotation, handshake, overlap, and recovery durations must be nonzero",
            ));
        }
        if self.handshake_timeout_ms >= self.overlap_timeout_ms {
            return Err(RotationError::InvalidConfig(
                "handshake timeout must be shorter than overlap timeout",
            ));
        }
        if self.overlap_timeout_ms >= self.rotation_interval_ms {
            return Err(RotationError::InvalidConfig(
                "overlap timeout must be shorter than rotation interval",
            ));
        }
        if self.recovery_timeout_ms > MAX_RECOVERY_TIMEOUT_MS {
            return Err(RotationError::InvalidConfig(
                "recovery timeout exceeds the 30-second protocol bound",
            ));
        }
        if self.max_roster_entries == 0 || self.max_roster_entries > MAX_ROSTER_ENTRIES {
            return Err(RotationError::InvalidConfig(
                "roster size exceeds the protocol hard bound",
            ));
        }
        Ok(())
    }
}

/// Explicit lifecycle phase.  There is no implicit transition from a timeout
/// back to the old generation after a commit decision has been sent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotationPhase {
    Active,
    Preparing,
    Quiescing,
    Draining,
    Committing,
    Retiring,
    Aborting,
    Recovering,
    Closed,
}

/// Which endpoint supplied a closure acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotationSide {
    Owner,
    Connector,
}

/// Reason retained in diagnostics when the machine enters recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryReason {
    Deadline,
    OldTransportLost,
    CandidateTransportLost,
    ControlLost,
    CommitUncertain,
    ReconciliationConflict,
    MissingRetainedBytes,
}

/// A bounded closure evidence record for one physical data connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosureEvidence {
    /// The connection whose closure is being attested.
    pub connection_id: String,
    /// Local close/transport teardown was observed.
    pub local_closed: bool,
    /// The peer's close acknowledgement or equivalent teardown was observed.
    pub peer_closed: bool,
}

impl ClosureEvidence {
    /// Construct positive closure evidence.
    #[must_use]
    pub fn closed(connection_id: impl Into<String>) -> Self {
        Self {
            connection_id: connection_id.into(),
            local_closed: true,
            peer_closed: true,
        }
    }

    /// Return whether this record proves this endpoint released its local
    /// transport resources.  `peer_closed` is diagnostic evidence for the
    /// WebSocket close handshake; a failed peer may never send that handshake.
    /// Callers that need bilateral retirement still submit one local record
    /// for each [`RotationSide`].
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.local_closed
    }
}

/// One bounded logical replay range.  Ranges carry original sequence numbers;
/// replay does not allocate new logical credit or dispatch a second operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayRange {
    pub stream_id: u64,
    pub direction: Direction,
    pub first_sequence: u64,
    pub last_sequence: u64,
}

/// A stream-specific recovery failure.  Side-effecting operations can be
/// surfaced as unknown by the runtime when the retained transport prefix is
/// not sufficient to reconcile them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryFailure {
    pub stream_id: u64,
    pub direction: Direction,
    pub outcome_unknown: bool,
    pub reason: RecoveryReason,
}

/// Bounded result of retained-state reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryReport {
    pub replay: Vec<ReplayRange>,
    pub failures: Vec<RecoveryFailure>,
}

impl RecoveryReport {
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.failures.is_empty()
    }
}

/// A recovery verdict produced after the sequence agent reconciles one
/// stream's two [`crate::sequence::DirectionSnapshot`] values.  Rotation does
/// not re-derive cursor, terminal, credit, or retained-history rules from
/// this value; it only verifies the bounded roster/direction shape before
/// activating the replacement carrier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedRecovery {
    stream_id: u64,
    replay: Vec<ReplayRange>,
    failures: Vec<RecoveryFailure>,
    ready: bool,
}

impl ValidatedRecovery {
    /// Convert a successful sequence-agent plan into a payload-free verdict.
    /// The sequence module has already checked terminal, credit, ACK and
    /// retained-history invariants before this conversion.
    pub fn from_sequence_plan(plan: &crate::sequence::RecoveryPlan) -> Result<Self, RotationError> {
        let stream_id = plan.stream_id();
        if stream_id == 0 {
            return Err(RotationError::InvalidStreamId);
        }
        let mut replay = Vec::new();
        for direction in [Direction::RelayToConnector, Direction::ConnectorToRelay] {
            let frames = plan.replay(direction);
            let Some(first) = frames.first() else {
                continue;
            };
            let Some(last) = frames.last() else {
                continue;
            };
            let first_sequence = first.sequence;
            let last_sequence = last.sequence;
            if first_sequence == 0 || first_sequence > last_sequence {
                return Err(RotationError::InvalidRecoveryVerdict);
            }
            let expected_len = last_sequence
                .checked_sub(first_sequence)
                .and_then(|span| span.checked_add(1))
                .ok_or(RotationError::InvalidRecoveryVerdict)?;
            if expected_len != frames.len() as u64
                || frames
                    .windows(2)
                    .any(|pair| pair[1].sequence != pair[0].sequence.saturating_add(1))
            {
                return Err(RotationError::InvalidRecoveryVerdict);
            }
            replay.push(ReplayRange {
                stream_id,
                direction,
                first_sequence,
                last_sequence,
            });
        }
        let peer_replay_pending = [Direction::RelayToConnector, Direction::ConnectorToRelay]
            .into_iter()
            .any(|direction| plan.peer_missing(direction).is_some());
        let ready = replay.is_empty() && !peer_replay_pending;
        Ok(Self {
            stream_id,
            replay,
            failures: Vec::new(),
            ready,
        })
    }

    /// Stream ID covered by this validated verdict.
    #[must_use]
    pub const fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// Replay ranges that must be sent before this stream is resume-ready.
    #[must_use]
    pub fn replay_ranges(&self) -> &[ReplayRange] {
        &self.replay
    }

    /// Whether both sequence agents have completed their replay exchange.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        self.ready
    }

    /// Construct a terminal stream failure after the sequence agent cannot
    /// reconcile one stream without making an unsafe replay decision.  A
    /// stream is failed in both directions together; rotation must never
    /// resume half of an inseparable logical stream.
    #[must_use]
    pub fn failed(stream_id: u64, reason: RecoveryReason, outcome_unknown: bool) -> Self {
        Self {
            stream_id,
            replay: Vec::new(),
            failures: [Direction::RelayToConnector, Direction::ConnectorToRelay]
                .into_iter()
                .map(|direction| RecoveryFailure {
                    stream_id,
                    direction,
                    outcome_unknown,
                    reason,
                })
                .collect(),
            ready: true,
        }
    }

    /// Convert a typed sequence-agent failure into an explicit scoped
    /// recovery verdict.  The sequence state remains authoritative; this
    /// adapter deliberately does not attempt a second cursor validation.
    #[must_use]
    pub fn from_sequence_error(stream_id: u64, error: &crate::sequence::SequenceError) -> Self {
        let reason = match error {
            crate::sequence::SequenceError::MissingHistory { .. }
            | crate::sequence::SequenceError::ReplayBufferFull { .. } => {
                RecoveryReason::MissingRetainedBytes
            }
            _ => RecoveryReason::ReconciliationConflict,
        };
        Self::failed(stream_id, reason, true)
    }
}

/// A read-only view useful to runtime diagnostics and deterministic tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationStatus {
    pub phase: RotationPhase,
    pub active_generation: u64,
    pub active_connection_id: String,
    pub attempt: Option<RotationAttemptIdentity>,
    pub started_at_ms: Option<RotationTime>,
    pub deadline_ms: Option<RotationTime>,
    pub candidate_ready: bool,
    pub writers_frozen: [bool; 2],
    pub drain_proofs: [bool; 2],
    pub commit_sent: bool,
    pub commit_accepted: bool,
    pub old_socket_closed: [bool; 2],
    pub candidate_socket_closed: [bool; 2],
    pub recovery_reason: Option<RecoveryReason>,
    pub deadline_forced_retirement: bool,
    pub socket_count: u8,
}

/// Results for repeated rotation requests.  Requests for the active attempt
/// coalesce; no second candidate is allocated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrepareResult {
    Started,
    Coalesced,
}

#[derive(Clone, Debug)]
struct AttemptState {
    identity: RotationAttemptIdentity,
    started_at_ms: RotationTime,
    handshake_deadline_ms: RotationTime,
    overlap_deadline_ms: RotationTime,
    /// True only for an attempt allocated by a validated RECOVERY_BEGIN.
    is_recovery_attempt: bool,
    /// True while this recovery attempt's candidate is physically reserved.
    recovery_socket_reserved: bool,
    /// A recovery attempt may reserve its candidate at most once.  A later
    /// retry creates a new attempt identity instead of reusing this carrier.
    recovery_socket_ever_reserved: bool,
    candidate_ready: bool,
    roster: Option<StreamRoster>,
    frozen: [Option<FenceSnapshot>; 2],
    drained: [Option<DrainProof>; 2],
    commit_sent: bool,
    commit_accepted: bool,
    retire_sent: bool,
    old_socket_closed: [bool; 2],
    candidate_socket_closed: [bool; 2],
    recovery_reason: Option<RecoveryReason>,
}

impl AttemptState {
    fn new(
        identity: RotationAttemptIdentity,
        started_at_ms: RotationTime,
        config: RotationConfig,
    ) -> Result<Self, RotationError> {
        Self::new_with_deadline(identity, started_at_ms, config, None)
    }

    fn new_with_deadline(
        identity: RotationAttemptIdentity,
        started_at_ms: RotationTime,
        config: RotationConfig,
        deadline_cap_ms: Option<RotationTime>,
    ) -> Result<Self, RotationError> {
        let handshake_deadline_ms = started_at_ms
            .checked_add(config.handshake_timeout_ms)
            .ok_or(RotationError::DeadlineOverflow)?;
        let proposed_overlap_deadline_ms = started_at_ms
            .checked_add(config.overlap_timeout_ms)
            .ok_or(RotationError::DeadlineOverflow)?;
        let (handshake_deadline_ms, overlap_deadline_ms) = deadline_cap_ms.map_or(
            (handshake_deadline_ms, proposed_overlap_deadline_ms),
            |cap| {
                (
                    handshake_deadline_ms.min(cap),
                    proposed_overlap_deadline_ms.min(cap),
                )
            },
        );
        if overlap_deadline_ms <= started_at_ms {
            return Err(RotationError::DeadlineExpired {
                now: started_at_ms,
                deadline: overlap_deadline_ms,
            });
        }
        Ok(Self {
            identity,
            started_at_ms,
            handshake_deadline_ms,
            overlap_deadline_ms,
            is_recovery_attempt: false,
            recovery_socket_reserved: false,
            recovery_socket_ever_reserved: false,
            candidate_ready: false,
            roster: None,
            frozen: [None, None],
            drained: [None, None],
            commit_sent: false,
            commit_accepted: false,
            retire_sent: false,
            old_socket_closed: [false, false],
            candidate_socket_closed: [false, false],
            recovery_reason: None,
        })
    }

    fn direction_index(direction: Direction) -> usize {
        match direction {
            Direction::RelayToConnector => 0,
            Direction::ConnectorToRelay => 1,
        }
    }
}

/// Pure state machine for one authenticated logical session's data carrier.
#[derive(Clone, Debug)]
pub struct RotationState {
    config: RotationConfig,
    phase: RotationPhase,
    session_id: String,
    owner_id: String,
    epoch: u64,
    active_generation: u64,
    active_connection_id: String,
    /// Highest generation ever allocated by this machine.  It is retained
    /// across aborts and recovery so generation reuse is impossible.
    generation_high_watermark: u64,
    attempt: Option<AttemptState>,
    allocated_connections: BTreeSet<String>,
    used_connection_ids: BTreeSet<String>,
    /// Absolute deadline supplied by RECOVERY_BEGIN and shared by all
    /// candidates in one recovery episode.  It survives candidate closure and
    /// is cleared only after a replacement becomes active or the session is
    /// closed.
    recovery_episode_deadline: Option<RotationTime>,
    /// Number of candidate attempts consumed in the current recovery episode.
    recovery_attempts: u8,
    deadline_forced_retirement: bool,
    last_time_ms: Option<RotationTime>,
}

impl RotationState {
    /// Start in the steady-state `Active` phase.
    pub fn new(
        session_id: impl Into<String>,
        owner_id: impl Into<String>,
        epoch: u64,
        active_generation: u64,
        active_connection_id: impl Into<String>,
        config: RotationConfig,
    ) -> Result<Self, RotationError> {
        config.validate()?;
        let session_id = session_id.into();
        let owner_id = owner_id.into();
        let active_connection_id = active_connection_id.into();
        validate_identifier("session_id", &session_id)?;
        validate_identifier("owner_id", &owner_id)?;
        validate_identifier("connection_id", &active_connection_id)?;
        if epoch == 0 {
            return Err(RotationError::InvalidEpoch);
        }
        if active_generation == 0 {
            return Err(RotationError::InvalidGeneration(active_generation));
        }
        let active_connection_key = active_connection_id.clone();
        Ok(Self {
            config,
            phase: RotationPhase::Active,
            session_id,
            owner_id,
            epoch,
            active_generation,
            active_connection_id: active_connection_id.clone(),
            generation_high_watermark: active_generation,
            attempt: None,
            allocated_connections: BTreeSet::from([active_connection_key]),
            used_connection_ids: BTreeSet::from([active_connection_id.clone()]),
            recovery_episode_deadline: None,
            recovery_attempts: 0,
            deadline_forced_retirement: false,
            last_time_ms: None,
        })
    }

    #[must_use]
    pub const fn phase(&self) -> RotationPhase {
        self.phase
    }

    #[must_use]
    pub const fn active_generation(&self) -> u64 {
        self.active_generation
    }

    #[must_use]
    pub fn active_connection_id(&self) -> &str {
        &self.active_connection_id
    }

    #[must_use]
    pub const fn generation_high_watermark(&self) -> u64 {
        self.generation_high_watermark
    }

    #[must_use]
    pub const fn config(&self) -> RotationConfig {
        self.config
    }

    /// Return the current bounded status snapshot.
    #[must_use]
    pub fn status(&self) -> RotationStatus {
        let (
            attempt,
            started_at_ms,
            deadline_ms,
            candidate_ready,
            writers_frozen,
            drain_proofs,
            commit_sent,
            commit_accepted,
            old_socket_closed,
            candidate_socket_closed,
            recovery_reason,
        ) = if let Some(attempt) = &self.attempt {
            (
                Some(attempt.identity.clone()),
                Some(attempt.started_at_ms),
                Some(attempt.overlap_deadline_ms),
                attempt.candidate_ready,
                [attempt.frozen[0].is_some(), attempt.frozen[1].is_some()],
                [attempt.drained[0].is_some(), attempt.drained[1].is_some()],
                attempt.commit_sent,
                attempt.commit_accepted,
                attempt.old_socket_closed,
                attempt.candidate_socket_closed,
                attempt.recovery_reason,
            )
        } else {
            (
                None,
                None,
                None,
                false,
                [false, false],
                [false, false],
                false,
                false,
                [false, false],
                [false, false],
                None,
            )
        };
        RotationStatus {
            phase: self.phase,
            active_generation: self.active_generation,
            active_connection_id: self.active_connection_id.clone(),
            attempt,
            started_at_ms,
            deadline_ms,
            candidate_ready,
            writers_frozen,
            drain_proofs,
            commit_sent,
            commit_accepted,
            old_socket_closed,
            candidate_socket_closed,
            recovery_reason,
            deadline_forced_retirement: self.deadline_forced_retirement,
            socket_count: self.socket_count(),
        }
    }

    /// Number of live or reserved connector sockets represented by the state.
    #[must_use]
    pub fn socket_count(&self) -> u8 {
        match self.phase {
            RotationPhase::Closed => 0,
            RotationPhase::Active => CONTROL_SOCKETS + 1,
            RotationPhase::Preparing
            | RotationPhase::Quiescing
            | RotationPhase::Draining
            | RotationPhase::Committing
            | RotationPhase::Retiring
            | RotationPhase::Aborting => CONTROL_SOCKETS + 2,
            RotationPhase::Recovering => CONTROL_SOCKETS + self.allocated_connections.len() as u8,
        }
    }

    /// Begin one candidate attempt.  A repeated request for the exact active
    /// attempt returns `Coalesced`; a different request cannot allocate a
    /// second candidate.
    pub fn prepare(
        &mut self,
        identity: RotationAttemptIdentity,
        now_ms: RotationTime,
    ) -> Result<PrepareResult, RotationError> {
        self.observe_time(now_ms)?;
        self.prepare_after_observed(identity, now_ms, None)
    }

    /// Begin a normal candidate attempt with an absolute monotonic deadline
    /// cap received from the peer's PREPARE message.  The cap applies to both
    /// the handshake and overlap deadlines, and can only shorten the local
    /// policy.  A repeated request is coalesced without changing the original
    /// attempt's deadlines.
    pub fn prepare_with_deadline_cap(
        &mut self,
        identity: RotationAttemptIdentity,
        now_ms: RotationTime,
        deadline_cap_ms: RotationTime,
    ) -> Result<PrepareResult, RotationError> {
        self.observe_time(now_ms)?;
        if deadline_cap_ms <= now_ms {
            return Err(RotationError::DeadlineExpired {
                now: now_ms,
                deadline: deadline_cap_ms,
            });
        }
        self.prepare_after_observed(identity, now_ms, Some(deadline_cap_ms))
    }

    fn prepare_after_observed(
        &mut self,
        identity: RotationAttemptIdentity,
        now_ms: RotationTime,
        deadline_cap_ms: Option<RotationTime>,
    ) -> Result<PrepareResult, RotationError> {
        if self.phase != RotationPhase::Active {
            let matching_deadline = self.attempt.as_ref().and_then(|attempt| {
                (attempt.identity == identity).then_some(attempt.overlap_deadline_ms)
            });
            if let Some(deadline) = matching_deadline {
                if now_ms >= deadline {
                    self.enter_recovery_in_place(RecoveryReason::Deadline);
                    return Err(RotationError::DeadlineExpired {
                        now: now_ms,
                        deadline,
                    });
                }
                if self.phase != RotationPhase::Recovering {
                    return Ok(PrepareResult::Coalesced);
                }
            }
            return Err(RotationError::InvalidPhase {
                expected: RotationPhase::Active,
                actual: self.phase,
            });
        }
        self.validate_attempt_identity(
            &identity,
            self.active_generation,
            &self.active_connection_id,
        )?;
        if identity.new_generation <= self.generation_high_watermark {
            return Err(RotationError::GenerationNotMonotonic {
                previous: self.generation_high_watermark,
                proposed: identity.new_generation,
            });
        }
        if self.allocated_connections.len() != 1 {
            return Err(RotationError::SocketBoundExceeded);
        }
        let new_connection_id = identity.new_connection_id.clone();
        let attempt = if let Some(cap) = deadline_cap_ms {
            AttemptState::new_with_deadline(identity, now_ms, self.config, Some(cap))?
        } else {
            AttemptState::new(identity, now_ms, self.config)?
        };
        self.claim_connection_id(&new_connection_id)?;
        if !self.allocated_connections.insert(new_connection_id) {
            return Err(RotationError::ConnectionReuse);
        }
        self.generation_high_watermark = attempt.identity.new_generation;
        self.attempt = Some(attempt);
        self.phase = RotationPhase::Preparing;
        self.assert_socket_bound();
        Ok(PrepareResult::Started)
    }

    /// Explicitly named alias for runtimes that model the wire phase as
    /// `ROTATE_PREPARE`.
    pub fn begin_prepare(
        &mut self,
        identity: RotationAttemptIdentity,
        now_ms: RotationTime,
    ) -> Result<PrepareResult, RotationError> {
        self.prepare(identity, now_ms)
    }

    /// Candidate DATA_READY.  Readiness reserves the candidate but cannot
    /// activate it or admit payloads before commit.
    pub fn candidate_ready(
        &mut self,
        identity: &RotationAttemptIdentity,
        now_ms: RotationTime,
    ) -> Result<(), RotationError> {
        self.observe_time(now_ms)?;
        self.ensure_attempt(identity, RotationPhase::Preparing)?;
        let (overlap_deadline_ms, handshake_deadline_ms) = {
            let attempt = self.attempt.as_ref().expect("phase checked above");
            (attempt.overlap_deadline_ms, attempt.handshake_deadline_ms)
        };
        if now_ms >= overlap_deadline_ms {
            self.enter_recovery_in_place(RecoveryReason::Deadline);
            return Err(RotationError::DeadlineExpired {
                now: now_ms,
                deadline: overlap_deadline_ms,
            });
        }
        if now_ms >= handshake_deadline_ms {
            self.phase = RotationPhase::Aborting;
            return Err(RotationError::HandshakeDeadlineExpired {
                now: now_ms,
                deadline: handshake_deadline_ms,
            });
        }
        let attempt = self.attempt.as_mut().expect("phase checked above");
        attempt.candidate_ready = true;
        Ok(())
    }

    /// Freeze admission and install the immutable stream roster.  The roster
    /// has no sequence fences yet; each endpoint supplies one direction's
    /// immutable fences with [`Self::frozen`].
    pub fn quiesce(
        &mut self,
        identity: &RotationAttemptIdentity,
        roster: StreamRoster,
        now_ms: RotationTime,
    ) -> Result<(), RotationError> {
        self.observe_time(now_ms)?;
        self.ensure_attempt(identity, RotationPhase::Preparing)?;
        let overlap_deadline_ms = self
            .attempt
            .as_ref()
            .expect("phase checked above")
            .overlap_deadline_ms;
        if now_ms >= overlap_deadline_ms {
            self.enter_recovery_in_place(RecoveryReason::Deadline);
            return Err(RotationError::DeadlineExpired {
                now: now_ms,
                deadline: overlap_deadline_ms,
            });
        }
        let maximum = self.config.max_roster_entries;
        let attempt = self.attempt.as_mut().expect("phase checked above");
        if !attempt.candidate_ready {
            return Err(RotationError::CandidateNotReady);
        }
        validate_roster(&roster, maximum)?;
        validate_identifier("snapshot_id", &roster.snapshot_id)?;
        attempt.roster = Some(roster);
        self.phase = RotationPhase::Quiescing;
        Ok(())
    }

    /// Record one endpoint's frozen per-stream fences.  The second call must
    /// provide the opposite direction and exactly the same roster.  Once both
    /// immutable fence sets are present, the machine enters `Draining`.
    pub fn frozen(
        &mut self,
        identity: &RotationAttemptIdentity,
        fences: FenceSnapshot,
        direction: Direction,
        now_ms: RotationTime,
    ) -> Result<(), RotationError> {
        self.observe_time(now_ms)?;
        self.ensure_attempt(identity, RotationPhase::Quiescing)?;
        self.check_deadline(now_ms)?;
        validate_fence_snapshot(&fences, direction, self.config.max_roster_entries)?;
        let attempt = self.attempt.as_mut().expect("phase checked above");
        let Some(roster) = attempt.roster.as_ref() else {
            return Err(RotationError::MissingRoster);
        };
        if fences.snapshot_id != roster.snapshot_id {
            return Err(RotationError::SnapshotMismatch);
        }
        if fences
            .entries
            .iter()
            .any(|entry| entry.direction != direction)
        {
            return Err(RotationError::MixedFenceDirections);
        }
        if !fence_roster_matches(&fences, roster) {
            return Err(RotationError::RosterMismatch);
        }
        let index = AttemptState::direction_index(direction);
        if attempt.frozen[index].is_some() {
            let old = attempt.frozen[index].as_ref().expect("checked above");
            if old == &fences {
                return Ok(());
            }
            return Err(RotationError::ConflictingFrozenFence { direction });
        }
        if let Some(other) = attempt.frozen[1 - index].as_ref()
            && !same_fence_roster(other, &fences)
        {
            return Err(RotationError::RosterMismatch);
        }
        attempt.frozen[index] = Some(fences);
        if attempt.frozen[0].is_some() && attempt.frozen[1].is_some() {
            self.phase = RotationPhase::Draining;
        }
        Ok(())
    }

    /// Record a complete drain proof for one direction.  The proof must
    /// acknowledge every sequence through that direction's immutable fence;
    /// a control FROZEN marker alone can never advance this phase.
    pub fn drained(
        &mut self,
        identity: &RotationAttemptIdentity,
        proof: DrainProof,
        now_ms: RotationTime,
    ) -> Result<(), RotationError> {
        self.observe_time(now_ms)?;
        self.ensure_attempt(identity, RotationPhase::Draining)?;
        self.check_deadline(now_ms)?;
        let maximum = self.config.max_roster_entries;
        let attempt = self.attempt.as_mut().expect("phase checked above");
        let Some(roster) = attempt.roster.as_ref() else {
            return Err(RotationError::MissingRoster);
        };
        if proof.snapshot_id != roster.snapshot_id {
            return Err(RotationError::SnapshotMismatch);
        }
        validate_identifier("snapshot_id", &proof.snapshot_id)?;
        validate_identifier("fence_digest", &proof.fence_digest)?;
        let direction = proof.direction;
        let index = AttemptState::direction_index(direction);
        let Some(fences) = attempt.frozen[index].as_ref() else {
            return Err(RotationError::MissingFrozenFence { direction });
        };
        if proof.fence_digest != digest_for_snapshot(fences)? {
            return Err(RotationError::FenceDigestMismatch);
        }
        if proof.ack_cursors.len() > maximum {
            return Err(RotationError::RosterTooLarge {
                count: proof.ack_cursors.len(),
                maximum,
            });
        }
        validate_ack_cursors(fences, &proof)?;
        if let Some(old) = attempt.drained[index].as_ref() {
            if old == &proof {
                return Ok(());
            }
            return Err(RotationError::ConflictingDrainProof { direction });
        }
        attempt.drained[index] = Some(proof);
        if attempt.drained[0].is_some() && attempt.drained[1].is_some() {
            self.phase = RotationPhase::Committing;
        }
        Ok(())
    }

    /// Return the paired drain proofs once both directions have been accepted.
    /// The shared wire type is intentionally compact and contains no local
    /// timestamp or payload state.
    pub fn drain_set(&self, identity: &RotationAttemptIdentity) -> Result<DrainSet, RotationError> {
        self.ensure_attempt(identity, RotationPhase::Committing)?;
        let attempt = self.attempt.as_ref().expect("phase checked above");
        let relay_to_connector =
            attempt.drained[0]
                .clone()
                .ok_or(RotationError::MissingFrozenFence {
                    direction: Direction::RelayToConnector,
                })?;
        let connector_to_relay =
            attempt.drained[1]
                .clone()
                .ok_or(RotationError::MissingFrozenFence {
                    direction: Direction::ConnectorToRelay,
                })?;
        Ok(DrainSet {
            relay_to_connector,
            connector_to_relay,
        })
    }

    /// Send the owner commit decision.  This is deliberately separate from
    /// the connector's activation acknowledgement.
    pub fn commit(
        &mut self,
        identity: &RotationAttemptIdentity,
        now_ms: RotationTime,
    ) -> Result<(), RotationError> {
        self.observe_time(now_ms)?;
        self.ensure_attempt(identity, RotationPhase::Committing)?;
        self.check_deadline(now_ms)?;
        let attempt = self.attempt.as_mut().expect("phase checked above");
        if attempt.drained[0].is_none() || attempt.drained[1].is_none() {
            return Err(RotationError::DrainIncomplete);
        }
        if attempt.commit_sent {
            return Ok(());
        }
        attempt.commit_sent = true;
        Ok(())
    }

    /// Acknowledge candidate activation.  Once this succeeds, abort is
    /// permanently forbidden and a timeout enters recovery instead of
    /// restoring the old carrier.
    pub fn committed(
        &mut self,
        identity: &RotationAttemptIdentity,
        now_ms: RotationTime,
    ) -> Result<(), RotationError> {
        self.observe_time(now_ms)?;
        self.ensure_attempt(identity, RotationPhase::Committing)?;
        self.check_deadline(now_ms)?;
        let attempt = self.attempt.as_mut().expect("phase checked above");
        if !attempt.commit_sent {
            return Err(RotationError::CommitNotSent);
        }
        attempt.commit_accepted = true;
        self.phase = RotationPhase::Retiring;
        Ok(())
    }

    /// Send RETIRE after the replacement has been activated.
    pub fn retire(
        &mut self,
        identity: &RotationAttemptIdentity,
        now_ms: RotationTime,
    ) -> Result<(), RotationError> {
        self.observe_time(now_ms)?;
        self.ensure_attempt(identity, RotationPhase::Retiring)?;
        self.check_deadline(now_ms)?;
        let attempt = self.attempt.as_mut().expect("phase checked above");
        if !attempt.commit_accepted {
            return Err(RotationError::CommitNotAccepted);
        }
        attempt.retire_sent = true;
        Ok(())
    }

    /// Record one side's close evidence for the old carrier.  Active
    /// transition is possible only after both endpoint attestations are
    /// present.  Evidence after the deadline is accepted as a forced
    /// retirement and remains visible in diagnostics.
    pub fn old_socket_closed(
        &mut self,
        identity: &RotationAttemptIdentity,
        side: RotationSide,
        evidence: ClosureEvidence,
        now_ms: RotationTime,
    ) -> Result<(), RotationError> {
        self.observe_time(now_ms)?;
        self.ensure_attempt(identity, RotationPhase::Retiring)?;
        let (old_connection_id, overlap_deadline_ms, retire_sent) = {
            let attempt = self.attempt.as_ref().expect("phase checked above");
            (
                attempt.identity.old_connection_id.clone(),
                attempt.overlap_deadline_ms,
                attempt.retire_sent,
            )
        };
        if !retire_sent {
            return Err(RotationError::RetireNotSent);
        }
        validate_identifier("connection_id", &evidence.connection_id)?;
        if evidence.connection_id != old_connection_id {
            return Err(RotationError::ConnectionMismatch);
        }
        if !evidence.is_complete() {
            return Err(RotationError::IncompleteClosureEvidence);
        }
        let complete = {
            let attempt = self.attempt.as_mut().expect("phase checked above");
            attempt.old_socket_closed[side_index(side)] = true;
            attempt.old_socket_closed[0] && attempt.old_socket_closed[1]
        };
        self.deadline_forced_retirement |= now_ms >= overlap_deadline_ms;
        if complete {
            self.allocated_connections.remove(&old_connection_id);
            if now_ms >= overlap_deadline_ms {
                // The close evidence is accepted as a forced retirement, but
                // the strict overlap budget cannot be retroactively converted
                // into a successful handover.  Recovery must establish a
                // fresh generation before payload admission resumes.
                self.enter_recovery_in_place(RecoveryReason::Deadline);
            } else {
                let (new_generation, new_connection_id) = {
                    let attempt = self.attempt.as_ref().expect("phase checked above");
                    (
                        attempt.identity.new_generation,
                        attempt.identity.new_connection_id.clone(),
                    )
                };
                self.active_generation = new_generation;
                self.active_connection_id = new_connection_id;
                self.attempt = None;
                self.phase = RotationPhase::Active;
                self.recovery_episode_deadline = None;
                self.recovery_attempts = 0;
            }
        }
        Ok(())
    }

    /// Alias matching the `ROTATE_RETIRED` control acknowledgement.
    pub fn retired(
        &mut self,
        identity: &RotationAttemptIdentity,
        side: RotationSide,
        evidence: ClosureEvidence,
        now_ms: RotationTime,
    ) -> Result<(), RotationError> {
        self.old_socket_closed(identity, side, evidence, now_ms)
    }

    /// Begin a coordinated abort while the old socket is still authoritative.
    /// A commit decision, even if its acknowledgement is uncertain, cannot be
    /// aborted or rolled back.
    pub fn abort(
        &mut self,
        identity: &RotationAttemptIdentity,
        now_ms: RotationTime,
        reason: RecoveryReason,
    ) -> Result<(), RotationError> {
        self.observe_time(now_ms)?;
        if self.phase != RotationPhase::Preparing
            && self.phase != RotationPhase::Quiescing
            && self.phase != RotationPhase::Draining
        {
            return Err(RotationError::InvalidPhase {
                expected: RotationPhase::Draining,
                actual: self.phase,
            });
        }
        self.ensure_attempt(identity, self.phase)?;
        self.check_deadline(now_ms)?;
        let attempt = self.attempt.as_mut().expect("phase checked above");
        if attempt.commit_sent || attempt.commit_accepted {
            return Err(RotationError::CommitCannotRollback);
        }
        attempt.recovery_reason = Some(reason);
        self.phase = RotationPhase::Aborting;
        Ok(())
    }

    /// Record one side's candidate close evidence during a known abort.  Both
    /// sides must release the candidate before old writers resume.
    pub fn candidate_closed(
        &mut self,
        identity: &RotationAttemptIdentity,
        side: RotationSide,
        evidence: ClosureEvidence,
        now_ms: RotationTime,
    ) -> Result<(), RotationError> {
        self.observe_time(now_ms)?;
        if self.phase != RotationPhase::Aborting && self.phase != RotationPhase::Recovering {
            return Err(RotationError::InvalidPhase {
                expected: RotationPhase::Aborting,
                actual: self.phase,
            });
        }
        self.ensure_attempt(identity, self.phase)?;
        let (new_connection_id, overlap_deadline_ms, is_recovery_attempt, recovery_socket_reserved) = {
            let attempt = self.attempt.as_ref().expect("phase checked above");
            (
                attempt.identity.new_connection_id.clone(),
                attempt.overlap_deadline_ms,
                attempt.is_recovery_attempt,
                attempt.recovery_socket_reserved,
            )
        };
        validate_identifier("connection_id", &evidence.connection_id)?;
        if evidence.connection_id != new_connection_id {
            return Err(RotationError::ConnectionMismatch);
        }
        if !evidence.is_complete() {
            return Err(RotationError::IncompleteClosureEvidence);
        }
        let was_recovering = self.phase == RotationPhase::Recovering;
        if was_recovering && is_recovery_attempt && !recovery_socket_reserved {
            return Err(RotationError::RecoverySocketNotReserved);
        }
        let complete = {
            let attempt = self.attempt.as_mut().expect("phase checked above");
            attempt.candidate_socket_closed[side_index(side)] = true;
            attempt.candidate_socket_closed[0] && attempt.candidate_socket_closed[1]
        };
        if complete {
            let removed = self.allocated_connections.remove(&new_connection_id);
            if was_recovering && is_recovery_attempt {
                if !removed {
                    return Err(RotationError::ConnectionNotAllocated);
                }
                if let Some(attempt) = self.attempt.as_mut() {
                    attempt.recovery_socket_reserved = false;
                }
            }
            if !was_recovering {
                if now_ms >= overlap_deadline_ms {
                    self.enter_recovery_in_place(RecoveryReason::Deadline);
                } else {
                    self.attempt = None;
                    self.phase = RotationPhase::Active;
                    self.recovery_episode_deadline = None;
                    self.recovery_attempts = 0;
                }
            }
        } else if now_ms >= overlap_deadline_ms {
            self.enter_recovery_in_place(RecoveryReason::Deadline);
        }
        Ok(())
    }

    /// Alias matching the `ROTATE_ABORTED` control acknowledgement.
    pub fn aborted(
        &mut self,
        identity: &RotationAttemptIdentity,
        side: RotationSide,
        evidence: ClosureEvidence,
        now_ms: RotationTime,
    ) -> Result<(), RotationError> {
        self.candidate_closed(identity, side, evidence, now_ms)
    }

    /// Enter retained-state recovery immediately when an authenticated data
    /// transport is lost.  This is separate from [`Self::tick`]: a carrier
    /// failure in `Committing` or `Retiring` cannot wait for the overlap timer
    /// and cannot restore an old generation after an accepted commit.
    pub fn transport_lost(
        &mut self,
        identity: &RotationAttemptIdentity,
        now_ms: RotationTime,
        reason: RecoveryReason,
    ) -> Result<(), RotationError> {
        self.observe_time(now_ms)?;
        if self.phase == RotationPhase::Closed {
            return Err(RotationError::Closed);
        }
        if self.phase == RotationPhase::Active {
            self.validate_attempt_identity(
                identity,
                self.active_generation,
                &self.active_connection_id,
            )?;
        } else if let Some(attempt) = self.attempt.as_ref() {
            if &attempt.identity != identity {
                return Err(RotationError::AttemptMismatch);
            }
        } else if self.phase != RotationPhase::Recovering {
            return Err(RotationError::MissingAttempt);
        } else {
            self.validate_attempt_identity(
                identity,
                self.active_generation,
                &self.active_connection_id,
            )?;
        }
        self.enter_recovery_in_place(reason);
        Ok(())
    }

    /// Start one bounded recovery attempt after its abandoned carriers have
    /// been released.  `episode_deadline_ms` is the local monotonic deadline
    /// retained from RECOVERY_BEGIN; it is immutable for every retry and its
    /// budget includes closure, attachment, replay and readiness.
    pub fn begin_recovery(
        &mut self,
        identity: RotationAttemptIdentity,
        roster: StreamRoster,
        now_ms: RotationTime,
        reason: RecoveryReason,
        episode_deadline_ms: RotationTime,
    ) -> Result<(), RotationError> {
        self.observe_time(now_ms)?;
        if self.phase == RotationPhase::Closed {
            return Err(RotationError::Closed);
        }
        if self.phase != RotationPhase::Active && self.phase != RotationPhase::Recovering {
            return Err(RotationError::InvalidPhase {
                expected: RotationPhase::Recovering,
                actual: self.phase,
            });
        }
        let (expected_old_generation, expected_old_connection_id) = self.recovery_anchor();
        self.validate_recovery_identity(
            &identity,
            expected_old_generation,
            &expected_old_connection_id,
        )?;
        validate_roster(&roster, self.config.max_roster_entries)?;
        validate_identifier("snapshot_id", &roster.snapshot_id)?;
        if let Some(previous_roster) = self
            .attempt
            .as_ref()
            .and_then(|attempt| attempt.roster.as_ref())
            && previous_roster != &roster
        {
            return Err(RotationError::RecoveryRosterMismatch);
        }
        let recovery_deadline = self.validate_recovery_deadline(now_ms, episode_deadline_ms)?;
        if !self.allocated_connections.is_empty() {
            return Err(RotationError::RecoveryResourcesNotReleased);
        }
        if self.recovery_attempts >= MAX_RECOVERY_ATTEMPTS {
            return Err(RotationError::RecoveryAttemptLimitExceeded {
                maximum: MAX_RECOVERY_ATTEMPTS,
            });
        }
        if identity.new_generation <= self.generation_high_watermark {
            return Err(RotationError::GenerationNotMonotonic {
                previous: self.generation_high_watermark,
                proposed: identity.new_generation,
            });
        }
        let attempt = AttemptState::new_with_deadline(
            identity,
            now_ms,
            self.config,
            Some(recovery_deadline),
        )?;
        let mut attempt = attempt;
        attempt.is_recovery_attempt = true;
        attempt.roster = Some(roster);
        attempt.recovery_reason = Some(reason);
        let recovery_attempts = self.recovery_attempts.checked_add(1).ok_or(
            RotationError::RecoveryAttemptLimitExceeded {
                maximum: MAX_RECOVERY_ATTEMPTS,
            },
        )?;
        self.claim_connection_id(&attempt.identity.new_connection_id)?;
        self.generation_high_watermark = attempt.identity.new_generation;
        self.recovery_episode_deadline = Some(recovery_deadline);
        self.recovery_attempts = recovery_attempts;
        self.attempt = Some(attempt);
        self.phase = RotationPhase::Recovering;
        self.assert_socket_bound();
        Ok(())
    }

    /// Alias for callers that treat recovery as a phase transition event.
    pub fn recover(
        &mut self,
        identity: RotationAttemptIdentity,
        roster: StreamRoster,
        now_ms: RotationTime,
        reason: RecoveryReason,
        episode_deadline_ms: RotationTime,
    ) -> Result<(), RotationError> {
        self.begin_recovery(identity, roster, now_ms, reason, episode_deadline_ms)
    }

    /// Allocate the single replacement recovery transport.  This helper makes
    /// the two-data-socket bound explicit even when a failed old transport is
    /// still awaiting close evidence.
    pub fn reserve_recovery_socket(&mut self, now_ms: RotationTime) -> Result<(), RotationError> {
        self.observe_time(now_ms)?;
        if self.phase != RotationPhase::Recovering {
            return Err(RotationError::InvalidPhase {
                expected: RotationPhase::Recovering,
                actual: self.phase,
            });
        }
        self.check_deadline(now_ms)?;
        if !self.allocated_connections.is_empty() {
            return Err(RotationError::RecoveryResourcesNotReleased);
        }
        if self.allocated_connections.len() >= MAX_DATA_SOCKETS as usize {
            return Err(RotationError::SocketBoundExceeded);
        }
        let Some(attempt) = self.attempt.as_ref() else {
            return Err(RotationError::MissingAttempt);
        };
        if !attempt.is_recovery_attempt {
            return Err(RotationError::RecoveryBeginRequired);
        }
        if self.recovery_episode_deadline.is_none() {
            return Err(RotationError::RecoveryBeginRequired);
        }
        if attempt.recovery_socket_ever_reserved {
            return Err(RotationError::RecoverySocketAlreadyReserved);
        }
        let connection_id = attempt.identity.new_connection_id.clone();
        if !self.allocated_connections.insert(connection_id) {
            return Err(RotationError::ConnectionReuse);
        }
        let attempt = self.attempt.as_mut().ok_or(RotationError::MissingAttempt)?;
        attempt.recovery_socket_reserved = true;
        attempt.recovery_socket_ever_reserved = true;
        Ok(())
    }

    /// Release one failed/retired recovery transport after explicit close
    /// evidence.  The connection ID is required so a stale close cannot free a
    /// different carrier.
    pub fn release_recovery_socket(
        &mut self,
        connection_id: impl Into<String>,
        evidence: ClosureEvidence,
        now_ms: RotationTime,
    ) -> Result<(), RotationError> {
        self.close_for_recovery(connection_id, evidence, now_ms)
    }

    /// Record explicit physical close evidence while recovering.  A new
    /// recovery candidate cannot be reserved while any prior carrier remains
    /// allocated, even if the phase has already changed to `Recovering`.
    pub fn close_for_recovery(
        &mut self,
        connection_id: impl Into<String>,
        evidence: ClosureEvidence,
        now_ms: RotationTime,
    ) -> Result<(), RotationError> {
        self.observe_time(now_ms)?;
        if self.phase != RotationPhase::Recovering {
            return Err(RotationError::InvalidPhase {
                expected: RotationPhase::Recovering,
                actual: self.phase,
            });
        }
        let connection_id = connection_id.into();
        validate_identifier("connection_id", &connection_id)?;
        validate_identifier("connection_id", &evidence.connection_id)?;
        if evidence.connection_id != connection_id || !evidence.is_complete() {
            return Err(RotationError::IncompleteClosureEvidence);
        }
        let known_to_attempt = self
            .attempt
            .as_ref()
            .map(|attempt| {
                connection_id == attempt.identity.old_connection_id
                    || connection_id == attempt.identity.new_connection_id
            })
            .unwrap_or(connection_id == self.active_connection_id);
        if !known_to_attempt {
            return Err(RotationError::ConnectionMismatch);
        }
        if !self.allocated_connections.remove(&connection_id) {
            return Err(RotationError::ConnectionNotAllocated);
        }
        if let Some(attempt) = self.attempt.as_mut()
            && attempt.is_recovery_attempt
            && connection_id == attempt.identity.new_connection_id
        {
            attempt.recovery_socket_reserved = false;
        }
        Ok(())
    }

    /// Apply per-stream verdicts produced by the sequence agent's
    /// `StreamState::reconcile` operation and activate the fresh carrier.
    /// Rotation validates only bounded shape and the immutable roster; it does
    /// not duplicate sequence, terminal, credit, or retained-history logic.
    pub fn reconcile_validated(
        &mut self,
        identity: &RotationAttemptIdentity,
        verdicts: impl IntoIterator<Item = ValidatedRecovery>,
        now_ms: RotationTime,
    ) -> Result<RecoveryReport, RotationError> {
        self.observe_time(now_ms)?;
        self.ensure_attempt(identity, RotationPhase::Recovering)?;
        self.check_deadline(now_ms)?;
        let maximum = self.config.max_roster_entries;
        let mut verdict_iter = verdicts.into_iter();
        let verdicts: Vec<ValidatedRecovery> = verdict_iter
            .by_ref()
            .take(maximum.saturating_add(1))
            .collect();
        if verdicts.len() > maximum || verdict_iter.next().is_some() {
            return Err(RotationError::RosterTooLarge {
                count: verdicts.len(),
                maximum,
            });
        }
        let Some(attempt) = self.attempt.as_ref() else {
            return Err(RotationError::MissingAttempt);
        };
        if !attempt.is_recovery_attempt {
            return Err(RotationError::RecoveryBeginRequired);
        }
        if self.recovery_episode_deadline.is_none() {
            return Err(RotationError::RecoveryBeginRequired);
        }
        if !attempt.recovery_socket_reserved {
            return Err(RotationError::RecoverySocketNotReserved);
        }
        if self.allocated_connections.len() != 1
            || !self
                .allocated_connections
                .contains(&attempt.identity.new_connection_id)
        {
            return Err(RotationError::RecoveryResourcesNotReleased);
        }
        if attempt.candidate_socket_closed.iter().any(|closed| *closed) {
            // A one-sided close record means the candidate is already in
            // teardown.  It may remain allocated until the second local side
            // releases it, but it can never become the active carrier.
            return Err(RotationError::RecoveryResourcesNotReleased);
        }
        let Some(roster) = attempt.roster.as_ref() else {
            return Err(RotationError::MissingRoster);
        };
        let expected_stream_ids = roster.stream_ids.clone();
        let mut seen_streams = BTreeSet::new();
        let mut replay = Vec::new();
        let mut failures = Vec::new();
        for verdict in verdicts {
            if verdict.stream_id == 0 || !seen_streams.insert(verdict.stream_id) {
                return Err(RotationError::InvalidRecoveryVerdict);
            }
            if !verdict.ready {
                return Err(RotationError::RecoveryReplayPending);
            }
            if !verdict.failures.is_empty() && !verdict.replay.is_empty() {
                return Err(RotationError::InvalidRecoveryVerdict);
            }
            let mut directions = BTreeSet::new();
            for range in verdict.replay {
                if range.stream_id != verdict.stream_id
                    || range.first_sequence == 0
                    || range.first_sequence > range.last_sequence
                    || !directions.insert(direction_index(range.direction))
                {
                    return Err(RotationError::InvalidRecoveryVerdict);
                }
                replay.push(range);
            }
            directions.clear();
            for failure in verdict.failures {
                if failure.stream_id != verdict.stream_id
                    || !directions.insert(direction_index(failure.direction))
                {
                    return Err(RotationError::InvalidRecoveryVerdict);
                }
                failures.push(failure);
            }
        }
        let actual_stream_ids: Vec<u64> = seen_streams.into_iter().collect();
        if actual_stream_ids != expected_stream_ids {
            return Err(RotationError::RecoveryRosterMismatch);
        }
        replay.sort_by_key(|range| (range.stream_id, direction_index(range.direction)));
        failures.sort_by_key(|failure| (failure.stream_id, direction_index(failure.direction)));

        // The replacement generation is authoritative even when one scoped
        // stream failed.  The runtime can fail those streams while preserving
        // other unaffected streams; it must never reactivate the old carrier.
        self.active_generation = identity.new_generation;
        self.active_connection_id = identity.new_connection_id.clone();
        self.attempt = None;
        self.phase = RotationPhase::Active;
        self.recovery_episode_deadline = None;
        self.recovery_attempts = 0;
        Ok(RecoveryReport { replay, failures })
    }

    /// Force the state machine closed.  No transport remains allocated.
    pub fn close(&mut self) {
        self.attempt = None;
        self.phase = RotationPhase::Closed;
        self.allocated_connections.clear();
        self.recovery_episode_deadline = None;
        self.recovery_attempts = 0;
    }

    /// Advance deadline handling.  Returns the resulting phase.  At the exact
    /// deadline, successful transition evidence is rejected and recovery is
    /// entered; no phase can extend the original overlap budget.
    pub fn tick(&mut self, now_ms: RotationTime) -> RotationPhase {
        if self.observe_time(now_ms).is_err() {
            return self.phase;
        }
        let Some((handshake_deadline_ms, overlap_deadline_ms)) = self
            .attempt
            .as_ref()
            .map(|attempt| (attempt.handshake_deadline_ms, attempt.overlap_deadline_ms))
        else {
            return self.phase;
        };
        if now_ms < overlap_deadline_ms {
            if self.phase == RotationPhase::Preparing && now_ms >= handshake_deadline_ms {
                self.phase = RotationPhase::Aborting;
            }
            return self.phase;
        }
        self.enter_recovery_in_place(RecoveryReason::Deadline);
        self.phase
    }

    fn ensure_attempt(
        &self,
        identity: &RotationAttemptIdentity,
        expected: RotationPhase,
    ) -> Result<(), RotationError> {
        if self.phase != expected {
            return Err(RotationError::InvalidPhase {
                expected,
                actual: self.phase,
            });
        }
        let Some(attempt) = self.attempt.as_ref() else {
            return Err(RotationError::MissingAttempt);
        };
        if &attempt.identity != identity {
            return Err(RotationError::AttemptMismatch);
        }
        Ok(())
    }

    fn recovery_anchor(&self) -> (u64, String) {
        if let Some(attempt) = self.attempt.as_ref() {
            if attempt.commit_accepted {
                return (
                    attempt.identity.new_generation,
                    attempt.identity.new_connection_id.clone(),
                );
            }
            return (
                attempt.identity.old_generation,
                attempt.identity.old_connection_id.clone(),
            );
        }
        (self.active_generation, self.active_connection_id.clone())
    }

    fn claim_connection_id(&mut self, connection_id: &str) -> Result<(), RotationError> {
        if self.used_connection_ids.contains(connection_id) {
            return Err(RotationError::ConnectionReuse);
        }
        if self.used_connection_ids.len() >= MAX_CONNECTION_ID_HISTORY {
            return Err(RotationError::ConnectionHistoryExhausted {
                maximum: MAX_CONNECTION_ID_HISTORY,
            });
        }
        self.used_connection_ids.insert(connection_id.to_owned());
        Ok(())
    }

    fn check_deadline(&mut self, now_ms: RotationTime) -> Result<(), RotationError> {
        let Some(attempt) = self.attempt.as_ref() else {
            return Err(RotationError::MissingAttempt);
        };
        let deadline = attempt.overlap_deadline_ms;
        if now_ms >= deadline {
            self.enter_recovery_in_place(RecoveryReason::Deadline);
            return Err(RotationError::DeadlineExpired {
                now: now_ms,
                deadline,
            });
        }
        Ok(())
    }

    fn validate_recovery_deadline(
        &self,
        now_ms: RotationTime,
        proposed_deadline_ms: RotationTime,
    ) -> Result<RotationTime, RotationError> {
        if let Some(existing_deadline_ms) = self.recovery_episode_deadline {
            if proposed_deadline_ms != existing_deadline_ms {
                return Err(RotationError::RecoveryDeadlineMismatch {
                    expected: existing_deadline_ms,
                    proposed: proposed_deadline_ms,
                });
            }
            if now_ms >= existing_deadline_ms {
                return Err(RotationError::RecoveryDeadlineExpired {
                    now: now_ms,
                    deadline: existing_deadline_ms,
                });
            }
            return Ok(existing_deadline_ms);
        }
        if now_ms >= proposed_deadline_ms {
            return Err(RotationError::RecoveryDeadlineExpired {
                now: now_ms,
                deadline: proposed_deadline_ms,
            });
        }
        let maximum = now_ms
            .checked_add(self.config.recovery_timeout_ms)
            .ok_or(RotationError::DeadlineOverflow)?;
        if proposed_deadline_ms > maximum {
            return Err(RotationError::RecoveryDeadlineTooFar {
                now: now_ms,
                deadline: proposed_deadline_ms,
                maximum,
            });
        }
        Ok(proposed_deadline_ms)
    }

    fn enter_recovery_in_place(&mut self, reason: RecoveryReason) {
        if let Some(attempt) = self.attempt.as_mut() {
            attempt.recovery_reason = Some(reason);
        }
        self.phase = RotationPhase::Recovering;
        debug_assert!(self.allocated_connections.len() <= MAX_DATA_SOCKETS as usize);
    }

    fn observe_time(&mut self, now_ms: RotationTime) -> Result<(), RotationError> {
        if self.last_time_ms.is_some_and(|last| now_ms < last) {
            return Err(RotationError::ClockWentBackwards {
                previous: self.last_time_ms.expect("checked above"),
                now: now_ms,
            });
        }
        self.last_time_ms = Some(now_ms);
        Ok(())
    }

    fn validate_attempt_identity(
        &self,
        identity: &RotationAttemptIdentity,
        old_generation: u64,
        old_connection_id: &str,
    ) -> Result<(), RotationError> {
        validate_identifier("session_id", &identity.session_id)?;
        validate_identifier("owner_id", &identity.owner_id)?;
        validate_identifier("rotation_id", &identity.rotation_id)?;
        validate_identifier("old_connection_id", &identity.old_connection_id)?;
        validate_identifier("new_connection_id", &identity.new_connection_id)?;
        if identity.session_id != self.session_id
            || identity.owner_id != self.owner_id
            || identity.epoch != self.epoch
        {
            return Err(RotationError::AttemptMismatch);
        }
        if identity.old_generation != old_generation
            || identity.old_connection_id != old_connection_id
        {
            return Err(RotationError::StaleCarrier);
        }
        if identity.new_generation <= identity.old_generation {
            return Err(RotationError::GenerationNotMonotonic {
                previous: identity.old_generation,
                proposed: identity.new_generation,
            });
        }
        if identity.new_generation <= self.generation_high_watermark {
            return Err(RotationError::GenerationNotMonotonic {
                previous: self.generation_high_watermark,
                proposed: identity.new_generation,
            });
        }
        if identity.new_connection_id == identity.old_connection_id {
            return Err(RotationError::ConnectionReuse);
        }
        Ok(())
    }

    fn validate_recovery_identity(
        &self,
        identity: &RotationAttemptIdentity,
        old_generation: u64,
        old_connection_id: &str,
    ) -> Result<(), RotationError> {
        self.validate_attempt_identity(identity, old_generation, old_connection_id)
    }

    fn assert_socket_bound(&self) {
        debug_assert!(self.socket_count() <= MAX_TOTAL_SOCKETS);
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), RotationError> {
    if value.is_empty() || value.len() > 256 {
        return Err(RotationError::InvalidIdentifier {
            field,
            length: value.len(),
        });
    }
    Ok(())
}

fn direction_index(direction: Direction) -> usize {
    match direction {
        Direction::RelayToConnector => 0,
        Direction::ConnectorToRelay => 1,
    }
}

fn side_index(side: RotationSide) -> usize {
    match side {
        RotationSide::Owner => 0,
        RotationSide::Connector => 1,
    }
}

fn validate_roster(roster: &StreamRoster, maximum: usize) -> Result<(), RotationError> {
    if roster.stream_ids.len() > maximum {
        return Err(RotationError::RosterTooLarge {
            count: roster.stream_ids.len(),
            maximum,
        });
    }
    let mut seen = BTreeSet::new();
    let mut previous = 0;
    for stream_id in &roster.stream_ids {
        if *stream_id == 0 {
            return Err(RotationError::InvalidStreamId);
        }
        if !seen.insert(*stream_id) {
            return Err(RotationError::DuplicateRosterStream(*stream_id));
        }
        if *stream_id <= previous {
            return Err(RotationError::RosterNotSorted);
        }
        previous = *stream_id;
    }
    Ok(())
}

fn validate_fence_snapshot(
    snapshot: &FenceSnapshot,
    direction: Direction,
    maximum: usize,
) -> Result<(), RotationError> {
    if snapshot.entries.len() > maximum {
        return Err(RotationError::RosterTooLarge {
            count: snapshot.entries.len(),
            maximum,
        });
    }
    let mut previous = 0;
    let mut seen = BTreeSet::new();
    for entry in &snapshot.entries {
        if entry.stream_id == 0 {
            return Err(RotationError::InvalidStreamId);
        }
        if entry.direction != direction {
            return Err(RotationError::MixedFenceDirections);
        }
        if !seen.insert(entry.stream_id) {
            return Err(RotationError::DuplicateFenceStream(entry.stream_id));
        }
        if entry.stream_id <= previous {
            return Err(RotationError::FenceRosterNotSorted);
        }
        previous = entry.stream_id;
    }
    // The shared control type validates snapshot IDs and the canonical digest;
    // call it here so state-machine inputs receive the same bounds as wire
    // messages.  Empty snapshots are valid because `direction` is explicit.
    snapshot
        .digest()
        .map_err(|_| RotationError::FenceDigestUnavailable)?;
    Ok(())
}

fn fence_roster_matches(snapshot: &FenceSnapshot, roster: &StreamRoster) -> bool {
    snapshot
        .entries
        .iter()
        .map(|entry| entry.stream_id)
        .eq(roster.stream_ids.iter().copied())
}

fn same_fence_roster(left: &FenceSnapshot, right: &FenceSnapshot) -> bool {
    let left_ids: BTreeSet<u64> = left.entries.iter().map(|entry| entry.stream_id).collect();
    let right_ids: BTreeSet<u64> = right.entries.iter().map(|entry| entry.stream_id).collect();
    left_ids == right_ids
}

fn digest_for_snapshot(snapshot: &FenceSnapshot) -> Result<String, RotationError> {
    snapshot
        .digest()
        .map_err(|_| RotationError::FenceDigestUnavailable)
}

fn validate_ack_cursors(fences: &FenceSnapshot, proof: &DrainProof) -> Result<(), RotationError> {
    let mut acks = BTreeMap::new();
    for ack in &proof.ack_cursors {
        if ack.stream_id == 0 {
            return Err(RotationError::InvalidStreamId);
        }
        if acks.insert(ack.stream_id, ack.acknowledged).is_some() {
            return Err(RotationError::DuplicateAckStream(ack.stream_id));
        }
    }
    for fence in &fences.entries {
        let Some(ack) = acks.get(&fence.stream_id) else {
            return Err(RotationError::MissingAck(fence.stream_id));
        };
        if *ack < fence.last_emitted {
            return Err(RotationError::AckBelowFence {
                stream_id: fence.stream_id,
                fence: fence.last_emitted,
                acknowledged: *ack,
            });
        }
        if *ack > fence.last_emitted {
            return Err(RotationError::AckAboveFence {
                stream_id: fence.stream_id,
                fence: fence.last_emitted,
                acknowledged: *ack,
            });
        }
    }
    if acks.len() != fences.entries.len() {
        return Err(RotationError::AckRosterMismatch);
    }
    Ok(())
}

/// Errors returned by the pure machine.  The variants intentionally preserve
/// phase, identity, deadline, fence, and socket-bound failures for diagnostics
/// without exposing payloads or credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RotationError {
    InvalidConfig(&'static str),
    InvalidIdentifier {
        field: &'static str,
        length: usize,
    },
    InvalidEpoch,
    InvalidGeneration(u64),
    DeadlineOverflow,
    InvalidPhase {
        expected: RotationPhase,
        actual: RotationPhase,
    },
    AttemptMismatch,
    StaleCarrier,
    ConnectionReuse,
    ConnectionHistoryExhausted {
        maximum: usize,
    },
    GenerationNotMonotonic {
        previous: u64,
        proposed: u64,
    },
    CandidateNotReady,
    HandshakeDeadlineExpired {
        now: u64,
        deadline: u64,
    },
    DeadlineExpired {
        now: u64,
        deadline: u64,
    },
    RecoveryDeadlineExpired {
        now: u64,
        deadline: u64,
    },
    RecoveryDeadlineTooFar {
        now: u64,
        deadline: u64,
        maximum: u64,
    },
    RecoveryDeadlineMismatch {
        expected: u64,
        proposed: u64,
    },
    MissingRoster,
    SnapshotMismatch,
    RosterMismatch,
    MixedFenceDirections,
    RosterTooLarge {
        count: usize,
        maximum: usize,
    },
    InvalidStreamId,
    DuplicateFenceStream(u64),
    DuplicateRosterStream(u64),
    RosterNotSorted,
    FenceRosterNotSorted,
    FenceDigestUnavailable,
    ConflictingFrozenFence {
        direction: Direction,
    },
    MissingFrozenFence {
        direction: Direction,
    },
    FenceDigestMismatch,
    MissingAck(u64),
    DuplicateAckStream(u64),
    AckBelowFence {
        stream_id: u64,
        fence: u64,
        acknowledged: u64,
    },
    AckAboveFence {
        stream_id: u64,
        fence: u64,
        acknowledged: u64,
    },
    AckRosterMismatch,
    ConflictingDrainProof {
        direction: Direction,
    },
    DrainIncomplete,
    CommitNotSent,
    CommitCannotRollback,
    CommitNotAccepted,
    RetireNotSent,
    IncompleteClosureEvidence,
    ConnectionMismatch,
    SocketBoundExceeded,
    SocketUnderflow,
    RecoveryResourcesNotReleased,
    RecoveryBeginRequired,
    RecoverySocketNotReserved,
    RecoverySocketAlreadyReserved,
    ConnectionNotAllocated,
    RecoveryRosterMismatch,
    InvalidRecoveryVerdict,
    RecoveryReplayPending,
    RecoveryAttemptLimitExceeded {
        maximum: u8,
    },
    ClockWentBackwards {
        previous: u64,
        now: u64,
    },
    MissingAttempt,
    Closed,
}

impl fmt::Display for RotationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(formatter, "invalid rotation config: {reason}"),
            Self::InvalidIdentifier { field, length } => {
                write!(formatter, "invalid {field} identifier length {length}")
            }
            Self::InvalidEpoch => formatter.write_str("rotation epoch must be nonzero"),
            Self::InvalidGeneration(generation) => {
                write!(formatter, "invalid generation {generation}")
            }
            Self::DeadlineOverflow => formatter.write_str("rotation deadline overflows the clock"),
            Self::InvalidPhase { expected, actual } => {
                write!(
                    formatter,
                    "rotation phase is {actual:?}, expected {expected:?}"
                )
            }
            Self::AttemptMismatch => formatter.write_str("rotation attempt identity mismatch"),
            Self::StaleCarrier => {
                formatter.write_str("rotation attempt references a stale carrier")
            }
            Self::ConnectionReuse => {
                formatter.write_str("rotation reuses a physical connection ID")
            }
            Self::ConnectionHistoryExhausted { maximum } => write!(
                formatter,
                "connection ID history reached its session bound of {maximum}; start a fresh session"
            ),
            Self::GenerationNotMonotonic { previous, proposed } => {
                write!(
                    formatter,
                    "generation {proposed} is not greater than {previous}"
                )
            }
            Self::CandidateNotReady => formatter.write_str("candidate is not ready"),
            Self::HandshakeDeadlineExpired { now, deadline } => {
                write!(
                    formatter,
                    "candidate handshake deadline {deadline} expired at {now}"
                )
            }
            Self::DeadlineExpired { now, deadline } => {
                write!(formatter, "rotation deadline {deadline} expired at {now}")
            }
            Self::RecoveryDeadlineExpired { now, deadline } => write!(
                formatter,
                "recovery episode deadline {deadline} expired at {now}"
            ),
            Self::RecoveryDeadlineTooFar {
                now,
                deadline,
                maximum,
            } => write!(
                formatter,
                "recovery episode deadline {deadline} at {now} exceeds maximum {maximum}"
            ),
            Self::RecoveryDeadlineMismatch { expected, proposed } => write!(
                formatter,
                "recovery episode deadline {proposed} does not match immutable {expected}"
            ),
            Self::MissingRoster => formatter.write_str("rotation has no stream roster"),
            Self::SnapshotMismatch => formatter.write_str("rotation snapshot mismatch"),
            Self::RosterMismatch => formatter.write_str("rotation fence rosters differ"),
            Self::MixedFenceDirections => formatter.write_str("fence snapshot mixes directions"),
            Self::RosterTooLarge { count, maximum } => {
                write!(
                    formatter,
                    "rotation roster has {count} entries, maximum {maximum}"
                )
            }
            Self::InvalidStreamId => formatter.write_str("stream ID must be nonzero"),
            Self::DuplicateFenceStream(stream_id) => {
                write!(formatter, "duplicate fence for stream {stream_id}")
            }
            Self::DuplicateRosterStream(stream_id) => {
                write!(formatter, "duplicate roster stream {stream_id}")
            }
            Self::RosterNotSorted => formatter.write_str("roster stream IDs are not sorted"),
            Self::FenceRosterNotSorted => formatter.write_str("fence stream IDs are not sorted"),
            Self::FenceDigestUnavailable => formatter.write_str("fence snapshot failed validation"),
            Self::ConflictingFrozenFence { direction } => {
                write!(formatter, "conflicting frozen fence for {direction:?}")
            }
            Self::MissingFrozenFence { direction } => {
                write!(formatter, "missing frozen fence for {direction:?}")
            }
            Self::FenceDigestMismatch => formatter.write_str("drain proof fence digest mismatch"),
            Self::MissingAck(stream_id) => write!(
                formatter,
                "missing drain acknowledgement for stream {stream_id}"
            ),
            Self::DuplicateAckStream(stream_id) => write!(
                formatter,
                "duplicate drain acknowledgement for stream {stream_id}"
            ),
            Self::AckBelowFence {
                stream_id,
                fence,
                acknowledged,
            } => write!(
                formatter,
                "stream {stream_id} acknowledgement {acknowledged} is below fence {fence}"
            ),
            Self::AckAboveFence {
                stream_id,
                fence,
                acknowledged,
            } => write!(
                formatter,
                "stream {stream_id} acknowledgement {acknowledged} is above fence {fence}"
            ),
            Self::AckRosterMismatch => formatter.write_str("drain acknowledgement roster mismatch"),
            Self::ConflictingDrainProof { direction } => {
                write!(formatter, "conflicting drain proof for {direction:?}")
            }
            Self::DrainIncomplete => formatter.write_str("both complete drain proofs are required"),
            Self::CommitNotSent => {
                formatter.write_str("commit acknowledgement arrived before commit")
            }
            Self::CommitCannotRollback => {
                formatter.write_str("accepted or uncertain commit cannot roll back")
            }
            Self::CommitNotAccepted => formatter.write_str("retire requires an accepted commit"),
            Self::RetireNotSent => formatter.write_str("old close evidence arrived before retire"),
            Self::IncompleteClosureEvidence => {
                formatter.write_str("incomplete physical closure evidence")
            }
            Self::ConnectionMismatch => {
                formatter.write_str("closure evidence references another connection")
            }
            Self::SocketBoundExceeded => formatter.write_str("rotation socket bound exceeded"),
            Self::SocketUnderflow => formatter.write_str("rotation socket count underflow"),
            Self::RecoveryResourcesNotReleased => {
                formatter.write_str("recovery resources still have close evidence outstanding")
            }
            Self::RecoveryBeginRequired => {
                formatter.write_str("recovery candidate requires a validated recovery begin")
            }
            Self::RecoverySocketNotReserved => {
                formatter.write_str("recovery candidate socket is not reserved")
            }
            Self::RecoverySocketAlreadyReserved => {
                formatter.write_str("recovery candidate reservation is single-use for this attempt")
            }
            Self::ConnectionNotAllocated => formatter.write_str("connection is not allocated"),
            Self::RecoveryRosterMismatch => {
                formatter.write_str("recovery requires both directions for every stream")
            }
            Self::InvalidRecoveryVerdict => {
                formatter.write_str("sequence-agent recovery verdict is malformed")
            }
            Self::RecoveryReplayPending => {
                formatter.write_str("recovery replay or peer replay is still pending")
            }
            Self::RecoveryAttemptLimitExceeded { maximum } => write!(
                formatter,
                "recovery attempt limit of {maximum} reached; establish a fresh session"
            ),
            Self::ClockWentBackwards { previous, now } => {
                write!(
                    formatter,
                    "monotonic clock moved backwards from {previous} to {now}"
                )
            }
            Self::MissingAttempt => formatter.write_str("rotation attempt is missing"),
            Self::Closed => formatter.write_str("rotation state is closed"),
        }
    }
}

impl std::error::Error for RotationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rotation_control::StreamFence;

    fn state() -> RotationState {
        RotationState::new(
            "session",
            "owner",
            7,
            3,
            "data-old",
            RotationConfig::new(100, 10, 30).expect("valid config"),
        )
        .expect("valid active state")
    }

    fn attempt(new_generation: u64) -> RotationAttemptIdentity {
        RotationAttemptIdentity {
            session_id: "session".to_owned(),
            epoch: 7,
            owner_id: "owner".to_owned(),
            rotation_id: format!("rotation-{new_generation}"),
            old_generation: 3,
            new_generation,
            old_connection_id: "data-old".to_owned(),
            new_connection_id: format!("data-{new_generation}"),
        }
    }

    fn snapshot(snapshot_id: &str, direction: Direction, last_emitted: u64) -> FenceSnapshot {
        FenceSnapshot {
            snapshot_id: snapshot_id.to_owned(),
            entries: vec![
                StreamFence {
                    stream_id: 11,
                    direction,
                    last_emitted,
                },
                StreamFence {
                    stream_id: 12,
                    direction,
                    last_emitted: last_emitted.saturating_add(1),
                },
            ],
        }
    }

    fn proof(snapshot_id: &str, direction: Direction, digest: String) -> DrainProof {
        DrainProof {
            snapshot_id: snapshot_id.to_owned(),
            fence_digest: digest,
            direction,
            ack_cursors: vec![
                crate::rotation_control::StreamAck {
                    stream_id: 11,
                    acknowledged: 2,
                },
                crate::rotation_control::StreamAck {
                    stream_id: 12,
                    acknowledged: 3,
                },
            ],
        }
    }

    fn prepare_to_quiesce(machine: &mut RotationState, identity: &RotationAttemptIdentity) {
        machine.prepare(identity.clone(), 0).expect("prepare");
        machine
            .candidate_ready(identity, 1)
            .expect("candidate ready");
        machine
            .quiesce(identity, StreamRoster::new("snap", vec![11, 12]), 2)
            .expect("quiesce");
    }

    fn recovery_roster() -> StreamRoster {
        StreamRoster::new("recovery", vec![11, 12])
    }

    fn ready_verdict(stream_id: u64) -> ValidatedRecovery {
        ValidatedRecovery {
            stream_id,
            replay: Vec::new(),
            failures: Vec::new(),
            ready: true,
        }
    }

    fn drain_to_committing(machine: &mut RotationState, identity: &RotationAttemptIdentity) {
        prepare_to_quiesce(machine, identity);
        machine
            .frozen(
                identity,
                snapshot("snap", Direction::RelayToConnector, 2),
                Direction::RelayToConnector,
                3,
            )
            .expect("relay frozen");
        machine
            .frozen(
                identity,
                snapshot("snap", Direction::ConnectorToRelay, 2),
                Direction::ConnectorToRelay,
                4,
            )
            .expect("connector frozen");
        let d0 = digest_for_snapshot(
            machine.attempt.as_ref().expect("attempt").frozen[0]
                .as_ref()
                .expect("relay fence"),
        )
        .expect("relay digest");
        let d1 = digest_for_snapshot(
            machine.attempt.as_ref().expect("attempt").frozen[1]
                .as_ref()
                .expect("connector fence"),
        )
        .expect("connector digest");
        machine
            .drained(identity, proof("snap", Direction::RelayToConnector, d0), 5)
            .expect("relay drained");
        machine
            .drained(identity, proof("snap", Direction::ConnectorToRelay, d1), 6)
            .expect("connector drained");
    }

    fn commit_to_retiring(machine: &mut RotationState, identity: &RotationAttemptIdentity) {
        drain_to_committing(machine, identity);
        machine.commit(identity, 7).expect("commit sent");
        machine.committed(identity, 8).expect("commit accepted");
        machine.retire(identity, 9).expect("retire sent");
    }

    #[test]
    fn successful_handover_requires_both_directions_and_close_evidence() {
        let mut machine = state();
        let identity = attempt(4);
        prepare_to_quiesce(&mut machine, &identity);
        machine
            .frozen(
                &identity,
                snapshot("snap", Direction::RelayToConnector, 2),
                Direction::RelayToConnector,
                3,
            )
            .expect("relay frozen");
        machine
            .frozen(
                &identity,
                snapshot("snap", Direction::ConnectorToRelay, 2),
                Direction::ConnectorToRelay,
                4,
            )
            .expect("connector frozen");
        assert_eq!(machine.phase(), RotationPhase::Draining);
        let d0 = digest_for_snapshot(
            machine.attempt.as_ref().expect("attempt").frozen[0]
                .as_ref()
                .expect("relay fence"),
        )
        .expect("relay digest");
        let d1 = digest_for_snapshot(
            machine.attempt.as_ref().expect("attempt").frozen[1]
                .as_ref()
                .expect("connector fence"),
        )
        .expect("connector digest");
        machine
            .drained(&identity, proof("snap", Direction::RelayToConnector, d0), 5)
            .expect("relay drained");
        machine
            .drained(&identity, proof("snap", Direction::ConnectorToRelay, d1), 6)
            .expect("connector drained");
        machine.commit(&identity, 7).expect("commit sent");
        machine.committed(&identity, 8).expect("committed");
        machine.retire(&identity, 9).expect("retire");
        machine
            .old_socket_closed(
                &identity,
                RotationSide::Owner,
                ClosureEvidence::closed("data-old"),
                10,
            )
            .expect("owner close");
        assert_eq!(machine.phase(), RotationPhase::Retiring);
        machine
            .old_socket_closed(
                &identity,
                RotationSide::Connector,
                ClosureEvidence::closed("data-old"),
                11,
            )
            .expect("connector close");
        assert_eq!(machine.phase(), RotationPhase::Active);
        assert_eq!(machine.active_generation(), 4);
        assert_eq!(machine.socket_count(), 2);
    }

    #[test]
    fn forced_local_close_does_not_require_peer_handshake_but_requires_both_sides() {
        let identity = attempt(4);
        let local_only = || ClosureEvidence {
            connection_id: "data-old".to_owned(),
            local_closed: true,
            peer_closed: false,
        };

        let mut machine = state();
        commit_to_retiring(&mut machine, &identity);
        machine
            .old_socket_closed(&identity, RotationSide::Owner, local_only(), 10)
            .expect("owner task joined after forced local close");
        assert_eq!(machine.phase(), RotationPhase::Retiring);
        machine
            .old_socket_closed(&identity, RotationSide::Connector, local_only(), 11)
            .expect("connector task joined after forced local close");
        assert_eq!(machine.phase(), RotationPhase::Active);

        let mut rejected = state();
        commit_to_retiring(&mut rejected, &identity);
        let local_not_closed = ClosureEvidence {
            connection_id: "data-old".to_owned(),
            local_closed: false,
            peer_closed: true,
        };
        assert!(matches!(
            rejected.old_socket_closed(&identity, RotationSide::Owner, local_not_closed, 10,),
            Err(RotationError::IncompleteClosureEvidence)
        ));
        assert_eq!(rejected.phase(), RotationPhase::Retiring);
    }

    #[test]
    fn abort_releases_candidate_only_after_both_sides_and_consumes_generation() {
        let mut machine = state();
        let identity = attempt(4);
        machine.prepare(identity.clone(), 0).expect("prepare");
        machine
            .candidate_ready(&identity, 1)
            .expect("candidate ready");
        machine
            .abort(&identity, 2, RecoveryReason::CandidateTransportLost)
            .expect("abort");
        assert_eq!(machine.phase(), RotationPhase::Aborting);
        machine
            .candidate_closed(
                &identity,
                RotationSide::Owner,
                ClosureEvidence::closed("data-4"),
                3,
            )
            .expect("owner candidate close");
        assert_eq!(machine.phase(), RotationPhase::Aborting);
        machine
            .candidate_closed(
                &identity,
                RotationSide::Connector,
                ClosureEvidence::closed("data-4"),
                4,
            )
            .expect("connector candidate close");
        assert_eq!(machine.phase(), RotationPhase::Active);
        assert_eq!(machine.generation_high_watermark(), 4);
        assert!(matches!(
            machine.prepare(identity, 5),
            Err(RotationError::GenerationNotMonotonic { .. })
        ));
    }

    #[test]
    fn connection_ids_are_single_use_across_aborts_and_recovery() {
        let mut machine = state();
        let first = attempt(4);
        machine.prepare(first.clone(), 0).expect("first prepare");
        machine.candidate_ready(&first, 1).expect("first candidate");
        machine
            .abort(&first, 2, RecoveryReason::CandidateTransportLost)
            .expect("abort");
        machine
            .candidate_closed(
                &first,
                RotationSide::Owner,
                ClosureEvidence::closed("data-4"),
                3,
            )
            .expect("owner close");
        machine
            .candidate_closed(
                &first,
                RotationSide::Connector,
                ClosureEvidence::closed("data-4"),
                4,
            )
            .expect("connector close");

        let mut reused = attempt(5);
        reused.new_connection_id = "data-4".to_owned();
        assert!(matches!(
            machine.prepare(reused, 5),
            Err(RotationError::ConnectionReuse)
        ));
    }

    #[test]
    fn stale_identity_and_cross_session_fences_are_rejected() {
        let mut machine = state();
        let mut stale = attempt(4);
        stale.old_generation = 2;
        assert!(matches!(
            machine.prepare(stale, 0),
            Err(RotationError::StaleCarrier)
        ));
        let identity = attempt(4);
        prepare_to_quiesce(&mut machine, &identity);
        let mut wrong = identity.clone();
        wrong.rotation_id = "other".to_owned();
        assert!(matches!(
            machine.frozen(
                &wrong,
                snapshot("snap", Direction::RelayToConnector, 2),
                Direction::RelayToConnector,
                3,
            ),
            Err(RotationError::AttemptMismatch)
        ));
        assert_eq!(machine.phase(), RotationPhase::Quiescing);
    }

    #[test]
    fn digest_and_ack_fences_block_gaps_and_duplicates() {
        let mut machine = state();
        let identity = attempt(4);
        prepare_to_quiesce(&mut machine, &identity);
        let relay = snapshot("snap", Direction::RelayToConnector, 2);
        let connector = snapshot("snap", Direction::ConnectorToRelay, 2);
        machine
            .frozen(&identity, relay, Direction::RelayToConnector, 3)
            .expect("relay frozen");
        machine
            .frozen(&identity, connector, Direction::ConnectorToRelay, 4)
            .expect("connector frozen");
        let digest = digest_for_snapshot(
            machine.attempt.as_ref().expect("attempt").frozen[0]
                .as_ref()
                .expect("relay fence"),
        )
        .expect("digest");
        let mut bad = proof("snap", Direction::RelayToConnector, digest.clone());
        bad.ack_cursors[0].acknowledged = 1;
        assert!(matches!(
            machine.drained(&identity, bad, 5),
            Err(RotationError::AckBelowFence { .. })
        ));
        let mut above = proof("snap", Direction::RelayToConnector, digest.clone());
        above.ack_cursors[0].acknowledged = 3;
        assert!(matches!(
            machine.drained(&identity, above, 5),
            Err(RotationError::AckAboveFence { .. })
        ));
        let good = proof("snap", Direction::RelayToConnector, digest.clone());
        machine
            .drained(&identity, good.clone(), 6)
            .expect("good proof");
        machine
            .drained(&identity, good, 7)
            .expect("duplicate proof is idempotent");
        assert_eq!(machine.phase(), RotationPhase::Draining);
    }

    #[test]
    fn commit_decision_cannot_roll_back_on_uncertain_timeout() {
        let mut machine = state();
        let identity = attempt(4);
        prepare_to_quiesce(&mut machine, &identity);
        machine
            .frozen(
                &identity,
                snapshot("snap", Direction::RelayToConnector, 2),
                Direction::RelayToConnector,
                3,
            )
            .expect("relay frozen");
        machine
            .frozen(
                &identity,
                snapshot("snap", Direction::ConnectorToRelay, 2),
                Direction::ConnectorToRelay,
                4,
            )
            .expect("connector frozen");
        let d0 = digest_for_snapshot(
            machine.attempt.as_ref().expect("attempt").frozen[0]
                .as_ref()
                .expect("relay fence"),
        )
        .expect("relay digest");
        let d1 = digest_for_snapshot(
            machine.attempt.as_ref().expect("attempt").frozen[1]
                .as_ref()
                .expect("connector fence"),
        )
        .expect("connector digest");
        machine
            .drained(&identity, proof("snap", Direction::RelayToConnector, d0), 5)
            .expect("drain relay");
        machine
            .drained(&identity, proof("snap", Direction::ConnectorToRelay, d1), 6)
            .expect("drain connector");
        machine.commit(&identity, 7).expect("commit sent");
        assert!(matches!(
            machine.abort(&identity, 8, RecoveryReason::CommitUncertain),
            Err(RotationError::InvalidPhase { .. })
        ));
        assert_eq!(machine.phase(), RotationPhase::Committing);
        assert_eq!(machine.tick(30), RotationPhase::Recovering);
        assert_ne!(machine.active_generation(), 4);
    }

    #[test]
    fn transport_loss_enters_recovery_immediately_in_committing_and_retiring() {
        let identity = attempt(4);

        let mut committing = state();
        drain_to_committing(&mut committing, &identity);
        let mut stale = identity.clone();
        stale.rotation_id = "stale".to_owned();
        assert!(matches!(
            committing.transport_lost(&stale, 7, RecoveryReason::ControlLost),
            Err(RotationError::AttemptMismatch)
        ));
        assert_eq!(committing.phase(), RotationPhase::Committing);
        committing
            .transport_lost(&identity, 8, RecoveryReason::CandidateTransportLost)
            .expect("committing loss");
        assert_eq!(committing.phase(), RotationPhase::Recovering);

        let mut retiring = state();
        commit_to_retiring(&mut retiring, &identity);
        retiring
            .transport_lost(&identity, 10, RecoveryReason::OldTransportLost)
            .expect("retiring loss");
        assert_eq!(retiring.phase(), RotationPhase::Recovering);
        assert_ne!(retiring.active_generation(), 4);
    }

    #[test]
    fn old_close_at_the_exact_overlap_deadline_cannot_activate_candidate() {
        let mut machine = state();
        let identity = attempt(4);
        commit_to_retiring(&mut machine, &identity);
        machine
            .old_socket_closed(
                &identity,
                RotationSide::Owner,
                ClosureEvidence::closed("data-old"),
                29,
            )
            .expect("first old close");
        machine
            .old_socket_closed(
                &identity,
                RotationSide::Connector,
                ClosureEvidence::closed("data-old"),
                30,
            )
            .expect("forced old close");
        assert_eq!(machine.phase(), RotationPhase::Recovering);
        assert_ne!(machine.active_generation(), 4);
        machine
            .close_for_recovery("data-4", ClosureEvidence::closed("data-4"), 31)
            .expect("candidate close");
        assert_eq!(machine.socket_count(), CONTROL_SOCKETS);
    }

    #[test]
    fn recovery_binds_old_carrier_and_never_panics_without_an_attempt() {
        let mut machine = state();
        let mut wrong = attempt(5);
        wrong.old_generation = 2;
        assert!(matches!(
            machine.begin_recovery(
                wrong,
                StreamRoster::new("empty", vec![]),
                0,
                RecoveryReason::OldTransportLost,
                30
            ),
            Err(RotationError::StaleCarrier)
        ));
        assert_eq!(machine.phase(), RotationPhase::Active);
        let correct = attempt(5);
        machine
            .transport_lost(&correct, 0, RecoveryReason::OldTransportLost)
            .expect("enter recovery");
        machine
            .close_for_recovery("data-old", ClosureEvidence::closed("data-old"), 0)
            .expect("old transport close");
        assert!(matches!(
            machine.reserve_recovery_socket(0),
            Err(RotationError::MissingAttempt)
        ));
        machine
            .begin_recovery(
                attempt(5),
                StreamRoster::new("empty", vec![]),
                1,
                RecoveryReason::OldTransportLost,
                30,
            )
            .expect("bound recovery");
    }

    #[test]
    fn recovery_after_accepted_commit_is_bound_to_the_new_carrier() {
        let mut machine = state();
        let committed = attempt(4);
        commit_to_retiring(&mut machine, &committed);
        machine
            .transport_lost(&committed, 10, RecoveryReason::OldTransportLost)
            .expect("loss after accepted commit");
        machine
            .close_for_recovery("data-old", ClosureEvidence::closed("data-old"), 11)
            .expect("old close");
        machine
            .close_for_recovery("data-4", ClosureEvidence::closed("data-4"), 12)
            .expect("candidate close");

        assert!(matches!(
            machine.begin_recovery(
                attempt(5),
                StreamRoster::new("snap", vec![11, 12]),
                13,
                RecoveryReason::OldTransportLost,
                40
            ),
            Err(RotationError::StaleCarrier)
        ));
        let mut next = attempt(5);
        next.old_generation = 4;
        next.old_connection_id = "data-4".to_owned();
        machine
            .begin_recovery(
                next,
                StreamRoster::new("snap", vec![11, 12]),
                13,
                RecoveryReason::OldTransportLost,
                40,
            )
            .expect("new-carrier recovery");
        assert_eq!(machine.phase(), RotationPhase::Recovering);
    }

    #[test]
    fn recovery_rejects_backwards_clock_before_reconciling_input() {
        let mut machine = state();
        let identity = attempt(5);
        assert!(matches!(
            machine.begin_recovery(
                identity.clone(),
                recovery_roster(),
                0,
                RecoveryReason::OldTransportLost,
                30
            ),
            Err(RotationError::RecoveryResourcesNotReleased)
        ));
        machine
            .transport_lost(&identity, 0, RecoveryReason::OldTransportLost)
            .expect("enter recovery");
        machine
            .close_for_recovery("data-old", ClosureEvidence::closed("data-old"), 0)
            .expect("old transport close");
        machine
            .begin_recovery(
                identity.clone(),
                recovery_roster(),
                1,
                RecoveryReason::OldTransportLost,
                30,
            )
            .expect("begin recovery");
        machine.reserve_recovery_socket(1).expect("candidate");
        assert!(matches!(
            machine.reconcile_validated(&identity, [], 0),
            Err(RotationError::ClockWentBackwards { .. })
        ));
    }

    #[test]
    fn recovery_candidate_failure_does_not_resurrect_closed_old_carrier() {
        let mut machine = state();
        let first = attempt(4);
        assert!(matches!(
            machine.begin_recovery(
                first.clone(),
                recovery_roster(),
                0,
                RecoveryReason::OldTransportLost,
                30,
            ),
            Err(RotationError::RecoveryResourcesNotReleased)
        ));
        machine
            .transport_lost(&first, 0, RecoveryReason::OldTransportLost)
            .expect("enter recovery");
        machine
            .close_for_recovery("data-old", ClosureEvidence::closed("data-old"), 0)
            .expect("old transport close");
        machine
            .begin_recovery(
                first.clone(),
                recovery_roster(),
                1,
                RecoveryReason::OldTransportLost,
                30,
            )
            .expect("begin recovery");
        machine.reserve_recovery_socket(1).expect("candidate");
        machine
            .candidate_closed(
                &first,
                RotationSide::Owner,
                ClosureEvidence::closed("data-4"),
                2,
            )
            .expect("owner candidate close");
        machine
            .candidate_closed(
                &first,
                RotationSide::Connector,
                ClosureEvidence::closed("data-4"),
                3,
            )
            .expect("connector candidate close");
        assert_eq!(machine.phase(), RotationPhase::Recovering);
        assert_eq!(machine.socket_count(), CONTROL_SOCKETS);
        machine
            .begin_recovery(
                attempt(5),
                recovery_roster(),
                4,
                RecoveryReason::CandidateTransportLost,
                30,
            )
            .expect("fresh recovery");
    }

    #[test]
    fn abandoned_scheduled_attempt_cannot_reconcile_without_fresh_recovery_begin() {
        let mut machine = state();
        let scheduled = attempt(4);
        machine
            .prepare(scheduled.clone(), 0)
            .expect("scheduled prepare");
        machine
            .transport_lost(&scheduled, 1, RecoveryReason::CandidateTransportLost)
            .expect("scheduled transport loss");
        assert_eq!(machine.phase(), RotationPhase::Recovering);
        assert_eq!(machine.socket_count(), MAX_TOTAL_SOCKETS);
        assert!(matches!(
            machine.reconcile_validated(&scheduled, [ready_verdict(11)], 1),
            Err(RotationError::RecoveryBeginRequired)
        ));
        machine
            .close_for_recovery("data-old", ClosureEvidence::closed("data-old"), 2)
            .expect("old scheduled carrier close");
        machine
            .close_for_recovery("data-4", ClosureEvidence::closed("data-4"), 2)
            .expect("scheduled candidate close");

        let mut recovery = attempt(5);
        recovery.old_connection_id = "data-old".to_owned();
        machine
            .begin_recovery(
                recovery,
                recovery_roster(),
                3,
                RecoveryReason::CandidateTransportLost,
                30,
            )
            .expect("fresh recovery begin");
        machine
            .reserve_recovery_socket(3)
            .expect("fresh recovery reservation");
        assert_eq!(machine.socket_count(), CONTROL_SOCKETS + 1);
    }

    #[test]
    fn recovery_candidate_reservation_is_single_use_and_stale_close_cannot_release_next() {
        let mut machine = state();
        let first = attempt(5);
        machine
            .transport_lost(&first, 0, RecoveryReason::OldTransportLost)
            .expect("old transport loss");
        machine
            .close_for_recovery("data-old", ClosureEvidence::closed("data-old"), 0)
            .expect("old carrier close");
        machine
            .begin_recovery(
                first.clone(),
                recovery_roster(),
                1,
                RecoveryReason::OldTransportLost,
                30,
            )
            .expect("first recovery begin");
        assert!(matches!(
            machine.candidate_closed(
                &first,
                RotationSide::Owner,
                ClosureEvidence::closed("data-5"),
                2,
            ),
            Err(RotationError::RecoverySocketNotReserved)
        ));
        machine
            .reserve_recovery_socket(2)
            .expect("single candidate reservation");
        machine
            .candidate_closed(
                &first,
                RotationSide::Owner,
                ClosureEvidence::closed("data-5"),
                3,
            )
            .expect("first local candidate close");
        machine
            .candidate_closed(
                &first,
                RotationSide::Connector,
                ClosureEvidence::closed("data-5"),
                3,
            )
            .expect("second local candidate close");
        assert!(matches!(
            machine.reserve_recovery_socket(3),
            Err(RotationError::RecoverySocketAlreadyReserved)
        ));

        let second = attempt(6);
        machine
            .begin_recovery(
                second.clone(),
                recovery_roster(),
                4,
                RecoveryReason::CandidateTransportLost,
                30,
            )
            .expect("second recovery begin");
        machine
            .reserve_recovery_socket(4)
            .expect("second candidate reservation");
        assert!(matches!(
            machine.close_for_recovery("data-5", ClosureEvidence::closed("data-5"), 5),
            Err(RotationError::ConnectionMismatch)
        ));
        assert_eq!(machine.socket_count(), CONTROL_SOCKETS + 1);
        assert!(machine.allocated_connections.contains("data-6"));
    }

    #[test]
    fn recovery_cannot_activate_after_either_candidate_side_starts_closing() {
        for side in [RotationSide::Owner, RotationSide::Connector] {
            let mut machine = state();
            let identity = attempt(5);
            machine
                .transport_lost(&identity, 0, RecoveryReason::OldTransportLost)
                .expect("old transport loss");
            machine
                .close_for_recovery("data-old", ClosureEvidence::closed("data-old"), 0)
                .expect("old carrier close");
            machine
                .begin_recovery(
                    identity.clone(),
                    recovery_roster(),
                    1,
                    RecoveryReason::OldTransportLost,
                    30,
                )
                .expect("recovery begin");
            machine
                .reserve_recovery_socket(1)
                .expect("candidate reservation");
            machine
                .candidate_closed(&identity, side, ClosureEvidence::closed("data-5"), 2)
                .expect("one candidate side close");
            assert!(matches!(
                machine.reconcile_validated(&identity, [ready_verdict(11), ready_verdict(12)], 3,),
                Err(RotationError::RecoveryResourcesNotReleased)
            ));
            assert_eq!(machine.phase(), RotationPhase::Recovering);
            assert_eq!(machine.active_generation(), 3);
        }
    }

    #[test]
    fn failed_recovery_verdict_covers_both_stream_directions() {
        let verdict = ValidatedRecovery::failed(11, RecoveryReason::MissingRetainedBytes, true);
        assert!(verdict.is_ready());
        assert_eq!(verdict.replay_ranges(), &[]);
        assert_eq!(verdict.failures.len(), 2);
        assert_eq!(
            verdict
                .failures
                .iter()
                .map(|failure| failure.direction)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([Direction::RelayToConnector, Direction::ConnectorToRelay])
        );
    }

    #[test]
    fn recovery_begin_validates_without_mutating_a_healthy_active_state() {
        let mut machine = state();
        let identity = attempt(5);
        let before = machine.status();
        assert!(matches!(
            machine.begin_recovery(
                identity.clone(),
                StreamRoster::new("bad", vec![11, 11]),
                0,
                RecoveryReason::OldTransportLost,
                30,
            ),
            Err(RotationError::DuplicateRosterStream(11))
        ));
        assert_eq!(machine.phase(), RotationPhase::Active);
        assert_eq!(machine.status(), before);
        assert!(matches!(
            machine.begin_recovery(
                identity,
                StreamRoster::new("ok", vec![]),
                0,
                RecoveryReason::OldTransportLost,
                31,
            ),
            Err(RotationError::RecoveryResourcesNotReleased)
        ));
        assert_eq!(machine.phase(), RotationPhase::Active);
        assert_eq!(machine.active_generation(), 3);
        assert_eq!(machine.socket_count(), CONTROL_SOCKETS + 1);
    }

    #[test]
    fn recovery_timeout_is_capped_at_the_protocol_budget() {
        let config = RotationConfig {
            recovery_timeout_ms: MAX_RECOVERY_TIMEOUT_MS + 1,
            ..RotationConfig::default()
        };
        assert!(matches!(
            RotationState::new("session", "owner", 7, 3, "data-old", config),
            Err(RotationError::InvalidConfig(_))
        ));
    }

    #[test]
    fn recovery_episode_has_one_absolute_budget_and_three_candidates() {
        let mut config = RotationConfig::new(100, 10, 30).expect("valid config");
        config.recovery_timeout_ms = 10;
        let mut machine = RotationState::new("session", "owner", 7, 3, "data-old", config)
            .expect("valid active state");
        let first = attempt(5);
        assert!(matches!(
            machine.begin_recovery(
                first.clone(),
                recovery_roster(),
                0,
                RecoveryReason::OldTransportLost,
                10,
            ),
            Err(RotationError::RecoveryResourcesNotReleased)
        ));
        machine
            .transport_lost(&first, 0, RecoveryReason::OldTransportLost)
            .expect("enter recovery");
        machine
            .close_for_recovery("data-old", ClosureEvidence::closed("data-old"), 0)
            .expect("old close");
        machine
            .begin_recovery(
                first.clone(),
                recovery_roster(),
                1,
                RecoveryReason::OldTransportLost,
                10,
            )
            .expect("first candidate");
        machine.reserve_recovery_socket(1).expect("first socket");
        machine
            .candidate_closed(
                &first,
                RotationSide::Owner,
                ClosureEvidence::closed("data-5"),
                2,
            )
            .expect("first owner close");
        machine
            .candidate_closed(
                &first,
                RotationSide::Connector,
                ClosureEvidence::closed("data-5"),
                3,
            )
            .expect("first connector close");

        let second = attempt(6);
        machine
            .begin_recovery(
                second.clone(),
                recovery_roster(),
                4,
                RecoveryReason::CandidateTransportLost,
                10,
            )
            .expect("second candidate shares episode");
        machine.reserve_recovery_socket(4).expect("second socket");
        machine
            .candidate_closed(
                &second,
                RotationSide::Owner,
                ClosureEvidence::closed("data-6"),
                5,
            )
            .expect("second owner close");
        machine
            .candidate_closed(
                &second,
                RotationSide::Connector,
                ClosureEvidence::closed("data-6"),
                6,
            )
            .expect("second connector close");

        let third = attempt(7);
        machine
            .begin_recovery(
                third.clone(),
                recovery_roster(),
                7,
                RecoveryReason::CandidateTransportLost,
                10,
            )
            .expect("third candidate shares episode");
        machine.reserve_recovery_socket(7).expect("third socket");
        machine
            .candidate_closed(
                &third,
                RotationSide::Owner,
                ClosureEvidence::closed("data-7"),
                8,
            )
            .expect("third owner close");
        machine
            .candidate_closed(
                &third,
                RotationSide::Connector,
                ClosureEvidence::closed("data-7"),
                9,
            )
            .expect("third connector close");

        assert!(matches!(
            machine.begin_recovery(
                attempt(8),
                recovery_roster(),
                9,
                RecoveryReason::CandidateTransportLost,
                11,
            ),
            Err(RotationError::RecoveryDeadlineMismatch {
                expected: 10,
                proposed: 11,
            })
        ));
        assert!(matches!(
            machine.begin_recovery(
                attempt(8),
                recovery_roster(),
                9,
                RecoveryReason::CandidateTransportLost,
                10,
            ),
            Err(RotationError::RecoveryAttemptLimitExceeded { .. })
        ));
        assert!(matches!(
            machine.begin_recovery(
                attempt(8),
                recovery_roster(),
                10,
                RecoveryReason::CandidateTransportLost,
                10,
            ),
            Err(RotationError::RecoveryDeadlineExpired { .. })
        ));
        assert_eq!(machine.phase(), RotationPhase::Recovering);
    }

    #[test]
    fn recovery_reservation_rejects_the_episode_deadline() {
        let mut config = RotationConfig::new(100, 10, 30).expect("valid config");
        config.recovery_timeout_ms = 10;
        let mut machine = RotationState::new("session", "owner", 7, 3, "data-old", config)
            .expect("valid active state");
        let identity = attempt(5);
        assert!(matches!(
            machine.begin_recovery(
                identity.clone(),
                recovery_roster(),
                0,
                RecoveryReason::OldTransportLost,
                10,
            ),
            Err(RotationError::RecoveryResourcesNotReleased)
        ));
        machine
            .transport_lost(&identity, 0, RecoveryReason::OldTransportLost)
            .expect("enter recovery");
        machine
            .close_for_recovery("data-old", ClosureEvidence::closed("data-old"), 0)
            .expect("old close");
        machine
            .begin_recovery(
                identity,
                recovery_roster(),
                1,
                RecoveryReason::OldTransportLost,
                10,
            )
            .expect("begin recovery");
        assert!(matches!(
            machine.reserve_recovery_socket(10),
            Err(RotationError::DeadlineExpired {
                now: 10,
                deadline: 10
            })
        ));
        assert_eq!(machine.socket_count(), CONTROL_SOCKETS);
    }

    #[test]
    fn recovery_requires_sequence_verdicts_for_the_exact_immutable_roster() {
        let mut machine = state();
        let identity = RotationAttemptIdentity {
            session_id: "session".to_owned(),
            epoch: 7,
            owner_id: "owner".to_owned(),
            rotation_id: "recovery-5".to_owned(),
            old_generation: 3,
            new_generation: 5,
            old_connection_id: "data-old".to_owned(),
            new_connection_id: "data-5".to_owned(),
        };
        assert!(matches!(
            machine.begin_recovery(
                identity.clone(),
                recovery_roster(),
                0,
                RecoveryReason::OldTransportLost,
                30,
            ),
            Err(RotationError::RecoveryResourcesNotReleased)
        ));
        machine
            .transport_lost(&identity, 0, RecoveryReason::OldTransportLost)
            .expect("enter recovery");
        machine
            .close_for_recovery("data-old", ClosureEvidence::closed("data-old"), 0)
            .expect("old transport close");
        machine
            .begin_recovery(
                identity.clone(),
                recovery_roster(),
                0,
                RecoveryReason::OldTransportLost,
                30,
            )
            .expect("begin recovery");
        machine
            .reserve_recovery_socket(0)
            .expect("recovery candidate");
        assert!(matches!(
            machine.reconcile_validated(&identity, [ready_verdict(11)], 1),
            Err(RotationError::RecoveryRosterMismatch)
        ));
        let report = machine
            .reconcile_validated(&identity, [ready_verdict(11), ready_verdict(12)], 2)
            .expect("reconcile exact roster");
        assert!(report.replay.is_empty());
        assert!(report.failures.is_empty());
        assert_eq!(machine.phase(), RotationPhase::Active);
        assert_eq!(machine.active_generation(), 5);
    }

    #[test]
    fn recovery_replay_pending_cannot_activate_a_carrier() {
        let mut machine = state();
        let identity = attempt(5);
        assert!(matches!(
            machine.begin_recovery(
                identity.clone(),
                recovery_roster(),
                0,
                RecoveryReason::OldTransportLost,
                30,
            ),
            Err(RotationError::RecoveryResourcesNotReleased)
        ));
        machine
            .transport_lost(&identity, 0, RecoveryReason::OldTransportLost)
            .expect("enter recovery");
        machine
            .close_for_recovery("data-old", ClosureEvidence::closed("data-old"), 0)
            .expect("old close");
        machine
            .begin_recovery(
                identity.clone(),
                recovery_roster(),
                1,
                RecoveryReason::OldTransportLost,
                30,
            )
            .expect("begin recovery");
        machine.reserve_recovery_socket(1).expect("candidate");
        let pending = ValidatedRecovery {
            stream_id: 11,
            replay: vec![ReplayRange {
                stream_id: 11,
                direction: Direction::RelayToConnector,
                first_sequence: 1,
                last_sequence: 2,
            }],
            failures: Vec::new(),
            ready: false,
        };
        assert!(matches!(
            machine.reconcile_validated(&identity, [pending, ready_verdict(12)], 2),
            Err(RotationError::RecoveryReplayPending)
        ));
        assert_eq!(machine.phase(), RotationPhase::Recovering);
    }

    #[test]
    fn overlap_deadline_is_strict_and_socket_bound_is_bounded() {
        let mut machine = state();
        let identity = attempt(4);
        machine.prepare(identity.clone(), 0).expect("prepare");
        assert_eq!(machine.socket_count(), MAX_TOTAL_SOCKETS);
        assert!(matches!(
            machine.candidate_ready(&identity, 30),
            Err(RotationError::DeadlineExpired { .. })
        ));
        assert_eq!(machine.phase(), RotationPhase::Recovering);
        assert_eq!(machine.socket_count(), MAX_TOTAL_SOCKETS);
        assert!(matches!(
            machine.reserve_recovery_socket(30),
            Err(RotationError::DeadlineExpired { .. })
        ));
    }

    #[test]
    fn prepare_deadline_cap_clamps_both_deadlines_and_never_extends_duplicates() {
        let mut machine = state();
        let identity = attempt(4);
        assert!(matches!(
            machine.prepare_with_deadline_cap(identity.clone(), 0, 0),
            Err(RotationError::DeadlineExpired {
                now: 0,
                deadline: 0
            })
        ));
        machine
            .prepare_with_deadline_cap(identity.clone(), 0, 5)
            .expect("short peer deadline starts attempt");
        let attempt_state = machine.attempt.as_ref().expect("attempt state");
        assert_eq!(attempt_state.handshake_deadline_ms, 5);
        assert_eq!(attempt_state.overlap_deadline_ms, 5);
        assert_eq!(machine.status().deadline_ms, Some(5));

        assert_eq!(
            machine
                .prepare_with_deadline_cap(identity.clone(), 1, 99)
                .expect("duplicate prepare coalesces"),
            PrepareResult::Coalesced
        );
        assert_eq!(machine.status().deadline_ms, Some(5));
        assert!(matches!(
            machine.candidate_ready(&identity, 5),
            Err(RotationError::DeadlineExpired {
                now: 5,
                deadline: 5
            })
        ));
    }

    #[test]
    fn recovery_retry_policy_delays_only_bounded_followup_attempts() {
        assert_eq!(RECOVERY_RETRY_DELAYS_MS, [100, 200]);
        assert_eq!(recovery_retry_delay_ms(1), Some(100));
        assert_eq!(recovery_retry_delay_ms(2), Some(200));
        assert_eq!(recovery_retry_delay_ms(3), None);
        assert_eq!(recovery_retry_delay_ms(0), None);
    }
}
