//! Bounded M2 rotation and recovery control contracts.
//!
//! The types in this module are wire values only.  They do not make a
//! decision about a rotation and they do not contain a monotonic timestamp.
//! A caller owns the state machine and supplies a fresh
//! [`RotationAttemptIdentity`] for every attempt.  In particular, the
//! `old_generation` and `new_generation` values fence physical data carriers
//! while the stream sequence space remains logical and unchanged.
//!
//! All 64-bit counters use the decimal-string serde helpers from `control`.
//! Roster and proof collections are deliberately bounded here so a decoded
//! value cannot ask a runtime to allocate an unbounded amount of state.

use core::fmt;

use serde::de::SeqAccess;
use serde::ser::SerializeTuple;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::control::{
    ControlError, MAX_IDENTIFIER_BYTES, MAX_LIST_ENTRIES, MAX_REASON_BYTES,
    MAX_ROTATION_INTERVAL_MS, MAX_ROTATION_OVERLAP_TIMEOUT_MS, MAX_ROTATION_RECOVERY_TIMEOUT_MS,
    decimal_u64,
};
use crate::sequence::Direction;

/// Maximum number of logical streams represented by one rotation roster,
/// fence snapshot, proof or resume state.
pub const MAX_ROTATION_ROSTER_ENTRIES: usize = MAX_LIST_ENTRIES;
/// Maximum number of proof references in a commit (one per direction).
pub const MAX_DRAIN_PROOF_REFERENCES: usize = 2;
/// Maximum number of replay ranges carried by one resume acknowledgement.
pub const MAX_REPLAY_RANGES: usize = MAX_LIST_ENTRIES;
/// Maximum number of physical connections whose closure is attested by one
/// recovery record.
pub const MAX_RECOVERY_CLOSED_CONNECTIONS: usize = 2;
/// Maximum recovery episode attempt number accepted on the wire.
pub const MAX_RECOVERY_ATTEMPT_NO: u64 = 3;

/// Keep the existing sequence direction type on the wire as a stable string.
///
/// This implementation lives next to the rotation contracts so callers can
/// use [`Direction`] directly without a second, wire-only direction enum.
impl Serialize for Direction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match self {
            Self::RelayToConnector => "relay_to_connector",
            Self::ConnectorToRelay => "connector_to_relay",
        })
    }
}

impl<'de> Deserialize<'de> for Direction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match String::deserialize(deserializer)?.as_str() {
            "relay_to_connector" => Ok(Self::RelayToConnector),
            "connector_to_relay" => Ok(Self::ConnectorToRelay),
            value => Err(serde::de::Error::custom(format!(
                "unknown sequence direction {value:?}"
            ))),
        }
    }
}

/// The authenticated endpoint role used when deriving a recovery closure
/// digest.  The role is supplied by the authenticated channel rather than
/// trusted from the recovery message itself.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoverySide {
    Relay,
    Connector,
}

/// A terminal state retained for resume and stream-forget evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum TerminalState {
    Fin,
    Reset { reason: u16 },
}

impl From<crate::sequence::Terminal> for TerminalState {
    fn from(value: crate::sequence::Terminal) -> Self {
        match value {
            crate::sequence::Terminal::Fin => Self::Fin,
            crate::sequence::Terminal::Reset(reason) => Self::Reset { reason },
        }
    }
}

impl From<TerminalState> for crate::sequence::Terminal {
    fn from(value: TerminalState) -> Self {
        match value {
            TerminalState::Fin => Self::Fin,
            TerminalState::Reset { reason } => Self::Reset(reason),
        }
    }
}

/// The immutable identity shared by every message in one rotation attempt.
///
/// This is intentionally separate from a message ID, reply-to ID, deadline,
/// roster, or proof.  A new attempt must use a new rotation ID and a greater
/// candidate generation; an old message cannot be applied to the new attempt
/// merely because its session is still live.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RotationAttemptIdentity {
    pub session_id: String,
    #[serde(with = "decimal_u64")]
    pub epoch: u64,
    pub owner_id: String,
    pub rotation_id: String,
    #[serde(with = "decimal_u64")]
    pub old_generation: u64,
    #[serde(with = "decimal_u64")]
    pub new_generation: u64,
    pub old_connection_id: String,
    pub new_connection_id: String,
}

impl RotationAttemptIdentity {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: impl Into<String>,
        epoch: u64,
        owner_id: impl Into<String>,
        rotation_id: impl Into<String>,
        old_generation: u64,
        new_generation: u64,
        old_connection_id: impl Into<String>,
        new_connection_id: impl Into<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            epoch,
            owner_id: owner_id.into(),
            rotation_id: rotation_id.into(),
            old_generation,
            new_generation,
            old_connection_id: old_connection_id.into(),
            new_connection_id: new_connection_id.into(),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ControlError> {
        validate_id("session_id", &self.session_id)?;
        validate_id("owner_id", &self.owner_id)?;
        validate_id("rotation_id", &self.rotation_id)?;
        validate_id("old_connection_id", &self.old_connection_id)?;
        validate_id("new_connection_id", &self.new_connection_id)?;
        validate_nonzero("epoch", self.epoch)?;
        validate_nonzero("old_generation", self.old_generation)?;
        validate_nonzero("new_generation", self.new_generation)?;
        if self.old_connection_id == self.new_connection_id {
            return Err(ControlError::SameConnection {
                field: "old_connection_id/new_connection_id",
            });
        }
        if self.new_generation <= self.old_generation {
            return Err(ControlError::GenerationNotAdvanced {
                old: self.old_generation,
                new: self.new_generation,
            });
        }
        Ok(())
    }
}

/// One immutable per-stream/per-direction emitted fence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamFence {
    #[serde(with = "decimal_u64")]
    pub stream_id: u64,
    pub direction: Direction,
    #[serde(with = "decimal_u64")]
    pub last_emitted: u64,
}

impl StreamFence {
    #[must_use]
    pub const fn new(stream_id: u64, direction: Direction, last_emitted: u64) -> Self {
        Self {
            stream_id,
            direction,
            last_emitted,
        }
    }

    fn validate(&self) -> Result<(), ControlError> {
        validate_nonzero("stream_id", self.stream_id)
    }
}

/// A bounded immutable fence snapshot for one endpoint direction.
///
/// `entries` contains at most one fence for each stream.  The endpoint sends
/// one snapshot for each local direction; a pure state machine may pair two
/// snapshots under the same `snapshot_id` without putting 256 entries into a
/// single wire value.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FenceSnapshot {
    pub snapshot_id: String,
    pub entries: Vec<StreamFence>,
}

impl FenceSnapshot {
    #[must_use]
    pub fn new(snapshot_id: impl Into<String>, entries: Vec<StreamFence>) -> Self {
        Self {
            snapshot_id: snapshot_id.into(),
            entries,
        }
    }

    /// Return a stable digest for a validated snapshot without retaining any
    /// payload bytes.  The digest is used by [`DrainProof`] as a compact
    /// reference to the immutable fence set.
    pub fn digest(&self) -> Result<String, ControlError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(ControlError::Json)?;
        let digest = Sha256::digest(bytes);
        Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    pub(crate) fn validate(&self) -> Result<(), ControlError> {
        validate_id("snapshot_id", &self.snapshot_id)?;
        if self.entries.len() > MAX_ROTATION_ROSTER_ENTRIES {
            return Err(ControlError::TooManyEntries {
                field: "fence_snapshot.entries",
                maximum: MAX_ROTATION_ROSTER_ENTRIES,
            });
        }
        let mut direction = None;
        let mut previous = 0;
        for entry in &self.entries {
            entry.validate()?;
            if let Some(expected) = direction {
                if entry.direction != expected {
                    return Err(ControlError::MixedFenceDirections);
                }
            } else {
                direction = Some(entry.direction);
            }
            if entry.stream_id <= previous {
                return Err(ControlError::UnorderedEntries {
                    field: "fence_snapshot.entries",
                });
            }
            previous = entry.stream_id;
        }
        Ok(())
    }
}

/// One cumulative receiver acknowledgement in a drain proof.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamAck {
    #[serde(with = "decimal_u64")]
    pub stream_id: u64,
    #[serde(with = "decimal_u64")]
    pub acknowledged: u64,
}

impl StreamAck {
    #[must_use]
    pub const fn new(stream_id: u64, acknowledged: u64) -> Self {
        Self {
            stream_id,
            acknowledged,
        }
    }

    fn validate(&self) -> Result<(), ControlError> {
        validate_nonzero("stream_id", self.stream_id)
    }
}

/// A compact proof that one direction reached every sequence in a fence set.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DrainProof {
    pub snapshot_id: String,
    pub fence_digest: String,
    pub direction: Direction,
    pub ack_cursors: Vec<StreamAck>,
}

impl DrainProof {
    #[must_use]
    pub fn new(
        snapshot_id: impl Into<String>,
        fence_digest: impl Into<String>,
        direction: Direction,
        ack_cursors: Vec<StreamAck>,
    ) -> Self {
        Self {
            snapshot_id: snapshot_id.into(),
            fence_digest: fence_digest.into(),
            direction,
            ack_cursors,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ControlError> {
        validate_id("snapshot_id", &self.snapshot_id)?;
        validate_id("fence_digest", &self.fence_digest)?;
        validate_acks(&self.ack_cursors, "drain_proof.ack_cursors")
    }
}

/// Both endpoint proofs, held together by the state machine after decode.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DrainSet {
    pub relay_to_connector: DrainProof,
    pub connector_to_relay: DrainProof,
}

impl DrainSet {
    pub fn validate(&self) -> Result<(), ControlError> {
        self.relay_to_connector.validate()?;
        self.connector_to_relay.validate()?;
        if self.relay_to_connector.snapshot_id != self.connector_to_relay.snapshot_id {
            return Err(ControlError::MismatchedSnapshot);
        }
        if self.relay_to_connector.direction != Direction::RelayToConnector
            || self.connector_to_relay.direction != Direction::ConnectorToRelay
        {
            return Err(ControlError::MixedFenceDirections);
        }
        Ok(())
    }
}

/// Compact proof reference carried by COMMIT.  The full fence roster is not
/// repeated after each DRAINED message.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DrainProofRef {
    pub snapshot_id: String,
    pub fence_digest: String,
    pub direction: Direction,
}

impl DrainProofRef {
    pub(crate) fn validate(&self) -> Result<(), ControlError> {
        validate_id("snapshot_id", &self.snapshot_id)?;
        validate_id("fence_digest", &self.fence_digest)
    }
}

/// The bounded stream roster fixed during QUIESCE.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamRoster {
    pub snapshot_id: String,
    #[serde(with = "decimal_u64_vec")]
    pub stream_ids: Vec<u64>,
}

impl StreamRoster {
    #[must_use]
    pub fn new(snapshot_id: impl Into<String>, stream_ids: Vec<u64>) -> Self {
        Self {
            snapshot_id: snapshot_id.into(),
            stream_ids,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ControlError> {
        validate_id("snapshot_id", &self.snapshot_id)?;
        if self.stream_ids.len() > MAX_ROTATION_ROSTER_ENTRIES {
            return Err(ControlError::TooManyEntries {
                field: "stream_roster.stream_ids",
                maximum: MAX_ROTATION_ROSTER_ENTRIES,
            });
        }
        let mut previous = 0;
        for stream_id in &self.stream_ids {
            validate_nonzero("stream_id", *stream_id)?;
            if *stream_id <= previous {
                return Err(ControlError::UnorderedEntries {
                    field: "stream_roster.stream_ids",
                });
            }
            previous = *stream_id;
        }
        Ok(())
    }
}

/// One endpoint's complete replay state for one stream direction.
///
/// Resume state is sent per endpoint direction: at most 128 entries are
/// carried by a message.  Short wire names keep the worst case (all counters
/// at `u64::MAX`, with terminal evidence) below the 32 KiB control bound.
/// `recv_contiguous` is the replay cursor.  The other counters are retained
/// so a reconnect cannot silently reduce an observed fence or credit limit.
/// The wire form is a compact 11-item tuple; terminal sequence numbers and
/// the replay floor are losslessly derived from their corresponding cursors.
/// The replay invariant is deliberately strict: while any emitted sequence
/// remains unacknowledged, the retained replay floor is exactly
/// `peer_acked + 1`; after all emitted sequences are acknowledged it is
/// absent.  This avoids an extra wire counter without hiding a missing
/// retained prefix.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResumeDirectionState {
    pub stream_id: u64,
    pub last_emitted: u64,
    pub peer_acked: u64,
    pub recv_contiguous: u64,
    pub delivered_contiguous: u64,
    pub sent_bytes: u64,
    pub received_bytes: u64,
    pub send_credit: u64,
    pub receive_credit: u64,
    pub send_terminal: Option<TerminalState>,
    pub receive_terminal: Option<TerminalState>,
    pub replay_floor: Option<u64>,
}

impl ResumeDirectionState {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        stream_id: u64,
        last_emitted: u64,
        peer_acked: u64,
        recv_contiguous: u64,
        delivered_contiguous: u64,
        sent_bytes: u64,
        received_bytes: u64,
        send_credit: u64,
        receive_credit: u64,
        send_terminal: Option<TerminalState>,
        receive_terminal: Option<TerminalState>,
        replay_floor: Option<u64>,
    ) -> Self {
        Self {
            stream_id,
            last_emitted,
            peer_acked,
            recv_contiguous,
            delivered_contiguous,
            sent_bytes,
            received_bytes,
            send_credit,
            receive_credit,
            send_terminal,
            receive_terminal,
            replay_floor,
        }
    }

    /// Replay floor is derived from the immutable sender ACK: a valid
    /// no-eviction snapshot retains the first unacknowledged sequence.
    #[must_use]
    pub const fn derived_replay_floor(&self) -> Option<u64> {
        if self.last_emitted > self.peer_acked {
            self.peer_acked.checked_add(1)
        } else {
            None
        }
    }

    /// Terminal sequence is derived from the immutable cursor: a valid
    /// terminal is always the last emitted/received sequence in its direction.
    #[must_use]
    pub const fn send_terminal_sequence(&self) -> Option<u64> {
        if self.send_terminal.is_some() {
            Some(self.last_emitted)
        } else {
            None
        }
    }

    #[must_use]
    pub const fn receive_terminal_sequence(&self) -> Option<u64> {
        if self.receive_terminal.is_some() {
            Some(self.recv_contiguous)
        } else {
            None
        }
    }

    /// Convert the sequence module's lossless recovery snapshot into its
    /// bounded wire representation.  Terminal sequence numbers are checked
    /// rather than guessed: the protocol's terminal invariant requires them
    /// to equal the corresponding cursor and derives them on decode.
    pub fn from_sequence_snapshot(
        stream_id: u64,
        snapshot: &crate::sequence::DirectionSnapshot,
    ) -> Result<Self, ControlError> {
        if snapshot.send_terminal.is_some()
            && snapshot.send_terminal_sequence != Some(snapshot.last_emitted)
        {
            return Err(ControlError::TerminalSequenceMismatch {
                field: "send_terminal_sequence",
            });
        }
        if snapshot.receive_terminal.is_some()
            && snapshot.receive_terminal_sequence != Some(snapshot.recv_contiguous)
        {
            return Err(ControlError::TerminalSequenceMismatch {
                field: "receive_terminal_sequence",
            });
        }
        if snapshot.send_terminal.is_none() && snapshot.send_terminal_sequence.is_some() {
            return Err(ControlError::TerminalSequenceMismatch {
                field: "send_terminal_sequence",
            });
        }
        if snapshot.receive_terminal.is_none() && snapshot.receive_terminal_sequence.is_some() {
            return Err(ControlError::TerminalSequenceMismatch {
                field: "receive_terminal_sequence",
            });
        }
        let state = Self::new(
            stream_id,
            snapshot.last_emitted,
            snapshot.peer_acked,
            snapshot.recv_contiguous,
            snapshot.delivered_contiguous,
            snapshot.sent_bytes,
            snapshot.received_bytes,
            snapshot.send_credit,
            snapshot.receive_credit,
            snapshot.send_terminal.map(TerminalState::from),
            snapshot.receive_terminal.map(TerminalState::from),
            snapshot.replay_floor,
        );
        state.validate()?;
        Ok(state)
    }

    fn validate(&self) -> Result<(), ControlError> {
        validate_nonzero("stream_id", self.stream_id)?;
        if self.peer_acked > self.last_emitted {
            return Err(ControlError::CursorBeyondFence {
                field: "peer_acked",
            });
        }
        if self.delivered_contiguous > self.recv_contiguous {
            return Err(ControlError::CursorBeyondFence {
                field: "delivered_contiguous",
            });
        }
        if self.sent_bytes > self.send_credit {
            return Err(ControlError::CreditExceeded {
                field: "sent_bytes",
            });
        }
        if self.received_bytes > self.receive_credit {
            return Err(ControlError::CreditExceeded {
                field: "received_bytes",
            });
        }
        if self.send_terminal.is_some() && self.last_emitted == 0 {
            return Err(ControlError::TerminalWithoutSequence {
                field: "send_terminal",
            });
        }
        if self.receive_terminal.is_some() && self.recv_contiguous == 0 {
            return Err(ControlError::TerminalWithoutSequence {
                field: "receive_terminal",
            });
        }
        if self.replay_floor != self.derived_replay_floor() {
            return Err(ControlError::CursorBeyondFence {
                field: "replay_floor",
            });
        }
        Ok(())
    }
}

impl Serialize for ResumeDirectionState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tuple = serializer.serialize_tuple(11)?;
        tuple.serialize_element(&self.stream_id.to_string())?;
        tuple.serialize_element(&self.last_emitted.to_string())?;
        tuple.serialize_element(&self.peer_acked.to_string())?;
        tuple.serialize_element(&self.recv_contiguous.to_string())?;
        tuple.serialize_element(&self.delivered_contiguous.to_string())?;
        tuple.serialize_element(&self.sent_bytes.to_string())?;
        tuple.serialize_element(&self.received_bytes.to_string())?;
        tuple.serialize_element(&self.send_credit.to_string())?;
        tuple.serialize_element(&self.receive_credit.to_string())?;
        tuple.serialize_element(&compact_terminal(&self.send_terminal))?;
        tuple.serialize_element(&compact_terminal(&self.receive_terminal))?;
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for ResumeDirectionState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StateVisitor;

        impl<'de> serde::de::Visitor<'de> for StateVisitor {
            type Value = ResumeDirectionState;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an 11-element compact resume direction tuple")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let stream_id = next_counter(&mut sequence, "stream_id")?;
                let last_emitted = next_counter(&mut sequence, "last_emitted")?;
                let peer_acked = next_counter(&mut sequence, "peer_acked")?;
                let recv_contiguous = next_counter(&mut sequence, "recv_contiguous")?;
                let delivered_contiguous = next_counter(&mut sequence, "delivered_contiguous")?;
                let sent_bytes = next_counter(&mut sequence, "sent_bytes")?;
                let received_bytes = next_counter(&mut sequence, "received_bytes")?;
                let send_credit = next_counter(&mut sequence, "send_credit")?;
                let receive_credit = next_counter(&mut sequence, "receive_credit")?;
                let send_terminal = next_terminal(&mut sequence, "send_terminal")?;
                let receive_terminal = next_terminal(&mut sequence, "receive_terminal")?;
                if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::custom(
                        "resume direction tuple has more than 11 elements",
                    ));
                }
                Ok(ResumeDirectionState {
                    stream_id,
                    last_emitted,
                    peer_acked,
                    recv_contiguous,
                    delivered_contiguous,
                    sent_bytes,
                    received_bytes,
                    send_credit,
                    receive_credit,
                    send_terminal,
                    receive_terminal,
                    replay_floor: if last_emitted > peer_acked {
                        peer_acked.checked_add(1)
                    } else {
                        None
                    },
                })
            }
        }

        deserializer.deserialize_seq(StateVisitor)
    }
}

fn compact_terminal(value: &Option<TerminalState>) -> Option<String> {
    value.as_ref().map(|terminal| match terminal {
        TerminalState::Fin => "F".to_owned(),
        TerminalState::Reset { reason } => format!("R:{reason}"),
    })
}

fn parse_counter<E>(value: String, field: &'static str) -> Result<u64, E>
where
    E: serde::de::Error,
{
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || (bytes.len() > 1 && bytes[0] == b'0')
        || bytes.iter().any(|byte| !byte.is_ascii_digit())
    {
        return Err(E::custom(format!(
            "{field} must be a canonical decimal u64"
        )));
    }
    value
        .parse::<u64>()
        .map_err(|_| E::custom(format!("{field} is outside the u64 range")))
}

fn next_counter<'de, A>(sequence: &mut A, field: &'static str) -> Result<u64, A::Error>
where
    A: SeqAccess<'de>,
{
    let value = sequence
        .next_element::<String>()?
        .ok_or_else(|| serde::de::Error::custom(format!("missing {field} in resume tuple")))?;
    parse_counter(value, field)
}

fn next_terminal<'de, A>(
    sequence: &mut A,
    field: &'static str,
) -> Result<Option<TerminalState>, A::Error>
where
    A: SeqAccess<'de>,
{
    let Some(value) = sequence.next_element::<Option<String>>()? else {
        return Err(serde::de::Error::custom(format!(
            "missing {field} in resume tuple"
        )));
    };
    let Some(value) = value else {
        return Ok(None);
    };
    if value == "F" {
        return Ok(Some(TerminalState::Fin));
    }
    let Some(reason) = value.strip_prefix("R:") else {
        return Err(serde::de::Error::custom(format!(
            "invalid {field} terminal marker"
        )));
    };
    let bytes = reason.as_bytes();
    if reason.is_empty()
        || (bytes.len() > 1 && bytes[0] == b'0')
        || bytes.iter().any(|byte| !byte.is_ascii_digit())
    {
        return Err(serde::de::Error::custom(format!(
            "invalid {field} reset reason"
        )));
    }
    let reason = reason
        .parse::<u16>()
        .map_err(|_| serde::de::Error::custom(format!("invalid {field} reset reason")))?;
    Ok(Some(TerminalState::Reset { reason }))
}

/// A bounded range that was replayed after resume.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayRange {
    #[serde(with = "decimal_u64")]
    pub stream_id: u64,
    pub direction: Direction,
    #[serde(with = "decimal_u64")]
    pub from: u64,
    #[serde(with = "decimal_u64")]
    pub through: u64,
}

impl ReplayRange {
    fn validate(&self) -> Result<(), ControlError> {
        validate_nonzero("stream_id", self.stream_id)?;
        validate_nonzero("replay.from", self.from)?;
        validate_nonzero("replay.through", self.through)?;
        if self.from > self.through {
            return Err(ControlError::InvalidReplayRange {
                from: self.from,
                through: self.through,
            });
        }
        Ok(())
    }
}

/// The purpose bound to a data attachment ticket.  A recovery attachment is
/// accepted only for the explicitly identified episode and closure evidence;
/// it cannot be replayed as an ordinary rotation candidate.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum DataAttachmentPurpose {
    #[default]
    RotationCandidate,
    Recovery {
        episode_id: String,
        #[serde(with = "crate::control::decimal_u64")]
        attempt_no: u64,
        closure_digest: String,
    },
}

impl DataAttachmentPurpose {
    pub(crate) fn validate(&self) -> Result<(), ControlError> {
        match self {
            Self::RotationCandidate => Ok(()),
            Self::Recovery {
                episode_id,
                attempt_no,
                closure_digest,
            } => {
                validate_id("episode_id", episode_id)?;
                validate_recovery_attempt_no(*attempt_no)?;
                validate_digest("closure_digest", closure_digest)
            }
        }
    }
}

/// RECOVERY_BEGIN starts a bounded recovery episode after explicit closure
/// evidence for the previous data carriers is collected.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBegin {
    pub message_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reply_to: String,
    pub attempt: RotationAttemptIdentity,
    pub episode_id: String,
    #[serde(with = "crate::control::decimal_u64")]
    pub attempt_no: u64,
    pub roster: StreamRoster,
    #[serde(with = "crate::control::decimal_u64")]
    pub remaining_ms: u64,
}

/// RECOVERY_CLOSED attests closure of the old physical carriers.  Its digest
/// is checked against the authenticated endpoint role with
/// [`RecoveryClosed::verify_closure_digest`].
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryClosed {
    pub message_id: String,
    pub reply_to: String,
    pub attempt: RotationAttemptIdentity,
    pub episode_id: String,
    #[serde(with = "crate::control::decimal_u64")]
    pub attempt_no: u64,
    pub closed_connection_ids: Vec<String>,
    pub closure_digest: String,
}

#[derive(Serialize)]
struct RecoveryClosureDigestInput<'a> {
    attempt: &'a RotationAttemptIdentity,
    episode_id: &'a str,
    #[serde(with = "crate::control::decimal_u64")]
    attempt_no: u64,
    side: RecoverySide,
    closed_connection_ids: &'a [String],
}

impl RecoveryClosed {
    /// Derive the role-bound digest without including the stored digest field
    /// in the input.  This lets callers verify an untrusted record without a
    /// self-referential digest computation.
    pub fn closure_digest_for(&self, side: RecoverySide) -> Result<String, ControlError> {
        self.validate_fields()?;
        let canonical = RecoveryClosureDigestInput {
            attempt: &self.attempt,
            episode_id: &self.episode_id,
            attempt_no: self.attempt_no,
            side,
            closed_connection_ids: &self.closed_connection_ids,
        };
        let bytes = serde_json::to_vec(&canonical).map_err(ControlError::Json)?;
        Ok(sha256_hex(&bytes))
    }

    /// Verify this record's digest against the authenticated endpoint role.
    pub fn verify_closure_digest(&self, side: RecoverySide) -> Result<(), ControlError> {
        let expected = self.closure_digest_for(side)?;
        if self.closure_digest != expected {
            return Err(ControlError::InvalidDigest {
                field: "closure_digest",
            });
        }
        Ok(())
    }

    fn validate_fields(&self) -> Result<(), ControlError> {
        self.attempt.validate()?;
        validate_id("episode_id", &self.episode_id)?;
        validate_recovery_attempt_no(self.attempt_no)?;
        validate_closed_connection_ids(&self.closed_connection_ids)
    }
}

/// Verify both role-specific closure records and derive the combined digest
/// carried by a recovery attachment purpose.  The array order is fixed as
/// relay first, connector second.
pub fn combined_closure_digest(
    relay: &RecoveryClosed,
    connector: &RecoveryClosed,
) -> Result<String, ControlError> {
    relay.verify_closure_digest(RecoverySide::Relay)?;
    connector.verify_closure_digest(RecoverySide::Connector)?;
    if relay.attempt != connector.attempt {
        return Err(ControlError::MismatchedRecoveryContext { field: "attempt" });
    }
    if relay.episode_id != connector.episode_id {
        return Err(ControlError::MismatchedRecoveryContext {
            field: "episode_id",
        });
    }
    if relay.attempt_no != connector.attempt_no {
        return Err(ControlError::MismatchedRecoveryContext {
            field: "attempt_no",
        });
    }
    let canonical = [&relay.closure_digest, &connector.closure_digest];
    let bytes = serde_json::to_vec(&canonical).map_err(ControlError::Json)?;
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// ROTATE_REQUEST asks the owner to enter the same serialized rotation
/// state-machine path used by the timer.  It identifies the currently active
/// carrier; the owner allocates the candidate generation and full attempt
/// identity in its response.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RotateRequest {
    pub message_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reply_to: String,
    pub session_id: String,
    #[serde(with = "decimal_u64")]
    pub epoch: u64,
    pub owner_id: String,
    #[serde(with = "decimal_u64")]
    pub generation: u64,
    pub connection_id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::control::optional_decimal_u64"
    )]
    pub desired_interval_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// ROTATE_PREPARE authorizes one candidate attachment.  Ticket and reconnect
/// credentials are opaque and are never exposed by Debug.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RotatePrepare {
    pub message_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reply_to: String,
    pub attempt: RotationAttemptIdentity,
    pub attachment_purpose: DataAttachmentPurpose,
    pub attachment_ticket: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect_credential: Option<String>,
    #[serde(with = "decimal_u64")]
    pub remaining_ms: u64,
}

impl fmt::Debug for RotatePrepare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RotatePrepare")
            .field("message_id", &self.message_id)
            .field("reply_to", &self.reply_to)
            .field("attempt", &self.attempt)
            .field("attachment_purpose", &self.attachment_purpose)
            .field("attachment_ticket", &"<redacted>")
            .field(
                "reconnect_credential",
                &self.reconnect_credential.as_ref().map(|_| "<redacted>"),
            )
            .field("remaining_ms", &self.remaining_ms)
            .finish()
    }
}

/// ROTATE_QUIESCE fixes the bounded roster and pauses new admission.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RotateQuiesce {
    pub message_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reply_to: String,
    pub attempt: RotationAttemptIdentity,
    pub roster: StreamRoster,
    #[serde(with = "decimal_u64")]
    pub remaining_ms: u64,
}

/// ROTATE_FROZEN carries one endpoint's immutable fence snapshot.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RotateFrozen {
    pub message_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reply_to: String,
    pub attempt: RotationAttemptIdentity,
    pub snapshot: FenceSnapshot,
}

/// ROTATE_DRAINED proves receipt through the corresponding immutable fence.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RotateDrained {
    pub message_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reply_to: String,
    pub attempt: RotationAttemptIdentity,
    pub proof: DrainProof,
}

/// ROTATE_COMMIT carries only compact references to the two drain proofs.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RotateCommit {
    pub message_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reply_to: String,
    pub attempt: RotationAttemptIdentity,
    pub snapshot_id: String,
    pub drain_proofs: Vec<DrainProofRef>,
}

/// ROTATE_COMMITTED acknowledges activation of the already-drained candidate.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RotateCommitted {
    pub message_id: String,
    pub reply_to: String,
    pub attempt: RotationAttemptIdentity,
    pub snapshot_id: String,
}

/// ROTATE_RETIRE asks both endpoints to close the old physical transport.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RotateRetire {
    pub message_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reply_to: String,
    pub attempt: RotationAttemptIdentity,
    pub snapshot_id: String,
}

/// ROTATE_RETIRED reports closure of the old connection only.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RotateRetired {
    pub message_id: String,
    pub reply_to: String,
    pub attempt: RotationAttemptIdentity,
    pub snapshot_id: String,
    pub closed_connection_id: String,
}

/// ROTATE_COMPLETE ends an attempt after retirement evidence.  `forced` is
/// explicit so a deadline-forced close is not confused with a clean close.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RotateComplete {
    pub message_id: String,
    pub reply_to: String,
    pub attempt: RotationAttemptIdentity,
    pub snapshot_id: String,
    pub forced: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// ROTATE_ABORT cancels a known-uncommitted candidate.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RotateAbort {
    pub message_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reply_to: String,
    pub attempt: RotationAttemptIdentity,
    pub reason: String,
    #[serde(with = "decimal_u64")]
    pub remaining_ms: u64,
}

/// ROTATE_ABORTED acknowledges candidate release; old writes may resume only
/// after this acknowledgement is processed.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RotateAborted {
    pub message_id: String,
    pub reply_to: String,
    pub attempt: RotationAttemptIdentity,
    pub reason: String,
    pub closed_connection_id: String,
}

/// STREAM_FORGET releases one terminal stream after final cursor evidence.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamForget {
    pub message_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reply_to: String,
    pub session_id: String,
    #[serde(with = "decimal_u64")]
    pub epoch: u64,
    #[serde(with = "decimal_u64")]
    pub stream_id: u64,
    pub operation_id: String,
    pub direction: Direction,
    pub final_state: ResumeDirectionState,
}

/// The fixed two-step recovery handshake stage.  The stage is mandatory on
/// both RESUME and RESUMED so a peer cannot infer readiness from an omitted
/// field or from an empty replay list.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResumeStage {
    #[default]
    Snapshot,
    Ready,
}

/// RESUME reconciles retained cursor, terminal and credit state after a
/// replacement or control reconnect.  The credential is opaque and redacted
/// from Debug.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Resume {
    pub message_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reply_to: String,
    pub attempt: RotationAttemptIdentity,
    pub snapshot_id: String,
    pub stage: ResumeStage,
    pub direction: Direction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect_credential: Option<String>,
    pub entries: Vec<ResumeDirectionState>,
    #[serde(with = "decimal_u64")]
    pub remaining_ms: u64,
}

impl fmt::Debug for Resume {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Resume")
            .field("message_id", &self.message_id)
            .field("reply_to", &self.reply_to)
            .field("attempt", &self.attempt)
            .field("snapshot_id", &self.snapshot_id)
            .field("stage", &self.stage)
            .field(
                "reconnect_credential",
                &self.reconnect_credential.as_ref().map(|_| "<redacted>"),
            )
            .field("entries", &self.entries)
            .field("remaining_ms", &self.remaining_ms)
            .finish()
    }
}

/// RESUMED acknowledges bounded reconciliation and reports replay ranges.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Resumed {
    pub message_id: String,
    pub reply_to: String,
    pub attempt: RotationAttemptIdentity,
    pub snapshot_id: String,
    pub stage: ResumeStage,
    pub direction: Direction,
    pub entries: Vec<ResumeDirectionState>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replay: Vec<ReplayRange>,
}

/// Validate a decoded M2 message's structural fields and bounds.
pub(crate) fn validate_rotate_request(message: &RotateRequest) -> Result<(), ControlError> {
    validate_id("message_id", &message.message_id)?;
    if !message.reply_to.is_empty() {
        validate_id("reply_to", &message.reply_to)?;
    }
    validate_id("session_id", &message.session_id)?;
    validate_id("owner_id", &message.owner_id)?;
    validate_id("connection_id", &message.connection_id)?;
    validate_nonzero("epoch", message.epoch)?;
    validate_nonzero("generation", message.generation)?;
    if let Some(interval) = message.desired_interval_ms {
        validate_nonzero("desired_interval_ms", interval)?;
        if interval > MAX_ROTATION_INTERVAL_MS {
            return Err(ControlError::InvalidRotationPolicy {
                field: "desired_interval_ms",
                reason: "value exceeds the negotiated hard bound",
            });
        }
    }
    if let Some(reason) = &message.reason {
        validate_reason("reason", reason)?;
    }
    Ok(())
}

pub(crate) fn validate_rotate_prepare(message: &RotatePrepare) -> Result<(), ControlError> {
    validate_header(&message.message_id, &message.reply_to, &message.attempt)?;
    message.attachment_purpose.validate()?;
    validate_credential("attachment_ticket", &message.attachment_ticket)?;
    if let Some(credential) = &message.reconnect_credential {
        validate_credential("reconnect_credential", credential)?;
    }
    validate_remaining_ms(message.remaining_ms)
}

pub(crate) fn validate_recovery_begin(message: &RecoveryBegin) -> Result<(), ControlError> {
    validate_header(&message.message_id, &message.reply_to, &message.attempt)?;
    validate_id("episode_id", &message.episode_id)?;
    validate_recovery_attempt_no(message.attempt_no)?;
    message.roster.validate()?;
    validate_recovery_remaining_ms(message.remaining_ms)
}

pub(crate) fn validate_recovery_closed(message: &RecoveryClosed) -> Result<(), ControlError> {
    validate_id("message_id", &message.message_id)?;
    validate_id("reply_to", &message.reply_to)?;
    message.validate_fields()?;
    validate_digest("closure_digest", &message.closure_digest)
}

pub(crate) fn validate_rotate_quiesce(message: &RotateQuiesce) -> Result<(), ControlError> {
    validate_header(&message.message_id, &message.reply_to, &message.attempt)?;
    message.roster.validate()?;
    validate_remaining_ms(message.remaining_ms)
}

pub(crate) fn validate_rotate_frozen(message: &RotateFrozen) -> Result<(), ControlError> {
    validate_reply_header(&message.message_id, &message.reply_to, &message.attempt)?;
    message.snapshot.validate()
}

pub(crate) fn validate_rotate_drained(message: &RotateDrained) -> Result<(), ControlError> {
    validate_reply_header(&message.message_id, &message.reply_to, &message.attempt)?;
    message.proof.validate()
}

pub(crate) fn validate_rotate_commit(message: &RotateCommit) -> Result<(), ControlError> {
    validate_header(&message.message_id, &message.reply_to, &message.attempt)?;
    validate_id("snapshot_id", &message.snapshot_id)?;
    if message.drain_proofs.len() != MAX_DRAIN_PROOF_REFERENCES {
        return Err(ControlError::InvalidProofCount {
            expected: MAX_DRAIN_PROOF_REFERENCES,
            actual: message.drain_proofs.len(),
        });
    }
    let mut directions = None;
    for proof in &message.drain_proofs {
        proof.validate()?;
        if proof.snapshot_id != message.snapshot_id {
            return Err(ControlError::MismatchedSnapshot);
        }
        if let Some(previous) = directions {
            if previous == proof.direction {
                return Err(ControlError::MixedFenceDirections);
            }
        } else {
            directions = Some(proof.direction);
        }
    }
    Ok(())
}

pub(crate) fn validate_rotate_committed(message: &RotateCommitted) -> Result<(), ControlError> {
    validate_reply_header(&message.message_id, &message.reply_to, &message.attempt)?;
    validate_id("snapshot_id", &message.snapshot_id)
}

pub(crate) fn validate_rotate_retire(message: &RotateRetire) -> Result<(), ControlError> {
    validate_header(&message.message_id, &message.reply_to, &message.attempt)?;
    validate_id("snapshot_id", &message.snapshot_id)
}

pub(crate) fn validate_rotate_retired(message: &RotateRetired) -> Result<(), ControlError> {
    validate_reply_header(&message.message_id, &message.reply_to, &message.attempt)?;
    validate_id("snapshot_id", &message.snapshot_id)?;
    if message.closed_connection_id != message.attempt.old_connection_id {
        return Err(ControlError::WrongConnection {
            field: "closed_connection_id",
        });
    }
    Ok(())
}

pub(crate) fn validate_rotate_complete(message: &RotateComplete) -> Result<(), ControlError> {
    validate_reply_header(&message.message_id, &message.reply_to, &message.attempt)?;
    validate_id("snapshot_id", &message.snapshot_id)?;
    if let Some(reason) = &message.reason {
        validate_reason("reason", reason)?;
    }
    Ok(())
}

pub(crate) fn validate_rotate_abort(message: &RotateAbort) -> Result<(), ControlError> {
    validate_header(&message.message_id, &message.reply_to, &message.attempt)?;
    validate_reason("reason", &message.reason)?;
    validate_remaining_ms(message.remaining_ms)
}

pub(crate) fn validate_rotate_aborted(message: &RotateAborted) -> Result<(), ControlError> {
    validate_reply_header(&message.message_id, &message.reply_to, &message.attempt)?;
    validate_reason("reason", &message.reason)?;
    validate_id("closed_connection_id", &message.closed_connection_id)?;
    if message.closed_connection_id != message.attempt.new_connection_id {
        return Err(ControlError::WrongConnection {
            field: "closed_connection_id",
        });
    }
    Ok(())
}

pub(crate) fn validate_stream_forget(message: &StreamForget) -> Result<(), ControlError> {
    validate_id("message_id", &message.message_id)?;
    if !message.reply_to.is_empty() {
        validate_id("reply_to", &message.reply_to)?;
    }
    validate_id("session_id", &message.session_id)?;
    validate_nonzero("epoch", message.epoch)?;
    validate_nonzero("stream_id", message.stream_id)?;
    validate_id("operation_id", &message.operation_id)?;
    message.final_state.validate()?;
    if message.final_state.stream_id != message.stream_id {
        return Err(ControlError::MismatchedStream);
    }
    Ok(())
}

pub(crate) fn validate_resume(message: &Resume) -> Result<(), ControlError> {
    validate_header(&message.message_id, &message.reply_to, &message.attempt)?;
    validate_id("snapshot_id", &message.snapshot_id)?;
    if let Some(credential) = &message.reconnect_credential {
        validate_credential("reconnect_credential", credential)?;
    }
    validate_recovery_remaining_ms(message.remaining_ms)?;
    validate_resume_entries(&message.entries, message.direction)
}

pub(crate) fn validate_resumed(message: &Resumed) -> Result<(), ControlError> {
    validate_reply_header(&message.message_id, &message.reply_to, &message.attempt)?;
    validate_id("snapshot_id", &message.snapshot_id)?;
    validate_resume_entries(&message.entries, message.direction)?;
    if message.replay.len() > MAX_REPLAY_RANGES {
        return Err(ControlError::TooManyEntries {
            field: "resumed.replay",
            maximum: MAX_REPLAY_RANGES,
        });
    }
    for range in &message.replay {
        range.validate()?;
    }
    if message.stage == ResumeStage::Ready && !message.replay.is_empty() {
        return Err(ControlError::InvalidRecoveryStage { field: "replay" });
    }
    Ok(())
}

fn validate_header(
    message_id: &str,
    reply_to: &str,
    attempt: &RotationAttemptIdentity,
) -> Result<(), ControlError> {
    validate_id("message_id", message_id)?;
    if !reply_to.is_empty() {
        validate_id("reply_to", reply_to)?;
    }
    attempt.validate()
}

fn validate_reply_header(
    message_id: &str,
    reply_to: &str,
    attempt: &RotationAttemptIdentity,
) -> Result<(), ControlError> {
    validate_id("message_id", message_id)?;
    validate_id("reply_to", reply_to)?;
    attempt.validate()
}

fn validate_resume_entries(
    entries: &[ResumeDirectionState],
    _direction: Direction,
) -> Result<(), ControlError> {
    if entries.len() > MAX_ROTATION_ROSTER_ENTRIES {
        return Err(ControlError::TooManyEntries {
            field: "resume.entries",
            maximum: MAX_ROTATION_ROSTER_ENTRIES,
        });
    }
    let mut previous = 0;
    for entry in entries {
        entry.validate()?;
        if entry.stream_id <= previous {
            return Err(ControlError::UnorderedEntries {
                field: "resume.entries",
            });
        }
        previous = entry.stream_id;
    }
    Ok(())
}

fn validate_acks(acks: &[StreamAck], field: &'static str) -> Result<(), ControlError> {
    if acks.len() > MAX_ROTATION_ROSTER_ENTRIES {
        return Err(ControlError::TooManyEntries {
            field,
            maximum: MAX_ROTATION_ROSTER_ENTRIES,
        });
    }
    let mut previous = 0;
    for ack in acks {
        ack.validate()?;
        if ack.stream_id <= previous {
            return Err(ControlError::UnorderedEntries { field });
        }
        previous = ack.stream_id;
    }
    Ok(())
}

fn validate_id(field: &'static str, value: &str) -> Result<(), ControlError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(ControlError::InvalidIdentifier {
            field,
            length: value.len(),
            maximum: MAX_IDENTIFIER_BYTES,
        });
    }
    Ok(())
}

fn validate_credential(field: &'static str, value: &str) -> Result<(), ControlError> {
    if value.is_empty()
        || value.len() > crate::control::MAX_CREDENTIAL_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ControlError::InvalidCredential {
            field,
            length: value.len(),
            maximum: crate::control::MAX_CREDENTIAL_BYTES,
        });
    }
    Ok(())
}

fn validate_reason(field: &'static str, value: &str) -> Result<(), ControlError> {
    if value.is_empty() || value.len() > MAX_REASON_BYTES || value.chars().any(char::is_control) {
        return Err(ControlError::ValueTooLong {
            field,
            length: value.len(),
            maximum: MAX_REASON_BYTES,
        });
    }
    Ok(())
}

fn validate_nonzero(field: &'static str, value: u64) -> Result<(), ControlError> {
    if value == 0 {
        return Err(ControlError::ZeroCounter { field });
    }
    Ok(())
}

fn validate_remaining_ms(value: u64) -> Result<(), ControlError> {
    validate_bounded_duration("remaining_ms", value, MAX_ROTATION_OVERLAP_TIMEOUT_MS)
}

fn validate_recovery_remaining_ms(value: u64) -> Result<(), ControlError> {
    validate_bounded_duration("remaining_ms", value, MAX_ROTATION_RECOVERY_TIMEOUT_MS)
}

fn validate_bounded_duration(
    field: &'static str,
    value: u64,
    maximum: u64,
) -> Result<(), ControlError> {
    validate_nonzero(field, value)?;
    if value > maximum {
        return Err(ControlError::InvalidRotationPolicy {
            field,
            reason: "duration exceeds the negotiated hard bound",
        });
    }
    Ok(())
}

fn validate_recovery_attempt_no(value: u64) -> Result<(), ControlError> {
    if !(1..=MAX_RECOVERY_ATTEMPT_NO).contains(&value) {
        return Err(ControlError::InvalidRotationPolicy {
            field: "attempt_no",
            reason: "must be between 1 and 3",
        });
    }
    Ok(())
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), ControlError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ControlError::InvalidDigest { field });
    }
    Ok(())
}

fn validate_closed_connection_ids(values: &[String]) -> Result<(), ControlError> {
    if values.len() > MAX_RECOVERY_CLOSED_CONNECTIONS {
        return Err(ControlError::TooManyEntries {
            field: "recovery.closed_connection_ids",
            maximum: MAX_RECOVERY_CLOSED_CONNECTIONS,
        });
    }
    let mut previous = None;
    for value in values {
        validate_id("closed_connection_id", value)?;
        if let Some(previous) = previous
            && value.as_str() <= previous
        {
            return Err(ControlError::UnorderedEntries {
                field: "recovery.closed_connection_ids",
            });
        }
        previous = Some(value.as_str());
    }
    Ok(())
}

/// Decimal-string serialization for a bounded vector of u64 stream IDs.
mod decimal_u64_vec {
    use super::*;

    pub fn serialize<S>(values: &[u64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        values
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<String>::deserialize(deserializer)?;
        values
            .into_iter()
            .map(|value| {
                crate::control::decimal_u64::deserialize(serde::de::value::StringDeserializer::<
                    D::Error,
                >::new(value))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{
        ControlMessage, MAX_CONTROL_MESSAGE_BYTES, decode_control, encode_control,
    };

    fn attempt() -> RotationAttemptIdentity {
        RotationAttemptIdentity::new("session", 7, "owner", "rotation", 3, 4, "old", "new")
    }

    fn worst_attempt() -> RotationAttemptIdentity {
        RotationAttemptIdentity::new(
            "s".repeat(64),
            u64::MAX,
            "o".repeat(64),
            "r".repeat(64),
            u64::MAX - 1,
            u64::MAX,
            "a".repeat(64),
            "b".repeat(64),
        )
    }

    fn direction_state(_direction: Direction, stream_id: u64) -> ResumeDirectionState {
        ResumeDirectionState::new(
            stream_id,
            11,
            8,
            7,
            7,
            1024,
            768,
            4096 + stream_id,
            4096 + stream_id,
            Some(TerminalState::Fin),
            Some(TerminalState::Fin),
            Some(9),
        )
    }

    fn worst_direction_state(stream_id: u64) -> ResumeDirectionState {
        ResumeDirectionState::new(
            stream_id,
            u64::MAX,
            u64::MAX - 1,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            Some(TerminalState::Reset { reason: u16::MAX }),
            Some(TerminalState::Reset { reason: u16::MAX }),
            Some(u64::MAX),
        )
    }

    #[test]
    fn rotation_identity_and_fence_round_trip() {
        let message = ControlMessage::RotateFrozen(RotateFrozen {
            message_id: "m-frozen".to_owned(),
            reply_to: "m-quiesce".to_owned(),
            attempt: attempt(),
            snapshot: FenceSnapshot::new(
                "snapshot",
                vec![
                    StreamFence::new(1, Direction::RelayToConnector, u64::MAX),
                    StreamFence::new(2, Direction::RelayToConnector, 8),
                ],
            ),
        });
        let encoded = encode_control(&message).expect("valid frozen");
        let json = String::from_utf8(encoded.clone()).expect("utf8");
        assert!(json.contains("\"old_generation\":\"3\""));
        assert!(json.contains("\"last_emitted\":\"18446744073709551615\""));
        assert!(json.contains("\"direction\":\"relay_to_connector\""));
        assert_eq!(decode_control(&encoded).expect("round trip"), message);
    }

    #[test]
    fn resume_uses_decimal_counters_and_redacts_credentials() {
        let message = ControlMessage::Resume(Resume {
            message_id: "m-resume".to_owned(),
            reply_to: String::new(),
            attempt: attempt(),
            snapshot_id: "snapshot".to_owned(),
            stage: ResumeStage::Snapshot,
            direction: Direction::RelayToConnector,
            reconnect_credential: Some("secret-reconnect".to_owned()),
            entries: (1..=2)
                .map(|stream_id| direction_state(Direction::RelayToConnector, stream_id))
                .collect(),
            remaining_ms: 30_000,
        });
        let encoded = encode_control(&message).expect("valid resume");
        let json = String::from_utf8(encoded.clone()).expect("utf8");
        assert!(json.contains("\"11\""));
        assert_eq!(decode_control(&encoded).expect("round trip"), message);
        assert!(format!("{message:?}").contains("<redacted>"));
        assert!(!format!("{message:?}").contains("secret-reconnect"));
    }

    #[test]
    fn full_roster_stays_within_control_bound() {
        let first_stream = u64::MAX - 127;
        let streams = (0..128)
            .map(|offset| worst_direction_state(first_stream + offset))
            .collect();
        let message = ControlMessage::Resume(Resume {
            message_id: "m".repeat(64),
            reply_to: String::new(),
            attempt: worst_attempt(),
            snapshot_id: "x".repeat(64),
            stage: ResumeStage::Snapshot,
            direction: Direction::RelayToConnector,
            reconnect_credential: None,
            entries: streams,
            remaining_ms: 30_000,
        });
        let encoded = encode_control(&message).expect("128 streams fit bound");
        assert!(encoded.len() <= MAX_CONTROL_MESSAGE_BYTES);
        assert_eq!(
            decode_control(&encoded).expect("worst-case round trip"),
            message
        );
    }

    #[test]
    fn identity_drain_and_resume_invariants_reject_false_evidence() {
        let mut same_connection = attempt();
        same_connection.new_connection_id = same_connection.old_connection_id.clone();
        let same_connection_message = ControlMessage::RotateFrozen(RotateFrozen {
            message_id: "m".to_owned(),
            reply_to: "quiesce".to_owned(),
            attempt: same_connection,
            snapshot: FenceSnapshot::new("snapshot", Vec::new()),
        });
        assert!(matches!(
            encode_control(&same_connection_message),
            Err(ControlError::SameConnection { .. })
        ));

        let wrong_direction = DrainSet {
            relay_to_connector: DrainProof::new(
                "snapshot",
                "digest",
                Direction::ConnectorToRelay,
                Vec::new(),
            ),
            connector_to_relay: DrainProof::new(
                "snapshot",
                "digest",
                Direction::ConnectorToRelay,
                Vec::new(),
            ),
        };
        assert!(matches!(
            wrong_direction.validate(),
            Err(ControlError::MixedFenceDirections)
        ));

        let over_credit = ResumeDirectionState::new(1, 2, 0, 0, 0, 2, 0, 1, 1, None, None, Some(1));
        assert!(matches!(
            over_credit.validate(),
            Err(ControlError::CreditExceeded {
                field: "sent_bytes"
            })
        ));
    }

    #[test]
    fn rotate_request_desired_interval_is_bounded() {
        let request = ControlMessage::RotateRequest(RotateRequest {
            message_id: "request".to_owned(),
            reply_to: String::new(),
            session_id: "session".to_owned(),
            epoch: 7,
            owner_id: "owner".to_owned(),
            generation: 3,
            connection_id: "old".to_owned(),
            desired_interval_ms: Some(MAX_ROTATION_INTERVAL_MS + 1),
            reason: None,
        });
        assert!(matches!(
            encode_control(&request),
            Err(ControlError::InvalidRotationPolicy {
                field: "desired_interval_ms",
                ..
            })
        ));
    }

    #[test]
    fn malformed_and_unbounded_rotation_values_are_rejected() {
        let too_many = FenceSnapshot::new(
            "snapshot",
            (1..=129)
                .map(|stream_id| StreamFence::new(stream_id, Direction::RelayToConnector, 1))
                .collect(),
        );
        let message = ControlMessage::RotateFrozen(RotateFrozen {
            message_id: "m".to_owned(),
            reply_to: "quiesce".to_owned(),
            attempt: attempt(),
            snapshot: too_many,
        });
        assert!(matches!(
            encode_control(&message),
            Err(ControlError::TooManyEntries { .. })
        ));

        let malformed = br#"{"type":"ROTATE_ABORT","message_id":"m","attempt":{"session_id":"s","epoch":"1","owner_id":"o","rotation_id":"r","old_generation":"2","new_generation":"3","old_connection_id":"old","new_connection_id":"new"},"reason":"x","remaining_ms":1}"#;
        assert!(matches!(
            decode_control(malformed),
            Err(ControlError::Json(_))
        ));
    }

    #[test]
    fn credentials_are_redacted_from_prepare_debug() {
        let message = RotatePrepare {
            message_id: "m".to_owned(),
            reply_to: String::new(),
            attempt: attempt(),
            attachment_purpose: DataAttachmentPurpose::RotationCandidate,
            attachment_ticket: "secret-ticket".to_owned(),
            reconnect_credential: Some("secret-credential".to_owned()),
            remaining_ms: 1,
        };
        let debug = format!("{message:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret-ticket"));
        assert!(!debug.contains("secret-credential"));
    }

    fn recovery_closed(side: RecoverySide, ids: Vec<String>) -> RecoveryClosed {
        let mut message = RecoveryClosed {
            message_id: format!("closed-{side:?}"),
            reply_to: "begin".to_owned(),
            attempt: attempt(),
            episode_id: "episode".to_owned(),
            attempt_no: 1,
            closed_connection_ids: ids,
            closure_digest: String::new(),
        };
        let digest = message
            .closure_digest_for(side)
            .expect("valid closure digest input");
        message.closure_digest = digest;
        message
    }

    #[test]
    fn recovery_closure_digest_is_role_bound_and_combined() {
        let relay = recovery_closed(
            RecoverySide::Relay,
            vec!["old-control".to_owned(), "old-data".to_owned()],
        );
        let connector = recovery_closed(RecoverySide::Connector, vec!["old-data".to_owned()]);
        assert!(relay.verify_closure_digest(RecoverySide::Relay).is_ok());
        assert!(
            relay
                .verify_closure_digest(RecoverySide::Connector)
                .is_err()
        );
        let combined = combined_closure_digest(&relay, &connector).expect("matching closure proof");

        let message = ControlMessage::RotatePrepare(RotatePrepare {
            message_id: "prepare-recovery".to_owned(),
            reply_to: "begin".to_owned(),
            attempt: attempt(),
            attachment_purpose: DataAttachmentPurpose::Recovery {
                episode_id: "episode".to_owned(),
                attempt_no: 1,
                closure_digest: combined,
            },
            attachment_ticket: "ticket".to_owned(),
            reconnect_credential: None,
            remaining_ms: 1,
        });
        let encoded = encode_control(&message).expect("valid recovery purpose");
        assert_eq!(decode_control(&encoded).expect("round trip"), message);
    }

    #[test]
    fn recovery_messages_and_resume_stages_are_bounded_and_typed() {
        let begin = ControlMessage::RecoveryBegin(RecoveryBegin {
            message_id: "recovery-begin".to_owned(),
            reply_to: String::new(),
            attempt: attempt(),
            episode_id: "episode".to_owned(),
            attempt_no: 2,
            roster: StreamRoster::new("snapshot", vec![1, 2]),
            remaining_ms: 30_000,
        });
        let encoded = encode_control(&begin).expect("valid recovery begin");
        let json = String::from_utf8(encoded.clone()).expect("utf8");
        assert!(json.contains("\"attempt_no\":\"2\""));
        assert_eq!(decode_control(&encoded).expect("round trip"), begin);

        let relay = recovery_closed(RecoverySide::Relay, vec!["old".to_owned()]);
        let closed = ControlMessage::RecoveryClosed(relay.clone());
        let encoded = encode_control(&closed).expect("valid recovery closed");
        assert_eq!(decode_control(&encoded).expect("round trip"), closed);

        let resumed = ControlMessage::Resumed(Resumed {
            message_id: "resumed".to_owned(),
            reply_to: "resume".to_owned(),
            attempt: attempt(),
            snapshot_id: "snapshot".to_owned(),
            stage: ResumeStage::Ready,
            direction: Direction::RelayToConnector,
            entries: Vec::new(),
            replay: Vec::new(),
        });
        assert_eq!(
            decode_control(&encode_control(&resumed).expect("ready resumed"))
                .expect("ready round trip"),
            resumed
        );
    }

    #[test]
    fn ready_resumed_replay_and_recovery_bounds_are_rejected() {
        let replay = ControlMessage::Resumed(Resumed {
            message_id: "resumed".to_owned(),
            reply_to: "resume".to_owned(),
            attempt: attempt(),
            snapshot_id: "snapshot".to_owned(),
            stage: ResumeStage::Ready,
            direction: Direction::RelayToConnector,
            entries: Vec::new(),
            replay: vec![ReplayRange {
                stream_id: 1,
                direction: Direction::RelayToConnector,
                from: 1,
                through: 1,
            }],
        });
        assert!(matches!(
            encode_control(&replay),
            Err(ControlError::InvalidRecoveryStage { field: "replay" })
        ));

        let mut closed = recovery_closed(RecoverySide::Relay, vec!["a".to_owned(), "b".to_owned()]);
        closed.closed_connection_ids.reverse();
        closed.closure_digest = "0".repeat(64);
        assert!(matches!(
            encode_control(&ControlMessage::RecoveryClosed(closed)),
            Err(ControlError::UnorderedEntries { .. })
        ));

        let begin = ControlMessage::RecoveryBegin(RecoveryBegin {
            message_id: "begin".to_owned(),
            reply_to: String::new(),
            attempt: attempt(),
            episode_id: "episode".to_owned(),
            attempt_no: 4,
            roster: StreamRoster::new("snapshot", Vec::new()),
            remaining_ms: 1,
        });
        assert!(matches!(
            encode_control(&begin),
            Err(ControlError::InvalidRotationPolicy {
                field: "attempt_no",
                ..
            })
        ));
    }
}
