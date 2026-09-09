//! Pure per-stream, per-direction sequence, replay, and credit accounting.
//!
//! This module deliberately knows nothing about sockets, rotations, epochs,
//! or adapter execution. A caller validates the decoded frame's authenticated
//! [`crate::frame::DataContext`] first, then passes it to [`StreamState`].
//!
//! Sequence numbers are logical stream state. The epoch and generation on a
//! [`Frame`] identify its carrier, but never reset a logical counter. The
//! state below is therefore suitable for both scheduled handover and bounded
//! retained-state recovery without allowing either operation to replay an
//! application effect automatically.

use core::fmt;
use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::frame::{Frame, FrameError, FrameKind, MAX_PAYLOAD_LEN};

/// The two independent logical sequence spaces in a stream.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Direction {
    #[default]
    RelayToConnector,
    ConnectorToRelay,
}

impl Direction {
    /// Return the opposite logical direction.
    #[must_use]
    pub const fn opposite(self) -> Self {
        match self {
            Self::RelayToConnector => Self::ConnectorToRelay,
            Self::ConnectorToRelay => Self::RelayToConnector,
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::RelayToConnector => 0,
            Self::ConnectorToRelay => 1,
        }
    }
}

/// Terminal state for one logical direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Terminal {
    Fin,
    Reset(u16),
}

/// Bounds applied independently to each direction of a logical stream.
///
/// Replay retains unacknowledged sequenced frames. Reorder bounds include
/// both frames waiting for a gap to close and contiguous frames waiting for
/// the adapter to accept them. Two terminal slots (FIN plus one RESET) have
/// reserved capacity in each bound so exhausted DATA capacity cannot prevent
/// a bounded FIN/RESET transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SequenceLimits {
    pub max_replay_frames: usize,
    pub max_replay_bytes: usize,
    pub max_reorder_frames: usize,
    pub max_reorder_bytes: usize,
}

/// Default retained frame count for one direction.
pub const DEFAULT_MAX_REPLAY_FRAMES: usize = 128;
/// Default retained replay payload budget for one direction.
pub const DEFAULT_MAX_REPLAY_BYTES: usize = 1024 * 1024;
/// Default number of receive-side frames held for reordering or delivery.
pub const DEFAULT_MAX_REORDER_FRAMES: usize = 128;
/// Default receive-side reorder/delivery payload budget for one direction.
pub const DEFAULT_MAX_REORDER_BYTES: usize = 1024 * 1024;
/// Hard maximum negotiated replay frame count per direction.
pub const MAX_REPLAY_FRAMES: usize = 128;
/// Hard maximum negotiated replay payload bytes per direction.
pub const MAX_REPLAY_BYTES: usize = 1024 * 1024;
/// Hard maximum negotiated receive-side frame count per direction.
pub const MAX_REORDER_FRAMES: usize = 128;
/// Hard maximum negotiated receive-side payload bytes per direction.
pub const MAX_REORDER_BYTES: usize = 1024 * 1024;

impl Default for SequenceLimits {
    fn default() -> Self {
        Self {
            max_replay_frames: DEFAULT_MAX_REPLAY_FRAMES,
            max_replay_bytes: DEFAULT_MAX_REPLAY_BYTES,
            max_reorder_frames: DEFAULT_MAX_REORDER_FRAMES,
            max_reorder_bytes: DEFAULT_MAX_REORDER_BYTES,
        }
    }
}

impl SequenceLimits {
    /// Construct explicit bounds for replay and receive-side buffering.
    #[must_use]
    pub const fn new(
        max_replay_frames: usize,
        max_replay_bytes: usize,
        max_reorder_frames: usize,
        max_reorder_bytes: usize,
    ) -> Self {
        Self {
            max_replay_frames,
            max_replay_bytes,
            max_reorder_frames,
            max_reorder_bytes,
        }
    }

    fn validate(self) -> Result<(), SequenceError> {
        for (field, requested, maximum) in [
            (
                "max_replay_frames",
                self.max_replay_frames,
                MAX_REPLAY_FRAMES,
            ),
            ("max_replay_bytes", self.max_replay_bytes, MAX_REPLAY_BYTES),
            (
                "max_reorder_frames",
                self.max_reorder_frames,
                MAX_REORDER_FRAMES,
            ),
            (
                "max_reorder_bytes",
                self.max_reorder_bytes,
                MAX_REORDER_BYTES,
            ),
        ] {
            if requested > maximum {
                return Err(SequenceError::LimitsExceeded {
                    field,
                    requested,
                    maximum,
                });
            }
        }
        Ok(())
    }
}

/// Result of receiving a sequenced frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveDisposition {
    /// The frame advanced the contiguous receive cursor and is available from
    /// [`StreamState::ready_frames`] for one adapter delivery.
    Accepted,
    /// The frame was accepted into the bounded gap buffer. It is not ready
    /// for adapter delivery until all preceding sequences arrive.
    Buffered,
    /// The sequence was already received. It must not be delivered a second
    /// time and consumes no credit. If the bounded fingerprint retention
    /// window has expired, this is a transport-level duplicate decision and
    /// does not claim that the newly presented payload bytes are identical.
    Duplicate,
}

/// A closed inclusive logical sequence range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SequenceRange {
    from: u64,
    through: u64,
}

impl SequenceRange {
    /// Construct a nonempty sequence range.
    pub fn new(from: u64, through: u64) -> Result<Self, SequenceError> {
        if from == 0 || through == 0 || from > through {
            return Err(SequenceError::InvalidReplayRange { from, through });
        }
        Ok(Self { from, through })
    }

    #[must_use]
    pub const fn from(self) -> u64 {
        self.from
    }

    #[must_use]
    pub const fn through(self) -> u64 {
        self.through
    }

    #[must_use]
    pub const fn len(self) -> u64 {
        self.through.saturating_sub(self.from).saturating_add(1)
    }

    /// A successfully constructed inclusive range is always nonempty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        false
    }
}

/// A bounded view of one direction's sequence, credit, and retained-frame
/// state.
#[derive(Clone, Debug)]
pub struct DirectionState {
    limits: SequenceLimits,
    last_emitted: u64,
    peer_acked: u64,
    recv_contiguous: u64,
    delivered_contiguous: u64,
    send_credit: u64,
    sent_bytes: u64,
    receive_credit: u64,
    received_bytes: u64,
    send_terminal: Option<Terminal>,
    send_terminal_sequence: Option<u64>,
    receive_terminal: Option<Terminal>,
    receive_terminal_sequence: Option<u64>,
    /// Fingerprints of recently received logical frames. Payload bytes are
    /// never retained in this map.
    fingerprints: BTreeMap<u64, FrameFingerprint>,
    /// Unacknowledged frames retained for recovery replay.
    replay: BTreeMap<u64, Frame>,
    replay_bytes: usize,
    /// Frames received above the contiguous cursor.
    reorder: BTreeMap<u64, Frame>,
    reorder_bytes: usize,
    /// Contiguous frames retained until the adapter confirms handoff.
    ready: BTreeMap<u64, Frame>,
    ready_bytes: usize,
}

impl DirectionState {
    /// Maximum duplicate metadata retained per direction. Retaining a bounded
    /// digest map detects changed immediate/recent duplicates without
    /// retaining application payloads.
    pub const MAX_RETAINED_FINGERPRINTS: usize = 128;

    fn new(send_credit: u64, receive_credit: u64, limits: SequenceLimits) -> Self {
        Self {
            limits,
            last_emitted: 0,
            peer_acked: 0,
            recv_contiguous: 0,
            delivered_contiguous: 0,
            send_credit,
            sent_bytes: 0,
            receive_credit,
            received_bytes: 0,
            send_terminal: None,
            send_terminal_sequence: None,
            receive_terminal: None,
            receive_terminal_sequence: None,
            fingerprints: BTreeMap::new(),
            replay: BTreeMap::new(),
            replay_bytes: 0,
            reorder: BTreeMap::new(),
            reorder_bytes: 0,
            ready: BTreeMap::new(),
            ready_bytes: 0,
        }
    }

    #[must_use]
    pub const fn limits(&self) -> SequenceLimits {
        self.limits
    }

    #[must_use]
    pub const fn last_emitted(&self) -> u64 {
        self.last_emitted
    }

    #[must_use]
    pub const fn peer_acked(&self) -> u64 {
        self.peer_acked
    }

    #[must_use]
    pub const fn recv_contiguous(&self) -> u64 {
        self.recv_contiguous
    }

    #[must_use]
    pub const fn delivered_contiguous(&self) -> u64 {
        self.delivered_contiguous
    }

    #[must_use]
    pub const fn send_credit(&self) -> u64 {
        self.send_credit
    }

    #[must_use]
    pub const fn sent_bytes(&self) -> u64 {
        self.sent_bytes
    }

    #[must_use]
    pub const fn receive_credit(&self) -> u64 {
        self.receive_credit
    }

    #[must_use]
    pub const fn received_bytes(&self) -> u64 {
        self.received_bytes
    }

    #[must_use]
    pub const fn send_terminal(&self) -> Option<Terminal> {
        self.send_terminal
    }

    #[must_use]
    pub const fn send_terminal_sequence(&self) -> Option<u64> {
        self.send_terminal_sequence
    }

    #[must_use]
    pub const fn receive_terminal(&self) -> Option<Terminal> {
        self.receive_terminal
    }

    #[must_use]
    pub const fn receive_terminal_sequence(&self) -> Option<u64> {
        self.receive_terminal_sequence
    }

    #[must_use]
    pub fn replay_len(&self) -> usize {
        self.replay.len()
    }

    #[must_use]
    pub const fn replay_bytes(&self) -> usize {
        self.replay_bytes
    }

    /// Return the oldest retained replay sequence, if any.
    #[must_use]
    pub fn replay_floor(&self) -> Option<u64> {
        self.replay.keys().next().copied()
    }

    #[must_use]
    pub fn replay_range(&self) -> Option<SequenceRange> {
        let from = self.replay.keys().next().copied()?;
        let through = self.replay.keys().next_back().copied()?;
        Some(SequenceRange { from, through })
    }

    #[must_use]
    pub fn reorder_len(&self) -> usize {
        self.reorder.len()
    }

    #[must_use]
    pub const fn reorder_bytes(&self) -> usize {
        self.reorder_bytes
    }

    /// Number of contiguous frames retained for adapter handoff.
    #[must_use]
    pub fn ready_len(&self) -> usize {
        self.ready.len()
    }

    #[must_use]
    pub const fn ready_bytes(&self) -> usize {
        self.ready_bytes
    }

    /// Return a bounded, sequence-ordered copy of frames ready for delivery.
    /// Calling this method does not mark the frames delivered.
    #[must_use]
    pub fn ready_frames(&self) -> Vec<Frame> {
        self.ready.values().cloned().collect()
    }

    /// Borrow ready records in sequence order without cloning payloads.
    pub fn ready_iter(&self) -> impl Iterator<Item = &Frame> {
        self.ready.values()
    }

    fn apply_ack(&mut self, ack: u64) -> Result<(), SequenceError> {
        if ack > self.last_emitted {
            return Err(SequenceError::AcknowledgementBeyondSent {
                acknowledged: ack,
                last_emitted: self.last_emitted,
            });
        }
        if ack > self.peer_acked {
            self.peer_acked = ack;
            self.prune_replay();
        }
        Ok(())
    }

    fn apply_send_credit(&mut self, limit: u64) -> Result<(), SequenceError> {
        // Absolute updates are idempotent. A delayed lower update cannot
        // revoke already granted logical credit.
        if limit > self.send_credit {
            self.send_credit = limit;
        }
        Ok(())
    }

    fn advertise_receive_credit(&mut self, limit: u64) -> Result<(), SequenceError> {
        if limit > self.receive_credit {
            self.receive_credit = limit;
        }
        Ok(())
    }

    fn emit(&mut self, frame: &Frame) -> Result<(), SequenceError> {
        match frame.kind {
            FrameKind::Ack | FrameKind::WindowUpdate => {
                debug_assert_eq!(frame.sequence, 0);
                Ok(())
            }
            FrameKind::Data | FrameKind::Fin | FrameKind::Reset => {
                self.validate_send_terminal(frame.kind)?;
                let expected =
                    self.last_emitted
                        .checked_add(1)
                        .ok_or(SequenceError::CounterExhausted {
                            counter: "last_emitted",
                        })?;
                if frame.sequence != expected {
                    return Err(SequenceError::SequenceNotNext {
                        expected,
                        actual: frame.sequence,
                    });
                }

                let attempted = if frame.kind == FrameKind::Data {
                    self.sent_bytes.checked_add(frame.payload.len() as u64)
                } else {
                    Some(self.sent_bytes)
                };
                let attempted = attempted.ok_or(SequenceError::CounterExhausted {
                    counter: "sent_bytes",
                })?;
                if frame.kind == FrameKind::Data && attempted > self.send_credit {
                    return Err(SequenceError::CreditExceeded {
                        limit: self.send_credit,
                        attempted,
                    });
                }
                self.ensure_replay_capacity(frame)?;

                if frame.kind == FrameKind::Data {
                    self.sent_bytes = attempted;
                }
                self.last_emitted = frame.sequence;
                self.retain_replay(frame);
                match frame.kind {
                    FrameKind::Fin => {
                        self.send_terminal = Some(Terminal::Fin);
                        self.send_terminal_sequence = Some(frame.sequence);
                    }
                    FrameKind::Reset => {
                        self.send_terminal =
                            Some(Terminal::Reset(frame.reset_reason()?.unwrap_or(0)));
                        self.send_terminal_sequence = Some(frame.sequence);
                    }
                    FrameKind::Data | FrameKind::Ack | FrameKind::WindowUpdate => {}
                }
                Ok(())
            }
        }
    }

    fn validate_send_terminal(&self, kind: FrameKind) -> Result<(), SequenceError> {
        match self.send_terminal {
            None => Ok(()),
            Some(Terminal::Fin) if kind == FrameKind::Reset => Ok(()),
            Some(terminal) => Err(SequenceError::AfterTerminal { kind, terminal }),
        }
    }

    fn ensure_replay_capacity(&self, frame: &Frame) -> Result<(), SequenceError> {
        let frame_count = self.replay.len();
        let payload_len = frame.payload.len();
        let is_terminal = matches!(frame.kind, FrameKind::Fin | FrameKind::Reset);
        let count_limit = self
            .limits
            .max_replay_frames
            .saturating_add(if is_terminal { 2 } else { 0 });
        let bytes_limit =
            self.limits
                .max_replay_bytes
                .saturating_add(if is_terminal { 2 } else { 0 });
        let projected_count =
            frame_count
                .checked_add(1)
                .ok_or(SequenceError::CounterExhausted {
                    counter: "replay_frames",
                })?;
        let projected_bytes =
            self.replay_bytes
                .checked_add(payload_len)
                .ok_or(SequenceError::CounterExhausted {
                    counter: "replay_bytes",
                })?;
        if projected_count > count_limit || projected_bytes > bytes_limit {
            return Err(SequenceError::ReplayBufferFull {
                frames: frame_count,
                bytes: self.replay_bytes,
            });
        }
        Ok(())
    }

    fn retain_replay(&mut self, frame: &Frame) {
        self.replay_bytes += frame.payload.len();
        self.replay.insert(frame.sequence, frame.clone());
    }

    fn prune_replay(&mut self) {
        let acknowledged = self.peer_acked;
        let keys: Vec<u64> = self
            .replay
            .range(..=acknowledged)
            .map(|(&key, _)| key)
            .collect();
        for key in keys {
            if let Some(frame) = self.replay.remove(&key) {
                self.replay_bytes -= frame.payload.len();
            }
        }
    }

    fn receive(&mut self, frame: &Frame) -> Result<ReceiveDisposition, SequenceError> {
        let disposition = self.preflight_receive(frame)?;
        if disposition == ReceiveDisposition::Duplicate {
            return Ok(disposition);
        }
        match frame.kind {
            FrameKind::Ack | FrameKind::WindowUpdate => Ok(ReceiveDisposition::Accepted),
            FrameKind::Data | FrameKind::Fin | FrameKind::Reset => {
                let expected =
                    self.recv_contiguous
                        .checked_add(1)
                        .ok_or(SequenceError::CounterExhausted {
                            counter: "recv_contiguous",
                        })?;
                if frame.sequence != expected {
                    self.charge_received(frame)?;
                    self.reorder_bytes += frame.payload.len();
                    self.reorder.insert(frame.sequence, frame.clone());
                    return Ok(disposition);
                }

                self.accept_contiguous(frame, true)?;
                self.drain_reorder()?;
                Ok(disposition)
            }
        }
    }

    /// Validate the complete contiguous promotion before mutating any
    /// metadata or retaining payload bytes. This keeps receive atomic without
    /// cloning the bounded history maps on every frame.
    fn preflight_receive(&self, frame: &Frame) -> Result<ReceiveDisposition, SequenceError> {
        match frame.kind {
            FrameKind::Ack | FrameKind::WindowUpdate => return Ok(ReceiveDisposition::Accepted),
            FrameKind::Data | FrameKind::Fin | FrameKind::Reset => {}
        }

        let digest = FrameFingerprint::of(frame);
        if frame.sequence <= self.recv_contiguous {
            if let Some(previous) = self.fingerprints.get(&frame.sequence)
                && *previous != digest
            {
                return Err(SequenceError::DuplicateConflict {
                    sequence: frame.sequence,
                });
            }
            return Ok(ReceiveDisposition::Duplicate);
        }
        if let Some(previous) = self.reorder.get(&frame.sequence) {
            if FrameFingerprint::of(previous) != digest {
                return Err(SequenceError::DuplicateConflict {
                    sequence: frame.sequence,
                });
            }
            return Ok(ReceiveDisposition::Duplicate);
        }

        let expected =
            self.recv_contiguous
                .checked_add(1)
                .ok_or(SequenceError::CounterExhausted {
                    counter: "recv_contiguous",
                })?;
        if frame.sequence != expected {
            if self.receive_terminal == Some(Terminal::Fin) && frame.kind == FrameKind::Reset {
                return Err(SequenceError::SequenceGap {
                    expected,
                    actual: frame.sequence,
                });
            }
            self.validate_receive_terminal(frame.kind)?;
            self.ensure_receive_capacity(frame)?;
            let _ = self.checked_received_bytes(frame, self.received_bytes)?;
            return Ok(ReceiveDisposition::Buffered);
        }

        let mut cursor = self.recv_contiguous;
        let mut terminal = self.receive_terminal;
        let mut received_bytes = self.received_bytes;
        let mut frame_count = self.reorder.len() + self.ready.len();
        let mut buffered_bytes = self.reorder_bytes + self.ready_bytes;
        let mut current = Some(frame);
        let mut is_new = true;
        while let Some(candidate) = current {
            let candidate_expected =
                cursor
                    .checked_add(1)
                    .ok_or(SequenceError::CounterExhausted {
                        counter: "recv_contiguous",
                    })?;
            if candidate.sequence != candidate_expected {
                return Err(SequenceError::SequenceGap {
                    expected: candidate_expected,
                    actual: candidate.sequence,
                });
            }
            match terminal {
                None => {}
                Some(Terminal::Fin) if candidate.kind == FrameKind::Reset => {}
                Some(previous) => {
                    return Err(SequenceError::AfterTerminal {
                        kind: candidate.kind,
                        terminal: previous,
                    });
                }
            }
            if is_new {
                Self::ensure_receive_capacity_values(
                    &self.limits,
                    frame_count,
                    buffered_bytes,
                    candidate,
                )?;
                received_bytes = self.checked_received_bytes(candidate, received_bytes)?;
                frame_count =
                    frame_count
                        .checked_add(1)
                        .ok_or(SequenceError::CounterExhausted {
                            counter: "reorder_frames",
                        })?;
                buffered_bytes = buffered_bytes.checked_add(candidate.payload.len()).ok_or(
                    SequenceError::CounterExhausted {
                        counter: "reorder_bytes",
                    },
                )?;
            }
            cursor = candidate.sequence;
            match candidate.kind {
                FrameKind::Fin => terminal = Some(Terminal::Fin),
                FrameKind::Reset => {
                    terminal = Some(Terminal::Reset(candidate.reset_reason()?.unwrap_or(0)))
                }
                FrameKind::Data | FrameKind::Ack | FrameKind::WindowUpdate => {}
            }
            let next_sequence = cursor.checked_add(1);
            current = next_sequence.and_then(|sequence| self.reorder.get(&sequence));
            is_new = false;
        }
        Ok(ReceiveDisposition::Accepted)
    }

    fn validate_receive_terminal(&self, kind: FrameKind) -> Result<(), SequenceError> {
        match self.receive_terminal {
            None => Ok(()),
            Some(Terminal::Fin) if kind == FrameKind::Reset => Ok(()),
            Some(terminal) => Err(SequenceError::AfterTerminal { kind, terminal }),
        }
    }

    fn accept_contiguous(&mut self, frame: &Frame, charge: bool) -> Result<(), SequenceError> {
        self.validate_receive_terminal(frame.kind)?;
        let expected =
            self.recv_contiguous
                .checked_add(1)
                .ok_or(SequenceError::CounterExhausted {
                    counter: "recv_contiguous",
                })?;
        if frame.sequence != expected {
            return Err(SequenceError::SequenceGap {
                expected,
                actual: frame.sequence,
            });
        }
        self.ensure_receive_capacity(frame)?;
        if charge {
            self.charge_received(frame)?;
        }
        self.recv_contiguous = frame.sequence;
        self.retain_fingerprint(frame.sequence, FrameFingerprint::of(frame));
        self.ready_bytes += frame.payload.len();
        self.ready.insert(frame.sequence, frame.clone());
        match frame.kind {
            FrameKind::Fin => {
                self.receive_terminal = Some(Terminal::Fin);
                self.receive_terminal_sequence = Some(frame.sequence);
            }
            FrameKind::Reset => {
                self.receive_terminal = Some(Terminal::Reset(frame.reset_reason()?.unwrap_or(0)));
                self.receive_terminal_sequence = Some(frame.sequence);
            }
            FrameKind::Data | FrameKind::Ack | FrameKind::WindowUpdate => {}
        }
        Ok(())
    }

    fn drain_reorder(&mut self) -> Result<(), SequenceError> {
        loop {
            let Some(expected) = self.recv_contiguous.checked_add(1) else {
                // u64::MAX is a valid final sequence. There cannot be a
                // later sequenced frame, so the exhausted cursor is a stable
                // terminal state rather than an error for this drain.
                return Ok(());
            };
            let Some(frame) = self.reorder.remove(&expected) else {
                return Ok(());
            };
            self.reorder_bytes -= frame.payload.len();
            self.accept_contiguous(&frame, false)?;
        }
    }

    fn ensure_receive_capacity(&self, frame: &Frame) -> Result<(), SequenceError> {
        let current_frames = self.reorder.len() + self.ready.len();
        let current_bytes = self.reorder_bytes.checked_add(self.ready_bytes).ok_or(
            SequenceError::CounterExhausted {
                counter: "reorder_bytes",
            },
        )?;
        Self::ensure_receive_capacity_values(&self.limits, current_frames, current_bytes, frame)
    }

    fn ensure_receive_capacity_values(
        limits: &SequenceLimits,
        current_frames: usize,
        current_bytes: usize,
        frame: &Frame,
    ) -> Result<(), SequenceError> {
        let is_terminal = matches!(frame.kind, FrameKind::Fin | FrameKind::Reset);
        let frame_limit = limits
            .max_reorder_frames
            .saturating_add(if is_terminal { 2 } else { 0 });
        let byte_limit = limits
            .max_reorder_bytes
            .saturating_add(if is_terminal { 2 } else { 0 });
        let projected_frames =
            current_frames
                .checked_add(1)
                .ok_or(SequenceError::CounterExhausted {
                    counter: "reorder_frames",
                })?;
        let projected_bytes = current_bytes.checked_add(frame.payload.len()).ok_or(
            SequenceError::CounterExhausted {
                counter: "reorder_bytes",
            },
        )?;
        if projected_frames > frame_limit || projected_bytes > byte_limit {
            return Err(SequenceError::ReorderBufferFull {
                frames: current_frames,
                bytes: current_bytes,
            });
        }
        Ok(())
    }

    fn checked_received_bytes(
        &self,
        frame: &Frame,
        received_bytes: u64,
    ) -> Result<u64, SequenceError> {
        if frame.kind != FrameKind::Data {
            return Ok(received_bytes);
        }
        if frame.payload.len() > MAX_PAYLOAD_LEN {
            return Err(SequenceError::Frame(FrameError::PayloadTooLarge {
                length: frame.payload.len(),
                maximum: MAX_PAYLOAD_LEN,
            }));
        }
        let attempted = received_bytes
            .checked_add(frame.payload.len() as u64)
            .ok_or(SequenceError::CounterExhausted {
                counter: "received_bytes",
            })?;
        if attempted > self.receive_credit {
            return Err(SequenceError::CreditExceeded {
                limit: self.receive_credit,
                attempted,
            });
        }
        Ok(attempted)
    }

    fn charge_received(&mut self, frame: &Frame) -> Result<(), SequenceError> {
        self.received_bytes = self.checked_received_bytes(frame, self.received_bytes)?;
        Ok(())
    }

    fn retain_fingerprint(&mut self, sequence: u64, fingerprint: FrameFingerprint) {
        self.fingerprints.insert(sequence, fingerprint);
        while self.fingerprints.len() > Self::MAX_RETAINED_FINGERPRINTS {
            let Some(oldest) = self.fingerprints.keys().next().copied() else {
                break;
            };
            self.fingerprints.remove(&oldest);
        }
    }

    fn mark_delivered(&mut self, through: u64) -> Result<(), SequenceError> {
        if through > self.recv_contiguous {
            return Err(SequenceError::DeliveredBeyondReceived {
                requested: through,
                received: self.recv_contiguous,
            });
        }
        if through <= self.delivered_contiguous {
            return Ok(());
        }
        let keys: Vec<u64> = self.ready.range(..=through).map(|(&key, _)| key).collect();
        for key in keys {
            if let Some(frame) = self.ready.remove(&key) {
                self.ready_bytes -= frame.payload.len();
            }
        }
        self.delivered_contiguous = through;
        Ok(())
    }

    /// Return an immutable snapshot suitable for a recovery handshake.
    #[must_use]
    pub fn snapshot(&self) -> DirectionSnapshot {
        DirectionSnapshot {
            last_emitted: self.last_emitted,
            peer_acked: self.peer_acked,
            recv_contiguous: self.recv_contiguous,
            delivered_contiguous: self.delivered_contiguous,
            send_credit: self.send_credit,
            sent_bytes: self.sent_bytes,
            receive_credit: self.receive_credit,
            received_bytes: self.received_bytes,
            send_terminal: self.send_terminal,
            send_terminal_sequence: self.send_terminal_sequence,
            receive_terminal: self.receive_terminal,
            receive_terminal_sequence: self.receive_terminal_sequence,
            replay_floor: self.replay_floor(),
            replay_bytes: self.replay_bytes,
            reorder_frames: self.reorder.len(),
            reorder_bytes: self.reorder_bytes,
        }
    }

    /// Return retained logical frames in an inclusive range. Frames already
    /// covered by the peer's cumulative ACK are omitted because they do not
    /// need replay. Every still-required sequence must be retained or this
    /// method returns [`SequenceError::MissingHistory`].
    pub fn retained_replay(&self, from: u64, through: u64) -> Result<Vec<Frame>, SequenceError> {
        if from == 0 || through == 0 || from > through {
            return Err(SequenceError::InvalidReplayRange { from, through });
        }
        if through > self.last_emitted {
            return Err(SequenceError::ReplayBeyondEmitted {
                requested: through,
                last_emitted: self.last_emitted,
            });
        }
        let Some(start) = self.peer_acked.checked_add(1) else {
            return Ok(Vec::new());
        };
        let start = from.max(start);
        if start > through {
            return Ok(Vec::new());
        }

        let mut expected = start;
        let mut replay = Vec::new();
        for (&sequence, frame) in self.replay.range(start..=through) {
            if sequence != expected {
                return Err(SequenceError::MissingHistory {
                    from: expected,
                    through: sequence.saturating_sub(1),
                });
            }
            replay.push(frame.clone());
            if sequence == through {
                return Ok(replay);
            }
            expected = expected
                .checked_add(1)
                .ok_or(SequenceError::CounterExhausted {
                    counter: "replay_sequence",
                })?;
        }
        Err(SequenceError::MissingHistory {
            from: expected,
            through,
        })
    }

    /// Return retained frames with the carrier epoch and generation replaced
    /// for a new authenticated data attachment. Logical sequence and stream
    /// identity remain unchanged. This operation does not charge credit or
    /// advance any cursor.
    pub fn retained_replay_for_carrier(
        &self,
        from: u64,
        through: u64,
        epoch: u64,
        generation: u64,
    ) -> Result<Vec<Frame>, SequenceError> {
        self.retained_replay(from, through).map(|frames| {
            frames
                .into_iter()
                .map(|mut frame| {
                    frame.epoch = epoch;
                    frame.generation = generation;
                    frame
                })
                .collect()
        })
    }
}

/// Immutable direction state exchanged during retained-state recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectionSnapshot {
    pub last_emitted: u64,
    pub peer_acked: u64,
    pub recv_contiguous: u64,
    pub delivered_contiguous: u64,
    pub send_credit: u64,
    pub sent_bytes: u64,
    pub receive_credit: u64,
    pub received_bytes: u64,
    pub send_terminal: Option<Terminal>,
    pub send_terminal_sequence: Option<u64>,
    pub receive_terminal: Option<Terminal>,
    pub receive_terminal_sequence: Option<u64>,
    pub replay_floor: Option<u64>,
    pub replay_bytes: usize,
    pub reorder_frames: usize,
    pub reorder_bytes: usize,
}

impl DirectionSnapshot {
    #[must_use]
    pub const fn last_emitted(&self) -> u64 {
        self.last_emitted
    }

    #[must_use]
    pub const fn peer_acked(&self) -> u64 {
        self.peer_acked
    }

    #[must_use]
    pub const fn recv_contiguous(&self) -> u64 {
        self.recv_contiguous
    }

    #[must_use]
    pub const fn delivered_contiguous(&self) -> u64 {
        self.delivered_contiguous
    }

    #[must_use]
    pub const fn send_credit(&self) -> u64 {
        self.send_credit
    }

    #[must_use]
    pub const fn receive_credit(&self) -> u64 {
        self.receive_credit
    }
}

/// Immutable stream state exchanged during retained-state recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamSnapshot {
    pub stream_id: u64,
    pub directions: [DirectionSnapshot; 2],
}

impl StreamSnapshot {
    #[must_use]
    pub const fn stream_id(&self) -> u64 {
        self.stream_id
    }

    #[must_use]
    pub const fn direction(&self, direction: Direction) -> &DirectionSnapshot {
        &self.directions[direction.index()]
    }
}

/// A pure recovery result. `replay` contains frames this side must resend;
/// `peer_missing` tells the caller which frames the peer must resend to this
/// side. The plan itself does not mutate the stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPlan {
    stream_id: u64,
    replay: [Vec<Frame>; 2],
    peer_missing: [Option<SequenceRange>; 2],
}

impl RecoveryPlan {
    #[must_use]
    pub const fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// Frames this endpoint must replay in one direction.
    #[must_use]
    pub fn replay(&self, direction: Direction) -> &[Frame] {
        &self.replay[direction.index()]
    }

    /// Range the peer must replay in one direction, if its sender is ahead.
    #[must_use]
    pub const fn peer_missing(&self, direction: Direction) -> Option<SequenceRange> {
        self.peer_missing[direction.index()]
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.replay.iter().all(Vec::is_empty) && self.peer_missing.iter().all(Option::is_none)
    }

    /// Consume the plan and return this endpoint's replay frames.
    #[must_use]
    pub fn into_replay(self, direction: Direction) -> Vec<Frame> {
        let RecoveryPlan {
            replay: [relay, connector],
            stream_id: _,
            peer_missing: _,
        } = self;
        match direction {
            Direction::RelayToConnector => relay,
            Direction::ConnectorToRelay => connector,
        }
    }
}

/// Logical stream state with independent sequence and credit state for both
/// directions.
#[derive(Clone, Debug)]
pub struct StreamState {
    stream_id: u64,
    directions: [DirectionState; 2],
}

impl StreamState {
    /// Construct a stream with the same initial absolute byte limit in both
    /// directions and default bounded replay/reorder limits.
    pub fn new(stream_id: u64, initial_credit: u64) -> Result<Self, SequenceError> {
        Self::with_credits(stream_id, initial_credit, initial_credit)
    }

    /// Construct a stream with independent local send and receive limits.
    pub fn with_credits(
        stream_id: u64,
        send_credit: u64,
        receive_credit: u64,
    ) -> Result<Self, SequenceError> {
        Self::with_credits_and_limits(
            stream_id,
            send_credit,
            receive_credit,
            SequenceLimits::default(),
        )
    }

    /// Construct a stream with explicit replay and receive-side bounds.
    pub fn with_credits_and_limits(
        stream_id: u64,
        send_credit: u64,
        receive_credit: u64,
        limits: SequenceLimits,
    ) -> Result<Self, SequenceError> {
        if stream_id == 0 {
            return Err(SequenceError::ZeroStreamId);
        }
        limits.validate()?;
        Ok(Self {
            stream_id,
            directions: [
                DirectionState::new(send_credit, receive_credit, limits),
                DirectionState::new(send_credit, receive_credit, limits),
            ],
        })
    }

    /// Construct a stream with one credit limit and explicit bounds.
    pub fn with_limits(
        stream_id: u64,
        initial_credit: u64,
        limits: SequenceLimits,
    ) -> Result<Self, SequenceError> {
        Self::with_credits_and_limits(stream_id, initial_credit, initial_credit, limits)
    }

    #[must_use]
    pub const fn stream_id(&self) -> u64 {
        self.stream_id
    }

    #[must_use]
    pub const fn direction(&self, direction: Direction) -> &DirectionState {
        &self.directions[direction.index()]
    }

    #[must_use]
    pub fn direction_mut(&mut self, direction: Direction) -> &mut DirectionState {
        &mut self.directions[direction.index()]
    }

    /// Validate and account for a locally emitted frame.
    pub fn send_frame(&mut self, direction: Direction, frame: &Frame) -> Result<(), SequenceError> {
        self.send_frame_inner(direction, frame)
    }

    fn send_frame_inner(
        &mut self,
        direction: Direction,
        frame: &Frame,
    ) -> Result<(), SequenceError> {
        frame.validate()?;
        self.check_stream(frame)?;
        let opposite = direction.opposite().index();
        if frame.ack > self.directions[opposite].recv_contiguous {
            return Err(SequenceError::AcknowledgementBeyondReceived {
                acknowledged: frame.ack,
                received: self.directions[opposite].recv_contiguous,
            });
        }
        if frame.kind == FrameKind::WindowUpdate {
            // `emit` cannot fail for an unsequenced housekeeping frame after
            // validation. Apply the monotonic absolute update only after all
            // checks above have passed.
            self.directions[opposite].advertise_receive_credit(frame.window)?;
            return Ok(());
        }
        self.directions[direction.index()].emit(frame)
    }

    /// Validate and account for a received frame. ACKs and window updates are
    /// applied to the opposite sequence/credit direction.
    pub fn receive_frame(
        &mut self,
        direction: Direction,
        frame: &Frame,
    ) -> Result<ReceiveDisposition, SequenceError> {
        self.receive_frame_inner(direction, frame)
    }

    fn receive_frame_inner(
        &mut self,
        direction: Direction,
        frame: &Frame,
    ) -> Result<ReceiveDisposition, SequenceError> {
        frame.validate()?;
        self.check_stream(frame)?;
        let opposite = direction.opposite().index();
        if frame.ack > self.directions[opposite].last_emitted {
            return Err(SequenceError::AcknowledgementBeyondSent {
                acknowledged: frame.ack,
                last_emitted: self.directions[opposite].last_emitted,
            });
        }
        let disposition = self.directions[direction.index()].receive(frame)?;
        self.directions[opposite].apply_ack(frame.ack)?;
        if frame.kind == FrameKind::WindowUpdate {
            self.directions[opposite].apply_send_credit(frame.window)?;
        }
        Ok(disposition)
    }

    /// Apply a cumulative acknowledgement received outside a data frame.
    pub fn apply_ack(&mut self, direction: Direction, ack: u64) -> Result<(), SequenceError> {
        self.directions[direction.index()].apply_ack(ack)
    }

    /// Apply an absolute send-credit update received outside a data frame.
    pub fn apply_window_update(
        &mut self,
        direction: Direction,
        limit: u64,
    ) -> Result<(), SequenceError> {
        self.directions[direction.index()].apply_send_credit(limit)
    }

    /// Mark contiguous received records as handed to the adapter. This is
    /// separate from transport receipt and never increases credit by itself.
    pub fn mark_delivered(
        &mut self,
        direction: Direction,
        through: u64,
    ) -> Result<(), SequenceError> {
        self.directions[direction.index()].mark_delivered(through)
    }

    /// Return contiguous records that have been received but not yet marked
    /// delivered. The returned frames are bounded by `SequenceLimits`.
    #[must_use]
    pub fn ready_frames(&self, direction: Direction) -> Vec<Frame> {
        self.directions[direction.index()].ready_frames()
    }

    /// Borrow ready records in sequence order without cloning payloads.
    pub fn ready_iter(&self, direction: Direction) -> impl Iterator<Item = &Frame> {
        self.directions[direction.index()].ready_iter()
    }

    /// Return retained unacknowledged frames in an inclusive range.
    pub fn retained_replay(
        &self,
        direction: Direction,
        from: u64,
        through: u64,
    ) -> Result<Vec<Frame>, SequenceError> {
        self.directions[direction.index()].retained_replay(from, through)
    }

    /// Return retained frames bound to a replacement carrier. No logical
    /// credit or sequence cursor is changed.
    pub fn replay_frames(
        &self,
        direction: Direction,
        from: u64,
        through: u64,
        epoch: u64,
        generation: u64,
    ) -> Result<Vec<Frame>, SequenceError> {
        self.directions[direction.index()]
            .retained_replay_for_carrier(from, through, epoch, generation)
    }

    /// Replay every frame after a reconciled peer receive cursor through the
    /// local emitted cursor. A cursor ahead of the local sender is a recovery
    /// conflict; missing retained bytes are reported explicitly.
    pub fn replay_missing(
        &self,
        direction: Direction,
        peer_receive_cursor: u64,
        epoch: u64,
        generation: u64,
    ) -> Result<Vec<Frame>, SequenceError> {
        let state = self.direction(direction);
        if peer_receive_cursor > state.last_emitted {
            return Err(SequenceError::RecoveryPeerAhead {
                direction,
                peer_cursor: peer_receive_cursor,
                local_last_emitted: state.last_emitted,
            });
        }
        if peer_receive_cursor == state.last_emitted {
            return Ok(Vec::new());
        }
        let from = peer_receive_cursor
            .checked_add(1)
            .ok_or(SequenceError::CounterExhausted {
                counter: "recovery_cursor",
            })?;
        state.retained_replay_for_carrier(from, state.last_emitted, epoch, generation)
    }

    /// Produce a recovery snapshot with all per-direction cursors, terminal
    /// state, and absolute credit counters.
    #[must_use]
    pub fn snapshot(&self) -> StreamSnapshot {
        StreamSnapshot {
            stream_id: self.stream_id,
            directions: [self.directions[0].snapshot(), self.directions[1].snapshot()],
        }
    }

    /// Reconcile a peer snapshot without mutating this stream. The result
    /// contains only missing retained ranges; it never recharges replay.
    pub fn reconcile(&self, peer: &StreamSnapshot) -> Result<RecoveryPlan, SequenceError> {
        if peer.stream_id != self.stream_id {
            return Err(SequenceError::WrongStream {
                expected: self.stream_id,
                actual: peer.stream_id,
            });
        }

        let mut replay: [Vec<Frame>; 2] = [Vec::new(), Vec::new()];
        let mut peer_missing = [None, None];
        for direction in [Direction::RelayToConnector, Direction::ConnectorToRelay] {
            let index = direction.index();
            let local = &self.directions[index];
            let remote = &peer.directions[index];
            Self::validate_recovery_pair(direction, local, remote)?;

            if remote.recv_contiguous < local.last_emitted {
                let from = remote.recv_contiguous.checked_add(1).ok_or(
                    SequenceError::CounterExhausted {
                        counter: "recovery_cursor",
                    },
                )?;
                replay[index] = local.retained_replay(from, local.last_emitted)?;
            }
            if local.recv_contiguous < remote.last_emitted {
                let from = local.recv_contiguous.checked_add(1).ok_or(
                    SequenceError::CounterExhausted {
                        counter: "recovery_cursor",
                    },
                )?;
                peer_missing[index] = Some(SequenceRange {
                    from,
                    through: remote.last_emitted,
                });
            }
        }

        Ok(RecoveryPlan {
            stream_id: self.stream_id,
            replay,
            peer_missing,
        })
    }

    /// Reconcile and bind this endpoint's replay frames to a replacement
    /// carrier. The stream itself remains unchanged.
    pub fn reconcile_for_carrier(
        &self,
        peer: &StreamSnapshot,
        epoch: u64,
        generation: u64,
    ) -> Result<RecoveryPlan, SequenceError> {
        let mut plan = self.reconcile(peer)?;
        for direction in [Direction::RelayToConnector, Direction::ConnectorToRelay] {
            for frame in &mut plan.replay[direction.index()] {
                frame.epoch = epoch;
                frame.generation = generation;
            }
        }
        Ok(plan)
    }

    /// Reconcile and advance local peer ACK cursors from an authenticated
    /// peer snapshot. This is the mutating form used once the control-plane
    /// handshake has accepted the snapshot. Returned replay frames are still
    /// available to the caller and are not charged a second time.
    pub fn reconcile_and_apply(
        &mut self,
        peer: &StreamSnapshot,
    ) -> Result<RecoveryPlan, SequenceError> {
        let plan = self.reconcile(peer)?;
        for direction in [Direction::RelayToConnector, Direction::ConnectorToRelay] {
            self.directions[direction.index()]
                .apply_ack(peer.directions[direction.index()].recv_contiguous)?;
        }
        Ok(plan)
    }

    fn validate_recovery_pair(
        direction: Direction,
        local: &DirectionState,
        remote: &DirectionSnapshot,
    ) -> Result<(), SequenceError> {
        validate_snapshot_invariants(direction, remote)?;
        if remote.recv_contiguous > local.last_emitted {
            return Err(SequenceError::RecoveryPeerAhead {
                direction,
                peer_cursor: remote.recv_contiguous,
                local_last_emitted: local.last_emitted,
            });
        }
        if local.recv_contiguous > remote.last_emitted {
            return Err(SequenceError::RecoveryPeerBehind {
                direction,
                local_cursor: local.recv_contiguous,
                peer_last_emitted: remote.last_emitted,
            });
        }
        if remote.recv_contiguous < local.peer_acked {
            return Err(SequenceError::RecoveryAckRegression {
                direction,
                acknowledged: local.peer_acked,
                received: remote.recv_contiguous,
            });
        }
        if local.recv_contiguous < remote.peer_acked {
            return Err(SequenceError::RecoveryAckRegression {
                direction,
                acknowledged: remote.peer_acked,
                received: local.recv_contiguous,
            });
        }
        if remote.receive_credit < local.send_credit {
            return Err(SequenceError::RecoveryCreditConflict {
                direction,
                local: local.send_credit,
                peer: remote.receive_credit,
            });
        }
        if local.receive_credit < remote.send_credit {
            return Err(SequenceError::RecoveryCreditConflict {
                direction,
                local: local.receive_credit,
                peer: remote.send_credit,
            });
        }
        if let Some(error) = terminal_conflict(
            local.receive_terminal,
            local.receive_terminal_sequence,
            local.recv_contiguous,
            remote.send_terminal,
            remote.send_terminal_sequence,
            remote.recv_contiguous,
            false,
        ) {
            return Err(SequenceError::TerminalConflict {
                direction,
                local: error.0,
                peer: error.1,
            });
        }
        if let Some((local_sequence, peer_sequence)) = terminal_sequence_conflict(
            local.receive_terminal,
            local.receive_terminal_sequence,
            remote.send_terminal,
            remote.send_terminal_sequence,
            false,
        ) {
            return Err(SequenceError::TerminalSequenceConflict {
                direction,
                local: local_sequence,
                peer: peer_sequence,
            });
        }
        if let Some(error) = terminal_conflict(
            local.send_terminal,
            local.send_terminal_sequence,
            local.last_emitted,
            remote.receive_terminal,
            remote.receive_terminal_sequence,
            remote.recv_contiguous,
            true,
        ) {
            return Err(SequenceError::TerminalConflict {
                direction,
                local: error.0,
                peer: error.1,
            });
        }
        if let Some((local_sequence, peer_sequence)) = terminal_sequence_conflict(
            local.send_terminal,
            local.send_terminal_sequence,
            remote.receive_terminal,
            remote.receive_terminal_sequence,
            true,
        ) {
            return Err(SequenceError::TerminalSequenceConflict {
                direction,
                local: local_sequence,
                peer: peer_sequence,
            });
        }
        Ok(())
    }

    fn check_stream(&self, frame: &Frame) -> Result<(), SequenceError> {
        if frame.stream_id != self.stream_id {
            return Err(SequenceError::WrongStream {
                expected: self.stream_id,
                actual: frame.stream_id,
            });
        }
        Ok(())
    }
}

/// Return a terminal mismatch that cannot be explained by one side being
/// one replay step behind. `sender_side` selects the symmetric comparison.
fn terminal_conflict(
    local: Option<Terminal>,
    local_sequence: Option<u64>,
    local_cursor: u64,
    peer: Option<Terminal>,
    peer_sequence: Option<u64>,
    peer_cursor: u64,
    sender_side: bool,
) -> Option<(Option<Terminal>, Option<Terminal>)> {
    match (local, peer) {
        (None, None) | (Some(Terminal::Fin), Some(Terminal::Fin)) => None,
        (Some(Terminal::Reset(a)), Some(Terminal::Reset(b))) if a == b => None,
        (Some(Terminal::Fin), Some(Terminal::Reset(_)))
        | (Some(Terminal::Reset(_)), Some(Terminal::Fin)) => None,
        // On a receiver comparison, a peer terminal that we have not yet
        // received is replayable only while the receiver cursor is below the
        // peer's terminal sequence. At or beyond that sequence, terminal
        // evidence was lost and cannot safely resume.
        (None, Some(_)) if !sender_side => {
            (peer_sequence.is_none_or(|sequence| local_cursor >= sequence)).then_some((local, peer))
        }
        // On a sender comparison, our terminal may still be missing at the
        // peer only while its receive cursor is below our terminal sequence.
        // At or beyond that sequence, the peer has observed a terminal that
        // this side can no longer account for.
        (Some(_), None) if sender_side => {
            (local_sequence.is_none_or(|sequence| peer_cursor >= sequence)).then_some((local, peer))
        }
        mismatch => Some(mismatch),
    }
}

fn terminal_sequence_conflict(
    local: Option<Terminal>,
    local_sequence: Option<u64>,
    peer: Option<Terminal>,
    peer_sequence: Option<u64>,
    sender_side: bool,
) -> Option<(u64, u64)> {
    let (Some(local), Some(local_sequence), Some(peer), Some(peer_sequence)) =
        (local, local_sequence, peer, peer_sequence)
    else {
        return None;
    };
    match (local, peer) {
        (Terminal::Fin, Terminal::Fin) | (Terminal::Reset(_), Terminal::Reset(_)) => {
            (local_sequence != peer_sequence).then_some((local_sequence, peer_sequence))
        }
        (Terminal::Fin, Terminal::Reset(_)) => {
            if sender_side || peer_sequence <= local_sequence {
                Some((local_sequence, peer_sequence))
            } else {
                None
            }
        }
        (Terminal::Reset(_), Terminal::Fin) => {
            if !sender_side || local_sequence <= peer_sequence {
                Some((local_sequence, peer_sequence))
            } else {
                None
            }
        }
    }
}

fn validate_snapshot_invariants(
    direction: Direction,
    snapshot: &DirectionSnapshot,
) -> Result<(), SequenceError> {
    if snapshot.peer_acked > snapshot.last_emitted {
        return Err(SequenceError::InvalidRecoverySnapshot {
            direction,
            field: "peer_acked",
        });
    }
    if snapshot.delivered_contiguous > snapshot.recv_contiguous {
        return Err(SequenceError::InvalidRecoverySnapshot {
            direction,
            field: "delivered_contiguous",
        });
    }
    if snapshot.sent_bytes > snapshot.send_credit {
        return Err(SequenceError::InvalidRecoverySnapshot {
            direction,
            field: "sent_bytes",
        });
    }
    if snapshot.received_bytes > snapshot.receive_credit {
        return Err(SequenceError::InvalidRecoverySnapshot {
            direction,
            field: "received_bytes",
        });
    }
    let expected_replay_floor = if snapshot.last_emitted > snapshot.peer_acked {
        Some(
            snapshot
                .peer_acked
                .checked_add(1)
                .ok_or(SequenceError::CounterExhausted {
                    counter: "replay_floor",
                })?,
        )
    } else {
        None
    };
    if snapshot.replay_floor != expected_replay_floor {
        return Err(SequenceError::InvalidRecoverySnapshot {
            direction,
            field: "replay_floor",
        });
    }
    validate_terminal_evidence(
        direction,
        snapshot.send_terminal,
        snapshot.send_terminal_sequence,
        snapshot.last_emitted,
        "send_terminal",
    )?;
    validate_terminal_evidence(
        direction,
        snapshot.receive_terminal,
        snapshot.receive_terminal_sequence,
        snapshot.recv_contiguous,
        "receive_terminal",
    )?;
    Ok(())
}

fn validate_terminal_evidence(
    direction: Direction,
    terminal: Option<Terminal>,
    sequence: Option<u64>,
    cursor: u64,
    field: &'static str,
) -> Result<(), SequenceError> {
    match (terminal, sequence) {
        (None, None) => Ok(()),
        (Some(_), Some(sequence)) if sequence != 0 && sequence == cursor => Ok(()),
        _ => Err(SequenceError::InvalidRecoverySnapshot { direction, field }),
    }
}

/// Errors from the pure sequence, replay, and credit state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SequenceError {
    Frame(FrameError),
    ZeroStreamId,
    WrongStream {
        expected: u64,
        actual: u64,
    },
    SequenceNotNext {
        expected: u64,
        actual: u64,
    },
    SequenceGap {
        expected: u64,
        actual: u64,
    },
    DuplicateConflict {
        sequence: u64,
    },
    AfterTerminal {
        kind: FrameKind,
        terminal: Terminal,
    },
    CreditExceeded {
        limit: u64,
        attempted: u64,
    },
    CreditDecreased {
        previous: u64,
        proposed: u64,
    },
    AcknowledgementBeyondSent {
        acknowledged: u64,
        last_emitted: u64,
    },
    AcknowledgementBeyondReceived {
        acknowledged: u64,
        received: u64,
    },
    DeliveredBeyondReceived {
        requested: u64,
        received: u64,
    },
    CounterExhausted {
        counter: &'static str,
    },
    LimitsExceeded {
        field: &'static str,
        requested: usize,
        maximum: usize,
    },
    ReplayBufferFull {
        frames: usize,
        bytes: usize,
    },
    ReorderBufferFull {
        frames: usize,
        bytes: usize,
    },
    MissingHistory {
        from: u64,
        through: u64,
    },
    InvalidReplayRange {
        from: u64,
        through: u64,
    },
    ReplayBeyondEmitted {
        requested: u64,
        last_emitted: u64,
    },
    RecoveryPeerAhead {
        direction: Direction,
        peer_cursor: u64,
        local_last_emitted: u64,
    },
    RecoveryPeerBehind {
        direction: Direction,
        local_cursor: u64,
        peer_last_emitted: u64,
    },
    RecoveryAckRegression {
        direction: Direction,
        acknowledged: u64,
        received: u64,
    },
    RecoveryCreditConflict {
        direction: Direction,
        local: u64,
        peer: u64,
    },
    TerminalConflict {
        direction: Direction,
        local: Option<Terminal>,
        peer: Option<Terminal>,
    },
    TerminalSequenceConflict {
        direction: Direction,
        local: u64,
        peer: u64,
    },
    InvalidRecoverySnapshot {
        direction: Direction,
        field: &'static str,
    },
}

impl From<FrameError> for SequenceError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
    }
}

impl fmt::Display for SequenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(error) => error.fmt(f),
            Self::ZeroStreamId => write!(f, "stream ID must be nonzero"),
            Self::WrongStream { expected, actual } => {
                write!(f, "frame addresses stream {actual}, expected {expected}")
            }
            Self::SequenceNotNext { expected, actual } => {
                write!(f, "next emitted sequence must be {expected}, got {actual}")
            }
            Self::SequenceGap { expected, actual } => {
                write!(
                    f,
                    "received sequence gap: expected {expected}, got {actual}"
                )
            }
            Self::DuplicateConflict { sequence } => {
                write!(
                    f,
                    "duplicate sequence {sequence} changed its frame contents"
                )
            }
            Self::AfterTerminal { kind, terminal } => {
                write!(
                    f,
                    "cannot process {kind:?} after terminal state {terminal:?}"
                )
            }
            Self::CreditExceeded { limit, attempted } => {
                write!(
                    f,
                    "byte credit exceeded: limit {limit}, attempted {attempted}"
                )
            }
            Self::CreditDecreased { previous, proposed } => {
                write!(f, "byte credit decreased from {previous} to {proposed}")
            }
            Self::AcknowledgementBeyondSent {
                acknowledged,
                last_emitted,
            } => write!(
                f,
                "acknowledgement {acknowledged} exceeds last emitted {last_emitted}"
            ),
            Self::AcknowledgementBeyondReceived {
                acknowledged,
                received,
            } => write!(
                f,
                "acknowledgement {acknowledged} exceeds received {received}"
            ),
            Self::DeliveredBeyondReceived {
                requested,
                received,
            } => write!(f, "delivery cursor {requested} exceeds received {received}"),
            Self::CounterExhausted { counter } => write!(f, "counter {counter} is exhausted"),
            Self::LimitsExceeded {
                field,
                requested,
                maximum,
            } => write!(
                f,
                "sequence limit {field}={requested} exceeds hard maximum {maximum}"
            ),
            Self::ReplayBufferFull { frames, bytes } => {
                write!(
                    f,
                    "replay buffer is full at {frames} frames and {bytes} bytes"
                )
            }
            Self::ReorderBufferFull { frames, bytes } => {
                write!(
                    f,
                    "reorder buffer is full at {frames} frames and {bytes} bytes"
                )
            }
            Self::MissingHistory { from, through } => {
                write!(
                    f,
                    "retained history is missing sequence range {from}..={through}"
                )
            }
            Self::InvalidReplayRange { from, through } => {
                write!(f, "invalid replay range {from}..={through}")
            }
            Self::ReplayBeyondEmitted {
                requested,
                last_emitted,
            } => write!(
                f,
                "replay sequence {requested} exceeds last emitted {last_emitted}"
            ),
            Self::RecoveryPeerAhead {
                direction,
                peer_cursor,
                local_last_emitted,
            } => write!(
                f,
                "recovery peer cursor {peer_cursor} in {direction:?} exceeds local emitted {local_last_emitted}"
            ),
            Self::RecoveryPeerBehind {
                direction,
                local_cursor,
                peer_last_emitted,
            } => write!(
                f,
                "recovery local cursor {local_cursor} in {direction:?} exceeds peer emitted {peer_last_emitted}"
            ),
            Self::RecoveryAckRegression {
                direction,
                acknowledged,
                received,
            } => write!(
                f,
                "recovery receiver cursor {received} in {direction:?} is below observed ACK {acknowledged}"
            ),
            Self::RecoveryCreditConflict {
                direction,
                local,
                peer,
            } => write!(
                f,
                "recovery credit conflict in {direction:?}: local {local}, peer {peer}"
            ),
            Self::TerminalConflict {
                direction,
                local,
                peer,
            } => write!(
                f,
                "recovery terminal conflict in {direction:?}: local {local:?}, peer {peer:?}"
            ),
            Self::TerminalSequenceConflict {
                direction,
                local,
                peer,
            } => write!(
                f,
                "recovery terminal sequence conflict in {direction:?}: local {local}, peer {peer}"
            ),
            Self::InvalidRecoverySnapshot { direction, field } => write!(
                f,
                "invalid recovery snapshot field {field} in {direction:?}"
            ),
        }
    }
}

impl std::error::Error for SequenceError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FrameFingerprint {
    kind: FrameKind,
    flags: u16,
    ack: u64,
    window: u64,
    payload_len: usize,
    payload_hash: [u8; 32],
}

impl FrameFingerprint {
    fn of(frame: &Frame) -> Self {
        // SHA-256 is used only to avoid retaining application bytes in
        // bounded duplicate metadata; it is not an authentication primitive.
        let payload_hash: [u8; 32] = Sha256::digest(&frame.payload).into();
        Self {
            kind: frame.kind,
            flags: frame.flags,
            ack: frame.ack,
            window: frame.window,
            payload_len: frame.payload.len(),
            payload_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPOCH: u64 = 1;
    const GENERATION: u64 = 2;

    fn data(sequence: u64, byte: u8) -> Frame {
        Frame::data(EPOCH, GENERATION, 7, sequence, 0, vec![byte])
    }

    #[derive(Clone, Copy)]
    struct ScheduleRng(u64);

    impl ScheduleRng {
        fn new(seed: u64) -> Self {
            Self(seed)
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }

        fn shuffle<T>(&mut self, items: &mut [T]) {
            for index in (1..items.len()).rev() {
                let selected = (self.next_u64() % (index as u64 + 1)) as usize;
                items.swap(index, selected);
            }
        }
    }

    #[test]
    fn directions_have_independent_sequence_spaces() {
        let mut state = StreamState::new(7, 8).expect("valid stream");
        state
            .send_frame(Direction::RelayToConnector, &data(1, 1))
            .expect("relay sequence one");
        state
            .send_frame(Direction::ConnectorToRelay, &data(1, 2))
            .expect("connector sequence one");
        assert_eq!(
            state.direction(Direction::RelayToConnector).last_emitted(),
            1
        );
        assert_eq!(
            state.direction(Direction::ConnectorToRelay).last_emitted(),
            1
        );
    }

    #[test]
    fn receive_holds_gaps_and_releases_contiguous_frames_in_order() {
        let mut state = StreamState::new(7, 8).expect("valid stream");
        assert_eq!(
            state
                .receive_frame(Direction::RelayToConnector, &data(2, 2))
                .expect("buffered gap"),
            ReceiveDisposition::Buffered
        );
        assert_eq!(
            state
                .direction(Direction::RelayToConnector)
                .recv_contiguous(),
            0
        );
        state
            .receive_frame(Direction::RelayToConnector, &data(1, 1))
            .expect("first frame");
        assert_eq!(
            state
                .direction(Direction::RelayToConnector)
                .recv_contiguous(),
            2
        );
        let ready = state.ready_frames(Direction::RelayToConnector);
        assert_eq!(
            ready.iter().map(|frame| frame.sequence).collect::<Vec<_>>(),
            [1, 2]
        );
        state
            .mark_delivered(Direction::RelayToConnector, 2)
            .expect("deliver");
        assert!(state.ready_frames(Direction::RelayToConnector).is_empty());
        assert_eq!(
            state
                .receive_frame(Direction::RelayToConnector, &data(1, 1))
                .expect("duplicate"),
            ReceiveDisposition::Duplicate
        );
        assert!(matches!(
            state.receive_frame(Direction::RelayToConnector, &data(1, 9)),
            Err(SequenceError::DuplicateConflict { sequence: 1 })
        ));
    }

    #[test]
    fn credit_is_absolute_and_replay_does_not_charge_again() {
        let mut state = StreamState::with_limits(7, 8, SequenceLimits::new(8, 128, 8, 128))
            .expect("valid stream");
        state
            .send_frame(Direction::RelayToConnector, &data(1, 1))
            .expect("one byte fits");
        assert_eq!(state.direction(Direction::RelayToConnector).sent_bytes(), 1);
        let replay = state
            .replay_frames(Direction::RelayToConnector, 1, 1, 4, 8)
            .expect("retained replay");
        assert_eq!(replay[0].generation, 8);
        assert_eq!(state.direction(Direction::RelayToConnector).sent_bytes(), 1);
        assert!(matches!(
            state.send_frame(Direction::RelayToConnector, &data(2, 2)),
            Ok(())
        ));
    }

    #[test]
    fn ack_is_monotonic_and_prunes_only_acknowledged_replay() {
        let mut state = StreamState::with_limits(7, 8, SequenceLimits::new(8, 128, 8, 128))
            .expect("valid stream");
        state
            .send_frame(Direction::RelayToConnector, &data(1, 1))
            .expect("first");
        state
            .send_frame(Direction::RelayToConnector, &data(2, 2))
            .expect("second");
        state
            .apply_ack(Direction::RelayToConnector, 2)
            .expect("ack");
        state
            .apply_ack(Direction::RelayToConnector, 1)
            .expect("delayed ack");
        assert_eq!(state.direction(Direction::RelayToConnector).peer_acked(), 2);
        assert_eq!(state.direction(Direction::RelayToConnector).replay_len(), 0);
    }

    #[test]
    fn fin_then_one_reset_is_allowed_and_payload_after_terminal_is_not() {
        let mut state = StreamState::new(7, 16).expect("valid stream");
        state
            .send_frame(
                Direction::RelayToConnector,
                &Frame::fin(EPOCH, GENERATION, 7, 1, 0),
            )
            .expect("FIN");
        state
            .send_frame(
                Direction::RelayToConnector,
                &Frame::reset(EPOCH, GENERATION, 7, 2, 0, 9),
            )
            .expect("reset after FIN");
        assert!(matches!(
            state.send_frame(Direction::RelayToConnector, &data(3, 3)),
            Err(SequenceError::AfterTerminal { .. })
        ));
        assert!(matches!(
            state.send_frame(
                Direction::RelayToConnector,
                &Frame::reset(EPOCH, GENERATION, 7, 3, 0, 9)
            ),
            Err(SequenceError::AfterTerminal { .. })
        ));
    }

    #[test]
    fn terminal_reserve_allows_fin_and_reset_when_data_bound_is_full() {
        let limits = SequenceLimits::new(1, 8, 1, 8);
        let mut sender = StreamState::with_limits(7, 8, limits).expect("valid stream");
        sender
            .send_frame(Direction::RelayToConnector, &data(1, 1))
            .expect("bounded DATA");
        sender
            .send_frame(
                Direction::RelayToConnector,
                &Frame::fin(EPOCH, GENERATION, 7, 2, 0),
            )
            .expect("reserved FIN");
        sender
            .send_frame(
                Direction::RelayToConnector,
                &Frame::reset(EPOCH, GENERATION, 7, 3, 0, 9),
            )
            .expect("reserved RESET");

        let mut receiver = StreamState::with_limits(7, 8, limits).expect("valid stream");
        receiver
            .receive_frame(Direction::RelayToConnector, &data(1, 1))
            .expect("DATA");
        receiver
            .receive_frame(
                Direction::RelayToConnector,
                &Frame::fin(EPOCH, GENERATION, 7, 2, 0),
            )
            .expect("FIN");
        receiver
            .receive_frame(
                Direction::RelayToConnector,
                &Frame::reset(EPOCH, GENERATION, 7, 3, 0, 9),
            )
            .expect("RESET");
        assert_eq!(
            receiver.direction(Direction::RelayToConnector).ready_len(),
            3
        );
    }

    #[test]
    fn negotiated_limits_cannot_remove_the_hard_bound() {
        let oversized = SequenceLimits::new(MAX_REPLAY_FRAMES + 1, 8, 1, 8);
        assert!(matches!(
            StreamState::with_limits(7, 8, oversized),
            Err(SequenceError::LimitsExceeded {
                field: "max_replay_frames",
                ..
            })
        ));
    }

    #[test]
    fn ack_and_window_update_apply_to_the_opposite_direction() {
        let mut state = StreamState::new(7, 1).expect("valid stream");
        state
            .send_frame(Direction::RelayToConnector, &data(1, 1))
            .expect("initial data");

        let incoming = Frame::window_update(EPOCH, GENERATION, 7, 3);
        state
            .receive_frame(Direction::ConnectorToRelay, &incoming)
            .expect("window update");
        assert_eq!(
            state.direction(Direction::RelayToConnector).send_credit(),
            3
        );

        let incoming_ack = Frame::ack(EPOCH, GENERATION, 7, 1);
        state
            .receive_frame(Direction::ConnectorToRelay, &incoming_ack)
            .expect("ack");
        assert_eq!(state.direction(Direction::RelayToConnector).peer_acked(), 1);
    }

    #[test]
    fn delayed_lower_window_update_is_harmless() {
        let mut state = StreamState::new(7, 1).expect("valid stream");
        state
            .receive_frame(
                Direction::ConnectorToRelay,
                &Frame::window_update(EPOCH, GENERATION, 7, 3),
            )
            .expect("first update");
        state
            .receive_frame(
                Direction::ConnectorToRelay,
                &Frame::window_update(EPOCH, GENERATION, 7, 2),
            )
            .expect("delayed update");
        assert_eq!(
            state.direction(Direction::RelayToConnector).send_credit(),
            3
        );
    }

    #[test]
    fn fin_then_reset_can_arrive_with_a_gap_but_no_frame_can_follow_reset() {
        let mut state = StreamState::new(7, 16).expect("valid stream");
        assert_eq!(
            state
                .receive_frame(
                    Direction::RelayToConnector,
                    &Frame::reset(EPOCH, GENERATION, 7, 2, 0, 9),
                )
                .expect("buffer reset"),
            ReceiveDisposition::Buffered
        );
        state
            .receive_frame(
                Direction::RelayToConnector,
                &Frame::fin(EPOCH, GENERATION, 7, 1, 0),
            )
            .expect("FIN promotes reset");
        assert_eq!(
            state
                .direction(Direction::RelayToConnector)
                .receive_terminal(),
            Some(Terminal::Reset(9))
        );
        assert!(matches!(
            state.receive_frame(Direction::RelayToConnector, &data(3, 3)),
            Err(SequenceError::AfterTerminal {
                terminal: Terminal::Reset(9),
                ..
            })
        ));

        let mut gapped = StreamState::new(7, 16).expect("valid stream");
        gapped
            .receive_frame(
                Direction::RelayToConnector,
                &Frame::fin(EPOCH, GENERATION, 7, 1, 0),
            )
            .expect("FIN");
        assert!(matches!(
            gapped.receive_frame(
                Direction::RelayToConnector,
                &Frame::reset(EPOCH, GENERATION, 7, 3, 0, 9)
            ),
            Err(SequenceError::SequenceGap {
                expected: 2,
                actual: 3
            })
        ));
    }

    #[test]
    fn delivery_cursor_is_separate_from_transport_receipt() {
        let mut state = StreamState::new(7, 16).expect("valid stream");
        state
            .receive_frame(Direction::RelayToConnector, &data(1, 1))
            .expect("receive");
        assert_eq!(
            state
                .direction(Direction::RelayToConnector)
                .delivered_contiguous(),
            0
        );
        state
            .mark_delivered(Direction::RelayToConnector, 1)
            .expect("deliver");
        assert_eq!(
            state
                .direction(Direction::RelayToConnector)
                .delivered_contiguous(),
            1
        );
    }

    #[test]
    fn bounded_replay_reports_missing_history() {
        let limits = SequenceLimits::new(1, 8, 8, 128);
        let mut state = StreamState::with_limits(7, 16, limits).expect("valid stream");
        state
            .send_frame(Direction::RelayToConnector, &data(1, 1))
            .expect("first");
        assert!(matches!(
            state.send_frame(Direction::RelayToConnector, &data(2, 2)),
            Err(SequenceError::ReplayBufferFull { .. })
        ));
        assert!(matches!(
            state.retained_replay(Direction::RelayToConnector, 1, 2),
            Err(SequenceError::ReplayBeyondEmitted {
                requested: 2,
                last_emitted: 1
            })
        ));

        state.directions[Direction::RelayToConnector.index()]
            .replay
            .remove(&1);
        assert!(matches!(
            state.retained_replay(Direction::RelayToConnector, 1, 1),
            Err(SequenceError::MissingHistory {
                from: 1,
                through: 1
            })
        ));
    }

    #[test]
    fn recovery_plan_replays_only_peer_missing_sequences() {
        let mut local = StreamState::with_limits(7, 16, SequenceLimits::new(8, 128, 8, 128))
            .expect("valid stream");
        local
            .send_frame(Direction::RelayToConnector, &data(1, 1))
            .expect("first");
        local
            .send_frame(Direction::RelayToConnector, &data(2, 2))
            .expect("second");
        let mut peer = local.snapshot();
        peer.directions[Direction::RelayToConnector.index()].recv_contiguous = 1;
        peer.directions[Direction::RelayToConnector.index()].delivered_contiguous = 1;
        let plan = local.reconcile(&peer).expect("recovery plan");
        assert_eq!(plan.replay(Direction::RelayToConnector).len(), 1);
        assert_eq!(plan.replay(Direction::RelayToConnector)[0].sequence, 2);
        assert_eq!(
            plan.peer_missing(Direction::RelayToConnector)
                .expect("peer replay range"),
            SequenceRange::new(1, 2).expect("range")
        );
    }

    #[test]
    fn recovery_rejects_peer_progress_below_observed_ack() {
        let mut local = StreamState::new(7, 16).expect("valid stream");
        local
            .send_frame(Direction::RelayToConnector, &data(1, 1))
            .expect("first");
        local
            .apply_ack(Direction::RelayToConnector, 1)
            .expect("ack");
        let mut peer = local.snapshot();
        peer.directions[Direction::RelayToConnector.index()].recv_contiguous = 0;
        assert!(matches!(
            local.reconcile(&peer),
            Err(SequenceError::RecoveryAckRegression { .. })
        ));
    }

    #[test]
    fn recovery_allows_missing_fin_to_be_replayed_but_rejects_lost_terminal_history() {
        let mut sender = StreamState::new(7, 16).expect("valid stream");
        sender
            .send_frame(
                Direction::RelayToConnector,
                &Frame::fin(EPOCH, GENERATION, 7, 1, 0),
            )
            .expect("FIN");
        let mut peer = sender.snapshot();
        peer.directions[Direction::RelayToConnector.index()].recv_contiguous = 0;
        peer.directions[Direction::RelayToConnector.index()].delivered_contiguous = 0;
        peer.directions[Direction::RelayToConnector.index()].receive_terminal = None;
        peer.directions[Direction::RelayToConnector.index()].receive_terminal_sequence = None;
        let plan = sender.reconcile(&peer).expect("missing FIN is replayable");
        assert_eq!(
            plan.replay(Direction::RelayToConnector)[0].kind,
            FrameKind::Fin
        );

        let mut receiver = StreamState::new(7, 16).expect("valid stream");
        receiver
            .receive_frame(
                Direction::RelayToConnector,
                &Frame::fin(EPOCH, GENERATION, 7, 1, 0),
            )
            .expect("received FIN");
        receiver
            .send_frame(Direction::RelayToConnector, &data(1, 8))
            .expect("local emitted sequence");
        let mut lost = receiver.snapshot();
        lost.directions[Direction::RelayToConnector.index()].last_emitted = 1;
        lost.directions[Direction::RelayToConnector.index()].replay_floor = Some(1);
        lost.directions[Direction::RelayToConnector.index()].send_terminal = None;
        lost.directions[Direction::RelayToConnector.index()].send_terminal_sequence = None;
        assert!(matches!(
            receiver.reconcile(&lost),
            Err(SequenceError::TerminalConflict {
                direction: Direction::RelayToConnector,
                ..
            })
        ));
    }

    #[test]
    fn recovery_rejects_invalid_terminal_and_replay_floor_evidence() {
        let state = StreamState::new(7, 16).expect("valid stream");
        let mut peer = state.snapshot();
        peer.directions[Direction::RelayToConnector.index()].send_terminal = Some(Terminal::Fin);
        assert!(matches!(
            state.reconcile(&peer),
            Err(SequenceError::InvalidRecoverySnapshot {
                field: "send_terminal",
                ..
            })
        ));
        let mut peer = state.snapshot();
        peer.directions[Direction::RelayToConnector.index()].last_emitted = 1;
        peer.directions[Direction::RelayToConnector.index()].replay_floor = None;
        assert!(matches!(
            state.reconcile(&peer),
            Err(SequenceError::InvalidRecoverySnapshot {
                field: "replay_floor",
                ..
            })
        ));
    }

    #[test]
    fn recovery_rejects_terminal_evidence_behind_send_or_receive_cursor() {
        let state = StreamState::new(7, 16).expect("valid stream");

        let mut send_behind = state.snapshot();
        let send = &mut send_behind.directions[Direction::RelayToConnector.index()];
        send.last_emitted = 2;
        send.send_terminal = Some(Terminal::Fin);
        send.send_terminal_sequence = Some(1);
        send.replay_floor = Some(1);
        assert!(matches!(
            state.reconcile(&send_behind),
            Err(SequenceError::InvalidRecoverySnapshot {
                field: "send_terminal",
                ..
            })
        ));

        let mut receive_behind = state.snapshot();
        let receive = &mut receive_behind.directions[Direction::RelayToConnector.index()];
        receive.recv_contiguous = 2;
        receive.receive_terminal = Some(Terminal::Fin);
        receive.receive_terminal_sequence = Some(1);
        assert!(matches!(
            state.reconcile(&receive_behind),
            Err(SequenceError::InvalidRecoverySnapshot {
                field: "receive_terminal",
                ..
            })
        ));
    }

    #[test]
    fn recovery_accepts_latest_reset_after_fin_terminal_evidence() {
        let mut sender = StreamState::new(7, 16).expect("valid stream");
        sender
            .send_frame(
                Direction::RelayToConnector,
                &Frame::fin(EPOCH, GENERATION, 7, 1, 0),
            )
            .expect("FIN");
        sender
            .send_frame(
                Direction::RelayToConnector,
                &Frame::reset(EPOCH, GENERATION, 7, 2, 0, 9),
            )
            .expect("RESET after FIN");

        let mut peer = sender.snapshot();
        let receive = &mut peer.directions[Direction::RelayToConnector.index()];
        receive.recv_contiguous = 2;
        receive.receive_terminal = Some(Terminal::Reset(9));
        receive.receive_terminal_sequence = Some(2);
        assert!(sender.reconcile(&peer).is_ok());
    }

    #[test]
    fn recovery_requires_terminal_evidence_at_the_receiver_cursor() {
        let mut sender = StreamState::new(7, 16).expect("valid stream");
        sender
            .send_frame(
                Direction::RelayToConnector,
                &Frame::fin(EPOCH, GENERATION, 7, 1, 0),
            )
            .expect("FIN");

        let mut behind = sender.snapshot();
        let behind_receive = &mut behind.directions[Direction::RelayToConnector.index()];
        behind_receive.recv_contiguous = 0;
        behind_receive.delivered_contiguous = 0;
        behind_receive.receive_terminal = None;
        behind_receive.receive_terminal_sequence = None;
        assert!(sender.reconcile(&behind).is_ok());

        let mut equal = sender.snapshot();
        let equal_receive = &mut equal.directions[Direction::RelayToConnector.index()];
        equal_receive.recv_contiguous = 1;
        equal_receive.delivered_contiguous = 1;
        equal_receive.receive_terminal = None;
        equal_receive.receive_terminal_sequence = None;
        assert!(matches!(
            sender.reconcile(&equal),
            Err(SequenceError::TerminalConflict {
                direction: Direction::RelayToConnector,
                ..
            })
        ));

        let mut receiver = StreamState::new(7, 16).expect("valid stream");
        receiver
            .receive_frame(
                Direction::RelayToConnector,
                &Frame::fin(EPOCH, GENERATION, 7, 1, 0),
            )
            .expect("received FIN");
        let receiver_state = &mut receiver.directions[Direction::RelayToConnector.index()];
        receiver_state.receive_terminal = None;
        receiver_state.receive_terminal_sequence = None;
        assert!(matches!(
            receiver.reconcile(&sender.snapshot()),
            Err(SequenceError::TerminalConflict {
                direction: Direction::RelayToConnector,
                ..
            })
        ));

        let receiver_behind = StreamState::new(7, 16).expect("valid stream");
        assert!(receiver_behind.reconcile(&sender.snapshot()).is_ok());
    }

    #[test]
    fn recovery_accepts_fin_cursor_before_reset_cursor() {
        let mut sender = StreamState::new(7, 16).expect("valid stream");
        sender
            .send_frame(
                Direction::RelayToConnector,
                &Frame::fin(EPOCH, GENERATION, 7, 1, 0),
            )
            .expect("FIN");
        sender
            .send_frame(
                Direction::RelayToConnector,
                &Frame::reset(EPOCH, GENERATION, 7, 2, 0, 9),
            )
            .expect("RESET after FIN");

        let mut after_fin = sender.snapshot();
        let receive = &mut after_fin.directions[Direction::RelayToConnector.index()];
        receive.recv_contiguous = 1;
        receive.delivered_contiguous = 1;
        receive.receive_terminal = Some(Terminal::Fin);
        receive.receive_terminal_sequence = Some(1);
        assert!(sender.reconcile(&after_fin).is_ok());

        let mut after_reset = sender.snapshot();
        let receive = &mut after_reset.directions[Direction::RelayToConnector.index()];
        receive.recv_contiguous = 2;
        receive.delivered_contiguous = 2;
        receive.receive_terminal = Some(Terminal::Reset(9));
        receive.receive_terminal_sequence = Some(2);
        assert!(sender.reconcile(&after_reset).is_ok());
    }

    #[test]
    fn generated_schedules_preserve_order_once_delivery_and_direction_bounds() {
        const SEEDS: [u64; 8] = [
            0x0123_4567_89ab_cdef,
            0x1020_3040_5060_7080,
            0xdead_beef_cafe_babe,
            0x3141_5926_5358_9793,
            0x2718_2818_2845_9045,
            0xa5a5_5a5a_33cc_cc33,
            0x0f0e_0d0c_0b0a_0908,
            0xfedc_ba98_7654_3210,
        ];
        const STREAMS_PER_SCHEDULE: usize = 4;
        let limits = SequenceLimits::new(16, 512, 16, 512);

        for (schedule_index, seed) in SEEDS.into_iter().enumerate() {
            let mut rng = ScheduleRng::new(seed);
            let mut senders = Vec::with_capacity(STREAMS_PER_SCHEDULE);
            let mut receivers = Vec::with_capacity(STREAMS_PER_SCHEDULE);
            let mut expected: Vec<[Vec<Frame>; 2]> = Vec::with_capacity(STREAMS_PER_SCHEDULE);
            let mut events: Vec<(usize, Direction, Frame)> = Vec::new();

            for stream_index in 0..STREAMS_PER_SCHEDULE {
                let stream_id = 10_000 + schedule_index as u64 * 100 + stream_index as u64;
                let mut sender = StreamState::with_limits(stream_id, 4 * 1024, limits)
                    .expect("generated sender limits");
                let receiver = StreamState::with_limits(stream_id, 4 * 1024, limits)
                    .expect("generated receiver limits");
                let mut expected_directions: [Vec<Frame>; 2] = [Vec::new(), Vec::new()];

                for (direction_index, direction) in
                    [Direction::RelayToConnector, Direction::ConnectorToRelay]
                        .into_iter()
                        .enumerate()
                {
                    let data_count =
                        2 + ((schedule_index + stream_index * 3 + direction_index) % 5) as u64;
                    let epoch = 100 + schedule_index as u64;
                    let generation = 10 + stream_index as u64 * 2 + direction_index as u64;
                    let include_reset = (schedule_index + stream_index + direction_index) % 2 == 0;
                    let mut frames = Vec::new();

                    for sequence in 1..=data_count {
                        let payload_len = 1 + (rng.next_u64() % 8) as usize;
                        let mut payload = Vec::with_capacity(payload_len);
                        for offset in 0..payload_len {
                            payload.push(
                                (rng.next_u64() as u8)
                                    .wrapping_add(stream_index as u8)
                                    .wrapping_add(direction_index as u8)
                                    .wrapping_add(offset as u8),
                            );
                        }
                        let frame = Frame::data(epoch, generation, stream_id, sequence, 0, payload);
                        sender
                            .send_frame(direction, &frame)
                            .expect("generated DATA sequence");
                        frames.push(frame);
                    }

                    let fin_sequence = data_count + 1;
                    let fin = Frame::fin(epoch, generation, stream_id, fin_sequence, 0);
                    sender
                        .send_frame(direction, &fin)
                        .expect("generated FIN sequence");
                    frames.push(fin);
                    if include_reset {
                        let reset =
                            Frame::reset(epoch, generation, stream_id, fin_sequence + 1, 0, 9);
                        sender
                            .send_frame(direction, &reset)
                            .expect("generated RESET sequence");
                        frames.push(reset);
                    }

                    for frame in &frames {
                        events.push((stream_index, direction, frame.clone()));
                        if frame.sequence == 1
                            || matches!(frame.kind, FrameKind::Fin | FrameKind::Reset)
                            || (frame.kind == FrameKind::Data && (rng.next_u64() & 3) == 0)
                        {
                            events.push((stream_index, direction, frame.clone()));
                        }
                    }
                    expected_directions[direction.index()] = frames;
                }

                senders.push(sender);
                receivers.push(receiver);
                expected.push(expected_directions);
            }

            rng.shuffle(&mut events);
            for stream_index in 0..STREAMS_PER_SCHEDULE {
                for direction in [Direction::RelayToConnector, Direction::ConnectorToRelay] {
                    let first_gap = events
                        .iter()
                        .position(|(index, candidate, frame)| {
                            *index == stream_index && *candidate == direction && frame.sequence > 1
                        })
                        .expect("generated direction has a gap frame");
                    let first_sequence = events
                        .iter()
                        .position(|(index, candidate, frame)| {
                            *index == stream_index && *candidate == direction && frame.sequence == 1
                        })
                        .expect("generated direction has sequence one");
                    if first_gap > first_sequence {
                        events.swap(first_gap, first_sequence);
                    }
                }
            }

            let mut buffered = 0usize;
            let mut duplicates = 0usize;
            for (stream_index, direction, frame) in events {
                let disposition = receivers[stream_index]
                    .receive_frame(direction, &frame)
                    .expect("generated schedule remains within bounds");
                match disposition {
                    ReceiveDisposition::Accepted => {}
                    ReceiveDisposition::Buffered => buffered += 1,
                    ReceiveDisposition::Duplicate => duplicates += 1,
                }
                let state = receivers[stream_index].direction(direction);
                assert!(
                    state.reorder_len().saturating_add(state.ready_len())
                        <= limits.max_reorder_frames.saturating_add(2),
                    "reorder frame bound exceeded for seed {seed:#x}"
                );
                assert!(
                    state.reorder_bytes().saturating_add(state.ready_bytes())
                        <= limits.max_reorder_bytes.saturating_add(2),
                    "reorder byte bound exceeded for seed {seed:#x}"
                );
            }
            assert!(buffered > 0, "seed {seed:#x} did not exercise a gap");
            assert!(duplicates > 0, "seed {seed:#x} did not exercise duplicates");

            for stream_index in 0..STREAMS_PER_SCHEDULE {
                assert_eq!(
                    senders[stream_index].stream_id(),
                    receivers[stream_index].stream_id()
                );
                for direction in [Direction::RelayToConnector, Direction::ConnectorToRelay] {
                    let direction_index = direction.index();
                    let expected_frames = &expected[stream_index][direction_index];
                    let expected_last = expected_frames
                        .last()
                        .expect("generated direction has a terminal")
                        .sequence;
                    let sender_state = senders[stream_index].direction(direction);
                    assert_eq!(sender_state.last_emitted(), expected_last);
                    assert_eq!(sender_state.peer_acked(), 0);
                    assert!(
                        sender_state.replay_len() <= limits.max_replay_frames.saturating_add(2)
                    );
                    assert!(
                        sender_state.replay_bytes() <= limits.max_replay_bytes.saturating_add(2)
                    );

                    let receiver_state = receivers[stream_index].direction(direction);
                    assert_eq!(receiver_state.recv_contiguous(), expected_last);
                    assert_eq!(receiver_state.delivered_contiguous(), 0);
                    let ready = receivers[stream_index].ready_frames(direction);
                    assert_eq!(ready.as_slice(), expected_frames.as_slice());
                    receivers[stream_index]
                        .mark_delivered(direction, expected_last)
                        .expect("ordered frames deliver once");
                    assert!(receivers[stream_index].ready_frames(direction).is_empty());
                    receivers[stream_index]
                        .mark_delivered(direction, expected_last)
                        .expect("delivery cursor is idempotent");
                    assert_eq!(
                        receivers[stream_index]
                            .direction(direction)
                            .delivered_contiguous(),
                        expected_last
                    );
                }
            }
        }
    }
}
