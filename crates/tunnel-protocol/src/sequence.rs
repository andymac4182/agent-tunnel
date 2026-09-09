//! Pure per-stream, per-direction sequence and credit accounting.
//!
//! This module deliberately knows nothing about sockets, rotations, epochs,
//! or adapter execution.  A caller validates the decoded frame's authenticated
//! [`crate::frame::DataContext`] first, then passes it to [`StreamState`].

use core::fmt;
use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::frame::{Frame, FrameError, FrameKind, MAX_PAYLOAD_LEN};

/// The two independent logical sequence spaces in a stream.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Direction {
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

/// Result of receiving a sequenced frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveDisposition {
    /// The frame advanced the contiguous receive cursor and should be
    /// delivered/accounted for by the caller.
    Accepted,
    /// The sequence was already received. It must not be delivered a second
    /// time and consumes no credit. If the bounded fingerprint retention
    /// window has expired, this is a transport-level duplicate decision and
    /// does not claim that the newly presented payload bytes are identical.
    Duplicate,
}

/// A bounded view of one direction's sequence and byte-credit state.
#[derive(Clone, Debug)]
pub struct DirectionState {
    last_emitted: u64,
    peer_acked: u64,
    recv_contiguous: u64,
    delivered_contiguous: u64,
    send_credit: u64,
    sent_bytes: u64,
    receive_credit: u64,
    received_bytes: u64,
    send_terminal: Option<Terminal>,
    receive_terminal: Option<Terminal>,
    fingerprints: BTreeMap<u64, FrameFingerprint>,
}

impl DirectionState {
    /// Maximum duplicate metadata retained per direction.  Retaining a
    /// bounded digest map detects changed immediate/recent duplicates without
    /// retaining application payloads.
    pub const MAX_RETAINED_FINGERPRINTS: usize = 128;

    fn new(send_credit: u64, receive_credit: u64) -> Self {
        Self {
            last_emitted: 0,
            peer_acked: 0,
            recv_contiguous: 0,
            delivered_contiguous: 0,
            send_credit,
            sent_bytes: 0,
            receive_credit,
            received_bytes: 0,
            send_terminal: None,
            receive_terminal: None,
            fingerprints: BTreeMap::new(),
        }
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
    pub const fn receive_terminal(&self) -> Option<Terminal> {
        self.receive_terminal
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
        }
        Ok(())
    }

    fn apply_send_credit(&mut self, limit: u64) -> Result<(), SequenceError> {
        if limit < self.send_credit {
            return Err(SequenceError::CreditDecreased {
                previous: self.send_credit,
                proposed: limit,
            });
        }
        self.send_credit = limit;
        Ok(())
    }

    fn advertise_receive_credit(&mut self, limit: u64) -> Result<(), SequenceError> {
        if limit < self.receive_credit {
            return Err(SequenceError::CreditDecreased {
                previous: self.receive_credit,
                proposed: limit,
            });
        }
        self.receive_credit = limit;
        Ok(())
    }

    fn emit(&mut self, frame: &Frame) -> Result<(), SequenceError> {
        match frame.kind {
            FrameKind::Ack | FrameKind::WindowUpdate => {
                debug_assert_eq!(frame.sequence, 0);
                Ok(())
            }
            FrameKind::Data | FrameKind::Fin | FrameKind::Reset => {
                if let Some(terminal) = self.send_terminal
                    && (frame.kind != FrameKind::Reset || terminal != Terminal::Fin)
                {
                    return Err(SequenceError::AfterTerminal {
                        kind: frame.kind,
                        terminal,
                    });
                }
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
                if frame.kind == FrameKind::Data {
                    let attempted = self
                        .sent_bytes
                        .checked_add(frame.payload.len() as u64)
                        .ok_or(SequenceError::CounterExhausted {
                            counter: "sent_bytes",
                        })?;
                    if attempted > self.send_credit {
                        return Err(SequenceError::CreditExceeded {
                            limit: self.send_credit,
                            attempted,
                        });
                    }
                    self.sent_bytes = attempted;
                }
                self.last_emitted = frame.sequence;
                if frame.kind == FrameKind::Fin {
                    self.send_terminal = Some(Terminal::Fin);
                } else if frame.kind == FrameKind::Reset {
                    self.send_terminal = Some(Terminal::Reset(frame.reset_reason()?.unwrap_or(0)));
                }
                Ok(())
            }
        }
    }

    fn receive(&mut self, frame: &Frame) -> Result<ReceiveDisposition, SequenceError> {
        match frame.kind {
            FrameKind::Ack | FrameKind::WindowUpdate => Ok(ReceiveDisposition::Accepted),
            FrameKind::Data | FrameKind::Fin | FrameKind::Reset => {
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
                if let Some(terminal) = self.receive_terminal {
                    return Err(SequenceError::AfterTerminal {
                        kind: frame.kind,
                        terminal,
                    });
                }
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
                if frame.kind == FrameKind::Data {
                    if frame.payload.len() > MAX_PAYLOAD_LEN {
                        return Err(SequenceError::Frame(FrameError::PayloadTooLarge {
                            length: frame.payload.len(),
                            maximum: MAX_PAYLOAD_LEN,
                        }));
                    }
                    let attempted = self
                        .received_bytes
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
                    self.received_bytes = attempted;
                }
                self.recv_contiguous = frame.sequence;
                self.retain_fingerprint(frame.sequence, digest);
                if frame.kind == FrameKind::Fin {
                    self.receive_terminal = Some(Terminal::Fin);
                } else if frame.kind == FrameKind::Reset {
                    self.receive_terminal =
                        Some(Terminal::Reset(frame.reset_reason()?.unwrap_or(0)));
                }
                Ok(ReceiveDisposition::Accepted)
            }
        }
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
        if through > self.delivered_contiguous {
            self.delivered_contiguous = through;
        }
        Ok(())
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
    /// directions.
    pub fn new(stream_id: u64, initial_credit: u64) -> Result<Self, SequenceError> {
        Self::with_credits(stream_id, initial_credit, initial_credit)
    }

    /// Construct a stream with independent local send and receive limits.
    pub fn with_credits(
        stream_id: u64,
        send_credit: u64,
        receive_credit: u64,
    ) -> Result<Self, SequenceError> {
        if stream_id == 0 {
            return Err(SequenceError::ZeroStreamId);
        }
        Ok(Self {
            stream_id,
            directions: [
                DirectionState::new(send_credit, receive_credit),
                DirectionState::new(send_credit, receive_credit),
            ],
        })
    }

    #[must_use]
    pub const fn stream_id(&self) -> u64 {
        self.stream_id
    }

    #[must_use]
    pub const fn direction(&self, direction: Direction) -> &DirectionState {
        &self.directions[direction.index()]
    }

    /// Validate and account for a locally emitted frame.
    pub fn send_frame(&mut self, direction: Direction, frame: &Frame) -> Result<(), SequenceError> {
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
            self.directions[opposite].advertise_receive_credit(frame.window)?;
        }
        self.directions[direction.index()].emit(frame)
    }

    /// Validate and account for a received frame.  ACKs and window updates
    /// are applied to the opposite sequence/credit direction.
    pub fn receive_frame(
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
        if frame.kind == FrameKind::WindowUpdate
            && frame.window < self.directions[opposite].send_credit
        {
            return Err(SequenceError::CreditDecreased {
                previous: self.directions[opposite].send_credit,
                proposed: frame.window,
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

    /// Mark contiguous received records as handed to the adapter.  This is
    /// separate from transport receipt and never increases credit by itself.
    pub fn mark_delivered(
        &mut self,
        direction: Direction,
        through: u64,
    ) -> Result<(), SequenceError> {
        self.directions[direction.index()].mark_delivered(through)
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

/// Errors from the pure sequence and credit state machine.
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
            } => {
                write!(f, "delivery cursor {requested} exceeds received {received}")
            }
            Self::CounterExhausted { counter } => write!(f, "counter {counter} is exhausted"),
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
    fn receive_requires_contiguous_sequences_and_suppresses_exact_duplicates() {
        let mut state = StreamState::new(7, 8).expect("valid stream");
        assert!(matches!(
            state.receive_frame(Direction::RelayToConnector, &data(2, 2)),
            Err(SequenceError::SequenceGap {
                expected: 1,
                actual: 2
            })
        ));
        assert_eq!(
            state
                .receive_frame(Direction::RelayToConnector, &data(1, 1))
                .expect("first frame"),
            ReceiveDisposition::Accepted
        );
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
    fn credit_is_absolute_and_terminal_frames_do_not_consume_payload_credit() {
        let mut state = StreamState::new(7, 1).expect("valid stream");
        state
            .send_frame(Direction::RelayToConnector, &data(1, 1))
            .expect("one byte fits");
        assert!(matches!(
            state.send_frame(Direction::RelayToConnector, &data(2, 2)),
            Err(SequenceError::CreditExceeded {
                limit: 1,
                attempted: 2
            })
        ));

        let fin = Frame::fin(EPOCH, GENERATION, 7, 2, 0);
        state
            .send_frame(Direction::RelayToConnector, &fin)
            .expect("FIN has reserved terminal capacity");
        assert_eq!(state.direction(Direction::RelayToConnector).sent_bytes(), 1);
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
    fn fin_then_reset_is_allowed_but_payload_after_fin_is_not() {
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
}
