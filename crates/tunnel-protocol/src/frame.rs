//! The fixed-width binary data frame used by the tunnel.
//!
//! A WebSocket binary message contains exactly one frame.  WebSocket
//! fragmentation is therefore outside this codec; callers must provide the
//! complete message to [`Frame::decode`].

use core::fmt;

/// The protocol major version implemented by this crate.
pub const PROTOCOL_MAJOR: u8 = 1;
/// The four-byte frame discriminator.
pub const MAGIC: [u8; 4] = *b"ATUN";
/// Every frame has this header size, in bytes.
pub const HEADER_LEN: usize = 64;
/// The largest DATA payload accepted by the codec.
pub const MAX_PAYLOAD_LEN: usize = 64 * 1024;
/// The largest complete encoded frame.
pub const MAX_FRAME_LEN: usize = HEADER_LEN + MAX_PAYLOAD_LEN;
/// No frame flags are assigned in the initial protocol version.
pub const KNOWN_FLAGS: u16 = 0;

/// The five data-frame kinds assigned by the initial numeric registry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    Data = 1,
    Fin = 2,
    Ack = 3,
    WindowUpdate = 4,
    Reset = 5,
}

impl FrameKind {
    /// Return the registry value used in the binary header.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for FrameKind {
    type Error = FrameError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Data),
            2 => Ok(Self::Fin),
            3 => Ok(Self::Ack),
            4 => Ok(Self::WindowUpdate),
            5 => Ok(Self::Reset),
            other => Err(FrameError::UnknownKind(other)),
        }
    }
}

/// The authenticated context supplied by a data-socket attachment.
///
/// The frame header carries only `epoch` and `generation`; `session_id` is
/// retained here so a caller can compare the complete context before passing
/// a decoded frame to stream state.  This type intentionally performs no
/// validation or ID generation.  Authentication and ownership code owns
/// those checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataContext {
    pub session_id: String,
    pub epoch: u64,
    pub generation: u64,
}

impl DataContext {
    /// Construct a context without attempting to validate its identifiers.
    #[must_use]
    pub fn new(session_id: impl Into<String>, epoch: u64, generation: u64) -> Self {
        Self {
            session_id: session_id.into(),
            epoch,
            generation,
        }
    }
}

/// One complete tunnel frame.
#[derive(Clone, Eq, PartialEq)]
pub struct Frame {
    pub version: u8,
    pub kind: FrameKind,
    pub flags: u16,
    pub epoch: u64,
    pub generation: u64,
    pub stream_id: u64,
    pub sequence: u64,
    /// Cumulative acknowledgement of the opposite direction.
    pub ack: u64,
    /// Absolute cumulative byte limit for the opposite direction.  This is
    /// meaningful only for [`FrameKind::WindowUpdate`].
    pub window: u64,
    pub payload: Vec<u8>,
}

impl fmt::Debug for Frame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Frame")
            .field("version", &self.version)
            .field("kind", &self.kind)
            .field("flags", &self.flags)
            .field("epoch", &self.epoch)
            .field("generation", &self.generation)
            .field("stream_id", &self.stream_id)
            .field("sequence", &self.sequence)
            .field("ack", &self.ack)
            .field("window", &self.window)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl Frame {
    /// Construct a frame with the fixed protocol version and no flags.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: FrameKind,
        epoch: u64,
        generation: u64,
        stream_id: u64,
        sequence: u64,
        ack: u64,
        window: u64,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            version: PROTOCOL_MAJOR,
            kind,
            flags: 0,
            epoch,
            generation,
            stream_id,
            sequence,
            ack,
            window,
            payload: payload.into(),
        }
    }

    /// Construct a DATA frame.
    #[must_use]
    pub fn data(
        epoch: u64,
        generation: u64,
        stream_id: u64,
        sequence: u64,
        ack: u64,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self::new(
            FrameKind::Data,
            epoch,
            generation,
            stream_id,
            sequence,
            ack,
            0,
            payload,
        )
    }

    /// Construct a FIN frame.
    #[must_use]
    pub fn fin(epoch: u64, generation: u64, stream_id: u64, sequence: u64, ack: u64) -> Self {
        Self::new(
            FrameKind::Fin,
            epoch,
            generation,
            stream_id,
            sequence,
            ack,
            0,
            Vec::new(),
        )
    }

    /// Construct an unsequenced cumulative ACK frame.
    #[must_use]
    pub fn ack(epoch: u64, generation: u64, stream_id: u64, acknowledged: u64) -> Self {
        Self::new(
            FrameKind::Ack,
            epoch,
            generation,
            stream_id,
            0,
            acknowledged,
            0,
            Vec::new(),
        )
    }

    /// Construct an unsequenced absolute credit update.
    #[must_use]
    pub fn window_update(epoch: u64, generation: u64, stream_id: u64, limit: u64) -> Self {
        Self::new(
            FrameKind::WindowUpdate,
            epoch,
            generation,
            stream_id,
            0,
            0,
            limit,
            Vec::new(),
        )
    }

    /// Construct a RESET frame.  The reason is encoded as a network-order
    /// unsigned 16-bit value in the reserved terminal-frame payload.
    #[must_use]
    pub fn reset(
        epoch: u64,
        generation: u64,
        stream_id: u64,
        sequence: u64,
        ack: u64,
        reason: u16,
    ) -> Self {
        Self::new(
            FrameKind::Reset,
            epoch,
            generation,
            stream_id,
            sequence,
            ack,
            0,
            reason.to_be_bytes(),
        )
    }

    /// Return the RESET reason, if this is a valid RESET frame.
    pub fn reset_reason(&self) -> Result<Option<u16>, FrameError> {
        self.validate()?;
        if self.kind != FrameKind::Reset {
            return Ok(None);
        }
        Ok(Some(u16::from_be_bytes([self.payload[0], self.payload[1]])))
    }

    /// Validate all framing and kind-specific invariants.
    pub fn validate(&self) -> Result<(), FrameError> {
        if self.version != PROTOCOL_MAJOR {
            return Err(FrameError::UnsupportedVersion(self.version));
        }
        if self.flags & !KNOWN_FLAGS != 0 {
            return Err(FrameError::ReservedFlags(self.flags));
        }
        if self.stream_id == 0 {
            return Err(FrameError::ZeroStreamId);
        }
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(FrameError::PayloadTooLarge {
                length: self.payload.len(),
                maximum: MAX_PAYLOAD_LEN,
            });
        }

        match self.kind {
            FrameKind::Data => {
                if self.sequence == 0 {
                    return Err(FrameError::ZeroSequence { kind: self.kind });
                }
                if self.window != 0 {
                    return Err(FrameError::UnexpectedWindow { kind: self.kind });
                }
            }
            FrameKind::Fin => {
                if self.sequence == 0 {
                    return Err(FrameError::ZeroSequence { kind: self.kind });
                }
                if !self.payload.is_empty() {
                    return Err(FrameError::UnexpectedPayload { kind: self.kind });
                }
                if self.window != 0 {
                    return Err(FrameError::UnexpectedWindow { kind: self.kind });
                }
            }
            FrameKind::Ack => {
                if self.sequence != 0 {
                    return Err(FrameError::UnexpectedSequence { kind: self.kind });
                }
                if !self.payload.is_empty() {
                    return Err(FrameError::UnexpectedPayload { kind: self.kind });
                }
                if self.window != 0 {
                    return Err(FrameError::UnexpectedWindow { kind: self.kind });
                }
            }
            FrameKind::WindowUpdate => {
                if self.sequence != 0 {
                    return Err(FrameError::UnexpectedSequence { kind: self.kind });
                }
                if !self.payload.is_empty() {
                    return Err(FrameError::UnexpectedPayload { kind: self.kind });
                }
                if self.ack != 0 {
                    return Err(FrameError::UnexpectedAcknowledgement { kind: self.kind });
                }
            }
            FrameKind::Reset => {
                if self.sequence == 0 {
                    return Err(FrameError::ZeroSequence { kind: self.kind });
                }
                if self.payload.len() != 2 {
                    return Err(FrameError::InvalidPayloadLength {
                        kind: self.kind,
                        expected: 2,
                        actual: self.payload.len(),
                    });
                }
                if self.window != 0 {
                    return Err(FrameError::UnexpectedWindow { kind: self.kind });
                }
            }
        }
        Ok(())
    }

    /// Return the encoded frame length if the payload fits the hard bound.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        HEADER_LEN.saturating_add(self.payload.len())
    }

    /// Encode this frame in network byte order.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        self.validate()?;
        let payload_len =
            u32::try_from(self.payload.len()).map_err(|_| FrameError::PayloadTooLarge {
                length: self.payload.len(),
                maximum: MAX_PAYLOAD_LEN,
            })?;
        let mut encoded = vec![0_u8; HEADER_LEN + self.payload.len()];
        encoded[0..4].copy_from_slice(&MAGIC);
        encoded[4] = self.version;
        encoded[5] = self.kind.code();
        encoded[6..8].copy_from_slice(&self.flags.to_be_bytes());
        encoded[8..10].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        // Bytes 10..12 are reserved and remain zero.
        encoded[12..20].copy_from_slice(&self.epoch.to_be_bytes());
        encoded[20..28].copy_from_slice(&self.generation.to_be_bytes());
        encoded[28..36].copy_from_slice(&self.stream_id.to_be_bytes());
        encoded[36..44].copy_from_slice(&self.sequence.to_be_bytes());
        encoded[44..52].copy_from_slice(&self.ack.to_be_bytes());
        encoded[52..60].copy_from_slice(&self.window.to_be_bytes());
        encoded[60..64].copy_from_slice(&payload_len.to_be_bytes());
        encoded[HEADER_LEN..].copy_from_slice(&self.payload);
        Ok(encoded)
    }

    /// Decode one complete frame and reject trailing or truncated bytes.
    pub fn decode(encoded: &[u8]) -> Result<Self, FrameError> {
        if encoded.len() < HEADER_LEN {
            return Err(FrameError::Truncated {
                minimum: HEADER_LEN,
                actual: encoded.len(),
            });
        }
        if encoded.len() > MAX_FRAME_LEN {
            return Err(FrameError::FrameTooLarge {
                length: encoded.len(),
                maximum: MAX_FRAME_LEN,
            });
        }
        if encoded[0..4] != MAGIC {
            return Err(FrameError::InvalidMagic(
                encoded[0..4].try_into().expect("slice length"),
            ));
        }

        let version = encoded[4];
        if version != PROTOCOL_MAJOR {
            return Err(FrameError::UnsupportedVersion(version));
        }
        let kind = FrameKind::try_from(encoded[5])?;
        let flags = u16::from_be_bytes([encoded[6], encoded[7]]);
        if flags & !KNOWN_FLAGS != 0 {
            return Err(FrameError::ReservedFlags(flags));
        }
        let header_len = u16::from_be_bytes([encoded[8], encoded[9]]);
        if header_len as usize != HEADER_LEN {
            return Err(FrameError::InvalidHeaderLength(header_len));
        }
        let reserved = u16::from_be_bytes([encoded[10], encoded[11]]);
        if reserved != 0 {
            return Err(FrameError::NonZeroReserved(reserved));
        }
        let payload_len =
            u32::from_be_bytes([encoded[60], encoded[61], encoded[62], encoded[63]]) as usize;
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(FrameError::PayloadTooLarge {
                length: payload_len,
                maximum: MAX_PAYLOAD_LEN,
            });
        }
        let expected = HEADER_LEN + payload_len;
        if encoded.len() != expected {
            return Err(FrameError::LengthMismatch {
                expected,
                actual: encoded.len(),
            });
        }

        let frame = Self {
            version,
            kind,
            flags,
            epoch: u64::from_be_bytes(encoded[12..20].try_into().expect("slice length")),
            generation: u64::from_be_bytes(encoded[20..28].try_into().expect("slice length")),
            stream_id: u64::from_be_bytes(encoded[28..36].try_into().expect("slice length")),
            sequence: u64::from_be_bytes(encoded[36..44].try_into().expect("slice length")),
            ack: u64::from_be_bytes(encoded[44..52].try_into().expect("slice length")),
            window: u64::from_be_bytes(encoded[52..60].try_into().expect("slice length")),
            payload: encoded[HEADER_LEN..].to_vec(),
        };
        frame.validate()?;
        Ok(frame)
    }
}

/// Encode one frame.  This free function mirrors [`Frame::encode`] for code
/// that prefers function-oriented codec APIs.
pub fn encode(frame: &Frame) -> Result<Vec<u8>, FrameError> {
    frame.encode()
}

/// Decode one complete frame.  This free function mirrors [`Frame::decode`].
pub fn decode(encoded: &[u8]) -> Result<Frame, FrameError> {
    Frame::decode(encoded)
}

/// Errors returned by the bounded frame codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrameError {
    InvalidMagic([u8; 4]),
    UnsupportedVersion(u8),
    UnknownKind(u8),
    ReservedFlags(u16),
    InvalidHeaderLength(u16),
    NonZeroReserved(u16),
    Truncated {
        minimum: usize,
        actual: usize,
    },
    FrameTooLarge {
        length: usize,
        maximum: usize,
    },
    LengthMismatch {
        expected: usize,
        actual: usize,
    },
    PayloadTooLarge {
        length: usize,
        maximum: usize,
    },
    InvalidPayloadLength {
        kind: FrameKind,
        expected: usize,
        actual: usize,
    },
    UnexpectedPayload {
        kind: FrameKind,
    },
    UnexpectedSequence {
        kind: FrameKind,
    },
    ZeroSequence {
        kind: FrameKind,
    },
    UnexpectedAcknowledgement {
        kind: FrameKind,
    },
    UnexpectedWindow {
        kind: FrameKind,
    },
    ZeroStreamId,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic(magic) => write!(f, "invalid frame magic {magic:?}"),
            Self::UnsupportedVersion(version) => write!(f, "unsupported frame version {version}"),
            Self::UnknownKind(kind) => write!(f, "unknown frame kind {kind}"),
            Self::ReservedFlags(flags) => write!(f, "reserved frame flags are set: 0x{flags:04x}"),
            Self::InvalidHeaderLength(length) => write!(f, "invalid frame header length {length}"),
            Self::NonZeroReserved(value) => {
                write!(f, "reserved header field is {value}, expected zero")
            }
            Self::Truncated { minimum, actual } => {
                write!(
                    f,
                    "truncated frame: need at least {minimum} bytes, got {actual}"
                )
            }
            Self::FrameTooLarge { length, maximum } => {
                write!(f, "frame is {length} bytes, maximum is {maximum}")
            }
            Self::LengthMismatch { expected, actual } => {
                write!(
                    f,
                    "frame length mismatch: header requires {expected}, got {actual}"
                )
            }
            Self::PayloadTooLarge { length, maximum } => {
                write!(f, "payload is {length} bytes, maximum is {maximum}")
            }
            Self::InvalidPayloadLength {
                kind,
                expected,
                actual,
            } => write!(f, "{kind:?} payload must be {expected} bytes, got {actual}"),
            Self::UnexpectedPayload { kind } => write!(f, "{kind:?} does not carry a payload"),
            Self::UnexpectedSequence { kind } => write!(f, "{kind:?} is unsequenced"),
            Self::ZeroSequence { kind } => write!(f, "{kind:?} requires a nonzero sequence"),
            Self::UnexpectedAcknowledgement { kind } => {
                write!(f, "{kind:?} cannot carry an acknowledgement")
            }
            Self::UnexpectedWindow { kind } => write!(f, "{kind:?} cannot carry a window limit"),
            Self::ZeroStreamId => write!(f, "stream ID must be nonzero"),
        }
    }
}

impl std::error::Error for FrameError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data(payload: Vec<u8>) -> Frame {
        Frame::data(7, 11, 19, 3, 2, payload)
    }

    #[test]
    fn golden_data_header_is_network_order_and_fixed_width() {
        let frame = sample_data(vec![0xaa, 0xbb]);
        let encoded = frame.encode().expect("valid frame");
        assert_eq!(
            encoded,
            vec![
                b'A', b'T', b'U', b'N', 1, 1, 0, 0, 0, 64, 0,
                0, // magic/version/kind/flags/header/reserved
                0, 0, 0, 0, 0, 0, 0, 7, // epoch
                0, 0, 0, 0, 0, 0, 0, 11, // generation
                0, 0, 0, 0, 0, 0, 0, 19, // stream
                0, 0, 0, 0, 0, 0, 0, 3, // sequence
                0, 0, 0, 0, 0, 0, 0, 2, // ack
                0, 0, 0, 0, 0, 0, 0, 0, // window
                0, 0, 0, 2, // payload len
                0xaa, 0xbb,
            ]
        );
        assert_eq!(Frame::decode(&encoded).expect("round trip"), frame);
    }

    #[test]
    fn every_registered_kind_has_the_expected_numeric_code() {
        assert_eq!(FrameKind::Data.code(), 1);
        assert_eq!(FrameKind::Fin.code(), 2);
        assert_eq!(FrameKind::Ack.code(), 3);
        assert_eq!(FrameKind::WindowUpdate.code(), 4);
        assert_eq!(FrameKind::Reset.code(), 5);
    }

    #[test]
    fn maximum_payload_is_accepted_and_one_byte_over_is_rejected() {
        let frame = sample_data(vec![0x5a; MAX_PAYLOAD_LEN]);
        let encoded = frame.encode().expect("maximum payload is valid");
        assert_eq!(encoded.len(), MAX_FRAME_LEN);
        assert_eq!(
            Frame::decode(&encoded).expect("maximum payload round trip"),
            frame
        );

        let too_large = sample_data(vec![0x5a; MAX_PAYLOAD_LEN + 1]);
        assert!(matches!(
            too_large.encode(),
            Err(FrameError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn malformed_reserved_fields_and_lengths_are_rejected() {
        let frame = sample_data(vec![1, 2, 3]);
        let mut encoded = frame.encode().expect("valid frame");

        encoded[11] = 1;
        assert!(matches!(
            Frame::decode(&encoded),
            Err(FrameError::NonZeroReserved(1))
        ));

        let mut encoded = frame.encode().expect("valid frame");
        encoded[6] = 0x80;
        assert!(matches!(
            Frame::decode(&encoded),
            Err(FrameError::ReservedFlags(0x8000))
        ));

        let mut encoded = frame.encode().expect("valid frame");
        encoded[63] = 4;
        assert!(matches!(
            Frame::decode(&encoded),
            Err(FrameError::LengthMismatch { expected, actual })
                if expected == HEADER_LEN + 4 && actual == HEADER_LEN + 3
        ));

        let mut encoded = frame.encode().expect("valid frame");
        encoded[5] = 0xff;
        assert!(matches!(
            Frame::decode(&encoded),
            Err(FrameError::UnknownKind(0xff))
        ));
    }

    #[test]
    fn kind_specific_lengths_are_checked() {
        let mut fin = Frame::fin(1, 1, 1, 1, 0);
        fin.payload.push(1);
        assert!(matches!(
            fin.validate(),
            Err(FrameError::UnexpectedPayload { .. })
        ));

        let mut reset = Frame::reset(1, 1, 1, 1, 0, 9);
        reset.payload.push(1);
        assert!(matches!(
            reset.validate(),
            Err(FrameError::InvalidPayloadLength { .. })
        ));

        let mut ack = Frame::ack(1, 1, 1, 1);
        ack.sequence = 1;
        assert!(matches!(
            ack.validate(),
            Err(FrameError::UnexpectedSequence { .. })
        ));
    }
}
