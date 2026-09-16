//! The device→relay record framing for a filesystem logical stream.
//!
//! # Why there is a framing here at all
//!
//! The contract gives the two transports different rules, and gate 3 made them
//! two functions rather than one with a flag: the consumer WebSocket carries
//! **exactly one complete 9P message per binary message**, while the relay and
//! the device share **an ordered byte stream over tunnel DATA frames** where a
//! record may span frames and several may share one.
//!
//! The consumer→device direction needs nothing more than that: the relay
//! validates each binary message with `decode_exact` and forwards its bytes, and
//! the device reassembles them with `FrameDecoder`. The device→consumer
//! direction needs one thing the 9P stream cannot carry — **the close code**.
//! A session ends with a WebSocket close code (1002 for a framing violation,
//! 1008 for an authorization change, 1013 for overload), and those are decided
//! on the **device**, by the dispatcher that holds the grant. There is no 9P
//! message that means "close with 1008", and inventing one would put a
//! non-profile opcode on the wire.
//!
//! So the device→relay direction is a sequence of records:
//!
//! ```text
//!   kind[1] length[4] payload[length]
//! ```
//!
//! `kind = 1` is one complete 9P message, which the relay sends as one binary
//! WebSocket message without re-decoding it. `kind = 2` is a close, whose
//! one-byte payload names a [`SessionErrorCode`]. This is the same shape the
//! relay-to-relay hop in `http-forward/1` already uses for the same reason —
//! an ordered byte carrier that must also carry terminal detail — rather than a
//! new idea.
//!
//! # Bounded before allocation
//!
//! A declared length is checked against [`MAX_RECORD_BYTES`] before a byte is
//! reserved, and the decoder's first error is **latched**: a stream that
//! produced one framing violation has no trustworthy boundary to resynchronise
//! on, which is gate 3's own rule for the 9P decoder and is applied here for the
//! same reason.

use tunnel_fs_core::SessionErrorCode;

/// `kind` for a complete 9P message.
pub const KIND_MESSAGE: u8 = 1;
/// `kind` for a session close carrying its code.
pub const KIND_CLOSE: u8 = 2;

/// The fixed part of a record: `kind[1] length[4]`.
pub const RECORD_HEADER_LEN: usize = 5;

/// The largest payload a record may declare.
///
/// The absolute 9P message ceiling, which is also the largest thing a record can
/// legitimately carry. A close record carries one byte.
pub const MAX_RECORD_BYTES: usize = tunnel_fs_ninep::MAX_MESSAGE_BYTES as usize;

/// One record read off the device→relay stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Record {
    /// One complete 9P message, to be sent as one binary WebSocket message.
    Message(Vec<u8>),
    /// Close the consumer socket with this code.
    Close(SessionErrorCode),
}

/// Why a record could not be decoded. Field-free.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RecordError {
    /// The `kind` byte was not one this framing defines.
    UnknownKind,
    /// A declared length was above [`MAX_RECORD_BYTES`].
    TooLong,
    /// A close record did not carry exactly one code byte, or the byte was not
    /// one of gate 1's eight session error codes.
    MalformedClose,
}

impl RecordError {
    /// The stable diagnostic token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownKind => "UNKNOWN_KIND",
            Self::TooLong => "TOO_LONG",
            Self::MalformedClose => "MALFORMED_CLOSE",
        }
    }
}

impl core::fmt::Display for RecordError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for RecordError {}

/// The index of a session error code in gate 1's own `ALL`.
///
/// Taken from that array rather than assigned here, so a code added to the
/// vocabulary cannot be silently unrepresentable: the round trip below is
/// asserted over `SessionErrorCode::ALL`.
#[must_use]
pub fn close_byte(code: SessionErrorCode) -> u8 {
    let index = SessionErrorCode::ALL
        .into_iter()
        .position(|candidate| candidate == code)
        .unwrap_or(0);
    u8::try_from(index).unwrap_or(0)
}

/// The session error code a close byte names.
#[must_use]
pub fn close_code(byte: u8) -> Option<SessionErrorCode> {
    SessionErrorCode::ALL.get(usize::from(byte)).copied()
}

/// Append one 9P message record.
pub fn encode_message(message: &[u8], out: &mut Vec<u8>) {
    out.push(KIND_MESSAGE);
    out.extend_from_slice(
        &u32::try_from(message.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    out.extend_from_slice(message);
}

/// Append one close record.
pub fn encode_close(code: SessionErrorCode, out: &mut Vec<u8>) {
    out.push(KIND_CLOSE);
    out.extend_from_slice(&1_u32.to_be_bytes());
    out.push(close_byte(code));
}

/// An incremental decoder over the ordered device→relay byte stream.
#[derive(Debug, Default)]
pub struct RecordDecoder {
    buffer: Vec<u8>,
    latched: Option<RecordError>,
}

impl RecordDecoder {
    /// A fresh decoder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Take more bytes from the carrier.
    ///
    /// # Errors
    ///
    /// The **latched** first violation, once one has been seen: the decoder
    /// keeps reporting the error that actually happened rather than a second
    /// code that would hide it.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), RecordError> {
        if let Some(error) = self.latched {
            return Err(error);
        }
        // Bounded before the copy: the buffer never holds more than one
        // maximum-size record plus its header.
        if self.buffer.len() + bytes.len() > MAX_RECORD_BYTES + RECORD_HEADER_LEN {
            return Err(self.latch(RecordError::TooLong));
        }
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    /// The next complete record, or `None` while one is still arriving.
    ///
    /// # Errors
    ///
    /// Any [`RecordError`]. The first one is **latched**: a stream that
    /// produced a framing violation has no trustworthy boundary to
    /// resynchronise on, so every later call reports that same violation and no
    /// well-formed record arriving after one is decoded.
    pub fn next_record(&mut self) -> Result<Option<Record>, RecordError> {
        if let Some(error) = self.latched {
            return Err(error);
        }
        if self.buffer.len() < RECORD_HEADER_LEN {
            return Ok(None);
        }
        let kind = self.buffer[0];
        let length = u32::from_be_bytes([
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
            self.buffer[4],
        ]);
        let length = usize::try_from(length).unwrap_or(usize::MAX);
        if length > MAX_RECORD_BYTES {
            return Err(self.latch(RecordError::TooLong));
        }
        if self.buffer.len() < RECORD_HEADER_LEN + length {
            return Ok(None);
        }
        let payload: Vec<u8> = self.buffer[RECORD_HEADER_LEN..RECORD_HEADER_LEN + length].to_vec();
        self.buffer.drain(..RECORD_HEADER_LEN + length);
        match kind {
            KIND_MESSAGE => Ok(Some(Record::Message(payload))),
            KIND_CLOSE => {
                let Some(code) = payload.first().copied().and_then(close_code) else {
                    return Err(self.latch(RecordError::MalformedClose));
                };
                if payload.len() != 1 {
                    return Err(self.latch(RecordError::MalformedClose));
                }
                Ok(Some(Record::Close(code)))
            }
            _ => Err(self.latch(RecordError::UnknownKind)),
        }
    }

    /// How many bytes are retained waiting for the rest of a record.
    #[must_use]
    pub fn retained(&self) -> usize {
        self.buffer.len()
    }

    fn latch(&mut self, error: RecordError) -> RecordError {
        self.latched = Some(error);
        self.buffer.clear();
        error
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_RECORD_BYTES, RECORD_HEADER_LEN, Record, RecordDecoder, RecordError, close_byte,
        close_code, encode_close, encode_message,
    };
    use tunnel_fs_core::SessionErrorCode;

    #[test]
    fn every_session_error_code_round_trips_through_one_byte() {
        for code in SessionErrorCode::ALL {
            assert_eq!(close_code(close_byte(code)), Some(code), "{code}");
        }
        assert_eq!(close_code(u8::MAX), None);
    }

    #[test]
    fn records_round_trip_at_every_split_point() {
        let mut stream = Vec::new();
        encode_message(b"first-message", &mut stream);
        encode_close(SessionErrorCode::CapabilitiesChanged, &mut stream);
        encode_message(b"second", &mut stream);

        for cut in 0..=stream.len() {
            let mut decoder = RecordDecoder::new();
            let mut records = Vec::new();
            for chunk in [&stream[..cut], &stream[cut..]] {
                decoder.push(chunk).expect("push");
                while let Some(record) = decoder.next_record().expect("decode") {
                    records.push(record);
                }
            }
            assert_eq!(
                records,
                vec![
                    Record::Message(b"first-message".to_vec()),
                    Record::Close(SessionErrorCode::CapabilitiesChanged),
                    Record::Message(b"second".to_vec()),
                ],
                "cut at {cut}"
            );
            assert_eq!(decoder.retained(), 0);
        }
    }

    #[test]
    fn a_declared_length_above_the_ceiling_is_refused_before_any_copy() {
        let mut decoder = RecordDecoder::new();
        let mut header = vec![super::KIND_MESSAGE];
        header.extend_from_slice(
            &u32::try_from(MAX_RECORD_BYTES + 1)
                .expect("fits")
                .to_be_bytes(),
        );
        decoder.push(&header).expect("the header itself fits");
        assert_eq!(decoder.next_record(), Err(RecordError::TooLong));
    }

    #[test]
    fn the_first_violation_is_latched_and_a_valid_record_after_it_is_not_decoded() {
        let mut decoder = RecordDecoder::new();
        let mut stream = vec![9_u8, 0, 0, 0, 0];
        encode_message(b"well-formed", &mut stream);
        decoder.push(&stream).expect("push");
        assert_eq!(decoder.next_record(), Err(RecordError::UnknownKind));
        // The latched error keeps naming the violation that happened.
        assert_eq!(decoder.next_record(), Err(RecordError::UnknownKind));
        assert_eq!(decoder.push(b"more"), Err(RecordError::UnknownKind));
    }

    #[test]
    fn a_close_record_with_an_unknown_code_is_refused() {
        let mut decoder = RecordDecoder::new();
        decoder
            .push(&[super::KIND_CLOSE, 0, 0, 0, 1, u8::MAX])
            .expect("push");
        assert_eq!(decoder.next_record(), Err(RecordError::MalformedClose));
    }

    #[test]
    fn a_record_exactly_at_the_ceiling_is_accepted() {
        let body = vec![7_u8; MAX_RECORD_BYTES];
        let mut stream = Vec::new();
        encode_message(&body, &mut stream);
        assert_eq!(stream.len(), MAX_RECORD_BYTES + RECORD_HEADER_LEN);
        let mut decoder = RecordDecoder::new();
        decoder.push(&stream).expect("push");
        assert_eq!(
            decoder.next_record().expect("decode"),
            Some(Record::Message(body))
        );
    }
}
