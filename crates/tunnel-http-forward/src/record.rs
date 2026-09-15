//! The fixed eight-byte `http-forward/1` record header and record encoders.

use crate::error::CodecError;

/// Every record begins with this many header bytes.
pub const RECORD_HEADER_LEN: usize = 8;
/// The largest complete record, header included.
pub const MAX_RECORD_LEN: usize = 65_536;
/// The largest BODY payload.
pub const MAX_BODY_PAYLOAD_LEN: usize = MAX_RECORD_LEN - RECORD_HEADER_LEN;
/// The largest REQUEST_HEAD or RESPONSE_HEAD payload (16 KiB).
pub const MAX_HEAD_PAYLOAD_LEN: usize = 16 * 1024;

/// The four record kinds assigned in v1.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RecordKind {
    RequestHead = 0x01,
    ResponseHead = 0x02,
    Body = 0x03,
    End = 0x04,
}

impl RecordKind {
    /// The registry byte used on the wire.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Decode a kind byte.
    ///
    /// # Errors
    /// Returns [`CodecError::UnknownKind`] for unassigned bytes.
    pub const fn from_code(code: u8) -> Result<Self, CodecError> {
        match code {
            0x01 => Ok(Self::RequestHead),
            0x02 => Ok(Self::ResponseHead),
            0x03 => Ok(Self::Body),
            0x04 => Ok(Self::End),
            other => Err(CodecError::UnknownKind(other)),
        }
    }
}

/// A validated fixed record header.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RecordHeader {
    kind: RecordKind,
    payload_len: u32,
}

impl RecordHeader {
    /// Build a header, enforcing the kind-specific payload length.
    ///
    /// # Errors
    /// Returns the same length errors as [`RecordHeader::decode`].
    pub const fn new(kind: RecordKind, payload_len: u32) -> Result<Self, CodecError> {
        match check_length(kind, payload_len) {
            Ok(()) => Ok(Self { kind, payload_len }),
            Err(error) => Err(error),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> RecordKind {
        self.kind
    }

    #[must_use]
    pub const fn payload_len(&self) -> u32 {
        self.payload_len
    }

    /// Decode and validate eight header bytes.  All checks run before any
    /// payload byte is read or allocated.
    ///
    /// # Errors
    /// Unknown kind, nonzero flags, nonzero reserved bytes, or a
    /// kind-specific invalid length.
    pub const fn decode(bytes: [u8; RECORD_HEADER_LEN]) -> Result<Self, CodecError> {
        let kind = match RecordKind::from_code(bytes[0]) {
            Ok(kind) => kind,
            Err(error) => return Err(error),
        };
        if bytes[1] != 0 {
            return Err(CodecError::NonzeroFlags);
        }
        if bytes[2] != 0 || bytes[3] != 0 {
            return Err(CodecError::NonzeroReserved);
        }
        let payload_len = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        Self::new(kind, payload_len)
    }

    /// Encode the header in network byte order.
    #[must_use]
    pub const fn encode(&self) -> [u8; RECORD_HEADER_LEN] {
        let len = self.payload_len.to_be_bytes();
        [self.kind.code(), 0, 0, 0, len[0], len[1], len[2], len[3]]
    }
}

const fn check_length(kind: RecordKind, payload_len: u32) -> Result<(), CodecError> {
    // Compare in u64 so no platform `usize` width can truncate.
    let len = payload_len as u64;
    match kind {
        RecordKind::RequestHead | RecordKind::ResponseHead => {
            if len == 0 {
                Err(CodecError::EmptyHead)
            } else if len > MAX_HEAD_PAYLOAD_LEN as u64 {
                Err(CodecError::HeadTooLarge)
            } else {
                Ok(())
            }
        }
        RecordKind::Body => {
            if len == 0 {
                Err(CodecError::EmptyBody)
            } else if len > MAX_BODY_PAYLOAD_LEN as u64 {
                Err(CodecError::RecordTooLarge)
            } else {
                Ok(())
            }
        }
        RecordKind::End => {
            if len == 0 {
                Ok(())
            } else {
                Err(CodecError::EndWithPayload)
            }
        }
    }
}

/// The complete END record.
pub const END_RECORD: [u8; RECORD_HEADER_LEN] = [RecordKind::End.code(), 0, 0, 0, 0, 0, 0, 0];

/// Append one HEAD or BODY record with an already bounded payload.
///
/// # Errors
/// Returns a length error if the payload violates the kind's bounds, or
/// [`CodecError::EndWithPayload`] for a nonempty END.
pub fn encode_record(
    kind: RecordKind,
    payload: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), CodecError> {
    let payload_len = u32::try_from(payload.len()).map_err(|_| match kind {
        RecordKind::RequestHead | RecordKind::ResponseHead => CodecError::HeadTooLarge,
        RecordKind::Body => CodecError::RecordTooLarge,
        RecordKind::End => CodecError::EndWithPayload,
    })?;
    let header = RecordHeader::new(kind, payload_len)?;
    out.reserve(RECORD_HEADER_LEN + payload.len());
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(payload);
    Ok(())
}

/// Append body octets as consecutive maximum-size BODY records.  Empty input
/// appends nothing, since BODY records are never empty.
pub fn encode_body(body: &[u8], out: &mut Vec<u8>) {
    for chunk in body.chunks(MAX_BODY_PAYLOAD_LEN) {
        // Chunks are 1..=MAX_BODY_PAYLOAD_LEN by construction.
        if let Ok(len) = u32::try_from(chunk.len())
            && let Ok(header) = RecordHeader::new(RecordKind::Body, len)
        {
            out.extend_from_slice(&header.encode());
            out.extend_from_slice(chunk);
        }
    }
}
