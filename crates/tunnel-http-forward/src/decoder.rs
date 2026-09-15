//! Incremental record decoder.
//!
//! The decoder accepts arbitrary input splits and coalesced records.  It
//! retains at most one unfinished eight-byte header or one bounded HEAD
//! payload.  BODY octets are never retained: each call yields a slice of the
//! caller's input, so an HTTP body is streamed rather than collected.

use core::mem;

use crate::error::CodecError;
use crate::record::{RECORD_HEADER_LEN, RecordHeader, RecordKind};

/// One decoded event.  BODY slices borrow the caller's input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordEvent<'input> {
    /// A fixed header was validated.  For END this is the complete record.
    /// It is yielded before any payload byte is consumed or allocated, so a
    /// caller can reject the record on its kind and length alone.
    Header(RecordHeader),
    /// The complete payload of the preceding HEAD header.
    Head(Vec<u8>),
    /// Some octets of the preceding BODY record.  `record_done` is true for
    /// the fragment that completes the record.
    Body {
        data: &'input [u8],
        record_done: bool,
    },
}

/// Observable state of a partly received record, for the caller's
/// completion-deadline enforcement.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PartialRecord {
    /// Increments for every record whose first byte has arrived, so a caller
    /// can distinguish a trickled record from a new one.
    pub ordinal: u64,
    /// Known once the eight header bytes are complete.
    pub kind: Option<RecordKind>,
    /// Record bytes received so far, header included.
    pub received: u32,
    /// Total record length, header included, once known.
    pub total: Option<u32>,
}

#[derive(Debug)]
enum State {
    Header {
        buf: [u8; RECORD_HEADER_LEN],
        filled: usize,
    },
    Head {
        header: RecordHeader,
        buf: Vec<u8>,
    },
    Body {
        header: RecordHeader,
        remaining: u32,
    },
    Failed(CodecError),
}

/// A pure, clock-free incremental `http-forward/1` record decoder.
#[derive(Debug)]
pub struct RecordDecoder {
    state: State,
    records_started: u64,
}

impl Default for RecordDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordDecoder {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: State::Header {
                buf: [0; RECORD_HEADER_LEN],
                filled: 0,
            },
            records_started: 0,
        }
    }

    /// Decode at most one event from the front of `input`, advancing it past
    /// the consumed bytes.  Returns `Ok(None)` once `input` is exhausted
    /// without completing another event.
    ///
    /// # Errors
    /// Returns a fixed-header error as soon as the eighth header byte is
    /// read.  Errors are sticky.
    pub fn decode<'input>(
        &mut self,
        input: &mut &'input [u8],
    ) -> Result<Option<RecordEvent<'input>>, CodecError> {
        match &mut self.state {
            State::Failed(error) => Err(*error),
            State::Header { buf, filled } => {
                if input.is_empty() {
                    return Ok(None);
                }
                if *filled == 0 {
                    self.records_started = self.records_started.saturating_add(1);
                }
                let take = (RECORD_HEADER_LEN - *filled).min(input.len());
                let (head, rest) = input.split_at(take);
                buf[*filled..*filled + take].copy_from_slice(head);
                *filled += take;
                *input = rest;
                if *filled < RECORD_HEADER_LEN {
                    return Ok(None);
                }
                let header = match RecordHeader::decode(*buf) {
                    Ok(header) => header,
                    Err(error) => {
                        self.state = State::Failed(error);
                        return Err(error);
                    }
                };
                self.state = match header.kind() {
                    RecordKind::RequestHead | RecordKind::ResponseHead => State::Head {
                        header,
                        // No allocation until the first payload byte.
                        buf: Vec::new(),
                    },
                    RecordKind::Body => State::Body {
                        header,
                        remaining: header.payload_len(),
                    },
                    RecordKind::End => State::Header {
                        buf: [0; RECORD_HEADER_LEN],
                        filled: 0,
                    },
                };
                Ok(Some(RecordEvent::Header(header)))
            }
            State::Head { header, buf } => {
                if input.is_empty() {
                    return Ok(None);
                }
                let total = header.payload_len() as usize;
                if buf.capacity() == 0 {
                    // Bounded by MAX_HEAD_PAYLOAD_LEN via RecordHeader.
                    buf.reserve_exact(total);
                }
                let take = (total - buf.len()).min(input.len());
                let (head, rest) = input.split_at(take);
                buf.extend_from_slice(head);
                *input = rest;
                if buf.len() < total {
                    return Ok(None);
                }
                let payload = mem::take(buf);
                self.state = State::Header {
                    buf: [0; RECORD_HEADER_LEN],
                    filled: 0,
                };
                Ok(Some(RecordEvent::Head(payload)))
            }
            State::Body { remaining, .. } => {
                if input.is_empty() {
                    return Ok(None);
                }
                let take = (*remaining as usize).min(input.len());
                let (data, rest) = input.split_at(take);
                *input = rest;
                // `take` is at most `remaining`, which fits u32.
                *remaining -= u32::try_from(take).unwrap_or(*remaining);
                let record_done = *remaining == 0;
                if record_done {
                    self.state = State::Header {
                        buf: [0; RECORD_HEADER_LEN],
                        filled: 0,
                    };
                }
                Ok(Some(RecordEvent::Body { data, record_done }))
            }
        }
    }

    /// The partly received record, or `None` at a record boundary.
    #[must_use]
    pub fn partial(&self) -> Option<PartialRecord> {
        let header_len = RECORD_HEADER_LEN as u32;
        match &self.state {
            State::Header { filled: 0, .. } | State::Failed(_) => None,
            State::Header { filled, .. } => Some(PartialRecord {
                ordinal: self.records_started,
                kind: None,
                received: u32::try_from(*filled).unwrap_or(header_len),
                total: None,
            }),
            State::Head { header, buf } => Some(PartialRecord {
                ordinal: self.records_started,
                kind: Some(header.kind()),
                received: header_len + u32::try_from(buf.len()).unwrap_or(0),
                total: Some(header_len + header.payload_len()),
            }),
            State::Body { header, remaining } => Some(PartialRecord {
                ordinal: self.records_started,
                kind: Some(header.kind()),
                received: header_len + (header.payload_len() - *remaining),
                total: Some(header_len + header.payload_len()),
            }),
        }
    }

    /// True at a record boundary with no retained bytes.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        matches!(self.state, State::Header { filled: 0, .. })
    }

    /// Bytes currently retained by the decoder (header or HEAD buffer).
    #[must_use]
    pub fn retained_len(&self) -> usize {
        match &self.state {
            State::Header { filled, .. } => *filled,
            State::Head { buf, .. } => buf.len(),
            State::Body { .. } | State::Failed(_) => 0,
        }
    }

    /// Latch an error so later calls fail consistently.
    pub(crate) fn fail(&mut self, error: CodecError) {
        self.state = State::Failed(error);
    }
}
