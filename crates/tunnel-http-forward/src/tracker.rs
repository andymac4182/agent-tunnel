//! A payload-free record-position tracker.
//!
//! [`RecordTracker`] follows the fixed eight-byte record headers of one
//! direction's byte stream without retaining or parsing any payload.  It
//! answers "where in the record grammar is this stream right now": how many
//! HEAD, BODY and END records have been seen, and whether the stream stops
//! inside a record header or inside a payload.  Transport endpoints use it
//! for bounded diagnostics (for example the record position at a rotation
//! fence) where running the full validating reader is not their job.
//!
//! The tracker never allocates and never keeps payload octets; the only
//! bytes it retains are an unfinished eight-byte framing header.

use crate::record::{RECORD_HEADER_LEN, RecordHeader, RecordKind};

/// Where an unfinished record stops.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum RecordPosition {
    /// Exactly on a record boundary.
    #[default]
    Boundary,
    /// Inside the eight-byte header: `received` of its bytes arrived.
    Header { received: u8 },
    /// Inside a payload: the header is complete and `received` of `total`
    /// payload bytes arrived.
    Payload {
        kind: RecordKind,
        received: u32,
        total: u32,
    },
}

impl RecordPosition {
    /// A stable, closed diagnostic label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Boundary => "boundary",
            Self::Header { .. } => "partial_header",
            Self::Payload {
                kind: RecordKind::Body,
                ..
            } => "partial_body",
            Self::Payload { .. } => "partial_head",
        }
    }

    /// True when the stream stops inside a record.
    #[must_use]
    pub const fn is_partial(&self) -> bool {
        !matches!(self, Self::Boundary)
    }
}

/// Counters and the current position of one direction's record stream.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct TrackerSnapshot {
    /// HEAD records whose header was seen (complete or not).
    pub heads: u32,
    /// BODY records whose header was seen.
    pub bodies: u64,
    /// END records seen.
    pub ends: u32,
    /// BODY payload octets seen.
    pub body_bytes: u64,
    /// Every byte observed, headers included.
    pub total_bytes: u64,
    pub position: RecordPosition,
    /// The framing was invalid at some point; counting stopped there.
    pub invalid: bool,
}

/// Follows record framing only.  See the module documentation.
#[derive(Clone, Debug, Default)]
pub struct RecordTracker {
    header: [u8; RECORD_HEADER_LEN],
    header_filled: usize,
    payload: Option<(RecordKind, u32, u32)>,
    snapshot: TrackerSnapshot,
}

impl RecordTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe the next bytes of the stream, in order.
    pub fn observe(&mut self, mut input: &[u8]) {
        if self.snapshot.invalid {
            return;
        }
        self.snapshot.total_bytes = self.snapshot.total_bytes.saturating_add(input.len() as u64);
        while !input.is_empty() {
            if let Some((kind, received, total)) = self.payload {
                let take = input.len().min((total - received) as usize);
                // `take` fits in u32 because it is at most `total - received`.
                let received = received + u32::try_from(take).unwrap_or(0);
                if kind == RecordKind::Body {
                    self.snapshot.body_bytes = self.snapshot.body_bytes.saturating_add(take as u64);
                }
                input = &input[take..];
                self.payload = (received < total).then_some((kind, received, total));
                continue;
            }
            let take = input.len().min(RECORD_HEADER_LEN - self.header_filled);
            self.header[self.header_filled..self.header_filled + take]
                .copy_from_slice(&input[..take]);
            self.header_filled += take;
            input = &input[take..];
            if self.header_filled < RECORD_HEADER_LEN {
                break;
            }
            self.header_filled = 0;
            let Ok(header) = RecordHeader::decode(self.header) else {
                self.snapshot.invalid = true;
                return;
            };
            match header.kind() {
                RecordKind::RequestHead | RecordKind::ResponseHead => {
                    self.snapshot.heads = self.snapshot.heads.saturating_add(1);
                }
                RecordKind::Body => self.snapshot.bodies = self.snapshot.bodies.saturating_add(1),
                RecordKind::End => self.snapshot.ends = self.snapshot.ends.saturating_add(1),
            }
            if header.payload_len() > 0 {
                self.payload = Some((header.kind(), 0, header.payload_len()));
            }
        }
        self.snapshot.position = self.position();
    }

    fn position(&self) -> RecordPosition {
        if let Some((kind, received, total)) = self.payload {
            return RecordPosition::Payload {
                kind,
                received,
                total,
            };
        }
        if self.header_filled > 0 {
            return RecordPosition::Header {
                received: u8::try_from(self.header_filled).unwrap_or(u8::MAX),
            };
        }
        RecordPosition::Boundary
    }

    #[must_use]
    pub const fn snapshot(&self) -> TrackerSnapshot {
        self.snapshot
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{END_RECORD, encode_body};

    fn head(kind: RecordKind, len: u32) -> Vec<u8> {
        let mut out = RecordHeader::new(kind, len)
            .expect("header")
            .encode()
            .to_vec();
        out.extend(std::iter::repeat_n(b'{', len as usize));
        out
    }

    #[test]
    fn counts_every_kind_at_every_split_point() {
        let mut stream = head(RecordKind::RequestHead, 20);
        encode_body(&[7; 300], &mut stream);
        encode_body(&[9; 5], &mut stream);
        stream.extend_from_slice(&END_RECORD);
        for split in 0..=stream.len() {
            let mut tracker = RecordTracker::new();
            tracker.observe(&stream[..split]);
            tracker.observe(&stream[split..]);
            let snapshot = tracker.snapshot();
            assert_eq!(snapshot.heads, 1, "split {split}");
            assert_eq!(snapshot.bodies, 2);
            assert_eq!(snapshot.ends, 1);
            assert_eq!(snapshot.body_bytes, 305);
            assert_eq!(snapshot.total_bytes, stream.len() as u64);
            assert_eq!(snapshot.position, RecordPosition::Boundary);
            assert!(!snapshot.invalid);
        }
    }

    #[test]
    fn reports_partial_header_and_payload_positions() {
        let mut stream = head(RecordKind::ResponseHead, 4);
        let mut tracker = RecordTracker::new();
        tracker.observe(&stream[..3]);
        assert_eq!(
            tracker.snapshot().position,
            RecordPosition::Header { received: 3 }
        );
        assert_eq!(tracker.snapshot().position.label(), "partial_header");
        tracker.observe(&stream[3..10]);
        assert_eq!(
            tracker.snapshot().position,
            RecordPosition::Payload {
                kind: RecordKind::ResponseHead,
                received: 2,
                total: 4
            }
        );
        tracker.observe(&stream[10..]);
        stream.clear();
        encode_body(&[1; 10], &mut stream);
        tracker.observe(&stream[..8]);
        assert_eq!(tracker.snapshot().position.label(), "partial_body");
        assert_eq!(tracker.snapshot().bodies, 1);
        assert_eq!(tracker.snapshot().body_bytes, 0);
        tracker.observe(&stream[8..]);
        assert_eq!(tracker.snapshot().position, RecordPosition::Boundary);
        assert_eq!(tracker.snapshot().body_bytes, 10);
    }

    #[test]
    fn invalid_framing_latches_and_stops_counting() {
        let mut tracker = RecordTracker::new();
        tracker.observe(&[0x09, 0, 0, 0, 0, 0, 0, 0]);
        assert!(tracker.snapshot().invalid);
        tracker.observe(&END_RECORD);
        assert_eq!(tracker.snapshot().ends, 0);
    }
}
