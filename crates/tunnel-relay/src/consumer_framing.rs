//! Bounded public echo record framing shared by every consumer ingress path.
//!
//! A public echo stream carries length-prefixed records: a four-byte
//! big-endian body length followed by the body.  Three relay code paths parse
//! that framing: the owner-local WebSocket handler, the non-owner ingress that
//! forwards public frames over the length-prefixed peer stream, and the owner
//! side of that peer stream.  They must reach the same bounded decision for
//! every record boundary, so the decision lives here exactly once:
//!
//! * [`ConsumerRecordLimit::admit_input`] bounds how many unconsumed bytes of
//!   the current record plus one incoming frame may exist, before any of the
//!   incoming bytes are copied.
//! * [`ConsumerRecordLimit::admit_prefix`] rejects a length prefix above the
//!   body limit as soon as its four bytes are available, before any buffer is
//!   sized by the attacker-supplied length and before any forwarding.
//!
//! [`ConsumerRecordAssembler`] applies both decisions while buffering complete
//! records for the paths that dispatch them.  [`ConsumerRecordCursor`] applies
//! the same decisions to a pass-through byte stream for the ingress that only
//! forwards, holding back at most three bytes of an incomplete prefix so the
//! decision is always taken on a complete prefix.

use std::cmp::min;

/// Length of the public record prefix.
pub(crate) const RECORD_PREFIX_LEN: usize = 4;

/// Typed rejection of a public record, shared by every ingress path.
///
/// Only sizes are carried: no record bytes are retained for diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConsumerRecordRejection {
    /// A complete length prefix declared more body bytes than the limit.
    DeclaredLengthExceedsLimit { declared: usize, limit: usize },
    /// Unconsumed bytes of the current record plus one incoming frame exceed
    /// one bounded record window.
    InputExceedsLimit {
        buffered: usize,
        incoming: usize,
        limit: usize,
    },
}

impl ConsumerRecordRejection {
    /// Stable payload-free phase label for diagnostics.
    pub(crate) const fn phase(self) -> &'static str {
        match self {
            Self::DeclaredLengthExceedsLimit { .. } => "consumer_record_declared_limit",
            Self::InputExceedsLimit { .. } => "consumer_record_input_limit",
        }
    }
}

/// The single bounded body-limit decision for public echo records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConsumerRecordLimit {
    max_body: usize,
}

impl ConsumerRecordLimit {
    pub(crate) const fn new(max_body: usize) -> Self {
        Self { max_body }
    }

    /// Largest admissible complete record, prefix included.
    pub(crate) const fn max_record(self) -> usize {
        self.max_body.saturating_add(RECORD_PREFIX_LEN)
    }

    /// Decide whether `incoming` frame bytes may join `buffered` unconsumed
    /// bytes of the current record.  Taken before any copy.
    pub(crate) fn admit_input(
        self,
        buffered: usize,
        incoming: usize,
    ) -> Result<(), ConsumerRecordRejection> {
        if buffered.saturating_add(incoming) > self.max_record() {
            return Err(ConsumerRecordRejection::InputExceedsLimit {
                buffered,
                incoming,
                limit: self.max_record(),
            });
        }
        Ok(())
    }

    /// Decide whether a complete prefix declares an admissible body length.
    /// Taken as soon as the prefix is complete, before the body is read.
    pub(crate) fn admit_prefix(
        self,
        prefix: [u8; RECORD_PREFIX_LEN],
    ) -> Result<usize, ConsumerRecordRejection> {
        let declared = u32::from_be_bytes(prefix) as usize;
        if declared > self.max_body {
            return Err(ConsumerRecordRejection::DeclaredLengthExceedsLimit {
                declared,
                limit: self.max_body,
            });
        }
        Ok(declared)
    }
}

/// Buffering assembler for paths that dispatch complete record bodies.
#[derive(Debug)]
pub(crate) struct ConsumerRecordAssembler {
    limit: ConsumerRecordLimit,
    input: Vec<u8>,
}

impl ConsumerRecordAssembler {
    pub(crate) fn new(limit: ConsumerRecordLimit) -> Self {
        Self {
            limit,
            input: Vec::new(),
        }
    }

    /// Unconsumed bytes currently buffered.
    #[cfg(test)]
    pub(crate) fn buffered(&self) -> usize {
        self.input.len()
    }

    /// Admit one frame into the buffer.  The prefix decision is taken here as
    /// well, so an over-limit prefix is rejected even when its body never
    /// arrives.
    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<(), ConsumerRecordRejection> {
        self.limit.admit_input(self.input.len(), bytes.len())?;
        self.input.extend_from_slice(bytes);
        self.peek_declared().map(|_| ())
    }

    fn peek_declared(&self) -> Result<Option<usize>, ConsumerRecordRejection> {
        if self.input.len() < RECORD_PREFIX_LEN {
            return Ok(None);
        }
        let prefix = [self.input[0], self.input[1], self.input[2], self.input[3]];
        self.limit.admit_prefix(prefix).map(Some)
    }

    /// Take the next complete record body, if one is buffered.
    pub(crate) fn next_body(&mut self) -> Result<Option<Vec<u8>>, ConsumerRecordRejection> {
        let Some(declared) = self.peek_declared()? else {
            return Ok(None);
        };
        let total = declared + RECORD_PREFIX_LEN;
        if self.input.len() < total {
            return Ok(None);
        }
        let body = self.input[RECORD_PREFIX_LEN..total].to_vec();
        self.input.drain(..total);
        Ok(Some(body))
    }
}

/// Pass-through cursor for the forwarding ingress.
///
/// It tracks record boundaries without buffering bodies, validates every
/// prefix as soon as it is complete, and reports the bytes that may be
/// forwarded from each frame.  At most three bytes of an incomplete prefix
/// are held between frames.
#[derive(Debug)]
pub(crate) struct ConsumerRecordCursor {
    limit: ConsumerRecordLimit,
    prefix: [u8; RECORD_PREFIX_LEN],
    prefix_len: usize,
    declared: usize,
    body_remaining: usize,
}

impl ConsumerRecordCursor {
    pub(crate) fn new(limit: ConsumerRecordLimit) -> Self {
        Self {
            limit,
            prefix: [0; RECORD_PREFIX_LEN],
            prefix_len: 0,
            declared: 0,
            body_remaining: 0,
        }
    }

    /// Bytes of the current incomplete record already accepted, which is
    /// exactly what the buffering assembler would hold at this point.
    pub(crate) fn buffered(&self) -> usize {
        if self.body_remaining > 0 {
            RECORD_PREFIX_LEN + (self.declared - self.body_remaining)
        } else {
            self.prefix_len
        }
    }

    /// Validate one public frame and return the bytes that may be forwarded
    /// now: any held prefix bytes completed by this frame, followed by the
    /// frame up to the last complete prefix decision.  A trailing partial
    /// prefix is held until it completes.
    pub(crate) fn forward(&mut self, frame: &[u8]) -> Result<Vec<u8>, ConsumerRecordRejection> {
        self.limit.admit_input(self.buffered(), frame.len())?;
        let held_at_entry = self.prefix_len;
        let mut offset = 0;
        let mut forwardable_end = 0;
        while offset < frame.len() {
            if self.body_remaining > 0 {
                let take = min(self.body_remaining, frame.len() - offset);
                self.body_remaining -= take;
                offset += take;
                forwardable_end = offset;
                continue;
            }
            let need = RECORD_PREFIX_LEN - self.prefix_len;
            let take = min(need, frame.len() - offset);
            self.prefix[self.prefix_len..self.prefix_len + take]
                .copy_from_slice(&frame[offset..offset + take]);
            self.prefix_len += take;
            offset += take;
            if self.prefix_len == RECORD_PREFIX_LEN {
                let declared = self.limit.admit_prefix(self.prefix)?;
                self.declared = declared;
                self.body_remaining = declared;
                self.prefix_len = 0;
                forwardable_end = offset;
            }
        }
        if forwardable_end == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(held_at_entry + forwardable_end);
        out.extend_from_slice(&self.prefix[..held_at_entry]);
        out.extend_from_slice(&frame[..forwardable_end]);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConsumerRecordAssembler, ConsumerRecordCursor, ConsumerRecordLimit,
        ConsumerRecordRejection, RECORD_PREFIX_LEN,
    };

    const LIMIT: usize = 64;

    fn limit() -> ConsumerRecordLimit {
        ConsumerRecordLimit::new(LIMIT)
    }

    fn record(body: &[u8]) -> Vec<u8> {
        let mut out = (body.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    /// The typed outcome both ingress paths must agree on for one frame
    /// sequence.
    #[derive(Debug, PartialEq, Eq)]
    enum Outcome {
        /// Complete bodies observed, in order, with the stream still open.
        Bodies(Vec<Vec<u8>>),
        Rejected(ConsumerRecordRejection),
    }

    /// Owner-local / owner-side path: buffer every frame, drain bodies.
    fn assemble(frames: &[Vec<u8>]) -> Outcome {
        let mut assembler = ConsumerRecordAssembler::new(limit());
        let mut bodies = Vec::new();
        for frame in frames {
            if let Err(rejection) = assembler.push(frame) {
                return Outcome::Rejected(rejection);
            }
            loop {
                match assembler.next_body() {
                    Ok(Some(body)) => bodies.push(body),
                    Ok(None) => break,
                    Err(rejection) => return Outcome::Rejected(rejection),
                }
            }
        }
        Outcome::Bodies(bodies)
    }

    /// Non-owner ingress path: validate and forward, then decode what the
    /// owner would receive with the same assembler.
    fn cursor_then_owner(frames: &[Vec<u8>]) -> Outcome {
        let mut cursor = ConsumerRecordCursor::new(limit());
        let mut forwarded = Vec::new();
        for frame in frames {
            match cursor.forward(frame) {
                Ok(bytes) => {
                    if !bytes.is_empty() {
                        forwarded.push(bytes);
                    }
                }
                Err(rejection) => return Outcome::Rejected(rejection),
            }
        }
        assemble(&forwarded)
    }

    #[test]
    fn both_paths_share_one_bounded_body_limit_decision() {
        let at_limit = vec![0x5a; LIMIT];
        let over_limit_prefix = ((LIMIT + 1) as u32).to_be_bytes().to_vec();
        let two_legal = {
            let mut frame = record(&[1; 10]);
            frame.extend_from_slice(&record(&[2; 10]));
            frame
        };
        let over_window = {
            // Two individually legal records whose single frame exceeds one
            // bounded record window (limit + prefix).
            let mut frame = record(&[3; 40]);
            frame.extend_from_slice(&record(&[4; 40]));
            frame
        };
        let cases: Vec<(&str, Vec<Vec<u8>>, Outcome)> = vec![
            (
                "limit",
                vec![record(&at_limit)],
                Outcome::Bodies(vec![at_limit.clone()]),
            ),
            (
                "limit split prefix/body",
                vec![(LIMIT as u32).to_be_bytes().to_vec(), at_limit.clone()],
                Outcome::Bodies(vec![at_limit.clone()]),
            ),
            (
                "limit plus one",
                vec![over_limit_prefix.clone()],
                Outcome::Rejected(ConsumerRecordRejection::DeclaredLengthExceedsLimit {
                    declared: LIMIT + 1,
                    limit: LIMIT,
                }),
            ),
            (
                "limit plus one with body bytes",
                vec![[over_limit_prefix.clone(), vec![0; 8]].concat()],
                Outcome::Rejected(ConsumerRecordRejection::DeclaredLengthExceedsLimit {
                    declared: LIMIT + 1,
                    limit: LIMIT,
                }),
            ),
            (
                "limit plus one split across frames",
                vec![
                    over_limit_prefix[..2].to_vec(),
                    over_limit_prefix[2..].to_vec(),
                ],
                Outcome::Rejected(ConsumerRecordRejection::DeclaredLengthExceedsLimit {
                    declared: LIMIT + 1,
                    limit: LIMIT,
                }),
            ),
            (
                "limit plus one after a legal record",
                vec![[record(&[9; 3]), over_limit_prefix.clone()].concat()],
                Outcome::Rejected(ConsumerRecordRejection::DeclaredLengthExceedsLimit {
                    declared: LIMIT + 1,
                    limit: LIMIT,
                }),
            ),
            ("zero", vec![record(&[])], Outcome::Bodies(vec![vec![]])),
            (
                "zero then legal",
                vec![[record(&[]), record(&[7; 2])].concat()],
                Outcome::Bodies(vec![vec![], vec![7; 2]]),
            ),
            (
                "truncated prefix",
                vec![vec![0, 0]],
                Outcome::Bodies(vec![]),
            ),
            (
                "truncated body",
                vec![record(&[1; 8])[..6].to_vec()],
                Outcome::Bodies(vec![]),
            ),
            (
                "coalesced legal",
                vec![two_legal.clone()],
                Outcome::Bodies(vec![vec![1; 10], vec![2; 10]]),
            ),
            (
                "coalesced over window",
                vec![over_window.clone()],
                Outcome::Rejected(ConsumerRecordRejection::InputExceedsLimit {
                    buffered: 0,
                    incoming: over_window.len(),
                    limit: LIMIT + RECORD_PREFIX_LEN,
                }),
            ),
            (
                "partial body then over window frame",
                vec![
                    record(&at_limit)[..40].to_vec(),
                    [record(&at_limit)[40..].to_vec(), vec![0; 12]].concat(),
                ],
                Outcome::Rejected(ConsumerRecordRejection::InputExceedsLimit {
                    buffered: 40,
                    incoming: LIMIT + RECORD_PREFIX_LEN - 40 + 12,
                    limit: LIMIT + RECORD_PREFIX_LEN,
                }),
            ),
            (
                "empty frame",
                vec![vec![], record(&[5; 1])],
                Outcome::Bodies(vec![vec![5]]),
            ),
        ];
        for (name, frames, expected) in cases {
            let local = assemble(&frames);
            let remote = cursor_then_owner(&frames);
            assert_eq!(local, expected, "owner-local path: {name}");
            assert_eq!(remote, expected, "remote ingress path: {name}");
        }
    }

    #[test]
    fn cursor_holds_at_most_a_partial_prefix_and_never_a_body() {
        let mut cursor = ConsumerRecordCursor::new(limit());
        let body = vec![0xab; 10];
        let frame = record(&body);
        // One byte at a time: nothing is forwardable until the prefix is
        // complete, then every body byte passes through immediately.
        let mut forwarded = Vec::new();
        for (index, byte) in frame.iter().enumerate() {
            let out = cursor.forward(&[*byte]).expect("legal byte");
            if index < RECORD_PREFIX_LEN - 1 {
                assert!(out.is_empty(), "prefix byte {index} was forwarded early");
                assert_eq!(cursor.buffered(), index + 1);
            } else if index == RECORD_PREFIX_LEN - 1 {
                assert_eq!(out, frame[..RECORD_PREFIX_LEN]);
                assert_eq!(cursor.buffered(), RECORD_PREFIX_LEN);
            } else {
                assert_eq!(out, vec![*byte]);
            }
            forwarded.extend_from_slice(&out);
        }
        assert_eq!(forwarded, frame);
        assert_eq!(cursor.buffered(), 0);
    }

    #[test]
    fn over_limit_prefix_is_rejected_before_any_body_is_read_or_forwarded() {
        let over = ((LIMIT + 1) as u32).to_be_bytes();
        let mut cursor = ConsumerRecordCursor::new(limit());
        assert!(
            cursor
                .forward(&over[..3])
                .expect("partial prefix")
                .is_empty()
        );
        let rejection = cursor.forward(&over[3..]).expect_err("over-limit prefix");
        assert_eq!(rejection.phase(), "consumer_record_declared_limit");

        let mut assembler = ConsumerRecordAssembler::new(limit());
        assert_eq!(assembler.push(&over[..3]), Ok(()));
        assert_eq!(assembler.buffered(), 3);
        assert_eq!(
            assembler.push(&over[3..]),
            Err(ConsumerRecordRejection::DeclaredLengthExceedsLimit {
                declared: LIMIT + 1,
                limit: LIMIT
            })
        );
    }

    #[test]
    fn input_window_is_decided_before_any_copy() {
        let mut assembler = ConsumerRecordAssembler::new(limit());
        let rejection = assembler
            .push(&[0; LIMIT + RECORD_PREFIX_LEN + 1])
            .expect_err("over-window frame");
        assert_eq!(rejection.phase(), "consumer_record_input_limit");
        assert_eq!(assembler.buffered(), 0, "rejected bytes were not copied");
    }
}
