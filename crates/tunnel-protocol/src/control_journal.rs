//! Bounded idempotency within one validated control attempt.
//!
//! The caller first authenticates the session and validates the attempt identity,
//! then journals the canonical encoded control message before applying effects.
//! Check the current phase only for a new message: an identical retained retry
//! may legitimately arrive after its original transition advanced the phase.
//! Entries are never evicted while the attempt is live. The entire journal
//! expires at its original deadline; runtime attempt tombstones must reject
//! late traffic before constructing a new journal. This is transport state,
//! not durable application idempotency.

use std::{collections::BTreeMap, fmt};

use sha2::{Digest, Sha256};

use crate::control::{MAX_CONTROL_MESSAGE_BYTES, MAX_IDENTIFIER_BYTES};

// Charge stored values plus conservative per-entry tree bookkeeping. The
// independent entry cap also bounds allocator/node overhead.
const ENTRY_OVERHEAD: usize = size_of::<Entry>() + size_of::<String>() + 64;
// Responses are retained as an ordered prefix. Include the record and owned
// string/vector bookkeeping so a zero-byte response still consumes bounded
// journal capacity; the identifier length is charged separately below.
const RESPONSE_OVERHEAD: usize = size_of::<ResponseRecord>() + 32;
pub const MAX_JOURNAL_ENTRIES: usize = 128;
pub const MAX_JOURNAL_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation {
    New,
    PendingDuplicate,
    CompletedDuplicate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalError {
    InvalidLimits,
    Expired,
    ClockReversed,
    InvalidIdentifier,
    OversizedMessage,
    Capacity,
    ConflictingMessage,
    MissingMessage,
    ConflictingResponse,
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimits => "invalid control journal limits",
            Self::Expired => "control attempt retention expired",
            Self::ClockReversed => "control journal monotonic clock reversed",
            Self::InvalidIdentifier => "invalid control message identifier",
            Self::OversizedMessage => "control message exceeds journal wire bound",
            Self::Capacity => "control journal capacity exhausted",
            Self::ConflictingMessage => "control message identifier reused with different content",
            Self::MissingMessage => "control response has no journaled request",
            Self::ConflictingResponse => "control request already has a different response",
        })
    }
}

impl std::error::Error for JournalError {}

struct Entry {
    fingerprint: [u8; 32],
    responses: Vec<ResponseRecord>,
}

struct ResponseRecord {
    response_id: String,
    bytes: Vec<u8>,
}

/// One attempt's immutable-deadline journal. Debug intentionally omits content.
pub struct ControlJournal {
    entries: BTreeMap<String, Entry>,
    max_entries: usize,
    max_bytes: usize,
    used_bytes: usize,
    response_items: usize,
    last_now: u64,
    deadline: u64,
}

impl fmt::Debug for ControlJournal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlJournal")
            .field("entries", &self.entries.len())
            .field("used_bytes", &self.used_bytes)
            .field("deadline", &self.deadline)
            .finish()
    }
}

impl ControlJournal {
    /// Ticks use the runtime's monotonic clock and must have one common unit.
    pub fn new(
        max_entries: usize,
        max_bytes: usize,
        now: u64,
        deadline: u64,
    ) -> Result<Self, JournalError> {
        if max_entries == 0
            || max_entries > MAX_JOURNAL_ENTRIES
            || !(ENTRY_OVERHEAD..=MAX_JOURNAL_BYTES).contains(&max_bytes)
            || deadline <= now
        {
            return Err(JournalError::InvalidLimits);
        }
        Ok(Self {
            entries: BTreeMap::new(),
            max_entries,
            max_bytes,
            used_bytes: 0,
            response_items: 0,
            last_now: now,
            deadline,
        })
    }

    fn check_time(&mut self, now: u64) -> Result<(), JournalError> {
        if now < self.last_now {
            return Err(JournalError::ClockReversed);
        }
        self.last_now = now;
        if now >= self.deadline {
            return Err(JournalError::Expired);
        }
        Ok(())
    }

    /// `canonical` includes the complete validated envelope, including identity.
    pub fn observe(
        &mut self,
        message_id: &str,
        canonical: &[u8],
        now: u64,
    ) -> Result<Observation, JournalError> {
        self.check_time(now)?;
        if message_id.is_empty() || message_id.len() > MAX_IDENTIFIER_BYTES {
            return Err(JournalError::InvalidIdentifier);
        }
        if canonical.is_empty() || canonical.len() > MAX_CONTROL_MESSAGE_BYTES {
            return Err(JournalError::OversizedMessage);
        }
        let fingerprint: [u8; 32] = Sha256::digest(canonical).into();
        if let Some(entry) = self.entries.get(message_id) {
            if entry.fingerprint != fingerprint {
                return Err(JournalError::ConflictingMessage);
            }
            return Ok(if entry.responses.is_empty() {
                Observation::PendingDuplicate
            } else {
                Observation::CompletedDuplicate
            });
        }
        let charge = ENTRY_OVERHEAD + message_id.len();
        if self.entries.len() >= self.max_entries || charge > self.max_bytes - self.used_bytes {
            return Err(JournalError::Capacity);
        }
        self.entries.insert(
            message_id.to_owned(),
            Entry {
                fingerprint,
                responses: Vec::new(),
            },
        );
        self.used_bytes += charge;
        Ok(Observation::New)
    }

    /// Record a bounded encoded reply before sending it. An empty reply records
    /// a completed transition that deliberately has no response message.
    ///
    /// This is the legacy one-shot completion operation. Progressive phase
    /// replies for one request belong in [`Self::append_response`], which keeps
    /// the complete response prefix available for replay.
    pub fn complete(
        &mut self,
        message_id: &str,
        response: &[u8],
        now: u64,
    ) -> Result<(), JournalError> {
        self.check_time(now)?;
        if response.len() > MAX_CONTROL_MESSAGE_BYTES {
            return Err(JournalError::OversizedMessage);
        }
        let entry = self
            .entries
            .get(message_id)
            .ok_or(JournalError::MissingMessage)?;
        if let Some(previous) = entry.responses.first() {
            return if previous.response_id.is_empty() && previous.bytes == response {
                Ok(())
            } else {
                Err(JournalError::ConflictingResponse)
            };
        }
        let charge = RESPONSE_OVERHEAD
            .checked_add(response.len())
            .ok_or(JournalError::Capacity)?;
        if self.response_items >= self.max_entries || charge > self.max_bytes - self.used_bytes {
            return Err(JournalError::Capacity);
        }
        let entry = self
            .entries
            .get_mut(message_id)
            .ok_or(JournalError::MissingMessage)?;
        entry.responses.push(ResponseRecord {
            response_id: String::new(),
            bytes: response.to_vec(),
        });
        self.used_bytes += charge;
        self.response_items += 1;
        Ok(())
    }

    /// Append one progressive encoded reply for a request.
    ///
    /// A request may move from pending to completed with its first appended
    /// response. Later phase replies append to the same ordered prefix. The
    /// response identifier is the stable message ID of that reply: repeating
    /// an identifier with identical bytes is idempotent, while reusing it for
    /// different bytes is rejected. The total number of retained response
    /// items shares the journal's bounded item limit, and response identifiers
    /// count toward the immutable byte budget even for empty response bodies.
    pub fn append_response(
        &mut self,
        message_id: &str,
        response_id: &str,
        response: &[u8],
        now: u64,
    ) -> Result<(), JournalError> {
        self.check_time(now)?;
        if response_id.is_empty() || response_id.len() > MAX_IDENTIFIER_BYTES {
            return Err(JournalError::InvalidIdentifier);
        }
        if response.len() > MAX_CONTROL_MESSAGE_BYTES {
            return Err(JournalError::OversizedMessage);
        }
        let entry = self
            .entries
            .get(message_id)
            .ok_or(JournalError::MissingMessage)?;
        if let Some(previous) = entry
            .responses
            .iter()
            .find(|previous| previous.response_id == response_id)
        {
            return if previous.bytes == response {
                Ok(())
            } else {
                Err(JournalError::ConflictingResponse)
            };
        }
        let charge = RESPONSE_OVERHEAD
            .checked_add(response_id.len())
            .and_then(|charge| charge.checked_add(response.len()))
            .ok_or(JournalError::Capacity)?;
        if self.response_items >= self.max_entries || charge > self.max_bytes - self.used_bytes {
            return Err(JournalError::Capacity);
        }
        let entry = self
            .entries
            .get_mut(message_id)
            .ok_or(JournalError::MissingMessage)?;
        entry.responses.push(ResponseRecord {
            response_id: response_id.to_owned(),
            bytes: response.to_vec(),
        });
        self.used_bytes += charge;
        self.response_items += 1;
        Ok(())
    }

    /// Borrow the response so retransmission does not allocate a second cache.
    pub fn response(&mut self, message_id: &str, now: u64) -> Result<Option<&[u8]>, JournalError> {
        self.check_time(now)?;
        Ok(self
            .entries
            .get(message_id)
            .ok_or(JournalError::MissingMessage)?
            .responses
            .first()
            .map(|response| response.bytes.as_slice()))
    }

    /// Borrow all retained replies in their append order for prefix replay.
    /// The returned prefix is bounded by the journal's total response-item and
    /// byte limits; no response is evicted while the attempt is live.
    pub fn responses(
        &mut self,
        message_id: &str,
        now: u64,
    ) -> Result<Option<Vec<&[u8]>>, JournalError> {
        self.check_time(now)?;
        let entry = self
            .entries
            .get(message_id)
            .ok_or(JournalError::MissingMessage)?;
        if entry.responses.is_empty() {
            return Ok(None);
        }
        Ok(Some(
            entry
                .responses
                .iter()
                .map(|response| response.bytes.as_slice())
                .collect(),
        ))
    }

    #[must_use]
    pub fn used_bytes(&self) -> usize {
        self.used_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_requests_never_become_new_and_conflicts_preserve_reply() {
        let mut journal = ControlJournal::new(2, 1024, 0, 20).unwrap();
        assert_eq!(journal.observe("id", b"prepare", 1), Ok(Observation::New));
        assert_eq!(
            journal.observe("id", b"prepare", 2),
            Ok(Observation::PendingDuplicate)
        );
        journal.complete("id", b"prepared", 3).unwrap();
        let bytes = journal.used_bytes();
        assert_eq!(
            journal.observe("id", b"prepare", 4),
            Ok(Observation::CompletedDuplicate)
        );
        assert_eq!(
            journal.observe("id", b"commit", 5),
            Err(JournalError::ConflictingMessage)
        );
        assert_eq!(
            journal.complete("id", b"changed", 6),
            Err(JournalError::ConflictingResponse)
        );
        journal.complete("id", b"prepared", 7).unwrap();
        assert_eq!(
            journal.response("id", 8).unwrap(),
            Some(b"prepared".as_slice())
        );
        assert_eq!(journal.used_bytes(), bytes);
    }

    #[test]
    fn count_and_byte_caps_do_not_evict_or_mutate_pending_entries() {
        let max_bytes = ENTRY_OVERHEAD + "id".len() + RESPONSE_OVERHEAD + 4;
        let mut journal = ControlJournal::new(1, max_bytes, 0, 20).unwrap();
        journal.observe("id", b"prepare", 1).unwrap();
        assert_eq!(
            journal.observe("next", b"prepare", 2),
            Err(JournalError::Capacity)
        );
        assert_eq!(
            journal.complete("id", b"12345", 3),
            Err(JournalError::Capacity)
        );
        assert_eq!(journal.response("id", 4).unwrap(), None);
        journal.complete("id", b"1234", 5).unwrap();
        assert_eq!(journal.used_bytes(), max_bytes);
        assert_eq!(
            journal.observe("id", b"prepare", 6),
            Ok(Observation::CompletedDuplicate)
        );
    }

    #[test]
    fn progressive_responses_are_ordered_and_replayable() {
        let mut journal = ControlJournal::new(4, 4096, 0, 20).unwrap();
        journal.observe("rotate", b"prepare", 1).unwrap();
        journal
            .append_response("rotate", "frozen", b"frozen", 2)
            .unwrap();
        journal
            .append_response("rotate", "drained", b"drained", 3)
            .unwrap();

        assert_eq!(
            journal.observe("rotate", b"prepare", 4),
            Ok(Observation::CompletedDuplicate)
        );
        assert_eq!(
            journal.response("rotate", 5).unwrap(),
            Some(b"frozen".as_slice())
        );
        assert_eq!(
            journal.responses("rotate", 6).unwrap(),
            Some(vec![b"frozen".as_slice(), b"drained".as_slice()])
        );
    }

    #[test]
    fn progressive_response_ids_are_idempotent_and_conflicts_are_rejected() {
        let mut journal = ControlJournal::new(4, 4096, 0, 20).unwrap();
        journal.observe("rotate", b"prepare", 1).unwrap();
        journal
            .append_response("rotate", "frozen", b"frozen", 2)
            .unwrap();
        let used_bytes = journal.used_bytes();
        assert_eq!(
            journal.append_response("rotate", "frozen", b"frozen", 3),
            Ok(())
        );
        assert_eq!(journal.used_bytes(), used_bytes);
        assert_eq!(
            journal.append_response("rotate", "frozen", b"changed", 4),
            Err(JournalError::ConflictingResponse)
        );
        journal
            .append_response("rotate", "drained", b"drained", 5)
            .unwrap();
        assert_eq!(
            journal.responses("rotate", 6).unwrap(),
            Some(vec![b"frozen".as_slice(), b"drained".as_slice()])
        );
    }

    #[test]
    fn progressive_response_items_and_identifiers_share_hard_bounds() {
        let mut journal = ControlJournal::new(2, 4096, 0, 20).unwrap();
        journal.observe("rotate", b"prepare", 1).unwrap();
        journal
            .append_response("rotate", "frozen", b"frozen", 2)
            .unwrap();
        journal
            .append_response("rotate", "drained", b"drained", 3)
            .unwrap();
        assert_eq!(
            journal.append_response("rotate", "committed", b"committed", 4),
            Err(JournalError::Capacity)
        );
        assert_eq!(
            journal.append_response("rotate", "", b"empty-id", 5),
            Err(JournalError::InvalidIdentifier)
        );
        assert_eq!(
            journal.append_response(
                "rotate",
                &"x".repeat(MAX_IDENTIFIER_BYTES + 1),
                b"too-long-id",
                6,
            ),
            Err(JournalError::InvalidIdentifier)
        );
        assert_eq!(
            journal.append_response(
                "rotate",
                "oversized",
                &vec![0; MAX_CONTROL_MESSAGE_BYTES + 1],
                7,
            ),
            Err(JournalError::OversizedMessage)
        );
        assert_eq!(
            journal.responses("rotate", 8).unwrap(),
            Some(vec![b"frozen".as_slice(), b"drained".as_slice()])
        );

        let max_bytes = ENTRY_OVERHEAD + "id".len() + RESPONSE_OVERHEAD + 1;
        let mut zero_body = ControlJournal::new(2, max_bytes, 0, 20).unwrap();
        zero_body.observe("id", b"prepare", 1).unwrap();
        zero_body
            .append_response("id", "a", b"", 2)
            .expect("identifier and response bookkeeping fit");
        assert_eq!(
            zero_body.append_response("id", "b", b"", 3),
            Err(JournalError::Capacity)
        );
    }

    #[test]
    fn original_deadline_is_not_extended_by_duplicates_or_responses() {
        let mut journal = ControlJournal::new(2, 1024, 5, 10).unwrap();
        journal.observe("id", b"prepare", 5).unwrap();
        journal.complete("id", b"ready", 9).unwrap();
        assert_eq!(
            journal.observe("id", b"prepare", 10),
            Err(JournalError::Expired)
        );
        assert_eq!(journal.response("id", 11), Err(JournalError::Expired));
        assert_eq!(
            journal.observe("new", b"prepare", 12),
            Err(JournalError::Expired)
        );
        assert_eq!(
            journal.observe("new", b"prepare", 8),
            Err(JournalError::ClockReversed)
        );
    }
}
