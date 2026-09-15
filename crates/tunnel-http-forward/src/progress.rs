//! Clock-free partial-record completion deadline.
//!
//! The codec never reads a clock.  The caller supplies `now` from its own
//! progress clock after each input delivery, in any unit, and stops that
//! clock while a rotation freeze or deliberately withheld credit pauses
//! progress.  Trickled bytes of the same record do not restart the budget.

use crate::decoder::PartialRecord;
use crate::error::CodecError;

/// Tracks how long the current partial record has been incomplete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordDeadline {
    budget: u64,
    current: Option<(u64, u64)>,
}

impl RecordDeadline {
    /// `budget` is the maximum progress-clock time from a record's first
    /// observed byte to its completion.
    #[must_use]
    pub const fn new(budget: u64) -> Self {
        Self {
            budget,
            current: None,
        }
    }

    /// Record an observation of the decoder's partial state at `now`.
    ///
    /// # Errors
    /// [`CodecError::RecordDeadlineExceeded`] when the same record has been
    /// partial for longer than the budget.
    pub fn observe(&mut self, partial: Option<PartialRecord>, now: u64) -> Result<(), CodecError> {
        let Some(partial) = partial else {
            self.current = None;
            return Ok(());
        };
        match self.current {
            Some((ordinal, started)) if ordinal == partial.ordinal => {
                // A non-monotonic caller clock counts as no elapsed time.
                if now.saturating_sub(started) > self.budget {
                    return Err(CodecError::RecordDeadlineExceeded);
                }
            }
            _ => self.current = Some((partial.ordinal, now)),
        }
        Ok(())
    }

    /// When the current partial record was first observed.
    #[must_use]
    pub fn started_at(&self) -> Option<u64> {
        self.current.map(|(_, started)| started)
    }
}
