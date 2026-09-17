//! `RESULT_STATUS` outcomes for ACP terminals (task row M8-03, M8 chunk 4).
//!
//! `docs/acp.md`: "States follow [protocol.md](protocol.md): `accepted`,
//! `running`, `succeeded`, `failed`, `cancelled`, `outcome_unknown`."  This
//! module is the one place that decides which of those an ACP terminal is, so
//! the connector's `RESULT_STATUS` and the consumer's operation record cannot
//! disagree about the same turn.
//!
//! It is **pure**: no clock, no socket, no child.  The vocabulary it emits is
//! `tunnel_protocol::RESULT_OUTCOMES`, asserted here rather than retyped.
//!
//! # The two rules that carry the weight
//!
//! **`succeeded` is about the ACP request completing, not about the work being
//! right.**  `docs/acp.md` says so in terms: "`succeeded` describes the ACP
//! request completing, not proof that every underlying tool succeeded."  So a
//! turn that ended in `Refusal` or at `MaxTokens` still *completed*, and is
//! `succeeded`.  A reader who wants to know what the agent decided reads the
//! `stopReason` off the wire; that is a different question from whether the
//! operation reached a terminal state.
//!
//! **An unknown terminal is never a success.**  `StopReason` is
//! `#[non_exhaustive]` upstream, so this crate cannot match it exhaustively and
//! a future variant *will* fall into a wildcard arm.  That arm maps to
//! `outcome_unknown`, not to `succeeded`: a stop reason nobody here has read is
//! precisely a turn whose outcome this repository does not know.  The
//! alternative — a wildcard that reports success — is the shape that makes a
//! protocol upgrade silently start claiming completions it never verified.

use agent_client_protocol::schema::v1::StopReason;

/// What ended an ACP operation, as the bridge observed it.
///
/// Every variant is an *observation*, never an inference from an HTTP status:
/// `docs/acp.md`'s 202 means accepted by the bridge and nothing more, so a
/// terminal is built from a message read off the wire or from a fault the
/// bridge itself witnessed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcpTerminal {
    /// A prompt turn's own result arrived, carrying this `stopReason`.
    ///
    /// The value has already passed [`crate::message::read_turn_completion`],
    /// so it is inside the pinned v1 vocabulary; a v2 acknowledgement with no
    /// `stopReason` never reaches here.
    Turn(StopReason),
    /// The bridge refused before anything was dispatched to a child.  Nothing
    /// ran, and that is *proven*, not assumed.
    NotDispatched,
    /// Work was dispatched to a child and its outcome can no longer be
    /// established: the child died, or the transport reset, before the turn's
    /// result arrived.
    ///
    /// `docs/acp.md`: "a reset connection or lost process marks dispatched
    /// unresolved work `outcome_unknown`."
    LostAfterDispatch,
}

impl AcpTerminal {
    /// The `RESULT_STATUS` outcome for this terminal.
    ///
    /// The returned string is always one of
    /// [`tunnel_protocol::RESULT_OUTCOMES`].
    #[must_use]
    pub fn result_status(self) -> &'static str {
        match self {
            // A confirmed cancelled turn.  `docs/acp.md`: "A confirmed
            // cancelled turn has `stopReason: "cancelled"`; a lost process
            // cannot confirm cancellation" — which is why a lost process is
            // `LostAfterDispatch` below and not this.
            Self::Turn(StopReason::Cancelled) => "cancelled",
            // The turn reached a terminal state the agent reported.  Refusal
            // and the two limit reasons are completions, not failures: the ACP
            // request completed and said so.
            Self::Turn(
                StopReason::EndTurn
                | StopReason::MaxTokens
                | StopReason::MaxTurnRequests
                | StopReason::Refusal,
            ) => "succeeded",
            // `StopReason` is `#[non_exhaustive]`.  A variant this repository
            // has never read is not a success; it is a turn whose outcome is
            // unknown here.  See the module comment.
            Self::Turn(_) => "outcome_unknown",
            Self::NotDispatched => "failed",
            Self::LostAfterDispatch => "outcome_unknown",
        }
    }

    /// Whether this terminal leaves the operation's execution in doubt.
    #[must_use]
    pub fn is_unknown(self) -> bool {
        self.result_status() == "outcome_unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every outcome this module can emit is in the protocol's closed
    /// vocabulary.  Retyping the four strings here would prove nothing; this
    /// reads them from `tunnel_protocol`.
    #[test]
    fn every_emitted_outcome_is_in_the_protocol_vocabulary() {
        for terminal in [
            AcpTerminal::Turn(StopReason::EndTurn),
            AcpTerminal::Turn(StopReason::MaxTokens),
            AcpTerminal::Turn(StopReason::MaxTurnRequests),
            AcpTerminal::Turn(StopReason::Refusal),
            AcpTerminal::Turn(StopReason::Cancelled),
            AcpTerminal::NotDispatched,
            AcpTerminal::LostAfterDispatch,
        ] {
            assert!(
                tunnel_protocol::control::RESULT_OUTCOMES.contains(&terminal.result_status()),
                "{terminal:?} emitted an outcome outside the protocol vocabulary"
            );
        }
    }

    #[test]
    fn a_confirmed_cancelled_turn_is_cancelled_and_a_lost_process_is_not() {
        assert_eq!(
            AcpTerminal::Turn(StopReason::Cancelled).result_status(),
            "cancelled"
        );
        // `docs/acp.md`: "a lost process cannot confirm cancellation".  The two
        // must not collapse into one outcome, or a crash during a cancellation
        // would be reported as a clean cancel.
        assert_eq!(
            AcpTerminal::LostAfterDispatch.result_status(),
            "outcome_unknown"
        );
    }

    /// A completion is a completion even when the agent refused or ran out of
    /// budget: `docs/acp.md` says `succeeded` is about the request completing.
    #[test]
    fn a_refusal_and_the_limit_reasons_are_completions() {
        for stop in [
            StopReason::EndTurn,
            StopReason::MaxTokens,
            StopReason::MaxTurnRequests,
            StopReason::Refusal,
        ] {
            assert_eq!(AcpTerminal::Turn(stop).result_status(), "succeeded");
        }
    }

    /// Nothing ran, and the bridge can prove it.  This is the one terminal
    /// that is `failed` rather than unknown.
    #[test]
    fn a_refusal_before_dispatch_is_failed_and_not_unknown() {
        assert_eq!(AcpTerminal::NotDispatched.result_status(), "failed");
        assert!(!AcpTerminal::NotDispatched.is_unknown());
        assert!(AcpTerminal::LostAfterDispatch.is_unknown());
    }
}
