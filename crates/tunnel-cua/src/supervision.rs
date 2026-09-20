//! What a supervised backend restart does to device-side state, and what it
//! tells an operation that was in flight when it happened.
//!
//! This module is **pure**: no process, no clock, no socket. The lifecycle —
//! spawning the backend, killing it, arming the parent-death sentinel — is
//! `tunnel-cua-export`. What lives here is the part that must not be
//! re-derived by whoever wires supervision up next, because getting it wrong
//! is the difference between one click and two.
//!
//! # The trap this module exists for
//!
//! A supervisor that restarts a hung backend has destroyed the only witness
//! to what that backend had already done. `docs/tasks.md` M5-04's trap —
//! *"unknown outcome" that is really "not dispatched"* — arrives here in a new
//! costume: not through a response parser, but through the supervisor. The
//! sequence is:
//!
//! 1. A consumer dispatches `click`.
//! 2. The backend accepts it, performs it, and then hangs.
//! 3. The supervisor notices, restarts the backend.
//! 4. The consumer's exchange fails.
//!
//! If step 4 is reported as *not dispatched*, the consumer retries and the
//! click lands twice. The restart tells us nothing about whether the click
//! happened; that is precisely what makes it [`Completion::Unknown`].
//!
//! # Two halves, and both are needed
//!
//! * [`restart_outcome`] decides what the **in-flight** operation is told. It
//!   is the retryability half, and [`crate::outcome::Dispatch::retry_is_safe_for`]
//!   is what acts on it.
//! * [`Invalidation`] records what the restart **took away** from every
//!   *later* operation: the exclusive input lease, and every outstanding
//!   capture identity. It is the authority half.
//!
//! They are separate because a consumer that ignores the first still meets
//! the second. A caller told `unknown` that retries anyway finds its lease
//! gone and its capture unknown, and is refused **above the dispatch
//! boundary**, so the retry never reaches the backend at all. That layering
//! is the reason a restart cannot double-dispatch even against a
//! badly-behaved consumer, and
//! `crates/tunnel-cua-fixture/tests/supervision.rs` measures it against the
//! fixture's ledger rather than asserting it here.
//!
//! # What this does *not* claim
//!
//! It does not claim the in-flight operation's effect did or did not happen.
//! That is unknowable after the backend is gone, and saying so is the whole
//! point. It also does not claim the *target OS session* returned to any
//! particular state: a backend killed mid-drag may have left a button down,
//! and nothing in this repository can observe that. See `docs/tasks.md`
//! M5-C09.

use crate::capture::Captures;
use crate::lease::{InputLeases, TargetSession};
use crate::outcome::{Completion, Dispatch, NotDispatched, UnknownReason};

/// Which generation of the supervised backend a piece of device-side state
/// belongs to.
///
/// Monotonic and never reused, for the same reason [`Captures`] does not
/// reset its counter: a generation number that wrapped or restarted would let
/// state minted against a dead backend compare equal to state minted against
/// the live one.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BackendGeneration(u64);

impl BackendGeneration {
    /// The generation of a backend that has never been started.
    ///
    /// Deliberately distinguishable from the first *running* generation:
    /// "no backend has run" and "the first backend is running" are different
    /// facts, and a health verdict must not confuse them.
    pub const INITIAL: Self = Self(0);

    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// The next generation. Called once per successful start.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }

    /// Whether any backend has run under this generation.
    #[must_use]
    pub const fn has_started(self) -> bool {
        self.0 > 0
    }
}

/// How far an in-flight operation had got when the backend was restarted.
///
/// **The only input [`restart_outcome`] takes**, and it is a fact about the
/// transport rather than a judgement: either the request was fully written to
/// the backend or it was not. A caller that cannot answer it must say
/// [`InFlight::ReachedBackend`], because that is the answer that refuses to
/// retry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InFlight {
    /// The connection was never established, or the request was not fully
    /// written, when the restart happened. The backend cannot have parsed a
    /// command out of bytes it never received.
    ///
    /// This inherits the assumption `tunnel-cua-fixture`'s dispatch client
    /// states explicitly: the pinned `/cmd` surface is `Content-Length`
    /// framed and dispatches to its command registry only after the body is
    /// complete. A streaming command surface — the deferred `/ws` — would
    /// break it, and a chunk that takes `/ws` up must revisit this rather
    /// than inherit it.
    NotReached,
    /// The request was fully written before the restart. Whether the effect
    /// happened is now unknowable.
    ReachedBackend,
}

/// What an operation in flight across a restart is told.
///
/// **There is no argument that can make this retryable for a reached
/// request**, and that is deliberate: a supervisor is exactly the component
/// that would be tempted to say "I restarted it, so surely nothing
/// happened".
///
/// ```
/// use tunnel_cua::Operation;
/// use tunnel_cua::supervision::{InFlight, restart_outcome};
///
/// let lost = restart_outcome(InFlight::ReachedBackend);
/// assert!(lost.reached_the_backend());
/// assert!(!lost.retry_is_safe());
/// assert!(!lost.retry_is_safe_for(Operation::Click));
///
/// // A request that never landed is genuinely free to send again -- but not
/// // automatically, for an operation that synthesises input, because the
/// // consumer cannot tell this from a rotation freeze (M3-15).
/// let never = restart_outcome(InFlight::NotReached);
/// assert!(never.retry_is_safe());
/// assert!(never.retry_is_safe_for(Operation::Capture));
/// assert!(never.retry_is_safe_for(Operation::Click));
/// ```
#[must_use]
pub const fn restart_outcome(stage: InFlight) -> Dispatch {
    match stage {
        InFlight::NotReached => Dispatch::NotDispatched(NotDispatched::NotReached),
        InFlight::ReachedBackend => {
            Dispatch::Dispatched(Completion::Unknown(UnknownReason::BackendRestarted))
        }
    }
}

/// What one restart took away.
///
/// Returned by [`invalidate`] so a supervisor reports the real counts rather
/// than the fact that it called something. The distinction matters for the
/// same reason `tunnel_deadman::Deadman::stand_down` returns a `bool`: a
/// counter incremented on the call rather than on the answer would report a
/// clean invalidation for one that freed nothing.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Invalidation {
    /// The generation the device is now on.
    pub generation: BackendGeneration,
    /// Every target whose exclusive input lease was dropped.
    pub leases_released: Vec<TargetSession>,
    /// How many capture identities were forgotten.
    pub captures_forgotten: usize,
}

impl Invalidation {
    /// Whether this restart took anything away at all.
    ///
    /// A restart of an idle backend legitimately frees nothing. Reported
    /// rather than inferred, so a supervisor's diagnostics cannot present
    /// "nothing was held" and "nothing was released" as the same event.
    #[must_use]
    pub fn freed_anything(&self) -> bool {
        !self.leases_released.is_empty() || self.captures_forgotten > 0
    }
}

/// Invalidate every piece of cross-exchange input authority, and advance the
/// generation.
///
/// **Both registries, in one call, with no way to do one and not the other.**
/// Splitting them would be the defect: a lease dropped without its captures
/// leaves a consumer able to re-acquire and click at coordinates from an
/// image the dead backend produced, and captures dropped without the lease
/// leave one session holding exclusivity against a backend that never granted
/// it.
///
/// Called on **every** end of the backend's life the supervisor lives to see
/// — a restart, a stop, and a crash it noticed — not only on a deliberate
/// restart. A backend that died on its own invalidates exactly as much as one
/// the supervisor replaced.
pub fn invalidate(
    leases: &mut InputLeases,
    captures: &mut Captures,
    generation: BackendGeneration,
) -> Invalidation {
    Invalidation {
        generation,
        leases_released: leases.invalidate_all(),
        captures_forgotten: captures.invalidate_all(),
    }
}

#[cfg(test)]
mod tests;
