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
//! # Layer 1 is now on the dispatch path — and what it took to get there
//!
//! [`restart_outcome`] spent one chunk as a decision nothing consulted, so a
//! real restart-mid-operation was answered by the **transport** noticing the
//! connection die — `Completion::Unknown(TransportLost)` — rather than by the
//! supervisor naming the restart. The contract held throughout, which is why
//! that was a gap in *attribution* and not in behaviour: `TransportLost` is
//! equally `Dispatched`, equally `Unknown`, and equally non-retryable for
//! every operation. What was missing was the **named reason**.
//!
//! [`attribute_restart`] closes it (`docs/tasks.md` M5-C10), and the way it
//! does so is not the way that row's acceptance described. **That wording —
//! observe the [`BackendGeneration`] across an exchange — is racy**, because
//! that counter advances inside the supervisor's *start*, strictly after the
//! old child is killed, while the exchange reads its "after" value the instant
//! the socket closes. What was measured is the equivalent ordering on
//! [`LifecycleEpoch`]: advancing it below the kill instead of above lost the
//! attribution in **3 of 3 runs**. That is the observed rate, not a proof that
//! the race can never be won — and a mechanism that depends on winning it
//! would be the wrong shape regardless. [`LifecycleEpoch`] carries the
//! argument in full.
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
/// // A request that never landed is genuinely free to send again, for a read
/// // and for an input operation alike. M3-15's narrower rule applies to
/// // `NotDispatched::PeerUnavailable` -- the relay's ambiguous answer -- and
/// // a restart is not that: it is a fact this device observed itself.
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
    /// **The generation whose state this invalidation dropped** — that is, the
    /// backend that has just died, not the one that replaces it.
    ///
    /// Corrected after review: this said "the generation the device is now
    /// on", which is off by one on the only path that has two. A supervisor
    /// stops before it starts, so the value it stamps is the generation it is
    /// leaving; the replacement's number does not exist yet when `stop` runs.
    /// The dying generation is also the more useful of the two here, because
    /// it is the one the dropped leases and captures were minted against.
    /// Nothing asserted it, which is why the wrong reading survived; see
    /// `an_invalidation_is_stamped_with_the_generation_that_died`.
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

/// Invalidate every piece of cross-exchange input authority, stamping the
/// generation whose state is being dropped.
///
/// It does **not** advance anything: the caller decides what generation this
/// belonged to and passes it in. An earlier summary said "advance the
/// generation", which described a side effect this function has never had.
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

// ------------------------------------------------------- restart attribution

/// A counter that advances **before** the supervisor does anything that can
/// disturb a backend an exchange is already talking to.
///
/// # Why this is not [`BackendGeneration`]
///
/// The obvious reading of `docs/tasks.md` M5-C10 — "read the backend
/// generation before the request is written and compare after" — is **racy,
/// and re-deriving it rather than inheriting it is the only reason this type
/// exists.** [`BackendGeneration`] advances inside the supervisor's *start*,
/// which on a restart happens strictly after the old child has been killed
/// and reaped. An exchange against that child observes its socket close at
/// the kill, so it reads its "after" value in the window between the kill and
/// the replacement's spawn — where the generation has **not** yet advanced.
/// Attribution driven off [`BackendGeneration`] would therefore report
/// `TransportLost` or `BackendRestarted` depending on which of two unrelated
/// tasks won a race, which is the flaky-evidence shape `AGENTS.md` forbids.
///
/// A lifecycle epoch fixes the ordering by announcing the disturbance before
/// causing it: the supervisor advances this at the top of `stop`, ahead of the
/// kill, so **every** exchange that could see the socket die has already been
/// guaranteed to observe a changed epoch afterwards. The comparison is
/// equality only; the magnitude and the number of advances per restart carry
/// no meaning.
///
/// # What it does not cover
///
/// A backend that dies on its own, with no supervisor call, advances nothing,
/// and an exchange across that death is reported `TransportLost` — which is
/// the honest answer, because no restart happened. The epoch names *supervisor
/// action*, not *backend death*.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LifecycleEpoch(u64);

impl LifecycleEpoch {
    /// The epoch before the supervisor has disturbed anything.
    pub const INITIAL: Self = Self(0);

    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// The next epoch.
    ///
    /// **Not what the supervisor advances the live counter with** — that is a
    /// `fetch_add` on the shared handle, because the counter is read
    /// concurrently and a read-modify-write through this type would not be
    /// atomic. This exists so a test can construct a *changed* epoch without
    /// a supervisor, and so `before.next()` reads as "some later epoch"
    /// rather than as a magic number; every attribution test uses it.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

/// Re-attribute a transport-level answer to the supervisor, when — and only
/// when — the supervisor disturbed the backend across this exchange.
///
/// This is the production route [`restart_outcome`] previously lacked
/// (`docs/tasks.md` M5-C10). `before` is read immediately before the request
/// is written, `after` immediately after the exchange resolves, and
/// `transport` is whatever the transport concluded on its own.
///
/// # It changes the reason and never the arm
///
/// The stage is **read out of the transport's own answer** rather than
/// guessed: an answer of [`NotDispatched::NotReached`] is
/// [`InFlight::NotReached`], and an [`Completion::Unknown`] is
/// [`InFlight::ReachedBackend`]. Feeding those to [`restart_outcome`] returns
/// the same `Dispatch` arm it was given, so re-attribution does not widen
/// retryability.
///
/// **That holds by the composition of two measured functions, not by
/// construction of this one.** This function delegates the mapping to
/// [`restart_outcome`], so the property is a fact about the two bodies
/// agreeing: mutating `restart_outcome`'s `ReachedBackend` arm to
/// `NotDispatched` — which is `m5-guard-deletion.py`'s `m5c4` case *an
/// operation in flight across a restart is unknown, never not-dispatched* —
/// would widen retryability through here too. What pins it is
/// `attribution_never_changes_what_a_retry_is_allowed_to_do`, which measures
/// every reason against every operation, not the shape of the match below.
///
/// # A stop that never restarted anything is still named a restart
///
/// [`LifecycleEpoch`] advances at the top of the supervisor's `stop`, so
/// three paths advance it without a completed restart: a bare `stop()`, a
/// `restart()` whose `start()` fails, and a `stop()` called when nothing was
/// running. An exchange in flight across any of them is renamed
/// `BackendRestarted`.
///
/// **That is a diagnostic-name inaccuracy and nothing more, which is why it is
/// tolerated rather than fixed.** Every one of those paths really did take the
/// backend away underneath the exchange, so `Unknown` is the correct verdict;
/// only the word "restarted" overstates what followed. It cannot cause a
/// double click, because the rename moves `Unknown(_)` to `Unknown(
/// BackendRestarted)` and leaves `NotReached` alone, and both
/// [`Dispatch::retry_is_safe`] and [`Dispatch::retry_is_safe_for`] are
/// unchanged by either. Narrowing the name would need the epoch to advance
/// only on a *successful* restart, which reintroduces exactly the race
/// [`LifecycleEpoch`] exists to remove.
///
/// # What is deliberately left alone
///
/// * [`Completion::Ok`] and [`Completion::Failed`] — one backend gave a
///   definitive answer on a connection that survived to deliver it. Rewriting
///   a known outcome to `Unknown` because something restarted *afterwards*
///   would destroy information, which is the opposite of this row's point.
/// * Every other [`NotDispatched`] arm — `BackendRejected`,
///   `BackendUnavailable` and the input-authority refusals each name a more
///   specific cause than "a restart happened", and each is already correct.
///   `BackendUnavailable` in particular is an answer the backend *sent*.
#[must_use]
pub fn attribute_restart(
    before: LifecycleEpoch,
    after: LifecycleEpoch,
    transport: Dispatch,
) -> Dispatch {
    if before == after {
        return transport;
    }
    match &transport {
        Dispatch::Dispatched(Completion::Unknown(_)) => restart_outcome(InFlight::ReachedBackend),
        Dispatch::NotDispatched(NotDispatched::NotReached) => restart_outcome(InFlight::NotReached),
        _ => transport,
    }
}

#[cfg(test)]
mod tests;
