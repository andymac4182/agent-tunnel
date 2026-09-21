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
//! point.
//!
//! # The third half: what a restart cannot see (`docs/tasks.md` M5-C09)
//!
//! [`restart_outcome`] and [`Invalidation`] are both statements about *this
//! device's* bookkeeping. Neither says anything about the target OS session,
//! and the silence was readable as a claim. [`DesktopResidue`] ends the
//! silence without resolving it: a restart now **declares** which kinds of
//! input state the departed backend may have left asserted on the target,
//! because it cannot observe them and cannot put them back.
//!
//! **It is a declaration and never a repair, and that is a decision with a
//! safety argument, not a shortfall.** A "release everything" sweep would be
//! the supervisor synthesising input — the thing M5's health probe is
//! forbidden from doing, for the reason that a click nobody asked for is the
//! same harm as a click that landed twice. It is also **inexpressible against
//! the pinned surface**: `tunnel_cua_fixture::REGISTERED_COMMANDS` mirrors the
//! 0.3.46 registry this repository has read, and it carries no button-up,
//! key-up or held-key primitive; `docs/integrations.md`'s platform table
//! records the same limit for the Cua Driver backend. The only way to force a
//! release through that registry is *more synthesised input* — a `drag` onto
//! itself, a `hotkey` re-press — each of which is an unauthorized effect on
//! somebody's desktop.
//!
//! Nor can the device read the residue away. The one pointer-adjacent read the
//! profile carries is `cursor_position`, which reports **where** the pointer
//! is and never **whether a button is down**; the fixture's answer is
//! `{success, x, y}` and the registry has nothing else. So there is no
//! observation that could clear a declared residue, and this module
//! deliberately offers no operation that removes one.

use crate::capture::Captures;
use crate::lease::{InputLeases, TargetSession};
use crate::operation::Operation;
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

// ------------------------------------------- what a restart cannot see (C09)

/// Input state a backend may have left asserted on the **target OS session**,
/// and that nothing on this device can observe.
///
/// # What is in scope, and why the boundary is where it is
///
/// A residue kind is carried only when both halves hold: the operation
/// synthesises input that can be interrupted **part-way**, and this device has
/// **no read that would settle it**. "Every input changes the world" is true
/// and useless; what a later agent inherits as a *stuck input device* is the
/// thing worth declaring, because it silently re-interprets everything that
/// agent does next — a `move` with a button still down is a drag.
///
/// The boundary excludes one input operation, which is the point of having a
/// map rather than a flag: see [`interruption_residue`] on [`Operation::Move`].
///
/// # There is no way to take a kind away
///
/// This type has a [`DesktopResidue::union`] and no difference, no `clear` and
/// no `observe`. That is deliberate and it is the honest limit stated as an
/// API: nothing in this repository can establish that a declared residue is
/// gone, so nothing in this repository may offer to say so. A future chunk
/// that measures a real backend on a VM (`docs/tasks.md` M5-C09a) would be
/// entitled to add one; reading is not.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct DesktopResidue {
    pointer_button: bool,
    key_held: bool,
    partial_effect: bool,
}

impl DesktopResidue {
    /// Nothing unobservable can have been left behind.
    ///
    /// **Not the same as "the desktop is unchanged."** A completed click
    /// changed the desktop and leaves no residue, because the change is the
    /// consumer's own intended effect rather than an input this device left
    /// asserted.
    pub const NONE: Self = Self {
        pointer_button: false,
        key_held: false,
        partial_effect: false,
    };

    /// A pointer button may still be down.
    pub const POINTER_BUTTON: Self = Self {
        pointer_button: true,
        ..Self::NONE
    };

    /// A key or modifier may still be held.
    pub const KEY_HELD: Self = Self {
        key_held: true,
        ..Self::NONE
    };

    /// An effect may have been applied in part: some of a string typed, some
    /// of a scroll delta delivered, a drag carried half way.
    pub const PARTIAL_EFFECT: Self = Self {
        partial_effect: true,
        ..Self::NONE
    };

    /// Everything either of these declares.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self {
            pointer_button: self.pointer_button || other.pointer_button,
            key_held: self.key_held || other.key_held,
            partial_effect: self.partial_effect || other.partial_effect,
        }
    }

    /// Whether this declares nothing at all.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.pointer_button && !self.key_held && !self.partial_effect
    }

    #[must_use]
    pub const fn pointer_button_may_be_down(self) -> bool {
        self.pointer_button
    }

    #[must_use]
    pub const fn key_may_be_held(self) -> bool {
        self.key_held
    }

    #[must_use]
    pub const fn effect_may_be_partial(self) -> bool {
        self.partial_effect
    }
}

/// What an interruption of this operation may have left on the target that
/// this device cannot see.
///
/// The four read-only operations synthesise no input at all, so an
/// interruption of one cannot leave any, and each declares
/// [`DesktopResidue::NONE`]. **A read that manufactured a residue would make
/// the declaration meaningless** — if everything declares everything, a
/// consumer learns nothing from being told.
///
/// # [`Operation::Move`] is the input operation that declares nothing
///
/// It asserts no button and no key, and its entire effect *is* the pointer
/// position — which `cursor_position` reports. So a `move` interrupted
/// half-way leaves the pointer somewhere the device can simply go and read.
/// It is the one place the profile's read surface actually covers an input
/// operation, and carrying it in the map rather than special-casing "input"
/// is what keeps this from being `mutates_target` under another name.
///
/// **The counter-argument, recorded rather than dismissed:** a `move` across a
/// desktop that *already* has a button down is a drag, so a move can have an
/// effect far beyond its position. That effect is attributable to the prior
/// residue, not to the move, which is exactly why the prior residue must be
/// declared — and it is the strongest reason this row could not be closed with
/// a prose note.
#[must_use]
pub const fn interruption_residue(operation: Operation) -> DesktopResidue {
    match operation {
        // Reads. No input is synthesised, so an interruption leaves none.
        Operation::Describe
        | Operation::Capture
        | Operation::ScreenInfo
        | Operation::CursorPosition => DesktopResidue::NONE,
        // See this function's own documentation: the pointer's position is
        // the whole effect, and the profile can read it.
        Operation::Move => DesktopResidue::NONE,
        // A press whose matching release the backend may not have reached.
        // `double_click` is one dispatch with two click effects, which makes
        // its interior strictly more interruptible, not less.
        Operation::Click | Operation::DoubleClick => DesktopResidue::POINTER_BUTTON,
        // Both, and the only operation that carries both: a drag is a press,
        // a traversal and a release, so it can end with the button down *and*
        // the gesture carried part of the way.
        Operation::Drag => DesktopResidue::POINTER_BUTTON.union(DesktopResidue::PARTIAL_EFFECT),
        // Discrete deltas, some of which may have been delivered. Nothing is
        // left asserted, and nothing reads how far it got.
        Operation::Scroll => DesktopResidue::PARTIAL_EFFECT,
        // A prefix of the string may have been typed. **Which prefix is not
        // recorded, here or anywhere**: the payload is keystrokes and
        // `crate::schema::Keystrokes` keeps it out of every diagnostic. The
        // declaration is that *some* prefix may exist, never what it was.
        Operation::TypeText => DesktopResidue::PARTIAL_EFFECT,
        // A key or chord whose release the backend may not have reached. Kept
        // distinct from `POINTER_BUTTON` because the two are cleared by
        // different things and inherited differently: a held modifier
        // re-interprets every later keystroke, a held button every later move.
        Operation::PressKey | Operation::Hotkey => DesktopResidue::KEY_HELD,
    }
}

/// The residue a restart declares, folded from [`interruption_residue`] over
/// every operation that synthesises input.
///
/// **Conservative on purpose, and derived rather than restated.** This device
/// does not record which operation was in flight when the supervisor killed
/// the backend — there is no in-flight register anywhere in `tunnel-cua` — so
/// a restart cannot narrow the declaration to the operation that was actually
/// running. Folding the map is what keeps this honest as the map changes: an
/// operation added with a new residue kind widens this automatically, where a
/// hand-written constant would quietly not.
pub const RESTART_RESIDUE: DesktopResidue = restart_residue();

const fn restart_residue() -> DesktopResidue {
    let mut residue = DesktopResidue::NONE;
    let mut index = 0;
    while index < Operation::INPUT.len() {
        residue = residue.union(interruption_residue(Operation::INPUT[index]));
        index += 1;
    }
    residue
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
    /// **What this restart may have left on the target, and cannot see.**
    ///
    /// The other two fields say what the device took away from itself; this
    /// one says what it could not take away from the desktop. It rides on the
    /// same value for the same reason both registries ride on one call: a
    /// supervisor that could report the invalidation without the declaration
    /// would report the reassuring half alone.
    ///
    /// Always [`RESTART_RESIDUE`] when [`invalidate`] produced it, and
    /// [`DesktopResidue::NONE`] on a [`Default`] value, which represents no
    /// restart having happened rather than a clean one.
    pub residue: DesktopResidue,
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

    /// What this restart may have left on the target and cannot see.
    #[must_use]
    pub const fn residue(&self) -> DesktopResidue {
        self.residue
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
///
/// # The declaration is unconditional, and that is the sharp part
///
/// [`RESTART_RESIDUE`] is stamped whatever the registries held, including on
/// the idle restart that frees nothing. Conditioning it on
/// [`Invalidation::freed_anything`] is the tempting narrowing and it is wrong
/// twice over: the device's own bookkeeping is **not a witness to the
/// desktop** — a lease released a microsecond before the kill leaves the
/// registry empty and says nothing about what the backend was mid-way through
/// — and the residue that matters most is precisely the one inherited by a
/// *later* agent, who holds no lease at the moment of the restart. A device
/// that said "nothing was held, so the desktop is clean" would be making the
/// exact claim this row exists to stop.
pub fn invalidate(
    leases: &mut InputLeases,
    captures: &mut Captures,
    generation: BackendGeneration,
) -> Invalidation {
    Invalidation {
        generation,
        leases_released: leases.invalidate_all(),
        captures_forgotten: captures.invalidate_all(),
        residue: RESTART_RESIDUE,
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
