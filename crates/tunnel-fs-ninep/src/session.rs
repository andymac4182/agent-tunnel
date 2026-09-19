//! The session as a pure state machine.
//!
//! No socket, no clock, no filesystem and no resolver.  [`Session`] is fed
//! decoded [`Frame`]s and answers, for each request, either a [`SessionError`]
//! or an [`Accepted`] saying which gate-1 [`Primitive`]s it needs and which
//! validated [`VirtualPath`]s it names.  That pair is the whole interface gate 4
//! needs: authorize the primitives against the live grant, hand the paths to
//! gate 2's resolver, then report the outcome through [`Session::complete`] or
//! [`Session::fail`].
//!
//! # State is applied on the reply, never on the request
//!
//! The single most important rule in the file.  A `Twalk` does not bind
//! `newfid`; the `Rwalk` does, and only when the walk arrived — a **partial**
//! walk binds nothing.  A `Tlopen` does not mark a fid open; the `Rlopen` does.
//! Mutating on the request and rolling back on failure would mean a failed walk
//! had briefly bound a fid that a concurrent request could have used.
//!
//! Two deliberate exceptions, both from 9P itself and both recorded here rather
//! than discovered later: `Tclunk` and `Tremove` release their fid on **either**
//! answer, because the fid is unusable after either.  A client that had to
//! guess whether a failed clunk left a fid behind would leak fids against its
//! own quota.
//!
//! # What this machine authorizes, and what it cannot
//!
//! It checks its grant on every request, before anything else about the request
//! is acted on.  It **cannot** check freshness: `docs/filesystem-api.md` and
//! `docs/cluster.md` require the grant to be rechecked after each asynchronous
//! queue wait and immediately before each primitive side effect, and a machine
//! with no clock and no queue has neither event to hook.  Gate 4 owns that
//! recheck; this is the static half of it.

use std::collections::{BTreeMap, BTreeSet};

use tunnel_fs_core::{
    CapabilitySet, FeatureSet, Limits, PathBounds, Primitive, VirtualPath, admits_session,
};

use crate::codec::{DIALECT, Frame, negotiate};
use crate::error::SessionError;
use crate::flags::{
    O_ACCMODE, O_APPEND, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, Primitives, create_primitives,
    getattr_primitives, open_primitives, setattr_primitives, unlinkat_primitives,
};
use crate::message::{Message, MessageType};
use crate::wire::{NOFID, NONUNAME, NOTAG, Qid, QidKind};

/// Where the session is in its lifecycle.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Phase {
    /// Nothing but `Tversion` is accepted.
    AwaitingVersion,
    /// `Tversion` answered; only `Tattach` and `Tflush` are accepted.
    Versioned,
    /// The root fid is bound; the profile's full request set is accepted.
    Attached,
    /// Ended.  Nothing is accepted.
    Closed,
}

/// How a fid is open, if it is.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct OpenMode {
    /// The fid may be read from.
    pub read: bool,
    /// The fid may be written to.
    pub write: bool,
    /// The fid names a directory and is enumerated rather than read.
    pub directory: bool,
}

/// What the session knows about one live fid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FidState {
    path: VirtualPath,
    qid: Qid,
    open: Option<OpenMode>,
    generation: u64,
}

impl FidState {
    /// The virtual path this fid names.
    #[must_use]
    pub const fn path(&self) -> &VirtualPath {
        &self.path
    }

    /// The qid the provider reported for it.
    #[must_use]
    pub const fn qid(&self) -> Qid {
        self.qid
    }

    /// How the fid is open, or `None` if it is not.
    #[must_use]
    pub const fn open(&self) -> Option<OpenMode> {
        self.open
    }

    /// Whether the fid names a directory.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.qid.kind == QidKind::Directory
    }

    /// Which **binding** of this fid number this is.
    ///
    /// A fid number says nothing on its own: a client may clunk one and walk a
    /// new file to the same number while a request naming the old binding is
    /// still outstanding.  The generation distinguishes the two, and it is what
    /// this machine checks before a late reply is allowed to touch a fid.  It
    /// is exported because gate 4 holds a resolved descriptor per fid and needs
    /// the same distinction: a descriptor cached against generation *n* must
    /// not be reused once the number carries generation *n + 1*.
    ///
    /// Monotonic within a session, never reused, and never zero for a live fid.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// The virtual paths a request names.
///
/// Every variant carries only already-validated [`VirtualPath`]s, so gate 4
/// never re-derives a path from wire bytes and gate 2's resolver is the only
/// thing that turns one into a descriptor.  Both endpoints of a rename and both
/// of a link are separate paths, because the contract confines them
/// independently and there is no implicit cross-export move.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestPaths {
    /// The request names no node: `Tversion`, `Tflush`.
    Session,
    /// One existing node.
    Node(VirtualPath),
    /// A walk: where it starts and where a complete walk would end.
    ///
    /// A partial walk stops short of `destination`; the `Rwalk`'s qid count
    /// says how far it got, and `newfid` is bound only for a walk that arrived.
    Walk {
        /// Where the walk starts.
        origin: VirtualPath,
        /// Where a complete walk ends.
        destination: VirtualPath,
    },
    /// A name inside a parent directory, created or removed.
    Child {
        /// The parent directory.
        parent: VirtualPath,
        /// The child the request names.
        child: VirtualPath,
    },
    /// Two independently confined endpoints.
    Pair {
        /// The source.
        source: VirtualPath,
        /// The destination.
        destination: VirtualPath,
    },
}

/// An admitted request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Accepted {
    /// Every primitive the request requires, as a conjunction.
    ///
    /// Already checked against this session's grant.  Gate 4 rechecks them
    /// against the **live** grant after any queue wait.
    pub primitives: Primitives,
    /// The paths the request names.
    pub paths: RequestPaths,
    /// The `msize` a `Tversion` settled on, and `None` for everything else.
    pub negotiated_msize: Option<u32>,
}

/// What a successful reply does to the fid table.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Effect {
    /// Nothing.
    None,
    /// Bind the reserved root fid.
    Attach { fid: u32 },
    /// Bind `newfid` to `destination`, but only for a complete walk.
    Walk {
        origin: u32,
        /// The binding `origin` carried when the walk was admitted.
        origin_generation: u64,
        newfid: u32,
        destination: VirtualPath,
        names: usize,
        reserved: bool,
    },
    /// Mark `fid` open.
    Open {
        fid: u32,
        /// The binding `fid` carried when the open was admitted.
        generation: u64,
        mode: OpenMode,
    },
    /// Rebind `fid` to the created child and mark it open.
    Create {
        fid: u32,
        /// The binding `fid` carried when the create was admitted.
        generation: u64,
        child: VirtualPath,
        mode: OpenMode,
    },
    /// Release `fid` whatever the answer is.
    Release {
        fid: u32,
        /// The binding `fid` carried when the clunk or remove was admitted.
        ///
        /// Two `Tclunk`s of one fid can be outstanding at once, and the first
        /// reply frees the number for a fresh walk.  Without this stamp the
        /// second reply deleted whatever now held that number: the client's
        /// live fid vanished while gate 4 still held a descriptor for it.
        generation: u64,
    },
    /// The reply carries a byte count the request bounded.
    ///
    /// `Tread` and `Treaddir` bound their reply's `data`; `Twrite` bounds the
    /// `count` an `Rwrite` may acknowledge, because a provider cannot have
    /// written more bytes than the request carried.  Without this the session
    /// would accept an `Rread` of a hundred bytes for a two-byte `Tread`, which
    /// is the same class of unchecked reply as an `Rwalk` longer than its
    /// `Twalk`.
    CountedReply { limit: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TagState {
    message_type: MessageType,
    effect: Effect,
    /// Every `Tflush` currently outstanding against this tag.
    ///
    /// A **set**, not one tag: 9P allows several flushes of one request, and a
    /// single slot meant the second flush overwrote the first.  Releasing then
    /// keyed on the flush's own `flushing` field alone, so the first `Rflush`
    /// freed the tag, the client could re-issue on it — and the second
    /// `Rflush` then cancelled that new request and undid its reservation.
    /// Membership is what makes a re-issued request safe: it carries an empty
    /// set, so no stale `Rflush` can ever match it.
    flushed_by: BTreeSet<u16>,
    /// The original reply arrived while a flush was still pending.
    ///
    /// `docs/filesystem-api.md`: "Respect a normal reply arriving before
    /// `Rflush`, and reserve the flushed tag until the flush response."
    answered: bool,
    /// This tag belongs to a `Tflush`, and this is the tag it flushes.
    flushing: Option<u16>,
}

/// How a retiring `Tflush` ended, which decides what happens to its victim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlushOutcome {
    /// An `Rflush` arrived: the flush happened, so its victim is released.
    Answered,
    /// The flush ended without happening — an `Rlerror`, or the flush was
    /// itself flushed — so its victim is **not** released.
    Cancelled,
}

/// The pure 9P session state machine.
#[derive(Clone, Debug)]
pub struct Session {
    phase: Phase,
    grant: CapabilitySet,
    features: FeatureSet,
    limits: Limits,
    bounds: PathBounds,
    msize: u32,
    pending_msize: Option<u32>,
    tags: BTreeMap<u16, TagState>,
    fids: BTreeMap<u32, FidState>,
    /// Fids a request has claimed that no reply has bound yet.
    ///
    /// Reserved at request time so two concurrent `Twalk`s cannot both claim
    /// one `newfid`, and so the fid quota counts work already in flight.
    reserved_fids: BTreeMap<u32, VirtualPath>,
    /// Hands out the stamp on [`FidState::generation`].  Monotonic, never
    /// reused, and never zero, so a stale effect can be told from a live one.
    next_generation: u64,
}

impl Session {
    /// Build a session for a grant.
    ///
    /// Returns `None` for an empty grant: gate 1's `admits_session` says an
    /// export granting nothing admits no session at all, rather than admitting
    /// one that can do nothing.
    #[must_use]
    pub fn new(grant: CapabilitySet, features: FeatureSet, limits: Limits) -> Option<Self> {
        if !admits_session(grant) {
            return None;
        }
        let msize = u32::try_from(limits.max_message_bytes()).unwrap_or(u32::MAX);
        Some(Self {
            phase: Phase::AwaitingVersion,
            grant,
            features,
            limits,
            bounds: limits.path_bounds(),
            msize,
            pending_msize: None,
            tags: BTreeMap::new(),
            fids: BTreeMap::new(),
            reserved_fids: BTreeMap::new(),
            next_generation: 0,
        })
    }

    /// The current phase.
    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    /// The `msize` in force.  This side's ceiling until `Rversion` commits one.
    #[must_use]
    pub const fn msize(&self) -> u32 {
        self.msize
    }

    /// The grant this session was admitted for.
    #[must_use]
    pub const fn grant(&self) -> CapabilitySet {
        self.grant
    }

    /// The features the provider implements.
    #[must_use]
    pub const fn features(&self) -> FeatureSet {
        self.features
    }

    /// How many tags are outstanding, including tags a flush still reserves.
    #[must_use]
    pub fn outstanding_tags(&self) -> usize {
        self.tags.len()
    }

    /// How many fids are live, counting those no reply has bound yet.
    #[must_use]
    pub fn live_fids(&self) -> usize {
        self.fids.len() + self.reserved_fids.len()
    }

    /// The state of one bound fid.
    #[must_use]
    pub fn fid(&self, fid: u32) -> Option<&FidState> {
        self.fids.get(&fid)
    }

    /// Whether `tag` is outstanding.
    #[must_use]
    pub fn has_tag(&self, tag: u16) -> bool {
        self.tags.contains_key(&tag)
    }

    /// End the session, forgetting every tag and fid.
    ///
    /// Cancelling pending operations and clunking remaining fids within a
    /// deadline is gate 4's; this only forgets them, which is what makes a fid
    /// from a closed session unusable when the same numbers appear again.
    pub fn close(&mut self) {
        self.phase = Phase::Closed;
        self.tags.clear();
        self.fids.clear();
        self.reserved_fids.clear();
    }

    /// The primitives a frame decodes to, without admitting it.
    ///
    /// [`Session::request`] classifies a frame and then throws the
    /// classification away when it refuses one, so a caller that wants to know
    /// **what** it refused has nothing to ask.  This is that question, and it
    /// is deliberately the *same* computation rather than a second one: a
    /// caller re-deriving a request's primitives from its opcode would get
    /// `Tlopen` wrong, because whether an open is a mutation is decided by its
    /// flag word — `O_TRUNC` discards content and `O_WRONLY` alone does not.
    ///
    /// `None` for a frame this session could not classify at all, which is a
    /// narrower answer than it looks: a request refused for its *fid state* —
    /// a `Twrite` to a fid that is not open for writing — is refused before
    /// any primitive is decided, so the session never formed an opinion about
    /// whether it was a mutation and this does not invent one.
    ///
    /// Pure: it reads the session and changes nothing, so it may be asked
    /// before or after a refusal and answers the same either way.
    #[must_use]
    pub fn required_primitives(&self, frame: &Frame) -> Option<Primitives> {
        self.classify(frame)
            .ok()
            .map(|(accepted, _)| accepted.primitives)
    }

    /// Admit one request.
    ///
    /// # Errors
    ///
    /// Every [`SessionError`].  [`SessionError::answer`] says whether the
    /// caller replies `Rlerror` or closes the socket.
    pub fn request(&mut self, frame: &Frame) -> Result<Accepted, SessionError> {
        if self.phase == Phase::Closed {
            return Err(SessionError::Closed);
        }
        if !frame.message.is_request() {
            return Err(SessionError::UnexpectedReply);
        }
        let (accepted, effect) = self.classify(frame)?;
        // The grant is checked before a tag is taken or a fid reserved, so a
        // refused request costs the session nothing.
        for primitive in accepted.primitives.iter() {
            if !primitive.is_permitted(self.grant, self.features) {
                return Err(SessionError::NotPermitted);
            }
        }
        let effect = self.reserve_for(effect)?;
        if let Err(error) = self.reserve_tag(frame, effect.clone()) {
            self.undo_reservation(&effect);
            return Err(error);
        }
        if let Some(msize) = accepted.negotiated_msize {
            self.pending_msize = Some(msize);
        }
        Ok(accepted)
    }

    /// Apply a successful reply and release its tag.
    ///
    /// # Errors
    ///
    /// [`SessionError::TagNotInUse`] for a tag nothing is waiting on,
    /// [`SessionError::UnexpectedReply`] for a reply of the wrong type, and
    /// [`SessionError::MalformedReply`] for one whose fields contradict the
    /// request it answers.
    ///
    /// # Gate 4 must not feed a late reply to this
    ///
    /// A provider reply that arrives **after** its `Rflush` names a tag this
    /// machine has already released, so it answers [`SessionError::TagNotInUse`]
    /// — which is a 1002 close.  That is the right answer for a peer inventing
    /// a tag and the wrong one for an ordinary flush race, and the machine
    /// cannot tell them apart: both look like a reply on a released tag.  **The
    /// dispatcher owns the distinction and must drop a reply whose tag it
    /// flushed rather than passing it here.** The contract already says a
    /// normal reply arriving before `Rflush` is honoured and the tag stays
    /// reserved until the flush response; this is the other side of that
    /// window.
    pub fn complete(&mut self, frame: &Frame) -> Result<(), SessionError> {
        if self.phase == Phase::Closed {
            return Err(SessionError::Closed);
        }
        if frame.message.is_request() {
            return Err(SessionError::UnexpectedReply);
        }
        if frame.message_type() == MessageType::Rversion {
            return self.complete_version(frame);
        }
        let state = self
            .tags
            .get(&frame.tag)
            .cloned()
            .ok_or(SessionError::TagNotInUse)?;
        if state.answered {
            // A second reply on a tag whose original answer already arrived.
            return Err(SessionError::TagNotInUse);
        }
        if reply_for(state.message_type) != frame.message_type() {
            return Err(SessionError::UnexpectedReply);
        }
        let applied = self.apply_effect(&state.effect, &frame.message);
        // Whatever the effect did or refused to do, the request is over: its
        // tag is released and any fid it had reserved but not bound goes with
        // it.  A reservation exists only for an outstanding request, so
        // leaving one behind on an error path would strand a fid number that
        // is neither bound (so it cannot be clunked) nor free (so it cannot be
        // walked to).  After a successful bind this is a no-op, because
        // `apply_effect` consumed the reservation itself.
        self.undo_reservation(&state.effect);
        self.retire_tag(frame.tag, &state, FlushOutcome::Answered);
        applied
    }

    /// Apply an `Rlerror` and release its tag.
    ///
    /// The request's state changes are **not** applied, except the `Tclunk` and
    /// `Tremove` fid release, which happens either way.
    ///
    /// # A failed `Tflush` is a cancelled flush, not an answered one
    ///
    /// 9P answers `Tflush` only with `Rflush`, so gate 4 will never reach this
    /// with a flush's tag and the case is unreachable in practice.  It is
    /// still worth getting right rather than documenting as impossible: the
    /// two answers differ in what they do to the **victim**, and an `Rlerror`
    /// says the flush did not happen.  Treating it as answered would release
    /// the victim and undo its reservation — cancelling a request on the
    /// strength of a cancellation that failed.  So a failed flush takes the
    /// same path as one that was itself flushed: it leaves its victim's set
    /// without releasing it.
    ///
    /// # Errors
    /// [`SessionError::TagNotInUse`].
    pub fn fail(&mut self, tag: u16) -> Result<(), SessionError> {
        if self.phase == Phase::Closed {
            return Err(SessionError::Closed);
        }
        let state = self
            .tags
            .get(&tag)
            .cloned()
            .ok_or(SessionError::TagNotInUse)?;
        if state.answered {
            return Err(SessionError::TagNotInUse);
        }
        match &state.effect {
            Effect::Release { fid, generation } => self.release_fid(*fid, *generation),
            other => self.undo_reservation(other),
        }
        // An `Rlerror` means the request did not happen, so a failed `Tflush`
        // is a **cancelled** flush rather than an answered one.
        self.retire_tag(tag, &state, FlushOutcome::Cancelled);
        Ok(())
    }

    /// The `Rversion` this session's pending `Tversion` must be answered with.
    ///
    /// Provided so a caller cannot accidentally reply with an `msize` other
    /// than the one negotiation settled on; [`Session::complete`] refuses any
    /// other value.
    #[must_use]
    pub fn version_reply(&self) -> Option<Frame> {
        self.pending_msize.map(|msize| {
            Frame::new(
                NOTAG,
                Message::Rversion {
                    msize,
                    version: DIALECT.to_owned(),
                },
            )
        })
    }

    // ---------------------------------------------------------------- tags

    fn reserve_tag(&mut self, frame: &Frame, effect: Effect) -> Result<(), SessionError> {
        if frame.tag == NOTAG {
            // Only `Tversion` reaches here with NOTAG; the codec guaranteed it.
            // It occupies no tag slot, because nothing may be outstanding
            // alongside the handshake.
            return Ok(());
        }
        if let Some(existing) = self.tags.get(&frame.tag) {
            return Err(if !existing.flushed_by.is_empty() || existing.answered {
                SessionError::TagReservedByFlush
            } else {
                SessionError::TagInUse
            });
        }
        let quota = usize::try_from(self.limits.max_inflight_requests()).unwrap_or(usize::MAX);
        if self.tags.len() >= quota {
            return Err(SessionError::TagQuotaExhausted);
        }
        let flushing = match &frame.message {
            Message::Tflush { oldtag } => Some(*oldtag),
            _ => None,
        };
        if let Some(oldtag) = flushing
            && let Some(target) = self.tags.get_mut(&oldtag)
        {
            target.flushed_by.insert(frame.tag);
        }
        self.tags.insert(
            frame.tag,
            TagState {
                message_type: frame.message_type(),
                effect,
                flushed_by: BTreeSet::new(),
                answered: false,
                flushing,
            },
        );
        Ok(())
    }

    /// Release a tag, honouring the flush reservation.
    fn retire_tag(&mut self, tag: u16, state: &TagState, outcome: FlushOutcome) {
        if state
            .flushed_by
            .iter()
            .any(|flush_tag| self.is_live_flush_of(*flush_tag, tag))
        {
            // The original reply arrived before its `Rflush`.  It is honoured —
            // the effect above has already been applied — but the tag stays
            // reserved, and unusable, until **every** flush outstanding
            // against it has been answered.
            if let Some(entry) = self.tags.get_mut(&tag) {
                entry.answered = true;
                entry.effect = Effect::None;
            }
            return;
        }
        self.tags.remove(&tag);
        if let Some(flushed) = state.flushing {
            match outcome {
                FlushOutcome::Answered => self.release_flushed(flushed, tag),
                // A flush that ended without happening leaves its victim's set
                // but does not release it — see `Session::fail`.
                FlushOutcome::Cancelled => self.cancel_flush(flushed, tag),
            }
        }
    }

    /// Whether `flush_tag` is a **live** tag that is a `Tflush` of `victim`.
    ///
    /// The identity of a flush is that pair, not the number.  Testing only
    /// whether the number is outstanding let a *reused* tag count as a flush of
    /// something it had nothing to do with: with a stale entry left in a
    /// target's set and the client re-issuing that number as a flush of some
    /// other tag, the target read as "still flushed" forever — reserved,
    /// un-reissuable, and releasable by nothing. Repeated, that pins the
    /// session's own `maxInflightRequests` one slot at a time.
    fn is_live_flush_of(&self, flush_tag: u16, victim: u16) -> bool {
        self.tags
            .get(&flush_tag)
            .is_some_and(|state| state.flushing == Some(victim))
    }

    /// The flushes still outstanding against `victim`, `excluded` aside.
    fn live_flushes_of(&self, victim: u16, excluded: u16) -> BTreeSet<u16> {
        self.tags.get(&victim).map_or_else(BTreeSet::new, |target| {
            target
                .flushed_by
                .iter()
                .copied()
                .filter(|candidate| {
                    *candidate != excluded && self.is_live_flush_of(*candidate, victim)
                })
                .collect()
        })
    }

    /// Answer one `Tflush`: drop it from its target's set, and release the
    /// target once it is the **last** flush outstanding against it.
    ///
    /// Keyed on membership rather than on the flush's own `flushing` field.
    /// That is what makes a re-issued request safe: with two flushes for one
    /// tag, the first `Rflush` must not free the tag — and if it did, the
    /// client could re-issue on it and the second `Rflush` would silently
    /// cancel that new request and undo its reservation, leaving its eventual
    /// reply to close the session with a fatal unknown tag.  A re-issued
    /// request carries an empty set, so no stale `Rflush` can match it.
    fn release_flushed(&mut self, flushed: u16, flush_tag: u16) {
        let Some(target) = self.tags.get(&flushed) else {
            return;
        };
        if !target.flushed_by.contains(&flush_tag) {
            return;
        }
        let remaining = self.live_flushes_of(flushed, flush_tag);
        if let Some(target) = self.tags.get_mut(&flushed) {
            target.flushed_by = remaining;
            if !target.flushed_by.is_empty() {
                // The contract's "reserve the flushed tag until the flush
                // response" means the **last** response when there are
                // several.
                return;
            }
        }
        if let Some(target) = self.tags.remove(&flushed) {
            if !target.answered {
                // An `Rflush` releases the tag it flushed, whether or not the
                // original reply ever arrived — and the flushed request's
                // **reservation** goes with it.  Without that, a flushed
                // `Twalk` or `Tattach` strands its target fid for the life of
                // the session: no reply will ever bind it and no `Tclunk` can
                // release it, because it is not bound, and a client that
                // flushes walks exhausts its own fid quota with nothing to
                // clunk.  A tag already marked `answered` bound its fid and had
                // its effect cleared, so it has nothing left to undo.
                self.undo_reservation(&target.effect);
            }
            if let Some(victim) = target.flushing {
                // The tag just removed was itself a `Tflush`, so removing it
                // **cancels** that flush and it must leave its own victim's
                // set — otherwise the victim keeps a member no reply will ever
                // answer.
                self.cancel_flush(victim, flushed);
            }
        }
    }

    /// Remove a cancelled flush from its victim's set.
    ///
    /// A cancelled flush is not an answered one, so this does **not** release
    /// the victim the way [`Session::release_flushed`] does: the victim's own
    /// request may still be outstanding, and undoing its reservation would
    /// cancel a request nobody asked to cancel.  The one case that must still
    /// be collected is a victim held *only* for this flush whose own reply has
    /// already arrived: with the flush gone there is nothing left for it to
    /// wait on, and leaving it would be the same permanent reservation this
    /// method exists to prevent.
    fn cancel_flush(&mut self, victim: u16, flush_tag: u16) {
        let Some(target) = self.tags.get(&victim) else {
            return;
        };
        if !target.flushed_by.contains(&flush_tag) {
            return;
        }
        let answered = target.answered;
        let remaining = self.live_flushes_of(victim, flush_tag);
        let Some(target) = self.tags.get_mut(&victim) else {
            return;
        };
        target.flushed_by = remaining;
        if !target.flushed_by.is_empty() || !answered {
            return;
        }
        // Held only for a flush that has now been cancelled, and already
        // answered, so its effect was cleared and there is nothing to undo.
        if let Some(target) = self.tags.remove(&victim)
            && let Some(next) = target.flushing
        {
            // It was a flush itself, so cancel it against its own victim too.
            // The chain is finite: every step removes one tag.
            self.cancel_flush(next, victim);
        }
    }

    // ---------------------------------------------------------------- fids

    fn reserve_for(&mut self, effect: Effect) -> Result<Effect, SessionError> {
        match effect {
            Effect::Attach { fid } => {
                self.reserve_fid(fid, VirtualPath::root())?;
                Ok(Effect::Attach { fid })
            }
            Effect::Walk {
                origin,
                origin_generation,
                newfid,
                destination,
                names,
                ..
            } => {
                let reserved = newfid != origin;
                if reserved {
                    self.reserve_fid(newfid, destination.clone())?;
                }
                Ok(Effect::Walk {
                    origin,
                    origin_generation,
                    newfid,
                    destination,
                    names,
                    reserved,
                })
            }
            other => Ok(other),
        }
    }

    fn undo_reservation(&mut self, effect: &Effect) {
        match effect {
            Effect::Attach { fid } => {
                self.reserved_fids.remove(fid);
            }
            Effect::Walk {
                newfid,
                reserved: true,
                ..
            } => {
                self.reserved_fids.remove(newfid);
            }
            _ => {}
        }
    }

    fn reserve_fid(&mut self, fid: u32, path: VirtualPath) -> Result<(), SessionError> {
        if fid == NOFID {
            return Err(SessionError::UnknownFid);
        }
        if self.fids.contains_key(&fid) || self.reserved_fids.contains_key(&fid) {
            return Err(SessionError::FidInUse);
        }
        let quota = usize::try_from(self.limits.max_fids()).unwrap_or(usize::MAX);
        if self.live_fids() >= quota {
            return Err(SessionError::FidQuotaExhausted);
        }
        self.reserved_fids.insert(fid, path);
        Ok(())
    }

    /// Hand out the next fid binding stamp.
    ///
    /// `checked_add` rather than `wrapping_add`, so "monotonic, never reused,
    /// never zero" is true without qualification.  Wrapping would have made it
    /// true only up to 2^64 bindings, which is unreachable — a session would
    /// have to bind a fid every nanosecond for five centuries — but a stated
    /// invariant that quietly stops holding at some ceiling is worse than one
    /// that says where it ends.
    fn fresh_generation(&mut self) -> u64 {
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .expect("a session cannot bind 2^64 fids");
        self.next_generation
    }

    /// Whether a `Tattach` is outstanding with no reply yet.
    fn attach_outstanding(&self) -> bool {
        self.tags
            .values()
            .any(|tag| matches!(tag.effect, Effect::Attach { .. }))
    }

    /// Release `fid`, but only if it still carries the binding the request
    /// was admitted against.
    ///
    /// `Tclunk` and `Tremove` release their fid on **either** answer, so this
    /// is reached from both [`Session::complete`] and [`Session::fail`]; it is
    /// the one apply path that deletes rather than writes, and it needs the
    /// generation for exactly the same reason the others do.
    fn release_fid(&mut self, fid: u32, generation: u64) {
        if self
            .fids
            .get(&fid)
            .is_some_and(|state| state.generation == generation)
        {
            self.fids.remove(&fid);
        }
    }

    fn require_fid(&self, fid: u32) -> Result<&FidState, SessionError> {
        if fid == NOFID {
            return Err(SessionError::UnknownFid);
        }
        self.fids.get(&fid).ok_or(SessionError::UnknownFid)
    }

    // ------------------------------------------------------- classification

    fn classify(&self, frame: &Frame) -> Result<(Accepted, Effect), SessionError> {
        match &frame.message {
            Message::Tversion { msize, version } => {
                // `pending_msize` is the second half of "one `Tversion` per
                // session": the phase alone only moves when the `Rversion`
                // arrives, so a **pipelined** client could otherwise land two
                // `Tversion`s before either was answered, and the second would
                // silently overwrite what the first negotiated.
                if self.phase != Phase::AwaitingVersion || self.pending_msize.is_some() {
                    return Err(SessionError::RepeatedVersion);
                }
                let negotiated = negotiate(*msize, version, self.msize)?;
                Ok((
                    Accepted {
                        primitives: Primitives::one(Primitive::Version),
                        paths: RequestPaths::Session,
                        negotiated_msize: Some(negotiated),
                    },
                    Effect::None,
                ))
            }
            Message::Tattach {
                fid,
                afid,
                uname,
                aname,
                n_uname,
            } => {
                match self.phase {
                    Phase::AwaitingVersion => return Err(SessionError::BeforeVersion),
                    Phase::Attached => return Err(SessionError::RepeatedAttach),
                    Phase::Versioned | Phase::Closed => {}
                }
                // The phase moves only when the `Rattach` arrives, so the
                // outstanding-attach check is what stops a pipelined client
                // binding two root fids before either was answered.
                if self.attach_outstanding() {
                    return Err(SessionError::RepeatedAttach);
                }
                if *afid != NOFID || !uname.is_empty() || !aname.is_empty() || *n_uname != NONUNAME
                {
                    return Err(SessionError::AttachFieldNotPermitted);
                }
                if *fid == NOFID {
                    return Err(SessionError::UnknownFid);
                }
                Ok((
                    Accepted {
                        primitives: Primitives::one(Primitive::Attach),
                        paths: RequestPaths::Node(VirtualPath::root()),
                        negotiated_msize: None,
                    },
                    Effect::Attach { fid: *fid },
                ))
            }
            Message::Tflush { .. } => {
                if self.phase == Phase::AwaitingVersion {
                    return Err(SessionError::BeforeVersion);
                }
                Ok((
                    Accepted {
                        primitives: Primitives::one(Primitive::Flush),
                        paths: RequestPaths::Session,
                        negotiated_msize: None,
                    },
                    Effect::None,
                ))
            }
            _ => self.classify_attached(frame),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn classify_attached(&self, frame: &Frame) -> Result<(Accepted, Effect), SessionError> {
        match self.phase {
            Phase::AwaitingVersion => return Err(SessionError::BeforeVersion),
            Phase::Versioned => return Err(SessionError::BeforeAttach),
            Phase::Attached => {}
            Phase::Closed => return Err(SessionError::Closed),
        }
        let node = |primitives: Primitives, path: &VirtualPath| Accepted {
            primitives,
            paths: RequestPaths::Node(path.clone()),
            negotiated_msize: None,
        };
        let child = |primitives: Primitives, parent: &VirtualPath, child: VirtualPath| Accepted {
            primitives,
            paths: RequestPaths::Child {
                parent: parent.clone(),
                child,
            },
            negotiated_msize: None,
        };
        let pair =
            |primitives: Primitives, source: VirtualPath, destination: VirtualPath| Accepted {
                primitives,
                paths: RequestPaths::Pair {
                    source,
                    destination,
                },
                negotiated_msize: None,
            };
        match &frame.message {
            Message::Twalk { fid, newfid, names } => {
                let origin = self.require_fid(*fid)?;
                if origin.open.is_some() {
                    // 9P: a walk from an open fid is illegal.  The fid's
                    // position and its open mode would otherwise disagree.
                    return Err(SessionError::FidIsOpen);
                }
                if *newfid == NOFID {
                    return Err(SessionError::UnknownFid);
                }
                let mut destination = origin.path.clone();
                for name in names {
                    destination = destination.join(name, self.bounds)?;
                }
                Ok((
                    Accepted {
                        primitives: Primitives::one(Primitive::Walk),
                        paths: RequestPaths::Walk {
                            origin: origin.path.clone(),
                            destination: destination.clone(),
                        },
                        negotiated_msize: None,
                    },
                    Effect::Walk {
                        origin: *fid,
                        origin_generation: origin.generation,
                        newfid: *newfid,
                        destination,
                        names: names.len(),
                        reserved: false,
                    },
                ))
            }
            Message::Tlopen { fid, flags } => {
                let state = self.require_fid(*fid)?;
                if state.open.is_some() {
                    return Err(SessionError::FidIsOpen);
                }
                let directory = state.is_directory();
                let primitives = open_primitives(*flags, directory)?;
                Ok((
                    node(primitives, &state.path),
                    Effect::Open {
                        fid: *fid,
                        generation: state.generation,
                        mode: open_mode(*flags, directory),
                    },
                ))
            }
            Message::Tlcreate {
                fid, name, flags, ..
            } => {
                let parent = self.require_fid(*fid)?;
                if parent.open.is_some() {
                    return Err(SessionError::FidIsOpen);
                }
                if !parent.is_directory() {
                    return Err(SessionError::FidWrongKind);
                }
                let created = parent.path.join(name, self.bounds)?;
                Ok((
                    child(create_primitives(*flags)?, &parent.path, created.clone()),
                    Effect::Create {
                        fid: *fid,
                        generation: parent.generation,
                        child: created,
                        mode: open_mode(*flags, false),
                    },
                ))
            }
            Message::Tmkdir { dfid, name, .. } => {
                let parent = self.require_fid(*dfid)?;
                let made = parent.path.join(name, self.bounds)?;
                Ok((
                    child(Primitives::one(Primitive::Mkdir), &parent.path, made),
                    Effect::None,
                ))
            }
            Message::Tsymlink { fid, name, .. } => {
                let parent = self.require_fid(*fid)?;
                let link = parent.path.join(name, self.bounds)?;
                Ok((
                    child(Primitives::one(Primitive::Symlink), &parent.path, link),
                    Effect::None,
                ))
            }
            Message::Tunlinkat {
                dirfid,
                name,
                flags,
            } => {
                let parent = self.require_fid(*dirfid)?;
                let target = parent.path.join(name, self.bounds)?;
                Ok((
                    child(unlinkat_primitives(*flags)?, &parent.path, target),
                    Effect::None,
                ))
            }
            Message::Tlink { dfid, fid, name } => {
                let source = self.require_fid(*fid)?;
                let parent = self.require_fid(*dfid)?;
                let destination = parent.path.join(name, self.bounds)?;
                Ok((
                    pair(
                        Primitives::one(Primitive::Link),
                        source.path.clone(),
                        destination,
                    ),
                    Effect::None,
                ))
            }
            Message::Trename { fid, dfid, name } => {
                let source = self.require_fid(*fid)?;
                let parent = self.require_fid(*dfid)?;
                let destination = parent.path.join(name, self.bounds)?;
                Ok((
                    pair(
                        Primitives::one(Primitive::Rename),
                        source.path.clone(),
                        destination,
                    ),
                    Effect::None,
                ))
            }
            Message::Trenameat {
                olddirfid,
                oldname,
                newdirfid,
                newname,
            } => {
                let old_parent = self.require_fid(*olddirfid)?;
                let new_parent = self.require_fid(*newdirfid)?;
                let source = old_parent.path.join(oldname, self.bounds)?;
                let destination = new_parent.path.join(newname, self.bounds)?;
                Ok((
                    pair(Primitives::one(Primitive::Rename), source, destination),
                    Effect::None,
                ))
            }
            Message::Tgetattr { fid, request_mask } => {
                let state = self.require_fid(*fid)?;
                Ok((
                    node(getattr_primitives(*request_mask)?, &state.path),
                    Effect::None,
                ))
            }
            Message::Tsetattr { fid, valid, .. } => {
                let state = self.require_fid(*fid)?;
                Ok((node(setattr_primitives(*valid)?, &state.path), Effect::None))
            }
            Message::Treadlink { fid } => {
                let state = self.require_fid(*fid)?;
                Ok((
                    node(Primitives::one(Primitive::Readlink), &state.path),
                    Effect::None,
                ))
            }
            Message::Tread { fid, count, .. } => {
                let state = self.require_fid(*fid)?;
                let open = state.open.ok_or(SessionError::FidNotOpen)?;
                if open.directory {
                    // A directory is enumerated with `Treaddir`, which returns
                    // records.  A byte read of one would hand the caller the
                    // host's own directory layout.
                    return Err(SessionError::FidWrongKind);
                }
                if !open.read {
                    return Err(SessionError::FidNotOpen);
                }
                Ok((
                    node(Primitives::one(Primitive::Read), &state.path),
                    Effect::CountedReply { limit: *count },
                ))
            }
            Message::Twrite { fid, data, .. } => {
                let state = self.require_fid(*fid)?;
                let open = state.open.ok_or(SessionError::FidNotOpen)?;
                if open.directory {
                    return Err(SessionError::FidWrongKind);
                }
                if !open.write {
                    return Err(SessionError::FidNotOpen);
                }
                Ok((
                    node(Primitives::one(Primitive::Write), &state.path),
                    Effect::CountedReply {
                        limit: u32::try_from(data.len()).unwrap_or(u32::MAX),
                    },
                ))
            }
            Message::Treaddir { fid, count, .. } => {
                let state = self.require_fid(*fid)?;
                let open = state.open.ok_or(SessionError::FidNotOpen)?;
                if !open.directory {
                    return Err(SessionError::FidWrongKind);
                }
                Ok((
                    node(Primitives::one(Primitive::Readdir), &state.path),
                    Effect::CountedReply { limit: *count },
                ))
            }
            Message::Tclunk { fid } => {
                let state = self.require_fid(*fid)?;
                Ok((
                    node(Primitives::one(Primitive::Clunk), &state.path),
                    Effect::Release {
                        fid: *fid,
                        generation: state.generation,
                    },
                ))
            }
            Message::Tremove { fid } => {
                let state = self.require_fid(*fid)?;
                // The kind decides the primitive: `Tremove` on a directory is
                // the same authority as `Tunlinkat` with `AT_REMOVEDIR`.
                let primitive = if state.is_directory() {
                    Primitive::RemoveDir
                } else {
                    Primitive::Unlink
                };
                Ok((
                    node(Primitives::one(primitive), &state.path),
                    Effect::Release {
                        fid: *fid,
                        generation: state.generation,
                    },
                ))
            }
            // `Tversion`, `Tattach` and `Tflush` are handled by `classify`, and
            // a reply was refused before classification began.
            _ => Err(SessionError::UnexpectedReply),
        }
    }

    // ------------------------------------------------------------- effects

    fn complete_version(&mut self, frame: &Frame) -> Result<(), SessionError> {
        let Message::Rversion { msize, version } = &frame.message else {
            return Err(SessionError::UnexpectedReply);
        };
        if self.phase != Phase::AwaitingVersion {
            return Err(SessionError::RepeatedVersion);
        }
        let expected = self.pending_msize.ok_or(SessionError::TagNotInUse)?;
        if *msize != expected || version != DIALECT {
            return Err(SessionError::MalformedReply);
        }
        self.msize = expected;
        self.pending_msize = None;
        self.phase = Phase::Versioned;
        Ok(())
    }

    fn apply_effect(&mut self, effect: &Effect, reply: &Message) -> Result<(), SessionError> {
        match (effect, reply) {
            (Effect::Attach { fid }, Message::Rattach { qid }) => {
                // A flushed attach released its reservation, so a late
                // `Rattach` binds nothing and leaves the session unattached.
                let Some(path) = self.reserved_fids.remove(fid) else {
                    return Ok(());
                };
                if qid.kind != QidKind::Directory {
                    // The export root is a directory.  A provider claiming
                    // otherwise has bound the session to something this profile
                    // cannot serve.
                    return Err(SessionError::MalformedReply);
                }
                let generation = self.fresh_generation();
                self.fids.insert(
                    *fid,
                    FidState {
                        path,
                        qid: *qid,
                        open: None,
                        generation,
                    },
                );
                self.phase = Phase::Attached;
                Ok(())
            }
            (Effect::CountedReply { limit }, Message::Rread { data })
            | (Effect::CountedReply { limit }, Message::Rreaddir { data }) => {
                // A short read is normal; a reply longer than the request asked
                // for is not, and accepting it would let a provider return
                // bytes the caller never made room for.
                if data.len() > *limit as usize {
                    return Err(SessionError::MalformedReply);
                }
                Ok(())
            }
            (Effect::CountedReply { limit }, Message::Rwrite { count }) => {
                // A short write is normal; acknowledging more bytes than the
                // `Twrite` carried is not, and `bytesAcknowledged` is built
                // from these.
                if count > limit {
                    return Err(SessionError::MalformedReply);
                }
                Ok(())
            }
            (
                Effect::Walk {
                    origin,
                    origin_generation,
                    newfid,
                    destination,
                    names,
                    reserved,
                },
                Message::Rwalk { qids },
            ) => {
                if qids.len() > *names {
                    return Err(SessionError::MalformedReply);
                }
                if qids.is_empty() && *names > 0 {
                    // 9P: when the **first** element cannot be walked the
                    // server answers an error reply, not an `Rwalk` carrying
                    // no qids.  Accepting the latter would let a provider
                    // report "nothing found" in a shape the client is supposed
                    // to read as a successful zero-element clone.
                    return Err(SessionError::MalformedReply);
                }
                if qids.len() < *names {
                    // A partial walk binds nothing.  The reservation is
                    // released, and `newfid` is as unused as before.
                    if *reserved {
                        self.reserved_fids.remove(newfid);
                    }
                    return Ok(());
                }
                let qid = if let Some(qid) = qids.last() {
                    *qid
                } else {
                    // A zero-element walk clones the fid, so the destination's
                    // qid is the origin's — and if the origin was clunked
                    // while this walk was outstanding there is nothing left to
                    // clone, so the reply applies nothing.
                    match self.fids.get(origin) {
                        Some(state) if state.generation == *origin_generation => state.qid,
                        // Gone, or the number carries a different binding now:
                        // either way there is nothing left to clone.
                        _ => return Ok(()),
                    }
                };
                if *reserved {
                    if self.reserved_fids.remove(newfid).is_none() {
                        // The reservation was released — flushed, or the
                        // request already failed — so there is nothing to bind.
                        return Ok(());
                    }
                } else if !matches!(
                    self.fids.get(newfid),
                    Some(state) if state.generation == *origin_generation
                ) {
                    // A walk in place reserves nothing, so it may bind only the
                    // **binding** it was admitted against.  Re-creating a fid
                    // clunked while the walk was outstanding would put a number
                    // back into the table that the quota had already released,
                    // and `live_fids()` could then exceed `maxFids`; moving a
                    // number the client has since re-bound to something else
                    // would leave this session's path and gate 4's descriptor
                    // for that fid disagreeing.
                    return Ok(());
                }
                let generation = self.fresh_generation();
                self.fids.insert(
                    *newfid,
                    FidState {
                        path: destination.clone(),
                        qid,
                        open: None,
                        generation,
                    },
                );
                Ok(())
            }
            (
                Effect::Open {
                    fid,
                    generation,
                    mode,
                },
                Message::Rlopen { qid, .. },
            ) => {
                // A fid clunked while its open was outstanding is gone, and a
                // number the client has since re-bound carries a different
                // generation; either way the reply applies nothing rather than
                // failing, because a reply is not a request and gate 4 has no
                // `Rlerror` to send for it.
                let Some(state) = self
                    .fids
                    .get_mut(fid)
                    .filter(|state| state.generation == *generation)
                else {
                    return Ok(());
                };
                let mut mode = *mode;
                // The provider's qid is the authority on the node's kind, so an
                // open that the flags called a file and the host calls a
                // directory is recorded as a directory rather than as whichever
                // the client claimed.
                mode.directory = qid.kind == QidKind::Directory;
                if mode.directory && (mode.write || !mode.read) {
                    return Err(SessionError::MalformedReply);
                }
                state.qid = *qid;
                state.open = Some(mode);
                Ok(())
            }
            (
                Effect::Create {
                    fid,
                    generation,
                    child,
                    mode,
                },
                Message::Rlcreate { qid, .. },
            ) => {
                if qid.kind != QidKind::File {
                    return Err(SessionError::MalformedReply);
                }
                let fresh = self.fresh_generation();
                let Some(state) = self
                    .fids
                    .get_mut(fid)
                    .filter(|state| state.generation == *generation)
                else {
                    return Ok(());
                };
                // A create rebinds the fid to the child it made, so the number
                // now carries a new binding.
                state.path = child.clone();
                state.qid = *qid;
                state.open = Some(*mode);
                state.generation = fresh;
                Ok(())
            }
            (Effect::Release { fid, generation }, _) => {
                self.release_fid(*fid, *generation);
                Ok(())
            }
            (Effect::None, _) => Ok(()),
            // Every other pairing means the reply's type did not match its
            // request's, which `complete` already refused.
            _ => Err(SessionError::UnexpectedReply),
        }
    }
}

/// The open mode a validated flag word produces.
///
/// Only reached after [`open_primitives`] or [`create_primitives`] accepted the
/// flags, so the impossible combinations are already gone.
fn open_mode(flags: u32, is_directory: bool) -> OpenMode {
    let access = flags & O_ACCMODE;
    OpenMode {
        read: access == O_RDONLY || access == O_RDWR,
        write: access == O_WRONLY || access == O_RDWR || flags & (O_TRUNC | O_APPEND) != 0,
        directory: is_directory,
    }
}

/// The reply type that answers a request type.
const fn reply_for(request: MessageType) -> MessageType {
    match request {
        MessageType::Tversion => MessageType::Rversion,
        MessageType::Tattach => MessageType::Rattach,
        MessageType::Tflush => MessageType::Rflush,
        MessageType::Twalk => MessageType::Rwalk,
        MessageType::Tlopen => MessageType::Rlopen,
        MessageType::Tlcreate => MessageType::Rlcreate,
        MessageType::Tsymlink => MessageType::Rsymlink,
        MessageType::Treadlink => MessageType::Rreadlink,
        MessageType::Tgetattr => MessageType::Rgetattr,
        MessageType::Tsetattr => MessageType::Rsetattr,
        MessageType::Treaddir => MessageType::Rreaddir,
        MessageType::Tlink => MessageType::Rlink,
        MessageType::Tmkdir => MessageType::Rmkdir,
        MessageType::Trename => MessageType::Rrename,
        MessageType::Trenameat => MessageType::Rrenameat,
        MessageType::Tunlinkat => MessageType::Runlinkat,
        MessageType::Tread => MessageType::Rread,
        MessageType::Twrite => MessageType::Rwrite,
        MessageType::Tclunk => MessageType::Rclunk,
        MessageType::Tremove => MessageType::Rremove,
        other => other,
    }
}
