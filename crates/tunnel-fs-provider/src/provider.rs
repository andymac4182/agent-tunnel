//! The dispatcher.
//!
//! One [`Provider`] is one 9P session on one consumer connection, against one
//! export root and one grant context.

use std::collections::{BTreeMap, VecDeque};

use tunnel_fs_core::{
    CapabilitySet, FeatureSet, FsError, FsErrorCode, Limits, Outcome, Primitive, SessionErrorCode,
};
use tunnel_fs_host::{
    DirReader, ExportRoot, FileKind, Handle, HostEntry, Intent, Metadata, TimeChange,
};
use tunnel_fs_ninep::{
    Accepted, Attributes, COUNTED_REPLY_OVERHEAD, DirEntry, ENTRY_OVERHEAD, Frame, GETATTR_ALL,
    GETATTR_BASIC, Message, Primitives, Qid, QidKind, RequestPaths, Session, SessionError,
    flags::{
        AT_REMOVEDIR, O_ACCMODE, O_APPEND, O_RDONLY, O_RDWR, O_TRUNC, SETATTR_ATIME,
        SETATTR_ATIME_SET, SETATTR_MODE, SETATTR_MTIME, SETATTR_MTIME_SET, SETATTR_SIZE,
    },
    open_primitives, pack_entries,
};

/// What the connector knows about this session's authorization right now.
///
/// Three facts, and no more: the contract's authorization model is a revision, a
/// capability set and a freshness deadline, and anything else a provider read
/// from an authorization source would be state it could be tempted to cache.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Authorization {
    /// The grant revision this session's authorization context is frozen at.
    ///
    /// A change closes the session. The contract: "An observed capability or
    /// grant change closes that session and requires fresh discovery; never
    /// silently broaden access."
    pub revision: u64,
    /// The capabilities the live grant carries.
    pub grant: CapabilitySet,
    /// Whether the authorization snapshot is still inside its deadline.
    ///
    /// `docs/cluster.md` gives that deadline a five-second ceiling measured from
    /// the start of the authoritative catalog read, and requires it to be
    /// checked "immediately before each local adapter dispatch, after every
    /// await/queue wait". This provider asks at exactly those two moments; the
    /// *deadline arithmetic* belongs to the connector, which has the clock.
    pub fresh: bool,
}

/// Where a provider asks what it is allowed to do at this instant.
///
/// A trait rather than a value, because the answer must be re-read and may not
/// be remembered: a provider that held an `Authorization` would answer a queued
/// request against the authorization the request arrived under, which is the
/// exact failure the recheck exists to prevent.
pub trait Authority {
    /// The live authorization, read now.
    fn current(&self) -> Authorization;
}

/// What the provider wants the connector to do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outbound {
    /// Encode and send this 9P frame to the consumer.
    Frame(Box<Frame>),
    /// Close the consumer socket, with the code gate 1 maps this failure to.
    ///
    /// The connector sends nothing further on this session.
    Close(SessionErrorCode),
}

impl Outbound {
    fn frame(frame: Frame) -> Self {
        Self::Frame(Box::new(frame))
    }
}

/// Payload-free counters, for a harness gate to assert against.
///
/// Every field counts events, so nothing here can carry a path, a name or a
/// byte of content.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProviderStats {
    /// Requests the session admitted and this provider queued.
    pub requests_queued: u64,
    /// Successful replies sent.
    pub replies_sent: u64,
    /// `Rlerror` replies sent.
    pub errors_sent: u64,
    /// Queued requests dropped because their tag had been flushed.
    ///
    /// The gate-3 obligation: such a reply is **dropped**, never handed to
    /// `Session::complete`, which would answer `TagNotInUse` and close 1002.
    pub dropped_after_flush: u64,
    /// Times the live authorization was re-read after a queue wait.
    pub grant_rechecks: u64,
    /// Requests refused because the live grant no longer permitted them.
    pub grant_refusals: u64,
    /// Sessions closed because the grant revision moved under them.
    pub revision_closures: u64,
    /// Sessions closed because the authorization snapshot had expired.
    pub freshness_closures: u64,
    /// `Tlopen`s the resolver's kind classified differently from the flags.
    ///
    /// The comparison is against the **flags alone**, which is the only
    /// classification available without asking something about the node: a
    /// directory opened read-only without `O_DIRECTORY` reads as `OpenRead`
    /// there and must become `OpenDir`. Gate 3's session reaches the same
    /// answer for a fid whose *qid* already says directory, so this counter is
    /// larger than the number of decisions the session would have got wrong —
    /// it measures the re-classification happening, not the session being
    /// mistaken, and those are different claims.
    pub reclassified_opens: u64,
    /// `Tlopen`s the re-classification refused that the flags alone permitted.
    ///
    /// This one *is* the gate-3 obligation's own measure: an open the flag-level
    /// decision would have admitted and the resolver's kind refuses.
    pub reclassification_refusals: u64,
    /// Mutating requests refused before the host was touched.
    ///
    /// Every one of these is [`Outcome::NotStarted`], which is the claim gate 4
    /// could make about *every* refusal it produced and gate 5 can no longer.
    pub mutations_refused: u64,
    /// Mutating requests this dispatcher handed to the host.
    ///
    /// The denominator of the outcome ledger below: a request counted here had
    /// its effecting syscall made, so it is one whose outcome is a fact about
    /// the host rather than about this dispatcher.
    pub mutations_dispatched: u64,
    /// Dispatched mutations the host reported it applied, whole or in part.
    pub mutations_applied: u64,
    /// Applied mutations whose reply reached the carrier **and described the
    /// effect**.
    ///
    /// `mutations_applied - mutations_acknowledged == mutation_unknown` is an
    /// identity, which is why this is counted where delivery is confirmed
    /// rather than where the reply is built: a reply that was produced and
    /// could not be sent is not an acknowledgement of anything.
    ///
    /// The second half of that sentence is what keeps the identity true for
    /// [`ProviderStats::mutation_unknown`]'s *other* source. A post-effect
    /// read that failed produces an `Rlerror` which does go out — but it names
    /// a code, not the effect, so nothing is acknowledged and the ledger is
    /// closed as `unknown` before the send rather than settled by it.
    pub mutations_acknowledged: u64,
    /// Dispatched mutations the host reported changed nothing.
    ///
    /// [`Outcome::Failed`], and **not** `not_started`: the request reached the
    /// host, which is a different fact from a refusal taken before it.
    pub mutation_failed: u64,
    /// Mutations that applied part of what they were asked for.
    ///
    /// A short `Twrite`, and a multi-field `Tsetattr` whose later field failed
    /// after an earlier one had already been applied. [`Outcome::Partial`].
    pub mutation_partial: u64,
    /// Applied mutations whose effect the consumer cannot learn.
    ///
    /// [`Outcome::Unknown`], and it has **two** sources rather than one.
    ///
    /// The first is a reply that never left: counted when the connector reports
    /// a send it could not complete, and at [`Provider::close`] for an effect
    /// still outstanding. A session that ends mid-mutation is the case the
    /// contract names: "Session loss during a potentially dispatched mutation
    /// carries `outcome: unknown`."
    ///
    /// The second is a **post-effect read that failed**, and there the
    /// `Rlerror` *is* delivered — which is why this field is worded about what
    /// the consumer can learn rather than about what arrived. `mkdirat` and
    /// `symlinkat` create a node and return nothing, so the qid the reply must
    /// carry costs a second syscall; when that syscall loses a race the node
    /// still exists, and no code in the closed vocabulary can say what was
    /// made. The caller is told something failed and cannot tell that anything
    /// applied, so the ledger is closed `unknown` at that point and the reply
    /// is never counted acknowledged — which is what keeps
    /// `mutations_applied - mutations_acknowledged == mutation_unknown` an
    /// identity across both sources.
    pub mutation_unknown: u64,
    /// Bytes the host acknowledged writing.
    ///
    /// The contract's `bytesAcknowledged` on this side of the wire: a lower
    /// bound confirmed by replies, never a claim about durable content.
    pub bytes_written: u64,
    /// Bytes answered to `Tread`.
    pub bytes_read: u64,
    /// `Rreaddir` blocks packed.
    pub readdir_blocks: u64,
    /// Directory entries packed into those blocks.
    pub readdir_entries: u64,
}

/// One resolved descriptor, held for as long as its fid binding lives.
struct OpenFid {
    /// The binding this descriptor was resolved for.
    ///
    /// **The cache key that matters.** A fid *number* is not a fid: a client may
    /// clunk one and walk a different file to the same number while a request
    /// naming the old binding is outstanding. Gate 3 exported
    /// `FidState::generation` so gate 4 could key on it, and this is that use:
    /// a descriptor resolved for generation *n* is never handed to a request
    /// against generation *n + 1*.
    generation: u64,
    handle: Handle,
    /// Present for a directory, absent for a file.
    reader: Option<DirReader>,
    /// One entry read from `reader` that did not fit its `Rreaddir` block.
    ///
    /// Held so the next `Treaddir` on this fid returns it without re-reading the
    /// directory from the start. The cookie contract is unchanged: a caller that
    /// resumes anywhere else clears this and seeks.
    pending: Option<HostEntry>,
}

/// One request waiting for the host.
struct Queued {
    tag: u16,
    frame: Frame,
    accepted: Accepted,
    /// The binding the request's primary fid carried when it was admitted.
    generation: u64,
    /// A `Tflush` named this request's tag while it was waiting here.
    ///
    /// **The mark belongs to the entry, not to the tag number.** A number is
    /// not a request: gate 3's session releases a flushed tag when its `Rflush`
    /// is answered, so a client may re-issue that number while the original is
    /// still queued, and then flush the new one too. Both are legitimately
    /// flushed, and a mark held per *number* can only be spent once — the first
    /// entry popped would clear it and the second would be performed, its reply
    /// handed to `Session::complete` for a tag nothing is waiting on, closing a
    /// well-behaved client's session with 1002.
    flushed: bool,
}

/// One 9P session over one export.
///
/// # Read-only, and refusing the rest by name
///
/// Gate 4 implements the descriptor endpoint, the upgrade, the dispatcher and
/// the **read** path. `Tlcreate`, `Twrite`, `Tmkdir`, `Tunlinkat`, `Tremove`,
/// `Trename`, `Trenameat`, `Tsetattr`, `Tsymlink` and `Tlink` are answered
/// `ENOTSUP` here **whatever the grant says**, and that is a deliberate
/// narrowing rather than an authorization decision: a write grant configured
/// against this build would be advertised and then refused, which is honest,
/// where implementing half of one would not be. Gate 5 is where they become
/// real, together with the partial and unknown outcomes they need.
pub struct Provider<A: Authority> {
    session: Session,
    root: ExportRoot,
    authority: A,
    limits: Limits,
    features: FeatureSet,
    /// The revision this session was admitted at. A different one closes it.
    admitted_revision: u64,
    /// Resolved descriptors, by fid number, validated by generation.
    open: BTreeMap<u32, OpenFid>,
    /// Requests admitted and not yet performed.
    queue: VecDeque<Queued>,
    /// An effect that happened on the host and whose reply the connector has
    /// not confirmed sending.
    ///
    /// **This is the whole of the `unknown` outcome on this side.** A
    /// dispatcher cannot observe delivery — the socket is the connector's — so
    /// the honest model is a one-entry ledger the connector settles: it calls
    /// [`Provider::confirm_effect_delivered`] once the record is on the
    /// carrier, and anything still outstanding when the session ends is
    /// reported `unknown` rather than guessed either way. It is one entry and
    /// not a set because [`Provider::step`] performs one request and the
    /// connector writes its reply before the next `step`, so two effects can
    /// never be outstanding at once; a dispatcher that performed requests
    /// concurrently would need a map here, and that is recorded rather than
    /// pre-built.
    undelivered_effect: bool,
    stats: ProviderStats,
}

impl<A: Authority> Provider<A> {
    /// Build a provider for an export.
    ///
    /// Returns `None` for an empty grant: gate 1's `admits_session` says an
    /// export granting nothing admits no session at all, and discovery answers
    /// `403 ACCESS_DENIED` for it rather than opening one that can do nothing.
    pub fn new(root: ExportRoot, limits: Limits, authority: A) -> Option<Self> {
        let live = authority.current();
        let features = root.features();
        let session = Session::new(root.grant(), features, limits)?;
        Some(Self {
            session,
            root,
            limits,
            features,
            admitted_revision: live.revision,
            authority,
            open: BTreeMap::new(),
            queue: VecDeque::new(),
            undelivered_effect: false,
            stats: ProviderStats::default(),
        })
    }

    /// The `msize` in force: this side's ceiling until `Rversion` commits one.
    #[must_use]
    pub const fn msize(&self) -> u32 {
        self.session.msize()
    }

    /// The counters.
    #[must_use]
    pub const fn stats(&self) -> ProviderStats {
        self.stats
    }

    /// Whether a queued request is waiting for [`Provider::step`].
    #[must_use]
    pub fn has_work(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Whether the reply this dispatcher just produced reports an effect that
    /// has already happened on the host.
    ///
    /// The connector reads this to decide whether a failed send is an
    /// `unknown` outcome or merely a lost read.
    #[must_use]
    pub const fn reply_carries_effect(&self) -> bool {
        self.undelivered_effect
    }

    /// Record that the reply carrying the outstanding effect reached the
    /// carrier.
    ///
    /// Delivery to the *carrier*, which is all a device can ever confirm: the
    /// contract is explicit that a transport acknowledgement proves neither a
    /// filesystem side effect nor its arrival, and this settles the ledger
    /// rather than claiming either.
    pub fn confirm_effect_delivered(&mut self) {
        if self.undelivered_effect {
            self.undelivered_effect = false;
            // Counted **here** and not where the reply was built, so that
            // `mutations_applied - mutations_acknowledged == mutation_unknown`
            // is an identity rather than an approximation: a reply the
            // connector could not send must not be counted as acknowledged and
            // then counted again as unknown.
            self.stats.mutations_acknowledged += 1;
        }
    }

    /// Record that the reply carrying the outstanding effect could not be sent.
    ///
    /// The effect happened and the consumer will never be told what it was, so
    /// the operation's outcome is [`Outcome::Unknown`] and is counted as such.
    /// It is never downgraded afterwards, which is gate 1's monotonic
    /// [`Outcome::merge`] applied to a counter.
    pub fn note_effect_undelivered(&mut self) {
        if self.undelivered_effect {
            self.undelivered_effect = false;
            self.stats.mutation_unknown += 1;
        }
    }

    /// End the session, releasing every descriptor it holds.
    pub fn close(&mut self) {
        // An effect that happened and whose reply never went out is `unknown`,
        // and the session ending is the last moment it can be recorded. A
        // queued request that was never performed is **not** counted here: it
        // was never dispatched, so it is `not_started` and there is nothing
        // ambiguous about it.
        self.note_effect_undelivered();
        self.session.close();
        self.queue.clear();
        // Dropping the map is what closes the descriptors.  Gate 3's `Session`
        // forgets its fids; this is the half that returns the host's resources.
        self.open.clear();
    }

    /// Admit one decoded inbound frame.
    ///
    /// Requests that change nothing on the host — the version handshake and
    /// `Tflush` — are answered here. Everything else is queued for
    /// [`Provider::step`], because the authorization recheck the contract
    /// requires is defined as happening *after* a queue wait, and a dispatcher
    /// with no queue would have nowhere to take it.
    pub fn accept(&mut self, frame: &Frame) -> Vec<Outbound> {
        let tag = frame.tag;
        let accepted = match self.session.request(frame) {
            Ok(accepted) => accepted,
            Err(error) => return self.refuse(tag, error),
        };

        match &frame.message {
            Message::Tversion { .. } => self.answer_version(),
            Message::Tflush { oldtag } => self.answer_flush(tag, *oldtag),
            _ => {
                let generation = self
                    .primary_fid(&frame.message)
                    .and_then(|fid| self.session.fid(fid))
                    .map_or(0, tunnel_fs_ninep::FidState::generation);
                self.stats.requests_queued += 1;
                self.queue.push_back(Queued {
                    tag,
                    frame: frame.clone(),
                    accepted,
                    generation,
                    flushed: false,
                });
                Vec::new()
            }
        }
    }

    /// Perform the oldest queued request.
    ///
    /// This is where the two rechecks the contract assigns to gate 4 are taken,
    /// and where a flushed request is dropped.
    pub fn step(&mut self) -> Vec<Outbound> {
        let Some(queued) = self.queue.pop_front() else {
            return Vec::new();
        };

        // Obligation 2.  A reply for a tag this dispatcher has already flushed
        // is **dropped**: the `Rflush` released that tag, so `Session::complete`
        // would see a reply on a tag nothing is waiting for — which is the right
        // answer for a peer inventing a tag and a 1002 close for an ordinary
        // flush race.  The machine cannot tell the two apart; this dispatcher
        // can, because it is the thing that sent the `Rflush`.
        if queued.flushed {
            self.stats.dropped_after_flush += 1;
            return Vec::new();
        }

        // The recheck after the queue wait, and immediately before the host is
        // touched.  Both halves, in the contract's own order: the revision
        // first, because a moved revision ends the session rather than refusing
        // one request, then freshness, then the primitives against the live
        // grant.
        let live = self.authority.current();
        self.stats.grant_rechecks += 1;
        if live.revision != self.admitted_revision {
            self.stats.revision_closures += 1;
            self.close();
            return vec![Outbound::Close(SessionErrorCode::CapabilitiesChanged)];
        }
        if !live.fresh {
            self.stats.freshness_closures += 1;
            self.close();
            return vec![Outbound::Close(SessionErrorCode::AuthExpired)];
        }
        for primitive in queued.accepted.primitives.iter() {
            if !primitive.is_permitted(live.grant, self.features) {
                // Narrowed inside one revision.  Belt and braces beside the
                // revision check above, and the cheaper of the two to be wrong
                // about: it refuses one request rather than the session.
                self.stats.grant_refusals += 1;
                return self.fail_queued(&queued, FsError::NotPermitted);
            }
        }

        match self.perform(&queued, live.grant) {
            Ok(reply) => self.settle(queued, reply),
            Err(error) => self.fail_queued(&queued, error),
        }
    }

    /// Whether a request's admitted primitives include one that can change the
    /// host.
    ///
    /// Taken from the primitives gate 3 decoded, not from the opcode: a
    /// `Tlopen` is a mutation when its flags decoded to `OpenTruncate` and is
    /// not when they decoded to `OpenWrite`, and only the flag word can tell
    /// those apart.
    fn is_mutation(queued: &Queued) -> bool {
        queued
            .accepted
            .primitives
            .iter()
            .any(Primitive::is_mutating)
    }

    // ------------------------------------------------------------- answering

    /// Answer a refusal the session took before anything was performed.
    fn refuse(&mut self, tag: u16, error: SessionError) -> Vec<Outbound> {
        match error.answer() {
            tunnel_fs_ninep::Answer::Rlerror(fs_error) => {
                self.stats.errors_sent += 1;
                vec![Outbound::frame(Frame::new(
                    tag,
                    Message::Rlerror {
                        code: fs_error.code(),
                    },
                ))]
            }
            tunnel_fs_ninep::Answer::Close(code) => {
                self.close();
                vec![Outbound::Close(code)]
            }
        }
    }

    /// Answer a performed request that failed, releasing its tag.
    fn fail(&mut self, tag: u16, error: FsError) -> Vec<Outbound> {
        if let Err(session_error) = self.session.fail(tag) {
            // The session refused to retire the tag, which can only mean this
            // dispatcher answered one it was not holding.  That is a bug here,
            // not a peer violation, and closing is the only honest answer.
            return self.refuse(tag, session_error);
        }
        self.stats.errors_sent += 1;
        vec![Outbound::frame(Frame::new(
            tag,
            Message::Rlerror { code: error.code() },
        ))]
    }

    /// Answer a performed request that failed, and release what its failure
    /// released.
    ///
    /// `Tclunk` and `Tremove` release their fid on **either** answer, which is
    /// 9P's own rule and gate 3's session applies it to an `Rlerror` too. The
    /// descriptor this provider holds for that fid has to go with it, or a
    /// refused `Tremove` on an open fid would leak one for the life of the
    /// session.
    fn fail_queued(&mut self, queued: &Queued, error: FsError) -> Vec<Outbound> {
        if Self::is_mutation(queued) {
            // The outcome the host reported, recorded as the host reported it.
            // `Outcome::Failed` means the effecting syscall was made and
            // changed nothing; `Outcome::NotStarted` means the refusal came
            // before it — from the grant, from the flags, from the namespace or
            // from resolving the parent. Gate 4 could only ever produce the
            // second, and conflating them here would give that claim back.
            match error.outcome() {
                Outcome::NotStarted => self.stats.mutations_refused += 1,
                Outcome::Failed => {
                    self.stats.mutations_dispatched += 1;
                    self.stats.mutation_failed += 1;
                }
                // **Both of these are reported by an `Rlerror`, and they are
                // not the same fact.**
                //
                // `Partial` is a composite mutation — a multi-field `Tsetattr`
                // — whose later field failed after an earlier one applied. The
                // consumer *is* told: it receives the `Rlerror` naming the
                // field that failed, and what it cannot tell from that alone is
                // that part of the request applied. So this opens the ledger
                // like any other effect-carrying reply and lets the connector
                // settle it on the send; counting it `unknown` here would label
                // a reply that was delivered as one that was not.
                //
                // `Unknown` is the post-effect identity read: the host changed
                // and no code in the closed vocabulary can say what it made, so
                // the caller cannot learn the outcome however well the reply is
                // delivered. That one is counted here and the ledger is closed
                // with it, because there is nothing left for delivery to
                // settle.
                Outcome::Partial => {
                    self.stats.mutations_dispatched += 1;
                    self.stats.mutations_applied += 1;
                    self.stats.mutation_partial += 1;
                    self.undelivered_effect = true;
                }
                Outcome::Unknown => {
                    self.stats.mutations_dispatched += 1;
                    self.stats.mutations_applied += 1;
                    self.undelivered_effect = true;
                    self.note_effect_undelivered();
                }
            }
        }
        let answer = self.fail(queued.tag, error);
        if let Some(fid) = self.primary_fid(&queued.frame.message) {
            self.prune(fid);
        }
        answer
    }

    /// Apply a successful reply to the session and emit it.
    fn settle(&mut self, queued: Queued, reply: Reply) -> Vec<Outbound> {
        if let Some(effect) = reply.effect {
            self.stats.mutations_dispatched += 1;
            self.stats.mutations_applied += 1;
            if effect == Applied::Partial {
                self.stats.mutation_partial += 1;
            }
            // The ledger opens here and is settled by the connector. Between
            // these two points the effect has happened and the consumer has not
            // been told, which is the only window in which `unknown` is the
            // truthful answer.
            self.undelivered_effect = true;
        }
        let frame = Frame::new(queued.tag, reply.message);
        if let Err(error) = self.session.complete(&frame) {
            return self.refuse(queued.tag, error);
        }
        if let Some(fid) = self.primary_fid(&queued.frame.message) {
            match reply.cache {
                CacheEffect::Insert(entry) => self.insert(fid, queued.generation, entry),
                // A create rebinds its fid to the file it made, so the session
                // stamped a *fresh* generation when the reply above was
                // applied. Keying the descriptor on the generation the request
                // was admitted against would leave the created file's
                // descriptor immediately unusable.
                CacheEffect::InsertCreated(entry) => {
                    let generation = self
                        .session
                        .fid(fid)
                        .map_or(queued.generation, tunnel_fs_ninep::FidState::generation);
                    self.insert(fid, generation, entry);
                }
                CacheEffect::Release => self.release(fid, queued.generation),
                CacheEffect::None => {}
            }
            self.prune(fid);
        }
        self.stats.replies_sent += 1;
        vec![Outbound::frame(frame)]
    }

    /// The version handshake, which occupies no tag and touches no host.
    fn answer_version(&mut self) -> Vec<Outbound> {
        let Some(reply) = self.session.version_reply() else {
            self.close();
            return vec![Outbound::Close(SessionErrorCode::ProtocolViolation)];
        };
        if let Err(error) = self.session.complete(&reply) {
            return self.refuse(reply.tag, error);
        }
        self.stats.replies_sent += 1;
        vec![Outbound::frame(reply)]
    }

    /// Cancel a queued request and answer its flush.
    ///
    /// `Tflush` is **cancellation, not rollback**. A request already performed
    /// keeps its reply — gate 3's session holds the flushed tag until the last
    /// flush against it is answered — and a request still in the queue is
    /// removed here and marked so [`Provider::step`] drops it if it is reached
    /// anyway.
    fn answer_flush(&mut self, tag: u16, oldtag: u16) -> Vec<Outbound> {
        // The victim is **left in the queue** and marked instead of being
        // removed.  Removing it here would make the drop unobservable — and
        // would model only the case where the flush wins the race, where the
        // obligation is about the case where it does not: a reply produced for
        // a tag whose `Rflush` has gone out.  `Provider::step` is where it is
        // dropped, before any host work, so nothing is performed either way.
        //
        // **Only a request still in the queue is marked, and the mark is per
        // entry rather than per tag number.** A victim this dispatcher has
        // already answered has no reply left to drop, and marking it anyway
        // would silently drop the reply of whatever the client re-issued on
        // that number. Marking *every* queued entry carrying `oldtag` is what
        // makes a re-issued-and-re-flushed number work: at this moment the
        // queue can hold both the original — already marked by its own flush —
        // and the re-issue this flush names, and both were legitimately
        // flushed. A single mark on the number could only be spent once.
        for queued in &mut self.queue {
            if queued.tag == oldtag {
                queued.flushed = true;
            }
        }
        let reply = Frame::new(tag, Message::Rflush);
        if let Err(error) = self.session.complete(&reply) {
            return self.refuse(tag, error);
        }
        self.stats.replies_sent += 1;
        vec![Outbound::frame(reply)]
    }

    // ---------------------------------------------------------- the fid cache

    /// The descriptor for `fid`, **only** if it belongs to the live binding.
    ///
    /// Obligation 3. The generation is asked of the session, so a number the
    /// client re-bound answers `None` rather than the previous binding's
    /// descriptor.
    ///
    /// **Defence in depth, and measured as such.** Deleting this filter, the
    /// prune and the release's own generation check — all three at once — turns
    /// no test red, because gate 3's session is already authoritative about a
    /// fid's open state *per binding*: it refuses a `Tread` on a fid it does not
    /// hold open at the current one, and applies a reply only to the binding it
    /// was admitted against, so nothing can reach a stale entry and an `Rlopen`
    /// for a re-bound number overwrites it rather than reading it. The
    /// obligation asked for the cache to be keyed on the generation and it is;
    /// that is not the same claim as the keying being load-bearing, and the
    /// difference is recorded rather than counted.
    fn cached(&self, fid: u32) -> Option<&OpenFid> {
        let generation = self.session.fid(fid)?.generation();
        self.open
            .get(&fid)
            .filter(|entry| entry.generation == generation)
    }

    fn cached_mut(&mut self, fid: u32) -> Option<&mut OpenFid> {
        let generation = self.session.fid(fid)?.generation();
        self.open
            .get_mut(&fid)
            .filter(|entry| entry.generation == generation)
    }

    fn insert(&mut self, fid: u32, generation: u64, entry: OpenState) {
        // Only if the number still carries the binding the request was admitted
        // against.  A late reply for a clunked fid applies nothing in gate 3's
        // session, and it must leave no descriptor behind here either.
        if self
            .session
            .fid(fid)
            .map(tunnel_fs_ninep::FidState::generation)
            != Some(generation)
        {
            return;
        }
        self.open.insert(
            fid,
            OpenFid {
                generation,
                handle: entry.handle,
                reader: entry.reader,
                pending: None,
            },
        );
    }

    fn release(&mut self, fid: u32, generation: u64) {
        // Keyed on the generation, not the number: two `Tclunk`s of one fid can
        // be outstanding, and without this the second would close the descriptor
        // of whatever the client had since walked to that number.
        //
        // **Defensive**, like the lookup's own filter above: the queue is FIFO
        // and gate 3's session refuses a `Twalk` to a fid that is still bound,
        // so a number cannot be re-bound until its clunk's *reply* has landed,
        // which happens before any request queued behind it is performed. A
        // dispatcher that performed requests out of order — the shape gate 5
        // needs for a blocking pool — would reach it.
        if self
            .open
            .get(&fid)
            .is_some_and(|entry| entry.generation == generation)
        {
            self.open.remove(&fid);
        }
    }

    /// Drop a descriptor whose binding has gone, so a re-bound number cannot
    /// accumulate one entry per generation.
    fn prune(&mut self, fid: u32) {
        let live = self
            .session
            .fid(fid)
            .map(tunnel_fs_ninep::FidState::generation);
        if self
            .open
            .get(&fid)
            .is_some_and(|entry| Some(entry.generation) != live)
        {
            self.open.remove(&fid);
        }
    }

    /// The fid a request's cache effect applies to, if it has one.
    fn primary_fid(&self, message: &Message) -> Option<u32> {
        match message {
            Message::Tattach { fid, .. }
            | Message::Tlopen { fid, .. }
            | Message::Tread { fid, .. }
            | Message::Treaddir { fid, .. }
            | Message::Tgetattr { fid, .. }
            | Message::Tclunk { fid }
            | Message::Tremove { fid }
            | Message::Treadlink { fid }
            // `Tlcreate` rebinds its parent fid to the file it made, so the
            // cache effect belongs to that same number.
            | Message::Tlcreate { fid, .. }
            | Message::Twrite { fid, .. }
            | Message::Tsetattr { fid, .. } => Some(*fid),
            Message::Twalk { newfid, .. } => Some(*newfid),
            // `Tmkdir`, `Tsymlink`, `Tunlinkat`, `Tlink` and both renames name
            // a *directory* fid whose own binding they do not change, so none
            // of them has a cache effect and pruning on one would drop a
            // descriptor the client still holds.
            _ => None,
        }
    }

    // ------------------------------------------------------------ performing

    fn perform(&mut self, queued: &Queued, grant: CapabilitySet) -> Result<Reply, FsError> {
        match &queued.frame.message {
            Message::Tattach { .. } => self.perform_attach(&queued.accepted),
            Message::Twalk { names, .. } => self.perform_walk(&queued.accepted, names),
            Message::Tlopen { fid, flags } => self.perform_open(*fid, *flags, grant),
            Message::Tread { fid, offset, count } => self.perform_read(*fid, *offset, *count),
            Message::Treaddir { fid, offset, count } => self.perform_readdir(*fid, *offset, *count),
            Message::Tgetattr { fid, request_mask } => self.perform_getattr(*fid, *request_mask),
            Message::Tclunk { .. } => Ok(Reply::releasing(Message::Rclunk)),
            Message::Treadlink { fid } => self.perform_readlink(*fid),
            Message::Tlcreate {
                name: _,
                flags,
                mode,
                ..
            } => self.perform_create(&queued.accepted, *flags, *mode),
            Message::Twrite { fid, offset, data } => self.perform_write(*fid, *offset, data),
            Message::Tmkdir { mode, .. } => self.perform_mkdir(&queued.accepted, *mode),
            Message::Tsymlink { target, .. } => self.perform_symlink(&queued.accepted, target),
            Message::Tunlinkat { flags, .. } => {
                self.perform_unlink(&queued.accepted, *flags & AT_REMOVEDIR != 0)
            }
            Message::Tremove { fid } => self.perform_remove(*fid, grant),
            Message::Trename { .. } => self.perform_rename(&queued.accepted, Message::Rrename),
            Message::Trenameat { .. } => self.perform_rename(&queued.accepted, Message::Rrenameat),
            Message::Tlink { .. } => self.perform_link(&queued.accepted),
            Message::Tsetattr {
                fid,
                valid,
                mode,
                size,
                atime_sec,
                atime_nsec,
                mtime_sec,
                mtime_nsec,
                ..
            } => self.perform_setattr(
                *fid,
                SetattrRequest {
                    valid: *valid,
                    mode: *mode,
                    size: *size,
                    atime: (*atime_sec, *atime_nsec),
                    mtime: (*mtime_sec, *mtime_nsec),
                },
            ),
            // `Tversion`, `Tattach` and `Tflush` never reach the queue, and a
            // reply was refused before classification began.
            _ => Err(FsError::refused(FsErrorCode::Einval)),
        }
    }

    fn perform_attach(&mut self, accepted: &Accepted) -> Result<Reply, FsError> {
        let RequestPaths::Node(path) = &accepted.paths else {
            return Err(FsError::refused(FsErrorCode::Einval));
        };
        // No capability is consulted: session lifecycle primitives require none,
        // because a session exists only for a non-empty grant.  `metadata`'s
        // `list` check is therefore deliberately bypassed here — and nothing a
        // forged `Tattach` could carry reaches this, because gate 3's session
        // refuses every non-default `afid`, `uname`, `aname` and `n_uname`
        // before this runs, and the path is the export root by construction
        // rather than anything the message named.
        let metadata = self.root.metadata_unchecked(path)?;
        Ok(Reply::plain(Message::Rattach {
            qid: qid_of(metadata),
        }))
    }

    fn perform_walk(&mut self, accepted: &Accepted, names: &[String]) -> Result<Reply, FsError> {
        let RequestPaths::Walk { origin, .. } = &accepted.paths else {
            return Err(FsError::refused(FsErrorCode::Einval));
        };
        let bounds = self.root.bounds();
        let mut current = origin.clone();
        let mut qids = Vec::with_capacity(names.len());
        for name in names {
            let next = match current.join(name, bounds) {
                Ok(next) => next,
                Err(rule) => {
                    if qids.is_empty() {
                        return Err(FsError::Path(rule));
                    }
                    break;
                }
            };
            // `Twalk` requires no capability, so the metadata lookup here must
            // not consult `list` either: the qid disclosure that follows from
            // that is the contract's own recorded decision, bounded to qids.
            match self.root.metadata_unchecked(&next) {
                Ok(metadata) => {
                    qids.push(qid_of(metadata));
                    current = next;
                }
                Err(error) => {
                    // 9P: an error reply when the **first** element fails, and a
                    // short `Rwalk` when a later one does.  A partial walk binds
                    // nothing, which gate 3's session enforces.
                    if qids.is_empty() {
                        return Err(error);
                    }
                    break;
                }
            }
        }
        Ok(Reply::plain(Message::Rwalk { qids }))
    }

    /// Obligation 1: re-classify the open with the kind the **resolver** reports.
    ///
    /// Gate 3's session re-runs `open_primitives` with the kind the fid's *qid*
    /// records, which is what the walk saw. That is not the same thing: the node
    /// can have changed kind since, and a `read`-without-`list` grant must not be
    /// able to open a directory that `Treaddir` would then refuse. So the
    /// decision is taken again here against a fresh metadata lookup, and the
    /// live grant is what it is checked against.
    fn open_primitives_now(
        &mut self,
        flags: u32,
        kind: FileKind,
        admitted: Primitives,
        grant: CapabilitySet,
    ) -> Result<Primitives, FsError> {
        let required = open_primitives(flags, kind == FileKind::Directory)
            .map_err(|_| FsError::refused(FsErrorCode::Enotsup))?;
        if required != admitted {
            self.stats.reclassified_opens += 1;
        }
        for primitive in required.iter() {
            if !primitive.is_permitted(grant, self.features) {
                if required != admitted {
                    self.stats.reclassification_refusals += 1;
                }
                return Err(FsError::NotPermitted);
            }
        }
        Ok(required)
    }

    fn perform_open(
        &mut self,
        fid: u32,
        flags: u32,
        grant: CapabilitySet,
    ) -> Result<Reply, FsError> {
        let path = self
            .session
            .fid(fid)
            .ok_or_else(|| FsError::refused(FsErrorCode::Einval))?
            .path()
            .clone();
        let metadata = self.root.metadata_unchecked(&path)?;
        let admitted =
            open_primitives(flags, false).map_err(|_| FsError::refused(FsErrorCode::Enotsup))?;
        let required = self.open_primitives_now(flags, metadata.kind(), admitted, grant)?;

        check_append_unsupported(flags)?;
        let writable = required
            .iter()
            .any(|primitive| matches!(primitive, Primitive::OpenWrite | Primitive::OpenTruncate));
        let truncating = flags & O_TRUNC != 0;

        let (handle, reader, mode) = if metadata.kind() == FileKind::Directory {
            let handle = self.root.open_directory(&path)?;
            let reader = self
                .root
                .reader_for(&handle, self.limits.max_traversal_entries())?;
            (handle, Some(reader), OpenKind::Directory)
        } else if writable {
            // The truncation happens **through the descriptor**, inside
            // `open_writable`, after the hard-link rule has permitted it. The
            // resolving open never carries `O_TRUNC`, which is gate 2's pinned
            // choice and is what keeps a refused write from following a
            // truncation that already destroyed the file.
            let handle = self
                .root
                .open_writable(&path, truncating, flags & O_ACCMODE == O_RDWR)?;
            (handle, None, OpenKind::File)
        } else {
            let handle = self.root.open_read(&path)?;
            (handle, None, OpenKind::File)
        };
        // The qid is taken from the descriptor that was actually opened, not
        // from the `statat` above: the two can disagree, and the descriptor is
        // the only authority.
        //
        // **A truncating open has already emptied the file by the time this
        // runs**, so both failures below are reported `unknown` rather than
        // `not_started`: the content is gone and an `Rlerror` saying the
        // request never started would invite a caller to conclude otherwise. A
        // non-truncating open changed nothing and keeps its own outcome.
        let effected = |error: FsError| {
            if truncating {
                tunnel_fs_host::after_effect(error)
            } else {
                error
            }
        };
        let opened = handle.metadata().map_err(effected)?;
        if (opened.kind() == FileKind::Directory) != matches!(mode, OpenKind::Directory) {
            return Err(effected(FsError::refused(FsErrorCode::Einval)));
        }
        let iounit = self.session.msize().saturating_sub(COUNTED_REPLY_OVERHEAD);
        let reply = Reply::opening(
            Message::Rlopen {
                qid: qid_of(opened),
                iounit,
            },
            OpenState { handle, reader },
        );
        // A truncating open **changed the file**, so its reply carries an
        // effect and its loss is `unknown`. A plain writable open changed
        // nothing and does not: the distinction is exactly why `OpenWrite` and
        // `OpenTruncate` are two primitives.
        Ok(if truncating {
            reply.with_effect(Applied::Whole)
        } else {
            reply
        })
    }

    fn perform_read(&mut self, fid: u32, offset: u64, count: u32) -> Result<Reply, FsError> {
        let limit = self.session.msize().saturating_sub(COUNTED_REPLY_OVERHEAD);
        let wanted = usize::try_from(count.min(limit)).unwrap_or(0);
        let entry = self
            .cached(fid)
            .ok_or_else(|| FsError::refused(FsErrorCode::Einval))?;
        if entry.reader.is_some() {
            // `Tread` on a directory is `EISDIR`: enumeration is `Treaddir`, and
            // handing back raw directory bytes would leak the host's own
            // on-disk layout.
            return Err(FsError::refused(FsErrorCode::Eisdir));
        }
        let mut data = vec![0_u8; wanted];
        let read = entry.handle.read_at(offset, &mut data)?;
        data.truncate(read);
        self.stats.bytes_read += read as u64;
        Ok(Reply::plain(Message::Rread { data }))
    }

    fn perform_readdir(&mut self, fid: u32, offset: u64, count: u32) -> Result<Reply, FsError> {
        let limit = usize::try_from(self.session.msize().saturating_sub(COUNTED_REPLY_OVERHEAD))
            .unwrap_or(0)
            .min(usize::try_from(count).unwrap_or(0));
        let budget = self.limits.max_traversal_entries();
        let entry = self
            .cached_mut(fid)
            .ok_or_else(|| FsError::refused(FsErrorCode::Einval))?;
        // Destructured rather than reached through accessors, because the
        // pushed-back entry and the reader are read together below and a method
        // borrow of one would freeze the other.
        let OpenFid {
            reader, pending, ..
        } = entry;
        let reader = reader
            .as_mut()
            .ok_or_else(|| FsError::refused(FsErrorCode::Enotdir))?;

        // Where this reader would answer from if the caller asked for the next
        // page: one behind the pushed-back entry if there is one, and the
        // reader's own position otherwise.
        let resume_at = pending
            .as_ref()
            .map_or_else(|| reader.position(), |held| held.cookie().saturating_sub(1));
        if offset != resume_at {
            // A cookie other than the one this reader is holding: the push-back
            // is for the sequential case only and must not survive a seek.
            *pending = None;
            reader.seek(offset, budget)?;
        }

        let mut entries = Vec::new();
        let mut used = 0_usize;
        loop {
            let host = match pending.take() {
                Some(held) => held,
                None => match reader.next_entry()? {
                    Some(host) => host,
                    None => break,
                },
            };
            let width = ENTRY_OVERHEAD + host.name().len();
            if used + width > limit {
                // This entry does not fit.  It is **pushed back**, not dropped:
                // dropping it would invent an end of directory, and re-seeking
                // for it would re-read the whole directory once per page.  An
                // entry is packed whole or left out entirely, which is gate 3's
                // own rule for the block.
                *pending = Some(host);
                break;
            }
            used += width;
            entries.push(DirEntry::new(
                Qid::new(qid_kind(host.kind()), host.qid_path()),
                host.cookie(),
                host.name().to_owned(),
            ));
        }
        let (data, packed) =
            pack_entries(&entries, limit).map_err(|_| FsError::refused(FsErrorCode::Einval))?;
        if packed != entries.len() {
            // The width arithmetic above and `pack_entries`' own bound
            // disagreed, which would mean an entry was silently dropped.
            return Err(FsError::refused(FsErrorCode::Einval));
        }
        self.stats.readdir_blocks += 1;
        self.stats.readdir_entries += packed as u64;
        Ok(Reply::plain(Message::Rreaddir { data }))
    }

    fn perform_getattr(&mut self, fid: u32, request_mask: u64) -> Result<Reply, FsError> {
        if request_mask == 0 || request_mask & !GETATTR_ALL != 0 {
            return Err(FsError::refused(FsErrorCode::Enotsup));
        }
        // An open fid answers from its own descriptor; a fid reached only by
        // walking answers from the metadata-only lookup, which is the gate-2
        // obligation this gate discharges and the reason a `list`-without-`read`
        // grant can stat at all.
        let metadata = match self.cached(fid) {
            Some(entry) => entry.handle.metadata()?,
            None => {
                let path = self
                    .session
                    .fid(fid)
                    .ok_or_else(|| FsError::refused(FsErrorCode::Einval))?
                    .path()
                    .clone();
                self.root.metadata(&path)?
            }
        };
        Ok(Reply::plain(Message::Rgetattr(attributes_of(
            metadata,
            request_mask,
        ))))
    }

    // ------------------------------------------------------------ mutations
    //
    // Everything below this line is implementation gate 5. Each one takes the
    // same shape and the shape is the point: the primitive was authorized
    // against the **live** grant in `step` before any of this ran, the paths
    // were validated by gate 1 and handed over by gate 3, the resolver anchors
    // the parent, and exactly one host syscall can change anything. A failure
    // before that syscall is `not_started` and a failure of it is `failed`; a
    // reply that reports an effect opens the ledger `settle` hands to the
    // connector, and that ledger is the whole of `unknown`.

    /// The virtual path a fid currently names.
    fn path_of(&self, fid: u32) -> Result<tunnel_fs_core::VirtualPath, FsError> {
        Ok(self
            .session
            .fid(fid)
            .ok_or_else(|| FsError::refused(FsErrorCode::Einval))?
            .path()
            .clone())
    }

    /// The `child` half of a create-or-remove request's paths.
    fn child_path(accepted: &Accepted) -> Result<&tunnel_fs_core::VirtualPath, FsError> {
        match &accepted.paths {
            RequestPaths::Child { child, .. } => Ok(child),
            _ => Err(FsError::refused(FsErrorCode::Einval)),
        }
    }

    /// The independently confined endpoints of a rename or a link.
    fn pair_paths(
        accepted: &Accepted,
    ) -> Result<(&tunnel_fs_core::VirtualPath, &tunnel_fs_core::VirtualPath), FsError> {
        match &accepted.paths {
            RequestPaths::Pair {
                source,
                destination,
            } => Ok((source, destination)),
            _ => Err(FsError::refused(FsErrorCode::Einval)),
        }
    }

    fn perform_readlink(&mut self, fid: u32) -> Result<Reply, FsError> {
        let path = self.path_of(fid)?;
        let target = self.root.read_link(&path)?;
        Ok(Reply::plain(Message::Rreadlink { target }))
    }

    /// `Tlcreate`: make a new regular file and rebind the parent fid to it.
    fn perform_create(
        &mut self,
        accepted: &Accepted,
        flags: u32,
        mode: u32,
    ) -> Result<Reply, FsError> {
        check_append_unsupported(flags)?;
        let access = flags & O_ACCMODE;
        if access == O_RDONLY {
            // A create whose fid is not writable is refused rather than
            // served, because gate 3's session would record the fid read-only
            // while the host descriptor this call makes is not, and a fid whose
            // two descriptions disagree is the defect the generation stamp
            // exists to prevent in the other direction. Creating a file one
            // cannot then write also has no use the profile names.
            return Err(FsError::refused(FsErrorCode::Einval));
        }
        let path = Self::child_path(accepted)?.clone();
        let handle = self
            .root
            .create(&path, mode, flags & O_TRUNC != 0, access == O_RDWR)?;
        // **The file exists by now**, so a failed identity read is `unknown`:
        // the create happened and this reply cannot say what it made.
        let created = handle.metadata().map_err(tunnel_fs_host::after_effect)?;
        let iounit = self.session.msize().saturating_sub(COUNTED_REPLY_OVERHEAD);
        Ok(Reply::creating(
            Message::Rlcreate {
                qid: qid_of(created),
                iounit,
            },
            OpenState {
                handle,
                reader: None,
            },
        )
        .with_effect(Applied::Whole))
    }

    /// `Twrite`: a positioned write through the fid's own descriptor.
    ///
    /// **A short write is an ordinary 9P answer and is the only partial outcome
    /// this profile can express on the wire.** The `Rwrite` carries what the
    /// host acknowledged, the contract's `bytesAcknowledged` is built from
    /// exactly that, and nothing here retries the remainder: a retry is a
    /// second dispatch, and this profile never replays a mutation on a caller's
    /// behalf.
    fn perform_write(&mut self, fid: u32, offset: u64, data: &[u8]) -> Result<Reply, FsError> {
        let entry = self
            .cached(fid)
            .ok_or_else(|| FsError::refused(FsErrorCode::Einval))?;
        if entry.reader.is_some() {
            // A directory is enumerated, never written.
            return Err(FsError::refused(FsErrorCode::Eisdir));
        }
        let written = entry.handle.write_at(offset, data)?;
        self.stats.bytes_written += written as u64;
        let count = u32::try_from(written).unwrap_or(u32::MAX);
        // Gate 3's session refuses an `Rwrite` acknowledging more than its
        // `Twrite` carried, so this cannot over-report even if the host did.
        Ok(
            Reply::plain(Message::Rwrite { count }).with_effect(if written == data.len() {
                Applied::Whole
            } else {
                Applied::Partial
            }),
        )
    }

    fn perform_mkdir(&mut self, accepted: &Accepted, mode: u32) -> Result<Reply, FsError> {
        let path = Self::child_path(accepted)?.clone();
        let identity = self.root.make_directory(&path, mode)?;
        Ok(Reply::plain(Message::Rmkdir {
            qid: Qid::new(QidKind::Directory, identity.qid_path()),
        })
        .with_effect(Applied::Whole))
    }

    fn perform_symlink(&mut self, accepted: &Accepted, target: &str) -> Result<Reply, FsError> {
        let path = Self::child_path(accepted)?.clone();
        let identity = self.root.symlink(&path, target)?;
        Ok(Reply::plain(Message::Rsymlink {
            qid: Qid::new(QidKind::Symlink, identity.qid_path()),
        })
        .with_effect(Applied::Whole))
    }

    fn perform_unlink(&mut self, accepted: &Accepted, directory: bool) -> Result<Reply, FsError> {
        let path = Self::child_path(accepted)?.clone();
        self.root.remove(&path, directory)?;
        Ok(Reply::plain(Message::Runlinkat).with_effect(Applied::Whole))
    }

    /// `Tremove`: unlink the name a fid names, and release the fid either way.
    ///
    /// The kind is re-decided with the **resolver's** answer rather than with
    /// the qid gate 3's session recorded at walk time, for the same reason
    /// `Tlopen` is: the node can have changed kind since the walk, and removing
    /// a directory is a different authority from removing a file. The
    /// re-decided primitive is re-checked against the live grant.
    ///
    /// **That re-check is belt and braces and is recorded as such rather than
    /// counted**, because `Unlink` and `RemoveDir` require the same capability
    /// — `delete` — so no grant can permit one and refuse the other. What the
    /// re-decision *is* load-bearing for is the syscall: `unlinkat` without
    /// `AT_REMOVEDIR` refuses a directory and with it refuses a file, so a kind
    /// taken from the walk rather than from now would answer `EISDIR` or
    /// `ENOTDIR` for a node that had changed kind, where the profile should
    /// simply remove it.
    fn perform_remove(&mut self, fid: u32, grant: CapabilitySet) -> Result<Reply, FsError> {
        let path = self.path_of(fid)?;
        let metadata = self.root.metadata_unchecked(&path)?;
        let directory = metadata.kind() == FileKind::Directory;
        let primitive = if directory {
            Primitive::RemoveDir
        } else {
            Primitive::Unlink
        };
        if !primitive.is_permitted(grant, self.features) {
            return Err(FsError::NotPermitted);
        }
        self.root.remove(&path, directory)?;
        Ok(Reply::releasing(Message::Rremove).with_effect(Applied::Whole))
    }

    fn perform_rename(&mut self, accepted: &Accepted, reply: Message) -> Result<Reply, FsError> {
        let (source, destination) = Self::pair_paths(accepted)?;
        let (source, destination) = (source.clone(), destination.clone());
        self.root.rename_checked(&source, &destination)?;
        Ok(Reply::plain(reply).with_effect(Applied::Whole))
    }

    fn perform_link(&mut self, accepted: &Accepted) -> Result<Reply, FsError> {
        let (source, destination) = Self::pair_paths(accepted)?;
        let (source, destination) = (source.clone(), destination.clone());
        // The source is resolved to a descriptor rather than named again at the
        // link syscall: the inode the new name refers to has to be the one the
        // anchored walk verified is inside the export.
        let handle = self.root.resolve(&source, Intent::Inspect)?;
        self.root.link(&handle, &destination)?;
        Ok(Reply::plain(Message::Rlink).with_effect(Applied::Whole))
    }

    /// `Tsetattr`: apply each named field, in a fixed order, and report how far
    /// it got.
    ///
    /// **This is the one composite mutation in the profile**, and it is where a
    /// genuine partial outcome arises without the wire's help: the mask can
    /// name a size, a mode and two timestamps, and the second of them can fail
    /// after the first has been applied. The order is fixed — size, then mode,
    /// then times — so one request has one answer, and a failure after any
    /// earlier field succeeded is reported [`Outcome::Partial`], never
    /// `not_started` and never `failed`. Gate 1's monotonic merge is what makes
    /// that expressible: once an effect is observed the outcome can only
    /// strengthen.
    fn perform_setattr(&mut self, fid: u32, request: SetattrRequest) -> Result<Reply, FsError> {
        let path = self.path_of(fid)?;
        let mut applied = false;
        // The hard-link rule and the size change both want the fid's own
        // descriptor when it has one, because that descriptor is the file the
        // session opened rather than whatever the name reaches now.
        if request.valid & SETATTR_SIZE != 0 {
            let result = match self.cached(fid) {
                Some(entry) => {
                    // Borrowed and finished with before `self.root` is touched
                    // again; the handle is cloned by reference, not by value.
                    let handle = &entry.handle;
                    self.root.set_size_through(handle, request.size)
                }
                None => self.root.set_size(&path, request.size),
            };
            result.map_err(|error| Self::escalate(error, applied))?;
            applied = true;
        }
        if request.valid & SETATTR_MODE != 0 {
            let result = match self.cached(fid) {
                Some(entry) => entry.handle.set_mode(request.mode),
                None => self
                    .root
                    .resolve(&path, Intent::Inspect)
                    .and_then(|handle| handle.set_mode(request.mode)),
            };
            result.map_err(|error| Self::escalate(error, applied))?;
            applied = true;
        }
        let atime = times_of(
            request.valid,
            SETATTR_ATIME,
            SETATTR_ATIME_SET,
            request.atime,
        );
        let mtime = times_of(
            request.valid,
            SETATTR_MTIME,
            SETATTR_MTIME_SET,
            request.mtime,
        );
        if atime != TimeChange::Omit || mtime != TimeChange::Omit {
            let result = match self.cached(fid) {
                Some(entry) => entry.handle.set_times(atime, mtime),
                None => self
                    .root
                    .resolve(&path, Intent::Inspect)
                    .and_then(|handle| handle.set_times(atime, mtime)),
            };
            result.map_err(|error| Self::escalate(error, applied))?;
            applied = true;
        }
        if !applied {
            // Gate 3 refuses an empty mask, and gate 1's mask excludes uid, gid
            // and ctime, so a `Tsetattr` that reached here naming nothing this
            // provider applies would answer `Rsetattr` for a mutation that did
            // not happen.
            return Err(FsError::refused(FsErrorCode::Enotsup));
        }
        Ok(Reply::plain(Message::Rsetattr).with_effect(Applied::Whole))
    }

    /// Strengthen a failure that arrived after something was already applied.
    ///
    /// The contract: "a rejection after a previously confirmed partial chunk
    /// cannot become `not_started`". This is that rule at the one place a
    /// composite mutation can violate it.
    fn escalate(error: FsError, applied: bool) -> FsError {
        if !applied {
            return error;
        }
        FsError::Filesystem {
            code: error.code(),
            outcome: error.outcome().merge(Outcome::Partial),
        }
    }
}

/// `Tsetattr`'s fields, gathered so the dispatch arm is not nine arguments.
#[derive(Clone, Copy, Debug)]
struct SetattrRequest {
    valid: u32,
    mode: u32,
    size: u64,
    atime: (u64, u64),
    mtime: (u64, u64),
}

/// What one `Tsetattr` timestamp field asks for.
///
const fn times_of(valid: u32, field: u32, explicit: u32, value: (u64, u64)) -> TimeChange {
    if valid & field == 0 {
        return TimeChange::Omit;
    }
    if valid & explicit == 0 {
        // The field bit without its `_SET` companion means "use the current
        // time", and it is the **ordinary** spelling rather than an exotic one:
        // `utimes(NULL)` sends it, which is what `touch` sends. An earlier
        // round of this gate dropped it silently and answered `Rsetattr`, which
        // reported success for a request that partly did not happen — exactly
        // what the contract forbids. Refusing it instead would have been the
        // other wrong answer: it would refuse `touch`.
        //
        // The clock is the **host's**, resolved by the kernel inside
        // `futimens` through `UTIME_NOW`. Nothing in this profile reads one, so
        // this is not the clock enforcement gate 5 deliberately does not do.
        return TimeChange::Now;
    }
    TimeChange::Explicit(value.0, value.1)
}

/// Refuse `O_APPEND`, which this profile does not implement.
///
/// **A decision with a named reason, not an omission.** The contract's
/// `appendFile` requires atomic append positioning per write, and the two hosts
/// this profile serves disagree about whether `pwrite` honours its offset on a
/// descriptor opened `O_APPEND`: POSIX says the offset wins, Linux says the
/// append does. A provider that accepted the flag would be writing to one of
/// two different places depending on the serving operating system, which is the
/// class of host-dependent behaviour the namespace rules exist to prevent. So
/// the flag is `ENOTSUP` and the `nativeAppend` feature is not advertised,
/// which is the contract's own instruction: "If a platform cannot provide
/// required flags/semantics, advertise them unsupported."
fn check_append_unsupported(flags: u32) -> Result<(), FsError> {
    if flags & O_APPEND == 0 {
        Ok(())
    } else {
        Err(FsError::refused(FsErrorCode::Enotsup))
    }
}

/// Which of the two shapes an open produced.
enum OpenKind {
    File,
    Directory,
}

/// A descriptor a successful open wants cached.
struct OpenState {
    handle: Handle,
    reader: Option<DirReader>,
}

/// What a successful reply does to the descriptor cache.
enum CacheEffect {
    None,
    Insert(OpenState),
    /// As [`CacheEffect::Insert`], but for a reply that **rebound** its fid.
    ///
    /// Only `Rlcreate` does: the fid named the parent directory on the way in
    /// and names the created file on the way out, so gate 3's session stamped a
    /// fresh generation when it applied the reply. Keying the descriptor on the
    /// generation the request was admitted against would file it under a
    /// binding that no longer exists, and the created file would be unwritable
    /// through the very fid that made it.
    InsertCreated(OpenState),
    Release,
}

/// How much of a mutation the host applied before its reply was built.
///
/// Deliberately **not** [`Outcome`]. An outcome describes a *failure*'s extent
/// and gate 1's vocabulary has no spelling for "it all worked", so reusing it
/// here would need a fifth variant whose only purpose is to be filtered out
/// again. This says what happened; [`Provider::settle`] and
/// [`Provider::note_effect_undelivered`] are what turn it into the outcome a
/// consumer is told.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Applied {
    /// Everything the request asked for.
    Whole,
    /// Some of it. A short `Twrite` is the only shape the wire can carry.
    Partial,
}

struct Reply {
    message: Message,
    cache: CacheEffect,
    /// Present when this reply reports something that has already happened on
    /// the host, and absent for every observation.
    ///
    /// This is what decides whether losing the reply is `unknown` or merely a
    /// lost read, and it is attached per reply rather than derived from the
    /// opcode because a `Tlopen` is both: truncating it changed the file and
    /// opening it for writing did not.
    effect: Option<Applied>,
}

impl Reply {
    const fn plain(message: Message) -> Self {
        Self {
            message,
            cache: CacheEffect::None,
            effect: None,
        }
    }

    const fn releasing(message: Message) -> Self {
        Self {
            message,
            cache: CacheEffect::Release,
            effect: None,
        }
    }

    const fn opening(message: Message, state: OpenState) -> Self {
        Self {
            message,
            cache: CacheEffect::Insert(state),
            effect: None,
        }
    }

    const fn creating(message: Message, state: OpenState) -> Self {
        Self {
            message,
            cache: CacheEffect::InsertCreated(state),
            effect: None,
        }
    }

    const fn with_effect(mut self, applied: Applied) -> Self {
        self.effect = Some(applied);
        self
    }
}

const fn qid_kind(kind: FileKind) -> QidKind {
    match kind {
        FileKind::Directory => QidKind::Directory,
        FileKind::Symlink => QidKind::Symlink,
        // Everything else the resolver would have refused before it got here;
        // a regular file is the only remaining case.
        _ => QidKind::File,
    }
}

/// The qid for a node.
///
/// The path is gate 2's 64-bit fold of `(st_dev, st_ino)`: equality is preserved
/// exactly, and the host's own numbers are not recoverable from it. The version
/// is zero, because this profile maintains no content version counter and a
/// fabricated one would imply conditional-update safety the contract refuses to
/// promise.
fn qid_of(metadata: Metadata) -> Qid {
    Qid::new(qid_kind(metadata.kind()), metadata.identity().qid_path())
}

/// Build an `Rgetattr` body.
///
/// `uid` and `gid` are **zero**, always. The contract: "File identity/metadata
/// must not leak host inode, UID, or directory details." `ino` is the qid fold
/// for the same reason, `rdev` is zero because this profile serves no device
/// node, and `btime`, `gen` and `data_version` are zero and are reported absent
/// from `valid` because nothing here records them.
fn attributes_of(metadata: Metadata, request_mask: u64) -> Attributes {
    let (atime_sec, atime_nsec) = metadata.atime();
    let (mtime_sec, mtime_nsec) = metadata.mtime();
    let (ctime_sec, ctime_nsec) = metadata.ctime();
    let qid = qid_of(metadata);
    Attributes {
        // Only the basic set is ever filled in, whatever was asked for: a
        // provider that set a `valid` bit it had no value for would report a
        // birth time of zero as a birth time.
        valid: request_mask & GETATTR_BASIC,
        qid,
        mode: metadata.mode(),
        uid: 0,
        gid: 0,
        nlink: metadata.links(),
        rdev: 0,
        size: metadata.size(),
        blksize: metadata.blksize(),
        blocks: metadata.blocks(),
        atime_sec,
        atime_nsec,
        mtime_sec,
        mtime_nsec,
        ctime_sec,
        ctime_nsec,
        btime_sec: 0,
        btime_nsec: 0,
        generation: 0,
        data_version: 0,
    }
}
