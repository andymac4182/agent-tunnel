//! The dispatcher.
//!
//! One [`Provider`] is one 9P session on one consumer connection, against one
//! export root and one grant context.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use tunnel_fs_core::{
    CapabilitySet, FeatureSet, FsError, FsErrorCode, Limits, Primitive, SessionErrorCode,
};
use tunnel_fs_host::{DirReader, ExportRoot, FileKind, Handle, HostEntry, Metadata};
use tunnel_fs_ninep::{
    Accepted, Attributes, COUNTED_REPLY_OVERHEAD, DirEntry, ENTRY_OVERHEAD, Frame, GETATTR_ALL,
    GETATTR_BASIC, Message, Primitives, Qid, QidKind, RequestPaths, Session, SessionError,
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
    /// Mutating requests refused because writes are gate 5's.
    pub mutations_refused: u64,
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
    /// Tags whose `Rflush` has already been sent.
    ///
    /// A queued request whose tag is in here is dropped rather than performed:
    /// its tag is gone from the session, so its reply has nothing to correlate
    /// against and `Session::complete` would read it as an invented tag.
    flushed: BTreeSet<u16>,
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
            flushed: BTreeSet::new(),
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

    /// End the session, releasing every descriptor it holds.
    pub fn close(&mut self) {
        self.session.close();
        self.queue.clear();
        self.flushed.clear();
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
        if self.flushed.remove(&queued.tag) {
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
        let answer = self.fail(queued.tag, error);
        if let Some(fid) = self.primary_fid(&queued.frame.message) {
            self.prune(fid);
        }
        answer
    }

    /// Apply a successful reply to the session and emit it.
    fn settle(&mut self, queued: Queued, reply: Reply) -> Vec<Outbound> {
        let frame = Frame::new(queued.tag, reply.message);
        if let Err(error) = self.session.complete(&frame) {
            return self.refuse(queued.tag, error);
        }
        if let Some(fid) = self.primary_fid(&queued.frame.message) {
            match reply.cache {
                CacheEffect::Insert(entry) => self.insert(fid, queued.generation, entry),
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
        // **Only a request still in the queue is marked.** A victim this
        // dispatcher has already answered has no reply left to drop, and
        // marking its tag anyway would be a defect rather than caution: gate
        // 3's session releases a flushed tag when its `Rflush` is answered, so
        // the client may immediately re-issue that number, and a stale mark
        // would silently drop the *new* request's reply.
        if self.queue.iter().any(|queued| queued.tag == oldtag) {
            self.flushed.insert(oldtag);
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
            | Message::Treadlink { fid } => Some(*fid),
            Message::Twalk { newfid, .. } => Some(*newfid),
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
            // Every mutation, and `Treadlink`, which needs a feature this
            // profile does not advertise and an implementation gate 4 does not
            // have.  `Tremove` releases its fid on either answer, which is 9P's
            // own rule and gate 3's session applies it to an `Rlerror` too.
            _ => {
                self.stats.mutations_refused += 1;
                Err(FsError::refused(FsErrorCode::Enotsup))
            }
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

        // Writes are gate 5's, whatever the grant says.
        if required.iter().any(|primitive| {
            matches!(
                primitive,
                Primitive::OpenWrite | Primitive::OpenTruncate | Primitive::Create
            )
        }) {
            self.stats.mutations_refused += 1;
            return Err(FsError::refused(FsErrorCode::Enotsup));
        }

        let (handle, reader, mode) = if metadata.kind() == FileKind::Directory {
            let handle = self.root.open_directory(&path)?;
            let reader = self.root.reader_for(&handle)?;
            (handle, Some(reader), OpenKind::Directory)
        } else {
            let handle = self.root.open_read(&path)?;
            (handle, None, OpenKind::File)
        };
        // The qid is taken from the descriptor that was actually opened, not
        // from the `statat` above: the two can disagree, and the descriptor is
        // the only authority.
        let opened = handle.metadata()?;
        if (opened.kind() == FileKind::Directory) != matches!(mode, OpenKind::Directory) {
            return Err(FsError::refused(FsErrorCode::Einval));
        }
        let iounit = self.session.msize().saturating_sub(COUNTED_REPLY_OVERHEAD);
        Ok(Reply::opening(
            Message::Rlopen {
                qid: qid_of(opened),
                iounit,
            },
            OpenState { handle, reader },
        ))
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
    Release,
}

struct Reply {
    message: Message,
    cache: CacheEffect,
}

impl Reply {
    const fn plain(message: Message) -> Self {
        Self {
            message,
            cache: CacheEffect::None,
        }
    }

    const fn releasing(message: Message) -> Self {
        Self {
            message,
            cache: CacheEffect::Release,
        }
    }

    const fn opening(message: Message, state: OpenState) -> Self {
        Self {
            message,
            cache: CacheEffect::Insert(state),
        }
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
