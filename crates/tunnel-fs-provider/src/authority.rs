//! The connector-facing half of the provider's interface: what it reads the
//! live authorization through, and the counters it reports.
//!
//! **Portable, unlike the dispatcher.** [`crate::Provider`] needs the
//! Unix-only resolver in `tunnel-fs-host`, so it is `cfg(unix)`; these types
//! need nothing from the host. `tunnel-client` names all three in code that
//! exists on every host -- the stream authority it shares with a provider,
//! and the per-session ledger it sums -- so while they lived beside the
//! dispatcher, `tunnel-client` did not compile for `x86_64-pc-windows-msvc`,
//! one of the four release targets.

use tunnel_fs_core::CapabilitySet;

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
    /// Every one of these is [`tunnel_fs_core::Outcome::NotStarted`], which is the claim gate 4
    /// could make about *every* refusal it produced and gate 5 can no longer.
    ///
    /// **Both refusal points, since task row M4-16.** A mutation refused after
    /// the queue wait is counted in [`crate::Provider::fail_queued`]; one refused at
    /// *admission*, by the session inside [`crate::Provider::accept`], is counted by
    /// [`crate::Provider::note_refused_mutation`]. The second is the common case and
    /// was missing: every capability refusal under a read-only grant is taken
    /// there, so an export being hammered by an unauthorized consumer used to
    /// read zero here.
    ///
    /// What it still does not count is a request refused before the session
    /// decided what primitives it needed — a `Twrite` to a fid that is not open
    /// for writing, which is refused for its fid state. That is a bound, it is
    /// deliberate, and task row M4-20 records it.
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
    /// [`tunnel_fs_core::Outcome::Failed`], and **not** `not_started`: the request reached the
    /// host, which is a different fact from a refusal taken before it.
    pub mutation_failed: u64,
    /// Mutations that applied part of what they were asked for.
    ///
    /// A short `Twrite`, and a multi-field `Tsetattr` whose later field failed
    /// after an earlier one had already been applied. [`tunnel_fs_core::Outcome::Partial`].
    pub mutation_partial: u64,
    /// Applied mutations whose effect the consumer cannot learn.
    ///
    /// [`tunnel_fs_core::Outcome::Unknown`], and it has **two** sources rather than one.
    ///
    /// The first is a reply that never left: counted when the connector reports
    /// a send it could not complete, and at [`crate::Provider::close`] for an effect
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
