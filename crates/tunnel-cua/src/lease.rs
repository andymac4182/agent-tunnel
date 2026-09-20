//! The **exclusive input lease**, one per target OS session.
//!
//! `docs/integrations.md`: "Use an exclusive input lease per target OS session
//! to prevent two authorized agents from interleaving keyboard/mouse actions.
//! Screenshot reads may be shared within the same permitted scope."
//!
//! Both halves are enforced here, and the second is enforced by *omission*
//! rather than by a rule: [`InputLeases`] is consulted only for operations
//! whose [`crate::Operation::mutates_target`] is true, so a `capture` from a
//! second session is never refused by this module. A lease that also gated
//! reads would be a different and worse contract — two agents watching one
//! screen is the normal case.
//!
//! # What the lease is keyed by, and what it is deliberately *not* keyed by
//!
//! The key is a [`TargetSession`]: the OS session being driven. The holder is
//! a [`SessionId`]: the **tunnel session** the operations arrive on.
//!
//! The holder is **not** the carrier connection, and that is the whole of this
//! module's answer to rotation. `docs/integrations.md` requires that "rotation
//! of the outer data WebSocket must leave the local operation running", and
//! `<scratchpad>/m5-scoping-and-decisions.md` states the rule as *a rotation
//! leaves the lease held*. Since a carrier generation is not part of holder
//! identity, a rotation cannot drop a lease: there is no code path that could.
//! `crates/tunnel-cua-fixture/tests/input_lease.rs` drives a rotation across a
//! held lease and a lost click to check that claim rather than trusting it.
//!
//! # Revocation — the part that is **not** closed
//!
//! M3-16 records the live hazard: revoking a consumer's grant fences the relay
//! but never reaches the device-side session. Applied here, a revoked
//! consumer's session could keep the input lease.
//!
//! This module splits that into two facts, because they have different answers
//! and only one of them is closed:
//!
//! 1. **A revoked holder cannot use the lease, and cannot launder the
//!    refusal away either.** Every acquisition records the [`GrantRevision`]
//!    it was authorized under, and [`InputLeases::check`] refuses with
//!    [`LeaseRefusal::GrantRevoked`] when the revision it is given has moved
//!    past the recorded one. **[`InputLeases::acquire`] refuses to raise an
//!    existing holding's recorded revision** for the same reason — review
//!    found that re-acquiring used to clear the refusal *and* leave
//!    [`InputLeases::reconcile_grant`] with nothing to free, which defeated
//!    both halves with one call. Fail-closed at the point of use, and it
//!    needs no new signal *beyond the revision itself*.
//! 2. **A revoked holder still blocks the target.** Nothing is released by
//!    (1): the entry stays, so a second agent still gets
//!    [`LeaseRefusal::HeldByAnotherSession`]. [`InputLeases::reconcile_grant`]
//!    is the mechanism that frees it, and it must be driven by something that
//!    learns the current revision.
//!
//! **That something does not exist today.** The device is not told that a
//! grant was revoked — that is exactly M3-16 — so in the shipped shape both
//! (1) and (2) are dormant: the revision the device holds never advances, so
//! `check` never refuses and `reconcile_grant` is never called with anything
//! that would drop an entry. The consequence, stated plainly rather than
//! implied away: **a revoked consumer's lease persists for the life of the
//! device-side tunnel session.** `docs/tasks.md` M5-C05 is that row; it is open.
//!
//! Both mechanisms are nonetheless tested here against an explicitly supplied
//! revision, so that when the signal arrives the behaviour is already pinned —
//! and so that the gap is the *delivery* of a revision, which is nameable, and
//! not a policy nobody has decided.

use std::collections::BTreeMap;

/// The tunnel session an operation arrived on. **This is the lease holder.**
///
/// Opaque: this crate never renders it into a payload, and it carries no
/// principal identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionId(u64);

impl SessionId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// The target OS session being driven. **This is the lease key.**
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TargetSession(String);

impl TargetSession {
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self(name.to_owned())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Identifies one *holding* of the lease.
///
/// A fresh value every time the lease is taken, so a release that names an
/// earlier holding is refused rather than dropping somebody else's lease. That
/// is the difference between "release the lease" and "release *my* lease", and
/// only the second is safe when a target can be re-leased between two
/// exchanges of a confused caller.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LeaseId(u64);

impl LeaseId {
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// The revision of the consumer grant an acquisition was authorized under.
///
/// Monotonic. See this module's header for what it can and cannot do today.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GrantRevision(u64);

impl GrantRevision {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Evidence that a session holds the input lease for a target.
///
/// Returned by [`InputLeases::acquire`] and consumed by
/// [`InputLeases::release`]. It is **not** an authorization token: nothing
/// dispatches on the strength of holding this value, because
/// [`crate::plan::plan`] re-checks the registry on every operation. A caller
/// that kept one past a revocation would still be refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseGrant {
    target: TargetSession,
    session: SessionId,
    lease: LeaseId,
    grant_revision: GrantRevision,
}

impl LeaseGrant {
    #[must_use]
    pub fn target(&self) -> &TargetSession {
        &self.target
    }

    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    #[must_use]
    pub const fn lease(&self) -> LeaseId {
        self.lease
    }

    #[must_use]
    pub const fn grant_revision(&self) -> GrantRevision {
        self.grant_revision
    }
}

/// Why a lease operation was refused.
///
/// **Every variant means nothing was dispatched.** The lease check runs
/// strictly above the dispatch boundary; see [`crate::plan`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LeaseRefusal {
    /// Another tunnel session holds the lease for this target. **This is the
    /// refusal the contract exists for**: two authorized agents must not
    /// interleave keyboard or pointer actions.
    HeldByAnotherSession,
    /// Nobody holds the lease for this target, and an input operation requires
    /// one. Acquiring is not implicit: an operation never takes the lease as a
    /// side effect, because a lease taken by a click is a lease nobody
    /// releases.
    NotHeld,
    /// The caller holds *a* lease for this target, but not the one it named.
    NotTheHolder,
    /// The grant the lease was acquired under has been superseded. See this
    /// module's header for why this is fail-closed but currently dormant.
    GrantRevoked,
}

impl core::fmt::Display for LeaseRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::HeldByAnotherSession => "the input lease is held by another session",
            Self::NotHeld => "no input lease is held for this target",
            Self::NotTheHolder => "the named input lease is not the one held",
            Self::GrantRevoked => "the grant behind the input lease has been superseded",
        })
    }
}

impl std::error::Error for LeaseRefusal {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Holder {
    session: SessionId,
    lease: LeaseId,
    grant_revision: GrantRevision,
}

/// The exclusive input leases held on this device, one per target OS session.
///
/// Pure state: no clock, no I/O, no expiry. **There is no timeout**, and that
/// is a stated limitation rather than an oversight — a lease that expired on a
/// clock would release the target in the middle of a drag. The lease ends when
/// it is released, when the grant behind it is reconciled away, or when the
/// device-side session holding it ends. See M5-C05.
#[derive(Clone, Debug, Default)]
pub struct InputLeases {
    next: u64,
    held: BTreeMap<TargetSession, Holder>,
}

impl InputLeases {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Take the exclusive input lease for `target`.
    ///
    /// Re-acquiring a lease this session already holds is **idempotent**: the
    /// same [`LeaseId`] comes back and **the recorded revision does not
    /// change**. A second agent gets [`LeaseRefusal::HeldByAnotherSession`]
    /// and nothing else changes.
    ///
    /// # Re-acquiring cannot clear a revocation, and an earlier revision of
    /// this function let it
    ///
    /// **This is the review finding that mattered most in chunk 3, recorded
    /// rather than quietly fixed.** `acquire` used to write the supplied
    /// revision into an existing holding. So a holder that
    /// [`InputLeases::check`] had just refused with
    /// [`LeaseRefusal::GrantRevoked`] could call `acquire` again with the
    /// advanced revision, have it recorded, and pass `check` — and
    /// [`InputLeases::reconcile_grant`] would then free nothing, because the
    /// recorded revision was no longer behind. Both halves of the M3-16 story
    /// were defeated by one call, and re-acquiring is the *obvious* client
    /// response to a refusal ("my lease was refused; take it again"). The old
    /// test stopped before the re-acquire, so nothing measured it.
    ///
    /// An acquisition that would **raise** an existing holding's recorded
    /// revision is therefore refused with [`LeaseRefusal::GrantRevoked`]. A
    /// revision at or below the recorded one is a stale reading rather than a
    /// revocation, so it is accepted and still changes nothing.
    ///
    /// **This is not a lockout for a legitimately re-granted consumer**, and
    /// that is why the rule can be this blunt: `release` then `acquire` mints
    /// a fresh holding at the new revision. What is refused is *raising the
    /// revision of a holding that already exists*, which is exactly the move
    /// that would launder a revocation.
    ///
    /// # Errors
    /// [`LeaseRefusal::HeldByAnotherSession`] if another session holds the
    /// target; [`LeaseRefusal::GrantRevoked`] if this session holds it under
    /// an older grant revision than the one supplied.
    pub fn acquire(
        &mut self,
        target: &TargetSession,
        session: SessionId,
        grant_revision: GrantRevision,
    ) -> Result<LeaseGrant, LeaseRefusal> {
        if let Some(holder) = self.held.get(target) {
            if holder.session != session {
                return Err(LeaseRefusal::HeldByAnotherSession);
            }
            // **Never raise an existing holding's recorded revision.** Doing
            // so would let a revoked holder clear its own refusal, and would
            // leave `reconcile_grant` with nothing to free. See the doc above.
            if grant_revision > holder.grant_revision {
                return Err(LeaseRefusal::GrantRevoked);
            }
            return Ok(LeaseGrant {
                target: target.clone(),
                session,
                lease: holder.lease,
                grant_revision: holder.grant_revision,
            });
        }
        self.next += 1;
        let lease = LeaseId(self.next);
        self.held.insert(
            target.clone(),
            Holder {
                session,
                lease,
                grant_revision,
            },
        );
        Ok(LeaseGrant {
            target: target.clone(),
            session,
            lease,
            grant_revision,
        })
    }

    /// Release a lease this session holds.
    ///
    /// # Errors
    /// [`LeaseRefusal::NotHeld`] if the target is unleased,
    /// [`LeaseRefusal::HeldByAnotherSession`] if somebody else has it, and
    /// [`LeaseRefusal::NotTheHolder`] if the grant names a superseded holding.
    pub fn release(&mut self, grant: &LeaseGrant) -> Result<(), LeaseRefusal> {
        let holder = *self.held.get(&grant.target).ok_or(LeaseRefusal::NotHeld)?;
        if holder.session != grant.session {
            return Err(LeaseRefusal::HeldByAnotherSession);
        }
        if holder.lease != grant.lease {
            return Err(LeaseRefusal::NotTheHolder);
        }
        self.held.remove(&grant.target);
        Ok(())
    }

    /// The check every input operation passes, immediately before its capture
    /// coordinates are checked and long before anything is sent.
    ///
    /// `grant_revision` is the revision the device currently believes the
    /// session's grant carries. See the module header for why that belief does
    /// not move today.
    ///
    /// # Errors
    /// Any [`LeaseRefusal`]. Every one means nothing was dispatched.
    pub fn check(
        &self,
        target: &TargetSession,
        session: SessionId,
        grant_revision: GrantRevision,
    ) -> Result<LeaseId, LeaseRefusal> {
        let holder = self.held.get(target).ok_or(LeaseRefusal::NotHeld)?;
        if holder.session != session {
            return Err(LeaseRefusal::HeldByAnotherSession);
        }
        if grant_revision > holder.grant_revision {
            return Err(LeaseRefusal::GrantRevoked);
        }
        Ok(holder.lease)
    }

    /// Drop every lease held by `session` under a revision older than
    /// `grant_revision`, and report which targets were freed.
    ///
    /// **This is the M3-16 mechanism, and it has no caller in this repository.**
    /// Nothing tells a device that a grant was revoked, so nothing supplies an
    /// advanced revision. It is implemented and tested so that the open work is
    /// the delivery of a revision rather than a policy decision nobody has
    /// taken; M5-C05 is the row, and it is open.
    pub fn reconcile_grant(
        &mut self,
        session: SessionId,
        grant_revision: GrantRevision,
    ) -> Vec<TargetSession> {
        let freed: Vec<TargetSession> = self
            .held
            .iter()
            .filter(|(_, holder)| {
                holder.session == session && grant_revision > holder.grant_revision
            })
            .map(|(target, _)| target.clone())
            .collect();
        for target in &freed {
            self.held.remove(target);
        }
        freed
    }

    /// Drop every lease held by `session`, whatever its revision.
    ///
    /// What a device-side session ending does to the leases it held. Also with
    /// no caller in this chunk, for the same reason: there is no session
    /// lifecycle here to hang it off.
    pub fn release_all_for_session(&mut self, session: SessionId) -> Vec<TargetSession> {
        let freed: Vec<TargetSession> = self
            .held
            .iter()
            .filter(|(_, holder)| holder.session == session)
            .map(|(target, _)| target.clone())
            .collect();
        for target in &freed {
            self.held.remove(target);
        }
        freed
    }

    /// Drop **every** lease, whoever holds it, and report which targets were
    /// freed.
    ///
    /// What a **supervised backend restart** does. It is deliberately the
    /// bluntest of the three: `reconcile_grant` and `release_all_for_session`
    /// both ask *whose* lease this is, and a restart does not care. The
    /// backend that was holding the target OS session's input down is gone;
    /// every lease held against it now describes a process that no longer
    /// exists, and a lease that outlived its backend would let the next
    /// operation through on the strength of an exclusivity nothing is
    /// enforcing any more.
    ///
    /// **This is the half of the restart contract that is not about
    /// retryability.** `restart_outcome` decides what the *in-flight*
    /// operation is told; this decides what every *later* operation must
    /// re-establish. Both are needed: a caller that ignores the first still
    /// meets the second.
    pub fn invalidate_all(&mut self) -> Vec<TargetSession> {
        let freed: Vec<TargetSession> = self.held.keys().cloned().collect();
        self.held.clear();
        freed
    }

    /// Which session holds `target`, if any.
    #[must_use]
    pub fn holder(&self, target: &TargetSession) -> Option<SessionId> {
        self.held.get(target).map(|holder| holder.session)
    }

    /// Which holding is current for `target`, if any.
    #[must_use]
    pub fn holding(&self, target: &TargetSession) -> Option<LeaseId> {
        self.held.get(target).map(|holder| holder.lease)
    }

    /// How many targets are leased.
    #[must_use]
    pub fn len(&self) -> usize {
        self.held.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }
}

#[cfg(test)]
mod tests;
